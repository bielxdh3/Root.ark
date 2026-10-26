"use strict";

// Independent historical-recovery ACK custodian. This module must execute in
// an operator-controlled process with its own database and mTLS identity.
// An ordinary local SQLite deployment is not independent physical custody.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { snapshotLocalDevicePolicy } =
  require("../../sync-client/rootark-sync-zk1-physical-binding");
const { verifyCommittedPhysicalReadback } =
  require("../crypto/rootark-zk-pg-physical-attestation-v1");
const { assertPrivateSqliteAuthorityDirectory, assertPrivateSqliteFile } =
  require("./zk1PrivateSqlitePath");

const ZERO = "0".repeat(64);
const DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-recovery-ledger/v2\0");
const MAX_SEQUENCE = 4096;
function deny() { throw Error("HISTORICAL_RECOVERY_OPERATOR_DENIED"); }
function validHash(v) { return typeof v === "string" && /^[a-f0-9]{64}$/.test(v); }
function sha(input) { return crypto.createHash("sha256").update(input).digest("hex"); }
function exact(v, keys) {
  if (!v || typeof v !== "object" || Array.isArray(v)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
    || Reflect.ownKeys(v).length !== keys.length
    || keys.some((k) => !Object.hasOwn(v, k)
      || !Object.hasOwn(Object.getOwnPropertyDescriptor(v, k), "value"))) deny();
  return v;
}
function bytes(v, length) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array)) || v.length !== length) deny();
  return Buffer.from(v);
}
function head(v) {
  exact(v, ["sequence", "lastHash"]);
  if (!Number.isSafeInteger(v.sequence) || v.sequence < 0 || v.sequence > MAX_SEQUENCE
    || !validHash(v.lastHash) || (v.sequence === 0 && v.lastHash !== ZERO)) deny();
  return v;
}
function ownerPolicy(v) {
  const normalized = snapshotLocalDevicePolicy(v);
  const canonical = JSON.stringify(normalized);
  if (typeof canonical !== "string" || canonical.length > 1048576) deny();
  return canonical;
}
function publicKey(pem) {
  if (typeof pem !== "string" || pem.length > 4096) deny();
  const key = crypto.createPublicKey(pem);
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") deny();
  return key;
}
function configPins(config) {
  const { witnessKeyId, statusKeyId } = config;
  for (const val of [witnessKeyId, statusKeyId]) {
    if (typeof val !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(val)
      || Buffer.from(val, "base64url").toString("base64url") !== val) deny();
  }
  const witness = publicKey(config.witnessPublicKeyPem);
  const physical = publicKey(config.physicalAttestorPublicKeyPem);
  const pins = sha(JSON.stringify([
    witnessKeyId, statusKeyId,
    witness.export({ type: "spki", format: "der" }).toString("base64"),
    physical.export({ type: "spki", format: "der" }).toString("base64"),
  ]));
  return { pins, witness, physical, witnessKeyId, statusKeyId };
}
function proofHash(proof) {
  if (!Number.isSafeInteger(proof.ownerGeneration) || proof.ownerGeneration < 0
    || !Number.isSafeInteger(proof.physicalIssuedAt)
    || typeof proof.policySnapshot !== "string"
    || (!Buffer.isBuffer(proof.physicalAttestation)
      && !(proof.physicalAttestation instanceof Uint8Array))) deny();
  return sha(JSON.stringify([
    bytes(proof.readySignature, 64).toString("base64url"),
    Buffer.from(proof.physicalAttestation).toString("base64url"),
    bytes(proof.nonce, 32).toString("base64url"),
    proof.policySnapshot, proof.ownerGeneration, proof.physicalIssuedAt,
  ]));
}
function proofShape(proof, previous, next, pins) {
  exact(proof, ["witnessKeyId", "statusKeyId", "readySignature",
    "policySnapshot", "ownerGeneration", "physicalIssuedAt", "physicalAttestation",
    "scope", "operation", "nonce", "recoveryRow"]);
  if (proof.witnessKeyId !== pins.witnessKeyId
    || proof.statusKeyId !== pins.statusKeyId
    || !Number.isSafeInteger(proof.ownerGeneration) || proof.ownerGeneration < 0
    || !Number.isSafeInteger(proof.physicalIssuedAt)
    || typeof proof.policySnapshot !== "string" || proof.policySnapshot.length > 1048576
    || ownerPolicy(JSON.parse(proof.policySnapshot)) !== proof.policySnapshot
    || (!Buffer.isBuffer(proof.physicalAttestation) && !(proof.physicalAttestation instanceof Uint8Array))
    || proof.physicalAttestation.length < 1 || proof.physicalAttestation.length > 2048) deny();
  bytes(proof.nonce, 32);
  const row = exact(proof.recoveryRow,
    ["sequence", "nonce", "operation_id", "admission_hash", "consumed_at_ms", "previous_hash", "hash"]);
  if (row.sequence !== next.sequence || !Number.isSafeInteger(row.consumed_at_ms)
    || row.consumed_at_ms < 1 || !/^[A-Za-z0-9_-]{22}$/.test(row.operation_id)
    || !validHash(row.admission_hash) || row.previous_hash !== previous.lastHash
    || row.hash !== next.lastHash || !bytes(row.nonce, 32).equals(bytes(proof.nonce, 32))
    || !bytes(proof.operation?.operation_id, 16).equals(Buffer.from(row.operation_id, "base64url"))
    || sha(row.previous_hash + "\0" + JSON.stringify([
      row.sequence, Buffer.from(row.nonce).toString("base64url"), row.operation_id,
      row.admission_hash, row.consumed_at_ms,
    ])) !== next.lastHash) deny();
  const ready = Buffer.concat([DOMAIN, Buffer.from(JSON.stringify([
    pins.witnessKeyId, pins.statusKeyId, next.sequence, next.lastHash, "READY", ZERO,
  ]))]);
  if (!crypto.verify(null, ready, pins.witness, bytes(proof.readySignature, 64))) deny();
}

class Zk1HistoricalRecoveryOperator {
  #db;
  #pins;
  constructor({ databasePath, bootstrapNew = false, initialPolicy, ...pinConfig }) {
    if (typeof databasePath !== "string" || !path.isAbsolute(databasePath)
      || typeof bootstrapNew !== "boolean") deny();
    this.#pins = configPins(pinConfig);
    assertPrivateSqliteAuthorityDirectory(databasePath);
    const existed = fs.existsSync(databasePath);
    if (existed === bootstrapNew) deny();
    if (existed) assertPrivateSqliteFile(databasePath);
    else if (initialPolicy === undefined) deny();
    const db = new Database(databasePath, { fileMustExist: existed,
      timeout: 2500 });
    try {
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      db.pragma("foreign_keys = ON");
      db.pragma("busy_timeout = 2500");
      if (bootstrapNew) {
        db.exec(`CREATE TABLE operator_recovery_floor (
          id INTEGER PRIMARY KEY CHECK(id=1), pins TEXT NOT NULL,
          sequence INTEGER NOT NULL, last_hash TEXT NOT NULL,
          finalized_sequence INTEGER NOT NULL, finalized_hash TEXT NOT NULL,
          quarantined INTEGER NOT NULL CHECK(quarantined IN (0,1)),
          owner_generation INTEGER NOT NULL, owner_policy TEXT NOT NULL,
          finalized_owner_generation INTEGER NOT NULL,
          ack_settlement TEXT NOT NULL CHECK(ack_settlement IN ('SEALED','PROVISIONAL')),
          provisional_proof_hash TEXT NOT NULL);`);
        db.prepare("INSERT INTO operator_recovery_floor VALUES(1,?,?,?,?,?,?,?,?,?,?,?)")
          .run(this.#pins.pins, 0, ZERO, 0, ZERO, 0, 0,
            ownerPolicy(initialPolicy), 0, "SEALED", "");
      }
      if (db.pragma("integrity_check", { simple: true }) !== "ok") deny();
      const row = db.prepare("SELECT * FROM operator_recovery_floor WHERE id=1").get();
      if (db.prepare("SELECT COUNT(*) AS count FROM operator_recovery_floor").get().count !== 1
        || !row || row.pins !== this.#pins.pins) deny();
      this.#db = db;
      this.#current();
      if (!existed) fs.chmodSync(databasePath, 0o600);
      assertPrivateSqliteFile(databasePath);
    } catch (e) { db.close(); throw e; }
  }
  #current() {
    const row = this.#db.prepare("SELECT * FROM operator_recovery_floor WHERE id=1").get();
    if (!row || row.pins !== this.#pins.pins
      || !Number.isSafeInteger(row.owner_generation) || row.owner_generation < 0
      || !Number.isSafeInteger(row.finalized_owner_generation)
      || row.finalized_owner_generation < 0
      || ![0, 1].includes(row.quarantined)
      || !["SEALED", "PROVISIONAL"].includes(row.ack_settlement)
      || !validHash(row.provisional_proof_hash || ZERO)
      || ownerPolicy(JSON.parse(row.owner_policy)) !== row.owner_policy) deny();
    head({ sequence: row.sequence, lastHash: row.last_hash });
    head({ sequence: row.finalized_sequence, lastHash: row.finalized_hash });
    if (row.finalized_sequence > row.sequence
      || (row.finalized_sequence === row.sequence && row.finalized_hash !== row.last_hash)
      || row.finalized_owner_generation > row.owner_generation) deny();
    return row;
  }
  loadHead() {
    const row = this.#current();
    return { sequence: row.sequence, lastHash: row.last_hash };
  }
  loadFinalizedHead() {
    const row = this.#current();
    if (row.quarantined || row.ack_settlement !== "SEALED"
      || row.finalized_owner_generation !== row.owner_generation) deny();
    return { sequence: row.finalized_sequence, lastHash: row.finalized_hash };
  }
  loadOwnerGeneration() { return this.#current().owner_generation; }
  loadQuarantinedHead() {
    const row = this.#current();
    if (row.quarantined !== 1) deny();
    return { sequence: row.sequence, lastHash: row.last_hash };
  }
  compareAndAdvance(previous, next) {
    head(previous); head(next);
    if (next.sequence !== previous.sequence + 1) deny();
    return this.#db.transaction(() => {
      this.#current();
      return this.#db.prepare("UPDATE operator_recovery_floor SET sequence=?,last_hash=?"
        + " WHERE id=1 AND sequence=? AND last_hash=? AND quarantined=0"
        + " AND ack_settlement='SEALED'").run(next.sequence, next.lastHash,
          previous.sequence, previous.lastHash).changes === 1;
    }).immediate();
  }
  advanceOwnerPolicy(expectedGeneration, nextPolicy) {
    if (!Number.isSafeInteger(expectedGeneration) || expectedGeneration < 0) deny();
    const canonical = ownerPolicy(nextPolicy);
    return this.#db.transaction(() => {
      const row = this.#current();
      if (row.owner_generation !== expectedGeneration || row.quarantined) return false;
      const old = JSON.parse(row.owner_policy);
      const incoming = JSON.parse(canonical);
      if (old.username !== incoming.username
        || old.revokedDeviceIds.some((id) => !incoming.revokedDeviceIds.includes(id))) deny();
      return this.#db.prepare("UPDATE operator_recovery_floor"
        + " SET owner_generation=owner_generation+1,owner_policy=?,quarantined=1"
        + " WHERE id=1 AND owner_generation=? AND quarantined=0")
        .run(canonical, expectedGeneration).changes === 1;
    }).immediate();
  }
  quarantineFinalizedAck(expected) {
    head(expected);
    return this.#db.transaction(() => {
      this.#current();
      return this.#db.prepare("UPDATE operator_recovery_floor SET quarantined=1"
        + " WHERE id=1 AND sequence=? AND last_hash=? AND quarantined=0")
        .run(expected.sequence, expected.lastHash).changes === 1;
    }).immediate();
  }
  async finalizeAck(previous, next, proof) {
    head(previous); head(next);
    if (next.sequence !== previous.sequence + 1) deny();
    proofShape(proof, previous, next, this.#pins);
    const signed = await verifyCommittedPhysicalReadback(proof.physicalAttestation, {
      scope: proof.scope, operation: proof.operation, nonce: proof.nonce,
      pinnedPublicKey: this.#pins.physical, expected: undefined,
      nowSeconds: Math.floor(Date.now() / 1000),
    });
    if (signed.issuedAt !== proof.physicalIssuedAt) deny();
    return this.#db.transaction(() => {
      const row = this.#current();
      if (row.owner_generation !== proof.ownerGeneration
        || row.owner_policy !== proof.policySnapshot
        || row.quarantined || row.ack_settlement !== "SEALED"
        || Math.abs(Math.floor(Date.now() / 1000) - signed.issuedAt) > 30) deny();
      return this.#db.prepare("UPDATE operator_recovery_floor SET"
        + " finalized_sequence=?,finalized_hash=?,ack_settlement='PROVISIONAL',"
        + " provisional_proof_hash=?,finalized_owner_generation=?"
        + " WHERE id=1 AND sequence=? AND last_hash=?"
        + " AND owner_generation=? AND quarantined=0 AND ack_settlement='SEALED'"
        + " AND finalized_sequence=? AND finalized_hash=?")
        .run(next.sequence, next.lastHash, proofHash(proof), proof.ownerGeneration,
          next.sequence, next.lastHash, proof.ownerGeneration,
          previous.sequence, previous.lastHash).changes === 1;
    }).immediate();
  }
  #assertSealPhysicalFresh(proof) {
    const observed = Date.now();
    if (!Number.isSafeInteger(observed) || observed < 1
      || !Number.isSafeInteger(proof?.physicalIssuedAt)
      || Math.abs(Math.floor(observed / 1000) - proof.physicalIssuedAt) > 30) deny();
  }
  sealAck(expected, proof) {
    head(expected);
    if (!proof || typeof proof !== "object"
      || !Number.isSafeInteger(proof.ownerGeneration)) deny();
    this.#assertSealPhysicalFresh(proof);
    const hash = proofHash(proof);
    const sealed = this.#db.transaction(() => {
      const row = this.#current();
      // BEGIN IMMEDIATE can block behind another process holding the SQLite
      // writer lock. The earlier freshness sample cannot authorize this CAS.
      this.#assertSealPhysicalFresh(proof);
      const changed = this.#db.prepare("UPDATE operator_recovery_floor SET ack_settlement='SEALED'"
        + " WHERE id=1 AND sequence=? AND last_hash=?"
        + " AND finalized_sequence=? AND finalized_hash=?"
        + " AND quarantined=0 AND ack_settlement='PROVISIONAL'"
        + " AND owner_generation=? AND finalized_owner_generation=?"
        + " AND owner_policy=? AND provisional_proof_hash=?")
        .run(expected.sequence, expected.lastHash, expected.sequence, expected.lastHash,
          proof.ownerGeneration, proof.ownerGeneration,
          proof.policySnapshot, hash).changes === 1;
      // A slow UPDATE or final SQL work must roll back before FULL COMMIT.
      if (changed) this.#assertSealPhysicalFresh(proof);
      return changed;
    }).immediate();
    if (!sealed) return false;
    // FULL COMMIT/fsync and remote response handling can outlive PG TTL.
    // Never advertise this as a fresh sealed ACK without one last readback.
    try {
      this.#assertSealPhysicalFresh(proof);
      const row = this.#current();
      if (row.quarantined !== 0 || row.ack_settlement !== "SEALED"
        || row.sequence !== expected.sequence || row.last_hash !== expected.lastHash
        || row.finalized_sequence !== expected.sequence
        || row.finalized_hash !== expected.lastHash
        || row.owner_generation !== proof.ownerGeneration
        || row.finalized_owner_generation !== proof.ownerGeneration
        || row.owner_policy !== proof.policySnapshot
        || row.provisional_proof_hash !== hash) deny();
      this.#assertSealPhysicalFresh(proof);
    } catch (_) {
      // Monotonic veto survives restart even when the SEALED commit succeeded
      // but its timely acknowledgement is uncertain. If fencing fails, DENY.
      let fenced = false;
      try {
        fenced = this.quarantineFinalizedAck(expected) === true;
        const veto = this.loadQuarantinedHead();
        if (veto.sequence !== expected.sequence || veto.lastHash !== expected.lastHash)
          fenced = false;
      } catch (_) { deny(); }
      if (!fenced) deny();
      return false;
    }
    return true;
  }
  close() { this.#db.close(); }
}

module.exports = { Zk1HistoricalRecoveryOperator, ZERO };
