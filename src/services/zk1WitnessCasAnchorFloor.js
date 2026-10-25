"use strict";

// Witness-owned, independent-of-CAS signed journal high-water store.
// Must run with separate storage and signing-key custody from the CAS host.
// A local SQLite file co-located with CAS offers NO independent rollback proof.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile } = require("./zk1PrivateSqlitePath");
const { Worker } = require("node:worker_threads");
const Database = require("better-sqlite3");
const { Zk1WitnessCasPhysicalAdmission } = require("./zk1WitnessCasPhysicalAdmission");
const { envelopeBinding, snapshotLocalDevicePolicy } =
  require("../../sync-client/rootark-sync-zk1-physical-binding");
const { verifyAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("../../sync-client/rootark-sync-authorization");

const RECORD_DOMAIN = Buffer.from("Root.ark/zk-1/cas-terminal-anchor/v1\0", "ascii");
const FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-anchor-floor/v1\0", "ascii");
const PHYSICAL_FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0", "ascii");
// Changing the signature domain makes missing original PG evidence fail closed.
// Existing v2 floors need an explicit external-owner-approved migration.
const PHYSICAL_FENCE_DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-inventory-fence/v3\0", "ascii");
const HISTORICAL_SYNC_DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0");
const RECOVERY_LEDGER_DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-recovery-ledger/v1\0");
// No TTL deletion is safe until an externally anchored compaction protocol
// proves every retired challenge is still permanently non-replayable.
const MAX_RECOVERY_CHALLENGES = 4096;
const RECORD_FIELDS = ["sequence", "reservation", "scope", "status", "ticketHash",
  "manifestHash", "terminalSeal", "previousHash", "signature"];
const RECORD_PAYLOAD = RECORD_FIELDS.slice(0, -1);
const ZERO = "0".repeat(64);
function fail() {
  const e = new Error("WITNESS_CAS_FLOOR_DENIED");
  e.code = e.message;
  throw e;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
  const result = Object.create(null);
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, "value")) fail();
    result[key] = d.value;
  }
  return result;
}
function digest(value) { return crypto.createHash("sha256").update(value).digest("hex"); }
function recoveryRowHash(row) {
  return digest(row.previous_hash + "\0" + JSON.stringify([
    row.sequence, row.nonce.toString("base64url"), row.operation_id,
    row.admission_hash, row.consumed_at_ms,
  ]));
}
function rowEvidence(row) {
  // Frame all SQL columns and their types, including historical rows. A single
  // streaming SHA-256 avoids 100k separate hash allocations at the history cap.
  // Newline disambiguates the end of each canonical JSON array.
  return JSON.stringify([row.sequence, row.line, row.hash, row.predecessor]) + "\n";
}
function physicalFenceEvidence(row) {
  return JSON.stringify([row.sequence, row.cas_hash, row.scope,
    row.operation_id, row.inventory_sequence, row.inventory_root,
    row.snapshot === null ? null : digest(row.snapshot),
    row.original_pg_evidence === null ? null : digest(row.original_pg_evidence),
    row.signature.toString("base64url")]) + "\n";
}
function physicalFenceMessage(row) {
  return Buffer.concat([PHYSICAL_FENCE_DOMAIN, Buffer.from(JSON.stringify([
    row.sequence, row.cas_hash, row.scope, row.operation_id, row.inventory_sequence,
    row.inventory_root, row.snapshot === null ? null : digest(row.snapshot),
    row.original_pg_evidence === null ? null : digest(row.original_pg_evidence),
  ]))]);
}
function id(value) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== 16) fail();
  return Buffer.from(value);
}
function validHex(value) { return typeof value === "string" && /^[a-f0-9]{64}$/.test(value); }
function spki(publicKey) { return publicKey.export({ type: "spki", format: "der" }); }
function parseRecord(line, pinned) {
  if (typeof line !== "string" || line.length < 100 || line.length > 2048
    || line.includes("\n") || line.includes("\r")) fail();
  let parsed;
  try { parsed = JSON.parse(line); }
  catch (_) { fail(); }
  const record = exact(parsed, RECORD_FIELDS);
  if (JSON.stringify(record) !== line || !Number.isSafeInteger(record.sequence)
    || record.sequence < 1 || record.sequence > 100000
    || typeof record.reservation !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(record.reservation)
    || typeof record.scope !== "string" || !/^[a-f0-9:]{40,400}$/.test(record.scope)
    || !["committed", "not-committed-final"].includes(record.status)
    || !validHex(record.ticketHash)
    || (record.manifestHash !== null && !validHex(record.manifestHash))
    || (record.status === "committed") !== (record.manifestHash !== null)
    || typeof record.terminalSeal !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(record.terminalSeal)
    || !validHex(record.previousHash)
    || typeof record.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(record.signature)) fail();
  const signature = Buffer.from(record.signature, "base64url");
  if (signature.length !== 64 || signature.toString("base64url") !== record.signature
    || !crypto.verify(null, Buffer.concat([RECORD_DOMAIN, Buffer.from(JSON.stringify(
      Object.fromEntries(RECORD_PAYLOAD.map((field) => [field, record[field]]))))]),
    pinned, signature)) fail();
  return { sequence: record.sequence, previousHash: record.previousHash,
    lastHash: digest(line), line, status: record.status, scope: record.scope };
}
function verifyFreshWitnessCasFloor({ signed, nonce, pinnedWitnessPublicKey,
  pinnedWitnessKeyId, pinnedStatusKeyId, minimumHead,
  requirePhysicalAdmission = false } = {}) {
  if (typeof requirePhysicalAdmission !== "boolean") fail();
  const fields = ["type", "witnessKeyId", "statusKeyId", "sequence",
    "lastHash", ...(requirePhysicalAdmission ? ["physicalFenceDigest"] : []),
    "nonce", "signature"];
  const value = exact(signed, fields);
  if (!(pinnedWitnessPublicKey instanceof crypto.KeyObject)
    || pinnedWitnessPublicKey.type !== "public"
    || pinnedWitnessPublicKey.asymmetricKeyType !== "ed25519"
    || value.type !== (requirePhysicalAdmission
      ? "rootark-zk1-witness-cas-physical-floor/v2"
      : "rootark-zk1-witness-cas-anchor-floor/v1")
    || value.witnessKeyId !== id(pinnedWitnessKeyId).toString("base64url")
    || value.statusKeyId !== id(pinnedStatusKeyId).toString("base64url")
    || (!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array))
    || nonce.byteLength !== 32
    || value.nonce !== Buffer.from(nonce).toString("base64url")
    || !Number.isSafeInteger(value.sequence) || value.sequence < 0
    || value.sequence > 100000 || !validHex(value.lastHash)
    || (requirePhysicalAdmission && !validHex(value.physicalFenceDigest))
    || (value.sequence === 0 && value.lastHash !== ZERO)
    || typeof value.signature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(value.signature)) fail();
  const signature = Buffer.from(value.signature, "base64url");
  const unsigned = Object.fromEntries(fields.slice(0, -1).map((key) => [key, value[key]]));
  if (signature.byteLength !== 64 || signature.toString("base64url") !== value.signature
    || !crypto.verify(null, Buffer.concat([requirePhysicalAdmission
      ? PHYSICAL_FLOOR_DOMAIN : FLOOR_DOMAIN,
      Buffer.from(JSON.stringify(unsigned))]), pinnedWitnessPublicKey, signature)) fail();
  if (minimumHead !== undefined) {
    // A strict external monotonic minimum must pin the physical fence too.
    // Accepting a valid CAS-only minimum would reopen a physical rollback
    // across client restart even though the current signed head is V2.
    const minimumKeys = requirePhysicalAdmission
      ? ["sequence", "lastHash", "physicalFenceDigest"]
      : ["sequence", "lastHash"];
    const minimum = exact(minimumHead, minimumKeys);
    if (!Number.isSafeInteger(minimum.sequence) || minimum.sequence < 0
      || !validHex(minimum.lastHash) || value.sequence < minimum.sequence
      || (value.sequence === minimum.sequence && value.lastHash !== minimum.lastHash)
      || (minimumKeys.length === 3 && (!validHex(minimum.physicalFenceDigest)
        || (value.sequence === minimum.sequence
          && value.physicalFenceDigest !== minimum.physicalFenceDigest)))) fail();
  }
  return Object.freeze({ sequence: value.sequence, lastHash: value.lastHash,
    ...(requirePhysicalAdmission ? { physicalFenceDigest: value.physicalFenceDigest } : {}) });
}
class Zk1WitnessCasAnchorFloor {
  #db;
  #status;
  #witness;
  #witnessId;
  #statusId;
  #identity;
  #trustedFloor = { sequence: 0, lastHash: ZERO };
  #verifiedChain = crypto.createHash("sha256");
  #verifiedChainDigest = digest("");
  #externalMinimum;
  #filename;
  #fileIdentity;
  #closed = false;
  #activeHeadVerifications = 0;
  #generation = 0;
  #attestedAdmission;
  #inventoryHeads = new Map();
  #physicalFenceChain = crypto.createHash("sha256");
  #physicalFenceDigest = digest("");
  #auditedOriginalPgDigest = null;
  #advanceQueue = Promise.resolve();
  #historicalEnabled = false;
  #historicalHead = Object.freeze({ sequence: 0, lastHash: ZERO });
  #recoveryHead = Object.freeze({ sequence: 0, lastHash: ZERO });
  #pinnedRecoveryHead;
  #externalRecoveryAuthority;
  #trustedSyncDevicePolicyProvider;
  // Read-only capability for the separately reviewed mTLS issuer transport.
  // Never advertise legacy/writer-signed floors or a closed issuer as nonce
  // bound; strict mode always uses the caller nonce for PG AND witness floor.
  get supportsClientHistoricalNonce() {
    if (!this.#historicalEnabled || this.#closed
      || !(this.#attestedAdmission instanceof Zk1WitnessCasPhysicalAdmission)
      || typeof this.#trustedSyncDevicePolicyProvider !== "function") return false;
    try { this.#assertExternalRecoveryHead(); return true; }
    catch (_) { return false; }
  }
  constructor(filename, { bootstrapNew = false, witnessKeyId, witnessPrivateKey,
    statusKeyId, statusPublicKey, trustedMinimumHead,
    attestedAdmission = null, enableSyncHistoricalIssuer = false,
    trustedHistoricalAdmissionHead, trustedRecoveryNonceHead,
    trustedRecoveryNonceAuthority,
    trustedSyncDevicePolicyProvider } = {}) {
    if (typeof enableSyncHistoricalIssuer !== "boolean"
      || (enableSyncHistoricalIssuer && (!attestedAdmission
        || typeof trustedSyncDevicePolicyProvider !== "function"
        || !trustedRecoveryNonceAuthority
        || typeof trustedRecoveryNonceAuthority.loadHead !== "function"
        || typeof trustedRecoveryNonceAuthority.compareAndAdvance !== "function"))
      || (!enableSyncHistoricalIssuer && trustedRecoveryNonceAuthority !== undefined)) fail();
    this.#historicalEnabled = enableSyncHistoricalIssuer;
    this.#externalRecoveryAuthority = trustedRecoveryNonceAuthority || null;
    // Operator-supplied trust context, independent of the incoming request:
    // remote callers may NEVER provide their own device pins or revocations.
    this.#trustedSyncDevicePolicyProvider = enableSyncHistoricalIssuer
      ? trustedSyncDevicePolicyProvider : null;
    if (enableSyncHistoricalIssuer) {
      if (!bootstrapNew && !trustedHistoricalAdmissionHead) fail();
      if (trustedHistoricalAdmissionHead !== undefined) {
        const pinned = exact(trustedHistoricalAdmissionHead, ["sequence", "lastHash"]);
        if (!Number.isSafeInteger(pinned.sequence) || pinned.sequence < 0
          || pinned.sequence > 100000 || !validHex(pinned.lastHash)
          || (pinned.sequence === 0 && pinned.lastHash !== ZERO)
          || (bootstrapNew && (pinned.sequence !== 0 || pinned.lastHash !== ZERO))) fail();
        this.#historicalHead = Object.freeze({ ...pinned });
      }
      if (trustedRecoveryNonceHead !== undefined) {
        const pinned = exact(trustedRecoveryNonceHead, ["sequence", "lastHash"]);
        if (!Number.isSafeInteger(pinned.sequence) || pinned.sequence < 0
          || pinned.sequence > MAX_RECOVERY_CHALLENGES || !validHex(pinned.lastHash)
          || (pinned.sequence === 0 && pinned.lastHash !== ZERO)
          || (bootstrapNew && (pinned.sequence !== 0 || pinned.lastHash !== ZERO))) fail();
        this.#pinnedRecoveryHead = Object.freeze({ ...pinned });
      }
      // The initial externally retained minimum must be acquired BEFORE
      // bootstrapping even an empty local ledger; no mutable DB or request
      // JSON is permitted to supply the authority.
      if (bootstrapNew) this.#assertExternalRecoveryHead();
    }
    if (trustedMinimumHead !== undefined) {
      // Strict restart's independent high-water anchor must bind the physical
      // witness chain, not merely its signed CAS sequence and last hash.
      const strict = attestedAdmission !== null;
      const floor = exact(trustedMinimumHead, ["sequence", "lastHash",
        ...(strict ? ["physicalFenceDigest"] : [])]);
      if (!Number.isSafeInteger(floor.sequence) || floor.sequence < 0
        || floor.sequence > 100000 || !validHex(floor.lastHash)
        || (floor.sequence === 0 && floor.lastHash !== ZERO)
        || (strict && (!validHex(floor.physicalFenceDigest)
          || (floor.sequence === 0 && floor.physicalFenceDigest !== digest(""))))) fail();
      // A caller-retained owner floor cannot be mutated after construction.
      this.#externalMinimum = Object.freeze({ sequence: floor.sequence,
        lastHash: floor.lastHash,
        ...(strict ? { physicalFenceDigest: floor.physicalFenceDigest } : {}) });
      if (bootstrapNew && floor.sequence !== 0) fail();
    }
    if (typeof filename !== "string" || !path.isAbsolute(filename)
      || !(witnessPrivateKey instanceof crypto.KeyObject)
      || witnessPrivateKey.type !== "private" || witnessPrivateKey.asymmetricKeyType !== "ed25519"
      || !(statusPublicKey instanceof crypto.KeyObject)
      || statusPublicKey.type !== "public" || statusPublicKey.asymmetricKeyType !== "ed25519") fail();
    this.#witnessId = id(witnessKeyId);
    this.#statusId = id(statusKeyId);
    this.#witness = witnessPrivateKey;
    this.#status = statusPublicKey;
    if (this.#witnessId.equals(this.#statusId)
      || spki(crypto.createPublicKey(witnessPrivateKey)).equals(spki(statusPublicKey))) fail();
    if (attestedAdmission !== null) {
      if (!(attestedAdmission instanceof Zk1WitnessCasPhysicalAdmission)) fail();
      try {
        attestedAdmission.assertSeparateFrom(statusPublicKey,
          crypto.createPublicKey(witnessPrivateKey));
      } catch (_) { fail(); }
      this.#attestedAdmission = attestedAdmission;
    }
    const absolute = path.resolve(filename);
    const exists = fs.existsSync(absolute);
    if (exists === bootstrapNew || (exists && !fs.lstatSync(absolute).isFile())) fail();
    // A valid, witness-signed SQLite prefix is not an external monotonic
    // anchor. Strict restart MUST be supplied the independently retained
    // exact last known head; otherwise a whole-file restore can rewind both
    // the CAS journal and its matching signed inventory fences.
    if (this.#attestedAdmission && exists && !this.#externalMinimum) fail();
    try {
      if (exists) assertPrivateSqliteFile(absolute);
      else ensurePrivateSqliteDirectory(absolute);
    } catch (_) { fail(); }
    if (!exists) {
      const fd = fs.openSync(absolute, "wx", 0o600);
      fs.closeSync(fd);
    }
    try { assertPrivateSqliteFile(absolute); } catch (_) { fail(); }
    const db = new Database(absolute, { fileMustExist: true });
    try {
      assertPrivateSqliteFile(absolute);
      this.#filename = absolute;
      this.#fileIdentity = fs.statSync(absolute, { bigint: true });
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      db.pragma("foreign_keys = ON");
      if (db.pragma("integrity_check", { simple: true }) !== "ok") fail();
      this.#identity = JSON.stringify({
        type: "rootark-zk1-witness-cas-floor/v1",
        witnessKeyId: this.#witnessId.toString("base64url"),
        witnessFingerprint: digest(spki(crypto.createPublicKey(witnessPrivateKey))),
        statusKeyId: this.#statusId.toString("base64url"),
        statusFingerprint: digest(spki(statusPublicKey)),
        ...(this.#attestedAdmission ? {
          normativePhysicalAdmissionDigest: this.#attestedAdmission.policyDigest(),
          physicalFenceSchema: "operation-id-v3-original-pg-attestor",
        } : {}),
        ...(this.#historicalEnabled ? { historicalSyncAdmissionIssuer: true } : {}),
      });
      if (exists) {
        const row = db.prepare("SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
        if (!row || row.identity !== this.#identity) fail();
      } else {
        db.exec(`CREATE TABLE witness_cas_floor_identity (
          id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL);
          CREATE TABLE witness_cas_floor_event (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            line TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
            predecessor TEXT NOT NULL);`);
        if (this.#attestedAdmission) {
          db.exec(`CREATE TABLE witness_cas_inventory_fence (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            cas_hash TEXT NOT NULL, scope TEXT NOT NULL,
            operation_id TEXT, inventory_sequence INTEGER, inventory_root TEXT,
            snapshot BLOB, original_pg_evidence BLOB,
            signature BLOB NOT NULL);`);
        }
        if (this.#historicalEnabled) {
          db.exec(`CREATE TABLE witness_cas_sync_historical_admission (
            sequence INTEGER PRIMARY KEY CHECK(sequence>=1),
            operation_id TEXT NOT NULL UNIQUE,
            previous_hash TEXT NOT NULL, receipt TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE);
            CREATE TRIGGER no_historical_admission_update
            BEFORE UPDATE ON witness_cas_sync_historical_admission
            BEGIN SELECT RAISE(ABORT,'HISTORICAL_ADMISSION_LOCKED'); END;
            CREATE TRIGGER no_historical_admission_delete
            BEFORE DELETE ON witness_cas_sync_historical_admission
            BEGIN SELECT RAISE(ABORT,'HISTORICAL_ADMISSION_LOCKED'); END;
            CREATE TABLE witness_cas_sync_historical_issue_nonce (
              admission_sequence INTEGER PRIMARY KEY CHECK(admission_sequence>=1),
              operation_id TEXT NOT NULL UNIQUE,
              admission_hash TEXT NOT NULL,
              nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=32),
              FOREIGN KEY(admission_sequence) REFERENCES witness_cas_sync_historical_admission(sequence),
              FOREIGN KEY(operation_id) REFERENCES witness_cas_sync_historical_admission(operation_id));
            CREATE TRIGGER no_historical_issue_nonce_update
            BEFORE UPDATE ON witness_cas_sync_historical_issue_nonce
            BEGIN SELECT RAISE(ABORT,'HISTORICAL_NONCE_LOCKED'); END;
            CREATE TRIGGER no_historical_issue_nonce_delete
            BEFORE DELETE ON witness_cas_sync_historical_issue_nonce
            BEGIN SELECT RAISE(ABORT,'HISTORICAL_NONCE_LOCKED'); END;
            CREATE TABLE witness_cas_sync_historical_recovery_nonce (
              sequence INTEGER PRIMARY KEY CHECK(sequence>=1 AND sequence<=4096),
              nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=32),
              operation_id TEXT NOT NULL,
              admission_hash TEXT NOT NULL,
              consumed_at_ms INTEGER NOT NULL CHECK(consumed_at_ms>=1),
              previous_hash TEXT NOT NULL,
              hash TEXT NOT NULL UNIQUE,
              FOREIGN KEY(operation_id) REFERENCES witness_cas_sync_historical_admission(operation_id));
            CREATE TRIGGER no_historical_recovery_nonce_update
            BEFORE UPDATE ON witness_cas_sync_historical_recovery_nonce
            BEGIN SELECT RAISE(ABORT,'HISTORICAL_RECOVERY_LOCKED'); END;
            CREATE TRIGGER no_historical_recovery_nonce_delete
            BEFORE DELETE ON witness_cas_sync_historical_recovery_nonce
            BEGIN SELECT RAISE(ABORT,'HISTORICAL_RECOVERY_LOCKED'); END;
            CREATE TABLE witness_cas_sync_historical_recovery_head (
              id INTEGER PRIMARY KEY CHECK(id=1),
              sequence INTEGER NOT NULL CHECK(sequence>=0 AND sequence<=4096),
              last_hash TEXT NOT NULL,
              signature BLOB NOT NULL CHECK(length(signature)=64));`);
        }
        db.prepare("INSERT INTO witness_cas_floor_identity VALUES(1,?)").run(this.#identity);
        if (this.#historicalEnabled) {
          const initial = { sequence: 0, lastHash: ZERO };
          db.prepare("INSERT INTO witness_cas_sync_historical_recovery_head"
            + " (id,sequence,last_hash,signature) VALUES(1,?,?,?)").run(
              0, ZERO, this.#signRecoveryHead(initial));
        }
      }
      const state = db.prepare("SELECT sequence,hash FROM witness_cas_floor_event ORDER BY sequence DESC LIMIT 1").get();
      const count = db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      if (count !== (state?.sequence || 0) || count > 100000) fail();
      if (this.#attestedAdmission && exists
        && (this.#externalMinimum.sequence !== count
          || this.#externalMinimum.lastHash !== (state?.hash || ZERO))) fail();
      if (this.#externalMinimum) {
        if (count < this.#externalMinimum.sequence) fail();
        if (this.#externalMinimum.sequence > 0) {
          const atMinimum = db.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=?")
            .get(this.#externalMinimum.sequence);
          if (atMinimum?.hash !== this.#externalMinimum.lastHash) fail();
        }
      }
      // Verify the entire bounded signed history at startup. A DB editor must
      // not be able to replace a record and forge a consistent SQL hash.
      let previous = ZERO;
      const verifiedChain = crypto.createHash("sha256");
      const signedRows = new Map();
      for (const row of db.prepare("SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event ORDER BY sequence" ).iterate()) {
        const event = parseRecord(row.line, this.#status);
        if (event.sequence !== row.sequence || event.previousHash !== previous
          || row.predecessor !== previous || event.lastHash !== row.hash) fail();
        verifiedChain.update(rowEvidence(row));
        signedRows.set(row.sequence, event);
        previous = event.lastHash;
      }
      if (this.#attestedAdmission) {
        // Every CAS event has one independently witness-signed physical-fence
        // decision. A writable SQL actor cannot lower the inventory minimum
        // while leaving CAS's signed high-water unchanged.
        let number = 0;
        let totalSnapshotBytes = 0;
        const physicalChain = crypto.createHash("sha256");
        for (const row of db.prepare(
          "SELECT * FROM witness_cas_inventory_fence ORDER BY sequence").iterate()) {
          number += 1;
          const source = signedRows.get(number);
          if (row.sequence !== number || !source || source.lastHash !== row.cas_hash
            || source.scope !== row.scope || !Buffer.isBuffer(row.signature)
            || row.signature.length !== 64
            || !crypto.verify(null, physicalFenceMessage(row),
              crypto.createPublicKey(this.#witness), row.signature)) fail();
          if (source.status === "committed") {
            if (typeof row.operation_id !== "string"
              || !/^[a-f0-9]{32}$/.test(row.operation_id)
              || !Number.isSafeInteger(row.inventory_sequence)
              || row.inventory_sequence < 1 || !validHex(row.inventory_root)
              || !Buffer.isBuffer(row.snapshot)
              || row.snapshot.length < 1
              || row.snapshot.length > 2 * 1024 * 1024
              || !Buffer.isBuffer(row.original_pg_evidence)
              || row.original_pg_evidence.length < 1
              || row.original_pg_evidence.length > 8192) fail();
            totalSnapshotBytes += row.snapshot.length;
            if (totalSnapshotBytes > 64 * 1024 * 1024) fail();
            const preceding = this.#inventoryHeads.get(row.scope);
            if (preceding && row.inventory_sequence <= preceding.head.sequence) fail();
            this.#inventoryHeads.set(row.scope, {
              head: { sequence: row.inventory_sequence,
                root: Buffer.from(row.inventory_root, "hex") },
              snapshot: Buffer.from(row.snapshot),
            });
          } else if (row.operation_id !== null || row.inventory_sequence !== null
            || row.inventory_root !== null
            || row.snapshot !== null || row.original_pg_evidence !== null) fail();
          physicalChain.update(physicalFenceEvidence(row));
        }
        if (number !== count) fail();
        this.#physicalFenceChain = physicalChain;
        this.#physicalFenceDigest = physicalChain.copy().digest("hex");
      }
      if (this.#attestedAdmission && this.#externalMinimum
        && this.#externalMinimum.physicalFenceDigest !== this.#physicalFenceDigest) fail();
      if (this.#historicalEnabled) {
        const triggerNames = new Set(db.prepare(
          "SELECT name FROM sqlite_master WHERE type='trigger'").all().map((r) => r.name));
        if (!triggerNames.has("no_historical_admission_update")
          || !triggerNames.has("no_historical_admission_delete")) fail();
        let sequence = 0;
        let previousHash = ZERO;
        let totalBytes = 0;
        for (const row of db.prepare(
          "SELECT * FROM witness_cas_sync_historical_admission ORDER BY sequence").iterate()) {
          sequence += 1;
          totalBytes += Buffer.byteLength(row.receipt || "");
          if (sequence > 100000 || totalBytes > 64 * 1024 * 1024) fail();
          if (row.sequence !== sequence || row.previous_hash !== previousHash
            || !validHex(row.hash) || typeof row.receipt !== "string"
            || row.receipt.length > 4096 || row.hash !== digest(previousHash + "\0" + row.receipt)) fail();
          let admission;
          try { admission = JSON.parse(row.receipt); } catch (_) { fail(); }
          if (JSON.stringify(admission) !== row.receipt
            || admission.operationId !== row.operation_id
            || typeof admission.signature !== "string") fail();
          const { signature, ...unsigned } = admission;
          if (!crypto.verify(null, Buffer.concat([HISTORICAL_SYNC_DOMAIN,
            Buffer.from(JSON.stringify(unsigned))]),
          crypto.createPublicKey(this.#witness), Buffer.from(signature, "base64url"))) fail();
          previousHash = row.hash;
        }
        if (exists && (this.#historicalHead.sequence !== sequence
          || this.#historicalHead.lastHash !== previousHash)) fail();
        this.#historicalHead = Object.freeze({ sequence, lastHash: previousHash });
        // A pre-upgrade database does not contain the original ISSUE nonce.
        // Never silently migrate it to an all-clear anti-replay ledger: safe
        // recovery requires the nonce co-committed with the original receipt.
        this.#assertHistoricalNonceIntegrity(db);
        this.#assertExternalRecoveryHead();
      }
      this.#verifiedChain = verifiedChain;
      this.#verifiedChainDigest = verifiedChain.copy().digest("hex");
      this.#trustedFloor = Object.freeze({ sequence: state?.sequence || 0,
        lastHash: state?.hash || ZERO });
      this.#db = db;
    } catch (error) { db.close(); fail(); }
  }
  #quickHeadCheck() {
    return this.#db.transaction(() => {
      const identity = this.#db.prepare(
        "SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
      const row = this.#db.prepare("SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event"
        + " ORDER BY sequence DESC LIMIT 1").get();
      const count = this.#db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      const trusted = this.#trustedFloor;
      if (!identity || identity.identity !== this.#identity || count > 100000
        || count !== trusted.sequence || count !== (row?.sequence || 0)
        || (row?.hash || ZERO) !== trusted.lastHash
        || (this.#externalMinimum && (count < this.#externalMinimum.sequence
          || (this.#externalMinimum.sequence > 0
            && this.#db.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=?")
              .get(this.#externalMinimum.sequence)?.hash !== this.#externalMinimum.lastHash)))) fail();
      if (row) {
        const signed = parseRecord(row.line, this.#status);
        if (signed.sequence !== row.sequence || signed.lastHash !== row.hash
          || signed.previousHash !== row.predecessor) fail();
      }
      return trusted;
    }).deferred();
  }
  #assertPhysicalFenceIntegrity() {
    if (!this.#attestedAdmission) return;
    const physical = crypto.createHash("sha256");
    let sequence = 0;
    let totalSnapshotBytes = 0;
    let totalOriginalPgBytes = 0;
    for (const row of this.#db.prepare(
      "SELECT * FROM witness_cas_inventory_fence ORDER BY sequence").iterate()) {
      sequence += 1;
      if (row.sequence !== sequence || !Buffer.isBuffer(row.signature)
        || row.signature.length !== 64
        || (row.snapshot !== null && !Buffer.isBuffer(row.snapshot))
        || (row.original_pg_evidence !== null
          && (!Buffer.isBuffer(row.original_pg_evidence)
            || row.original_pg_evidence.length > 8192))) fail();
      totalSnapshotBytes += row.snapshot?.length || 0;
      totalOriginalPgBytes += row.original_pg_evidence?.length || 0;
      if (totalSnapshotBytes > 64 * 1024 * 1024
        || totalOriginalPgBytes > 64 * 1024 * 1024) fail();
      physical.update(physicalFenceEvidence(row));
    }
    if (sequence !== this.#trustedFloor.sequence
      || physical.digest("hex") !== this.#physicalFenceDigest) fail();
  }
  #assertFileIdentity() {
    try { assertPrivateSqliteFile(this.#filename); } catch (_) { fail(); }
    const now = fs.statSync(this.#filename, { bigint: true });
    if (!now.isFile() || now.dev !== this.#fileIdentity.dev
      || now.ino !== this.#fileIdentity.ino) fail();
  }
  #fileMutationStamp() {
    // data_version detects committed SQL changes from another connection.
    // Also detect visible direct file/WAL edits between the worker's snapshot
    // and the signature decision (such writes may bypass SQLite counters).
    const stamp = (filename) => {
      let stat;
      try { stat = fs.lstatSync(filename, { bigint: true }); }
      catch (error) { if (error?.code === "ENOENT") return null; throw error; }
      if (!stat.isFile() || stat.isSymbolicLink()) fail();
      return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs]
        .map((v) => v.toString()).join(":");
    };
    return JSON.stringify([stamp(this.#filename), stamp(this.#filename + "-wal")]);
  }
  #signHead(nonce, value) {
    const strict = Boolean(this.#attestedAdmission);
    const unsigned = { type: strict
      ? "rootark-zk1-witness-cas-physical-floor/v2"
      : "rootark-zk1-witness-cas-anchor-floor/v1",
      witnessKeyId: this.#witnessId.toString("base64url"),
      statusKeyId: this.#statusId.toString("base64url"),
      sequence: value.sequence, lastHash: value.lastHash,
      ...(strict ? { physicalFenceDigest: this.#physicalFenceDigest } : {}),
      nonce: nonce.toString("base64url") };
    const signature = crypto.sign(null, Buffer.concat([strict
      ? PHYSICAL_FLOOR_DOMAIN : FLOOR_DOMAIN,
      Buffer.from(JSON.stringify(unsigned))]), this.#witness);
    return Object.freeze({ ...unsigned, signature: signature.toString("base64url") });
  }
  // HTTPS-only path. Full SQLite snapshot verification executes off the HTTP
  // thread; the signer private key never enters the worker. Limit concurrent
  // snapshots so hostile clients cannot create an unbounded worker/DB pool.
  async freshHeadAsync({ nonce }) {
    if ((!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array))
      || nonce.byteLength !== 32) fail();
    const challenge = Buffer.from(nonce); // pin caller's nonce before any await
    if (this.#closed || this.#activeHeadVerifications >= 2) fail();
    this.#activeHeadVerifications += 1;
    try {
      if (this.#attestedAdmission) await this.auditRetainedPhysicalEvidence();
      this.#assertFileIdentity();
      const initialMutationStamp = this.#fileMutationStamp();
      const initialDataVersion = this.#db.pragma("data_version", { simple: true });
      this.#quickHeadCheck();
      const pinned = { sequence: this.#trustedFloor.sequence,
        lastHash: this.#trustedFloor.lastHash,
        chainDigest: this.#verifiedChainDigest, generation: this.#generation };
      const dbInfo = { filename: this.#filename, identity: this.#identity,
        sequence: pinned.sequence, lastHash: pinned.lastHash,
        chainDigest: pinned.chainDigest,
        fileDev: this.#fileIdentity.dev.toString(),
        fileIno: this.#fileIdentity.ino.toString() };
      await new Promise((resolve, reject) => {
        const worker = new Worker(path.join(__dirname, "zk1WitnessCasAnchorHeadVerifierWorker.js"),
          { workerData: dbInfo });
        let verified = false;
        let settled = false;
        const timer = setTimeout(() => { worker.terminate(); finish(false); }, 15000);
        const finish = (ok) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (ok) resolve();
          else reject(new Error("WITNESS_CAS_FLOOR_DENIED"));
        };
        worker.on("message", (result) => { if (result === "VERIFIED") verified = true; else finish(false); });
        worker.once("error", () => finish(false));
        worker.once("exit", (code) => finish(code === 0 && verified));
      });
      // Any CAS append or external SQLite writer during the snapshot invalidates
      // the completed proof. Recheck the authenticated final row before signing.
      if (this.#closed || this.#generation !== pinned.generation
        || this.#verifiedChainDigest !== pinned.chainDigest
        || this.#db.pragma("data_version", { simple: true }) !== initialDataVersion
        || this.#fileMutationStamp() !== initialMutationStamp) fail();
      this.#assertFileIdentity();
      const fresh = this.#quickHeadCheck();
      this.#assertPhysicalFenceIntegrity();
      if (this.#db.pragma("data_version", { simple: true }) !== initialDataVersion
        || this.#fileMutationStamp() !== initialMutationStamp
        || fresh.sequence !== pinned.sequence || fresh.lastHash !== pinned.lastHash) fail();
      return this.#signHead(challenge, fresh);
    } catch (_) { fail(); }
    finally { this.#activeHeadVerifications -= 1; }
  }
  head() {
    try {
      return this.#db.transaction(() => {
      // A hostile SQLite editor may mutate files or rows *after* witness
      // bootstrap. Never sign an unsigned or rewound SQL head. The final
      // signer-verified row and identity are rechecked on EVERY lookup.
      const identity = this.#db.prepare(
        "SELECT identity FROM witness_cas_floor_identity WHERE id=1").get();
      const row = this.#db.prepare(
        "SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event"
          + " ORDER BY sequence DESC LIMIT 1").get();
      const count = this.#db.prepare("SELECT COUNT(*) AS n FROM witness_cas_floor_event").get().n;
      const trusted = this.#trustedFloor;
      if (!identity || identity.identity !== this.#identity
        || count !== (row?.sequence || 0) || count > 100000
        || count !== trusted.sequence
        || (row?.hash || ZERO) !== trusted.lastHash) fail();
      // An attacker with SQL write access can corrupt any *earlier* event and
      // leave the final signed head untouched. Verify the full immutable
      // snapshot before signing a fresh receipt, not only the last SQL row.
      let sequence = 0;
      const liveChain = crypto.createHash("sha256");
      for (const checked of this.#db.prepare(
        "SELECT sequence,line,hash,predecessor FROM witness_cas_floor_event ORDER BY sequence").iterate()) {
        sequence += 1;
        if (checked.sequence !== sequence) fail();
        liveChain.update(rowEvidence(checked));
      }
      if (sequence !== count || liveChain.digest("hex") !== this.#verifiedChainDigest) fail();
      this.#assertPhysicalFenceIntegrity();
      if (this.#externalMinimum && (count < this.#externalMinimum.sequence
        || (this.#externalMinimum.sequence > 0
          && this.#db.prepare("SELECT hash FROM witness_cas_floor_event WHERE sequence=?")
            .get(this.#externalMinimum.sequence)?.hash !== this.#externalMinimum.lastHash))) fail();
      if (row) {
        const signed = parseRecord(row.line, this.#status);
        if (signed.sequence !== row.sequence || signed.lastHash !== row.hash
          || signed.previousHash !== row.predecessor) fail();
      }
      return Object.freeze({ ...trusted });
      }).deferred();
    } catch (_) { fail(); }
  }
  // Independent witness-owned evidence that an EXACT operation was included
  // in a physically attested, owner-authorized CAS terminal transition. The
  // signed floor is produced only after the full on-disk SQLite history and
  // physical-fence chain have been verified. This does NOT issue a Sync v2
  // historical admission receipt or assert fresh PostgreSQL readback now.
  async proveCommittedPhysicalFence({ scope, operationId, inventorySequence,
    inventoryRoot, nonce } = {}) {
    try {
      await this.auditRetainedPhysicalEvidence();
      if (!this.#attestedAdmission || this.#closed
        || !scope || typeof scope !== "object"
        || ![Object.prototype, null].includes(Object.getPrototypeOf(scope))
        || Reflect.ownKeys(scope).length !== 3
        || !["account_id", "compartment_id", "keyring_id"].every((name) =>
          Object.hasOwn(scope, name))) fail();
      const account = id(scope.account_id);
      const compartment = Buffer.from(scope.compartment_id);
      const keyring = id(scope.keyring_id);
      const operation = id(operationId);
      const expectedRoot = Buffer.from(inventoryRoot);
      const challenge = Buffer.from(nonce);
      if (compartment.length < 1 || compartment.length > 128
        || expectedRoot.length !== 32 || challenge.length !== 32
        || !Number.isSafeInteger(inventorySequence)
        || inventorySequence < 1) fail();
      const expectedScope = account.toString("hex") + ":" + compartment.length
        + ":" + compartment.toString("hex") + ":" + keyring.toString("hex");
      const signedFloor = await this.freshHeadAsync({ nonce: challenge });
      const rows = this.#db.prepare(
        "SELECT * FROM witness_cas_inventory_fence WHERE operation_id=? AND scope=?")
        .all(operation.toString("hex"), expectedScope);
      if (rows.length !== 1) fail();
      const row = rows[0];
      if (row.sequence > signedFloor.sequence
        || row.inventory_sequence !== inventorySequence
        || row.inventory_root !== expectedRoot.toString("hex")
        || !Buffer.isBuffer(row.signature) || row.signature.length !== 64
        || !crypto.verify(null, physicalFenceMessage(row),
          crypto.createPublicKey(this.#witness), row.signature)) fail();
      const committed = this.#db.prepare(
        "SELECT line,hash FROM witness_cas_floor_event WHERE sequence=?")
        .get(row.sequence);
      if (!committed || committed.hash !== row.cas_hash
        || parseRecord(committed.line, this.#status).status !== "committed") fail();
      const after = this.head();
      if (after.sequence !== signedFloor.sequence
        || after.lastHash !== signedFloor.lastHash) fail();
      return Object.freeze({ signedFloor, committedSequence: row.sequence,
        operationId: Buffer.from(operation), inventorySequence,
        inventoryRoot: Buffer.from(expectedRoot),
        authorizesHistoricalRead: false, authorizesIo: false });
    } catch (_) { fail(); }
  }
  // Revalidate ORIGINAL independent PostgreSQL signatures from SQLite after
  // restart without opening PostgreSQL. This is a historical observation only.
  async auditRetainedPhysicalEvidence() {
    try {
      if (!this.#attestedAdmission || this.#closed) fail();
      this.head();
      this.#assertPhysicalFenceIntegrity();
      const before = this.#physicalFenceDigest;
      const version = this.#db.pragma("data_version", { simple: true });
      const rows = this.#db.prepare(
        "SELECT * FROM witness_cas_inventory_fence ORDER BY sequence").all();
      let total = 0;
      let verifiedCommitted = 0;
      if (this.#auditedOriginalPgDigest !== before) {
        for (const row of rows) {
          total += row.original_pg_evidence?.length || 0;
          if (total > 64 * 1024 * 1024) fail();
          if (row.original_pg_evidence === null) continue;
          const verified = await this.#attestedAdmission.verifyRetainedPhysicalEvidence(
            row.original_pg_evidence);
          if (!verified.verifiedOriginalPgSignature
            || verified.scope !== row.scope
            || verified.operationId.toString("hex") !== row.operation_id
            || verified.inventorySequence !== row.inventory_sequence
            || verified.inventoryRoot.toString("hex") !== row.inventory_root) fail();
          verifiedCommitted++;
        }
      } else {
        verifiedCommitted = rows.filter((row) => row.original_pg_evidence !== null).length;
      }
      if (rows.length !== this.#trustedFloor.sequence
        || this.#db.pragma("data_version", { simple: true }) !== version) fail();
      this.#assertPhysicalFenceIntegrity();
      if (this.#physicalFenceDigest !== before) fail();
      this.#auditedOriginalPgDigest = before;
      return Object.freeze({ verifiedCommitted, currentPgReadbackProven: false,
        externalDurabilityProven: false });
    } catch (_) { fail(); }
  }
  historicalAdmissionHead() {
    if (!this.#historicalEnabled || this.#closed) fail();
    this.head();
    this.#assertHistoricalIntegrity();
    return Object.freeze({ ...this.#historicalHead });
  }
  historicalRecoveryNonceHead() {
    if (!this.#historicalEnabled || this.#closed) fail();
    this.head();
    this.#assertHistoricalIntegrity();
    this.#assertExternalRecoveryHead();
    // Operator-retained off-host minimum is needed to detect restoration of
    // an ENTIRE previously valid signed SQLite replay ledger snapshot.
    return Object.freeze({ ...this.#recoveryHead });
  }
  #recoveryHeadMessage({ sequence, lastHash }) {
    return Buffer.concat([RECOVERY_LEDGER_DOMAIN, Buffer.from(JSON.stringify([
      this.#witnessId.toString("base64url"), this.#statusId.toString("base64url"),
      sequence, lastHash,
    ]))]);
  }
  #readExternallyCommittedRecoveryHead() {
    if (!this.#externalRecoveryAuthority) fail();
    // The operator-provisioned external reader MUST load committed durable
    // state on every invocation. Promises/remote unavailability are not
    // implicitly successful: this API deliberately requires synchronous
    // independently durable admission fencing.
    let observed;
    try { observed = this.#externalRecoveryAuthority.loadHead(); }
    catch (_) { fail(); }
    const head = exact(observed, ["sequence", "lastHash"]);
    if (!Number.isSafeInteger(head.sequence)
      || head.sequence < 0 || head.sequence > MAX_RECOVERY_CHALLENGES
      || !validHex(head.lastHash)
      || (head.sequence === 0 && head.lastHash !== ZERO)) fail();
    return Object.freeze({ sequence: head.sequence, lastHash: head.lastHash });
  }
  #assertExternalRecoveryHead() {
    const external = this.#readExternallyCommittedRecoveryHead();
    if (external.sequence !== this.#recoveryHead.sequence
      || external.lastHash !== this.#recoveryHead.lastHash) fail();
  }
  #commitExternalRecoveryHead(previous, next) {
    const loaded = this.#readExternallyCommittedRecoveryHead();
    if (loaded.sequence !== previous.sequence
      || loaded.lastHash !== previous.lastHash) fail();
    let acknowledged;
    try {
      acknowledged = this.#externalRecoveryAuthority.compareAndAdvance(
        Object.freeze({ ...previous }), Object.freeze({ ...next }));
    } catch (_) { fail(); }
    // Only explicit durable CAS acknowledgment is accepted. Re-read from
    // external custody *after* the CAS, before any HTTP success response.
    if (acknowledged !== true) fail();
    this.#assertExternalRecoveryHead();
  }
  #signRecoveryHead(head) {
    return crypto.sign(null, this.#recoveryHeadMessage(head), this.#witness);
  }
  #assertHistoricalNonceIntegrity(db) {
    const schema = new Set(db.prepare(
      "SELECT name FROM sqlite_master WHERE type IN ('table','trigger','index')")
      .all().map((row) => row.name));
    for (const name of ["witness_cas_sync_historical_issue_nonce",
      "witness_cas_sync_historical_recovery_nonce",
      "witness_cas_sync_historical_recovery_head",
      "no_historical_issue_nonce_update", "no_historical_issue_nonce_delete",
      "no_historical_recovery_nonce_update", "no_historical_recovery_nonce_delete"]) {
      if (!schema.has(name)) fail();
    }
    // The original challenge is mandatory for EVERY signed admission. No
    // retroactive nonce can be invented for an old signed receipt.
    const originals = db.prepare(
      "SELECT a.sequence,a.operation_id,a.hash,i.admission_sequence,"
      + "i.operation_id AS nonce_operation,i.admission_hash,i.nonce"
      + " FROM witness_cas_sync_historical_admission a"
      + " LEFT JOIN witness_cas_sync_historical_issue_nonce i"
      + " ON i.admission_sequence=a.sequence ORDER BY a.sequence").all();
    if (originals.length !== this.#historicalHead.sequence) fail();
    if (db.prepare("SELECT COUNT(*) AS n FROM witness_cas_sync_historical_issue_nonce")
      .get().n !== this.#historicalHead.sequence) fail();
    for (const row of originals) {
      if (row.sequence !== row.admission_sequence
        || row.operation_id !== row.nonce_operation
        || row.hash !== row.admission_hash
        || !Buffer.isBuffer(row.nonce) || row.nonce.length !== 32) fail();
    }
    const recent = db.prepare(
      "SELECT r.sequence,r.nonce,r.operation_id,r.admission_hash,r.consumed_at_ms,"
      + "r.previous_hash,r.hash,"
      + "a.hash AS original_hash,i.nonce AS issuance_nonce"
      + " FROM witness_cas_sync_historical_recovery_nonce r"
      + " LEFT JOIN witness_cas_sync_historical_admission a"
      + " ON a.operation_id=r.operation_id"
      + " LEFT JOIN witness_cas_sync_historical_issue_nonce i"
      + " ON i.operation_id=r.operation_id ORDER BY r.sequence"
      + " LIMIT ?").all(MAX_RECOVERY_CHALLENGES + 1);
    if (recent.length > MAX_RECOVERY_CHALLENGES) fail();
    let previous = ZERO;
    for (let idx = 0; idx < recent.length; idx += 1) {
      const row = recent[idx];
      if (row.sequence !== idx + 1 || row.previous_hash !== previous
        || !validHex(row.hash)
        || !Buffer.isBuffer(row.nonce) || row.nonce.length !== 32
        || row.admission_hash !== row.original_hash
        || !Buffer.isBuffer(row.issuance_nonce) || row.issuance_nonce.length !== 32
        || row.nonce.equals(row.issuance_nonce)
        || !Number.isSafeInteger(row.consumed_at_ms)
        || row.consumed_at_ms < 1
        || recoveryRowHash(row) !== row.hash) fail();
      previous = row.hash;
    }
    const stored = db.prepare(
      "SELECT sequence,last_hash,signature FROM"
      + " witness_cas_sync_historical_recovery_head WHERE id=1").get();
    if (!stored || stored.sequence !== recent.length
      || stored.last_hash !== previous
      || !Buffer.isBuffer(stored.signature) || stored.signature.length !== 64
      || !crypto.verify(null, this.#recoveryHeadMessage({
        sequence: stored.sequence, lastHash: stored.last_hash,
      }), crypto.createPublicKey(this.#witness), stored.signature)) fail();
    const pinned = { sequence: stored.sequence, lastHash: stored.last_hash };
    if (this.#pinnedRecoveryHead
      && (pinned.sequence < this.#pinnedRecoveryHead.sequence
        || (this.#pinnedRecoveryHead.sequence === 0
          ? this.#pinnedRecoveryHead.lastHash !== ZERO
          : recent[this.#pinnedRecoveryHead.sequence - 1]?.hash
            !== this.#pinnedRecoveryHead.lastHash))) fail();
    if (this.#db === db) {
      if (this.#recoveryHead.sequence !== pinned.sequence
        || this.#recoveryHead.lastHash !== pinned.lastHash) fail();
    } else {
      this.#recoveryHead = Object.freeze(pinned);
    }
    const overlap = db.prepare(
      "SELECT 1 FROM witness_cas_sync_historical_issue_nonce i"
      + " JOIN witness_cas_sync_historical_recovery_nonce r"
      + " ON i.nonce=r.nonce LIMIT 1").get();
    if (overlap) fail();
  }
  #historicalNonceUsed(nonce) {
    return Boolean(this.#db.prepare(
      "SELECT 1 FROM witness_cas_sync_historical_issue_nonce WHERE nonce=?").get(nonce)
      || this.#db.prepare(
        "SELECT 1 FROM witness_cas_sync_historical_recovery_nonce WHERE nonce=?").get(nonce));
  }
  #assertHistoricalIntegrity() {
    if (!this.#historicalEnabled) fail();
    let sequence = 0;
    let previousHash = ZERO;
    let totalBytes = 0;
    const verifyKey = crypto.createPublicKey(this.#witness);
    const triggers = new Set(this.#db.prepare(
      "SELECT name FROM sqlite_master WHERE type='trigger'").all().map((r) => r.name));
    if (!triggers.has("no_historical_admission_update")
      || !triggers.has("no_historical_admission_delete")) fail();
    for (const row of this.#db.prepare(
      "SELECT * FROM witness_cas_sync_historical_admission ORDER BY sequence").iterate()) {
      sequence += 1;
      totalBytes += Buffer.byteLength(row.receipt || "");
      if (sequence > 100000 || totalBytes > 64 * 1024 * 1024) fail();
      if (row.sequence !== sequence || row.previous_hash !== previousHash
        || !validHex(row.hash) || typeof row.receipt !== "string"
        || row.receipt.length > 4096 || row.hash !== digest(previousHash + "\0" + row.receipt)) fail();
      let admission;
      try { admission = JSON.parse(row.receipt); } catch (_) { fail(); }
      if (JSON.stringify(admission) !== row.receipt
        || admission.operationId !== row.operation_id
        || typeof admission.signature !== "string") fail();
      const { signature, ...unsigned } = admission;
      const raw = Buffer.from(signature, "base64url");
      if (raw.length !== 64 || raw.toString("base64url") !== signature
        || !crypto.verify(null, Buffer.concat([HISTORICAL_SYNC_DOMAIN,
          Buffer.from(JSON.stringify(unsigned))]), verifyKey, raw)) fail();
      previousHash = row.hash;
    }
    if (this.#historicalHead.sequence !== sequence
      || this.#historicalHead.lastHash !== previousHash) fail();
    this.#assertHistoricalNonceIntegrity(this.#db);
  }
  historicalAdmissionForOperation(operationId) {
    if (!this.#historicalEnabled || this.#closed) fail();
    const operation = id(operationId).toString("base64url");
    this.historicalAdmissionHead();
    const row = this.#db.prepare(
      "SELECT receipt FROM witness_cas_sync_historical_admission WHERE operation_id=?")
      .get(operation);
    if (!row) return null;
    const receipt = JSON.parse(row.receipt);
    return Object.freeze({ admission: Object.freeze(receipt),
      authorizesHistoricalRead: false, authorizesIo: false });
  }
  // Witness-owned issuance after (1) fresh DEVICE Ed25519 authorization,
  // (2) fresh independent mTLS PostgreSQL readback plus inventory signature,
  // and (3) a previously committed owner-authorized CAS physical fence.
  // The receipt is returned ONLY after an immutable SQLite FULL-sync commit.
  // This is NOT cross-service atomicity or an external monotonic anchor.
  async issueSyncHistoricalAdmission(input) {
    if (!this.#historicalEnabled || this.#closed) fail();
    // Pin the caller's challenge BEFORE entering the asynchronous witness
    // queue. Otherwise a caller could mutate the same Buffer while waiting
    // for another admission and silently change the attested nonce.
    const captured = exact(input, ["envelope", "scope", "expectedSequence",
      "expectedRoot", "inventoryReceipt", "nonce"]);
    if ((!Buffer.isBuffer(captured.nonce) && !(captured.nonce instanceof Uint8Array))
      || captured.nonce.byteLength !== 32
      || (typeof SharedArrayBuffer !== "undefined"
        && captured.nonce.buffer instanceof SharedArrayBuffer)) fail();
    const pinnedInput = { ...captured, nonce: Buffer.from(captured.nonce) };
    const pending = this.#advanceQueue.then(() => this.#issueSyncSerial(pinnedInput));
    this.#advanceQueue = pending.catch(() => {});
    return pending;
  }
  // Lost HTTP ACK recovery never inserts, updates or re-signs a historical
  // admission. It independently re-proves the exact durable receipt with a
  // NEW client challenge, a fresh signed witness floor and fresh mTLS PG
  // readback. Inability to prove the original exact floor is a hard denial;
  // accepting a later head would require a separately reviewed ancestry proof.
  async recoverSyncHistoricalAdmission(input) {
    if (!this.supportsClientHistoricalNonce) fail();
    const captured = exact(input, ["envelope", "scope", "expectedSequence",
      "expectedRoot", "inventoryReceipt", "nonce"]);
    if ((!Buffer.isBuffer(captured.nonce) && !(captured.nonce instanceof Uint8Array))
      || captured.nonce.byteLength !== 32
      || (typeof SharedArrayBuffer !== "undefined"
        && captured.nonce.buffer instanceof SharedArrayBuffer)
      || (!Buffer.isBuffer(captured.inventoryReceipt)
        && !(captured.inventoryReceipt instanceof Uint8Array))
      || captured.inventoryReceipt.byteLength < 1
      || captured.inventoryReceipt.byteLength > 8192) fail();
    // Canonicalize and detach all attacker-owned mutable input before queuing.
    let bound;
    try {
      bound = envelopeBinding(captured.envelope, captured.scope,
        captured.expectedSequence, captured.expectedRoot);
    } catch (_) { fail(); }
    const pinned = { bound, receipt: Buffer.from(captured.inventoryReceipt),
      nonce: Buffer.from(captured.nonce) };
    const pending = this.#advanceQueue.then(() => this.#recoverSyncSerial(pinned));
    this.#advanceQueue = pending.catch(() => {});
    return pending;
  }
  async #recoverSyncSerial({ bound, receipt, nonce }) {
    try {
      if (!this.supportsClientHistoricalNonce) fail();
      this.#assertExternalRecoveryHead();
      const operationId = bound.operation.operation_id.toString("base64url");
      const saved = this.historicalAdmissionForOperation(bound.operation.operation_id);
      if (!saved) fail();
      const admission = saved.admission;
      const stamp = Date.now();
      if (!Number.isSafeInteger(stamp) || stamp < 1
        || !Number.isSafeInteger(admission.admittedAtMs)
        || admission.admittedAtMs < 1 || admission.admittedAtMs > stamp
        || admission.admittedAtMs >= bound.envelope.authorization.expiresAt
        || admission.type !== "rootark-sync-v2-historical-witness-admission/v1"
        || admission.operationId !== operationId
        || admission.envelopeSha256 !== crypto.createHash("sha256")
          .update(bound.canonicalEnvelope).digest("base64url")
        || admission.deviceId !== bound.envelope.deviceId
        || admission.epoch !== bound.operation.epoch
        || admission.checkpointSequence !== bound.operation.expected_sequence
        || admission.checkpointRoot !== bound.operation.expected_root.toString("base64url")
        || admission.inventoryReceiptSha256 !== crypto.createHash("sha256")
          .update(receipt).digest("base64url")) fail();
      const deviceSpki = Buffer.from(bound.envelope.authorization.publicKey, "base64url");
      if (admission.deviceSpkiSha256 !== crypto.createHash("sha256")
        .update(deviceSpki).digest("base64url")) fail();
      const deviceKey = crypto.createPublicKey({ key: deviceSpki,
        format: "der", type: "spki" });
      if (deviceKey.asymmetricKeyType !== "ed25519"
        || crypto.KeyObject.prototype.equals.call(
          deviceKey, crypto.createPublicKey(this.#witness))
        || crypto.KeyObject.prototype.equals.call(deviceKey, this.#status)) fail();
      this.#attestedAdmission.assertSeparateDevice(deviceKey);
      const policy = snapshotLocalDevicePolicy(this.#trustedSyncDevicePolicyProvider());
      if (await verifyHistoricalAuthorizationProof(bound.envelope.authorization,
        bound.envelope, policy) !== true) fail();
      const policySnapshot = JSON.stringify(policy);
      const nonceText = nonce.toString("base64url");
      const originalRow = this.#db.prepare(
        "SELECT a.hash,i.nonce,i.admission_hash"
        + " FROM witness_cas_sync_historical_admission a"
        + " JOIN witness_cas_sync_historical_issue_nonce i"
        + " ON i.admission_sequence=a.sequence AND i.operation_id=a.operation_id"
        + " WHERE a.operation_id=?").get(operationId);
      if (!originalRow || originalRow.hash !== originalRow.admission_hash
        || !Buffer.isBuffer(originalRow.nonce) || originalRow.nonce.length !== 32
        || this.#historicalNonceUsed(nonce)) fail();
      const composite = await this.#attestedAdmission.attestSyncCommitted({
        scope: bound.scope, operation: bound.operation, receipt, nonce });
      if (!composite.pgReadbackVerified || composite.authorizesIo !== false
        || composite.inventorySequence !== bound.operation.expected_sequence + 1
        || composite.receiptSha256.toString("base64url")
          !== admission.inventoryReceiptSha256) fail();
      const fenced = await this.proveCommittedPhysicalFence({
        scope: bound.scope, operationId: bound.operation.operation_id,
        inventorySequence: composite.inventorySequence,
        inventoryRoot: composite.inventoryRoot, nonce });
      const floor = fenced.signedFloor;
      // No optimistic promotion of the original receipt to a later floor.
      if (admission.witnessSequence !== floor.sequence
        || admission.witnessLastHash !== floor.lastHash
        || admission.witnessPhysicalFenceDigest !== floor.physicalFenceDigest
        || floor.nonce !== nonceText) fail();
      const current = snapshotLocalDevicePolicy(this.#trustedSyncDevicePolicyProvider());
      if (JSON.stringify(current) !== policySnapshot
        || await verifyHistoricalAuthorizationProof(bound.envelope.authorization,
          bound.envelope, current) !== true) fail();
      const completed = Date.now();
      if (!Number.isSafeInteger(completed) || completed < stamp
        || !Number.isSafeInteger(composite.physicalIssuedAt)
        || Math.abs(Math.floor(completed / 1000) - composite.physicalIssuedAt) > 30
        || admission.admittedAtMs > completed) fail();
      // A durable nonce claim is part of the final decision. SQLite FULL,
      // BEGIN IMMEDIATE, an immutable row-chain and the signed high-water
      // detect unauthorized deletes after the ACK. NO TTL deletion/compaction:
      // a spent nonce must never become reusable, even after five minutes.
      let committedHead;
      this.#db.transaction(() => {
        this.#assertHistoricalIntegrity();
        this.#assertExternalRecoveryHead();
        const own = this.#db.prepare(
          "SELECT a.hash,i.admission_hash,i.nonce"
          + " FROM witness_cas_sync_historical_admission a"
          + " JOIN witness_cas_sync_historical_issue_nonce i"
          + " ON i.admission_sequence=a.sequence AND i.operation_id=a.operation_id"
          + " WHERE a.operation_id=?").get(operationId);
        if (!own || own.hash !== originalRow.hash
          || own.admission_hash !== originalRow.hash
          || !Buffer.isBuffer(own.nonce) || !own.nonce.equals(originalRow.nonce)
          || this.#historicalNonceUsed(nonce)) fail();
        const commitAtMs = Date.now();
        if (!Number.isSafeInteger(commitAtMs) || commitAtMs < completed
          || Math.abs(Math.floor(commitAtMs / 1000) - composite.physicalIssuedAt) > 30) fail();
        if (this.#db.prepare(
          "SELECT COUNT(*) AS count FROM witness_cas_sync_historical_recovery_nonce"
        ).get().count >= MAX_RECOVERY_CHALLENGES) fail();
        // Final *synchronous* current-policy check is immediately before the
        // durable claim: no awaits, caller callbacks or HTTP response in between.
        if (JSON.stringify(snapshotLocalDevicePolicy(
          this.#trustedSyncDevicePolicyProvider())) !== policySnapshot) fail();
        const row = {
          sequence: this.#recoveryHead.sequence + 1,
          nonce, operation_id: operationId,
          admission_hash: originalRow.hash, consumed_at_ms: commitAtMs,
          previous_hash: this.#recoveryHead.lastHash,
        };
        const hash = recoveryRowHash(row);
        this.#db.prepare("INSERT INTO witness_cas_sync_historical_recovery_nonce"
          + " (sequence,nonce,operation_id,admission_hash,consumed_at_ms,"
          + "previous_hash,hash) VALUES(?,?,?,?,?,?,?)").run(
            row.sequence, nonce, operationId, originalRow.hash, commitAtMs,
            row.previous_hash, hash);
        const nextHead = { sequence: row.sequence, lastHash: hash };
        const advance = this.#db.prepare(
          "UPDATE witness_cas_sync_historical_recovery_head"
          + " SET sequence=?,last_hash=?,signature=?"
          + " WHERE id=1 AND sequence=? AND last_hash=?").run(
            nextHead.sequence, nextHead.lastHash, this.#signRecoveryHead(nextHead),
            this.#recoveryHead.sequence, this.#recoveryHead.lastHash);
        if (advance.changes !== 1) fail();
        const afterInsert = Date.now();
        if (!Number.isSafeInteger(afterInsert) || afterInsert < commitAtMs
          || Math.abs(Math.floor(afterInsert / 1000) - composite.physicalIssuedAt) > 30) fail();
        committedHead = Object.freeze(nextHead);
      }).immediate();
      const previousExternal = this.#recoveryHead;
      this.#recoveryHead = committedHead;
      // Crash point: FULL SQLite has committed but the independent CAS may
      // not yet have committed. A missed/ambiguous external ACK denies this
      // request and all future historical operations until the operator
      // reconciles both durable stores. NEVER infer authority from SQLite.
      this.#commitExternalRecoveryHead(previousExternal, committedHead);
      return Object.freeze({
        admission, freshFloor: floor,
        physicalAttestation: Buffer.from(composite.physicalAttestation),
        recoveredDurableAdmission: true,
        authorizesHistoricalRead: false, authorizesIo: false,
        externalCustodyProven: false,
      });
    } catch (_) { fail(); }
  }
  async #issueSyncSerial(input) {
    try {
      this.#assertExternalRecoveryHead();
      const v = exact(input, ["envelope", "scope", "expectedSequence",
        "expectedRoot", "inventoryReceipt", "nonce"]);
      const bound = envelopeBinding(v.envelope, v.scope, v.expectedSequence,
        v.expectedRoot);
      if ((!Buffer.isBuffer(v.nonce) && !(v.nonce instanceof Uint8Array))
        || v.nonce.byteLength !== 32
        || (typeof SharedArrayBuffer !== "undefined"
          && v.nonce.buffer instanceof SharedArrayBuffer)) fail();
      // One exact caller challenge must bind the PG attestor signature and
      // witness's signed physical floor. Detach before the first await.
      const nonce = Buffer.from(v.nonce);
      // The trusted operator must provide a synchronous current policy, not
      // attacker-chosen `input.localTrustedDevicePolicy` or mutable disk JSON.
      const policy = snapshotLocalDevicePolicy(this.#trustedSyncDevicePolicyProvider());
      const policySnapshot = JSON.stringify(policy);
      if ((!Buffer.isBuffer(v.inventoryReceipt)
        && !(v.inventoryReceipt instanceof Uint8Array))
        || v.inventoryReceipt.length < 1 || v.inventoryReceipt.length > 8192) fail();
      const signedReceipt = Buffer.from(v.inventoryReceipt);
      const deviceSpki = Buffer.from(bound.envelope.authorization.publicKey, "base64url");
      const deviceKey = crypto.createPublicKey({ key: deviceSpki,
        format: "der", type: "spki" });
      const witnessKey = crypto.createPublicKey(this.#witness);
      if (deviceKey.asymmetricKeyType !== "ed25519"
        || crypto.KeyObject.prototype.equals.call(deviceKey, witnessKey)
        || crypto.KeyObject.prototype.equals.call(deviceKey, this.#status)
        || signedReceipt.length < 1 || signedReceipt.length > 8192) fail();
      this.#attestedAdmission.assertSeparateDevice(deviceKey);
      if (await verifyAuthorizationProof(bound.envelope.authorization,
        bound.envelope, policy) !== true
        || bound.envelope.authorization.expiresAt <= Date.now()) fail();
      if (this.#db.prepare("SELECT 1 FROM witness_cas_sync_historical_admission WHERE operation_id=?")
        .get(bound.operation.operation_id.toString("base64url"))) fail();
      const composite = await this.#attestedAdmission.attestSyncCommitted({
        scope: bound.scope, operation: bound.operation,
        receipt: signedReceipt, nonce,
      });
      if (!composite.pgReadbackVerified || composite.authorizesIo !== false
        || composite.inventorySequence !== bound.operation.expected_sequence + 1) fail();
      const fenced = await this.proveCommittedPhysicalFence({ scope: bound.scope,
        operationId: bound.operation.operation_id,
        inventorySequence: composite.inventorySequence,
        inventoryRoot: composite.inventoryRoot, nonce });
      const admittedAtMs = Date.now();
      if (!Number.isSafeInteger(admittedAtMs) || admittedAtMs < 1
        || admittedAtMs >= bound.envelope.authorization.expiresAt
        || !Number.isSafeInteger(composite.physicalIssuedAt)
        || Math.abs(Math.floor(admittedAtMs / 1000)
          - composite.physicalIssuedAt) > 30) fail();
      const floor = fenced.signedFloor;
      const unsigned = {
        type: "rootark-sync-v2-historical-witness-admission/v1",
        envelopeSha256: crypto.createHash("sha256")
          .update(bound.canonicalEnvelope).digest("base64url"),
        operationId: bound.operation.operation_id.toString("base64url"),
        deviceId: bound.envelope.deviceId,
        deviceSpkiSha256: crypto.createHash("sha256").update(deviceSpki)
          .digest("base64url"),
        epoch: bound.operation.epoch,
        checkpointSequence: bound.operation.expected_sequence,
        checkpointRoot: bound.operation.expected_root.toString("base64url"),
        inventoryReceiptSha256: composite.receiptSha256.toString("base64url"),
        admittedAtMs,
        witnessSequence: floor.sequence,
        witnessLastHash: floor.lastHash,
        witnessPhysicalFenceDigest: floor.physicalFenceDigest,
      };
      const signature = crypto.sign(null, Buffer.concat([HISTORICAL_SYNC_DOMAIN,
        Buffer.from(JSON.stringify(unsigned))]), this.#witness);
      // Crossing the device expiry while signing means we never admitted the
      // operation on time, even if the Ed25519 signature is authentic.
      const signedAtMs = Date.now();
      if (!Number.isSafeInteger(signedAtMs) || signedAtMs < admittedAtMs
        || signedAtMs >= bound.envelope.authorization.expiresAt) fail();
      const admission = Object.freeze({ ...unsigned,
        signature: signature.toString("base64url") });
      const serialized = JSON.stringify(admission);
      const previous = this.#historicalHead;
      const hash = digest(previous.lastHash + "\0" + serialized);
      const head = this.head();
      if (head.sequence !== floor.sequence || head.lastHash !== floor.lastHash) fail();
      this.#assertHistoricalIntegrity();
      this.#assertExternalRecoveryHead();
      this.#db.transaction(() => {
        this.#assertExternalRecoveryHead();
        if (this.#db.prepare("SELECT COUNT(*) AS n FROM witness_cas_sync_historical_admission")
            .get().n !== previous.sequence) fail();
        // Native SQLite stmt creation precedes the final time sample too.
        const insert = this.#db.prepare("INSERT INTO witness_cas_sync_historical_admission"
          + " (sequence,operation_id,previous_hash,receipt,hash) VALUES(?,?,?,?,?)");
        // Synchronous trusted callbacks may advance the clock during policy
        // refresh/serialization. Never sample time before invoking them.
        const freshPolicy = JSON.stringify(snapshotLocalDevicePolicy(
          this.#trustedSyncDevicePolicyProvider()));
        // The final authorization decision is inside the very same immediate
        // SQLite transaction that persists this signed admission. No await or
        // policy-provider callback may intervene between check and INSERT.
        const commitAtMs = Date.now();
        if (!Number.isSafeInteger(commitAtMs) || commitAtMs < admittedAtMs
          || commitAtMs >= bound.envelope.authorization.expiresAt
          || !Number.isSafeInteger(composite.physicalIssuedAt)
          || Math.abs(Math.floor(commitAtMs / 1000)
            - composite.physicalIssuedAt) > 30
          || freshPolicy !== policySnapshot) fail();
        insert.run(previous.sequence + 1, unsigned.operationId,
            previous.lastHash, serialized, hash);
        if (this.#historicalNonceUsed(nonce)) fail();
        this.#db.prepare("INSERT INTO witness_cas_sync_historical_issue_nonce"
          + " (admission_sequence,operation_id,admission_hash,nonce)"
          + " VALUES(?,?,?,?)").run(previous.sequence + 1, unsigned.operationId,
            hash, nonce);
        // Abort and roll back if SQLite's own synchronous INSERT/WAL operation
        // outlived the signed device authorization or PG freshness window.
        const insertedAtMs = Date.now();
        if (!Number.isSafeInteger(insertedAtMs) || insertedAtMs < commitAtMs
          || insertedAtMs >= bound.envelope.authorization.expiresAt
          || Math.abs(Math.floor(insertedAtMs / 1000)
            - composite.physicalIssuedAt) > 30) fail();
      }).immediate();
      this.#historicalHead = Object.freeze({ sequence: previous.sequence + 1,
        lastHash: hash });
      // A concurrent loss or advancement of externally retained recovery
      // custody after the initial check must not still yield an ISSUE ACK.
      // The original immutable local receipt may now be PENDING lost-ACK
      // recovery, but no mutable fallback or retroactive signature is allowed.
      this.#assertExternalRecoveryHead();
      return Object.freeze({ admission, freshFloor: floor,
        physicalAttestation: Buffer.from(composite.physicalAttestation),
        historicalAdmissionHead: this.historicalAdmissionHead(),
        durableLocalWitnessAdmission: true,
        independentPhysicalReadbackVerified: true,
        authorizesHistoricalRead: false, authorizesIo: false,
        externalCustodyProven: false });
    } catch (_) { fail(); }
  }
  // A signed CAS event is the only admissible means of advancing the floor.
  // A caller may repeat a lost ACK's IDENTICAL signed event, never skip,
  // truncate, fork, or arbitrarily submit an unsigned head number/hash.
  get requiresPhysicalAttestation() { return Boolean(this.#attestedAdmission); }
  #captureRecords(records) {
    if (!Array.isArray(records) || records.length < 1 || records.length > 16
      || Reflect.ownKeys(records).length !== records.length + 1) fail();
    const captured = [];
    for (let i = 0; i < records.length; i++) {
      const d = Object.getOwnPropertyDescriptor(records, String(i));
      if (!d || !Object.hasOwn(d, "value")) fail();
      const record = parseRecord(d.value, this.#status);
      if (i > 0 && record.sequence <= captured[i - 1].sequence) fail();
      captured.push(record);
    }
    return captured;
  }
  advance({ records }) {
    // The historical signed-status-only mode remains explicitly legacy.
    // A strict witness cannot downgrade through this otherwise valid API.
    if (this.#attestedAdmission) fail();
    return this.#advanceCaptured(this.#captureRecords(records));
  }
  async advanceAttested({ records, evidence }) {
    if (!this.#attestedAdmission) fail();
    const captured = this.#captureRecords(records);
    if (!Array.isArray(evidence) || evidence.length !== captured.length
      || Reflect.ownKeys(evidence).length !== evidence.length + 1) fail();
    const copiedEvidence = evidence.map((_, index) => {
      const entry = Object.getOwnPropertyDescriptor(evidence, String(index));
      if (!entry || !Object.hasOwn(entry, "value")) fail();
      return entry.value;
    });
    // Serialize asynchronous fresh challenges and the subsequent SQLite CAS.
    // Otherwise two pending requests can both see predecessor A and accept
    // unrelated signed successors B and B' before either inserts its fence.
    const pending = this.#advanceQueue.then(() =>
      this.#advanceAttestedSerial(captured, copiedEvidence));
    this.#advanceQueue = pending.catch(() => {});
    return pending;
  }
  async #advanceAttestedSerial(captured, evidence) {
    if (this.#closed) fail();
    await this.auditRetainedPhysicalEvidence();
    const admissionStart = process.hrtime.bigint();
    const maxAdmissionNs = 300_000_000_000n;
    this.head();
    const pendingHeads = new Map(this.#inventoryHeads);
    const verifiedPhysical = new Map();
    // Both the owner authorization and fresh physical PG readback MUST be
    // verified before ANY transaction mutates the independently held floor.
    for (let i = 0; i < captured.length; i++) {
      const record = captured[i];
      if (record.sequence <= this.#trustedFloor.sequence) continue;
      try {
        const verified = await this.#attestedAdmission.verify({
          line: record.line, lastHash: record.lastHash,
          status: record.status, scope: record.scope,
        }, evidence[i], pendingHeads.get(record.scope));
        if (process.hrtime.bigint() - admissionStart > maxAdmissionNs) fail();
        if (record.status === "committed") {
          if (!verified.physicallyCommitted || !verified.localReadbackConfirmed
            || !Buffer.isBuffer(verified.operationId)
            || verified.operationId.length !== 16
            || verified.inventoryScope !== record.scope
            || !Number.isSafeInteger(verified.inventorySequence)
            || verified.inventorySequence < 1
            || !Buffer.isBuffer(verified.inventoryRoot)
            || verified.inventoryRoot.length !== 32
            || !Buffer.isBuffer(verified.inventorySnapshot)
            || verified.inventorySnapshot.length < 1
            || verified.inventorySnapshot.length > 2 * 1024 * 1024
            || !Buffer.isBuffer(verified.originalPgEvidence)
            || verified.originalPgEvidence.length < 1
            || verified.originalPgEvidence.length > 8192) fail();
          const minimum = pendingHeads.get(record.scope);
          if (minimum && verified.inventorySequence <= minimum.head.sequence) fail();
          pendingHeads.set(record.scope, { head: {
            sequence: verified.inventorySequence,
            root: Buffer.from(verified.inventoryRoot),
          }, snapshot: Buffer.from(verified.inventorySnapshot) });
        } else if (verified.physicallyCommitted || !verified.ownerBound) fail();
        verifiedPhysical.set(record.sequence, verified);
      } catch (_) { fail(); }
    }
    if (process.hrtime.bigint() - admissionStart > maxAdmissionNs) fail();
    return this.#advanceCaptured(captured, verifiedPhysical, pendingHeads,
      admissionStart);
  }
  #advanceCaptured(captured, verifiedPhysical = null, pendingHeads = null,
    admissionStart = null) {
    const priorSequence = this.#trustedFloor.sequence;
    if (Boolean(verifiedPhysical) !== Boolean(this.#attestedAdmission)) fail();
    const insertedFences = [];
    const updated = this.#db.transaction(() => {
      let previous = this.head();
      const existing = this.#db.prepare("SELECT hash,line FROM witness_cas_floor_event WHERE sequence=?");
      const insert = this.#db.prepare("INSERT INTO witness_cas_floor_event VALUES(?,?,?,?)");
      const insertFence = verifiedPhysical ? this.#db.prepare(
        "INSERT INTO witness_cas_inventory_fence VALUES(?,?,?,?,?,?,?,?,?)") : null;
      const existingBytes = verifiedPhysical ? this.#db.prepare(
        "SELECT COALESCE(SUM(length(snapshot)),0) AS total FROM witness_cas_inventory_fence").get().total : 0;
      const existingPgBytes = verifiedPhysical ? this.#db.prepare(
        "SELECT COALESCE(SUM(length(original_pg_evidence)),0) AS total FROM witness_cas_inventory_fence").get().total : 0;
      let totalSnapshotBytes = existingBytes;
      let totalPgBytes = existingPgBytes;
      for (const item of captured) {
        if (item.sequence <= previous.sequence) {
          const saved = existing.get(item.sequence);
          if (!saved || saved.hash !== item.lastHash || saved.line !== item.line) fail();
          continue;
        }
        if (item.sequence !== previous.sequence + 1
          || item.previousHash !== previous.lastHash) fail();
        if (insertFence) {
          const verified = verifiedPhysical.get(item.sequence);
          if (!verified || verified.ownerBound !== true) fail();
          const committed = item.status === "committed";
          const snapshot = committed ? Buffer.from(verified.inventorySnapshot) : null;
          totalSnapshotBytes += snapshot?.length || 0;
          totalPgBytes += committed ? verified.originalPgEvidence.length : 0;
          if (totalSnapshotBytes > 64 * 1024 * 1024
            || totalPgBytes > 64 * 1024 * 1024) fail();
          const fence = { sequence: item.sequence, cas_hash: item.lastHash,
            scope: item.scope,
            operation_id: committed ? verified.operationId.toString("hex") : null,
            inventory_sequence: committed ? verified.inventorySequence : null,
            inventory_root: committed ? verified.inventoryRoot.toString("hex") : null,
            snapshot,
            original_pg_evidence: committed ? Buffer.from(verified.originalPgEvidence) : null,
            signature: null };
          fence.signature = crypto.sign(null, physicalFenceMessage(fence), this.#witness);
          insertFence.run(fence.sequence, fence.cas_hash, fence.scope, fence.operation_id,
            fence.inventory_sequence, fence.inventory_root, fence.snapshot,
            fence.original_pg_evidence, fence.signature);
          insertedFences.push(fence);
        }
        insert.run(item.sequence, item.line, item.lastHash, item.previousHash);
        previous = { sequence: item.sequence, lastHash: item.lastHash };
      }
      // This check still runs inside the SQLite transaction. A long pause
      // while inserting fences must roll it back, not commit stale evidence.
      if (admissionStart !== null
        && process.hrtime.bigint() - admissionStart > 300_000_000_000n) fail();
      return Object.freeze({ ...previous });
    }).immediate();
    for (const item of captured) {
      if (item.sequence > priorSequence) this.#verifiedChain.update(
        rowEvidence({ sequence: item.sequence, line: item.line,
          hash: item.lastHash, predecessor: item.previousHash }));
    }
    this.#verifiedChainDigest = this.#verifiedChain.copy().digest("hex");
    for (const fence of insertedFences) this.#physicalFenceChain.update(
      physicalFenceEvidence(fence));
    if (verifiedPhysical) {
      this.#physicalFenceDigest = this.#physicalFenceChain.copy().digest("hex");
      this.#inventoryHeads = pendingHeads;
      this.#auditedOriginalPgDigest = this.#physicalFenceDigest;
    }
    this.#trustedFloor = Object.freeze({ ...updated });
    this.#generation += 1;
    return updated;
  }
  freshHead({ nonce }) {
    if ((!Buffer.isBuffer(nonce) && !(nonce instanceof Uint8Array))
      || nonce.byteLength !== 32) fail();
    // Require cold Ed25519 re-audit before signed synchronous readback after
    // restart. The mTLS async path runs that audit automatically.
    if (this.#attestedAdmission && this.#trustedFloor.sequence > 0
      && this.#auditedOriginalPgDigest !== this.#physicalFenceDigest) fail();
    const value = this.head();
    return this.#signHead(Buffer.from(nonce), value);
  }
  close() { this.#closed = true; if (this.#db.open) this.#db.close(); }
}
module.exports = { Zk1WitnessCasAnchorFloor, verifyFreshWitnessCasFloor };
