"use strict";

// Disposable TEST authority only. A different SQLite database proves that the
// witness never reads its OWN restored database to authorize the recovery
// head. Production authority custody MUST be on an independently governed
// host/service and use the operator's durable synchronous CAS adapter.
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { snapshotLocalDevicePolicy } = require("../../sync-client/rootark-sync-zk1-physical-binding");
const { verifyCommittedPhysicalReadback } =
  require("../../src/crypto/rootark-zk-pg-physical-attestation-v1");
const ZERO = "0".repeat(64);
const READY_DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-recovery-ledger/v2\0");

function createExternalRecoveryHeadFixture(filename, initialHead = {
  sequence: 0, lastHash: ZERO,
}, operator = {}) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) throw Error("FIXTURE_PATH");
  const db = new Database(filename);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.exec(`CREATE TABLE IF NOT EXISTS operator_recovery_floor (
    id INTEGER PRIMARY KEY CHECK(id=1),
    sequence INTEGER NOT NULL, last_hash TEXT NOT NULL,
    finalized_sequence INTEGER NOT NULL, finalized_hash TEXT NOT NULL);
  `);
  db.prepare("INSERT OR IGNORE INTO operator_recovery_floor"
    + " (id,sequence,last_hash,finalized_sequence,finalized_hash)"
    + " VALUES(1,?,?,?,?)").run(
      initialHead.sequence, initialHead.lastHash,
      initialHead.sequence, initialHead.lastHash);
  let available = true;
  let failurePhase = null;
  let reads = 0;
  const read = () => {
    if (!available) throw Error("TEST_AUTHORITY_UNAVAILABLE");
    reads += 1;
    const row = db.prepare(
      "SELECT sequence,last_hash FROM operator_recovery_floor WHERE id=1").get();
    if (!row) throw Error("TEST_AUTHORITY_MISSING");
    return { sequence: row.sequence, lastHash: row.last_hash };
  };
  const authority = {
    loadHead: read,
    loadFinalizedHead() {
      if (!available) throw Error("TEST_AUTHORITY_UNAVAILABLE");
      const row = db.prepare("SELECT finalized_sequence,finalized_hash"
        + " FROM operator_recovery_floor WHERE id=1").get();
      if (!row) throw Error("TEST_FINALIZATION_MISSING");
      return { sequence: row.finalized_sequence, lastHash: row.finalized_hash };
    },
    compareAndAdvance(expected, next) {
      if (!available) throw Error("TEST_AUTHORITY_UNAVAILABLE");
      if (!Number.isSafeInteger(expected?.sequence)
        || !Number.isSafeInteger(next?.sequence)
        || next.sequence !== expected.sequence + 1
        || !/^[a-f0-9]{64}$/.test(expected.lastHash)
        || !/^[a-f0-9]{64}$/.test(next.lastHash))
        throw Error("TEST_NON_MONOTONIC_EXTERNAL_CAS");
      if (failurePhase === "before") throw Error("TEST_EXTERNAL_CAS_DOWN");
      const n = db.transaction(() => db.prepare(
        "UPDATE operator_recovery_floor SET sequence=?,last_hash=?"
        + " WHERE id=1 AND sequence=? AND last_hash=?").run(
          next.sequence, next.lastHash, expected.sequence, expected.lastHash).changes);
      const changed = n.immediate();
      if (failurePhase === "after") throw Error("TEST_EXTERNAL_ACK_LOST");
      return changed === 1;
    },
    async finalizeAck(previous, next, proof) {
      if (!available || failurePhase === "finalize-before")
        throw Error("TEST_FINALIZATION_UNAVAILABLE");
      // Explicitly pinned independent witness, owner policy and PostgreSQL
      // signer are required in this disposable synthetic operator. The real
      // operator must perform equivalent validation with independent custody.
      if (!(operator.witnessPublicKey instanceof crypto.KeyObject)
        || !(operator.physicalAttestorPublicKey instanceof crypto.KeyObject)
        || typeof operator.policyProvider !== "function"
        || !proof || typeof proof !== "object"
        || !Buffer.isBuffer(proof.readySignature)
        || proof.readySignature.length !== 64
        || !/^[A-Za-z0-9_-]{22}$/.test(proof.witnessKeyId)
        || !/^[A-Za-z0-9_-]{22}$/.test(proof.statusKeyId)
        || !Buffer.isBuffer(proof.physicalAttestation)
        || !Buffer.isBuffer(proof.nonce)
        || !Number.isSafeInteger(proof.physicalIssuedAt))
        throw Error("TEST_FINALIZATION_PROOF_REQUIRED");
      const readyMessage = Buffer.concat([READY_DOMAIN, Buffer.from(JSON.stringify([
        proof.witnessKeyId, proof.statusKeyId, next.sequence,
        next.lastHash, "READY", ZERO,
      ]))]);
      if (!crypto.verify(null, readyMessage,
        operator.witnessPublicKey, proof.readySignature))
        throw Error("TEST_FINALIZATION_BAD_SIGNATURE");
      const verified = await verifyCommittedPhysicalReadback(
        proof.physicalAttestation, {
          scope: proof.scope, operation: proof.operation, nonce: proof.nonce,
          pinnedPublicKey: operator.physicalAttestorPublicKey,
          expected: undefined, nowSeconds: Math.floor(Date.now() / 1000),
        });
      if (verified.issuedAt !== proof.physicalIssuedAt)
        throw Error("TEST_FINALIZATION_PHYSICAL_TIME_MISMATCH");
      const changed = db.transaction(() => {
        const currentPolicy = JSON.stringify(snapshotLocalDevicePolicy(operator.policyProvider()));
        if (currentPolicy !== proof.policySnapshot
          || Math.abs(Math.floor(Date.now() / 1000) - verified.issuedAt) > 30)
          throw Error("TEST_FINALIZATION_STALE_POLICY_OR_PROOF");
        return db.prepare("UPDATE operator_recovery_floor"
          + " SET finalized_sequence=?,finalized_hash=?"
          + " WHERE id=1 AND sequence=? AND last_hash=?"
          + " AND finalized_sequence=? AND finalized_hash=?").run(
            next.sequence, next.lastHash, next.sequence, next.lastHash,
            previous.sequence, previous.lastHash).changes;
      }).immediate();
      if (failurePhase === "finalize-after") throw Error("TEST_FINALIZATION_ACK_LOST");
      return changed === 1;
    },
  };
  return { authority, read, setAvailable(value) { available = value; },
    setFailurePhase(phase) { failurePhase = phase; },
    get reads() { return reads; }, close() { db.close(); } };
}

module.exports = { createExternalRecoveryHeadFixture };
