"use strict";

// Standalone, operator-owned PostgreSQL ciphertext read adapter for the
// directly supervised GET laboratory. This reader holds the authoritative
// head row lock while selecting REAL sealed bytes. It never writes to a
// network socket: physical STOP of the independently owned egress child is
// still required before the gate may progress to PENDING.
const { Zk1SharedPgGateAuthority } = require("./zk1SharedPgGateAuthority");
const { verifyZk1SharedPgRuntimePool } = require("./zk1SharedPgGateRuntime");

function deny() {
  const error = new Error("ZK_GATE_GET_DENIED");
  error.code = error.message;
  throw error;
}
function blob(value, size) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length !== size) deny();
  return Buffer.from(value);
}
function scopeOf(scope) {
  if (!scope || typeof scope !== "object" || Array.isArray(scope)
    || Reflect.ownKeys(scope).length !== 3
    || ["account_id", "compartment_id", "keyring_id"].some((k) => !Object.hasOwn(scope, k))) deny();
  const account = blob(scope.account_id, 16);
  const keyring = blob(scope.keyring_id, 16);
  const part = scope.compartment_id;
  if ((!Buffer.isBuffer(part) && !(part instanceof Uint8Array))
    || part.length < 1 || part.length > 128) deny();
  const compartment = Buffer.from(part);
  return { key: account.toString("hex") + ":" + compartment.length.toString(16)
    + ":" + compartment.toString("hex"), keyring };
}

class Zk1SharedPgSealedGetReader {
  constructor({ gate } = {}) {
    if (!(gate instanceof Zk1SharedPgGateAuthority)) deny();
    this.gate = gate;
  }

  async preflight() {
    await verifyZk1SharedPgRuntimePool(this.gate.pool);
  }

  async readChunk({ io, process, admissionId, generation, expectedRootHash,
    chunkIndex } = {}) {
    // Snapshot every caller-owned byte before the first asynchronous read.
    if (!io || typeof io !== "object" || Array.isArray(io)
      || Reflect.ownKeys(io).length !== 7 || io.action !== "get"
      || typeof io.principal !== "string" || io.principal.length < 1
      || typeof io.objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(io.objectId)
      || Buffer.from(io.objectId, "base64url").toString("base64url") !== io.objectId
      || !Number.isSafeInteger(io.revision) || io.revision < 1
      || !Number.isSafeInteger(generation) || generation < 1
      || !Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > 4095
      || !process || !Number.isSafeInteger(process.processPid)
      || process.processPid < 1 || process.processPid > 0x7fffffff) deny();
    const s = scopeOf(io.scope);
    const worker = blob(io.workerId, 16);
    const digest = blob(io.digest, 32);
    const admission = blob(admissionId, 16);
    const hostKey = blob(process.hostKeyId, 16);
    const epoch = blob(process.processEpoch, 16);
    const root = blob(expectedRootHash, 32);
    const { principal, objectId, revision } = io;
    try {
      return await this.gate.transaction(async (db) => {
        const h = await this.gate.lockedHead(db, { key: s.key, keyringId: s.keyring });
        if (h.require_stop_proof !== true || h.phase !== "OPEN"
          || Number(h.generation) !== generation || Number(h.revision) !== revision
          || !h.digest.equals(digest)) deny();
        const a = await db.query("SELECT * FROM zk1_gate.admission WHERE id=$1", [admission]);
        const workerRow = a.rows[0];
        if (a.rowCount !== 1 || !workerRow || workerRow.scope_key !== s.key
          || !workerRow.id.equals(admission) || !workerRow.worker_id.equals(worker)
          || workerRow.principal !== principal || workerRow.action !== "get"
          || workerRow.object_id !== objectId || workerRow.state !== "ACTIVE"
          || Number(workerRow.generation) !== generation
          || Number(workerRow.revision) !== revision || !workerRow.digest.equals(digest)
          || !workerRow.host_key_id?.equals(hostKey)
          || !workerRow.process_epoch?.equals(epoch)
          || Number(workerRow.process_pid) !== process.processPid) deny();
        const sealed = await db.query(`SELECT revision,digest,generation,expected_chunks,root_hash
          FROM zk1_gate.sealed_object WHERE scope_key=$1 AND object_id=$2`, [s.key, objectId]);
        const object = sealed.rows[0];
        if (sealed.rowCount !== 1 || !object || Number(object.revision) !== revision
          || !object.digest.equals(digest) || Number(object.generation) !== generation
          || !object.root_hash.equals(root) || Number(object.expected_chunks) !== 2
          || chunkIndex >= Number(object.expected_chunks)) deny();
        const chunk = await db.query(`SELECT ciphertext FROM zk1_gate.ciphertext_chunk
          WHERE scope_key=$1 AND object_id=$2 AND chunk_index=$3`, [s.key, objectId, chunkIndex]);
        if (chunk.rowCount !== 1 || !Buffer.isBuffer(chunk.rows[0]?.ciphertext)
          || chunk.rows[0].ciphertext.length < 1 || chunk.rows[0].ciphertext.length > 4 * 1024 * 1024) deny();
        return Buffer.from(chunk.rows[0].ciphertext);
      });
    } catch (_) { deny(); }
  }
}

module.exports = { Zk1SharedPgSealedGetReader };
