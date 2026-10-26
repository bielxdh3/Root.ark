"use strict";

// Isolated PostgreSQL ciphertext WRITE-only completion marker. This cannot
// issue authorization, release ciphertext, or publish a signed ZK manifest.
// Every check and the atomic seal occur under the same authoritative
// PostgreSQL head lock as chunk INSERT and quiescence. Nothing is sealed by
// merely reaching the end of an HTTP stream.
const crypto = require("node:crypto");
const { createZk1CiphertextRootBuilder } = require("../crypto/rootark-zk-chunk-root-v1");

function fail(code = "ZK_GATE_SEAL_DENIED") {
  const error = new Error(code); error.code = code; throw error;
}
function bytes(data, length) {
  if ((!Buffer.isBuffer(data) && !(data instanceof Uint8Array))
    || data.length !== length) fail();
  return Buffer.from(data);
}
function fields(data, keys) {
  if (!data || typeof data !== "object" || Array.isArray(data)
    || Reflect.ownKeys(data).length !== keys.length
    || keys.some((field) => !Object.hasOwn(data, field))) fail();
}
function normalize(input) {
  fields(input, ["scope", "workerId", "principal", "action", "objectId",
    "revision", "digest", "admissionId", "generation", "expectedChunkCount", "expectedRootHash"]);
  fields(input.scope, ["account_id", "compartment_id", "keyring_id"]);
  const account = bytes(input.scope.account_id, 16);
  const part = input.scope.compartment_id;
  if ((!Buffer.isBuffer(part) && !(part instanceof Uint8Array))
    || part.length < 1 || part.length > 128) fail();
  const compartment = Buffer.from(part);
  if (!Number.isSafeInteger(input.revision) || input.revision < 1
    || !Number.isSafeInteger(input.generation) || input.generation < 1
    || !Number.isSafeInteger(input.expectedChunkCount) || input.expectedChunkCount < 1
    || input.expectedChunkCount > 4096 || input.action !== "put"
    || typeof input.principal !== "string" || input.principal.length < 1
    || input.principal.length > 128 || /[\x00-\x1f\x7f]/.test(input.principal)
    || typeof input.objectId !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(input.objectId)
    || Buffer.from(input.objectId, "base64url").toString("base64url") !== input.objectId) fail();
  return { key: account.toString("hex") + ":" + compartment.length.toString(16)
    + ":" + compartment.toString("hex"), keyring: bytes(input.scope.keyring_id, 16),
    worker: bytes(input.workerId, 16), principal: input.principal, objectId: input.objectId,
    revision: input.revision, digest: bytes(input.digest, 32),
    admissionId: bytes(input.admissionId, 16), generation: input.generation,
    count: input.expectedChunkCount, root: bytes(input.expectedRootHash, 32) };
}
class Zk1SharedPgSealedObjectStore {
  constructor({ pool } = {}) {
    if (!pool || typeof pool.connect !== "function") fail("ZK_GATE_SEAL_CONFIG_INVALID");
    this.pool = pool;
  }

  async seal(input) {
    // Snapshot all caller-supplied mutable buffers BEFORE first await.
    const v = normalize(input);
    let db;
    try {
      db = await this.pool.connect();
      await db.query("BEGIN");
      // PostgreSQL 18+ enforces a server-side wall-clock bound: an enormous
      // or stalled seal must not hold the quiescence row lock indefinitely.
      // On timeout the entire transaction aborts; chunks remain unsealed.
      await db.query("SET LOCAL transaction_timeout = '15000ms'");
      const head = await db.query("SELECT * FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE", [v.key]);
      const h = head.rows[0];
      if (!h || !h.keyring_id.equals(v.keyring) || h.phase !== "OPEN"
        || Number(h.generation) !== v.generation || Number(h.revision) !== v.revision
        || !h.digest.equals(v.digest)) fail();
      const admission = await db.query("SELECT * FROM zk1_gate.admission WHERE id=$1", [v.admissionId]);
      const a = admission.rows[0];
      if (!a || a.scope_key !== v.key || !a.id.equals(v.admissionId)
        || !a.worker_id.equals(v.worker) || a.principal !== v.principal
        || a.action !== "put" || a.object_id !== v.objectId
        || a.state !== "ACTIVE" || Number(a.revision) !== v.revision
        || Number(a.generation) !== v.generation || !a.digest.equals(v.digest)) fail();
      const existing = await db.query(`SELECT * FROM zk1_gate.sealed_object
        WHERE scope_key=$1 AND object_id=$2`, [v.key, v.objectId]);
      if (existing.rowCount) {
        const row = existing.rows[0];
        if (row.revision == v.revision && row.generation == v.generation
          && row.digest.equals(v.digest) && row.admission_id.equals(v.admissionId)
          && row.expected_chunks === v.count && row.root_hash.equals(v.root)) {
          await db.query("COMMIT");
          return { status: "SEALED", chunkCount: v.count };
        }
        fail();
      }
      // Check for extra chunks and read at most 4 MiB per iteration. 4096
      // chunks can total 16 GiB; no array materialization or SQL string_agg.
      const extra = await db.query(`SELECT 1 FROM zk1_gate.ciphertext_chunk
        WHERE scope_key=$1 AND object_id=$2 AND chunk_index >= $3 LIMIT 1`,
      [v.key, v.objectId, v.count]);
      if (extra.rowCount) fail("ZK_GATE_SEAL_INCOMPLETE");
      const hash = createZk1CiphertextRootBuilder(v.count);
      for (let index = 0; index < v.count; ++index) {
        const row = await db.query(`SELECT ciphertext FROM zk1_gate.ciphertext_chunk
          WHERE scope_key=$1 AND object_id=$2 AND chunk_index=$3`, [v.key, v.objectId, index]);
        if (row.rowCount !== 1) fail("ZK_GATE_SEAL_INCOMPLETE");
        hash.append(row.rows[0].ciphertext);
      }
      if (!crypto.timingSafeEqual(hash.finish(), v.root)) fail("ZK_GATE_SEAL_DIGEST_MISMATCH");
      await db.query(`INSERT INTO zk1_gate.sealed_object
        (scope_key,object_id,revision,digest,generation,admission_id,expected_chunks,root_hash)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
      [v.key, v.objectId, v.revision, v.digest, v.generation, v.admissionId, v.count, v.root]);
      await db.query("COMMIT");
      return { status: "SEALED", chunkCount: v.count };
    } catch (error) {
      if (db) { try { await db.query("ROLLBACK"); } catch (_) { /* fail closed */ } }
      if (/^ZK_GATE_SEAL_/.test(error?.code || "")) throw error;
      fail("ZK_GATE_SEAL_UNAVAILABLE");
    } finally { if (db) db.release(); }
  }
}
module.exports = { Zk1SharedPgSealedObjectStore };
