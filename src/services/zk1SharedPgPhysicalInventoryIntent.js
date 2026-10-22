"use strict";

// Trusted gate-side PREWRITE binding: exact inventory operation -> physical
// object/root/generation. PostgreSQL enforces immutable first-writer wins under
// its own head row lock. Never callable by a generic web user or writer child.
const crypto = require("node:crypto");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { verifyZk1SharedPgRuntimePool } = require("./zk1SharedPgGateRuntime");

function fail() {
  const e = new Error("ZK_PHYSICAL_INTENT_UNAVAILABLE");
  e.code = e.message;
  throw e;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) fail();
  const out = Object.create(null);
  for (const key of keys) {
    const d = Object.getOwnPropertyDescriptor(value, key);
    if (!d || !Object.hasOwn(d, "value")) fail();
    out[key] = d.value;
  }
  return out;
}
function bytes(value, n) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
    || value.byteLength !== n) fail();
  return Buffer.from(value);
}
function same(a, b) { return crypto.timingSafeEqual(a, b); }
function copy(input) {
  const r = exact(input, ["scope", "operation", "digest", "expectedRootHash", "expectedChunkCount"]);
  const scope = inventory.normalizeScope(r.scope);
  const op = exact(r.operation, [
    "operation_id", "expected_sequence", "expected_root", "object_id",
    "revision", "epoch", "ciphertext_sha256",
  ]);
  const entry = inventory.normalizeEntry({
    object_id: op.object_id, revision: op.revision,
    epoch: op.epoch, ciphertext_sha256: op.ciphertext_sha256,
  });
  if (!Number.isSafeInteger(op.expected_sequence) || op.expected_sequence < 0
    || op.expected_sequence >= inventory.MAX_ENTRIES
    || !Number.isSafeInteger(r.expectedChunkCount) || r.expectedChunkCount < 1
    || r.expectedChunkCount > 16) fail();
  return {
    scope,
    scopeKey: scope.account_id.toString("hex") + ":" + scope.compartment_id.length.toString(16)
      + ":" + scope.compartment_id.toString("hex"),
    operationId: bytes(op.operation_id, 16),
    expectedSequence: op.expected_sequence, expectedRoot: bytes(op.expected_root, 32),
    objectId: entry.object_id.toString("base64url"), revision: entry.revision,
    epoch: entry.epoch, ciphertextSha256: entry.ciphertext_sha256,
    digest: bytes(r.digest, 32), root: bytes(r.expectedRootHash, 32),
    count: r.expectedChunkCount,
  };
}
function isSame(row, x, generation) {
  return row && row.scope_key === x.scopeKey && row.object_id === x.objectId
    && same(row.operation_id, x.operationId)
    && Number(row.expected_inventory_sequence) === x.expectedSequence
    && same(row.expected_inventory_root, x.expectedRoot)
    && same(row.keyring_id, x.scope.keyring_id)
    && Number(row.revision) === x.revision && Number(row.epoch) === x.epoch
    && same(row.digest, x.digest) && Number(row.generation) === generation
    && same(row.ciphertext_sha256, x.ciphertextSha256)
    && same(row.expected_root_hash, x.root) && row.expected_chunks === x.count;
}

class Zk1SharedPgPhysicalInventoryIntent {
  constructor({ pool } = {}) {
    if (!pool || typeof pool.connect !== "function") fail();
    this.pool = pool;
  }
  async reserveExact(input) {
    const v = copy(input);
    // Full SQL role identity preflight, including hidden SET ROLE powers,
    // before any lock or mutation. A privileged web/app/attestor role is not a binder.
    const role = await verifyZk1SharedPgRuntimePool(this.pool).catch(() => fail());
    let c;
    let open = false;
    try {
      c = await this.pool.connect();
      await c.query("BEGIN ISOLATION LEVEL READ COMMITTED");
      open = true;
      await c.query("SET LOCAL transaction_timeout = '10000ms'");
      const identity = await c.query(
        "SELECT session_user AS session_identity,current_user AS active_identity");
      if (identity.rowCount !== 1
        || identity.rows[0]?.session_identity !== role.runtimeRole
        || identity.rows[0]?.active_identity !== role.runtimeRole) fail();
      const rows = await c.query(`SELECT keyring_id,revision,digest,generation,phase,
          require_physical_inventory_intent
        FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE`, [v.scopeKey]);
      const h = rows.rows?.[0];
      if (rows.rowCount !== 1 || !h || h.phase !== "OPEN"
        || h.require_physical_inventory_intent !== true
        || !same(h.keyring_id, v.scope.keyring_id)
        || Number(h.revision) !== v.revision || !same(h.digest, v.digest)
        || !Number.isSafeInteger(Number(h.generation))) fail();
      const generation = Number(h.generation);
      const previous = await c.query(`SELECT * FROM zk1_gate.physical_inventory_intent
        WHERE scope_key=$1 AND object_id=$2`, [v.scopeKey, v.objectId]);
      if (previous.rowCount > 1
        || (previous.rowCount === 1 && !isSame(previous.rows[0], v, generation))) fail();
      if (!previous.rowCount) {
        const result = await c.query(`INSERT INTO zk1_gate.physical_inventory_intent
          (scope_key,object_id,operation_id,expected_inventory_sequence,
            expected_inventory_root,keyring_id,revision,epoch,digest,generation,
            ciphertext_sha256,expected_root_hash,expected_chunks)
          VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
        [v.scopeKey, v.objectId, v.operationId, v.expectedSequence, v.expectedRoot,
          v.scope.keyring_id, v.revision, v.epoch, v.digest, generation,
          v.ciphertextSha256, v.root, v.count]);
        if (result.rowCount !== 1) fail();
      }
      await c.query("COMMIT");
      open = false;
      return Object.freeze({ status: "IMMUTABLE_PREWRITE_INTENT",
        operationId: Buffer.from(v.operationId), generation,
        replay: previous.rowCount === 1, authorizesIo: false });
    } catch (_) {
      if (open && c) { try { await c.query("ROLLBACK"); } catch (_) {} }
      fail();
    } finally { if (c) c.release(); }
  }
}
module.exports = { Zk1SharedPgPhysicalInventoryIntent };
