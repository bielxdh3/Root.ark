"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");

const url = process.env.ROOTARK_ZK1_TEST_PG_URL;
const restrictedUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const pgTest = { skip: !url && "requires disposable ROOTARK_ZK1_TEST_PG_URL" };
test("ciphertext root v1 independently matches domain-separated index and byte lengths", () => {
  const chunks = [Buffer.from("encrypted-A"), Buffer.from("encrypted-BC")];
  const count = Buffer.alloc(4); count.writeUInt32BE(chunks.length);
  const fields = [Buffer.from("Root.ark/zk-1/ciphertext-chunk-root/v1\0", "ascii"), count];
  for (let i = 0; i < chunks.length; ++i) {
    const header = Buffer.alloc(8);
    header.writeUInt32BE(i, 0);
    header.writeUInt32BE(chunks[i].length, 4);
    fields.push(header, crypto.createHash("sha256").update(chunks[i]).digest());
  }
  const independentlyEncoded = crypto.createHash("sha256")
    .update(Buffer.concat(fields)).digest();
  assert.deepEqual(computeZk1CiphertextRoot(chunks), independentlyEncoded);
  assert.notDeepEqual(computeZk1CiphertextRoot([chunks[1], chunks[0]]), independentlyEncoded);
  assert.notDeepEqual(computeZk1CiphertextRoot([Buffer.concat(chunks)]), independentlyEncoded);
  assert.throws(() => computeZk1CiphertextRoot([]), /ZK_CHUNK_ROOT_INVALID/);
  assert.throws(() => computeZk1CiphertextRoot([Buffer.alloc(0)]), /ZK_CHUNK_ROOT_INVALID/);
});
function scope() {
  return { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(6),
    keyring_id: crypto.randomBytes(16) };
}
function key(s) {
  return `${s.account_id.toString("hex")}:${s.compartment_id.length.toString(16)}:${s.compartment_id.toString("hex")}`;
}
async function setup(t) {
  const pool = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => pool.end());
  const runtime = restrictedUrl
    ? new Pool({ connectionString: restrictedUrl, max: 2, connectionTimeoutMillis: 3000 })
    : pool;
  if (runtime !== pool) t.after(async () => runtime.end());
  const s = scope();
  const digest = crypto.randomBytes(32);
  await pool.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key(s), s.keyring_id, digest]);
  const gate = new Zk1SharedPgGateAuthority({ pool });
  const store = new Zk1SharedPgSealedObjectStore({ pool: runtime });
  const io = { scope: s, workerId: crypto.randomBytes(16), principal: "fixture-gateway",
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"), revision: 1, digest };
  const admission = await gate.beginIoAdmission(io);
  const worker = { ...io, admissionId: admission.admissionId, generation: admission.generation };
  return { pool, runtime, gate, store, scope: s, io, worker, digest };
}

test("incomplete ciphertext is not publishable; final seal binds ordered bytes and admission", pgTest, async (t) => {
  const f = await setup(t);
  const chunks = [crypto.randomBytes(200), crypto.randomBytes(300), crypto.randomBytes(11)];
  const manifest = { ...f.worker, expectedChunkCount: chunks.length,
    expectedRootHash: computeZk1CiphertextRoot(chunks) };
  await f.gate.putCiphertextChunk(f.worker, 0, chunks[0]);
  await assert.rejects(f.store.seal(manifest), /ZK_GATE_SEAL_INCOMPLETE/);
  assert.equal((await f.pool.query("SELECT count(*)::int AS n FROM zk1_gate.sealed_object WHERE scope_key=$1",
    [key(f.scope)])).rows[0].n, 0, "partial writes never become a visible finalized object");
  await f.gate.putCiphertextChunk(f.worker, 1, chunks[1]);
  await f.gate.putCiphertextChunk(f.worker, 2, chunks[2]);
  await assert.rejects(f.store.seal({ ...manifest, expectedRootHash: crypto.randomBytes(32) }),
    /ZK_GATE_SEAL_DIGEST_MISMATCH/);
  await assert.rejects(f.store.seal({ ...manifest, workerId: crypto.randomBytes(16) }),
    /ZK_GATE_SEAL_DENIED/);
  assert.deepEqual(await f.store.seal(manifest), { status: "SEALED", chunkCount: 3 });
  assert.deepEqual(await f.store.seal(manifest), { status: "SEALED", chunkCount: 3 },
    "lost seal ACK is idempotent only for exact still-active admission");
  const saved = await f.pool.query(`SELECT root_hash,expected_chunks FROM zk1_gate.sealed_object
    WHERE scope_key=$1 AND object_id=$2`, [key(f.scope), f.io.objectId]);
  assert.equal(saved.rowCount, 1);
  assert.deepEqual(saved.rows[0].root_hash, manifest.expectedRootHash);
  assert.equal(saved.rows[0].expected_chunks, 3);
  await assert.rejects(f.gate.putCiphertextChunk(f.worker, 3, crypto.randomBytes(16)),
    /ZK_GATE_UNAVAILABLE|ZK_GATE_DENIED/,
    "once sealed, even a still-authorized worker must not append hidden trailing chunks");
  await assert.rejects(f.runtime.query(`INSERT INTO zk1_gate.ciphertext_chunk
    (scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,3,$3)`,
  [key(f.scope), f.io.objectId, crypto.randomBytes(16)]),
  /sealed ciphertext object is immutable/i,
  "even direct INSERT with the restricted gate SQL role must not bypass the physical seal");
  const remaining = await f.pool.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1 AND object_id=$2`, [key(f.scope), f.io.objectId]);
  assert.equal(remaining.rows[0].n, 3);
});

test("quiescence and wrong scope prohibit sealing, and crashes leave chunks unsealed", pgTest, async (t) => {
  const f = await setup(t);
  const chunks = [crypto.randomBytes(60)];
  const manifest = { ...f.worker, expectedChunkCount: 1,
    expectedRootHash: computeZk1CiphertextRoot(chunks) };
  await f.gate.putCiphertextChunk(f.worker, 0, chunks[0]);
  await assert.rejects(f.store.seal({ ...manifest, scope: scope() }), /ZK_GATE_SEAL_DENIED/);
  const op = { scope: f.scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest: f.digest };
  const q = await f.gate.beginQuiesce(op);
  assert.equal(q.state, "QUIESCING");
  await assert.rejects(f.store.seal(manifest), /ZK_GATE_SEAL_DENIED/,
    "no seal after authoritative quiesce even if all bytes were previously stored");
  assert.equal((await f.pool.query("SELECT count(*)::int AS n FROM zk1_gate.sealed_object WHERE scope_key=$1",
    [key(f.scope)])).rows[0].n, 0);
});

test("restricted PostgreSQL stale snapshots cannot append chunks AFTER a committed seal", {
  skip: !url || !restrictedUrl ? "requires disposable isolated PG plus restricted runtime login" : false,
}, async (t) => {
  const f = await setup(t);
  const chunk = crypto.randomBytes(131);
  const seal = { ...f.worker, expectedChunkCount: 1,
    expectedRootHash: computeZk1CiphertextRoot([chunk]) };
  await f.gate.putCiphertextChunk(f.worker, 0, chunk);
  const adversary = new Pool({ connectionString: restrictedUrl, max: 3,
    connectionTimeoutMillis: 3000 });
  const pinned = [];
  t.after(async () => {
    for (const entry of pinned) {
      if (entry.released) continue;
      try { await entry.c.query("ROLLBACK"); } catch (_) { /* disposable fixture */ }
      entry.c.release();
      entry.released = true;
    }
    await adversary.end();
  });
  for (const level of ["READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE"]) {
    const c = await adversary.connect();
    pinned.push({ c, level, released: false });
    await c.query("BEGIN ISOLATION LEVEL " + level);
    const snapshot = await c.query(`SELECT COUNT(*)::int AS n
      FROM zk1_gate.sealed_object WHERE scope_key=$1 AND object_id=$2`,
    [key(f.scope), f.io.objectId]);
    assert.equal(snapshot.rows[0].n, 0, "attacker establishes a pre-seal view");
  }
  assert.deepEqual(await f.store.seal(seal), { status: "SEALED", chunkCount: 1 });
  for (const entry of pinned) {
    const { c, level } = entry;
    try {
      await assert.rejects(c.query(`INSERT INTO zk1_gate.ciphertext_chunk
        (scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,1,$3)`,
      [key(f.scope), f.io.objectId, crypto.randomBytes(31)]),
      /sealed|isolation|serializ|serialize|denied|unsupported/i,
      "restricted runtime must not bypass the physical trigger with stale " + level + " snapshot");
    } finally {
      await c.query("ROLLBACK");
      c.release();
      entry.released = true;
    }
  }
  const stored = await f.pool.query(`SELECT chunk_index FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1 AND object_id=$2 ORDER BY chunk_index`,
  [key(f.scope), f.io.objectId]);
  assert.deepEqual(stored.rows.map((row) => row.chunk_index), [0],
    "sealed ciphertext object must not accumulate hidden chunks");
});
