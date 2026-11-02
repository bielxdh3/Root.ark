"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");

const url = process.env.ROOTARK_ZK1_TEST_PG_URL;
const restrictedUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const attestorUrl = process.env.ROOTARK_ZK1_ATTESTOR_PG_URL;
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

test("PG18 strict physical revisions preserve v1 ciphertext and reject stale or same-revision replacement", {
  skip: !url || !restrictedUrl || !attestorUrl
    ? "requires disposable PG18 plus isolated gate and attestor runtimes" : false,
}, async (t) => {
  const admin = new Pool({ connectionString: url, max: 3, connectionTimeoutMillis: 3000 });
  const runtime = new Pool({ connectionString: restrictedUrl, max: 2, connectionTimeoutMillis: 3000 });
  const attestor = new Pool({ connectionString: attestorUrl, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => { await admin.end(); await runtime.end(); await attestor.end(); });
  const s = scope();
  const scopeKey = key(s);
  const objectId = crypto.randomBytes(16).toString("base64url");
  const gate = new Zk1SharedPgGateAuthority({ pool: runtime });
  const store = new Zk1SharedPgSealedObjectStore({ pool: runtime });
  const intent = new Zk1SharedPgPhysicalInventoryIntent({ pool: runtime });
  const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool: attestor });
  const firstDigest = crypto.randomBytes(32);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_physical_inventory_intent)
    VALUES($1,$2,1,$3,true)`, [scopeKey, s.keyring_id, firstDigest]);
  const write = async (revision, digest, bytes, sequence, physicalObjectId = objectId) => {
    const op = { operation_id: crypto.randomBytes(16), expected_sequence: sequence,
      expected_root: crypto.randomBytes(32), object_id: Buffer.from(physicalObjectId, "base64url"),
      revision, epoch: 1, ciphertext_sha256: crypto.createHash("sha256").update(bytes).digest() };
    const request = { scope: s, operation: op, digest,
      expectedRootHash: computeZk1CiphertextRoot([bytes]), expectedChunkCount: 1 };
    await intent.reserveExact(request);
    const io = { scope: s, workerId: crypto.randomBytes(16), principal: "versioned-physical-fixture",
      action: "put", objectId: physicalObjectId, revision, digest };
    const admission = await gate.beginIoAdmission(io);
    assert.equal(admission.proceed, true);
    const authorized = { ...io, admissionId: admission.admissionId,
      generation: admission.generation };
    assert.deepEqual(await gate.putCiphertextChunk(authorized, 0, bytes), { stored: true });
    assert.deepEqual(await store.seal({ ...authorized, expectedChunkCount: 1,
      expectedRootHash: request.expectedRootHash }), { status: "SEALED", chunkCount: 1 });
    await assert.rejects(gate.putCiphertextChunk(authorized, 1, bytes),
      /ZK_GATE_DENIED|ZK_GATE_UNAVAILABLE/);
    assert.deepEqual(await store.seal({ ...authorized, expectedChunkCount: 1,
      expectedRootHash: request.expectedRootHash }), { status: "SEALED", chunkCount: 1 });
    await assert.rejects(intent.reserveExact({ ...request,
      operation: { ...op, operation_id: crypto.randomBytes(16) } }),
    /ZK_PHYSICAL_INTENT_UNAVAILABLE/, "same version cannot be relabeled to another operation");
    await gate.finishIoAdmission({ scope: s, admissionId: admission.admissionId,
      workerId: io.workerId, principal: io.principal });
    return { request, authorized, physicalObjectId };
  };
  const first = crypto.randomBytes(48);
  const firstSeal = await write(1, firstDigest, first, 0);
  assert.equal((await intent.reserveExact(firstSeal.request)).replay, true,
    "same operation prewrite replay is read-only and preserves the original revision");
  await assert.rejects(runtime.query(`INSERT INTO zk1_gate.ciphertext_chunk
    (scope_key,object_id,revision,chunk_index,ciphertext) VALUES($1,$2,1,1,$3)`,
  [scopeKey, objectId, first]), /revision differs|immutable|denied/i,
  "restricted SQL cannot append to the prior sealed revision");
  const second = crypto.randomBytes(60);
  const secondSeal = await write(2, firstDigest, second, 1);
  const secondObjectId = crypto.randomBytes(16).toString("base64url");
  const siblingSeal = await write(1, firstDigest, crypto.randomBytes(25), 2, secondObjectId);
  await assert.rejects(gate.beginIoAdmission({ scope: s, workerId: crypto.randomBytes(16),
    principal: "versioned-physical-fixture", action: "put", objectId,
    revision: 1, digest: firstDigest }), /ZK_GATE_UNAVAILABLE|ZK_GATE_DENIED/,
  "a new stale v1 admission cannot consume or replace its immutable physical binding");
  await assert.rejects(runtime.query(`INSERT INTO zk1_gate.admission
    (id,scope_key,worker_id,principal,action,object_id,revision,object_revision,digest,generation,state)
    VALUES($1,$2,$3,'gate-forgery','put',$4,2,2,$5,1,'ACTIVE')`,
  [crypto.randomBytes(16), scopeKey, crypto.randomBytes(16), objectId, firstDigest]),
  /current OPEN gate|revision|denied/i,
  "attacker cannot substitute object revision for current gate authority revision");
  const persisted = await admin.query(`SELECT c.revision,c.ciphertext,s.root_hash,i.operation_id,
      b.admission_id FROM zk1_gate.ciphertext_chunk c
    JOIN zk1_gate.sealed_object s ON s.scope_key=c.scope_key
      AND s.object_id=c.object_id AND s.revision=c.revision
    JOIN zk1_gate.physical_inventory_intent i ON i.scope_key=c.scope_key
      AND i.object_id=c.object_id AND i.revision=c.revision
    JOIN zk1_gate.physical_inventory_admission b ON b.scope_key=c.scope_key
      AND b.object_id=c.object_id AND b.revision=c.revision
    WHERE c.scope_key=$1 AND c.object_id=$2 AND c.chunk_index=0 ORDER BY c.revision`,
  [scopeKey, objectId]);
  assert.deepEqual(persisted.rows.map((row) => Number(row.revision)), [1, 2]);
  assert.deepEqual(persisted.rows.map((row) => row.ciphertext), [first, second]);
  assert.deepEqual(persisted.rows[0].root_hash, firstSeal.request.expectedRootHash);
  assert.deepEqual(persisted.rows[1].root_hash, secondSeal.request.expectedRootHash);
  assert.deepEqual(persisted.rows[0].operation_id, firstSeal.request.operation.operation_id);
  assert.deepEqual(persisted.rows[1].operation_id, secondSeal.request.operation.operation_id);
  assert.notDeepEqual(persisted.rows[0].admission_id, persisted.rows[1].admission_id);
  const gateRevision = await admin.query(`SELECT revision,object_revision FROM zk1_gate.admission
    WHERE id=$1`, [secondSeal.authorized.admissionId]);
  assert.equal(Number(gateRevision.rows[0].revision), 1, "scope-wide gate authority stays pinned");
  assert.equal(Number(gateRevision.rows[0].object_revision), 2, "signed object revision stays separate");
  const reread = async ({ request, physicalObjectId }) => verifier.verifyExact({
    scope: s, objectId: physicalObjectId, revision: request.operation.revision,
    digest: firstDigest, expectedRootHash: request.expectedRootHash,
    expectedChunkCount: request.expectedChunkCount,
    expectedSha256: request.operation.ciphertext_sha256,
    operationId: request.operation.operation_id,
    expectedInventorySequence: request.operation.expected_sequence,
    expectedInventoryRoot: request.operation.expected_root, epoch: request.operation.epoch,
  });
  for (const item of [firstSeal, secondSeal, siblingSeal]) {
    const result = await reread(item);
    assert.equal(result.status, "PHYSICALLY_REREAD_PG_COMMITTED");
    assert.deepEqual(result.operationId, item.request.operation.operation_id);
    assert.equal(result.revision, item.request.operation.revision);
  }
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

test("restricted SQL login cannot forge SEALED rows without exact live admission and full chunks", {
  skip: !url || !restrictedUrl ? "requires disposable PG restricted runtime login" : false,
}, async (t) => {
  const f = await setup(t);
  const direct = new Pool({ connectionString: restrictedUrl, max: 1,
    connectionTimeoutMillis: 3000 });
  t.after(async () => direct.end());
  const insert = async (admissionId, count, rootHash = crypto.randomBytes(32)) => direct.query(`
    INSERT INTO zk1_gate.sealed_object
      (scope_key,object_id,revision,digest,generation,admission_id,expected_chunks,root_hash)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
  [key(f.scope), f.io.objectId, f.io.revision, f.digest,
    f.worker.generation, admissionId, count, rootHash]);
  await assert.rejects(insert(crypto.randomBytes(16), 1),
    /seal|admission|chunk|deny|integrity|violat/i,
    "a restricted role must not invent a sealed object with no admission/chunks");
  const first = crypto.randomBytes(124);
  await f.gate.putCiphertextChunk(f.worker, 0, first);
  await assert.rejects(insert(f.worker.admissionId, 2),
    /seal|admission|chunk|deny|integrity|violat/i,
    "one stored chunk must not finalize an object claiming two chunks");
  await assert.rejects(insert(f.worker.admissionId, 1),
    /seal|admission|chunk|deny|integrity|violat/i,
    "even matching live admission and complete chunks cannot authorize a forged ciphertext digest");
  const correctHash = computeZk1CiphertextRoot([first]);
  const c = await direct.connect();
  try {
    await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
    await assert.rejects(c.query(`INSERT INTO zk1_gate.sealed_object
      (scope_key,object_id,revision,digest,generation,admission_id,expected_chunks,root_hash)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [key(f.scope), f.io.objectId, f.io.revision, f.digest,
      f.worker.generation, f.worker.admissionId, 1, correctHash]),
    /isolation|read committed/i,
    "a snapshot-isolated direct SQL seal must never claim complete fresh ciphertext");
  } finally { await c.query("ROLLBACK"); c.release(); }
  assert.equal((await f.pool.query("SELECT COUNT(*)::int AS n FROM zk1_gate.sealed_object WHERE scope_key=$1",
    [key(f.scope)])).rows[0].n, 0);
  assert.deepEqual(await f.store.seal({ ...f.worker,
    expectedChunkCount: 1, expectedRootHash: correctHash }),
  { status: "SEALED", chunkCount: 1 },
  "the fully validated trusted sealing path must remain available");
});
