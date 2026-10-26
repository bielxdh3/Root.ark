"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const fileCrypto = require("../public/client/rootark-zk1-file-content");
const clientRoot = require("../public/client/rootark-zk1-ciphertext-chunk-root");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const gateUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const skip = !adminUrl || !gateUrl
  ? "needs disposable loopback PostgreSQL admin and restricted gate SQL identities" : false;
const random = (count) => crypto.randomBytes(count);
const hex = (bytes) => bytes.toString("hex");
const scopeKey = (s) => [hex(s.account_id),
  s.compartment_id.length.toString(16), hex(s.compartment_id)].join(":");
const b64 = (value) => value.toString("base64url");

async function setup(t) {
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const gatePool = new Pool({ connectionString: gateUrl, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), gatePool.end()]));
  const scope = { account_id: random(16), compartment_id: random(7),
    keyring_id: random(16) };
  const digest = random(32);
  // Legacy reference only. The strict physical STOP/remote/device-authorized
  // production gateway remains DENIED; this test proves byte-format interop.
  await admin.query("INSERT INTO zk1_gate.head" +
    " (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,FALSE)",
  [scopeKey(scope), scope.keyring_id, digest]);
  const objectId = b64(random(16));
  const io = { scope, workerId: random(16), principal: "client-only-browser-fixture",
    action: "put", objectId, revision: 1, digest };
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool });
  const sealStore = new Zk1SharedPgSealedObjectStore({ pool: gatePool });
  const admission = await gate.beginIoAdmission(io);
  assert.equal(admission.proceed, true);
  return { admin, gate, sealStore, scope, io, admission, objectId };
}

async function encryptFixture(scope, objectId) {
  const cek = await fileCrypto.generateFileCek();
  assert.equal(cek.extractable, false);
  const identifier = () => b64(random(16));
  const metadata = {
    account_id: b64(scope.account_id), compartment_id: b64(scope.compartment_id),
    keyring_id: b64(scope.keyring_id), object_id: objectId, version_id: identifier(),
    parent_version_id: null, epoch: 1, kind: "file",
  };
  const privateName = "super-secret-browser-file.txt";
  const source = random(512 * 1024);
  const encrypted = Buffer.from(await fileCrypto.encryptFile({ cek, metadata,
    name: privateName, mediaType: "application/octet-stream", data: source }));
  const chunks = [];
  for (let start = 0; start < encrypted.length; start += 128 * 1024) {
    chunks.push(Buffer.from(encrypted.subarray(start, Math.min(start + 128 * 1024, encrypted.length))));
  }
  const root = Buffer.from(await clientRoot.computeCiphertextRoot(chunks));
  assert.deepEqual(root, computeZk1CiphertextRoot(chunks));
  return { cek, metadata, privateName, source, encrypted, chunks, root };
}

test("client-only AES-GCM and WebCrypto root seal ordered physical PG ciphertext with no server CEK", {
  skip,
}, async (t) => {
  const f = await setup(t);
  const file = await encryptFixture(f.scope, f.objectId);
  assert.equal(file.encrypted.includes(Buffer.from(file.privateName)), false);
  const grant = { ...f.io, admissionId: f.admission.admissionId,
    generation: f.admission.generation };
  for (let i = 0; i < file.chunks.length; ++i) {
    assert.deepEqual(await f.gate.putCiphertextChunk(grant, i, file.chunks[i]),
      { stored: true });
  }
  const expected = { ...grant, expectedChunkCount: file.chunks.length,
    expectedRootHash: file.root };
  assert.deepEqual(await f.sealStore.seal(expected),
    { status: "SEALED", chunkCount: file.chunks.length });
  const physical = await f.admin.query("SELECT chunk_index,ciphertext" +
    " FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1 AND object_id=$2 ORDER BY chunk_index",
  [scopeKey(f.scope), f.objectId]);
  assert.deepEqual(physical.rows.map((r) => r.chunk_index),
    file.chunks.map((_, i) => i));
  const loaded = Buffer.concat(physical.rows.map((r) => r.ciphertext));
  assert.equal(loaded.includes(Buffer.from(file.privateName)), false);
  const storedRoot = await f.admin.query("SELECT root_hash,expected_chunks FROM zk1_gate.sealed_object" +
    " WHERE scope_key=$1 AND object_id=$2", [scopeKey(f.scope), f.objectId]);
  assert.equal(storedRoot.rowCount, 1);
  assert.deepEqual(storedRoot.rows[0].root_hash, file.root);
  assert.equal(storedRoot.rows[0].expected_chunks, file.chunks.length);
  assert.deepEqual(Buffer.from(await clientRoot.computeCiphertextRoot(
    physical.rows.map((r) => r.ciphertext))), file.root);
  const decrypted = await fileCrypto.decryptFile({ cek: file.cek,
    metadata: file.metadata, envelopeBytes: loaded });
  assert.equal(decrypted.name, file.privateName);
  assert.deepEqual(Buffer.from(decrypted.data), file.source);
  decrypted.data.fill(0);
});

test("foreign client ciphertext root is not publishable; corrupt post-seal bytes are detectable by client", {
  skip,
}, async (t) => {
  const f = await setup(t);
  const file = await encryptFixture(f.scope, f.objectId);
  const grant = { ...f.io, admissionId: f.admission.admissionId,
    generation: f.admission.generation };
  for (let i = 0; i < file.chunks.length; ++i) {
    await f.gate.putCiphertextChunk(grant, i, file.chunks[i]);
  }
  const expected = { ...grant, expectedChunkCount: file.chunks.length,
    expectedRootHash: file.root };
  await assert.rejects(f.sealStore.seal({ ...expected,
    expectedRootHash: Buffer.from(await clientRoot.computeCiphertextRoot(
      file.chunks.slice().reverse())) }), /ZK_GATE_SEAL_DIGEST_MISMATCH/);
  assert.equal((await f.admin.query("SELECT COUNT(*)::int AS n FROM zk1_gate.sealed_object" +
    " WHERE scope_key=$1", [scopeKey(f.scope)])).rows[0].n, 0);
  assert.equal((await f.sealStore.seal(expected)).status, "SEALED");
  // Simulate privileged storage/database compromise on disposable fixture:
  // a cached SEALED marker does NOT imply ciphertext can never be corrupted.
  const corrupted = Buffer.from(file.chunks[0]);
  corrupted[0] ^= 1;
  await f.admin.query("UPDATE zk1_gate.ciphertext_chunk SET ciphertext=$1" +
    " WHERE scope_key=$2 AND object_id=$3 AND chunk_index=0",
  [corrupted, scopeKey(f.scope), f.objectId]);
  const rows = (await f.admin.query("SELECT ciphertext FROM zk1_gate.ciphertext_chunk" +
    " WHERE scope_key=$1 AND object_id=$2 ORDER BY chunk_index",
  [scopeKey(f.scope), f.objectId])).rows;
  const readRoot = Buffer.from(await clientRoot.computeCiphertextRoot(
    rows.map((r) => r.ciphertext)));
  assert.notDeepEqual(readRoot, file.root,
    "client detects DB-admin modified bytes against the previously pinned client root");
  await assert.rejects(fileCrypto.decryptFile({ cek: file.cek, metadata: file.metadata,
    envelopeBytes: Buffer.concat(rows.map((r) => r.ciphertext)) }), /ZK_FILE_INVALID/);
});
