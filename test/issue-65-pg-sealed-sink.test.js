"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");

function fixture({ failFirstSeal = false, wrongSeal = false, gateRevoked = false } = {}) {
  const activity = [];
  const admissionId = crypto.randomBytes(16);
  let sealCalls = 0;
  const gateClient = {
    async beginIoAdmission(input) {
      activity.push(["start", Buffer.from(input.workerId)]);
      return { admissionId, generation: 2, proceed: true };
    },
    async putCiphertextChunk(input, chunkIndex, bytes) {
      activity.push(["put", chunkIndex, Buffer.from(bytes), Buffer.from(input.workerId)]);
      if (gateRevoked && chunkIndex === 1) throw new Error("ZK_GATE_DENIED");
      return { stored: true };
    },
    async sealCiphertextObject(input, count, root) {
      activity.push(["seal", count, Buffer.from(root), Buffer.from(input.workerId)]);
      sealCalls++;
      if (failFirstSeal && sealCalls === 1) throw new Error("lost ACK");
      return wrongSeal ? { status: "SEALED", chunkCount: count - 1 }
        : { status: "SEALED", chunkCount: count };
    },
    async finishIoAdmission({ workerId }) {
      activity.push(["finish", Buffer.from(workerId)]);
      return { status: "FINISHED" };
    },
  };
  return { gateClient, activity };
}
function request(chunks) {
  return { scope: { account_id: crypto.randomBytes(16),
    compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) },
  objectId: crypto.randomBytes(16).toString("base64url"),
  revision: 1, digest: crypto.randomBytes(32),
  chunks, expectedChunkCount: chunks.length,
  expectedRootHash: computeZk1CiphertextRoot(chunks) };
}

test("trusted sealed sink verifies expected root and seal before declaring a completed upload", async () => {
  const chunks = [crypto.randomBytes(91), crypto.randomBytes(50)];
  const f = fixture({ failFirstSeal: true });
  const sink = new Zk1SharedPgCiphertextSink({ gateClient: f.gateClient });
  assert.deepEqual(await sink.putSealed(request(chunks)),
    { status: "SEALED", chunkCount: 2 });
  assert.deepEqual(f.activity.map((a) => a[0]),
    ["start", "put", "put", "seal", "seal", "finish"]);
  assert.deepEqual(f.activity[3][2], computeZk1CiphertextRoot(chunks));
  assert.deepEqual(f.activity[3][3], f.activity[4][3]);
  assert.deepEqual(f.activity[3][3], f.activity[5][1]);
});

test("sealed sink rejects invalid root, bad receipt and revoked next chunk without reporting success", async () => {
  const chunks = [crypto.randomBytes(30), crypto.randomBytes(40)];
  const f = fixture();
  const sink = new Zk1SharedPgCiphertextSink({ gateClient: f.gateClient });
  await assert.rejects(sink.putSealed({ ...request(chunks), expectedRootHash: crypto.randomBytes(31) }),
    /ZK_GATE_SINK_UNAVAILABLE/);
  assert.deepEqual(f.activity, [], "malformed root must reject before issuing an admission");
  const g = fixture({ wrongSeal: true });
  await assert.rejects(new Zk1SharedPgCiphertextSink({ gateClient: g.gateClient })
    .putSealed(request(chunks)), /ZK_GATE_SINK_UNAVAILABLE/);
  assert.equal(g.activity.at(-1)[0], "finish");
  const h = fixture({ gateRevoked: true });
  await assert.rejects(new Zk1SharedPgCiphertextSink({ gateClient: h.gateClient })
    .putSealed(request(chunks)), /ZK_GATE_SINK_UNAVAILABLE/);
  assert.deepEqual(h.activity.map((a) => a[0]), ["start", "put", "put", "put", "finish"]);
});

test("mutable source scope cannot retarget later chunks or seal after owner authorization", async () => {
  const chunks = [crypto.randomBytes(32)];
  const input = request(chunks);
  const originalAccount = Buffer.from(input.scope.account_id);
  const originalKeyring = Buffer.from(input.scope.keyring_id);
  const f = fixture();
  const originalStart = f.gateClient.beginIoAdmission;
  f.gateClient.beginIoAdmission = async (op) => {
    const result = await originalStart(op);
    input.scope.account_id.fill(0xaa);
    input.scope.keyring_id.fill(0xbb);
    return result;
  };
  const originalPut = f.gateClient.putCiphertextChunk;
  f.gateClient.putCiphertextChunk = async (op, n, bytes) => {
    assert.deepEqual(op.scope.account_id, originalAccount);
    assert.deepEqual(op.scope.keyring_id, originalKeyring);
    return originalPut(op, n, bytes);
  };
  const originalSeal = f.gateClient.sealCiphertextObject;
  f.gateClient.sealCiphertextObject = async (op, count, root) => {
    assert.deepEqual(op.scope.account_id, originalAccount);
    return originalSeal(op, count, root);
  };
  assert.deepEqual(await new Zk1SharedPgCiphertextSink({ gateClient: f.gateClient })
    .putSealed(input), { status: "SEALED", chunkCount: 1 });
});

test("mutating external admission adapter cannot retarget subsequent physical chunks", async () => {
  const chunks = [crypto.randomBytes(40)];
  const f = fixture();
  const source = request(chunks);
  const original = Buffer.from(source.scope.account_id);
  const oldStart = f.gateClient.beginIoAdmission;
  f.gateClient.beginIoAdmission = async (input) => {
    const receipt = await oldStart(input);
    input.scope.account_id.fill(0xef);
    input.digest.fill(0xaa);
    input.workerId.fill(0xbb);
    return receipt;
  };
  const oldPut = f.gateClient.putCiphertextChunk;
  f.gateClient.putCiphertextChunk = async (input, count, bytes) => {
    assert.deepEqual(input.scope.account_id, original);
    assert.deepEqual(input.digest, source.digest);
    return oldPut(input, count, bytes);
  };
  assert.deepEqual(await new Zk1SharedPgCiphertextSink({ gateClient: f.gateClient })
    .putSealed(source), { status: "SEALED", chunkCount: 1 });
  assert.deepEqual(f.activity[0][1], f.activity[1][3],
    "worker identity must remain pinned even if START adapter mutates its input");
});

test("sealed sink commits all physical chunks and seal under real PG generation", {
  skip: !process.env.ROOTARK_ZK1_TEST_PG_URL || !process.env.ROOTARK_ZK1_RUNTIME_PG_URL
    ? "requires disposable PostgreSQL admin and restricted runtime" : false,
}, async (t) => {
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL,
    max: 2, connectionTimeoutMillis: 3000 });
  const restricted = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL,
    max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), restricted.end()]));
  const parts = [crypto.randomBytes(87), crypto.randomBytes(13)];
  const input = request(parts);
  const s = input.scope;
  const key = `${s.account_id.toString("hex")}:${s.compartment_id.length.toString(16)}:${s.compartment_id.toString("hex")}`;
  await admin.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key, s.keyring_id, input.digest]);
  const gate = new Zk1SharedPgGateAuthority({ pool: restricted });
  const sealedStore = new Zk1SharedPgSealedObjectStore({ pool: restricted });
  const principal = "trusted-isolated-gateway";
  const client = {
    beginIoAdmission: (op) => gate.beginIoAdmission({ ...op, principal }),
    putCiphertextChunk: (op, index, bytes) =>
      gate.putCiphertextChunk({ ...op, principal }, index, bytes),
    sealCiphertextObject: (op, count, root) => sealedStore.seal({ ...op,
      principal, expectedChunkCount: count, expectedRootHash: root }),
    finishIoAdmission: (op) => gate.finishIoAdmission({ ...op, principal }),
  };
  const result = await new Zk1SharedPgCiphertextSink({ gateClient: client }).putSealed(input);
  assert.deepEqual(result, { status: "SEALED", chunkCount: 2 });
  const persisted = await admin.query(`SELECT expected_chunks,root_hash FROM zk1_gate.sealed_object
    WHERE scope_key=$1 AND object_id=$2`, [key, input.objectId]);
  assert.equal(persisted.rowCount, 1);
  assert.equal(persisted.rows[0].expected_chunks, 2);
  assert.deepEqual(persisted.rows[0].root_hash, input.expectedRootHash);
  const operation = { scope: s, revision: 1, digest: input.digest,
    operationId: crypto.randomBytes(16), reservationId: crypto.randomBytes(16) };
  assert.equal((await gate.beginQuiesce(operation)).activeCount, 0,
    "the sink must not leave a live worker after a successful seal");
  assert.equal((await gate.markPending({ scope: s, operationId: operation.operationId,
    reservationId: operation.reservationId })).status, "PENDING");
});
