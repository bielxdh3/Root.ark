"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1PgPhysicalInventoryBridge } = require("../src/services/zk1PgPhysicalInventoryBridge");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");

function fixture({ sealed, readbackFailure = false, terminal = false }) {
  const chunks = [crypto.randomBytes(32), crypto.randomBytes(27)];
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("vault"), keyring_id: crypto.randomBytes(16) };
  const operation = { operation_id: crypto.randomBytes(16), expected_sequence: 0,
    expected_root: crypto.randomBytes(32), object_id: crypto.randomBytes(16),
    revision: 1, epoch: 1,
    ciphertext_sha256: crypto.createHash("sha256").update(Buffer.concat(chunks)).digest() };
  const expectedRootHash = computeZk1CiphertextRoot(chunks);
  const digest = crypto.randomBytes(32);
  const request = { scope, operation, digest, expectedRootHash,
    expectedChunkCount: chunks.length, chunks };
  const activity = [];
  const admissionId = crypto.randomBytes(16);
  const sink = Object.create(Zk1SharedPgCiphertextSink.prototype);
  sink.finishVerifiedSeal = async ({ scope: sealedScope, operationId, admissionId: sealedId }) => {
    activity.push("finish");
    assert.deepEqual(sealedScope, scope);
    assert.deepEqual(operationId, operation.operation_id);
    assert.deepEqual(sealedId, admissionId);
    return { status: "FINISHED" };
  };
  sink.putSealed = async (input) => {
    activity.push("write");
    assert.deepEqual(input.operationId, operation.operation_id);
    assert.deepEqual(input.expectedRootHash, expectedRootHash);
    return { status: "SEALED", chunkCount: chunks.length };
  };
  const verifier = Object.create(Zk1SharedPgPhysicalCiphertextVerifier.prototype);
  verifier.verifyExact = async (input) => {
    activity.push("readback");
    if (readbackFailure) throw Error("PHYSICAL_VERIFIER_UNAVAILABLE");
    assert.deepEqual(input.operationId, operation.operation_id);
    return { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, operationId: Buffer.from(operation.operation_id),
      admissionId: Buffer.from(admissionId),
      root: Buffer.from(expectedRootHash),
      ciphertextSha256: Buffer.from(operation.ciphertext_sha256) };
  };
  const intentAuthority = Object.create(Zk1SharedPgPhysicalInventoryIntent.prototype);
  intentAuthority.reserveExact = async (input) => {
    activity.push("reserve");
    assert.deepEqual(input.operation.operation_id, operation.operation_id);
    return { status: "IMMUTABLE_PREWRITE_INTENT", operationId: Buffer.from(operation.operation_id),
      generation: 1, replay: sealed, sealed, authorizesIo: false };
  };
  const ledger = Object.create(Zk1DurableContentInventoryLedger.prototype);
  ledger.scope = scope;
  ledger.getOperationStatus = async () => ({ status: "pending" });
  ledger.prepareAppend = async (input) => {
    activity.push("prepare");
    assert.deepEqual(input.operation_id, operation.operation_id);
    if (terminal) return { status: "not_committed_final",
      reason: "UNRESOLVED_PENDING", proof: Buffer.from("signed-terminal-fixture") };
    return { status: "pending", replay: false };
  };
  ledger.append = async () => ({ status: "pending" });
  const key = crypto.generateKeyPairSync("ed25519");
  const bridge = new Zk1PgPhysicalInventoryBridge({ sink, verifier, intentAuthority,
    ledger, pinnedPublicKey: key.publicKey, pinnedSignerKeyId: crypto.randomBytes(16) });
  return { request, bridge, activity };
}

test("previously sealed strict operation skips writer and requires authenticated readback", async () => {
  const f = fixture({ sealed: true });
  assert.deepEqual(await f.bridge.putAndAttest(f.request),
    { status: "pending", authorizesIo: false });
  assert.deepEqual(f.activity, ["prepare", "reserve", "readback", "finish", "readback"]);
});

test("unsealed exact prewrite intent resumes same immutable operation", async () => {
  const f = fixture({ sealed: false });
  assert.deepEqual(await f.bridge.putAndAttest(f.request),
    { status: "pending", authorizesIo: false });
  assert.deepEqual(f.activity, ["prepare", "reserve", "write", "readback"]);
});

test("sealed prewrite with failed verifier cannot be downgraded to a new START", async () => {
  const f = fixture({ sealed: true, readbackFailure: true });
  await assert.rejects(f.bridge.putAndAttest(f.request),
    /PHYSICAL_VERIFIER_UNAVAILABLE|ZK_PHYSICAL_INVENTORY_UNAVAILABLE/);
  assert.deepEqual(f.activity, ["prepare", "reserve", "readback"]);
});

test("terminally rejected inventory contender never reserves immutable physical storage", async () => {
  const f = fixture({ sealed: false, terminal: true });
  const result = await f.bridge.putAndAttest(f.request);
  assert.equal(result.status, "not_committed_final");
  assert.equal(result.reason, "UNRESOLVED_PENDING");
  assert.deepEqual(result.proof, Buffer.from("signed-terminal-fixture"));
  assert.equal(result.authorizesIo, false);
  assert.deepEqual(f.activity, ["prepare"],
    "loser must never invoke the PG intent authority or physical writer");
});
