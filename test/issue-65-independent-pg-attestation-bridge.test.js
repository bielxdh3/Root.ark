"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { Zk1PgPhysicalInventoryBridge } = require("../src/services/zk1PgPhysicalInventoryBridge");
const { Zk1SharedPgCiphertextSink } = require("../src/services/zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("../src/services/zk1SharedPgPhysicalInventoryIntent");
const { Zk1DurableContentInventoryLedger } =
  require("../src/services/zk1DurableContentInventoryLedger");

test("strict bridge rejects a writer-owned physical proof and accepts only pinned separate attestor", async () => {
  const random = (n) => crypto.randomBytes(n);
  const attest = crypto.generateKeyPairSync("ed25519");
  const writer = crypto.generateKeyPairSync("ed25519");
  const inventorySigner = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const operation = { operation_id: random(16), expected_sequence: 2,
    expected_root: random(32), object_id: random(16), revision: 3, epoch: 4,
    ciphertext_sha256: random(32) };
  const digest = random(32);
  const root = random(32);
  const physical = { scope, operation, digest, expectedRootHash: root,
    expectedChunkCount: 2 };
  const mockOf = (Class) => Object.create(Class.prototype);
  const verifier = mockOf(Zk1SharedPgPhysicalCiphertextVerifier);
  verifier.verifyExact = async () => { throw Error("writer-held local verifier must never be trusted"); };
  const ledger = mockOf(Zk1DurableContentInventoryLedger);
  ledger.scope = scope;
  ledger.getOperationStatus = async () => ({ status: "pending" });
  const received = [];
  let signer = attest.privateKey;
  const attestorClient = { async requestAttestation(v) {
    received.push(v);
    const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 5, admissionId: random(16),
      operationId: v.operation.operation_id, revision: v.operation.revision,
      epoch: v.operation.epoch, digest,
      expectedInventorySequence: v.operation.expected_sequence,
      expectedInventoryRoot: v.operation.expected_root, chunkCount: 2,
      root, ciphertextSha256: v.operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false };
    return signCommittedPhysicalReadback({ ...v, readback,
      issuedAt: Math.floor(Date.now() / 1000) }, signer);
  } };
  const ctor = { sink: mockOf(Zk1SharedPgCiphertextSink), verifier,
    intentAuthority: mockOf(Zk1SharedPgPhysicalInventoryIntent), ledger,
    pinnedPublicKey: inventorySigner.publicKey, pinnedSignerKeyId: random(16),
    attestorClient, pinnedPhysicalAttestorPublicKey: attest.publicKey };
  const bridge = new Zk1PgPhysicalInventoryBridge(ctor);
  assert.deepEqual(await bridge.reconcile(physical),
    { status: "pending", authorizesIo: false });
  // The writer process must not need a physical PostgreSQL attestor login.
  // Its only readback capability in strict mode is the remote signed proof.
  const remoteOnly = new Zk1PgPhysicalInventoryBridge({ ...ctor, verifier: undefined });
  assert.deepEqual(await remoteOnly.reconcile(physical),
    { status: "pending", authorizesIo: false });
  assert.equal(received.length, 2);
  assert.deepEqual(received[0].operation.operation_id, operation.operation_id);
  signer = writer.privateKey;
  await assert.rejects(bridge.reconcile(physical), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "writer with valid own Ed25519 key cannot forge independent PG success");
  assert.throws(() => new Zk1PgPhysicalInventoryBridge({ ...ctor,
    pinnedPhysicalAttestorPublicKey: undefined }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "strict remote verifier never silently downgrades without a pinned key");
});
