"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
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
  let issuedAtOverride = null;
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
      issuedAt: issuedAtOverride ?? Math.floor(Date.now() / 1000) }, signer);
  } };
  const ctor = { sink: mockOf(Zk1SharedPgCiphertextSink), verifier,
    intentAuthority: mockOf(Zk1SharedPgPhysicalInventoryIntent), ledger,
    pinnedPublicKey: inventorySigner.publicKey, pinnedSignerKeyId: random(16),
    attestorClient, pinnedPhysicalAttestorPublicKey: attest.publicKey };
  const forgedSameWriter = crypto.createPublicKey(inventorySigner.privateKey);
  forgedSameWriter.export = () => attest.publicKey.export({ type: "spki", format: "der" });
  assert.throws(() => new Zk1PgPhysicalInventoryBridge({ ...ctor,
    pinnedPhysicalAttestorPublicKey: forgedSameWriter }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "a mutable KeyObject export cannot invent an independent bridge attestor");
  const bridge = new Zk1PgPhysicalInventoryBridge(ctor);
  const actualDateNow = Date.now;
  const baseSeconds = Math.floor(actualDateNow() / 1000);
  let clockReads = 0;
  try {
    issuedAtOverride = baseSeconds;
    Date.now = () => (baseSeconds + (++clockReads === 1 ? 29 : 31)) * 1000;
    await assert.rejects(bridge.reconcile(physical),
      /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
      "strict bridge must reject attestation expiring during async verification");
    assert.ok(clockReads >= 2);
  } finally {
    Date.now = actualDateNow;
    issuedAtOverride = null;
  }
  assert.deepEqual(await bridge.reconcile(physical),
    { status: "pending", authorizesIo: false });
  // The writer process must not need a physical PostgreSQL attestor login.
  // Its only readback capability in strict mode is the remote signed proof.
  const remoteOnly = new Zk1PgPhysicalInventoryBridge({ ...ctor, verifier: undefined });
  assert.deepEqual(await remoteOnly.reconcile(physical),
    { status: "pending", authorizesIo: false });
  assert.equal(received.length, 3, "includes the rejected stale proof readback");
  assert.deepEqual(received[0].operation.operation_id, operation.operation_id);
  // The bridge must export a verified composite receipt, rather than a
  // writer-signed local catalog entry with an unrelated boolean PG flag.
  const signerId = ctor.pinnedSignerKeyId;
  const committedRoot = random(32);
  const signedEntry = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: signerId, scope, sequence: operation.expected_sequence + 1,
    previous_root: operation.expected_root, root: committedRoot,
    operation_id: operation.operation_id,
    expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root,
    request_digest: crypto.createHash("sha256").update(
      await z.encodeDeterministic(operation)).digest(),
    entry: { object_id: operation.object_id, revision: operation.revision,
      epoch: operation.epoch, ciphertext_sha256: operation.ciphertext_sha256 } };
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
    await z.encodeDeterministic(signedEntry),
  ]), inventorySigner.privateKey);
  const signedProof = Buffer.from(await z.encodeDeterministic({ ...signedEntry, signature }));
  ledger.getOperationStatus = async () => ({ status: "committed", sequence: 3,
    root: committedRoot, proof: signedProof });
  const committed = await bridge.reconcile(physical);
  assert.equal(committed.status, "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY");
  assert.equal(committed.independentPhysicalAttestationVerified, true);
  assert.equal(committed.physicalAttestationReceiptDigest.length, 32);
  const retried = await bridge.publishExisting(physical);
  assert.equal(retried.independentPhysicalAttestationVerified, true,
    "an already committed operation must not bypass composite verification on restart/retry");
  assert.equal(retried.physicalAttestationReceiptDigest.length, 32);
  signer = writer.privateKey;
  await assert.rejects(bridge.reconcile(physical), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
    "writer with valid own Ed25519 key cannot forge independent PG success");
  assert.throws(() => new Zk1PgPhysicalInventoryBridge({ ...ctor,
    pinnedPhysicalAttestorPublicKey: undefined }), /ZK_PHYSICAL_INVENTORY_UNAVAILABLE/,
  "strict remote verifier never silently downgrades without a pinned key");
});
