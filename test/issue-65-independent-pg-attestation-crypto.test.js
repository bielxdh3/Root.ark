"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { signCommittedPhysicalReadback, verifyCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");

const random = (n) => crypto.randomBytes(n);
function fixture() {
  const attestor = crypto.generateKeyPairSync("ed25519");
  const writer = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const operation = { operation_id: random(16), expected_sequence: 3,
    expected_root: random(32), object_id: random(16), revision: 4, epoch: 7,
    ciphertext_sha256: random(32) };
  const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
    walFlushConfirmed: true, generation: 8, admissionId: random(16),
    operationId: Buffer.from(operation.operation_id),
    revision: operation.revision, epoch: operation.epoch,
    digest: random(32), expectedInventorySequence: operation.expected_sequence,
    expectedInventoryRoot: Buffer.from(operation.expected_root),
    chunkCount: 2, root: random(32),
    ciphertextSha256: Buffer.from(operation.ciphertext_sha256),
    authorizesIo: false, provesIndependentOperator: false };
  const nonce = random(32);
  const issuedAt = Math.floor(Date.now() / 1000);
  return { attestor, writer, scope, operation, readback, nonce, issuedAt };
}

test("PG attestor signs exact WAL readback for a separately pinned identity", async () => {
  const f = fixture();
  const raw = await signCommittedPhysicalReadback({ scope: f.scope,
    operation: f.operation, readback: f.readback, nonce: f.nonce,
    issuedAt: f.issuedAt }, f.attestor.privateKey);
  const options = { scope: f.scope, operation: f.operation,
    expected: { digest: f.readback.digest, root: f.readback.root,
      chunks: f.readback.chunkCount }, nonce: f.nonce,
    pinnedPublicKey: f.attestor.publicKey, nowSeconds: f.issuedAt };
  const verified = await verifyCommittedPhysicalReadback(raw, options);
  assert.equal(verified.status, "PHYSICALLY_REREAD_PG_COMMITTED");
  assert.equal(verified.generation, f.readback.generation);
  assert.equal(verified.walFlushConfirmed, true);
  assert.equal(verified.authorizesIo, false);
  assert.deepEqual(verified.operationId, f.operation.operation_id);
  // The inventory mTLS append knows only its signed operation; the read-only
  // PG attestor discovers the physical intent's digest/root/chunks itself.
  const withoutWriterProvidedPhysicalDigest = await verifyCommittedPhysicalReadback(raw,
    { ...options, expected: undefined });
  assert.deepEqual(withoutWriterProvidedPhysicalDigest.physicalDigest, f.readback.digest);
  assert.deepEqual(withoutWriterProvidedPhysicalDigest.chunkRoot, f.readback.root);
  assert.equal(withoutWriterProvidedPhysicalDigest.chunkCount, 2);

  async function denied(proof, context = {}) {
    await assert.rejects(verifyCommittedPhysicalReadback(proof,
      { ...options, ...context }), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  }
  await denied(raw, { nonce: random(32) });
  await denied(raw, { pinnedPublicKey: f.writer.publicKey });
  await denied(raw, { operation: { ...f.operation, epoch: f.operation.epoch + 1 } });
  await denied(raw, { operation: { ...f.operation, operation_id: random(16) } });
  await denied(raw, { operation: { ...f.operation, expected_root: random(32) } });
  await denied(raw, { expected: { ...options.expected, digest: random(32) } });
  await denied(raw, { expected: { ...options.expected, chunks: 3 } });
  await denied(raw, { nowSeconds: f.issuedAt + 61 });

  const writerForgery = await signCommittedPhysicalReadback({ scope: f.scope,
    operation: f.operation, readback: f.readback, nonce: f.nonce,
    issuedAt: f.issuedAt }, f.writer.privateKey);
  await denied(writerForgery);
});

test("PG attestor never signs an unflushed, substituted, or authorizing readback", async () => {
  const f = fixture();
  for (const changed of [
    { walFlushConfirmed: false },
    { verified: false },
    { operationId: random(16) },
    { ciphertextSha256: random(32) },
    { expectedInventoryRoot: random(32) },
    { epoch: f.operation.epoch + 1 },
    { authorizesIo: true },
  ]) {
    await assert.rejects(signCommittedPhysicalReadback({ scope: f.scope,
      operation: f.operation, readback: { ...f.readback, ...changed },
      nonce: f.nonce, issuedAt: f.issuedAt }, f.attestor.privateKey),
    /ZK_PHYSICAL_ATTESTATION_DENIED/);
  }
});

test("untrusted attestor response is rejected before converting attacker-controlled objects or oversized buffers", async () => {
  const f = fixture();
  let dangerousCoercion = 0;
  const deceptive = {
    length: 1_000_000,
    [Symbol.iterator]() { dangerousCoercion += 1; throw new Error("attacker iterator evaluated"); },
  };
  const context = { scope: f.scope, operation: f.operation, expected: undefined,
    nonce: f.nonce, pinnedPublicKey: f.attestor.publicKey, nowSeconds: f.issuedAt };
  await assert.rejects(verifyCommittedPhysicalReadback(deceptive, context),
    /ZK_PHYSICAL_ATTESTATION_DENIED/);
  assert.equal(dangerousCoercion, 0, "must check Buffer/typed-array type before any conversion");
  await assert.rejects(verifyCommittedPhysicalReadback(Buffer.alloc(2049), context),
    /ZK_PHYSICAL_ATTESTATION_DENIED/);
});
