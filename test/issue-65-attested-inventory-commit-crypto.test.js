"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");

const random = (n) => crypto.randomBytes(n);
const sha = (data) => crypto.createHash("sha256").update(data).digest();
const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");

async function fixture() {
  const writer = crypto.generateKeyPairSync("ed25519");
  const attestor = crypto.generateKeyPairSync("ed25519");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const signerId = random(16);
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const operation = { operation_id: random(16), expected_sequence: 4,
    expected_root: random(32), object_id: random(16), revision: 5, epoch: 6,
    ciphertext_sha256: random(32) };
  const unsigned = {
    type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: signerId, scope, sequence: 5,
    previous_root: operation.expected_root, root: random(32),
    operation_id: operation.operation_id, expected_sequence: 4,
    expected_root: operation.expected_root,
    request_digest: sha(await z.encodeDeterministic(operation)),
    entry: { object_id: operation.object_id, revision: 5, epoch: 6,
      ciphertext_sha256: operation.ciphertext_sha256 },
  };
  const unsignedBytes = await z.encodeDeterministic(unsigned);
  const receipt = Buffer.from(await z.encodeDeterministic({ ...unsigned,
    signature: crypto.sign(null, Buffer.concat([ENTRY_DOMAIN, unsignedBytes]), writer.privateKey) }));
  const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED",
    verified: true, walFlushConfirmed: true, authorizesIo: false,
    provesIndependentOperator: false, generation: 7, admissionId: random(16),
    operationId: operation.operation_id, revision: 5, epoch: 6,
    expectedInventorySequence: 4, expectedInventoryRoot: operation.expected_root,
    ciphertextSha256: operation.ciphertext_sha256,
    digest: random(32), root: random(32), chunkCount: 1 };
  const nonce = random(32);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const makePhysical = (privateKey, operationOverride = operation) =>
    signCommittedPhysicalReadback({ scope, operation: operationOverride,
      readback, nonce, issuedAt: nowSeconds }, privateKey);
  const physicalAttestation = await makePhysical(attestor.privateKey);
  const input = { receipt, physicalAttestation, scope, operation, nonce,
    pinnedInventoryPublicKey: writer.publicKey,
    pinnedInventorySignerKeyId: signerId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey, nowSeconds };
  return { writer, attestor, foreign, receipt, readback, makePhysical, input };
}

test("composite inventory receipt binds separate signer, physical PG proof, operation checkpoint and client nonce", async () => {
  const f = await fixture();
  const verified = await verifyAttestedInventoryCommit(f.input);
  assert.equal(verified.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(verified.inventoryReceipt.sequence, 5);
  assert.equal(verified.physicalReadback.walFlushConfirmed, true);
  assert.equal(verified.receiptDigest.length, 32);
  assert.equal(verified.authorizesIo, false);
  assert.equal(verified.externalDurabilityProven, false);
  assert.equal(verified.independentlyAnchoredFloorProven, false);

  const deny = (change) => assert.rejects(verifyAttestedInventoryCommit({
    ...f.input, ...change,
  }), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  await deny({ nonce: random(32) });
  await deny({ pinnedPhysicalAttestorPublicKey: f.writer.publicKey });
  await deny({ pinnedPhysicalAttestorPublicKey: f.foreign.publicKey });
  await deny({ pinnedInventoryPublicKey: f.foreign.publicKey });
  await deny({ operation: { ...f.input.operation, epoch: 7 } });
  await deny({ operation: { ...f.input.operation, expected_root: random(32) } });
  await deny({ receipt: Buffer.from(f.receipt).fill(0, 0, 1) });
  await deny({ physicalAttestation: Buffer.alloc(2049) });
  await deny({ nowSeconds: f.input.nowSeconds + 61 });
  const writerForgery = await f.makePhysical(f.writer.privateKey);
  await deny({ physicalAttestation: writerForgery });
});
