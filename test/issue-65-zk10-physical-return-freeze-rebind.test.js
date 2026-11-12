"use strict";

// Authentic, disposable Ed25519 inventory and PostgreSQL signatures. The
// synthetic proof is deliberately non-durable: this tests the verified
// NON-AUTHORIZING return contract, not real PostgreSQL/off-host custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const pg = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");

async function authenticEvidence() {
  const inventorySigner = crypto.generateKeyPairSync("ed25519");
  const physicalSigner = crypto.generateKeyPairSync("ed25519");
  assert.equal(crypto.KeyObject.prototype.equals.call(
    inventorySigner.publicKey, physicalSigner.publicKey), false);
  const scope = { account_id: Buffer.alloc(16, 20),
    compartment_id: Buffer.from("private"), keyring_id: Buffer.alloc(16, 21) };
  const operation = { operation_id: Buffer.alloc(16, 22), expected_sequence: 0,
    expected_root: Buffer.alloc(32, 23), object_id: Buffer.alloc(16, 24),
    revision: 1, epoch: 1, ciphertext_sha256: Buffer.alloc(32, 25) };
  const signerKeyId = Buffer.alloc(16, 26);
  const nonce = Buffer.alloc(32, 27);
  const issuedAt = Math.floor(Date.now() / 1000);
  const entry = { object_id: operation.object_id, revision: operation.revision,
    epoch: operation.epoch, ciphertext_sha256: operation.ciphertext_sha256 };
  const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: signerKeyId, scope, sequence: 1,
    previous_root: operation.expected_root, root: Buffer.alloc(32, 28),
    operation_id: operation.operation_id, expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(operation)).digest(), entry };
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
    await z.encodeDeterministic(unsigned),
  ]), inventorySigner.privateKey);
  const receipt = Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  const physicalAttestation = await pg.signCommittedPhysicalReadback({
    scope, operation, nonce, issuedAt,
    readback: {
      status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1,
      admissionId: Buffer.alloc(16, 29), operationId: operation.operation_id,
      revision: operation.revision, epoch: operation.epoch,
      digest: Buffer.alloc(32, 30),
      expectedInventorySequence: operation.expected_sequence,
      expectedInventoryRoot: operation.expected_root, chunkCount: 1,
      root: Buffer.alloc(32, 31), ciphertextSha256: operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false,
    },
  }, physicalSigner.privateKey);
  const readbackOptions = { scope, operation, expected: undefined, nonce,
    pinnedPublicKey: physicalSigner.publicKey, nowSeconds: issuedAt };
  assert.equal((await inventory.verifyCommittedEntryProof({
    serialized: receipt, pinnedPublicKey: inventorySigner.publicKey,
    pinnedSignerKeyId: signerKeyId, expectedScope: scope, operation,
  })).outcome, "COMMITTED_IN_SIGNED_LEDGER", "real Ed25519 inventory signature");
  assert.equal((await pg.verifyCommittedPhysicalReadback(
    physicalAttestation, readbackOptions)).verified, true,
  "real distinct Ed25519 PG attestor signature");
  return { inventorySigner, physicalSigner, physicalAttestation,
    readbackOptions,
    input: { receipt, physicalAttestation, scope, operation, nonce,
      pinnedInventoryPublicKey: inventorySigner.publicKey,
      pinnedInventorySignerKeyId: signerKeyId,
      pinnedPhysicalAttestorPublicKey: physicalSigner.publicKey, nowSeconds: issuedAt } };
}

test("P2: native signer kHandle callback cannot turn authentic nonauthorizing composite into authorizesIo:true", async () => {
  const fixture = await authenticEvidence();
  const baseline = await verifyAttestedInventoryCommit(fixture.input);
  assert.equal(baseline.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(baseline.authorizesIo, false);
  assert.equal(baseline.externalDurabilityProven, false);
  const nativeHandle = Object.getOwnPropertySymbols(fixture.inventorySigner.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(nativeHandle);
  const nativePin = Object.create(fixture.inventorySigner.publicKey);
  const trustedFreeze = Object.freeze;
  let getterReads = 0;
  let flipped = 0;
  Object.defineProperty(nativePin, nativeHandle, { get() {
    getterReads++;
    Object.freeze = function(value) {
      if (value?.status === "VERIFIED_COMPOSITE_NONAUTHORIZING") {
        flipped++;
        return trustedFreeze({ ...value, authorizesIo: true,
          externalDurabilityProven: true, independentlyAnchoredFloorProven: true });
      }
      return trustedFreeze(value);
    };
    return fixture.inventorySigner.publicKey[nativeHandle];
  } });
  let outcome;
  try {
    outcome = await verifyAttestedInventoryCommit({ ...fixture.input,
      pinnedInventoryPublicKey: nativePin });
  } finally { Object.freeze = trustedFreeze; }
  assert.ok(getterReads > 0, "a genuine native KeyObject getter must install the attack");
  assert.equal(outcome.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(outcome.inventoryReceipt.outcome, "COMMITTED_IN_SIGNED_LEDGER");
  assert.equal(outcome.physicalReadback.verified, true);
  assert.equal(outcome.authorizesIo, false, "signed evidence cannot enable product I/O");
  assert.equal(outcome.externalDurabilityProven, false);
  assert.equal(outcome.independentlyAnchoredFloorProven, false);
  assert.equal(flipped, 0, "terminal result must use captured early Object.freeze");
});

test("P2: a signed PG physical readback cannot elevate nonauthorizing fields through native kHandle / Object.freeze", async () => {
  const fixture = await authenticEvidence();
  const normal = await pg.verifyCommittedPhysicalReadback(
    fixture.physicalAttestation, fixture.readbackOptions);
  assert.equal(normal.verified, true);
  assert.equal(normal.authorizesIo, false);
  assert.equal(normal.provesIndependentOperator, false);
  const real = fixture.physicalSigner.publicKey;
  const handle = Object.getOwnPropertySymbols(real)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle);
  const keyWithCallback = Object.create(real);
  let reads = 0;
  let flipped = 0;
  const oldFreeze = Object.freeze;
  Object.defineProperty(keyWithCallback, handle, { get() {
    reads++;
    Object.freeze = function(value) {
      if (value?.status === "PHYSICALLY_REREAD_PG_COMMITTED") {
        flipped++;
        return oldFreeze({ ...value, authorizesIo: true,
          provesIndependentOperator: true });
      }
      return oldFreeze(value);
    };
    return real[handle];
  } });
  let signedResult;
  try {
    signedResult = await pg.verifyCommittedPhysicalReadback(fixture.physicalAttestation,
      { ...fixture.readbackOptions, pinnedPublicKey: keyWithCallback });
  } finally { Object.freeze = oldFreeze; }
  assert.ok(reads > 0, "native Ed25519 public-key getter must execute before returning");
  assert.equal(signedResult.verified, true);
  assert.equal(signedResult.authorizesIo, false,
    "a genuine PG Ed25519 signature never conveys product I/O authority");
  assert.equal(signedResult.provesIndependentOperator, false,
    "a signed PG readback alone never proves operator independence");
  assert.equal(flipped, 0, "native pin must use captured freeze after getter");
});
