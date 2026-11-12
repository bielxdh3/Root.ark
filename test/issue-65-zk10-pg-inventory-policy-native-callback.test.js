"use strict";

// Real disposable Ed25519 signatures. The inherited native kHandle getter is
// invoked by the product verifier, after the modules were loaded, and then
// attempts to replace mutable same-realm cryptographic/Array methods.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const pg = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");
const { snapshotLocalDevicePolicy } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");

function nativeGetter(publicKey, onRead) {
  const symbol = Object.getOwnPropertySymbols(publicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(symbol, "Node22 KeyObject native kHandle needed");
  const forged = Object.create(publicKey);
  let reads = 0;
  Object.defineProperty(forged, symbol, { get() {
    reads += 1;
    onRead();
    return publicKey[symbol];
  } });
  return { forged, get reads() { return reads; } };
}

function fixture() {
  const signer = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: Buffer.alloc(16, 21),
    compartment_id: Buffer.from("vault"), keyring_id: Buffer.alloc(16, 22) };
  const operation = { operation_id: Buffer.alloc(16, 23), expected_sequence: 0,
    expected_root: Buffer.alloc(32, 24), object_id: Buffer.alloc(16, 25),
    revision: 1, epoch: 1, ciphertext_sha256: Buffer.alloc(32, 26) };
  return { signer, scope, operation, signerKeyId: Buffer.alloc(16, 27) };
}

async function inventoryReceipt(f) {
  const entry = { object_id: f.operation.object_id, revision: f.operation.revision,
    epoch: f.operation.epoch, ciphertext_sha256: f.operation.ciphertext_sha256 };
  const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: f.signerKeyId, scope: f.scope, sequence: 1,
    previous_root: f.operation.expected_root, root: Buffer.alloc(32, 28),
    operation_id: f.operation.operation_id, expected_sequence: f.operation.expected_sequence,
    expected_root: f.operation.expected_root,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(f.operation)).digest(), entry };
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
    await z.encodeDeterministic(unsigned),
  ]), f.signer.privateKey);
  return { good: Buffer.from(await z.encodeDeterministic({ ...unsigned, signature })),
    forged: Buffer.from(await z.encodeDeterministic({
      ...unsigned, root: Buffer.alloc(32, 99), signature,
    })) };
}

test("P2 inventory: native getter must not retarget genuine A signature to forged B", async () => {
  const f = fixture();
  const proof = await inventoryReceipt(f);
  const input = (serialized, pinnedPublicKey) => ({ serialized, pinnedPublicKey,
    pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope, operation: f.operation });
  assert.equal((await inventory.verifyCommittedEntryProof(input(proof.good,
    f.signer.publicKey))).outcome, "COMMITTED_IN_SIGNED_LEDGER");
  await assert.rejects(inventory.verifyCommittedEntryProof(input(proof.forged,
    f.signer.publicKey)), { code: "INVENTORY_SIGNATURE" });
  const originalVerify = crypto.verify;
  let retargetCalls = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    crypto.verify = () => { retargetCalls++; return true; };
  });
  try {
    await assert.rejects(inventory.verifyCommittedEntryProof(input(proof.forged,
      evil.forged)), { code: "INVENTORY_SIGNATURE" });
  } finally { crypto.verify = originalVerify; }
  assert.ok(evil.reads > 0, "native getter executes after snapshot");
  assert.equal(retargetCalls, 0, "must use early captured crypto.verify");
  assert.equal((await inventory.verifyCommittedEntryProof(input(proof.good,
    f.signer.publicKey))).authorizesIo, false);
});

test("P2 composite: inherited Ed25519 inventory pin cannot make A signature authorize forged inventory B", async () => {
  const f = fixture();
  f.pgSigner = crypto.generateKeyPairSync("ed25519");
  assert.equal(f.signer.publicKey.equals(f.pgSigner.publicKey), false);
  const receipts = await inventoryReceipt(f);
  const physical = await physicalReceipt(f);
  const input = (receipt, pinnedInventoryPublicKey) => ({
    receipt, physicalAttestation: physical.signed,
    scope: f.scope, operation: f.operation, nonce: physical.nonce,
    pinnedInventoryPublicKey, pinnedInventorySignerKeyId: f.signerKeyId,
    pinnedPhysicalAttestorPublicKey: f.pgSigner.publicKey,
    nowSeconds: physical.now,
  });
  const positive = await verifyAttestedInventoryCommit(input(receipts.good,
    f.signer.publicKey));
  assert.equal(positive.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(positive.authorizesIo, false);
  await assert.rejects(verifyAttestedInventoryCommit(input(receipts.forged,
    f.signer.publicKey)), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  const originalVerify = crypto.verify;
  let mutableCalls = 0;
  const poisonedKey = nativeGetter(f.signer.publicKey, () => {
    crypto.verify = () => { mutableCalls++; return true; };
  });
  try {
    await assert.rejects(verifyAttestedInventoryCommit(input(receipts.forged,
      poisonedKey.forged)), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  } finally { crypto.verify = originalVerify; }
  assert.ok(poisonedKey.reads > 0, "real inherited native getter before composite");
  assert.equal(mutableCalls, 0, "the pinned native inventory verifier must be used");
  assert.equal((await verifyAttestedInventoryCommit(input(receipts.good,
    f.signer.publicKey))).authorizesIo, false);
});

async function physicalReceipt(f) {
  const now = Math.floor(Date.now() / 1000);
  const nonce = Buffer.alloc(32, 29);
  const digest = Buffer.alloc(32, 30);
  const signed = await pg.signCommittedPhysicalReadback({
    scope: f.scope, operation: f.operation, nonce, issuedAt: now,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: Buffer.alloc(16, 31),
      operationId: f.operation.operation_id, revision: 1, epoch: 1,
      digest, expectedInventorySequence: 0,
      expectedInventoryRoot: f.operation.expected_root, chunkCount: 1,
      root: Buffer.alloc(32, 32), ciphertextSha256: f.operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, (f.pgSigner || f.signer).privateKey);
  return { signed, now, nonce, digest };
}

test("P2 PG: native getter cannot substitute signature verification or byte comparison", async () => {
  const f = fixture();
  const { signed, now, nonce, digest } = await physicalReceipt(f);
  const options = (pin, expected = undefined) => ({ scope: f.scope,
    operation: f.operation, expected, nonce, pinnedPublicKey: pin, nowSeconds: now });
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    options(f.signer.publicKey))).verified, true);
  const decoded = await z.decodeDeterministic(signed);
  const forged = Buffer.from(await z.encodeDeterministic({
    ...decoded, generation: 2, signature: decoded.signature,
  }));
  await assert.rejects(pg.verifyCommittedPhysicalReadback(forged,
    options(f.signer.publicKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  const originalVerify = crypto.verify;
  let verifyCalls = 0;
  const evil = nativeGetter(f.signer.publicKey, () => {
    crypto.verify = () => { verifyCalls++; return true; };
  });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(forged,
      options(evil.forged)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  } finally { crypto.verify = originalVerify; }
  assert.ok(evil.reads > 0);
  assert.equal(verifyCalls, 0, "PG must verify Ed25519 through original native method");

  const originalCompare = crypto.timingSafeEqual;
  let comparisons = 0;
  const comparisonEvil = nativeGetter(f.signer.publicKey, () => {
    crypto.timingSafeEqual = () => { comparisons++; return true; };
  });
  try {
    await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
      options(comparisonEvil.forged, {
        digest: Buffer.alloc(32, 88), root: Buffer.alloc(32, 32), chunks: 1,
      })), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  } finally { crypto.timingSafeEqual = originalCompare; }
  assert.ok(comparisonEvil.reads > 0);
  assert.equal(comparisons, 0, "PG must retain original constant-time comparator");
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    options(f.signer.publicKey, { digest, root: Buffer.alloc(32, 32), chunks: 1 })))
    .authorizesIo, false);
});

test("P2 device revocation: post-kHandle Array.push cannot erase revoked device", () => {
  const device = crypto.generateKeyPairSync("ed25519");
  const message = Buffer.from("real device policy callback");
  const signature = crypto.sign(null, message, device.privateKey);
  const originalPush = Array.prototype.push;
  const evil = nativeGetter(device.publicKey, () => {
    Array.prototype.push = function() { return this.length; };
  });
  let revoked;
  try {
    assert.equal(crypto.verify(null, message, evil.forged, signature), true,
      "real Ed25519 verifier invokes inherited kHandle");
    const policy = snapshotLocalDevicePolicy({ username: "alice",
      trustedDevicePublicKeys: { device_1: "AA" }, revokedDeviceIds: ["device_1"] });
    revoked = policy.revokedDeviceIds;
  } finally {
    Array.prototype.push = originalPush;
  }
  assert.ok(evil.reads > 0);
  assert.deepEqual(revoked, ["device_1"],
    "revoked device is retained even with post-getter Array.push monkeypatch");
});

test("P2 signed owner history returns immutable compartment coverage with original digest", () => {
  const owner = crypto.generateKeyPairSync("ed25519");
  const id = (value) => Buffer.alloc(16, value).toString("base64url");
  const a = signOwnerCutover({ type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: id(40), zk_account_id: id(41),
    generation: 1, previous_cutover_digest: null,
    inventory_head: Buffer.alloc(32, 42).toString("hex"), complete_corpus: true,
    covered_compartments: [id(43)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted", migration_disposition: "closed",
    grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: Buffer.alloc(32, 44).toString("base64url"), issued_at: 1800000000,
  }, owner.privateKey);
  const digestA = digestOwnerCutover(a);
  const result = verifyOwnerCutoverHistory([a], [owner.publicKey], id(40));
  assert.equal(result.digest, digestA);
  assert.equal(result.statement.covered_compartments[0], id(43));
  assert.ok(Object.isFrozen(result.statement.covered_compartments));
  assert.ok(Object.isFrozen(result.statement.grants));
  assert.throws(() => { result.statement.covered_compartments[0] = id(88); }, TypeError);
  assert.throws(() => { result.statement.grants.push("legacy_allow"); }, TypeError);
  assert.equal(result.statement.covered_compartments[0], id(43));
  assert.equal(result.digest, digestOwnerCutover(a));
});
