"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const { signZk1CiphertextDeviceApprovalV1,
  inspectZk1CiphertextDeviceApprovalCryptoV1 } =
  require("../src/crypto/rootark-zk-ciphertext-device-approval-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/ciphertext-device-approval/v1\0", "ascii");
const rand = (length) => crypto.randomBytes(length);

function fixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: rand(16), compartment_id: rand(9), keyring_id: rand(16) };
  const approval = {
    type: "rootark-zk1-ciphertext-device-approval/v1", suite: "rootark-zk-1",
    ...scope, object_id: rand(16).toString("base64url"), object_revision: 3,
    manifest_revision: 7, manifest_digest: rand(32), keyring_epoch: 2,
    expected_chunk_count: 2, expected_root_hash: rand(32),
    device_id: "owner-phone", signer_key_id: rand(16), nonce: rand(32),
    issued_at: 1000, expires_at: 1060,
  };
  const pinned = { deviceId: approval.device_id,
    signerKeyId: Buffer.from(approval.signer_key_id), publicKey: keys.publicKey };
  const expected = {
    scope, objectId: approval.object_id, objectRevision: approval.object_revision,
    manifestRevision: approval.manifest_revision, manifestDigest: approval.manifest_digest,
    keyringEpoch: approval.keyring_epoch, expectedChunkCount: approval.expected_chunk_count,
    expectedRootHash: approval.expected_root_hash, nonce: approval.nonce,
  };
  return { keys, approval, pinned, expected };
}
async function signature(f, approval = f.approval, privateKey = f.keys.privateKey) {
  return signZk1CiphertextDeviceApprovalV1({ approval, privateKey });
}
async function inspect(f, raw, overrides = {}) {
  return inspectZk1CiphertextDeviceApprovalCryptoV1({
    raw, pinned: f.pinned, expected: f.expected, nowSeconds: 1010, ...overrides,
  });
}

test("versioned deterministic CBOR Ed25519 approval binds only exact owner context but cannot authorize release", async () => {
  const f = fixture();
  const wire = await signature(f);
  const raw = await z.decodeDeterministic(wire);
  assert.equal(raw.type, f.approval.type);
  assert.equal(raw.signature.length, 64);
  assert.deepEqual(await signature(f), wire, "Ed25519 and canonical CBOR are deterministic");
  const result = await inspect(f, wire);
  assert.deepEqual(result, { signatureVerified: true, authorizesRelease: false,
    deviceAuthorizationVerified: false, liveManifestHeadVerified: false,
    nonceConsumed: false });
  assert.equal(Object.isFrozen(result), true);
  assert.notEqual(Buffer.from(raw.signature).toString("hex"), f.keys.privateKey.export({
    type: "pkcs8", format: "der" }).toString("hex"), "signed proof never serializes a secret");
});

test("validly re-signed tampering in every commitment, scope, device and epoch field fails", async () => {
  const f = fixture();
  const tampered = [
    { account_id: rand(16) }, { compartment_id: rand(10) }, { keyring_id: rand(16) },
    { object_id: rand(16).toString("base64url") }, { object_revision: 4 },
    { manifest_revision: 8 }, { manifest_digest: rand(32) }, { keyring_epoch: 3 },
    { expected_chunk_count: 3 }, { expected_root_hash: rand(32) },
    { device_id: "different-device" }, { signer_key_id: rand(16) },
    { nonce: rand(32) },
  ];
  for (const mutation of tampered) {
    const wire = await signature(f, { ...f.approval, ...mutation });
    await assert.rejects(inspect(f, wire), /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/,
      Object.keys(mutation)[0] + " must be bound even with a valid signature");
  }
  for (const mutation of [{ type: "rootark-zk1-ciphertext-device-approval/v2" },
    { suite: "wrong-suite" }]) {
    await assert.rejects(signature(f, { ...f.approval, ...mutation }),
      /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  }
});

test("key substitution, changed signature, stale/replayed nonce, expiry and foreign manifest head deny", async () => {
  const f = fixture();
  const wire = await signature(f);
  const other = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(inspect(f, wire, { pinned: { ...f.pinned, publicKey: other.publicKey } }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, await signature(f, f.approval, other.privateKey)),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  const corrupted = Buffer.from(wire);
  corrupted[corrupted.length - 1] ^= 1;
  await assert.rejects(inspect(f, corrupted), /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, wire, { expected: { ...f.expected, nonce: rand(32) } }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, wire, { expected: { ...f.expected,
    manifestDigest: rand(32) } }), /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, wire, { nowSeconds: 1061 }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, wire, { nowSeconds: 1060 }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/,
    "expiry at equality is exclusive: no 1-second grace");
  assert.equal((await inspect(f, wire, { nowSeconds: 1059 })).signatureVerified, true);
  assert.equal((await inspect(f, wire, { nowSeconds: 1000 })).signatureVerified, true);
  await assert.rejects(inspect(f, wire, { nowSeconds: 999 }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/,
    "proof is not valid before issued_at");
  await assert.rejects(inspect(f, wire, { nowSeconds: 970 }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(signature(f, { ...f.approval, expires_at: 1400 }),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  // Replaying identical valid evidence never grants release or consumes a
  // nonce; a true one-use online CAS/witness admission is still missing.
  assert.equal((await inspect(f, wire)).authorizesRelease, false);
  assert.equal((await inspect(f, wire)).nonceConsumed, false);
});

test("unknown keys, noncanonical CBOR, invalid widths and caller-provided trust roots are refused", async () => {
  const f = fixture();
  const wire = await signature(f);
  const decoded = await z.decodeDeterministic(wire);
  for (const candidate of [
    { ...decoded, extra: true },
    { ...decoded, signature: rand(63) },
    { ...decoded, object_id: "unsafe" },
    { ...decoded, expected_chunk_count: 4097 },
  ]) {
    const raw = await z.encodeDeterministic(candidate);
    await assert.rejects(inspect(f, raw), /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  }
  await assert.rejects(inspect(f, Buffer.concat([wire, Buffer.from([0])])),
    /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  // A correct Ed25519 signature on the same canonical CBOR under ANOTHER
  // protocol's domain is deliberately not interchangeable.
  const { signature: ignored, ...unsigned } = decoded;
  const alien = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/foreign-protocol/v1\0", "ascii"),
    await z.encodeDeterministic(unsigned),
  ]), f.keys.privateKey);
  await assert.rejects(inspect(f,
    await z.encodeDeterministic({ ...unsigned, signature: alien })),
  /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, wire, { pinned: { ...f.pinned,
    claimedActive: true } }), /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
  await assert.rejects(inspect(f, wire, { expected: { ...f.expected,
    trustedDevicePublicKey: f.keys.publicKey } }), /ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID/);
});

test("mutable buffers and public-key references are copied/pinned before asynchronous CBOR operations", async () => {
  const f = fixture();
  const wire = await signature(f);
  const input = Buffer.from(wire);
  const originalExpected = Buffer.from(f.expected.expectedRootHash);
  const originalPin = Buffer.from(f.pinned.signerKeyId);
  const promise = inspect(f, input);
  input.fill(0);
  f.expected.expectedRootHash.fill(0);
  f.pinned.signerKeyId.fill(0);
  assert.deepEqual(await promise, { signatureVerified: true, authorizesRelease: false,
    deviceAuthorizationVerified: false, liveManifestHeadVerified: false,
    nonceConsumed: false });
  assert.equal(originalExpected.length, 32);
  assert.equal(originalPin.length, 16);
  const other = fixture();
  const changedWire = await signature(other);
  const original = other.pinned.publicKey;
  const pending = inspect(other, changedWire);
  other.pinned.publicKey = crypto.generateKeyPairSync("ed25519").publicKey;
  assert.equal((await pending).authorizesRelease, false);
  other.pinned.publicKey = original;
  const signing = fixture();
  const originalManifestDigest = Buffer.from(signing.approval.manifest_digest);
  const pendingSignature = signature(signing);
  signing.approval.manifest_digest.fill(0);
  const signed = await z.decodeDeterministic(await pendingSignature);
  assert.deepEqual(Buffer.from(signed.manifest_digest), originalManifestDigest,
    "signer must snapshot content before awaiting the CBOR codec");
});
