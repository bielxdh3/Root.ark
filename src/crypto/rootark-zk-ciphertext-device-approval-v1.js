"use strict";

// Experimental, versioned, cryptographic linkage ONLY for issue #65.
// Neither an Ed25519 signature nor a caller-supplied device status proves
// that the signer is STILL ACTIVE at the independently committed CAS/witness
// head. No normal server route, sink, or release gate may use this as authority.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const TYPE = "rootark-zk1-ciphertext-device-approval/v1";
const DOMAIN = Buffer.from("Root.ark/zk-1/ciphertext-device-approval/v1\0", "ascii");
const FIELDS = Object.freeze([
  "type", "suite", "account_id", "compartment_id", "keyring_id",
  "object_id", "object_revision", "manifest_revision", "manifest_digest",
  "keyring_epoch", "expected_chunk_count", "expected_root_hash",
  "device_id", "signer_key_id", "nonce", "issued_at", "expires_at",
]);
const WIRE_FIELDS = Object.freeze([...FIELDS, "signature"]);
const EXPECTED_FIELDS = Object.freeze([
  "scope", "objectId", "objectRevision", "manifestRevision", "manifestDigest",
  "keyringEpoch", "expectedChunkCount", "expectedRootHash", "nonce",
]);
function invalid() {
  const e = new Error("ZK_CIPHERTEXT_DEVICE_APPROVAL_INVALID");
  e.code = e.message;
  throw e;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) invalid();
}
function copy(value, size, max = size) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < size || value.byteLength > max) invalid();
  return Buffer.from(value);
}
function natural(value, min, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < min || value > max) invalid();
  return value;
}
function id(value, max = 64) {
  if (typeof value !== "string" || value.length < 1 || value.length > max
    || /[\u0000-\u001f\u007f]/.test(value)) invalid();
  return value;
}
function scope(value) {
  exact(value, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: copy(value.account_id, 16),
    compartment_id: copy(value.compartment_id, 1, 128),
    keyring_id: copy(value.keyring_id, 16) };
}
function objectId(value) {
  if (typeof value !== "string" || !/^[a-zA-Z0-9_-]{22}$/.test(value)
    || Buffer.from(value, "base64url").toString("base64url") !== value) invalid();
  return value;
}
function approval(value) {
  exact(value, FIELDS);
  if (value.type !== TYPE || value.suite !== "rootark-zk-1") invalid();
  const { account_id, compartment_id, keyring_id } = scope({
    account_id: value.account_id, compartment_id: value.compartment_id,
    keyring_id: value.keyring_id,
  });
  const issued = natural(value.issued_at, 1);
  const expires = natural(value.expires_at, issued + 1);
  if (expires - issued > 300) invalid();
  return {
    type: TYPE, suite: "rootark-zk-1", account_id, compartment_id, keyring_id,
    object_id: objectId(value.object_id),
    object_revision: natural(value.object_revision, 1),
    manifest_revision: natural(value.manifest_revision, 1),
    manifest_digest: copy(value.manifest_digest, 32),
    keyring_epoch: natural(value.keyring_epoch, 1, 64),
    expected_chunk_count: natural(value.expected_chunk_count, 1, 4096),
    expected_root_hash: copy(value.expected_root_hash, 32),
    device_id: id(value.device_id), signer_key_id: copy(value.signer_key_id, 16),
    nonce: copy(value.nonce, 32), issued_at: issued, expires_at: expires,
  };
}
function expectedContext(value) {
  exact(value, EXPECTED_FIELDS);
  return {
    ...scope(value.scope), object_id: objectId(value.objectId),
    object_revision: natural(value.objectRevision, 1),
    manifest_revision: natural(value.manifestRevision, 1),
    manifest_digest: copy(value.manifestDigest, 32),
    keyring_epoch: natural(value.keyringEpoch, 1, 64),
    expected_chunk_count: natural(value.expectedChunkCount, 1, 4096),
    expected_root_hash: copy(value.expectedRootHash, 32), nonce: copy(value.nonce, 32),
  };
}
function pinnedDevice(value) {
  exact(value, ["deviceId", "signerKeyId", "publicKey"]);
  if (!(value.publicKey instanceof crypto.KeyObject)
    || value.publicKey.type !== "public"
    || value.publicKey.asymmetricKeyType !== "ed25519") invalid();
  return { device_id: id(value.deviceId),
    signer_key_id: copy(value.signerKeyId, 16), publicKey: value.publicKey };
}
function same(left, right) {
  if (Buffer.isBuffer(left) || Buffer.isBuffer(right)) return Buffer.isBuffer(left)
    && Buffer.isBuffer(right) && left.length === right.length
    && crypto.timingSafeEqual(left, right);
  return left === right;
}
function checked(context, wanted, pin, now) {
  if (now < context.issued_at || now >= context.expires_at
    || !same(context.device_id, pin.device_id)
    || !same(context.signer_key_id, pin.signer_key_id)) invalid();
  for (const [field, value] of Object.entries(wanted)) {
    if (!same(context[field], value)) invalid();
  }
}
async function signZk1CiphertextDeviceApprovalV1({ approval: input, privateKey } = {}) {
  // Snapshot all caller-owned bytes and capture the KeyObject before the
  // first async CBOR step. The signed map is exact and domain-separated.
  const unsigned = approval(input);
  if (!(privateKey instanceof crypto.KeyObject) || privateKey.type !== "private"
    || privateKey.asymmetricKeyType !== "ed25519") invalid();
  try {
    const payload = await z.encodeDeterministic(unsigned);
    const signature = crypto.sign(null, Buffer.concat([DOMAIN, payload]), privateKey);
    return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  } catch (_) { invalid(); }
}

async function inspectZk1CiphertextDeviceApprovalCryptoV1({ raw, pinned, expected,
  nowSeconds } = {}) {
  // Inputs are NOT allowed to provide public keys or active/revoked flags in
  // their signed wire. `pinned` is a separately supplied verifier-side key;
  // even that does not prove live authorization at a fresh witness head.
  const wire = copy(raw, 100, 4096);
  const key = pinnedDevice(pinned);
  const want = expectedContext(expected);
  const now = natural(nowSeconds, 1);
  try {
    const decoded = await z.decodeDeterministic(wire);
    exact(decoded, WIRE_FIELDS);
    const signature = copy(decoded.signature, 64);
    const { signature: _signature, ...unsigned } = decoded;
    const normalized = approval(unsigned);
    checked(normalized, want, key, now);
    const encoded = await z.encodeDeterministic(normalized);
    const canonical = await z.encodeDeterministic({ ...normalized, signature });
    if (!wire.equals(canonical)
      || !crypto.verify(null, Buffer.concat([DOMAIN, encoded]), key.publicKey, signature)) invalid();
    return Object.freeze({ signatureVerified: true, authorizesRelease: false,
      deviceAuthorizationVerified: false, liveManifestHeadVerified: false,
      nonceConsumed: false });
  } catch (_) { invalid(); }
}

module.exports = { signZk1CiphertextDeviceApprovalV1,
  inspectZk1CiphertextDeviceApprovalCryptoV1 };
