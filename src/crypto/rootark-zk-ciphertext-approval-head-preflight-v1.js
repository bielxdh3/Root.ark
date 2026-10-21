"use strict";

// Standalone read-only CRYPTOGRAPHIC INSPECTOR, NOT release authorization.
// Reconciles a proposed ciphertext approval with already-verified v2 signed
// history and a separately pinned, nonce-bound signed witness head. The
// witness receipt is supplied by the caller: no online freshness, monotonic
// storage, CAS/gate state, device custody or nonce consumption is established.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const histories = require("./rootark-zk-recovery-history-v2");
const manifest = require("./rootark-zk-recovery-manifest-v2");
const witness = require("./rootark-zk-witness-history-consistency-v1");
const approval = require("./rootark-zk-ciphertext-device-approval-v1");

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_WITNESS_AGE_SECONDS = 60; // Lab-only freshness *shape*, not online proof.
const FIELDS = Object.freeze([
  "rawApproval", "verifiedPublicHistory", "rawWitnessHead", "witnessPinned",
  "witnessNonce", "minimumHead", "pinnedDevice", "expected", "nowSeconds",
]);
const EXPECTED = Object.freeze([
  "scope", "objectId", "objectRevision", "expectedChunkCount", "expectedRootHash", "nonce",
]);
const PINNED = Object.freeze(["deviceId", "signerKeyId", "publicKey"]);
const WITNESS_PINNED = Object.freeze(["keyId", "publicKey"]);
const FLOOR = Object.freeze(["revision", "digest", "witnessSequence"]);
const SCOPE = Object.freeze(["account_id", "compartment_id", "keyring_id"]);

function fail() {
  const error = new z.RootarkZkError("ZK_CIPHERTEXT_APPROVAL_PREFLIGHT_UNAVAILABLE");
  throw error;
}
function exact(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== fields.length
    || fields.some((k) => !Object.hasOwn(input, k))) fail();
}
function bytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function positive(value, min = 1) {
  if (!Number.isSafeInteger(value) || value < min) fail();
  return value;
}
function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function scopeOf(s) {
  exact(s, SCOPE);
  return { account_id: bytes(s.account_id, 16),
    compartment_id: bytes(s.compartment_id, 1, 128),
    keyring_id: bytes(s.keyring_id, 16) };
}
function pinnedKey(pinned, fields, idField) {
  exact(pinned, fields);
  const publicKey = pinned.publicKey;
  if (!(publicKey instanceof crypto.KeyObject) || publicKey.type !== "public"
    || publicKey.asymmetricKeyType !== "ed25519") fail();
  return { publicKey, keyId: bytes(pinned[idField], 16) };
}
function ed25519Raw(key) {
  const der = Buffer.from(key.export({ type: "spki", format: "der" }));
  if (der.length !== 44 || !der.subarray(0, 12).equals(ED25519_SPKI_PREFIX)) fail();
  return der.subarray(12);
}
function id(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 64
    || /[\u0000-\u001f\u007f]/.test(value)) fail();
  return value;
}

async function inspectZk1CiphertextApprovalHeadPreflightV1(input) {
  try {
    // Capture ALL caller-controlled byte views and key references before the
    // very first await; async CBOR import can otherwise race a changing pin.
    exact(input, FIELDS);
    const history = input.verifiedPublicHistory;
    const rawApproval = bytes(input.rawApproval, 100, 4096);
    const rawWitnessHead = bytes(input.rawWitnessHead, 1, 8 * 1024 * 1024);
    const witnessNonce = bytes(input.witnessNonce, 32);
    const witnessPin = pinnedKey(input.witnessPinned, WITNESS_PINNED, "keyId");
    const devicePin = pinnedKey(input.pinnedDevice, PINNED, "signerKeyId");
    const deviceId = id(input.pinnedDevice.deviceId);
    const ownerExpected = input.expected;
    exact(ownerExpected, EXPECTED);
    const expectedScope = scopeOf(ownerExpected.scope);
    const expectedRootHash = bytes(ownerExpected.expectedRootHash, 32);
    const expectedNonce = bytes(ownerExpected.nonce, 32);
    const expectedObjectId = ownerExpected.objectId;
    const objectRevision = positive(ownerExpected.objectRevision);
    const chunkCount = positive(ownerExpected.expectedChunkCount);
    if (chunkCount > 4096) fail();
    const floor = input.minimumHead;
    exact(floor, FLOOR);
    const minimumHead = { revision: positive(floor.revision),
      digest: bytes(floor.digest, 32), witnessSequence: positive(floor.witnessSequence) };
    const nowSeconds = positive(input.nowSeconds);
    const head = history?.headManifest;
    if (!head || !Array.isArray(head.devices)) fail();
    // A signed-history WeakMap proof alone is acceptable as HISTORY evidence,
    // not as an asserted current/recent state. Capture manifest fields early.
    const headScope = scopeOf({ account_id: head.account_id,
      compartment_id: head.compartment_id, keyring_id: head.keyring_id });
    const headRevision = positive(head.revision);
    const epoch = positive(head.current_epoch);
    const headDigest = bytes(history.headDigest, 32);
    const headDevices = head.devices.map((d) => ({
      deviceId: d.device_id,
      keyId: bytes(d.authorization_key_id, 16),
      key: bytes(d.authorization_public_key, 32),
      enrolled: d.enrolled_epoch, revoked: d.revoked_at_epoch,
    }));
    if (!await histories.isVerifiedPublicRecoveryHistoryV2(history)
      || history.revision !== headRevision
      || !same(headDigest, bytes(history.headDigest, 32))
      || !same(headScope.account_id, expectedScope.account_id)
      || !same(headScope.compartment_id, expectedScope.compartment_id)
      || !same(headScope.keyring_id, expectedScope.keyring_id)
      || !same(headDigest, await manifest.recoveryManifestDigestV2(head))) fail();

    const matching = headDevices.filter((d) => d.deviceId === deviceId
      && same(d.keyId, devicePin.keyId)
      && same(d.key, ed25519Raw(devicePin.publicKey)));
    if (matching.length !== 1 || matching[0].revoked !== null
      || !Number.isSafeInteger(matching[0].enrolled)
      || matching[0].enrolled < 1 || matching[0].enrolled > epoch) fail();

    const witnessMatched = await witness.verifyWitnessHeadMatchesSignedHistoryV1({
      verifiedPublicHistory: history, raw: rawWitnessHead,
      pinned: { keyId: witnessPin.keyId, publicKey: witnessPin.publicKey },
      scope: expectedScope, nonce: witnessNonce, minimumHead,
    });
    if (witnessMatched.verifiedConsistentHead !== true
      || witnessMatched.authorizesProtectedIo !== false) fail();
    // Timestamp merely confirms the authenticated RECEIPT's claimed window;
    // caller-supplied bytes cannot establish that a live server issued it NOW.
    const signedHead = await z.decodeDeterministic(rawWitnessHead);
    const observedAt = positive(signedHead.observed_at);
    if (observedAt > nowSeconds || nowSeconds - observedAt > MAX_WITNESS_AGE_SECONDS) fail();

    const checked = await approval.inspectZk1CiphertextDeviceApprovalCryptoV1({
      raw: rawApproval,
      pinned: { deviceId, signerKeyId: devicePin.keyId, publicKey: devicePin.publicKey },
      expected: { scope: expectedScope, objectId: expectedObjectId,
        objectRevision, manifestRevision: headRevision, manifestDigest: headDigest,
        keyringEpoch: epoch, expectedChunkCount: chunkCount,
        expectedRootHash, nonce: expectedNonce }, nowSeconds,
    });
    if (checked.signatureVerified !== true || checked.authorizesRelease !== false
      || !await histories.isVerifiedPublicRecoveryHistoryV2(history)) fail();

    return Object.freeze({ cryptographicLinkVerified: true,
      signerListedActiveInSignedHead: true, witnessHeadSignatureMatched: true,
      authorizesRelease: false, liveAuthorityVerified: false,
      nonceConsumed: false });
  } catch (_) { fail(); }
}

module.exports = { inspectZk1CiphertextApprovalHeadPreflightV1 };
