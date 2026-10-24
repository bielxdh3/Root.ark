"use strict";

// Issue #65 laboratory inspector. This compares existing verified cryptographic
// evidence; none of the receipts proves live CAS/witness freshness, durable
// monotonic state, independent key bootstrap, or atomic nonce consumption.
// This module must never be used as a publication or recovery admission gate.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const manifestV2 = require("./rootark-zk-recovery-manifest-v2");
const historyV2 = require("./rootark-zk-recovery-history-v2");
const witnessV1 = require("./rootark-zk-witness-head-wire-v1");
const approvalV1 = require("./rootark-zk-ciphertext-device-approval-v1");

const PUBLIC_KEY_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const INPUT_FIELDS = Object.freeze([
  "raw", "expected", "nowSeconds", "verifiedHistory", "pinnedDevice", "witness",
]);

function invalid() {
  const error = new Error("ZK_CIPHERTEXT_APPROVAL_CONSISTENCY_INVALID");
  error.code = error.message;
  throw error;
}

function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) invalid();
  return value;
}

function bytes(value, size, min = size, max = size) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) invalid();
  return Buffer.from(value);
}

function same(left, right) {
  return (Buffer.isBuffer(left) || left instanceof Uint8Array)
    && (Buffer.isBuffer(right) || right instanceof Uint8Array)
    && left.byteLength === right.byteLength
    && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function positiveSafeInteger(value) {
  if (!Number.isSafeInteger(value) || value < 1) invalid();
  return value;
}

function revision(value) {
  if (typeof value === "bigint") {
    if (value < 1n || value > BigInt(Number.MAX_SAFE_INTEGER)) invalid();
    return Number(value);
  }
  return positiveSafeInteger(value);
}

function pinnedKey(value, keyField, idField) {
  if (!value || !(value[keyField] instanceof crypto.KeyObject)
    || value[keyField].type !== "public"
    || value[keyField].asymmetricKeyType !== "ed25519") invalid();
  return { ...value, [idField]: bytes(value[idField], 16),
    [keyField]: value[keyField] };
}

function rawEd25519(value) {
  const der = value.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(der) || der.length !== PUBLIC_KEY_PREFIX.length + 32
    || !der.subarray(0, PUBLIC_KEY_PREFIX.length).equals(PUBLIC_KEY_PREFIX)) invalid();
  return Buffer.from(der.subarray(PUBLIC_KEY_PREFIX.length));
}

async function inspectZk1CiphertextApprovalConsistencyV1(input) {
  // Take snapshots synchronously: all of the shared validators await CBOR.
  // Captured public KeyObjects are immutable verification keys. Neither the
  // approval wire nor its sender may supply a trusted device or witness key.
  try {
    exact(input, INPUT_FIELDS);
    const raw = bytes(input.raw, undefined, 100, 4096);
    const expected = structuredClone(input.expected);
    const head = structuredClone(input.verifiedHistory?.headManifest);
    const historyDigest = bytes(input.verifiedHistory?.headDigest, 32);
    const pinnedDevice = pinnedKey(exact(input.pinnedDevice,
      ["deviceId", "signerKeyId", "publicKey"]), "publicKey", "signerKeyId");
    const witnessInput = exact(input.witness,
      ["raw", "pinned", "nonce", "minimumHead"]);
    const witnessPinned = pinnedKey(exact(witnessInput.pinned, ["keyId", "publicKey"]),
      "publicKey", "keyId");
    const witness = {
      raw: bytes(witnessInput.raw, undefined, 1, 8 * 1024 * 1024),
      pinned: witnessPinned,
      nonce: bytes(witnessInput.nonce, 32),
      minimumHead: exact(structuredClone(witnessInput.minimumHead),
        ["revision", "witnessSequence", "digest"]),
    };
    witness.minimumHead.digest = bytes(witness.minimumHead.digest, 32);
    const nowSeconds = positiveSafeInteger(input.nowSeconds);

    // A caller-provided manifest or boolean is insufficient. Require a live
    // WeakMap-issued, MAC-verified complete history from the existing module.
    if (!await historyV2.isVerifiedRecoveryHistoryV2(input.verifiedHistory)) invalid();
    manifestV2.validateManifestShape(head);
    const digest = await manifestV2.recoveryManifestDigestV2(head);
    if (!same(digest, historyDigest)
      || !same(digest, expected?.manifestDigest)
      || revision(head.revision) !== positiveSafeInteger(expected?.manifestRevision)
      || revision(head.current_epoch) !== positiveSafeInteger(expected?.keyringEpoch)
      || !same(head.account_id, expected?.scope?.account_id)
      || !same(head.compartment_id, expected?.scope?.compartment_id)
      || !same(head.keyring_id, expected?.scope?.keyring_id)) invalid();

    const device = head.devices.find((row) => row.device_id === pinnedDevice.deviceId);
    if (!device || device.revoked_at_epoch !== null
      || !same(device.authorization_key_id, pinnedDevice.signerKeyId)
      || !same(device.authorization_public_key, rawEd25519(pinnedDevice.publicKey))) invalid();

    // Witness verifier ensures canonical signed committed receipt and checks
    // the independently supplied floor. Explicitly check the actual signed
    // tuple (its result exposes only current_revision, not the digest).
    const checkedWitness = await witnessV1.inspectVerifiedWitnessFreshHeadV1({
      ...witness, scope: {
        account_id: bytes(expected.scope.account_id, 16),
        compartment_id: bytes(expected.scope.compartment_id, undefined, 1, 128),
        keyring_id: bytes(expected.scope.keyring_id, 16),
      },
    });
    const signedHead = await z.decodeDeterministic(witness.raw);
    if (checkedWitness.verifiedSignatureOnly !== true
      || checkedWitness.authorizesRecovery !== false
      || revision(checkedWitness.current_revision) !== revision(head.revision)
      || revision(signedHead.current_revision) !== revision(head.revision)
      || !same(signedHead.current_manifest_digest, digest)
      || !same(witness.nonce, expected.nonce)) invalid();

    const approval = await approvalV1.inspectZk1CiphertextDeviceApprovalCryptoV1({
      raw, pinned: pinnedDevice, expected, nowSeconds,
    });
    if (approval.signatureVerified !== true || approval.authorizesRelease !== false) invalid();
    return Object.freeze({
      signatureVerified: true,
      manifestHistoryVerified: true,
      deviceRecordConsistent: true,
      witnessSignatureVerified: true,
      manifestWitnessTupleConsistent: true,
      liveFreshnessVerified: false,
      nonceConsumed: false,
      authorizesPublish: false,
      authorizesRecovery: false,
    });
  } catch (_) {
    invalid();
  }
}

module.exports = { inspectZk1CiphertextApprovalConsistencyV1 };
