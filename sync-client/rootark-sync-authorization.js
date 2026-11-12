"use strict";

const {
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  createHash: NATIVE_CREATE_HASH,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  verify: NATIVE_VERIFY,
  sign: NATIVE_SIGN,
  randomBytes: NATIVE_RANDOM_BYTES,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT,
  bufferToString: NATIVE_BUFFER_TO_STRING,
  jsonStringify: NATIVE_JSON_STRINGIFY,
  arraySome: NATIVE_ARRAY_SOME,
  arrayIncludes: NATIVE_ARRAY_INCLUDES,
  dateNow: NATIVE_DATE_NOW,
} = require("../src/crypto/rootark-zk10-native-intrinsics-v1");
const zk = require("../src/crypto/rootark-zk-1");

const PROOF_FIELDS = Object.freeze([
  "schemaVersion", "type", "suite", "protocolVersion", "username", "deviceId", "operationId",
  "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch",
  "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
  "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature",
]);
// This comparison runs after caller-owned native KeyObject callbacks in some
// historical proof paths. Array.prototype[Symbol.iterator] can be replaced by
// those callbacks; keep the exact binding field order and iterate own slots.
const ENVELOPE_BINDING_FIELDS = Object.freeze([
  "protocolVersion", "deviceId", "operationId", "objectId", "fileId",
  "versionId", "operation", "revision", "baseRevision", "keyEpoch", "compartmentId",
  "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
]);

function fail(message, code = "invalid_device_authorization") {
  throw Object.assign(new Error(message), { code });
}

// idempotencyKey is an opaque token: validated by charset and length only, never decoded as base64.
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
// Keys persisted before the canonical rule were operationIds (idempotencyKey defaulted to operationId).
// They were accepted when they matched the old base64url charset check (length % 4 !== 1). The longest
// such id is a WebDAV composite: "webdav-" + 160-char id + "-" + 24 hex = 192 characters.
const LEGACY_IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{1,192}$/;
const GENERATED_IDEMPOTENCY_KEY_BYTES = 16;

function isValidIdempotencyKey(value) {
  if (typeof value !== "string") return false;
  if (IDEMPOTENCY_KEY_PATTERN.test(value)) return true;
  return LEGACY_IDEMPOTENCY_KEY_PATTERN.test(value) && value.length % 4 !== 1;
}

function generateIdempotencyKey() {
  return NATIVE_BUFFER_TO_STRING.call(NATIVE_RANDOM_BYTES(GENERATED_IDEMPOTENCY_KEY_BYTES), "base64url");
}

function text(value, name) {
  if (typeof value !== "string" || !value || value.length > 512) fail(`Invalid authorization ${name}`);
  return value;
}

function digest(value, name) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) fail(`Invalid authorization ${name}`);
  const bytes = NATIVE_BUFFER_FROM(value, "base64url");
  if (bytes.length !== 32 || NATIVE_BUFFER_TO_STRING.call(bytes, "base64url") !== value) fail(`Invalid authorization ${name}`);
  return bytes;
}

function exact(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || NATIVE_ARRAY_SOME.call(Object.keys(value), (key) => !NATIVE_ARRAY_INCLUDES.call(PROOF_FIELDS, key))
    || NATIVE_ARRAY_SOME.call(PROOF_FIELDS, (key) => !Object.hasOwn(value, key))) fail("Invalid authorization schema");
}

function hashDigest(value) {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, NATIVE_BUFFER_FROM(value, "base64url"));
  return NATIVE_BUFFER_TO_STRING.call(NATIVE_HASH_DIGEST.call(hash), "base64url");
}

function proofCore(operation, options, requireFresh = true) {
  const expiresAt = options.expiresAt === undefined ? NATIVE_DATE_NOW() + 5 * 60 * 1000 : options.expiresAt;
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0
    || (requireFresh && expiresAt <= NATIVE_DATE_NOW())) fail("Authorization expired");
  const replayId = options.replayId || NATIVE_BUFFER_TO_STRING.call(NATIVE_RANDOM_BYTES(16), "base64url");
  const idempotencyKey = options.idempotencyKey === undefined ? generateIdempotencyKey() : options.idempotencyKey;
  if (!isValidIdempotencyKey(idempotencyKey)) fail("Invalid device authorization");
  return {
    schemaVersion: 1,
    type: "rootark-sync-device-authorization-v1",
    suite: zk.SUITE_ID,
    protocolVersion: operation.protocolVersion,
    username: text(options.username, "username"),
    deviceId: text(operation.deviceId, "deviceId"),
    operationId: text(operation.operationId, "operationId"),
    objectId: text(operation.objectId, "objectId"),
    fileId: text(operation.fileId, "fileId"),
    versionId: text(operation.versionId, "versionId"),
    operation: text(operation.operation, "operation"),
    revision: operation.revision,
    baseRevision: operation.baseRevision || null,
    keyEpoch: text(operation.keyEpoch, "keyEpoch"),
    compartmentId: text(operation.compartmentId, "compartmentId"),
    metadata: operation.metadata,
    aadDigest: hashDigest(operation.aad),
    ciphertextDigest: hashDigest(operation.ciphertext),
    nonceDigest: hashDigest(operation.nonce),
    tagDigest: hashDigest(operation.tag),
    expiresAt,
    replayId,
    idempotencyKey,
    publicKey: text(options.publicKey, "publicKey"),
    signature: "",
  };
}

async function signedBytes(core) {
  const { signature: _signature, ...unsigned } = core;
  return NATIVE_BUFFER_CONCAT([NATIVE_BUFFER_FROM(zk.ASCII.AUTHORIZATION, "ascii"),
    NATIVE_BUFFER_FROM([0]), await zk.encodeDeterministic(unsigned)]);
}

async function createAuthorizationProof(operation, options = {}) {
  if (!options.privateKey || !options.publicKey) fail("Authorization key material is required");
  const core = proofCore(operation, options);
  core.signature = NATIVE_BUFFER_TO_STRING.call(
    NATIVE_SIGN(null, await signedBytes(core), options.privateKey), "base64url");
  return core;
}

// Structural binding, NOT device authorization. Check that every claimed
// identifier and encrypted-byte digest describes the actual envelope.
// Neither the supplied key nor its signature is trusted by this check.
function assertAuthorizationEnvelopeBinding(proof, operation) {
  exact(proof);
  if (!isValidIdempotencyKey(proof.idempotencyKey)) fail("Invalid device authorization");
  if (proof.schemaVersion !== 1 || proof.type !== "rootark-sync-device-authorization-v1"
    || proof.suite !== zk.SUITE_ID) fail("Unsupported authorization proof");
  const expectedCore = proofCore(operation, {
    username: proof.username, publicKey: proof.publicKey,
    expiresAt: proof.expiresAt, replayId: proof.replayId,
    idempotencyKey: proof.idempotencyKey,
  }, false);
  for (let index = 0; index < ENVELOPE_BINDING_FIELDS.length; index += 1) {
    const field = ENVELOPE_BINDING_FIELDS[index];
    if (NATIVE_JSON_STRINGIFY(proof[field]) !== NATIVE_JSON_STRINGIFY(expectedCore[field])) {
      fail("Authorization envelope binding mismatch", "authorization_scope");
    }
  }
  return true;
}

async function verifyAuthorizationProofInternal(proof, operation, expected, requireFresh) {
  exact(proof);
  const normalized = { ...proof };
  if (!isValidIdempotencyKey(normalized.idempotencyKey)) fail("Invalid device authorization");
  if (normalized.schemaVersion !== 1 || normalized.type !== "rootark-sync-device-authorization-v1" || normalized.suite !== zk.SUITE_ID) fail("Unsupported authorization proof");
  if (!Number.isSafeInteger(normalized.expiresAt) || normalized.expiresAt <= 0) fail("Invalid authorization expiry");
  if (requireFresh && normalized.expiresAt <= NATIVE_DATE_NOW()) fail("Authorization expired", "authorization_expired");
  if (normalized.protocolVersion !== operation.protocolVersion || normalized.username !== expected.username || normalized.deviceId !== operation.deviceId) fail("Authorization scope mismatch", "authorization_scope");
  const pins = expected.trustedDevicePublicKeys;
  const pinned = pins && typeof pins === "object" && !Array.isArray(pins)
    && Object.hasOwn(pins, normalized.deviceId) ? pins[normalized.deviceId] : null;
  // A signed envelope proves control of the *supplied* key. Authorization
  // always requires an independently provisioned device-to-key binding.
  // Do not permit callers to omit the pin option and silently downgrade
  // this public verification API into self-enrollment.
  if (typeof pinned !== "string" || pinned !== normalized.publicKey) {
    fail("Device signing key is not trusted", "authorization_device_untrusted");
  }
  if (!Array.isArray(expected.revokedDeviceIds)
    || NATIVE_ARRAY_INCLUDES.call(expected.revokedDeviceIds, normalized.deviceId)) {
    fail("Device has been revoked or revocation state is invalid", "authorization_device_revoked");
  }
  assertAuthorizationEnvelopeBinding(normalized, operation);
  const key = NATIVE_CREATE_PUBLIC_KEY({ key: NATIVE_BUFFER_FROM(normalized.publicKey, "base64url"), format: "der", type: "spki" });
  if (!NATIVE_VERIFY(null, await signedBytes(normalized), key,
    NATIVE_BUFFER_FROM(normalized.signature, "base64url"))) fail("Authorization signature invalid", "authorization_signature");
  return true;
}

function verifyAuthorizationProof(proof, operation, expected = {}) {
  return verifyAuthorizationProofInternal(proof, operation, expected, true);
}

// Only for reading an operation already admitted by the sync inventory. Keep
// signature, independent device pin, scope and current revocation checks; a
// historical expiry cannot be replayed through the fresh ingress verifier.
function verifyHistoricalAuthorizationProof(proof, operation, expected = {}) {
  return verifyAuthorizationProofInternal(proof, operation, expected, false);
}

module.exports = { PROOF_FIELDS, IDEMPOTENCY_KEY_PATTERN, assertAuthorizationEnvelopeBinding, createAuthorizationProof, generateIdempotencyKey, isValidIdempotencyKey, verifyAuthorizationProof, verifyHistoricalAuthorizationProof };
