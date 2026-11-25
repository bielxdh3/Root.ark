"use strict";

const crypto = require("node:crypto");
const { types: nodeUtilTypes } = require("node:util");
const zk = require("../src/crypto/rootark-zk-1");
const nativeZkEncodeDeterministic = zk.encodeDeterministic;
const nativeZkSuiteId = zk.SUITE_ID;
const nativeZkAuthorizationDomain = zk.ASCII.AUTHORIZATION;

// Authorization binding is rechecked on retries, after the transport has had
// a chance to mutate shared globals. Keep its digest/nonce/verification path
// on the native primitives captured before that trust boundary.
const NativeBuffer = Buffer;
const nativeBufferFrom = NativeBuffer.from.bind(NativeBuffer);
const nativeBufferConcat = NativeBuffer.concat.bind(NativeBuffer);
const nativeBufferToString = NativeBuffer.prototype.toString;
const nativeRandomBytes = crypto.randomBytes.bind(crypto);
const nativeCreateHash = crypto.createHash.bind(crypto);
const nativeHashUpdate = crypto.Hash.prototype.update;
const nativeHashDigest = crypto.Hash.prototype.digest;
const nativeSign = crypto.sign.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeVerify = crypto.verify.bind(crypto);
const nativeReflectApply = Reflect.apply;
const nativeJsonStringify = JSON.stringify.bind(JSON);
const nativeArrayIsArray = Array.isArray;
const nativeArrayIncludes = Array.prototype.includes;
const nativeRegExpExec = RegExp.prototype.exec;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeDateNow = Date.now;
const nativeObjectKeys = Object.keys;
const nativeObjectHasOwn = Object.hasOwn;
const nativeObjectAssign = Object.assign;
const NativeArray = Array;
const NativeObjectPrototype = Object.prototype;
const nativeIsProxy = nodeUtilTypes.isProxy;
const nativeObjectCreate = Object.create;
const nativeObjectFreeze = Object.freeze;
const nativeObjectGetPrototypeOf = Object.getPrototypeOf;
const nativeObjectSetPrototypeOf = Object.setPrototypeOf;
const nativeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeReflectOwnKeys = Reflect.ownKeys;

function ownDataValue(value, key) {
  if (!value || typeof value !== "object") return undefined;
  const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
  if (descriptor && !nativeObjectHasOwn(descriptor, "value")) fail(`Invalid authorization accessor: ${key}`);
  return descriptor && nativeObjectHasOwn(descriptor, "value") ? descriptor.value : undefined;
}

function assertPlainDataObject(value, name) {
  if (!value || typeof value !== "object" || nativeArrayIsArray(value) || nativeIsProxy(value)) {
    fail(`Invalid ${name}`);
  }
  const prototype = nativeObjectGetPrototypeOf(value);
  if (prototype !== NativeObjectPrototype && prototype !== null) fail(`Invalid ${name}`);
  const keys = nativeObjectKeys(value);
  if (nativeReflectOwnKeys(value).length !== keys.length) fail(`Invalid ${name}`);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, keys[index]);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      fail(`Invalid ${name}`);
    }
  }
}

function regexTest(pattern, value) {
  return nativeReflectApply(nativeRegExpExec, pattern, [value]) !== null;
}

function freezeJson(value) {
  if (!value || typeof value !== "object") return value;
  const keys = nativeObjectKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, keys[index]);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) fail("Invalid authorization JSON value");
    freezeJson(descriptor.value);
  }
  nativeObjectSetPrototypeOf(value, null);
  return nativeObjectFreeze(value);
}

function snapshotStringArray(value, code) {
  if (!nativeArrayIsArray(value) || nativeIsProxy(value)
    || (nativeObjectGetPrototypeOf(value) !== NativeArray.prototype
      && nativeObjectGetPrototypeOf(value) !== null)) {
    fail("Device revocation state is unavailable", code);
  }
  const length = value.length;
  const keys = nativeObjectKeys(value);
  if (keys.length !== length || nativeReflectOwnKeys(value).length !== length + 1) {
    fail("Device revocation state is ambiguous", code);
  }
  const snapshot = new NativeArray(length);
  for (let index = 0; index < length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || typeof descriptor.value !== "string") {
      fail("Device revocation state is ambiguous", code);
    }
    snapshot[index] = descriptor.value;
  }
  nativeObjectSetPrototypeOf(snapshot, null);
  return nativeObjectFreeze(snapshot);
}

function canonicalizeJson(value) {
  if (typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") {
    fail("Invalid authorization JSON value");
  }
  if (value === null || typeof value !== "object") return value;
  if (nativeIsProxy(value)) fail("Invalid authorization JSON proxy");
  if (nativeArrayIsArray(value)) {
    const prototype = nativeObjectGetPrototypeOf(value);
    if ((prototype !== NativeArray.prototype && prototype !== null)
      || nativeObjectKeys(value).length !== value.length
      || nativeReflectOwnKeys(value).length !== value.length + 1) {
      fail("Invalid authorization JSON array");
    }
    const result = new NativeArray(value.length);
    nativeObjectSetPrototypeOf(result, null);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor) fail("Sparse authorization JSON arrays are not accepted");
      if (!nativeObjectHasOwn(descriptor, "value")) fail("Invalid authorization JSON value");
      result[index] = canonicalizeJson(descriptor.value);
    }
    if (nativeReflectOwnKeys(value).length !== value.length + 1) fail("Invalid authorization JSON array");
    return result;
  }
  assertPlainDataObject(value, "authorization JSON object");
  const keys = nativeObjectKeys(value);
  if (nativeReflectOwnKeys(value).length !== keys.length) fail("Invalid authorization JSON object");
  for (let index = 1; index < keys.length; index += 1) {
    const key = keys[index];
    let cursor = index - 1;
    while (cursor >= 0 && keys[cursor] > key) {
      keys[cursor + 1] = keys[cursor];
      cursor -= 1;
    }
    keys[cursor + 1] = key;
  }
  const result = nativeObjectCreate(null);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
      fail("Invalid authorization JSON value");
    }
    result[key] = canonicalizeJson(descriptor.value);
  }
  return result;
}

function safeCanonicalJson(value) {
  return nativeJsonStringify(canonicalizeJson(value));
}

function bufferToString(value, encoding) {
  return nativeReflectApply(nativeBufferToString, value, [encoding]);
}

function sha256Base64Url(value) {
  const hash = nativeCreateHash("sha256");
  nativeReflectApply(nativeHashUpdate, hash, [value]);
  return bufferToString(nativeReflectApply(nativeHashDigest, hash, []), "base64url");
}

const PROOF_FIELDS = nativeObjectFreeze([
  "schemaVersion", "type", "suite", "protocolVersion", "username", "deviceId", "operationId",
  "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch",
  "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
  "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature",
]);

function fail(message, code = "invalid_device_authorization") {
  throw nativeObjectAssign(new Error(message), { code });
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
  if (regexTest(IDEMPOTENCY_KEY_PATTERN, value)) return true;
  return regexTest(LEGACY_IDEMPOTENCY_KEY_PATTERN, value) && value.length % 4 !== 1;
}

function generateIdempotencyKey() {
  return bufferToString(nativeRandomBytes(GENERATED_IDEMPOTENCY_KEY_BYTES), "base64url");
}

function text(value, name) {
  if (typeof value !== "string" || !value || value.length > 512) fail(`Invalid authorization ${name}`);
  return value;
}

function digest(value, name) {
  if (typeof value !== "string" || !regexTest(/^[A-Za-z0-9_-]+$/, value) || value.length % 4 === 1) fail(`Invalid authorization ${name}`);
  const bytes = nativeBufferFrom(value, "base64url");
  if (bytes.length !== 32 || bufferToString(bytes, "base64url") !== value) fail(`Invalid authorization ${name}`);
  return bytes;
}

function exact(value) {
  assertPlainDataObject(value, "authorization schema");
  const keys = nativeObjectKeys(value);
  if (nativeReflectOwnKeys(value).length !== keys.length) fail("Invalid authorization schema");
  for (let index = 0; index < keys.length; index += 1) {
    if (!nativeReflectApply(nativeArrayIncludes, PROOF_FIELDS, [keys[index]])) {
      fail("Invalid authorization schema");
    }
  }
  const detached = nativeObjectCreate(null);
  for (let index = 0; index < PROOF_FIELDS.length; index += 1) {
    const field = PROOF_FIELDS[index];
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, field);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
      fail("Invalid authorization schema");
    }
    detached[field] = canonicalizeJson(descriptor.value);
  }
  return freezeJson(detached);
}

function proofCore(operation, options, requireFresh = true) {
  assertPlainDataObject(operation, "authorization operation");
  assertPlainDataObject(options, "authorization options");
  const capturedOperation = nativeObjectCreate(null);
  const operationFields = ["protocolVersion", "deviceId", "operationId", "objectId", "fileId",
    "versionId", "operation", "revision", "baseRevision", "keyEpoch", "compartmentId",
    "metadata", "aad", "ciphertext", "nonce", "tag"];
  for (let index = 0; index < operationFields.length; index += 1) {
    const field = operationFields[index];
    const value = ownDataValue(operation, field);
    if (value === undefined && field !== "baseRevision") fail(`Invalid authorization operation field: ${field}`);
    capturedOperation[field] = field === "revision" || field === "baseRevision" || field === "metadata"
      ? canonicalizeJson(value) : value;
  }
  freezeJson(capturedOperation);
  const expiresAtOption = ownDataValue(options, "expiresAt");
  const expiresAt = expiresAtOption === undefined ? nativeDateNow() + 5 * 60 * 1000 : expiresAtOption;
  if (!nativeNumberIsSafeInteger(expiresAt) || expiresAt <= 0
    || (requireFresh && expiresAt <= nativeDateNow())) fail("Authorization expired", "authorization_expired");
  const replayIdOption = ownDataValue(options, "replayId");
  const replayId = replayIdOption || bufferToString(nativeRandomBytes(16), "base64url");
  const idempotencyKeyOption = ownDataValue(options, "idempotencyKey");
  const idempotencyKey = idempotencyKeyOption === undefined ? generateIdempotencyKey() : idempotencyKeyOption;
  if (!isValidIdempotencyKey(idempotencyKey)) fail("Invalid device authorization");
  return {
    schemaVersion: 1,
    type: "rootark-sync-device-authorization-v1",
    suite: nativeZkSuiteId,
    protocolVersion: capturedOperation.protocolVersion,
    username: text(ownDataValue(options, "username"), "username"),
    deviceId: text(capturedOperation.deviceId, "deviceId"),
    operationId: text(capturedOperation.operationId, "operationId"),
    objectId: text(capturedOperation.objectId, "objectId"),
    fileId: text(capturedOperation.fileId, "fileId"),
    versionId: text(capturedOperation.versionId, "versionId"),
    operation: text(capturedOperation.operation, "operation"),
    revision: capturedOperation.revision,
    baseRevision: capturedOperation.baseRevision || null,
    keyEpoch: text(capturedOperation.keyEpoch, "keyEpoch"),
    compartmentId: text(capturedOperation.compartmentId, "compartmentId"),
    metadata: capturedOperation.metadata,
    aadDigest: sha256Base64Url(nativeBufferFrom(capturedOperation.aad, "base64url")),
    ciphertextDigest: sha256Base64Url(nativeBufferFrom(capturedOperation.ciphertext, "base64url")),
    nonceDigest: sha256Base64Url(nativeBufferFrom(capturedOperation.nonce, "base64url")),
    tagDigest: sha256Base64Url(nativeBufferFrom(capturedOperation.tag, "base64url")),
    expiresAt,
    replayId,
    idempotencyKey,
    publicKey: text(ownDataValue(options, "publicKey"), "publicKey"),
    signature: "",
  };
}

async function signedBytes(core) {
  const { signature: _signature, ...unsigned } = core;
  return nativeBufferConcat([nativeBufferFrom(nativeZkAuthorizationDomain, "ascii"),
    nativeBufferFrom([0]), await nativeReflectApply(nativeZkEncodeDeterministic, undefined, [unsigned])]);
}

async function createAuthorizationProof(operation, options = {}) {
  assertPlainDataObject(operation, "authorization operation");
  assertPlainDataObject(options, "authorization options");
  const privateKey = ownDataValue(options, "privateKey");
  const publicKey = ownDataValue(options, "publicKey");
  if (!privateKey || !publicKey) fail("Authorization key material is required");
  const core = proofCore(operation, options);
  const signatureInput = await signedBytes(core);
  core.signature = bufferToString(nativeSign(null, signatureInput, privateKey), "base64url");
  return core;
}

// Structural binding, NOT device authorization. Check that every claimed
// identifier and encrypted-byte digest describes the actual envelope.
// Neither the supplied key nor its signature is trusted by this check.
function assertAuthorizationEnvelopeBinding(proof, operation) {
  const normalized = exact(proof);
  if (!isValidIdempotencyKey(normalized.idempotencyKey)) fail("Invalid device authorization");
  if (normalized.schemaVersion !== 1 || normalized.type !== "rootark-sync-device-authorization-v1"
    || normalized.suite !== nativeZkSuiteId) fail("Unsupported authorization proof");
  const expectedCore = proofCore(operation, {
    username: normalized.username, publicKey: normalized.publicKey,
    expiresAt: normalized.expiresAt, replayId: normalized.replayId,
    idempotencyKey: normalized.idempotencyKey,
  }, false);
  const boundFields = ["protocolVersion", "deviceId", "operationId", "objectId", "fileId",
    "versionId", "operation", "revision", "baseRevision", "keyEpoch", "compartmentId",
    "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest"];
  for (let index = 0; index < boundFields.length; index += 1) {
    const field = boundFields[index];
    if (safeCanonicalJson(normalized[field]) !== safeCanonicalJson(expectedCore[field])) {
      fail("Authorization envelope binding mismatch", "authorization_scope");
    }
  }
  return true;
}

async function verifyAuthorizationProofInternal(proof, operation, expected, requireFresh) {
  assertPlainDataObject(operation, "authorization operation");
  assertPlainDataObject(expected, "authorization scope");
  const normalized = exact(proof);
  if (!isValidIdempotencyKey(normalized.idempotencyKey)) fail("Invalid device authorization");
  if (normalized.schemaVersion !== 1 || normalized.type !== "rootark-sync-device-authorization-v1" || normalized.suite !== nativeZkSuiteId) fail("Unsupported authorization proof");
  if (!nativeNumberIsSafeInteger(normalized.expiresAt) || normalized.expiresAt <= 0) fail("Invalid authorization expiry");
  if (requireFresh && normalized.expiresAt <= nativeDateNow()) fail("Authorization expired", "authorization_expired");
  if (!expected || typeof expected !== "object" || nativeArrayIsArray(expected)) fail("Invalid authorization scope", "authorization_scope");
  const username = ownDataValue(expected, "username");
  const pins = ownDataValue(expected, "trustedDevicePublicKeys");
  const revokedDeviceIdsSource = ownDataValue(expected, "revokedDeviceIds");
  const revokedDeviceIds = snapshotStringArray(revokedDeviceIdsSource,
    "authorization_device_revoked");
  if (normalized.protocolVersion !== ownDataValue(operation, "protocolVersion")
    || normalized.username !== username || normalized.deviceId !== ownDataValue(operation, "deviceId")) {
    fail("Authorization scope mismatch", "authorization_scope");
  }
  let pinned = null;
  if (pins && typeof pins === "object" && !nativeArrayIsArray(pins)) {
    if (nativeIsProxy(pins)) fail("Device signing key registry is ambiguous", "authorization_device_untrusted");
    const prototype = nativeObjectGetPrototypeOf(pins);
    if (prototype !== NativeObjectPrototype && prototype !== null) fail("Device signing key registry is ambiguous", "authorization_device_untrusted");
    if (nativeReflectOwnKeys(pins).length !== nativeObjectKeys(pins).length) fail("Device signing key registry is ambiguous", "authorization_device_untrusted");
    const pinDescriptor = nativeObjectGetOwnPropertyDescriptor(pins, normalized.deviceId);
    if (pinDescriptor && !nativeObjectHasOwn(pinDescriptor, "value")) fail("Device signing key registry is ambiguous", "authorization_device_untrusted");
    pinned = pinDescriptor && nativeObjectHasOwn(pinDescriptor, "value") ? pinDescriptor.value : null;
  }
  // A signed envelope proves control of the *supplied* key. Authorization
  // always requires an independently provisioned device-to-key binding.
  // Do not permit callers to omit the pin option and silently downgrade
  // this public verification API into self-enrollment.
  if (typeof pinned !== "string" || pinned !== normalized.publicKey) {
    fail("Device signing key is not trusted", "authorization_device_untrusted");
  }
  if (!nativeArrayIsArray(revokedDeviceIds)
    || nativeReflectApply(nativeArrayIncludes, revokedDeviceIds,
      [normalized.deviceId])) {
    fail("Device has been revoked or revocation state is invalid", "authorization_device_revoked");
  }
  assertAuthorizationEnvelopeBinding(normalized, operation);
  // CBOR encoding yields before verify(). Do not reuse a prior trust-policy
  // snapshot if the embedding authority revoked or replaced a pin mid-await.
  const signedInput = await signedBytes(normalized);
  const liveRevocationsSource = ownDataValue(expected, "revokedDeviceIds");
  const liveRevocations = snapshotStringArray(liveRevocationsSource,
    "authorization_device_revoked");
  const livePins = ownDataValue(expected, "trustedDevicePublicKeys");
  const livePin = livePins && typeof livePins === "object" && !nativeIsProxy(livePins)
    ? ownDataValue(livePins, normalized.deviceId) : null;
  if (ownDataValue(expected, "username") !== username || livePins !== pins
    || livePin !== pinned) {
    fail("Device trust policy changed during verification", "authorization_device_untrusted");
  }
  if (liveRevocationsSource !== revokedDeviceIdsSource
    || liveRevocations.length !== revokedDeviceIds.length) {
    fail("Device revocation policy changed during verification", "authorization_device_revoked");
  }
  for (let index = 0; index < revokedDeviceIds.length; index += 1) {
    if (liveRevocations[index] !== revokedDeviceIds[index]) {
      fail("Device revocation policy changed during verification", "authorization_device_revoked");
    }
  }
  if (nativeReflectApply(nativeArrayIncludes, liveRevocations, [normalized.deviceId])) {
    fail("Device has been revoked during verification", "authorization_device_revoked");
  }
  if (requireFresh && normalized.expiresAt <= nativeDateNow()) {
    fail("Authorization expired during verification", "authorization_expired");
  }
  const key = nativeCreatePublicKey({ key: nativeBufferFrom(normalized.publicKey, "base64url"), format: "der", type: "spki" });
  if (!nativeVerify(null, signedInput, key,
    nativeBufferFrom(normalized.signature, "base64url"))) fail("Authorization signature invalid", "authorization_signature");
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
