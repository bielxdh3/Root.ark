"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { CipherSuite, HkdfSha256, Aes256Gcm } = require("@hpke/core");
const { DhkemX25519HkdfSha256 } = require("@hpke/dhkem-x25519");
const sodium = require("libsodium-wrappers-sumo");

const SUITE_ID = "rootark-zk-1";
const SUITE_VERSION = 1;
const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0002;
const MAX_U64 = 0xffffffffffffffffn;
const MAX_I63 = 0x7fffffffffffffffn;
const ASCII = Object.freeze({
  HPKE_INFO: "Root.ark/zk-1/hpke-info/v1",
  HPKE_INFO_V2: "Root.ark/zk-1/hpke-info/v2",
  KEY_WRAP: "Root.ark/zk-1/key-wrap/v1",
  AUTHORIZATION: "Root.ark/zk-1/authorization-manifest/v1",
  AUTHORIZATION_V2: "Root.ark/zk-1/authorization-manifest/v2",
});
const PROFILE = Object.freeze({
  ROOT: "rootark-zk-1",
  AAD: "rootark-zk-1/aad/v1",
  AAD_V2: "rootark-zk-1/aad/v2",
  HPKE_INFO: "rootark-zk-1/hpke-info/v1",
  HPKE_INFO_V2: "rootark-zk-1/hpke-info/v2",
});
const MANIFEST_TYPE = Object.freeze({
  1: "rootark-authorization-manifest-v1",
  2: "rootark-authorization-manifest-v2",
});
const V2_EXPECTED_SCOPE = Object.freeze([
  "sender_key_id", "recipient_key_id", "compartment_id", "object_id", "version_id",
  "key_ref", "purpose", "epoch", "wrap_id",
]);
const V1_EXPECTED_FIELDS = Object.freeze([
  "sender_key_id", "recipient_key_id", "compartment_id", "object_id", "version_id",
  "purpose", "epoch", "expiry", "replay_id", "idempotency_key", "wrap_id", "hpke_enc",
  "hpke_info_digest", "wrapped_key_digest", "ciphertext_digest",
]);
const V2_EXPECTED_FIELDS = Object.freeze([
  ...V1_EXPECTED_FIELDS, "type", "suite", "envelope_version", "key_ref",
]);
const PURPOSES = Object.freeze([
  "content",
  "derived-data",
  "key-wrap",
  "recovery-package",
  "authorization",
]);
const SUITE_STATES = Object.freeze({
  ALLOWED: "allowed",
  DEPRECATED: "deprecated",
  REJECTED: "rejected",
});
const SUITE_REGISTRY = Object.freeze({
  [SUITE_ID]: Object.freeze({
    version: SUITE_VERSION,
    state: SUITE_STATES.ALLOWED,
    read: "allowed",
    write: "allowed",
    kem: KEM_ID,
    kdf: KDF_ID,
    aead: AEAD_ID,
  }),
});
const SECURITY_CLASS = Object.freeze({
  FAIL_CLOSED: "FAIL_CLOSED_SECURITY",
  AUTHENTICATION: "AUTHENTICATION_FAILED",
  SCOPE: "SCOPE_MISMATCH",
  ENVIRONMENT: "BLOCKED_ENVIRONMENT",
});

class RootarkZkError extends Error {
  constructor(code, classification = SECURITY_CLASS.FAIL_CLOSED) {
    super(code);
    this.name = "RootarkZkError";
    this.code = code;
    this.classification = classification;
  }
}

function fail(code, classification) {
  throw new RootarkZkError(code, classification);
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function bytes(value, code = "INVALID_BYTES", exact, min, max) {
  if (!isBytes(value)) fail(code);
  const result = Buffer.from(value);
  if (exact !== undefined && result.length !== exact) fail("INVALID_LENGTH");
  if (min !== undefined && result.length < min) fail("INVALID_LENGTH");
  if (max !== undefined && result.length > max) fail("INVALID_LENGTH");
  return result;
}

function text(value) {
  if (typeof value !== "string" || value.length === 0) fail("INVALID_TEXT");
  return value;
}

function uint(value, max, code = "INVALID_INTEGER") {
  let result;
  if (typeof value === "bigint") result = value;
  else if (Number.isSafeInteger(value)) result = BigInt(value);
  else fail(code);
  if (result < 0n || result > max) fail(code);
  return result;
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value) || isBytes(value)) {
    fail("AMBIGUOUS_MAP");
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail("AMBIGUOUS_MAP");
  return value;
}

function safeMap(value, required, exact) {
  const map = plainObject(value);
  const keys = Object.keys(map);
  if (exact && (keys.length !== exact.length || exact.some((key) => !Object.hasOwn(map, key)))) {
    fail("UNKNOWN_REQUIRED_FIELD");
  }
  if (required && required.some((key) => !Object.hasOwn(map, key))) fail("MISSING_REQUIRED_FIELD");
  if (keys.some((key) => key === "__proto__" || key === "constructor" || key === "prototype")) {
    fail("INVALID_MAP_KEY");
  }
  return map;
}

function validateCborValue(value, seen = new Set()) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) fail("UNSUPPORTED_CBOR_VALUE");
    return;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > MAX_U64) fail("UNSUPPORTED_CBOR_VALUE");
    return;
  }
  if (isBytes(value)) return;
  if (typeof value !== "object" || seen.has(value)) fail("UNSUPPORTED_CBOR_VALUE");
  seen.add(value);
  if (Array.isArray(value)) {
    value.forEach((entry) => validateCborValue(entry, seen));
  } else {
    const map = plainObject(value);
    for (const key of Object.keys(map)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") fail("INVALID_MAP_KEY");
      validateCborValue(map[key], seen);
    }
  }
  seen.delete(value);
}

let cborgPromise;
function cborg() {
  if (!cborgPromise) cborgPromise = import("cborg").catch((error) => {
    const searchPath = process.env.NODE_PATH?.split(path.delimiter).find((entry) => entry);
    if (!searchPath) throw error;
    return import(pathToFileURL(path.join(searchPath, "cborg", "cborg.js")).href);
  });
  return cborgPromise;
}

async function encodeDeterministic(value) {
  validateCborValue(value);
  try {
    const api = await cborg();
    return Buffer.from(api.encode(value, {
      ...api.rfc8949EncodeOptions,
      ignoreUndefinedProperties: false,
    }));
  } catch (_) {
    fail("CBOR_ENCODE_FAILED");
  }
}

function inspectDecoded(value, seen = new Set()) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) fail("UNSUPPORTED_CBOR_VALUE");
    return;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > MAX_U64) fail("UNSUPPORTED_CBOR_VALUE");
    return;
  }
  if (isBytes(value)) return;
  if (typeof value !== "object" || seen.has(value)) fail("UNSUPPORTED_CBOR_VALUE");
  seen.add(value);
  if (Array.isArray(value)) value.forEach((entry) => inspectDecoded(entry, seen));
  else {
    const map = plainObject(value);
    for (const key of Object.keys(map)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") fail("INVALID_MAP_KEY");
      inspectDecoded(map[key], seen);
    }
  }
  seen.delete(value);
}

async function decodeDeterministic(input) {
  const encoded = bytes(input);
  try {
    const api = await cborg();
    const value = api.decode(encoded, {
      strict: true,
      allowIndefinite: false,
      allowUndefined: false,
      allowInfinity: false,
      allowNaN: false,
      allowBigInt: true,
      rejectDuplicateMapKeys: true,
    });
    inspectDecoded(value);
    const canonical = await encodeDeterministic(value);
    if (!crypto.timingSafeEqual(encoded, canonical)) fail("NON_CANONICAL_ENCODING");
    return value;
  } catch (error) {
    if (error instanceof RootarkZkError) throw error;
    fail("CBOR_DECODE_FAILED");
  }
}

function resolveSuite(suite = SUITE_ID, version = SUITE_VERSION) {
  if (suite !== SUITE_ID) fail("UNKNOWN_SUITE");
  if (version !== SUITE_VERSION) fail("UNSUPPORTED_SUITE_VERSION");
  if (SUITE_REGISTRY[SUITE_ID].state !== SUITE_STATES.ALLOWED) fail("SUITE_NOT_ALLOWED");
  return SUITE_REGISTRY[SUITE_ID];
}

function profile(input) {
  const map = safeMap(input);
  if (!Number.isInteger(map.envelope_version) || map.envelope_version < 0 || map.envelope_version > 0xffff) {
    fail("INVALID_ENVELOPE_VERSION");
  }
  if (map.envelope_version !== 1 && map.envelope_version !== 2) fail("UNSUPPORTED_ENVELOPE_VERSION");
  resolveSuite(map.suite, SUITE_VERSION);
  return map;
}

function scopedFields(input, includeSender) {
  const map = profile(input);
  const result = {
    profile: text(map.profile || PROFILE.ROOT),
    suite: SUITE_ID,
    envelope_version: map.envelope_version,
    compartment_id: bytes(map.compartment_id, "INVALID_COMPARTMENT_ID", undefined, 1, 128),
    epoch: uint(map.epoch, MAX_U64),
    purpose: text(map.purpose),
    object_id: bytes(map.object_id, "INVALID_OBJECT_ID", undefined, 1, 128),
    version_id: bytes(map.version_id, "INVALID_VERSION_ID", undefined, 1, 128),
    key_ref: bytes(map.key_ref, "INVALID_KEY_REF", undefined, 1, 128),
  };
  if (!PURPOSES.includes(result.purpose)) fail("INVALID_PURPOSE");
  if (includeSender) {
    result.sender_key_id = bytes(map.sender_key_id, "INVALID_SENDER_KEY_ID", undefined, 1, 128);
    result.recipient_key_id = bytes(map.recipient_key_id, "INVALID_RECIPIENT_KEY_ID", undefined, 1, 128);
  }
  return result;
}

async function manifestCore(input) {
  const map = profile(input);
  const exact = [
    "type", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "sender_key_id", "recipient_key_id", "object_id", "version_id", "key_ref",
    "expiry", "replay_id", "idempotency_key", "wrap_id", "hpke_enc",
  ];
  safeMap(map, exact, exact);
  if (map.type !== MANIFEST_TYPE[map.envelope_version]) fail("INVALID_MANIFEST_TYPE");
  const scope = scopedFields(map, true);
  return {
    type: map.type,
    suite: SUITE_ID,
    envelope_version: map.envelope_version,
    compartment_id: scope.compartment_id,
    epoch: scope.epoch,
    purpose: scope.purpose,
    sender_key_id: scope.sender_key_id,
    recipient_key_id: scope.recipient_key_id,
    object_id: scope.object_id,
    version_id: scope.version_id,
    key_ref: scope.key_ref,
    expiry: uint(map.expiry, MAX_I63),
    replay_id: bytes(map.replay_id, "INVALID_REPLAY_ID", undefined, 1, 128),
    idempotency_key: bytes(map.idempotency_key, "INVALID_IDEMPOTENCY_KEY", undefined, 1, 128),
    wrap_id: bytes(map.wrap_id, "INVALID_WRAP_ID", 16, 16, 16),
    hpke_enc: bytes(map.hpke_enc, "INVALID_HPKE_ENC", 32, 32, 32),
  };
}

async function buildManifestCoreBytes(input) {
  return encodeDeterministic(await manifestCore(input));
}

async function buildManifestCoreMap(input) {
  return manifestCore(input);
}

async function buildManifestCoreDigest(input) {
  return crypto.createHash("sha256").update(await buildManifestCoreBytes(input)).digest();
}

async function buildAadBytes(input) {
  return encodeDeterministic(await buildAadMap(input));
}

async function buildAadMap(input) {
  const map = safeMap(input);
  const exact = [
    "profile", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "object_id", "version_id", "key_ref", "wrap_id", "manifest_core_digest",
  ];
  safeMap(map, exact, exact);
  const expectedProfile = map.envelope_version === 1 ? PROFILE.AAD : PROFILE.AAD_V2;
  if (map.profile !== expectedProfile) fail("INVALID_PROFILE");
  const scope = scopedFields(map, false);
  return {
    profile: scope.profile,
    suite: SUITE_ID,
    envelope_version: scope.envelope_version,
    compartment_id: scope.compartment_id,
    epoch: scope.epoch,
    purpose: scope.purpose,
    object_id: scope.object_id,
    version_id: scope.version_id,
    key_ref: scope.key_ref,
    wrap_id: bytes(map.wrap_id, "INVALID_WRAP_ID", 16, 16, 16),
    manifest_core_digest: bytes(map.manifest_core_digest, "INVALID_MANIFEST_DIGEST", 32, 32, 32),
  };
}

async function buildHpkeInfoBytes(input) {
  const infoMap = await buildHpkeInfoMap(input);
  const prefix = infoMap.profile === PROFILE.HPKE_INFO ? ASCII.HPKE_INFO : ASCII.HPKE_INFO_V2;
  return Buffer.concat([Buffer.from(prefix, "ascii"), Buffer.from([0]), await encodeDeterministic(infoMap)]);
}

async function buildHpkeInfoMap(input) {
  const map = safeMap(input);
  if (map.profile === PROFILE.HPKE_INFO_V2) return buildAuthorizationHpkeInfoV2Map(map);
  const exact = [
    "profile", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "object_id", "version_id", "key_ref", "sender_key_id", "recipient_key_id",
    "wrap_id", "manifest_core_digest",
  ];
  safeMap(map, exact, exact);
  if (map.profile !== PROFILE.HPKE_INFO) fail("INVALID_PROFILE");
  const scope = scopedFields(map, true);
  return {
    profile: scope.profile,
    suite: SUITE_ID,
    envelope_version: scope.envelope_version,
    compartment_id: scope.compartment_id,
    epoch: scope.epoch,
    purpose: scope.purpose,
    object_id: scope.object_id,
    version_id: scope.version_id,
    key_ref: scope.key_ref,
    sender_key_id: scope.sender_key_id,
    recipient_key_id: scope.recipient_key_id,
    wrap_id: bytes(map.wrap_id, "INVALID_WRAP_ID", 16, 16, 16),
    manifest_core_digest: bytes(map.manifest_core_digest, "INVALID_MANIFEST_DIGEST", 32, 32, 32),
  };
}

function manifestStaticV2(input) {
  const map = profile(input);
  const exact = [
    "type", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "sender_key_id", "recipient_key_id", "object_id", "version_id", "key_ref",
    "expiry", "replay_id", "idempotency_key", "wrap_id",
  ];
  safeMap(map, exact, exact);
  if (map.envelope_version !== 2 || map.type !== MANIFEST_TYPE[2]) fail("INVALID_MANIFEST_TYPE");
  const scope = scopedFields(map, true);
  return {
    type: map.type,
    suite: SUITE_ID,
    envelope_version: 2,
    compartment_id: scope.compartment_id,
    epoch: scope.epoch,
    purpose: scope.purpose,
    sender_key_id: scope.sender_key_id,
    recipient_key_id: scope.recipient_key_id,
    object_id: scope.object_id,
    version_id: scope.version_id,
    key_ref: scope.key_ref,
    expiry: uint(map.expiry, MAX_I63),
    replay_id: bytes(map.replay_id, "INVALID_REPLAY_ID", undefined, 1, 128),
    idempotency_key: bytes(map.idempotency_key, "INVALID_IDEMPOTENCY_KEY", undefined, 1, 128),
    wrap_id: bytes(map.wrap_id, "INVALID_WRAP_ID", 16, 16, 16),
  };
}

async function buildAuthorizationHpkeInfoV2Map(input) {
  const map = safeMap(input);
  const exact = [
    "profile", "type", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "sender_key_id", "recipient_key_id", "object_id", "version_id", "key_ref",
    "expiry", "replay_id", "idempotency_key", "wrap_id",
  ];
  safeMap(map, exact, exact);
  if (map.profile !== PROFILE.HPKE_INFO_V2) fail("INVALID_PROFILE");
  const { profile: _profile, ...manifestInput } = map;
  return { profile: PROFILE.HPKE_INFO_V2, ...manifestStaticV2(manifestInput) };
}

async function buildAuthorizationHpkeInfoV2Bytes(input) {
  const infoMap = await buildAuthorizationHpkeInfoV2Map(input);
  return Buffer.concat([
    Buffer.from(ASCII.HPKE_INFO_V2, "ascii"),
    Buffer.from([0]),
    await encodeDeterministic(infoMap),
  ]);
}

async function buildHpkeInfoDigest(input) {
  return crypto.createHash("sha256").update(await buildHpkeInfoBytes(input)).digest();
}

async function buildManifestMap(input) {
  const map = safeMap(input);
  const coreKeys = [
    "type", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "sender_key_id", "recipient_key_id", "object_id", "version_id", "key_ref",
    "expiry", "replay_id", "idempotency_key", "wrap_id", "hpke_enc",
  ];
  const exact = [...coreKeys, "hpke_info_digest", "wrapped_key_digest", "ciphertext_digest"];
  safeMap(map, exact, exact);
  const core = await manifestCore(Object.fromEntries(coreKeys.map((key) => [key, map[key]])));
  return {
    ...core,
    hpke_info_digest: bytes(map.hpke_info_digest, "INVALID_HPKE_INFO_DIGEST", 32, 32, 32),
    wrapped_key_digest: bytes(map.wrapped_key_digest, "INVALID_WRAPPED_KEY_DIGEST", 32, 32, 32),
    ciphertext_digest: bytes(map.ciphertext_digest, "INVALID_CIPHERTEXT_DIGEST", 32, 32, 32),
  };
}

async function buildManifestBytes(input) {
  return encodeDeterministic(await buildManifestMap(input));
}

async function buildAuthorizationSignatureInput(manifest) {
  const encoded = await buildManifestBytes(manifest);
  const type = (await buildManifestMap(manifest)).type;
  const prefix = type === MANIFEST_TYPE[1] ? ASCII.AUTHORIZATION : ASCII.AUTHORIZATION_V2;
  return Buffer.concat([Buffer.from(prefix, "ascii"), Buffer.from([0]), encoded]);
}

async function buildWrapInfo(input) {
  const map = safeMap(input);
  const exact = [
    "suite", "compartment_id", "epoch", "purpose", "object_id", "version_id",
    "key_ref", "recipient_key_id", "wrap_id",
  ];
  safeMap(map, exact, exact);
  resolveSuite(map.suite, SUITE_VERSION);
  const scope = {
    compartment_id: bytes(map.compartment_id, "INVALID_COMPARTMENT_ID", undefined, 1, 128),
    epoch: uint(map.epoch, MAX_U64),
    purpose: text(map.purpose),
    object_id: bytes(map.object_id, "INVALID_OBJECT_ID", undefined, 1, 128),
    version_id: bytes(map.version_id, "INVALID_VERSION_ID", undefined, 1, 128),
    key_ref: bytes(map.key_ref, "INVALID_KEY_REF", undefined, 1, 128),
  };
  if (!PURPOSES.includes(scope.purpose)) fail("INVALID_PURPOSE");
  return Buffer.concat([
    Buffer.from(ASCII.KEY_WRAP, "ascii"),
    Buffer.from([0]),
    await encodeDeterministic({
      suite: SUITE_ID,
      compartment_id: scope.compartment_id,
      epoch: scope.epoch,
      purpose: scope.purpose,
      object_id: scope.object_id,
      version_id: scope.version_id,
      key_ref: scope.key_ref,
      recipient_key_id: bytes(map.recipient_key_id, "INVALID_RECIPIENT_KEY_ID", undefined, 1, 128),
      wrap_id: bytes(map.wrap_id, "INVALID_WRAP_ID", 16, 16, 16),
    }),
  ]);
}

function hkdfSha256(input) {
  const ikm = bytes(input.ikm, "INVALID_HKDF_IKM");
  const salt = bytes(input.salt === undefined ? Buffer.alloc(0) : input.salt, "INVALID_HKDF_SALT");
  const info = bytes(input.info, "INVALID_HKDF_INFO");
  if (!Number.isSafeInteger(input.length) || input.length < 1 || input.length > 8160) {
    fail("INVALID_HKDF_LENGTH");
  }
  try {
    return Buffer.from(crypto.hkdfSync("sha256", ikm, salt, info, input.length));
  } catch (_) {
    fail("HKDF_FAILED", SECURITY_CLASS.ENVIRONMENT);
  }
}

async function deriveWrapKey(input) {
  const cer = bytes(input.cer, "INVALID_CER", 32, 32, 32);
  const info = await buildWrapInfo({
    suite: input.suite,
    compartment_id: input.compartment_id,
    epoch: input.epoch,
    purpose: input.purpose,
    object_id: input.object_id,
    version_id: input.version_id,
    key_ref: input.key_ref,
    recipient_key_id: input.recipient_key_id,
    wrap_id: input.wrap_id,
  });
  return hkdfSha256({ ikm: cer, salt: Buffer.alloc(0), info, length: 32 });
}

function aesGcmSeal(input) {
  const key = bytes(input.key, "INVALID_AES_KEY", 32, 32, 32);
  const nonce = bytes(input.nonce, "INVALID_AES_NONCE", 12, 12, 12);
  const aad = bytes(input.aad, "INVALID_AAD");
  const plaintext = bytes(input.plaintext, "INVALID_PLAINTEXT");
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    return { ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]), tag: cipher.getAuthTag() };
  } catch (_) {
    fail("ENCRYPTION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

function aesGcmOpen(input) {
  const key = bytes(input.key, "INVALID_AES_KEY", 32, 32, 32);
  const nonce = bytes(input.nonce, "INVALID_AES_NONCE", 12, 12, 12);
  const aad = bytes(input.aad, "INVALID_AAD");
  const ciphertext = bytes(input.ciphertext, "INVALID_CIPHERTEXT");
  const tag = bytes(input.tag, "INVALID_TAG", 16, 16, 16);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (_) {
    fail("AUTHENTICATION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

async function wrapKey(input) {
  const plaintext = bytes(input.plaintext, "INVALID_CONTENT_KEY", 32, 32, 32);
  const key = await deriveWrapKey(input);
  const nonce = crypto.randomBytes(12);
  try {
    const sealed = aesGcmSeal({ key, nonce, aad: bytes(input.aad, "INVALID_AAD"), plaintext });
    return Buffer.concat([nonce, sealed.ciphertext, sealed.tag]);
  } finally {
    clearSecret(key);
  }
}

async function unwrapKey(input) {
  const wrapped = bytes(input.wrapped, "INVALID_WRAPPED_KEY", 60, 60, 60);
  const key = await deriveWrapKey(input);
  try {
    return aesGcmOpen({
      key,
      nonce: wrapped.subarray(0, 12),
      ciphertext: wrapped.subarray(12, 44),
      tag: wrapped.subarray(44),
      aad: bytes(input.aad, "INVALID_AAD"),
    });
  } finally {
    clearSecret(key);
  }
}

function hpkeSuite() {
  return new CipherSuite({
    kem: new DhkemX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes256Gcm(),
  });
}

async function hpkeSeal(input) {
  const info = bytes(input.info, "INVALID_HPKE_INFO");
  const aad = bytes(input.aad, "INVALID_AAD");
  const plaintext = bytes(input.plaintext, "INVALID_PLAINTEXT");
  if (!input.recipientPublicKey) fail("INVALID_RECIPIENT_KEY");
  try {
    const sender = await hpkeSuite().createSenderContext({ recipientPublicKey: input.recipientPublicKey, info });
    return { enc: Buffer.from(sender.enc), ciphertext: Buffer.from(await sender.seal(plaintext, aad)) };
  } catch (_) {
    fail("HPKE_SEAL_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

async function hpkeOpen(input) {
  const info = bytes(input.info, "INVALID_HPKE_INFO");
  const aad = bytes(input.aad, "INVALID_AAD");
  const enc = bytes(input.enc, "INVALID_HPKE_ENC", 32, 32, 32);
  const ciphertext = bytes(input.ciphertext, "INVALID_CIPHERTEXT");
  if (!input.recipientKey) fail("INVALID_RECIPIENT_KEY");
  try {
    const recipient = await hpkeSuite().createRecipientContext({ recipientKey: input.recipientKey, enc, info });
    return Buffer.from(await recipient.open(ciphertext, aad));
  } catch (_) {
    fail("AUTHENTICATION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest();
}

function authorizationAadV2Input(core, digest) {
  return {
    profile: PROFILE.AAD_V2,
    suite: SUITE_ID,
    envelope_version: 2,
    compartment_id: core.compartment_id,
    epoch: core.epoch,
    purpose: core.purpose,
    object_id: core.object_id,
    version_id: core.version_id,
    key_ref: core.key_ref,
    wrap_id: core.wrap_id,
    manifest_core_digest: digest,
  };
}

async function sealAuthorizationEnvelopeV2(input) {
  if (!input?.recipientPublicKey || !input?.signingKey) fail("INVALID_AUTHORIZATION_KEY");
  const core = manifestStaticV2(input.static_core);
  const plaintext = bytes(input.plaintext, "INVALID_PLAINTEXT");
  const wrappedKey = bytes(input.wrapped_key, "INVALID_WRAPPED_KEY", 60, 60, 60);
  const contentCiphertext = bytes(input.ciphertext, "INVALID_CIPHERTEXT");
  const info = await buildAuthorizationHpkeInfoV2Bytes({ profile: PROFILE.HPKE_INFO_V2, ...core });
  const hpkeInfoDigest = sha256(info);

  let sender;
  try {
    sender = await hpkeSuite().createSenderContext({ recipientPublicKey: input.recipientPublicKey, info });
  } catch (_) {
    fail("HPKE_SEAL_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }

  const hpkeEnc = bytes(Buffer.from(sender.enc), "INVALID_HPKE_ENC", 32, 32, 32);
  const manifestCoreMap = await manifestCore({ ...core, hpke_enc: hpkeEnc });
  const manifestCoreDigest = sha256(await encodeDeterministic(manifestCoreMap));
  const aad = await buildAadBytes(authorizationAadV2Input(manifestCoreMap, manifestCoreDigest));
  let hpkeCiphertext;
  try {
    hpkeCiphertext = Buffer.from(await sender.seal(plaintext, aad));
  } catch (_) {
    fail("HPKE_SEAL_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }

  const manifest = await buildManifestMap({
    ...manifestCoreMap,
    hpke_info_digest: hpkeInfoDigest,
    wrapped_key_digest: sha256(wrappedKey),
    ciphertext_digest: sha256(contentCiphertext),
  });
  const signature = await signAuthorization(manifest, input.signingKey);
  return { manifest, signature, info, aad, hpke_ciphertext: hpkeCiphertext };
}

async function openAuthorizationEnvelopeV2(input) {
  if (!input || typeof input !== "object") fail("INVALID_AUTHORIZATION_INPUT");
  const manifest = await buildManifestMap(input.manifest);
  if (manifest.envelope_version !== 2) fail("UNSUPPORTED_ENVELOPE_VERSION");
  if (!input?.recipientKey || !input?.senderPublicKey) fail("INVALID_AUTHORIZATION_KEY");
  const { hpke_info_digest: _infoDigest, wrapped_key_digest: _wrappedKeyDigest, ciphertext_digest: _ciphertextDigest, ...core } = manifest;
  const staticCore = manifestStaticV2(Object.fromEntries(Object.entries(core).filter(([key]) => key !== "hpke_enc")));
  const info = await buildAuthorizationHpkeInfoV2Bytes({ profile: PROFILE.HPKE_INFO_V2, ...staticCore });
  const manifestCoreDigest = sha256(await buildManifestCoreBytes(core));
  const aad = await buildAadBytes(authorizationAadV2Input(core, manifestCoreDigest));
  const wrappedKey = bytes(input.wrapped_key, "INVALID_WRAPPED_KEY", 60, 60, 60);
  const contentCiphertext = bytes(input.ciphertext, "INVALID_CIPHERTEXT");
  const expected = {
    ...(input.expected || {}),
    hpke_info_digest: sha256(info),
    wrapped_key_digest: sha256(wrappedKey),
    ciphertext_digest: sha256(contentCiphertext),
  };
  const normalized = await verifyAuthorizationCore(manifest, input.signature, input.senderPublicKey, {
    ...expected,
    now: input.now,
    claimReplay: input.claimReplay,
  }, false);
  const plaintext = await hpkeOpen({
    recipientKey: input.recipientKey,
    enc: manifest.hpke_enc,
    ciphertext: bytes(input.hpke_ciphertext, "INVALID_CIPHERTEXT"),
    info,
    aad,
  });
  let claimed;
  try {
    claimed = await input.claimReplay(normalized);
  } catch (_) {
    clearSecret(plaintext);
    fail("REPLAY_CHECK_FAILED", SECURITY_CLASS.ENVIRONMENT);
  }
  if (claimed !== true) {
    clearSecret(plaintext);
    fail("REPLAY_DETECTED", SECURITY_CLASS.AUTHENTICATION);
  }
  return plaintext;
}

function signAuthorization(manifest, privateKey) {
  if (!privateKey) fail("INVALID_SIGNING_KEY");
  return buildAuthorizationSignatureInput(manifest).then((input) => {
    try {
      return crypto.sign(null, input, privateKey);
    } catch (_) {
      fail("SIGNATURE_FAILED", SECURITY_CLASS.AUTHENTICATION);
    }
  });
}

async function verifyAuthorization(manifest, signature, publicKey, expected = {}) {
  await verifyAuthorizationCore(manifest, signature, publicKey, expected, true);
  return true;
}

async function verifyAuthorizationCore(manifest, signature, publicKey, expected = {}, consumeReplay) {
  const sig = bytes(signature, "INVALID_SIGNATURE", 64, 64, 64);
  if (!publicKey) fail("INVALID_VERIFYING_KEY");
  const expectedMap = safeMap(expected);
  const normalized = await buildManifestMap(manifest);
  const checkExpected = (fields, source, normalizeIntegers = false) => {
    for (const field of fields) {
      if (Object.hasOwn(expectedMap, field)) {
        const actual = source[field];
        let same;
        if (isBytes(actual) && isBytes(expectedMap[field])) {
          same = Buffer.from(actual).equals(Buffer.from(expectedMap[field]));
        } else if (normalizeIntegers && (field === "epoch" || field === "expiry")) {
          try {
            same = uint(actual, field === "expiry" ? MAX_I63 : MAX_U64) === uint(expectedMap[field], field === "expiry" ? MAX_I63 : MAX_U64);
          } catch (_) {
            same = false;
          }
        } else {
          same = actual === expectedMap[field];
        }
        if (!same) fail("SCOPE_MISMATCH", SECURITY_CLASS.SCOPE);
      }
    }
  };
  if (normalized.envelope_version === 1) checkExpected(V1_EXPECTED_FIELDS, manifest);
  let valid;
  try {
    valid = crypto.verify(null, await buildAuthorizationSignatureInput(normalized), publicKey, sig);
    if (!valid) fail("AUTHENTICATION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  } catch (error) {
    if (error instanceof RootarkZkError) throw error;
    fail("SIGNATURE_VERIFY_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
  if (normalized.envelope_version === 2) {
    if (V2_EXPECTED_SCOPE.some((field) => !Object.hasOwn(expectedMap, field))) {
      fail("EXPECTED_SCOPE_REQUIRED", SECURITY_CLASS.SCOPE);
    }
    checkExpected(V2_EXPECTED_FIELDS, normalized, true);
    if (consumeReplay) fail("V2_ENVELOPE_OPEN_REQUIRED");
    if (!Number.isSafeInteger(expectedMap.now) || typeof expectedMap.claimReplay !== "function") {
      fail("REPLAY_STATE_REQUIRED", SECURITY_CLASS.ENVIRONMENT);
    }
    const now = uint(expectedMap.now, MAX_I63, "INVALID_CURRENT_TIME");
    if (normalized.expiry <= now) fail("AUTHORIZATION_EXPIRED", SECURITY_CLASS.AUTHENTICATION);
    if (consumeReplay) {
      let claimed;
      try {
        claimed = await expectedMap.claimReplay(normalized);
      } catch (_) {
        fail("REPLAY_CHECK_FAILED", SECURITY_CLASS.ENVIRONMENT);
      }
      if (claimed !== true) fail("REPLAY_DETECTED", SECURITY_CLASS.AUTHENTICATION);
    }
  }
  return normalized;
}

async function deriveRecoveryKey(input) {
  const password = typeof input.password === "string" ? Buffer.from(input.password, "utf8") : bytes(input.password, "INVALID_PASSWORD");
  const salt = bytes(input.salt, "INVALID_RECOVERY_SALT", 16, 16, 16);
  if (!Number.isSafeInteger(input.opslimit) || input.opslimit < 1 || !Number.isSafeInteger(input.memlimit) || input.memlimit < 8192) {
    fail("INVALID_ARGON2_LIMITS");
  }
  try {
    await sodium.ready;
    return Buffer.from(sodium.crypto_pwhash(32, password, salt, input.opslimit, input.memlimit, sodium.crypto_pwhash_ALG_ARGON2ID13));
  } catch (_) {
    fail("ARGON2_FAILED", SECURITY_CLASS.ENVIRONMENT);
  } finally {
    clearSecret(password);
  }
}

function newWrapId() {
  return crypto.randomBytes(16);
}

function newRecoverySalt() {
  return crypto.randomBytes(16);
}

/**
 * Best-effort clearing for caller-owned mutable bytes. JavaScript copies,
 * garbage collection, and libsodium/WASM internal buffers are outside this
 * helper's control; this is not a guaranteed zeroization primitive.
 */
function clearSecret(value) {
  if (isBytes(value)) {
    value.fill(0);
    return true;
  }
  return false;
}

module.exports = {
  SUITE_ID,
  SUITE_VERSION,
  KEM_ID,
  KDF_ID,
  AEAD_ID,
  ASCII,
  PROFILE,
  PURPOSES,
  SUITE_STATES,
  SUITE_REGISTRY,
  SECURITY_CLASS,
  RootarkZkError,
  resolveSuite,
  encodeDeterministic,
  decodeDeterministic,
  buildManifestCoreMap,
  buildManifestCoreBytes,
  buildManifestCoreDigest,
  buildManifestMap,
  buildManifestBytes,
  buildAadMap,
  buildAadBytes,
  buildHpkeInfoMap,
  buildHpkeInfoBytes,
  buildHpkeInfoDigest,
  buildAuthorizationHpkeInfoV2Map,
  buildAuthorizationHpkeInfoV2Bytes,
  buildAuthorizationSignatureInput,
  buildWrapInfo,
  hkdfSha256,
  deriveWrapKey,
  aesGcmSeal,
  aesGcmOpen,
  wrapKey,
  unwrapKey,
  hpkeSuite,
  hpkeSeal,
  hpkeOpen,
  sealAuthorizationEnvelopeV2,
  openAuthorizationEnvelopeV2,
  signAuthorization,
  verifyAuthorization,
  deriveRecoveryKey,
  newWrapId,
  newRecoverySalt,
  clearSecret,
};
