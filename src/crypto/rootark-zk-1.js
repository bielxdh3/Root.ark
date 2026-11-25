"use strict";

const crypto = require("node:crypto");
// The canonical codec must not reread these mutable exported helpers after a
// caller-owned KeyObject getter has already run in the same Node realm.
const CODEC_BUFFER_FROM = Buffer.from.bind(Buffer);
const CODEC_IS_BUFFER = Buffer.isBuffer.bind(Buffer);
const CODEC_TIMING_SAFE_EQUAL = crypto.timingSafeEqual.bind(crypto);
const CODEC_OBJECT_KEYS = Object.keys.bind(Object);
const CODEC_OBJECT_HAS_OWN = Object.hasOwn.bind(Object);
const CODEC_OBJECT_GET_PROTOTYPE = Object.getPrototypeOf.bind(Object);
const CODEC_OBJECT_SET_PROTOTYPE = Object.setPrototypeOf.bind(Object);
const CODEC_OBJECT_DESCRIPTOR = Object.getOwnPropertyDescriptor.bind(Object);
const CODEC_OBJECT_CREATE = Object.create.bind(Object);
const CODEC_OBJECT_DEFINE_PROPERTY = Object.defineProperty.bind(Object);
const CODEC_ARRAY_IS_ARRAY = Array.isArray.bind(Array);
const CODEC_PLAIN_OBJECT_PROTOTYPE = Object.prototype;
// The cycle guard executes before the signed-map copy: KeyObject.type can
// replace Set.prototype.has and temporarily turn unsigned B into signed A.
// Keep this guard on load-time native references, without a late .call lookup.
const CODEC_SET = Set;
const CODEC_SET_HAS = Set.prototype.has;
const CODEC_SET_ADD = Set.prototype.add;
const CODEC_SET_DELETE = Set.prototype.delete;
const CODEC_APPLY = Reflect.apply.bind(Reflect);
const CODEC_DECODED_ARRAYS = new WeakSet();
const CODEC_WEAKSET_HAS = WeakSet.prototype.has;
const CODEC_WEAKSET_ADD = WeakSet.prototype.add;
const CODEC_PROMISE = Promise;
const { types: { isProxy: CODEC_IS_PROXY, isPromise: CODEC_IS_PROMISE } } = require("node:util");
function codecNativePromise(value) {
  if (CODEC_IS_PROXY(value) || !CODEC_IS_PROMISE(value)) {
    throw new TypeError("non-native codec Promise");
  }
  CODEC_OBJECT_DEFINE_PROPERTY(value, "constructor", {
    value: CODEC_PROMISE, configurable: false, writable: false,
  });
  return value;
}

function codecNonThenableResult(value) {
  // Node's async PromiseResolve assimilates returned Buffers, arrays and maps
  // through inherited Object.prototype.then BEFORE the caller can pin its
  // Promise. An untrusted native KeyObject getter may install that inherited
  // method after real signature validation. Prevent this at the codec result.
  if (value !== null && typeof value === "object") {
    if (!CODEC_ARRAY_IS_ARRAY(value) && !isBytes(value)) {
      // Canonical decoded maps are consumed by exact() validators that count
      // Reflect.ownKeys. Adding even a nonenumerable own "then" here corrupts
      // the signed field set and makes genuine persisted ledgers unreadable.
      // A null prototype preserves *all* signed DATA fields while excluding
      // any hostile Object.prototype.then from async PromiseResolve.
      const prototype = CODEC_OBJECT_GET_PROTOTYPE(value);
      if (prototype !== null && prototype !== CODEC_PLAIN_OBJECT_PROTOTYPE) {
        fail("UNSUPPORTED_CBOR_VALUE");
      }
      const present = CODEC_OBJECT_DESCRIPTOR(value, "then");
      if (present && (!CODEC_OBJECT_HAS_OWN(present, "value")
        || typeof present.value === "function")) fail("UNSUPPORTED_CBOR_VALUE");
      if (prototype !== null) CODEC_OBJECT_SET_PROTOTYPE(value, null);
      return value;
    }
    const ownThen = CODEC_OBJECT_DESCRIPTOR(value, "then");
    if (ownThen) {
      if (!CODEC_OBJECT_HAS_OWN(ownThen, "value")
        || typeof ownThen.value === "function") fail("UNSUPPORTED_CBOR_VALUE");
    } else {
      CODEC_OBJECT_DEFINE_PROPERTY(value, "then", { value: undefined,
        enumerable: false, writable: false, configurable: false });
    }
    if (CODEC_ARRAY_IS_ARRAY(value)) {
      CODEC_APPLY(CODEC_WEAKSET_ADD, CODEC_DECODED_ARRAYS, [value]);
    }
  }
  return value;
}
const path = require("node:path");
const { pathToFileURL } = require("node:url");
const { types: nodeUtilTypes } = require("node:util");
const { CipherSuite, HkdfSha256, Aes256Gcm } = require("@hpke/core");
const { DhkemX25519HkdfSha256 } = require("@hpke/dhkem-x25519");
const sodium = require("libsodium-wrappers-sumo");

// Deterministic authorization encoding can run after an untrusted sync
// transport/readback callback. Pin the byte, object and equality primitives
// used by its validation/encoding path before that callback can poison globals.
const NativeBuffer = Buffer;
const NativeUint8Array = Uint8Array;
const NativeArray = Array;
const NativeSet = Set;
const NativePromise = Promise;
const NativeObjectPrototype = Object.prototype;
const nativeIsProxy = nodeUtilTypes.isProxy;
const nativeIsUint8Array = nodeUtilTypes.isUint8Array;
const nativeBufferFrom = NativeBuffer.from.bind(NativeBuffer);
const nativeBufferFromProperty = NativeBuffer.from;
const nativeBufferIsBufferProperty = NativeBuffer.isBuffer;
const nativeBufferConcatProperty = NativeBuffer.concat;
const nativeBufferAllocProperty = NativeBuffer.alloc;
const nativeBufferByteLength = NativeBuffer.byteLength.bind(NativeBuffer);
const nativeBufferAlloc = NativeBuffer.alloc.bind(NativeBuffer);
const nativeTypedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(NativeUint8Array.prototype), "byteLength").get;
const nativeUint8ArraySet = NativeUint8Array.prototype.set;
const nativeBufferConcat = NativeBuffer.concat.bind(NativeBuffer);
const nativeBufferIsBuffer = NativeBuffer.isBuffer.bind(NativeBuffer);
const nativeBufferEquals = NativeBuffer.prototype.equals;
const nativeBufferSubarray = NativeBuffer.prototype.subarray;
const nativeBufferToString = NativeBuffer.prototype.toString;
const nativeBufferFill = NativeBuffer.prototype.fill;
const nativeUint8ArrayFill = NativeUint8Array.prototype.fill;
const nativeArrayIsArray = Array.isArray;
const nativeArrayValues = Array.prototype.values;
const nativeSymbolIterator = Symbol.iterator;
const nativeArrayIncludes = Array.prototype.includes;
const nativeArrayPush = Array.prototype.push;
const nativeStringSplit = String.prototype.split;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeNumberIsInteger = Number.isInteger;
const nativeBigInt = BigInt;
const nativeObjectGetPrototypeOf = Object.getPrototypeOf;
const nativeObjectKeys = Object.keys;
const nativeObjectHasOwn = Object.hasOwn;
const nativeObjectCreate = Object.create;
const nativeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeObjectDefineProperty = Object.defineProperty;
const nativeObjectSetPrototypeOf = Object.setPrototypeOf;
const nativeObjectFreeze = Object.freeze;
const nativeReflectOwnKeys = Reflect.ownKeys;
const nativeSetHas = NativeSet.prototype.has;
const nativeSetAdd = NativeSet.prototype.add;
const nativeSetDelete = NativeSet.prototype.delete;
const nativeReflectApply = Reflect.apply;
const nativePromiseThen = Promise.prototype.then;
const nativePromiseCatch = Promise.prototype.catch;
const nativePromiseResolve = Promise.resolve.bind(Promise);
const nativeArrayIteratorPrototype = nativeObjectGetPrototypeOf(
  nativeReflectApply(nativeArrayValues, [], []),
);
const nativeArrayIteratorNext = nativeObjectGetOwnPropertyDescriptor(
  nativeArrayIteratorPrototype, "next",
).value;
const nativeCryptoTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeCryptoCreateHash = crypto.createHash.bind(crypto);
const nativeCryptoSign = crypto.sign.bind(crypto);
const nativeCryptoVerify = crypto.verify.bind(crypto);
const nativeCryptoHkdfSync = crypto.hkdfSync.bind(crypto);
const nativeCryptoRandomBytes = crypto.randomBytes.bind(crypto);
const nativeCryptoCreateCipheriv = crypto.createCipheriv.bind(crypto);
const nativeCryptoCreateDecipheriv = crypto.createDecipheriv.bind(crypto);
const nativeHashUpdate = crypto.Hash.prototype.update;
const nativeHashDigest = crypto.Hash.prototype.digest;
const nativeSodiumReady = sodium.ready;
const nativeSodiumPrimitivesPromise = nativeReflectApply(nativePromiseThen, nativeSodiumReady, [() => {
  const cryptoPwhash = sodium.crypto_pwhash;
  if (typeof cryptoPwhash !== "function" || nativeIsProxy(cryptoPwhash)) return null;
  return {
    cryptoPwhash: (...args) => nativeReflectApply(cryptoPwhash, sodium, args),
    algorithm: sodium.crypto_pwhash_ALG_ARGON2ID13,
  };
}, () => null]);
const nativeCipherProbe = nativeCryptoCreateCipheriv(
  "aes-256-gcm", nativeBufferAlloc(32), nativeBufferAlloc(12), { authTagLength: 16 },
);
const nativeCipherPrototype = nativeObjectGetPrototypeOf(nativeCipherProbe);
const nativeCipherSetAAD = nativeCipherPrototype.setAAD;
const nativeCipherUpdate = nativeCipherPrototype.update;
const nativeCipherFinal = nativeCipherPrototype.final;
const nativeCipherGetAuthTag = nativeCipherPrototype.getAuthTag;
nativeReflectApply(nativeCipherFinal, nativeCipherProbe, []);
const nativeDecipherProbe = nativeCryptoCreateDecipheriv(
  "aes-256-gcm", nativeBufferAlloc(32), nativeBufferAlloc(12), { authTagLength: 16 },
);
const nativeDecipherPrototype = nativeObjectGetPrototypeOf(nativeDecipherProbe);
const nativeDecipherSetAAD = nativeDecipherPrototype.setAAD;
const nativeDecipherSetAuthTag = nativeDecipherPrototype.setAuthTag;
const nativeDecipherUpdate = nativeDecipherPrototype.update;
const nativeDecipherFinal = nativeDecipherPrototype.final;

const SUITE_ID = "rootark-zk-1";
const SUITE_VERSION = 1;
const KEM_ID = 0x0020;
const KDF_ID = 0x0001;
const AEAD_ID = 0x0002;
const MAX_U64 = 0xffffffffffffffffn;
const MAX_I63 = 0x7fffffffffffffffn;
const ASCII = nativeObjectFreeze({
  HPKE_INFO: "Root.ark/zk-1/hpke-info/v1",
  HPKE_INFO_V2: "Root.ark/zk-1/hpke-info/v2",
  KEY_WRAP: "Root.ark/zk-1/key-wrap/v1",
  AUTHORIZATION: "Root.ark/zk-1/authorization-manifest/v1",
  AUTHORIZATION_V2: "Root.ark/zk-1/authorization-manifest/v2",
});
const PROFILE = nativeObjectFreeze({
  ROOT: "rootark-zk-1",
  AAD: "rootark-zk-1/aad/v1",
  AAD_V2: "rootark-zk-1/aad/v2",
  HPKE_INFO: "rootark-zk-1/hpke-info/v1",
  HPKE_INFO_V2: "rootark-zk-1/hpke-info/v2",
});
const MANIFEST_TYPE = nativeObjectFreeze({
  1: "rootark-authorization-manifest-v1",
  2: "rootark-authorization-manifest-v2",
});
const V2_EXPECTED_SCOPE = nativeObjectFreeze([
  "sender_key_id", "recipient_key_id", "compartment_id", "object_id", "version_id",
  "key_ref", "purpose", "epoch", "wrap_id",
]);
const V1_EXPECTED_FIELDS = nativeObjectFreeze([
  "sender_key_id", "recipient_key_id", "compartment_id", "object_id", "version_id",
  "purpose", "epoch", "expiry", "replay_id", "idempotency_key", "wrap_id", "hpke_enc",
  "hpke_info_digest", "wrapped_key_digest", "ciphertext_digest",
]);
const V2_EXPECTED_FIELDS = [];
for (let index = 0; index < V1_EXPECTED_FIELDS.length; index += 1) {
  nativeReflectApply(nativeArrayPush, V2_EXPECTED_FIELDS, [V1_EXPECTED_FIELDS[index]]);
}
const V2_EXTRA_FIELDS = ["type", "suite", "envelope_version", "key_ref"];
for (let index = 0; index < V2_EXTRA_FIELDS.length; index += 1) {
  nativeReflectApply(nativeArrayPush, V2_EXPECTED_FIELDS, [V2_EXTRA_FIELDS[index]]);
}
nativeObjectFreeze(V2_EXPECTED_FIELDS);
const PURPOSES = nativeObjectFreeze([
  "content",
  "derived-data",
  "key-wrap",
  "recovery-package",
  "authorization",
]);
const SUITE_STATES = nativeObjectFreeze({
  ALLOWED: "allowed",
  DEPRECATED: "deprecated",
  REJECTED: "rejected",
});
const SUITE_REGISTRY = nativeObjectFreeze({
  [SUITE_ID]: nativeObjectFreeze({
    version: SUITE_VERSION,
    state: SUITE_STATES.ALLOWED,
    read: "allowed",
    write: "allowed",
    kem: KEM_ID,
    kdf: KDF_ID,
    aead: AEAD_ID,
  }),
});
const SECURITY_CLASS = nativeObjectFreeze({
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

function ownDataValue(value, key) {
  if (!value || (typeof value !== "object" && typeof value !== "function") || nativeIsProxy(value)) {
    return undefined;
  }
  const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
  return descriptor && nativeObjectHasOwn(descriptor, "value") ? descriptor.value : undefined;
}

function isBytes(value) {
  return !nativeIsProxy(value) && (nativeBufferIsBuffer(value) || nativeIsUint8Array(value));
}

function bytes(value, code = "INVALID_BYTES", exact, min, max) {
  if (!isBytes(value)) fail(code);
  const result = nativeBufferFrom(value);
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
  else if (nativeNumberIsSafeInteger(value)) result = nativeBigInt(value);
  else fail(code);
  if (result < 0n || result > max) fail(code);
  return result;
}

function plainObject(value) {
  if (value === null || typeof value !== "object" || nativeArrayIsArray(value)
    || nativeIsProxy(value) || isBytes(value)) {
    fail("AMBIGUOUS_MAP");
  }
  const proto = nativeObjectGetPrototypeOf(value);
  if (proto !== NativeObjectPrototype && proto !== null) fail("AMBIGUOUS_MAP");
  return value;
}

function safeMap(value, required, exact) {
  const source = plainObject(value);
  const keys = nativeObjectKeys(source);
  const ownKeys = nativeReflectOwnKeys(source);
  if (ownKeys.length !== keys.length) fail("CBOR maps cannot contain symbols or hidden properties", "AMBIGUOUS_MAP");
  const map = nativeObjectCreate(null);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === "__proto__" || key === "constructor" || key === "prototype") fail("INVALID_MAP_KEY");
    const descriptor = nativeObjectGetOwnPropertyDescriptor(source, key);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      fail("AMBIGUOUS_MAP");
    }
    const item = descriptor.value;
    map[key] = isBytes(item) ? nativeBufferFrom(item) : item;
  }
  if (exact) {
    if (keys.length !== exact.length) fail("UNKNOWN_REQUIRED_FIELD");
    for (let index = 0; index < exact.length; index += 1) {
      if (!nativeObjectHasOwn(map, exact[index])) fail("UNKNOWN_REQUIRED_FIELD");
    }
  }
  if (required) {
    for (let index = 0; index < required.length; index += 1) {
      if (!nativeObjectHasOwn(map, required[index])) fail("MISSING_REQUIRED_FIELD");
    }
  }
  return map;
}

function validateCborValue(value, seen = new NativeSet(), budget = { nodes: 0 }, depth = 1) {
  // The decoder's output is untrusted too. Apply the same finite traversal
  // budget before canonical re-encoding, even if the decoder returns aliases.
  if (depth > CBOR_SNAPSHOT_MAX_DEPTH || ++budget.nodes > CBOR_SNAPSHOT_MAX_NODES) {
    fail("CBOR_VALUE_TOO_LARGE");
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") return;
  if (typeof value === "number") {
    if (!nativeNumberIsSafeInteger(value) || value < 0) fail("UNSUPPORTED_CBOR_VALUE");
    return;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > MAX_U64) fail("UNSUPPORTED_CBOR_VALUE");
    return value;
  }
  if (isBytes(value)) return;
  if (typeof value !== "object" || nativeReflectApply(nativeSetHas, seen, [value])) fail("UNSUPPORTED_CBOR_VALUE");
  nativeReflectApply(nativeSetAdd, seen, [value]);
  if (nativeArrayIsArray(value)) {
    if (nativeIsProxy(value)) fail("UNSUPPORTED_CBOR_VALUE");
    const prototype = nativeObjectGetPrototypeOf(value);
    if (prototype !== NativeArray.prototype && prototype !== null) {
      fail("UNSUPPORTED_CBOR_VALUE");
    }
    const length = value.length;
    const keys = nativeObjectKeys(value);
    const ownKeys = nativeReflectOwnKeys(value);
    const iterator = nativeObjectGetOwnPropertyDescriptor(value, nativeSymbolIterator);
    const pinnedIterator = prototype === null && iterator
      && nativeObjectHasOwn(iterator, "value") && iterator.value === nativeArrayValues
      && iterator.enumerable === false && iterator.configurable === false;
    if (keys.length !== length || ownKeys.length !== length + (pinnedIterator ? 2 : 1)) {
      fail("UNSUPPORTED_CBOR_VALUE");
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
        fail("UNSUPPORTED_CBOR_VALUE");
      }
      validateCborValue(descriptor.value, seen, budget, depth + 1);
    }
  } else {
    const map = plainObject(value);
    const keys = nativeObjectKeys(map);
    const ownKeys = nativeReflectOwnKeys(map);
    if (ownKeys.length !== keys.length) fail("UNSUPPORTED_CBOR_VALUE");
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (key === "__proto__" || key === "constructor" || key === "prototype") fail("INVALID_MAP_KEY");
      const descriptor = nativeObjectGetOwnPropertyDescriptor(map, key);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
        fail("UNSUPPORTED_CBOR_VALUE");
      }
      validateCborValue(descriptor.value, seen, budget, depth + 1);
    }
  }
  nativeReflectApply(nativeSetDelete, seen, [value]);
}

// Authorization encoding must snapshot before its first await. Shared but
// acyclic CBOR maps are legal; cloning an aliased binary DAG without a budget
// otherwise expands a few input objects into exponentially many copies.
// The supported maximum keyring manifest contains 256 devices x 64 epochs
// (16,384 wraps), which needs about 118k snapshot nodes. Keep that supported
// shape below a finite bound while retaining the independent 64 MiB byte and
// 64-level depth limits against oversized or adversarial CBOR values.
const CBOR_SNAPSHOT_MAX_NODES = 131072;
const CBOR_SNAPSHOT_MAX_DEPTH = 64;
const CBOR_SNAPSHOT_MAX_BYTES = 64 * 1024 * 1024;

function snapshotCborValue(value, seen = new NativeSet(), budget = { nodes: 0, bytes: 0 }, depth = 1, internalCopy = false) {
  if (depth > CBOR_SNAPSHOT_MAX_DEPTH || ++budget.nodes > CBOR_SNAPSHOT_MAX_NODES) {
    fail("CBOR_VALUE_TOO_LARGE");
  }
  // Nine bytes conservatively cover CBOR type/length overhead and u64 values.
  budget.bytes += 9;
  if (budget.bytes > CBOR_SNAPSHOT_MAX_BYTES) fail("CBOR_VALUE_TOO_LARGE");
  if (typeof value === "string") {
    if (value.length > CBOR_SNAPSHOT_MAX_BYTES - budget.bytes) fail("CBOR_VALUE_TOO_LARGE");
    budget.bytes += nativeBufferByteLength(value, "utf8");
    if (budget.bytes > CBOR_SNAPSHOT_MAX_BYTES) fail("CBOR_VALUE_TOO_LARGE");
    return value;
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!nativeNumberIsSafeInteger(value) || value < 0) fail("UNSUPPORTED_CBOR_VALUE");
    return value;
  }
  if (typeof value === "bigint") {
    if (value < 0n || value > MAX_U64) fail("UNSUPPORTED_CBOR_VALUE");
    return value;
  }
  if (isBytes(value)) {
    // Buffer.byteLength(typedArray) consults the public byteLength property,
    // which an untrusted caller can shadow with an own property of zero.
    // Read the actual byte view's internal slot via the captured native getter
    // and copy via the captured native set (not spoofable length/iterator).
    const length = nativeReflectApply(nativeTypedArrayByteLength, value, []);
    if (length > CBOR_SNAPSHOT_MAX_BYTES - budget.bytes) fail("CBOR_VALUE_TOO_LARGE");
    budget.bytes += length;
    const detachedBytes = nativeBufferAlloc(length);
    nativeReflectApply(nativeUint8ArraySet, detachedBytes, [value]);
    return detachedBytes;
  }
  if (typeof value !== "object" || nativeReflectApply(nativeSetHas, seen, [value])) fail("UNSUPPORTED_CBOR_VALUE");
  nativeReflectApply(nativeSetAdd, seen, [value]);
  let snapshot;
  if (nativeArrayIsArray(value)) {
    if (nativeIsProxy(value)) fail("UNSUPPORTED_CBOR_VALUE");
    const prototype = nativeObjectGetPrototypeOf(value);
    if (prototype !== NativeArray.prototype && prototype !== null) {
      fail("UNSUPPORTED_CBOR_VALUE");
    }
    const length = value.length;
    if (length > CBOR_SNAPSHOT_MAX_NODES - budget.nodes) fail("CBOR_VALUE_TOO_LARGE");
    const keys = nativeObjectKeys(value);
    const ownKeys = nativeReflectOwnKeys(value);
    const iterator = internalCopy && prototype === null
      ? nativeObjectGetOwnPropertyDescriptor(value, nativeSymbolIterator) : undefined;
    const internalIterator = iterator && nativeObjectHasOwn(iterator, "value")
      && iterator.value === nativeArrayValues && iterator.enumerable === false
      && iterator.writable === false && iterator.configurable === false;
    const then = CODEC_APPLY(CODEC_WEAKSET_HAS, CODEC_DECODED_ARRAYS, [value])
      ? nativeObjectGetOwnPropertyDescriptor(value, "then") : undefined;
    const decodedMarker = then && nativeObjectHasOwn(then, "value")
      && then.value === undefined && then.enumerable === false
      && then.writable === false && then.configurable === false;
    if (keys.length !== length || ownKeys.length !== length + 1
      + (internalIterator ? 1 : 0) + (decodedMarker ? 1 : 0)) {
      fail("UNSUPPORTED_CBOR_VALUE");
    }
    snapshot = new NativeArray(length);
    for (let index = 0; index < length; index += 1) {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
        fail("UNSUPPORTED_CBOR_VALUE");
      }
      snapshot[index] = snapshotCborValue(descriptor.value, seen, budget, depth + 1, internalCopy);
    }
    // cborg uses for..of. A null-prototype snapshot with its OWN captured
    // native iterator prevents Array.prototype[Symbol.iterator] from swapping
    // validated elements during the asynchronous dynamic import.
    nativeObjectSetPrototypeOf(snapshot, null);
    nativeObjectDefineProperty(snapshot, nativeSymbolIterator, {
      value: nativeArrayValues, enumerable: false, writable: false, configurable: false,
    });
    nativeObjectFreeze(snapshot);
  } else {
    const source = plainObject(value);
    const keys = nativeObjectKeys(source);
    if (keys.length > CBOR_SNAPSHOT_MAX_NODES - budget.nodes) fail("CBOR_VALUE_TOO_LARGE");
    const ownKeys = nativeReflectOwnKeys(source);
    if (ownKeys.length !== keys.length) fail("UNSUPPORTED_CBOR_VALUE");
    snapshot = nativeObjectCreate(null);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (key === "__proto__" || key === "constructor" || key === "prototype") fail("INVALID_MAP_KEY");
      if (key.length > CBOR_SNAPSHOT_MAX_BYTES - budget.bytes) fail("CBOR_VALUE_TOO_LARGE");
      budget.bytes += 9 + nativeBufferByteLength(key, "utf8");
      if (budget.bytes > CBOR_SNAPSHOT_MAX_BYTES) fail("CBOR_VALUE_TOO_LARGE");
      const descriptor = nativeObjectGetOwnPropertyDescriptor(source, key);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
        fail("UNSUPPORTED_CBOR_VALUE");
      }
      snapshot[key] = snapshotCborValue(descriptor.value, seen, budget, depth + 1, internalCopy);
    }
    nativeObjectFreeze(snapshot);
  }
  nativeReflectApply(nativeSetDelete, seen, [value]);
  return snapshot;
}

function sameCborValue(a, b) {
  if (isBytes(a)) return isBytes(b) && a.length === b.length
    && CODEC_TIMING_SAFE_EQUAL(a, b);
  if (typeof a === "bigint" && typeof b === "number") {
    return Number.isSafeInteger(b) && BigInt(b) === a;
  }
  if (typeof b === "bigint" && typeof a === "number") {
    return Number.isSafeInteger(a) && a === Number(b);
  }
  if (a === null || typeof a !== "object") return a === b;
  if (b === null || typeof b !== "object" || CODEC_ARRAY_IS_ARRAY(a) !== CODEC_ARRAY_IS_ARRAY(b)) {
    return false;
  }
  if (CODEC_ARRAY_IS_ARRAY(a) && a.length !== b.length) return false;
  const keysA = CODEC_OBJECT_KEYS(a);
  const keysB = CODEC_OBJECT_KEYS(b);
  if (keysA.length !== keysB.length) return false;
  for (let index = 0; index < keysA.length; index += 1) {
    const key = keysA[index];
    // Canonical CBOR reorders map keys, so compare by own key and value.
    if (!CODEC_OBJECT_HAS_OWN(b, key)) return false;
    const left = CODEC_OBJECT_DESCRIPTOR(a, key);
    const right = CODEC_OBJECT_DESCRIPTOR(b, key);
    if (!left || !right || !CODEC_OBJECT_HAS_OWN(left, "value")
      || !CODEC_OBJECT_HAS_OWN(right, "value") || !sameCborValue(left.value, right.value)) return false;
  }
  return true;
}

let cborgPromise;
function cborg() {
  if (!cborgPromise) {
    const imported = import("cborg");
    const withFallback = nativeReflectApply(nativePromiseCatch, imported, [(error) => {
    const nodePath = process.env.NODE_PATH;
    const entries = typeof nodePath === "string"
      ? nativeReflectApply(nativeStringSplit, nodePath, [path.delimiter]) : [];
    let searchPath = null;
    for (let index = 0; index < entries.length; index += 1) {
      if (entries[index]) { searchPath = entries[index]; break; }
    }
    if (!searchPath) throw error;
    return import(pathToFileURL(path.join(searchPath, "cborg", "cborg.js")).href);
    }]);
    cborgPromise = nativeReflectApply(nativePromiseThen, withFallback, [(module) => {
    if (!module || typeof module !== "object" || nativeIsProxy(module)) fail("CBOR_API_UNAVAILABLE");
    const defaultApi = ownDataValue(module, "default");
    const api = defaultApi && typeof defaultApi === "object" ? defaultApi : module;
    if (nativeIsProxy(api)) fail("CBOR_API_UNAVAILABLE");
    const encode = ownDataValue(api, "encode");
    const decode = ownDataValue(api, "decode");
    if (typeof encode !== "function" || typeof decode !== "function"
      || nativeIsProxy(encode) || nativeIsProxy(decode)) fail("CBOR_API_UNAVAILABLE");
    const options = safeMap(ownDataValue(api, "rfc8949EncodeOptions") || {});
    options.ignoreUndefinedProperties = false;
    nativeObjectFreeze(options);
    return nativeObjectFreeze({
      encode,
      decode,
      rfc8949EncodeOptions: options,
    });
    }]);
  }
  return cborgPromise;
}

function invokeWithPinnedBytePrimitives(method, args) {
  // cborg and Node's native one-shot crypto glue consult global Buffer
  // methods synchronously even with detached inputs. Pin them only during
  // that synchronous trusted call, restoring the prior descriptors on exit.
  const slots = [
    // cborg dispatches on Number.isSafeInteger inside its synchronous
    // RFC 8949 encoder; a readback callback must not change this decision.
    [Number, "isSafeInteger", nativeNumberIsSafeInteger],
    // A snapshot's own Array.prototype.values iterator still inherits its
    // mutable `next` method from %ArrayIteratorPrototype%. Pin that method
    // across cborg's synchronous walk after the asynchronous module import.
    [nativeArrayIteratorPrototype, "next", nativeArrayIteratorNext],
    [NativeBuffer, "isBuffer", nativeBufferIsBufferProperty],
    [NativeBuffer, "from", nativeBufferFromProperty],
    [NativeBuffer, "concat", nativeBufferConcatProperty],
    [NativeBuffer, "alloc", nativeBufferAllocProperty],
    [NativeBuffer.prototype, "subarray", nativeBufferSubarray],
    [NativeBuffer.prototype, "fill", nativeBufferFill],
    [NativeBuffer.prototype, "toString", nativeBufferToString],
  ];
  const previous = new NativeArray(slots.length);
  for (let index = 0; index < slots.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(slots[index][0], slots[index][1]);
    if (!descriptor || descriptor.configurable !== true || !nativeObjectHasOwn(descriptor, "value")) {
      fail("CBOR_API_UNAVAILABLE");
    }
    previous[index] = descriptor;
  }
  try {
    for (let index = 0; index < slots.length; index += 1) {
      nativeObjectDefineProperty(slots[index][0], slots[index][1], {
        ...previous[index], value: slots[index][2],
      });
    }
    return nativeReflectApply(method, undefined, args);
  } finally {
    for (let index = slots.length - 1; index >= 0; index -= 1) {
      nativeObjectDefineProperty(slots[index][0], slots[index][1], previous[index]);
    }
  }
}

async function encodeDeterministicInternal(value) {
  const expected = snapshotCborValue(value);
  const isolated = snapshotCborValue(expected, new NativeSet(), { nodes: 0, bytes: 0 }, 1, true);
  validateCborValue(expected);
  try {
    const api = await codecNativePromise(cborg());
    const encoded = nativeBufferFrom(invokeWithPinnedBytePrimitives(
      api.encode, [isolated, api.rfc8949EncodeOptions]));
    const roundtrip = invokeWithPinnedBytePrimitives(api.decode, [encoded, {
      strict: true, allowIndefinite: false, allowUndefined: false,
      allowInfinity: false, allowNaN: false, allowBigInt: true, rejectDuplicateMapKeys: true,
    }]);
    validateCborValue(roundtrip);
    if (!sameCborValue(expected, roundtrip)) fail("CBOR_ENCODE_FAILED");
    return codecNonThenableResult(encoded);
  } catch (_) {
    fail("CBOR_ENCODE_FAILED");
  }
}

function inspectDecoded(value) {
  validateCborValue(value);
}

async function decodeDeterministicInternal(input) {
  const encoded = bytes(input);
  try {
    const api = await codecNativePromise(cborg());
    const value = invokeWithPinnedBytePrimitives(api.decode, [encoded, {
      strict: true,
      allowIndefinite: false,
      allowUndefined: false,
      allowInfinity: false,
      allowNaN: false,
      allowBigInt: true,
      rejectDuplicateMapKeys: true,
    }]);
    inspectDecoded(value);
    const canonical = await codecNativePromise(encodeDeterministic(value));
    if (encoded.length !== canonical.length ||
        !CODEC_TIMING_SAFE_EQUAL(encoded, canonical)) fail("NON_CANONICAL_ENCODING");
    return codecNonThenableResult(value);
  } catch (error) {
    if (ownDataValue(error, "name") === "RootarkZkError") throw error;
    fail("CBOR_DECODE_FAILED");
  }
}

// The caller's await is also a trust boundary: never expose an async return
// whose inherited Promise constructor/then can be replaced after a key getter.
function encodeDeterministic(value) {
  return codecNativePromise(encodeDeterministicInternal(value));
}
function decodeDeterministic(input) {
  return codecNativePromise(decodeDeterministicInternal(input));
}
function resolveSuite(suite = SUITE_ID, version = SUITE_VERSION) {
  if (suite !== SUITE_ID) fail("UNKNOWN_SUITE");
  if (version !== SUITE_VERSION) fail("UNSUPPORTED_SUITE_VERSION");
  if (SUITE_REGISTRY[SUITE_ID].state !== SUITE_STATES.ALLOWED) fail("SUITE_NOT_ALLOWED");
  return SUITE_REGISTRY[SUITE_ID];
}

function profile(input) {
  const map = safeMap(input);
  if (!nativeNumberIsInteger(map.envelope_version) || map.envelope_version < 0 || map.envelope_version > 0xffff) {
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
  if (!nativeReflectApply(nativeArrayIncludes, PURPOSES, [result.purpose])) fail("INVALID_PURPOSE");
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
  return sha256(await buildManifestCoreBytes(input));
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
  return nativeBufferConcat([nativeBufferFrom(prefix, "ascii"), nativeBufferFrom([0]), await encodeDeterministic(infoMap)]);
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
  if (map.envelope_version !== 1) fail("INVALID_PROFILE");
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
  return nativeBufferConcat([
    nativeBufferFrom(ASCII.HPKE_INFO_V2, "ascii"),
    nativeBufferFrom([0]),
    await encodeDeterministic(infoMap),
  ]);
}

async function buildHpkeInfoDigest(input) {
  return sha256(await buildHpkeInfoBytes(input));
}

async function buildManifestMap(input) {
  const map = safeMap(input);
  const coreKeys = [
    "type", "suite", "envelope_version", "compartment_id", "epoch", "purpose",
    "sender_key_id", "recipient_key_id", "object_id", "version_id", "key_ref",
    "expiry", "replay_id", "idempotency_key", "wrap_id", "hpke_enc",
  ];
  const exact = new NativeArray(coreKeys.length + 3);
  for (let index = 0; index < coreKeys.length; index += 1) exact[index] = coreKeys[index];
  exact[coreKeys.length] = "hpke_info_digest";
  exact[coreKeys.length + 1] = "wrapped_key_digest";
  exact[coreKeys.length + 2] = "ciphertext_digest";
  safeMap(map, exact, exact);
  const coreInput = nativeObjectCreate(null);
  for (let index = 0; index < coreKeys.length; index += 1) {
    const key = coreKeys[index];
    coreInput[key] = map[key];
  }
  const core = await manifestCore(coreInput);
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
  const snapshot = snapshotCborValue(manifest);
  const encoded = await buildManifestBytes(snapshot);
  const type = (await buildManifestMap(snapshot)).type;
  const prefix = type === MANIFEST_TYPE[1] ? ASCII.AUTHORIZATION : ASCII.AUTHORIZATION_V2;
  return nativeBufferConcat([nativeBufferFrom(prefix, "ascii"), nativeBufferFrom([0]), encoded]);
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
  if (!nativeReflectApply(nativeArrayIncludes, PURPOSES, [scope.purpose])) fail("INVALID_PURPOSE");
  return nativeBufferConcat([
    nativeBufferFrom(ASCII.KEY_WRAP, "ascii"),
    nativeBufferFrom([0]),
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
  const inputMap = safeMap(input);
  const ikm = bytes(inputMap.ikm, "INVALID_HKDF_IKM");
  const salt = bytes(inputMap.salt === undefined ? nativeBufferAlloc(0) : inputMap.salt, "INVALID_HKDF_SALT");
  const info = bytes(inputMap.info, "INVALID_HKDF_INFO");
  if (!nativeNumberIsSafeInteger(inputMap.length) || inputMap.length < 1 || inputMap.length > 8160) {
    fail("INVALID_HKDF_LENGTH");
  }
  try {
    return nativeBufferFrom(nativeCryptoHkdfSync("sha256", ikm, salt, info, inputMap.length));
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
  return hkdfSha256({ ikm: cer, salt: nativeBufferAlloc(0), info, length: 32 });
}

function aesGcmSeal(input) {
  const inputMap = safeMap(input);
  const key = bytes(inputMap.key, "INVALID_AES_KEY", 32, 32, 32);
  const nonce = bytes(inputMap.nonce, "INVALID_AES_NONCE", 12, 12, 12);
  const aad = bytes(inputMap.aad, "INVALID_AAD");
  const plaintext = bytes(inputMap.plaintext, "INVALID_PLAINTEXT");
  try {
    const cipher = nativeCryptoCreateCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    nativeReflectApply(nativeCipherSetAAD, cipher, [aad]);
    return {
      ciphertext: nativeBufferConcat([
        nativeReflectApply(nativeCipherUpdate, cipher, [plaintext]),
        nativeReflectApply(nativeCipherFinal, cipher, []),
      ]),
      tag: nativeReflectApply(nativeCipherGetAuthTag, cipher, []),
    };
  } catch (_) {
    fail("ENCRYPTION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

function aesGcmOpen(input) {
  const inputMap = safeMap(input);
  const key = bytes(inputMap.key, "INVALID_AES_KEY", 32, 32, 32);
  const nonce = bytes(inputMap.nonce, "INVALID_AES_NONCE", 12, 12, 12);
  const aad = bytes(inputMap.aad, "INVALID_AAD");
  const ciphertext = bytes(inputMap.ciphertext, "INVALID_CIPHERTEXT");
  const tag = bytes(inputMap.tag, "INVALID_TAG", 16, 16, 16);
  try {
    const decipher = nativeCryptoCreateDecipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
    nativeReflectApply(nativeDecipherSetAAD, decipher, [aad]);
    nativeReflectApply(nativeDecipherSetAuthTag, decipher, [tag]);
    return nativeBufferConcat([
      nativeReflectApply(nativeDecipherUpdate, decipher, [ciphertext]),
      nativeReflectApply(nativeDecipherFinal, decipher, []),
    ]);
  } catch (_) {
    fail("AUTHENTICATION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

async function wrapKey(input) {
  const inputMap = safeMap(input);
  const plaintext = bytes(inputMap.plaintext, "INVALID_CONTENT_KEY", 32, 32, 32);
  const key = await deriveWrapKey(inputMap);
  const nonce = nativeCryptoRandomBytes(12);
  try {
    const sealed = aesGcmSeal({ key, nonce, aad: bytes(inputMap.aad, "INVALID_AAD"), plaintext });
    return nativeBufferConcat([nonce, sealed.ciphertext, sealed.tag]);
  } finally {
    clearSecret(key);
  }
}

async function unwrapKey(input) {
  const inputMap = safeMap(input);
  const wrapped = bytes(inputMap.wrapped, "INVALID_WRAPPED_KEY", 60, 60, 60);
  const key = await deriveWrapKey(inputMap);
  try {
    return aesGcmOpen({
      key,
      nonce: nativeReflectApply(nativeBufferSubarray, wrapped, [0, 12]),
      ciphertext: nativeReflectApply(nativeBufferSubarray, wrapped, [12, 44]),
      tag: nativeReflectApply(nativeBufferSubarray, wrapped, [44]),
      aad: bytes(inputMap.aad, "INVALID_AAD"),
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
  const inputMap = safeMap(input);
  const info = bytes(inputMap.info, "INVALID_HPKE_INFO");
  const aad = bytes(inputMap.aad, "INVALID_AAD");
  const plaintext = bytes(inputMap.plaintext, "INVALID_PLAINTEXT");
  const recipientPublicKey = inputMap.recipientPublicKey;
  if (!recipientPublicKey) fail("INVALID_RECIPIENT_KEY");
  try {
    const sender = await hpkeSuite().createSenderContext({ recipientPublicKey, info });
    return { enc: nativeBufferFrom(sender.enc), ciphertext: nativeBufferFrom(await sender.seal(plaintext, aad)) };
  } catch (_) {
    fail("HPKE_SEAL_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

async function hpkeOpen(input) {
  const inputMap = safeMap(input);
  const info = bytes(inputMap.info, "INVALID_HPKE_INFO");
  const aad = bytes(inputMap.aad, "INVALID_AAD");
  const enc = bytes(inputMap.enc, "INVALID_HPKE_ENC", 32, 32, 32);
  const ciphertext = bytes(inputMap.ciphertext, "INVALID_CIPHERTEXT");
  const recipientKey = inputMap.recipientKey;
  if (!recipientKey) fail("INVALID_RECIPIENT_KEY");
  try {
    const recipient = await hpkeSuite().createRecipientContext({ recipientKey, enc, info });
    return nativeBufferFrom(await recipient.open(ciphertext, aad));
  } catch (_) {
    fail("AUTHENTICATION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
}

function sha256(input) {
  const hash = nativeCryptoCreateHash("sha256");
  nativeReflectApply(nativeHashUpdate, hash, [input]);
  return nativeReflectApply(nativeHashDigest, hash, []);
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
  const inputMap = safeMap(input);
  const recipientPublicKey = inputMap.recipientPublicKey;
  const signingKey = inputMap.signingKey;
  if (!recipientPublicKey || !signingKey) fail("INVALID_AUTHORIZATION_KEY");
  const core = manifestStaticV2(inputMap.static_core);
  const plaintext = bytes(inputMap.plaintext, "INVALID_PLAINTEXT");
  const wrappedKey = bytes(inputMap.wrapped_key, "INVALID_WRAPPED_KEY", 60, 60, 60);
  const contentCiphertext = bytes(inputMap.ciphertext, "INVALID_CIPHERTEXT");
  const info = await buildAuthorizationHpkeInfoV2Bytes({ profile: PROFILE.HPKE_INFO_V2, ...core });
  const hpkeInfoDigest = sha256(info);

  let sender;
  try {
    sender = await hpkeSuite().createSenderContext({ recipientPublicKey, info });
  } catch (_) {
    fail("HPKE_SEAL_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }

  const hpkeEnc = bytes(nativeBufferFrom(sender.enc), "INVALID_HPKE_ENC", 32, 32, 32);
  const manifestCoreMap = await manifestCore({ ...core, hpke_enc: hpkeEnc });
  const manifestCoreDigest = sha256(await encodeDeterministic(manifestCoreMap));
  const aad = await buildAadBytes(authorizationAadV2Input(manifestCoreMap, manifestCoreDigest));
  let hpkeCiphertext;
  try {
    hpkeCiphertext = nativeBufferFrom(await sender.seal(plaintext, aad));
  } catch (_) {
    fail("HPKE_SEAL_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }

  const manifest = await buildManifestMap({
    ...manifestCoreMap,
    hpke_info_digest: hpkeInfoDigest,
    wrapped_key_digest: sha256(wrappedKey),
    ciphertext_digest: sha256(contentCiphertext),
  });
  const signature = await signAuthorization(manifest, signingKey);
  return { manifest, signature, info, aad, hpke_ciphertext: hpkeCiphertext };
}

async function openAuthorizationEnvelopeV2(input) {
  if (input === null || input === undefined) fail("INVALID_AUTHORIZATION_INPUT");
  const inputMap = safeMap(input);
  const manifestInput = snapshotCborValue(inputMap.manifest);
  const signature = bytes(inputMap.signature, "INVALID_SIGNATURE", 64, 64, 64);
  const recipientKey = inputMap.recipientKey;
  const senderPublicKey = inputMap.senderPublicKey;
  const hpkeCiphertext = bytes(inputMap.hpke_ciphertext, "INVALID_CIPHERTEXT");
  const wrappedKey = bytes(inputMap.wrapped_key, "INVALID_WRAPPED_KEY", 60, 60, 60);
  const contentCiphertext = bytes(inputMap.ciphertext, "INVALID_CIPHERTEXT");
  const expectedInput = safeMap(inputMap.expected || {});
  const now = inputMap.now;
  const claimReplay = inputMap.claimReplay;
  const manifest = await buildManifestMap(manifestInput);
  if (manifest.envelope_version !== 2) fail("UNSUPPORTED_ENVELOPE_VERSION");
  if (!recipientKey || !senderPublicKey || typeof claimReplay !== "function") fail("INVALID_AUTHORIZATION_KEY");
  const core = nativeObjectCreate(null);
  const manifestKeys = nativeObjectKeys(manifest);
  for (let index = 0; index < manifestKeys.length; index += 1) {
    const key = manifestKeys[index];
    if (key !== "hpke_info_digest" && key !== "wrapped_key_digest" && key !== "ciphertext_digest") {
      core[key] = manifest[key];
    }
  }
  const staticCore = nativeObjectCreate(null);
  const coreKeys = nativeObjectKeys(core);
  for (let index = 0; index < coreKeys.length; index += 1) {
    const key = coreKeys[index];
    if (key !== "hpke_enc") staticCore[key] = core[key];
  }
  const normalizedStaticCore = manifestStaticV2(staticCore);
  const info = await buildAuthorizationHpkeInfoV2Bytes({ profile: PROFILE.HPKE_INFO_V2, ...normalizedStaticCore });
  const manifestCoreDigest = sha256(await buildManifestCoreBytes(core));
  const aad = await buildAadBytes(authorizationAadV2Input(core, manifestCoreDigest));
  const expected = {
    ...expectedInput,
    hpke_info_digest: sha256(info),
    wrapped_key_digest: sha256(wrappedKey),
    ciphertext_digest: sha256(contentCiphertext),
  };
  const normalized = await verifyAuthorizationCore(manifest, signature, senderPublicKey, {
    ...expected,
    now,
    claimReplay,
  }, false);
  const plaintext = await hpkeOpen({
    recipientKey,
    enc: manifest.hpke_enc,
    ciphertext: hpkeCiphertext,
    info,
    aad,
  });
  let claimed;
  try {
    claimed = await claimReplay(snapshotCborValue(normalized));
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
  return nativeReflectApply(nativePromiseThen, buildAuthorizationSignatureInput(manifest), [(input) => {
    try {
      return invokeWithPinnedBytePrimitives(nativeCryptoSign, [null, input, privateKey]);
    } catch (_) {
      fail("SIGNATURE_FAILED", SECURITY_CLASS.AUTHENTICATION);
    }
  }]);
}

async function verifyAuthorization(manifest, signature, publicKey, expected = {}) {
  await verifyAuthorizationCore(manifest, signature, publicKey, expected, true);
  return true;
}

async function verifyAuthorizationCore(manifest, signature, publicKey, expected = {}, consumeReplay) {
  const sig = bytes(signature, "INVALID_SIGNATURE", 64, 64, 64);
  if (!publicKey) fail("INVALID_VERIFYING_KEY");
  const expectedMap = safeMap(expected);
  const manifestSnapshot = snapshotCborValue(manifest);
  const normalized = await buildManifestMap(manifestSnapshot);
  const checkExpected = (fields, source, normalizeIntegers = false) => {
    for (let index = 0; index < fields.length; index += 1) {
      const field = fields[index];
      if (nativeObjectHasOwn(expectedMap, field)) {
        const actual = source[field];
        let same;
        if (isBytes(actual) && isBytes(expectedMap[field])) {
          same = nativeReflectApply(nativeBufferEquals, nativeBufferFrom(actual),
            [nativeBufferFrom(expectedMap[field])]);
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
  // Compare the detached original v1 scope without rereading caller input;
  // number/bigint encodings of the same epoch remain semantically equivalent.
  if (normalized.envelope_version === 1) checkExpected(V1_EXPECTED_FIELDS, manifestSnapshot, true);
  if (normalized.envelope_version === 2) {
    for (let index = 0; index < V2_EXPECTED_SCOPE.length; index += 1) {
      if (!nativeObjectHasOwn(expectedMap, V2_EXPECTED_SCOPE[index])) {
        fail("EXPECTED_SCOPE_REQUIRED", SECURITY_CLASS.SCOPE);
      }
    }
  }
  let valid;
  try {
    valid = nativeCryptoVerify(null, await buildAuthorizationSignatureInput(normalized), publicKey, sig);
    if (!valid) fail("AUTHENTICATION_FAILED", SECURITY_CLASS.AUTHENTICATION);
  } catch (error) {
    if (ownDataValue(error, "name") === "RootarkZkError") throw error;
    fail("SIGNATURE_VERIFY_FAILED", SECURITY_CLASS.AUTHENTICATION);
  }
  if (normalized.envelope_version === 2) {
    checkExpected(V2_EXPECTED_FIELDS, normalized, true);
    if (consumeReplay) fail("V2_ENVELOPE_OPEN_REQUIRED");
    if (!nativeNumberIsSafeInteger(expectedMap.now) || typeof expectedMap.claimReplay !== "function") {
      fail("REPLAY_STATE_REQUIRED", SECURITY_CLASS.ENVIRONMENT);
    }
    const now = uint(expectedMap.now, MAX_I63, "INVALID_CURRENT_TIME");
    if (normalized.expiry <= now) fail("AUTHORIZATION_EXPIRED", SECURITY_CLASS.AUTHENTICATION);
    if (consumeReplay) {
      let claimed;
      try {
        claimed = await expectedMap.claimReplay(snapshotCborValue(normalized));
      } catch (_) {
        fail("REPLAY_CHECK_FAILED", SECURITY_CLASS.ENVIRONMENT);
      }
      if (claimed !== true) fail("REPLAY_DETECTED", SECURITY_CLASS.AUTHENTICATION);
    }
  }
  return normalized;
}

async function deriveRecoveryKey(input) {
  const inputMap = safeMap(input);
  const password = typeof inputMap.password === "string" ? nativeBufferFrom(inputMap.password, "utf8") : bytes(inputMap.password, "INVALID_PASSWORD");
  const salt = bytes(inputMap.salt, "INVALID_RECOVERY_SALT", 16, 16, 16);
  if (!nativeNumberIsSafeInteger(inputMap.opslimit) || inputMap.opslimit < 1 || !nativeNumberIsSafeInteger(inputMap.memlimit) || inputMap.memlimit < 8192) {
    fail("INVALID_ARGON2_LIMITS");
  }
  try {
    const sodiumPrimitives = await nativeSodiumPrimitivesPromise;
    if (!sodiumPrimitives) fail("SODIUM_PRIMITIVE_UNAVAILABLE");
    return nativeBufferFrom(sodiumPrimitives.cryptoPwhash(
      32, password, salt, inputMap.opslimit, inputMap.memlimit, sodiumPrimitives.algorithm,
    ));
  } catch (_) {
    fail("ARGON2_FAILED", SECURITY_CLASS.ENVIRONMENT);
  } finally {
    clearSecret(password);
  }
}

function newWrapId() {
  return nativeCryptoRandomBytes(16);
}

function newRecoverySalt() {
  return nativeCryptoRandomBytes(16);
}

/**
 * Best-effort clearing for caller-owned mutable bytes. JavaScript copies,
 * garbage collection, and libsodium/WASM internal buffers are outside this
 * helper's control; this is not a guaranteed zeroization primitive.
 */
function clearSecret(value) {
  if (nativeBufferIsBuffer(value)) {
    nativeReflectApply(nativeBufferFill, value, [0]);
    return true;
  }
  if (!nativeIsProxy(value) && nativeIsUint8Array(value)) {
    nativeReflectApply(nativeUint8ArrayFill, value, [0]);
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
