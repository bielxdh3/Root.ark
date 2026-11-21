"use strict";

const crypto = require("node:crypto");
const { types: nodeUtilTypes } = require("node:util");
const { DOS_RESERVED, INTERNAL, INTERNAL_PREFIXES } = require("./rootark-sync-paths");
const { isValidIdempotencyKey, assertAuthorizationEnvelopeBinding } = require("./rootark-sync-authorization");

// Validation can run again after an untrusted transport callback. Pin the
// native byte/nonce/crypto surface before that callback can replace globals.
const NativeBuffer = Buffer;
const NativeArray = Array;
const NativeObjectPrototype = Object.prototype;
const nativeIsProxy = nodeUtilTypes.isProxy;
const nativeIsUint8Array = nodeUtilTypes.isUint8Array;
const nativeBufferFrom = NativeBuffer.from.bind(NativeBuffer);
const nativeBufferAlloc = NativeBuffer.alloc.bind(NativeBuffer);
const nativeBufferIsBuffer = NativeBuffer.isBuffer.bind(NativeBuffer);
const nativeBufferByteLength = NativeBuffer.byteLength.bind(NativeBuffer);
const nativeBufferConcat = NativeBuffer.concat.bind(NativeBuffer);
const nativeBufferToString = NativeBuffer.prototype.toString;
const nativeBufferSubarray = NativeBuffer.prototype.subarray;
const nativeBufferEquals = NativeBuffer.prototype.equals;
const nativeBufferWriteBigUInt64BE = NativeBuffer.prototype.writeBigUInt64BE;
const nativeBufferReadBigUInt64BE = NativeBuffer.prototype.readBigUInt64BE;
const nativeCryptoRandomBytes = crypto.randomBytes.bind(crypto);
const nativeCryptoRandomUUID = crypto.randomUUID.bind(crypto);
const nativeCryptoCreateCipheriv = crypto.createCipheriv.bind(crypto);
const nativeCryptoCreateDecipheriv = crypto.createDecipheriv.bind(crypto);
const nativeCryptoCreateHmac = crypto.createHmac.bind(crypto);
const nativeCryptoTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeCipherSetAAD = crypto.Cipheriv.prototype.setAAD;
const nativeCipherUpdate = crypto.Cipheriv.prototype.update;
const nativeCipherFinal = crypto.Cipheriv.prototype.final;
const nativeCipherGetAuthTag = crypto.Cipheriv.prototype.getAuthTag;
const nativeDecipherSetAAD = crypto.Decipheriv.prototype.setAAD;
const nativeDecipherSetAuthTag = crypto.Decipheriv.prototype.setAuthTag;
const nativeDecipherUpdate = crypto.Decipheriv.prototype.update;
const nativeDecipherFinal = crypto.Decipheriv.prototype.final;
const nativeHmacUpdate = crypto.Hmac.prototype.update;
const nativeHmacDigest = crypto.Hmac.prototype.digest;
const nativeReflectApply = Reflect.apply;
const nativeJsonStringify = JSON.stringify.bind(JSON);
const nativeObjectFreeze = Object.freeze;
const nativeObjectKeys = Object.keys;
const nativeArrayIsArray = Array.isArray;
const nativeArrayIncludes = Array.prototype.includes;
const nativeArrayFilter = Array.prototype.filter;
const nativeArrayPush = Array.prototype.push;
const nativeArraySort = Array.prototype.sort;
const nativeObjectHasOwn = Object.hasOwn;
const nativeObjectAssign = Object.assign;
const nativeObjectCreate = Object.create;
const nativeObjectDefineProperty = Object.defineProperty;
const nativeObjectSetPrototypeOf = Object.setPrototypeOf;
const nativeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeObjectGetPrototypeOf = Object.getPrototypeOf;
const nativeReflectOwnKeys = Reflect.ownKeys;
const nativeRegExpExec = RegExp.prototype.exec;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeNumberIsInteger = Number.isInteger;
const nativeNumberMaxSafeInteger = Number.MAX_SAFE_INTEGER;
const nativeDateNow = Date.now;
const nativeMathMax = Math.max;
const nativeBigInt = BigInt;
const nativeStringSplit = String.prototype.split;
const nativeStringCharCodeAt = String.prototype.charCodeAt;
const nativeStringIncludes = String.prototype.includes;
const nativeStringStartsWith = String.prototype.startsWith;
const nativeStringToLowerCase = String.prototype.toLowerCase;
const nativeStringLocaleCompare = String.prototype.localeCompare;
const nativeSetHas = Set.prototype.has;
const nativeSetAdd = Set.prototype.add;
const nativeSetDelete = Set.prototype.delete;
const nativeSetForEach = Set.prototype.forEach;
const NativeSet = Set;
const NativeMap = Map;
const nativeMapGet = Map.prototype.get;
const nativeMapSet = Map.prototype.set;
const INTERNAL_SEGMENTS = [];
nativeReflectApply(nativeSetForEach, INTERNAL, [(segment) => nativeReflectApply(nativeArrayPush, INTERNAL_SEGMENTS, [segment])]);
nativeObjectFreeze(INTERNAL_SEGMENTS);
const INTERNAL_PREFIXES_SNAPSHOT = [];
for (let index = 0; index < INTERNAL_PREFIXES.length; index += 1) {
  nativeReflectApply(nativeArrayPush, INTERNAL_PREFIXES_SNAPSHOT, [INTERNAL_PREFIXES[index]]);
}
nativeObjectFreeze(INTERNAL_PREFIXES_SNAPSHOT);

function ownDataValue(value, key) {
  if (!value || typeof value !== "object") return undefined;
  const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
  if (descriptor && !nativeObjectHasOwn(descriptor, "value")) fail(`Accessor property is not allowed: ${key}`);
  return descriptor && nativeObjectHasOwn(descriptor, "value") ? descriptor.value : undefined;
}

function assertPlainDataObject(value, name) {
  if (!value || typeof value !== "object" || nativeArrayIsArray(value) || nativeIsProxy(value)) {
    fail(`${name} must be a plain data object`);
  }
  const prototype = nativeObjectGetPrototypeOf(value);
  if (prototype !== NativeObjectPrototype && prototype !== null) fail(`${name} must be a plain data object`);
  const keys = nativeObjectKeys(value);
  if (nativeReflectOwnKeys(value).length !== keys.length) fail(`${name} contains hidden or symbol properties`);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, keys[index]);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      fail(`${name} contains an accessor or hidden property`);
    }
  }
}

function safeBufferFrom(value, name, allowString = false) {
  if (nativeIsProxy(value)) fail(`Invalid ${name}`);
  if (allowString && typeof value === "string") return nativeBufferFrom(value, "utf8");
  if (nativeBufferIsBuffer(value) || nativeIsUint8Array(value)) return nativeBufferFrom(value);
  if (nativeArrayIsArray(value)) {
    if (nativeIsProxy(value) || (nativeObjectGetPrototypeOf(value) !== NativeArray.prototype
      && nativeObjectGetPrototypeOf(value) !== null)
      || nativeObjectKeys(value).length !== value.length
      || nativeReflectOwnKeys(value).length !== value.length + 1) fail(`Invalid ${name}`);
    const copy = new NativeArray(value.length);
    nativeObjectSetPrototypeOf(copy, null);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value")
        || !nativeNumberIsInteger(descriptor.value) || descriptor.value < 0 || descriptor.value > 255) {
        fail(`Invalid ${name}`);
      }
      copy[index] = descriptor.value;
    }
    return nativeBufferFrom(copy);
  }
  fail(`Invalid ${name}`);
}

function regexTest(pattern, value) {
  return nativeReflectApply(nativeRegExpExec, pattern, [value]) !== null;
}

function stringSplit(value, separator, limit) {
  return nativeReflectApply(nativeStringSplit, value,
    limit === undefined ? [separator] : [separator, limit]);
}

function stringIncludes(value, search) {
  return nativeReflectApply(nativeStringIncludes, value, [search]);
}

function stringStartsWith(value, prefix) {
  return nativeReflectApply(nativeStringStartsWith, value, [prefix]);
}

function stringToLowerCase(value) {
  return nativeReflectApply(nativeStringToLowerCase, value, []);
}

function stringLocaleCompare(value, other) {
  return nativeReflectApply(nativeStringLocaleCompare, value, [other]);
}

function isInternalSegment(segment) {
  const normalized = stringToLowerCase(segment);
  if (nativeReflectApply(nativeArrayIncludes, INTERNAL_SEGMENTS, [normalized])) return true;
  for (let index = 0; index < INTERNAL_PREFIXES_SNAPSHOT.length; index += 1) {
    if (stringStartsWith(normalized, INTERNAL_PREFIXES_SNAPSHOT[index])) return true;
  }
  return false;
}

function bufferToString(value, encoding) {
  return nativeReflectApply(nativeBufferToString, value, [encoding]);
}

function bufferSubarray(value, start, end) {
  return nativeReflectApply(nativeBufferSubarray, value,
    end === undefined ? [start] : [start, end]);
}

const PROTOCOL_VERSION = 2;
const MAX_ID_LENGTH = 160;
const MAX_METADATA_BYTES = 16 * 1024;
const MOVE_PAYLOAD_MAGIC = nativeBufferFrom("ROOTARK-SYNC-MOVE\0v1\0", "utf8");
const MOVE_PAYLOAD_LENGTH_BYTES = 8;
const MOVE_PAYLOAD_MAC_BYTES = 32;
const VALID_OPERATIONS = nativeObjectFreeze(["create", "update", "move", "delete"]);
const OPERATIONS = new NativeSet();
for (let index = 0; index < VALID_OPERATIONS.length; index += 1) {
  nativeReflectApply(nativeSetAdd, OPERATIONS, [VALID_OPERATIONS[index]]);
}
const METADATA_KEYS = nativeObjectFreeze([
  "fileId", "versionId", "path", "parentId", "name", "contentType", "size",
  "keyEpoch", "compartmentId", "deviceId", "sourcePath",
]);
const createUpdateMetadataKeys = nativeObjectFreeze(nativeReflectApply(nativeArrayFilter,
  METADATA_KEYS, [(key) => key !== "sourcePath"]));
const METADATA_KEYS_BY_OPERATION = nativeObjectFreeze({
  create: createUpdateMetadataKeys,
  update: createUpdateMetadataKeys,
  move: nativeObjectFreeze(["fileId", "versionId", "path", "sourcePath", "keyEpoch", "compartmentId", "deviceId"]),
  delete: nativeObjectFreeze(["fileId", "versionId", "path", "keyEpoch", "compartmentId", "deviceId"]),
});
const OPERATION_FIELDS = nativeObjectFreeze([
  "protocolVersion", "operationId", "objectId", "fileId", "versionId", "operation",
  "revision", "baseRevision", "keyEpoch", "compartmentId", "deviceId", "metadata",
  "tombstone", "ciphertext", "nonce", "tag", "aad", "authorization",
]);
const OPTIONAL_OPERATION_FIELDS = new NativeSet();
nativeReflectApply(nativeSetAdd, OPTIONAL_OPERATION_FIELDS, ["authorization"]);
const REQUIRED_LEGACY_OPERATION_FIELDS = nativeObjectFreeze(nativeReflectApply(nativeArrayFilter,
  OPERATION_FIELDS, [(field) => field !== "authorization"]));
const AUTHORIZATION_FIELDS = nativeObjectFreeze([
  "schemaVersion", "type", "suite", "protocolVersion", "username", "deviceId", "operationId",
  "objectId", "fileId", "versionId", "operation", "revision", "baseRevision", "keyEpoch",
  "compartmentId", "metadata", "aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest",
  "expiresAt", "replayId", "idempotencyKey", "publicKey", "signature",
]);

function fail(message, code = "invalid_operation") {
  throw nativeObjectAssign(new Error(message), { code });
}

function id(value, name) {
  if (typeof value !== "string" || !value || value.length > MAX_ID_LENGTH
    || !regexTest(/^[A-Za-z0-9._:-]+$/, value)) fail(`Invalid ${name}`);
  return value;
}

function revision(value, name = "revision") {
  assertPlainDataObject(value, name);
  const counter = ownDataValue(value, "counter");
  const deviceId = ownDataValue(value, "deviceId");
  if (!nativeNumberIsSafeInteger(counter) || counter < 0) fail(`Invalid ${name}`);
  return { counter, deviceId: id(deviceId, `${name}.deviceId`) };
}

function compareRevisions(left, right) {
  if (!left && !right) return 0;
  if (!left) return -1;
  if (!right) return 1;
  const leftRevision = revision(left, "left revision");
  const rightRevision = revision(right, "right revision");
  return leftRevision.counter - rightRevision.counter
    || stringLocaleCompare(leftRevision.deviceId, rightRevision.deviceId);
}

// Sync ingress accepts at most 9 MiB of JSON. Keep the generic bound wide
// enough for that payload while capping expanded DAGs before cloning them.
// Operator-provisioned owner credentials are tiny and use a tighter budget.
const CANONICAL_JSON_BUDGET = nativeObjectFreeze({ depth: 64, nodes: 32768, bytes: 64 * 1024 * 1024 });
const OWNER_JSON_BUDGET = nativeObjectFreeze({ depth: 24, nodes: 1024, bytes: 64 * 1024 });

function jsonStringByteLength(value) {
  // Ordinary ciphertext/Base64 contains no JSON escapes. Counting every
  // character as six bytes would reject valid payloads far below the limit.
  if (nativeReflectApply(nativeRegExpExec, /["\\\u0000-\u001f\uD800-\uDFFF]/, [value]) === null) {
    return nativeBufferByteLength(value, "utf8") + 2;
  }
  let bytes = 2; // opening and closing quotes
  for (let index = 0; index < value.length; index += 1) {
    const unit = nativeReflectApply(nativeStringCharCodeAt, value, [index]);
    if (unit === 34 || unit === 92 || unit === 8 || unit === 9 || unit === 10
      || unit === 12 || unit === 13) bytes += 2;
    else if (unit < 32) bytes += 6;
    else if (unit < 128) bytes += 1;
    else if (unit < 2048) bytes += 2;
    else if (unit >= 0xD800 && unit <= 0xDBFF) {
      const next = index + 1 < value.length
        ? nativeReflectApply(nativeStringCharCodeAt, value, [index + 1]) : 0;
      if (next >= 0xDC00 && next <= 0xDFFF) { bytes += 4; index += 1; }
      else bytes += 6;
    } else if (unit >= 0xDC00 && unit <= 0xDFFF) bytes += 6;
    else bytes += 3;
  }
  return bytes;
}

function assertCanonicalJsonBudget(root, budget) {
  const active = new NativeSet();
  const memo = new NativeMap();
  let uniqueNodes = 0;
  const overBudget = () => fail("Canonical JSON expansion exceeds depth, node or byte budget", "payload_too_large");

  function measure(value, depth) {
    if (depth > budget.depth) overBudget();
    if (value === null) return { nodes: 1, bytes: 4, height: 1 };
    if (typeof value === "string") {
      // Even an entirely unescaped JSON string needs at least one output
      // byte per UTF-16 code unit. Reject oversized input before scanning it.
      if (value.length + 2 > budget.bytes) overBudget();
      const bytes = jsonStringByteLength(value);
      if (bytes > budget.bytes) overBudget();
      return { nodes: 1, bytes, height: 1 };
    }
    if (typeof value === "boolean") return { nodes: 1, bytes: 5, height: 1 };
    if (typeof value === "number") {
      // JSON.stringify of a primitive number cannot invoke a user toJSON
      // hook. The old 330-byte estimate per numeric leaf falsely rejected
      // harmless compact numeric arrays under the owner 64-KiB limit.
      return { nodes: 1, bytes: nativeJsonStringify(value).length, height: 1 };
    }
    if (typeof value === "undefined") return { nodes: 1, bytes: 4, height: 1 };
    if (!value || typeof value !== "object" || nativeIsProxy(value)) fail("Invalid JSON value");
    if (nativeReflectApply(nativeSetHas, active, [value])) fail("Cyclic JSON graph is not accepted");
    const cached = nativeReflectApply(nativeMapGet, memo, [value]);
    if (cached) {
      if (depth + cached.height - 1 > budget.depth) overBudget();
      return cached;
    }
    if (++uniqueNodes > budget.nodes) overBudget();
    nativeReflectApply(nativeSetAdd, active, [value]);
    const array = nativeArrayIsArray(value);
    let keys;
    if (array) {
      if ((nativeObjectGetPrototypeOf(value) !== NativeArray.prototype
        && nativeObjectGetPrototypeOf(value) !== null)
        || value.length > budget.nodes
        || nativeObjectKeys(value).length !== value.length
        || nativeReflectOwnKeys(value).length !== value.length + 1) fail("Ambiguous JSON array");
      keys = nativeObjectKeys(value);
    } else {
      assertPlainDataObject(value, "JSON object");
      keys = nativeObjectKeys(value);
    }
    if (keys.length > budget.nodes) overBudget();
    let nodes = 1;
    let bytes = 2;
    let height = 1;
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (!array && key.length + 2 > budget.bytes) overBudget();
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value")
        || descriptor.enumerable !== true) fail("Invalid JSON value");
      const child = measure(descriptor.value, depth + 1);
      nodes += child.nodes;
      // Exact JSON punctuation: one comma only after the first member, plus
      // a colon and escaped key for objects. A spare byte per member would
      // reject otherwise-valid owner certificates at the 64-KiB boundary.
      bytes += child.bytes + (index > 0 ? 1 : 0)
        + (array ? 0 : jsonStringByteLength(key) + 1);
      if (child.height + 1 > height) height = child.height + 1;
      if (nodes > budget.nodes || bytes > budget.bytes || depth + height - 1 > budget.depth) overBudget();
    }
    nativeReflectApply(nativeSetDelete, active, [value]);
    const measured = { nodes, bytes, height };
    nativeReflectApply(nativeMapSet, memo, [value, measured]);
    return measured;
  }
  measure(root, 1);
}

function canonicalize(value) {
  if (typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") {
    fail("Invalid JSON value");
  }
  if (value === null || typeof value !== "object") return value;
  if (nativeIsProxy(value)) fail("Proxy JSON values are not accepted");
  if (nativeArrayIsArray(value)) {
    const arrayPrototype = nativeObjectGetPrototypeOf(value);
    if ((arrayPrototype !== NativeArray.prototype && arrayPrototype !== null)
      || nativeObjectKeys(value).length !== value.length
      || nativeReflectOwnKeys(value).length !== value.length + 1) {
      fail("Ambiguous JSON array");
    }
    const result = new NativeArray(value.length);
    // JSON.stringify consults inherited `toJSON` even when the stringify
    // function itself was captured. Canonical arrays must not inherit a
    // callback-poisonable Array.prototype hook between validation and signing.
    nativeObjectSetPrototypeOf(result, null);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor) fail("Sparse JSON arrays are not accepted");
      if (!nativeObjectHasOwn(descriptor, "value")) fail("Invalid JSON value");
      result[index] = canonicalize(descriptor.value);
    }
    return result;
  }
  assertPlainDataObject(value, "JSON object");
  const keys = nativeObjectKeys(value);
  // A 32k-key object fits the node budget. Insertion sort would still take
  // ~500 million comparisons; use the native sort captured before callbacks.
  nativeReflectApply(nativeArraySort, keys, [(left, right) => left < right ? -1 : left > right ? 1 : 0]);
  const result = nativeObjectCreate(null);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) fail("Invalid JSON value");
    // Define an own data property on the null-prototype result rather than
    // invoking dynamic bracket assignment. Even reserved JSON keys remain
    // inert data properties, never setters or prototype mutation.
    nativeObjectDefineProperty(result, key, {
      value: canonicalize(descriptor.value), enumerable: true,
      writable: true, configurable: true,
    });
  }
  return result;
}

function canonicalJson(value, ownerProvisioning = false) {
  const budget = ownerProvisioning === true ? OWNER_JSON_BUDGET : CANONICAL_JSON_BUDGET;
  assertCanonicalJsonBudget(value, budget);
  const serialized = nativeJsonStringify(canonicalize(value));
  if (typeof serialized === "string" && nativeBufferByteLength(serialized, "utf8") > budget.bytes) {
    fail("Canonical JSON exceeds byte budget", "payload_too_large");
  }
  return serialized;
}

function assertExactKeys(input, allowed, name) {
  assertPlainDataObject(input, name);
  const keys = nativeObjectKeys(input);
  for (let index = 0; index < keys.length; index += 1) {
    if (!nativeReflectApply(nativeArrayIncludes, allowed, [keys[index]])) {
      fail(`Unknown ${name} field: ${keys[index]}`);
    }
  }
}

function safeRelativePath(value, name) {
  if (typeof value !== "string" || !value || value.length > 512
    || stringIncludes(value, "%") || stringIncludes(value, "\\") || stringIncludes(value, ":")
    || stringStartsWith(value, "/") || regexTest(/^[A-Za-z]:/, value)
    || regexTest(/[\u0000-\u001f\u007f]/, value)) fail(`Invalid metadata.${name}`);
  const segments = stringSplit(value, "/");
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (!segment || segment === "." || segment === ".." || isInternalSegment(segment)
      || regexTest(DOS_RESERVED, segment) || regexTest(/[. ]$/, segment)) {
      fail(`Invalid metadata.${name}`);
    }
  }
  return value;
}

function isInternalRelativePath(value) {
  if (typeof value !== "string") return false;
  const segments = stringSplit(value, "/");
  for (let index = 0; index < segments.length; index += 1) {
    if (isInternalSegment(segments[index])) return true;
  }
  return false;
}

function normalizeMetadata(input = {}, allowedKeys = METADATA_KEYS) {
  if (!input || typeof input !== "object" || nativeArrayIsArray(input)) fail("Invalid metadata");
  assertExactKeys(input, allowedKeys, "metadata");
  const result = nativeObjectCreate(null);
  for (let index = 0; index < allowedKeys.length; index += 1) {
    const key = allowedKeys[index];
    const descriptor = nativeObjectGetOwnPropertyDescriptor(input, key);
    if (!descriptor) continue;
    if (!nativeObjectHasOwn(descriptor, "value")) fail("Invalid metadata");
    const value = descriptor.value;
    if (value === undefined || value === null) continue;
    if (key === "size") {
      if (!nativeNumberIsSafeInteger(value) || value < 0) fail("Invalid metadata.size");
      result[key] = value;
    } else if (nativeReflectApply(nativeArrayIncludes, ["path", "sourcePath"], [key])) {
      result[key] = safeRelativePath(value, key);
    } else if (nativeReflectApply(nativeArrayIncludes, ["name", "contentType"], [key])) {
      if (typeof value !== "string" || !value || value.length > 512
        || regexTest(/[\u0000-\u001f\u007f]/, value)) fail(`Invalid metadata.${key}`);
      result[key] = value;
    } else {
      result[key] = id(value, `metadata.${key}`);
    }
  }
  if (nativeBufferByteLength(canonicalJson(result)) > MAX_METADATA_BYTES) fail("Metadata too large", "payload_too_large");
  return canonicalize(result);
}

function assertFileKey(fileKey) {
  const key = safeBufferFrom(fileKey, "file key");
  if (key.length !== 32) fail("A 32-byte per-file key is required");
  return key;
}

function aadFor(operation) {
  assertPlainDataObject(operation, "operation");
  return canonicalJson({
    protocolVersion: PROTOCOL_VERSION,
    objectId: operation.objectId,
    fileId: operation.fileId,
    versionId: operation.versionId,
    operation: operation.operation,
    revision: operation.revision,
    baseRevision: operation.baseRevision || null,
    keyEpoch: operation.keyEpoch,
    compartmentId: operation.compartmentId,
    deviceId: operation.deviceId,
    metadata: operation.metadata,
    tombstone: operation.tombstone,
  });
}

function normalizeAuthorizationShape(value, requireFresh) {
  if (!value || typeof value !== "object" || nativeArrayIsArray(value)) fail("Invalid device authorization");
  assertExactKeys(value, AUTHORIZATION_FIELDS, "authorization");
  const normalized = canonicalize(value);
  for (let index = 0; index < AUTHORIZATION_FIELDS.length; index += 1) {
    if (!nativeObjectHasOwn(normalized, AUTHORIZATION_FIELDS[index])) fail("Invalid device authorization");
  }
  if (normalized.schemaVersion !== 1 || normalized.type !== "rootark-sync-device-authorization-v1" || normalized.suite !== "rootark-zk-1" || normalized.protocolVersion !== PROTOCOL_VERSION) fail("Invalid device authorization");
  if (!nativeNumberIsSafeInteger(normalized.expiresAt) || normalized.expiresAt <= 0
    || (requireFresh && normalized.expiresAt <= nativeDateNow())) fail("Expired device authorization", "authorization_expired");
  const requiredStrings = ["aadDigest", "ciphertextDigest", "nonceDigest", "tagDigest", "replayId", "publicKey", "signature"];
  for (let index = 0; index < requiredStrings.length; index += 1) {
    const field = requiredStrings[index];
    if (typeof normalized[field] !== "string" || !regexTest(/^[A-Za-z0-9_-]+$/, normalized[field]) || normalized[field].length % 4 === 1) fail("Invalid device authorization");
  }
  if (!isValidIdempotencyKey(normalized.idempotencyKey)) fail("Invalid device authorization");
  return normalized;
}

function normalizeAuthorization(value) {
  return normalizeAuthorizationShape(value, true);
}

function encryptPayload(operation, plaintext, fileKey) {
  const key = assertFileKey(fileKey);
  const nonce = nativeCryptoRandomBytes(12);
  const cipher = nativeCryptoCreateCipheriv("aes-256-gcm", key, nonce);
  const aad = nativeBufferFrom(aadFor(operation), "utf8");
  nativeReflectApply(nativeCipherSetAAD, cipher, [aad]);
  const ciphertext = nativeBufferConcat([
    nativeReflectApply(nativeCipherUpdate, cipher, [safeBufferFrom(plaintext, "plaintext", true)]),
    nativeReflectApply(nativeCipherFinal, cipher, []),
  ]);
  return {
    ciphertext: bufferToString(ciphertext, "base64url"),
    nonce: bufferToString(nonce, "base64url"),
    tag: bufferToString(nativeReflectApply(nativeCipherGetAuthTag, cipher, []), "base64url"),
    aad: bufferToString(aad, "base64url"),
  };
}

function decodeBase64Url(value, field) {
  if (typeof value !== "string" || (field !== "ciphertext" && !value) || !regexTest(/^[A-Za-z0-9_-]*$/, value) || value.length % 4 === 1) {
    fail(`Invalid encrypted field: ${field}`, "invalid_envelope");
  }
  const decoded = nativeBufferFrom(value, "base64url");
  if (bufferToString(decoded, "base64url") !== value) fail(`Invalid encrypted field: ${field}`, "invalid_envelope");
  if (field === "nonce" && decoded.length !== 12 || field === "tag" && decoded.length !== 16) {
    fail(`Invalid encrypted field: ${field}`, "invalid_envelope");
  }
  return decoded;
}

function decryptPayload(operation, fileKey) {
  assertPlainDataObject(operation, "operation");
  if (typeof operation.ciphertext !== "string" || !operation.nonce || !operation.tag || !operation.aad) fail("Encrypted payload is incomplete");
  const key = assertFileKey(fileKey);
  const ciphertext = decodeBase64Url(operation.ciphertext, "ciphertext");
  const nonce = decodeBase64Url(operation.nonce, "nonce");
  const tag = decodeBase64Url(operation.tag, "tag");
  const aad = decodeBase64Url(operation.aad, "aad");
  const expectedAad = nativeBufferFrom(aadFor(operation), "utf8");
  if (aad.length !== expectedAad.length || !nativeCryptoTimingSafeEqual(aad, expectedAad)) fail("AAD binding mismatch", "aad_mismatch");
  const decipher = nativeCryptoCreateDecipheriv("aes-256-gcm", key, nonce);
  nativeReflectApply(nativeDecipherSetAAD, decipher, [aad]);
  nativeReflectApply(nativeDecipherSetAuthTag, decipher, [tag]);
  return nativeBufferConcat([
    nativeReflectApply(nativeDecipherUpdate, decipher, [ciphertext]),
    nativeReflectApply(nativeDecipherFinal, decipher, []),
  ]);
}

function encodeMovePayload(plaintext, fileKey) {
  const key = assertFileKey(fileKey);
  const content = safeBufferFrom(plaintext ?? [], "move payload", true);
  const length = nativeBufferAlloc(MOVE_PAYLOAD_LENGTH_BYTES);
  nativeReflectApply(nativeBufferWriteBigUInt64BE, length, [nativeBigInt(content.length)]);
  const header = nativeBufferConcat([MOVE_PAYLOAD_MAGIC, length]);
  const hmac = nativeCryptoCreateHmac("sha256", key);
  nativeReflectApply(nativeHmacUpdate, hmac, [header]);
  nativeReflectApply(nativeHmacUpdate, hmac, [content]);
  const mac = nativeReflectApply(nativeHmacDigest, hmac, []);
  return nativeBufferConcat([header, mac, content]);
}

function decodeMovePayload(plaintext, fileKey) {
  const payload = safeBufferFrom(plaintext ?? [], "move payload", true);
  if (payload.length < MOVE_PAYLOAD_MAGIC.length
    || !nativeReflectApply(nativeBufferEquals,
      bufferSubarray(payload, 0, MOVE_PAYLOAD_MAGIC.length), [MOVE_PAYLOAD_MAGIC])) return null;
  const headerSize = MOVE_PAYLOAD_MAGIC.length + MOVE_PAYLOAD_LENGTH_BYTES;
  const contentOffset = headerSize + MOVE_PAYLOAD_MAC_BYTES;
  if (payload.length < contentOffset) return null;
  const header = bufferSubarray(payload, 0, headerSize);
  const contentLength = nativeReflectApply(nativeBufferReadBigUInt64BE, payload,
    [MOVE_PAYLOAD_MAGIC.length]);
  if (contentLength > nativeBigInt(nativeNumberMaxSafeInteger)
    || nativeBigInt(payload.length - contentOffset) !== contentLength) return null;
  const mac = bufferSubarray(payload, headerSize, contentOffset);
  const content = bufferSubarray(payload, contentOffset);
  const hmac = nativeCryptoCreateHmac("sha256", assertFileKey(fileKey));
  nativeReflectApply(nativeHmacUpdate, hmac, [header]);
  nativeReflectApply(nativeHmacUpdate, hmac, [content]);
  const expectedMac = nativeReflectApply(nativeHmacDigest, hmac, []);
  if (!nativeCryptoTimingSafeEqual(mac, expectedMac)) return null;
  return nativeBufferFrom(content);
}

function createOperation(input = {}) {
  // Encryption must precede signing. An externally provided proof cannot
  // authorize the freshly encrypted bytes from this constructor.
  assertPlainDataObject(input, "operation input");
  if (nativeObjectHasOwn(input, "authorization")) fail("Do not supply authorization to the encryption constructor", "authorization_scope");
  const inputOperation = ownDataValue(input, "operation");
  const operation = inputOperation;
  if (typeof operation !== "string") fail("Invalid sync operation");
  if (!nativeReflectApply(nativeArrayIncludes, VALID_OPERATIONS, [operation])) fail("Invalid sync operation");
  const inputObjectId = ownDataValue(input, "objectId");
  const objectId = id(inputObjectId || nativeCryptoRandomUUID(), "objectId");
  const fileId = id(ownDataValue(input, "fileId") || objectId, "fileId");
  const versionId = id(ownDataValue(input, "versionId") || nativeCryptoRandomUUID(), "versionId");
  const deviceId = id(ownDataValue(input, "deviceId"), "deviceId");
  const keyEpoch = id(ownDataValue(input, "keyEpoch"), "keyEpoch");
  const compartmentId = id(ownDataValue(input, "compartmentId"), "compartmentId");
  const inputBaseRevision = ownDataValue(input, "baseRevision");
  const baseRevision = inputBaseRevision == null ? null : revision(inputBaseRevision, "baseRevision");
  const inputRevision = ownDataValue(input, "revision");
  const inputMetadata = ownDataValue(input, "metadata");
  const metadataSource = inputMetadata == null ? nativeObjectCreate(null) : canonicalize(inputMetadata);
  const metadataInput = nativeObjectAssign(nativeObjectCreate(null), metadataSource);
  metadataInput.fileId = fileId;
  metadataInput.versionId = versionId;
  metadataInput.keyEpoch = keyEpoch;
  metadataInput.compartmentId = compartmentId;
  metadataInput.deviceId = deviceId;
  const result = nativeObjectCreate(null);
  nativeObjectAssign(result, {
    protocolVersion: PROTOCOL_VERSION,
    operationId: id(ownDataValue(input, "operationId") || nativeCryptoRandomUUID(), "operationId"),
    objectId,
    fileId,
    versionId,
    operation,
    revision: revision(inputRevision, "revision"),
    baseRevision,
    keyEpoch,
    compartmentId,
    deviceId,
    metadata: normalizeMetadata(metadataInput, METADATA_KEYS_BY_OPERATION[operation]),
    tombstone: operation === "delete",
  });
  const inputPlaintext = ownDataValue(input, "plaintext");
  const plaintext = inputPlaintext === undefined ? nativeBufferFrom("{}", "utf8") : inputPlaintext;
  nativeObjectAssign(result, encryptPayload(result, plaintext, ownDataValue(input, "fileKey")));
  return result;
}

function validateOperationInternal(input, requireFreshAuthorization, requireSignedAuthorization = false) {
  assertPlainDataObject(input, "operation");
  const source = canonicalize(input);
  if (source.protocolVersion !== PROTOCOL_VERSION) fail("Unsupported sync protocol version", "invalid_protocol_version");
  assertExactKeys(source, OPERATION_FIELDS, "operation");
  // Required fields depend ONLY on the trusted entry point, never on whether
  // an untrusted request elects to send its optional proof. This is the
  // protected-route fail-closed boundary even if a caller skips a precheck.
  const mandatory = requireSignedAuthorization
    ? OPERATION_FIELDS : REQUIRED_LEGACY_OPERATION_FIELDS;
  for (let index = 0; index < mandatory.length; index += 1) {
    const field = mandatory[index];
    if (!nativeObjectHasOwn(source, field)) {
      fail(`Missing operation field: ${field}`,
        requireSignedAuthorization && field === "authorization"
          ? "authorization_required" : "invalid_operation");
    }
  }
  const { authorization: _authorization, ...unsignedInput } = source;
  const operation = createOperation({ ...unsignedInput,
    plaintext: nativeBufferAlloc(0), fileKey: nativeBufferAlloc(32) });
  if (nativeObjectHasOwn(source, "authorization")) {
    operation.authorization = normalizeAuthorizationShape(source.authorization,
      requireFreshAuthorization);
    // Signed fields/digests must match the supplied envelope BEFORE a caller
    // has a chance to treat this normalized operation as signed data.
    // Device signature and revocation are checked separately by the store.
    assertAuthorizationEnvelopeBinding(operation.authorization, { ...operation,
      ciphertext: source.ciphertext, nonce: source.nonce, tag: source.tag, aad: source.aad });
  }
  if (source.tombstone !== operation.tombstone) fail("Invalid tombstone flag");
  if (!operation.metadata.path) fail("Operation metadata.path is required");
  if (operation.operation === "move" && !operation.metadata.sourcePath) fail("Move metadata.sourcePath is required");
  const encryptedFields = ["ciphertext", "nonce", "tag", "aad"];
  for (let index = 0; index < encryptedFields.length; index += 1) {
    const field = encryptedFields[index];
    if (typeof source[field] !== "string" || (field !== "ciphertext" && !source[field])) fail(`Missing encrypted field: ${field}`);
  }
  decodeBase64Url(source.ciphertext, "ciphertext");
  decodeBase64Url(source.nonce, "nonce");
  decodeBase64Url(source.tag, "tag");
  const aad = decodeBase64Url(source.aad, "aad");
  const expectedAad = nativeBufferFrom(aadFor(operation), "utf8");
  if (aad.length !== expectedAad.length || !nativeCryptoTimingSafeEqual(aad, expectedAad)) fail("AAD binding mismatch", "aad_mismatch");
  return { ...operation, ciphertext: source.ciphertext, nonce: source.nonce, tag: source.tag, aad: source.aad };
}

function validateOperation(input) {
  return validateOperationInternal(input, true);
}

// Trusted mode selection belongs to the caller, never the incoming proof's
// presence. This validates shape/digest binding, NOT a signature or device.
function validateFreshSignedOperation(input) {
  return validateOperationInternal(input, true, true);
}

// A persisted record's authorization was checked at ingress. Its historical
// expiry must not make unrelated ciphertext unreadable after a restart.
// This is structural validation only; never use it to admit a new write.
function validateStoredOperation(input) {
  return validateOperationInternal(input, false);
}

function nextRevision(current, deviceId) {
  const device = id(deviceId, "deviceId");
  if (current != null) assertPlainDataObject(current, "current revision");
  const currentCounter = current == null ? 0 : ownDataValue(current, "counter");
  if (!nativeNumberIsSafeInteger(currentCounter) || currentCounter < 0) {
    fail("Invalid current revision", "invalid_revision");
  }
  return { counter: nativeMathMax(0, currentCounter) + 1, deviceId: device };
}

module.exports = {
  OPERATION_FIELDS,
  PROTOCOL_VERSION,
  OPERATIONS,
  METADATA_KEYS,
  canonicalJson,
  compareRevisions,
  createOperation,
  decodeMovePayload,
  decryptPayload,
  encodeMovePayload,
  nextRevision,
  normalizeMetadata,
  normalizeAuthorization,
  safeRelativePath,
  validateOperation,
  validateFreshSignedOperation,
  validateStoredOperation,
  OPTIONAL_OPERATION_FIELDS,
};
