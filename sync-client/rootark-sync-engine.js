"use strict";

const crypto = require("node:crypto");
const { AsyncLocalStorage } = require("node:async_hooks");
const { types: nodeUtilTypes } = require("node:util");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");

// These primitives are captured when the trusted module is loaded. Transport,
// witness and CAS callbacks are untrusted extension points and may mutate the
// shared crypto/Buffer objects while an asynchronous admission is in flight.
const NativeBuffer = Buffer;
const NativeUint8Array = Uint8Array;
const NativeArray = Array;
const NativeJSON = JSON;
const NativeObject = Object;
const NativeObjectPrototype = Object.prototype;
const NativeReflect = Reflect;
const NativeNumber = Number;
const NativeRegExp = RegExp;
const NativeTypeError = TypeError;
const NativePromise = Promise;
const NativeGlobalThis = globalThis;
const nativeIsProxy = nodeUtilTypes.isProxy;
const nativeIsPromise = nodeUtilTypes.isPromise;
const nativeIsUint8Array = nodeUtilTypes.isUint8Array;
const nativeIsKeyObject = nodeUtilTypes.isKeyObject;
const nativeFunctionHasInstance = Function.prototype[Symbol.hasInstance];
const nativeAsyncLocalStorageGetStore = AsyncLocalStorage.prototype.getStore;
const nativeAsyncLocalStorageRun = AsyncLocalStorage.prototype.run;
const nativeBufferFrom = NativeBuffer.from.bind(NativeBuffer);
const nativeBufferAlloc = NativeBuffer.alloc.bind(NativeBuffer);
const nativeBufferByteLength = NativeBuffer.byteLength.bind(NativeBuffer);
const nativeBufferIsBuffer = NativeBuffer.isBuffer.bind(NativeBuffer);
const nativeBufferToString = NativeBuffer.prototype.toString;
const nativeBufferEquals = NativeBuffer.prototype.equals;
const nativeBufferSubarray = NativeBuffer.prototype.subarray;
const nativeBufferFill = NativeBuffer.prototype.fill;
const nativeCreateHash = crypto.createHash.bind(crypto);
const nativeHashUpdate = crypto.Hash.prototype.update;
const nativeHashDigest = crypto.Hash.prototype.digest;
const nativeRandomBytes = crypto.randomBytes.bind(crypto);
const nativeRandomUUID = crypto.randomUUID.bind(crypto);
const nativeVerify = crypto.verify.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeBufferFromProperty = NativeBuffer.from;
const nativeBufferIsBufferProperty = NativeBuffer.isBuffer;
const nativeCryptoVerifyProperty = crypto.verify;
const nativeCryptoCreateHashProperty = crypto.createHash;
const nativeCryptoCreatePublicKeyProperty = crypto.createPublicKey;
const nativeCryptoHashUpdateProperty = crypto.Hash.prototype.update;
const nativeCryptoHashDigestProperty = crypto.Hash.prototype.digest;
const nativeJsonParseProperty = NativeJSON.parse;
const NativeKeyObject = crypto.KeyObject;
// Node 22 exposes export() on PublicKeyObject, not the KeyObject base class.
// Resolve its native method once from a fixed, public RFC 8032 test key.
// This bootstrap key is never used for owner or witness authorization.
const nativePublicKeyObjectPrototype = Object.getPrototypeOf(nativeCreatePublicKey({
  key: nativeBufferFrom("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex"),
  format: "der", type: "spki",
}));
const nativeKeyObjectExport = nativePublicKeyObjectPrototype.export;
const nativeReflectApply = Reflect.apply;
const nativeObjectFreeze = Object.freeze;
const nativeObjectKeys = Object.keys;
const nativeObjectEntries = Object.entries;
const nativeObjectValues = Object.values;
const nativeObjectHasOwn = Object.hasOwn;
const nativeObjectCreate = Object.create;
const nativeObjectDefineProperty = Object.defineProperty;
const nativeObjectGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeObjectGetPrototypeOf = Object.getPrototypeOf;
const nativeObjectSetPrototypeOf = Object.setPrototypeOf;
const nativeReflectOwnKeys = Reflect.ownKeys;
const nativeArrayIsArray = Array.isArray;
const nativeArrayIncludes = Array.prototype.includes;
const nativeArraySort = Array.prototype.sort;
const nativeArraySome = Array.prototype.some;
const nativeArrayEvery = Array.prototype.every;
const nativeArrayPush = Array.prototype.push;
const nativeArrayMap = Array.prototype.map;
const nativeArrayFilter = Array.prototype.filter;
const NativeMap = Map;
const nativeMapGet = Map.prototype.get;
const nativeMapSet = Map.prototype.set;
const nativeMapHas = Map.prototype.has;
const nativeMapDelete = Map.prototype.delete;
const nativeMapValues = Map.prototype.values;
const nativeMapForEach = Map.prototype.forEach;
const NativeSet = Set;
const nativeSetAdd = Set.prototype.add;
const nativeSetHas = Set.prototype.has;
const nativeSetDelete = Set.prototype.delete;
const nativePromiseResolve = Promise.resolve.bind(Promise);
const nativePromiseReject = Promise.reject.bind(Promise);
const nativePromiseThen = Promise.prototype.then;
const nativePromiseCatch = Promise.prototype.catch;
const nativePromiseFinally = Promise.prototype.finally;
const nativeRegExpExec = RegExp.prototype.exec;
const nativeRegExpTest = RegExp.prototype.test;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeNumberIsInteger = Number.isInteger;
const nativeNumberIsFinite = Number.isFinite;
const nativeDateNow = Date.now;
const nativeMathMax = Math.max;
const nativeMathMin = Math.min;
const nativeStringStartsWith = String.prototype.startsWith;
const nativeStringSlice = String.prototype.slice;
const nativeStringSplit = String.prototype.split;
const nativeStringIncludes = String.prototype.includes;
const nativeStringReplace = String.prototype.replace;
const nativeStringLocaleCompare = String.prototype.localeCompare;
const nativeStringToLowerCase = String.prototype.toLowerCase;
const nativeBigIntToString = BigInt.prototype.toString;
const nativeDecodeURIComponent = decodeURIComponent;
const nativeObjectAssign = Object.assign;
const nativeJsonParse = NativeJSON.parse.bind(NativeJSON);
const nativeJsonStringifyDescriptor = nativeObjectGetOwnPropertyDescriptor(NativeJSON, "stringify");

const protocol = require("./rootark-sync-protocol");
const { verifyPinnedAtomicOwnerProvision } = require("./rootark-sync-atomic-owner-provision");
const { validatePortableRelativePath } = require("./rootark-sync-paths");
const { SyncJournal, renameWithRetry, safeJsonStringify } = require("./rootark-sync-journal");
const { SyncConflictError, assertOpaqueEnvelope } = require("../public/client/rootark-sync-adapter");
const canonicalJson = protocol.canonicalJson;

const SNAPSHOT_VERSION = 1;
const INTERNAL_NAMES = nativeObjectFreeze([".rootark-trash", ".rootark-conflicts", ".rootark-sync-journal.json", ".rootark-sync-index.json", ".rootark-sync.lock", ".rootark-webdav-owner.lock"]);
const INTERNAL_NAME_PREFIXES = [".rootark-sync-lock-init-"];
const HISTORICAL_RESTORE_TEMP_SUFFIX = /\.tmp-[1-9][0-9]*-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const ROOT_MUTATION_QUEUES = new NativeMap();
const MAX_EVICTION_ATTEMPTS = 3;
const TRANSIENT_EVICTION_CODES = new NativeSet(["EBUSY", "EPERM", "EAGAIN"]);
const TRANSIENT_REMOTE_CODES = new NativeSet([
  "ECONNREFUSED", "ECONNRESET", "EPIPE", "ENETUNREACH", "EHOSTUNREACH",
  "ETIMEDOUT", "EAI_AGAIN", "offline", "UND_ERR_SOCKET", "UND_ERR_CONNECT_TIMEOUT",
  "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_BODY_TIMEOUT", "UND_ERR_ABORTED",
  "ERR_SOCKET_CLOSED", "ERR_STREAM_PREMATURE_CLOSE", "ERR_HTTP2_STREAM_CANCEL",
]);
const ROOT_MUTATION_CONTEXT = new AsyncLocalStorage();

function createPinnedSha256() {
  const hash = nativeCreateHash("sha256");
  return {
    update(value) {
      nativeReflectApply(nativeHashUpdate, hash, [value]);
      return this;
    },
    digest(encoding) {
      return encoding === undefined
        ? nativeReflectApply(nativeHashDigest, hash, [])
        : nativeReflectApply(nativeHashDigest, hash, [encoding]);
    },
  };
}

function sha256Hex(value) {
  return createPinnedSha256().update(value).digest("hex");
}

function bufferToString(value, encoding) {
  return nativeReflectApply(nativeBufferToString, value, [encoding]);
}

function randomBase64Url(byteLength) {
  return bufferToString(nativeRandomBytes(byteLength), "base64url");
}

function zeroBuffer(value) {
  if (nativeBufferIsBuffer(value)) nativeReflectApply(nativeBufferFill, value, [0]);
}

function deepFreezeJson(value) {
  if (!value || typeof value !== "object") return value;
  const keys = nativeObjectKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, keys[index]);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
      fail("Captured JSON cannot contain accessors", "restore_remote_admission_unproven");
    }
    deepFreezeJson(descriptor.value);
  }
  nativeObjectSetPrototypeOf(value, null);
  return nativeObjectFreeze(value);
}

function captureSignedEnvelope(operation) {
  let canonicalBytes;
  let detached;
  try {
    canonicalBytes = canonicalJson(operation);
    detached = nativeJsonParse(canonicalBytes);
  } catch {
    fail("Historical restore envelope cannot be captured safely",
      "restore_remote_admission_unproven");
  }
  if (!detached || typeof detached !== "object" || nativeArrayIsArray(detached)
    || typeof detached.operationId !== "string"
  ) {
    fail("Signed operation envelope identity is invalid",
      "restore_remote_admission_unproven");
  }
  deepFreezeJson(detached);
  return nativeObjectFreeze({
    operation: detached,
    operationId: detached.operationId,
    canonicalBytes,
    digest: sha256Hex(canonicalBytes),
  });
}

function assertCapturedSignedEnvelope(captured) {
  if (!captured || !captured.operation || typeof captured.operationId !== "string"
    || captured.operation.operationId !== captured.operationId
  ) {
    fail("Signed operation identity changed during admission",
      "restore_remote_admission_unproven");
  }
  let canonical;
  try { canonical = canonicalJson(captured.operation); }
  catch {
    fail("Historical restore envelope cannot be revalidated",
      "restore_remote_admission_unproven");
  }
  if (canonical !== captured.canonicalBytes || sha256Hex(canonical) !== captured.digest) {
    fail("Signed operation envelope changed during admission",
      "restore_remote_admission_unproven");
  }
}

function captureHistoricalRestoreEnvelope(operation, engine) {
  const captured = captureSignedEnvelope(operation);
  if (captured.operation.operation !== "update" || !stringStartsWith(captured.operationId, "histrestore-")) {
    fail("Historical restore envelope identity is invalid", "restore_remote_admission_unproven");
  }
  const journal = ownDataValue(engine, "journal");
  const journalState = ownDataValue(journal, "state");
  const journalPending = ownDataValue(journalState, "pending");
  const adapter = ownDataValue(engine, "adapter");
  const adapterPush = ownDataValue(adapter, "push");
  const adapterValidate = ownDataValue(adapter, "validate");
  if (!journal || !journalState || !nativeArrayIsArray(journalPending)
    || nativeIsProxy(journalPending)
    || typeof adapterPush !== "function") {
    fail("Historical restore pending journal or transport is unavailable",
      "restore_remote_admission_unproven");
  }
  const engineMethods = captureMethodSet(engine, HISTORICAL_ENGINE_METHODS);
  const journalMethods = captureMethodSet(journal, HISTORICAL_JOURNAL_METHODS);
  let pendingIndex = -1;
  let pendingRecord = null;
  for (let index = 0; index < journalPending.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(journalPending, `${index}`);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
      fail("Historical restore journal pending list is ambiguous",
        "restore_remote_admission_unproven");
    }
    const candidate = descriptor.value;
    if (ownDataValue(candidate, "operationId") !== captured.operationId) continue;
    if (pendingRecord || signedEnvelopeDigest(candidate) !== captured.digest) {
      fail("Historical restore journal does not contain the exact signed envelope",
        "restore_remote_admission_unproven");
    }
    pendingIndex = index;
    pendingRecord = candidate;
  }
  if (!pendingRecord) fail("Historical restore is not durably pending",
    "restore_remote_admission_unproven");
  return nativeObjectFreeze({
    ...captured,
    journal,
    journalState,
    journalPending,
    journalPendingIndex: pendingIndex,
    journalPendingRecord: pendingRecord,
    adapter,
    adapterPush,
    adapterValidate,
    engineMethods,
    journalMethods,
    serializedEnvelopeRequired: adapterValidate === assertOpaqueEnvelope,
  });
}

function assertCapturedHistoricalRestoreEnvelope(captured) {
  assertCapturedSignedEnvelope(captured);
  if (captured.operation.operation !== "update" || !stringStartsWith(captured.operationId, "histrestore-")) {
    fail("Historical restore envelope identity changed during admission", "restore_remote_admission_unproven");
  }
}

function assertCapturedHistoricalRestorePending(engine, captured) {
  assertCapturedHistoricalRestoreEnvelope(captured);
  const journal = captured && captured.journal;
  const journalState = ownDataValue(journal, "state");
  const journalPending = ownDataValue(journalState, "pending");
  if (ownDataValue(engine, "journal") !== journal || nativeIsProxy(journalPending)
    || journalState !== captured.journalState
    || journalPending !== captured.journalPending
    || engine.adapter !== captured.adapter
    || ownDataValue(captured.adapter, "push") !== captured.adapterPush
    || ownDataValue(captured.adapter, "validate") !== captured.adapterValidate) {
    fail("The original signed historical restore is no longer the exact pending envelope",
      "restore_remote_admission_unproven");
  }
  // Inspect the pending index only after proving the array is not a Proxy;
  // even getOwnPropertyDescriptor() can execute attacker-controlled traps.
  const pendingDescriptor = journalPending && nativeObjectGetOwnPropertyDescriptor(
    journalPending, `${captured.journalPendingIndex}`);
  assertMethodSet(engine, captured.engineMethods);
  assertMethodSet(journal, captured.journalMethods);
  if (!pendingDescriptor || !nativeObjectHasOwn(pendingDescriptor, "value")
    || pendingDescriptor.value !== captured.journalPendingRecord
    || signedEnvelopeDigest(pendingDescriptor.value) !== captured.digest) {
    fail("The original signed historical restore is no longer the exact pending envelope",
      "restore_remote_admission_unproven");
  }
  let matchingPendingIds = 0;
  for (let index = 0; index < journalPending.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(journalPending, `${index}`);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
      fail("Historical restore journal pending list is ambiguous",
        "restore_remote_admission_unproven");
    }
    if (ownDataValue(descriptor.value, "operationId") === captured.operationId) {
      matchingPendingIds += 1;
      if (index !== captured.journalPendingIndex || descriptor.value !== captured.journalPendingRecord) {
        fail("Historical restore journal contains a substituted operation identity",
          "restore_remote_admission_unproven");
      }
    }
  }
  if (matchingPendingIds !== 1) {
    fail("Historical restore journal operation identity is not unique",
      "restore_remote_admission_unproven");
  }
  assertCapturedHistoricalRestoreEnvelope(captured);
}

function assertHistoricalRestorePhysicalAuthority(engine) {
  if (!engine || !engine.requireAuthorization || !engine.atomicBatchWitnessPublicKey
    || !engine.atomicBatchWitnessReadback || !engine.atomicBatchWitnessScope
    || !engine.atomicBatchOwnerIdentity || !engine.atomicBatchOwnerProvisionerPublicKey
    || !engine.atomicBatchCasFloorPublicKey || !engine.atomicBatchCasFloorReadback) {
    fail("Historical restore requires independently provisioned physical CURRENT authority",
      "restore_remote_admission_unproven");
  }
}

function pushCapturedHistoricalRestore(captured) {
  assertCapturedHistoricalRestoreEnvelope(captured);
  if (!captured || !captured.adapter || typeof captured.adapterPush !== "function"
    || ownDataValue(captured.adapter, "push") !== captured.adapterPush
    || ownDataValue(captured.adapter, "validate") !== captured.adapterValidate) {
    fail("Historical restore transport identity changed before POST",
      "restore_remote_admission_unproven");
  }
  if (NativeGlobalThis.JSON !== NativeJSON || !nativeJsonStringifyDescriptor
    || nativeJsonStringifyDescriptor.configurable !== true) {
    fail("Historical restore transport serializer is not trusted", "restore_remote_admission_unproven");
  }
  const currentDescriptor = nativeObjectGetOwnPropertyDescriptor(NativeJSON, "stringify");
  if (!currentDescriptor || currentDescriptor.configurable !== true) {
    fail("Historical restore transport serializer cannot be fenced", "restore_remote_admission_unproven");
  }
  let serializedEnvelope = false;
  const safeStringify = (value, replacer, space) => {
    if (replacer !== undefined || space !== undefined) {
      fail("Historical restore adapter requested non-canonical JSON serialization", "restore_remote_admission_unproven");
    }
    const canonical = canonicalJson(value);
    if (value && typeof value === "object") {
      const operationId = nativeObjectGetOwnPropertyDescriptor(value, "operationId");
      const operation = nativeObjectGetOwnPropertyDescriptor(value, "operation");
      const ciphertext = nativeObjectGetOwnPropertyDescriptor(value, "ciphertext");
      const authorization = nativeObjectGetOwnPropertyDescriptor(value, "authorization");
      if (operationId && nativeObjectHasOwn(operationId, "value")
        && operation && nativeObjectHasOwn(operation, "value")
        && ciphertext && nativeObjectHasOwn(ciphertext, "value")
        && authorization && nativeObjectHasOwn(authorization, "value")) {
        // A custom adapter cannot serialize a different signed operation B
        // after first serializing A to satisfy a superficial envelope check.
        if (operationId.value !== captured.operationId || operation.value !== "update"
          || canonical !== captured.canonicalBytes || sha256Hex(canonical) !== captured.digest) {
          fail("Historical restore adapter serialized a non-matching signed envelope", "restore_remote_admission_unproven");
        }
        serializedEnvelope = true;
      }
    }
    return canonical;
  };
  const fencedDescriptor = {
    configurable: true,
    enumerable: nativeJsonStringifyDescriptor.enumerable,
    get: () => safeStringify,
  };
  nativeObjectDefineProperty(NativeJSON, "stringify", fencedDescriptor);
  let result;
  let restoreFailure = null;
  try {
    result = nativeReflectApply(captured.adapterPush, captured.adapter, [captured.operation]);
  } finally {
    try {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(NativeJSON, "stringify");
      if (!descriptor || descriptor.configurable === true) {
        if (!descriptor || descriptor.get !== fencedDescriptor.get
          || nativeObjectHasOwn(descriptor, "value")) {
          restoreFailure = new Error("Transport callback replaced the signed-envelope serializer fence");
          restoreFailure.code = "restore_transport_global_tamper";
          restoreFailure.status = 503;
        }
        nativeObjectDefineProperty(NativeJSON, "stringify", nativeJsonStringifyDescriptor);
      } else {
        restoreFailure = new Error("Transport callback made JSON.stringify non-configurable");
        restoreFailure.code = "restore_transport_global_tamper";
        restoreFailure.status = 503;
      }
    } catch {
      restoreFailure = new Error("Transport callback prevented restoration of JSON.stringify");
      restoreFailure.code = "restore_transport_global_tamper";
      restoreFailure.status = 503;
    }
  }
  if (restoreFailure) throw restoreFailure;
  // The production opaque adapter exposes validate/normalize and must cross
  // this exact serializer fence. Test-only/custom in-process adapters may
  // implement their own authenticated transport without JSON serialization.
  if (captured.serializedEnvelopeRequired && !serializedEnvelope) {
    fail("Historical restore adapter did not serialize the captured envelope",
      "restore_remote_admission_unproven");
  }
  return result;
}

function captureHistoricalRestoreAuthority(engine) {
  let scopeCanonical;
  let ownerCanonical;
  let scope;
  let ownerIdentity;
  try {
    scopeCanonical = canonicalJson(engine.atomicBatchWitnessScope);
    ownerCanonical = canonicalJson(engine.atomicBatchOwnerIdentity);
    scope = deepFreezeJson(nativeJsonParse(scopeCanonical));
    ownerIdentity = deepFreezeJson(nativeJsonParse(ownerCanonical));
  } catch {
    fail("Historical restore physical authority configuration is ambiguous",
      "restore_remote_admission_unproven");
  }
  return nativeObjectFreeze({
    scopeSource: engine.atomicBatchWitnessScope,
    ownerIdentitySource: engine.atomicBatchOwnerIdentity,
    witnessPublicKey: engine.atomicBatchWitnessPublicKey,
    witnessReadback: engine.atomicBatchWitnessReadback,
    casFloorPublicKey: engine.atomicBatchCasFloorPublicKey,
    casFloorReadback: engine.atomicBatchCasFloorReadback,
    scopeCanonical,
    ownerCanonical,
    scope,
    ownerIdentity,
  });
}

function assertHistoricalRestoreAuthoritySnapshot(engine, captured) {
  let scopeCanonical;
  let ownerCanonical;
  try {
    scopeCanonical = canonicalJson(engine.atomicBatchWitnessScope);
    ownerCanonical = canonicalJson(engine.atomicBatchOwnerIdentity);
  } catch {
    fail("Historical restore physical authority changed during readback",
      "restore_remote_admission_unproven");
  }
  if (engine.atomicBatchWitnessScope !== captured.scopeSource
    || engine.atomicBatchOwnerIdentity !== captured.ownerIdentitySource
    || engine.atomicBatchWitnessPublicKey !== captured.witnessPublicKey
    || engine.atomicBatchWitnessReadback !== captured.witnessReadback
    || engine.atomicBatchCasFloorPublicKey !== captured.casFloorPublicKey
    || engine.atomicBatchCasFloorReadback !== captured.casFloorReadback
    || scopeCanonical !== captured.scopeCanonical || ownerCanonical !== captured.ownerCanonical) {
    fail("Historical restore physical authority changed during readback",
      "restore_remote_admission_unproven");
  }
}

function signedEnvelopeDigest(operation) {
  return sha256Hex(canonicalJson(operation));
}

function hasExactKeys(value, required) {
  if (!value || typeof value !== "object" || nativeArrayIsArray(value)) return false;
  const actual = nativeObjectKeys(value);
  if (actual.length !== required.length) return false;
  for (let index = 0; index < required.length; index += 1) {
    let found = false;
    for (let cursor = 0; cursor < actual.length; cursor += 1) {
      if (actual[cursor] === required[index]) {
        found = true;
        break;
      }
    }
    if (!found) return false;
  }
  return true;
}

// v2 is intentionally incompatible with v1: a v1 receipt has no immutable
// owner-provisioned account/store namespace and MUST NOT authorize new ACKs.
const ATOMIC_ADMISSION_DOMAIN = "rootark-sync-atomic-batch-witness-v2\0";
const ATOMIC_CAS_FLOOR_DOMAIN = "rootark-sync-atomic-batch-external-cas-floor-v2\0";
// A standalone historical UPDATE has different semantics from the protected
// two-member WebDAV DELETE+MOVE transaction. Never reuse the pair signature
// domain to admit a singleton or accept a server-supplied receipt.
const RESTORE_ADMISSION_DOMAIN = "rootark-sync-historical-restore-physical-witness-v1\0";
const RESTORE_CAS_FLOOR_DOMAIN = "rootark-sync-historical-restore-physical-current-v1\0";
const ATOMIC_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
function pinnedAtomicOwnerIdentity(value) {
  if (value == null) return null;
  // Detach option-owned getters just once. An apparent immutable identity
  // must not be replaced between constructor validation and signed readback.
  let identity;
  try { identity = nativeJsonParse(canonicalJson(value)); }
  catch { fail("Atomic batch owner identity is not canonical JSON", "authorization_required"); }
  const actualKeys = identity && typeof identity === "object" && !nativeArrayIsArray(identity)
    ? nativeObjectKeys(identity) : [];
  const requiredKeys = ["accountId", "storeId", "username", "compartmentId"];
  let exactKeys = actualKeys.length === requiredKeys.length;
  for (let index = 0; exactKeys && index < requiredKeys.length; index += 1) {
    let found = false;
    for (let cursor = 0; cursor < actualKeys.length; cursor += 1) {
      if (actualKeys[cursor] === requiredKeys[index]) { found = true; break; }
    }
    if (!found) exactKeys = false;
  }
  if (!identity || typeof identity !== "object" || nativeArrayIsArray(identity)
    || !exactKeys
    || typeof identity.accountId !== "string" || !regexTest(ATOMIC_UUID, identity.accountId)
    || typeof identity.storeId !== "string" || !regexTest(ATOMIC_UUID, identity.storeId)
    || typeof identity.username !== "string" || !identity.username || identity.username.length > 512
    || typeof identity.compartmentId !== "string"
    || !identity.compartmentId || identity.compartmentId.length > 512) {
    fail("Atomic batch requires immutable externally provisioned account/store identity",
      "authorization_required");
  }
  return deepFreezeJson(identity);
}
function pinnedAtomicWitnessKey(value) {
  if (value == null) return null;
  if (nativeIsProxy(value)) fail("Atomic authority key must not be a proxy", "authorization_required");
  let key;
  if (nativeBufferIsBuffer(value) || nativeIsUint8Array(value)) {
    key = nativeCreatePublicKey({ key: nativeBufferFrom(value), format: "der", type: "spki" });
  } else if (typeof value === "string" && regexTest(/^[A-Za-z0-9_-]{40,512}$/, value)) {
    const der = nativeBufferFrom(value, "base64url");
    if (bufferToString(der, "base64url") !== value) {
      fail("Atomic batch witness key is not canonical", "authorization_required");
    }
    key = nativeCreatePublicKey({ key: der, format: "der", type: "spki" });
  } else if (nativeIsKeyObject(value) && value.type === "public") {
    // createPublicKey(publicKeyObject) throws ERR_CRYPTO_INVALID_KEY_OBJECT_TYPE:
    // an independently supplied public pin is already a parsed KeyObject.
    key = value;
  } else {
    // createPublicKey({ key: getter }) executes caller code inside the
    // synchronous owner-verification boundary, before its crypto signature.
    fail("Atomic authority pin requires plain encoded Ed25519 key bytes",
      "authorization_required");
  }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") {
    fail("Atomic batch witness pin must be an Ed25519 public key",
      "authorization_required");
  }
  return key;
}
function verifyAtomicBatchAdmission(response, operations, trustedWitnessKey, trustedScope, identity,
  historicalRestore = false) {
  // Client-signed envelopes echoed by the server are NOT evidence that the
  // server committed them. Only a separate pinned witness can attest the
  // exact physical store head AFTER the two operations become durable.
  if (!trustedWitnessKey || !nativeArrayIsArray(operations)
    || (historicalRestore
      ? operations.length !== 1 || operations[0]?.operation !== "update"
        || typeof operations[0]?.operationId !== "string"
        || !stringStartsWith(operations[0].operationId, "histrestore-")
      : operations.length !== 2)) fail("Independent atomic batch witness is unavailable",
    "sync_atomic_batch_indeterminate");
  const receipt = response?.atomicAdmission;
  const statement = receipt?.statement;
  const required = ["version", "scope", "accountId", "storeId", "username",
    "compartmentId", "nonce", "operationIds", "envelopeDigests",
    "commitId", "storeHeadSha256", "fencingEpoch", "physicalDurable"];
  let operationMismatch = false;
  for (let index = 0; index < operations.length; index += 1) {
    const operation = operations[index];
    if (!operation || typeof operation !== "object"
      || operation.authorization?.username !== identity?.username
      || operation.compartmentId !== identity?.compartmentId
      || statement?.operationIds?.[index] !== operation.operationId
      || statement?.envelopeDigests?.[index] !== signedEnvelopeDigest(operation)) {
      operationMismatch = true;
      break;
    }
  }
  if (!hasExactKeys(receipt, ["signature", "statement"])
    || !hasExactKeys(statement, required)
    || statement.version !== 2 || statement.scope !== trustedScope
    || !identity || statement.accountId !== identity.accountId
    || statement.storeId !== identity.storeId
    || statement.username !== identity.username
    || statement.compartmentId !== identity.compartmentId
    || statement.physicalDurable !== true
    || typeof statement.nonce !== "string"
    || !regexTest(/^[A-Za-z0-9_-]{43}$/, statement.nonce)
    || !nativeNumberIsSafeInteger(statement.fencingEpoch) || statement.fencingEpoch < 1
    || typeof statement.commitId !== "string" || !regexTest(/^[A-Za-z0-9_-]{16,128}$/, statement.commitId)
    || typeof statement.storeHeadSha256 !== "string"
    || !regexTest(/^[a-f0-9]{64}$/, statement.storeHeadSha256)
    || !nativeArrayIsArray(statement.operationIds) || statement.operationIds.length !== operations.length
    || !nativeArrayIsArray(statement.envelopeDigests) || statement.envelopeDigests.length !== operations.length
    || operationMismatch
    || typeof receipt.signature !== "string"
    || !regexTest(/^[A-Za-z0-9_-]{86}$/, receipt.signature)) {
    fail("Atomic batch lacks an exact independent durable admission receipt",
      "sync_atomic_batch_indeterminate");
  }
  const signature = nativeBufferFrom(receipt.signature, "base64url");
  if (signature.length !== 64
    || bufferToString(signature, "base64url") !== receipt.signature
    || !nativeVerify(null, nativeBufferFrom((historicalRestore ? RESTORE_ADMISSION_DOMAIN : ATOMIC_ADMISSION_DOMAIN)
      + canonicalJson(statement), "utf8"), trustedWitnessKey, signature)) {
    fail("Independent atomic batch witness signature invalid",
      "sync_atomic_batch_indeterminate");
  }
}
function verifyAtomicBatchCasFloor(floor, witnessStatement, trustedCasKey,
  trustedScope, expectedNonce, identity, historicalRestore = false) {
  // An independent, off-host CAS reader must attest the CURRENT retained
  // physical head with a separate pinned signer. A new witness nonce alone
  // cannot distinguish a re-signed stale head after physical rollback.
  // Detach any callback-owned objects/getters before checking fields or
  // verifying bytes; an accessor must not swap a value between comparison
  // against the physical witness and Ed25519 verification.
  let detached;
  try { detached = nativeJsonParse(canonicalJson(floor)); }
  catch { fail("External CAS floor is not canonical JSON", "sync_atomic_batch_indeterminate"); }
  const statement = detached?.statement;
  const keys = ["version", "scope", "accountId", "storeId", "nonce",
    "commitId", "storeHeadSha256", "fencingEpoch", "sequence", "current"];
  if (!trustedCasKey || !hasExactKeys(detached, ["statement", "signature"])
    || !hasExactKeys(statement, keys)
    || statement.version !== 2 || statement.scope !== trustedScope
    || !identity || statement.accountId !== identity.accountId
    || statement.storeId !== identity.storeId
    || statement.accountId !== witnessStatement.accountId
    || statement.storeId !== witnessStatement.storeId
    || statement.scope !== witnessStatement.scope
    || statement.nonce !== expectedNonce || statement.current !== true
    || !nativeNumberIsSafeInteger(statement.sequence) || statement.sequence < 1
    || statement.commitId !== witnessStatement.commitId
    || statement.storeHeadSha256 !== witnessStatement.storeHeadSha256
    || statement.fencingEpoch !== witnessStatement.fencingEpoch
    || typeof detached.signature !== "string"
    || !regexTest(/^[A-Za-z0-9_-]{86}$/, detached.signature)) {
    fail("External CAS floor does not attest the same current batch head",
      "sync_atomic_batch_indeterminate");
  }
  const signature = nativeBufferFrom(detached.signature, "base64url");
  if (signature.length !== 64 || bufferToString(signature, "base64url") !== detached.signature
    || !nativeVerify(null, nativeBufferFrom((historicalRestore ? RESTORE_CAS_FLOOR_DOMAIN : ATOMIC_CAS_FLOOR_DOMAIN)
      + canonicalJson(statement), "utf8"), trustedCasKey, signature)) {
    fail("External CAS current floor signature invalid",
      "sync_atomic_batch_indeterminate");
  }
}
function envelopeCopy(operation) {
  // Detach incoming JSON from transport/callback-owned mutable references.
  // An async key resolver must never be able to swap an already-verified
  // signed envelope before the filesystem is changed.
  return nativeJsonParse(canonicalJson(operation));
}

function signedWebDavEventId(operation) {
  // Only an exact deterministic WebDAV operation ID can group two pending
  // signed envelopes. Never infer batch ownership from adjacent array order
  // alone, an untrusted metadata field or a caller-selected operation ID.
  if (!operation || typeof operation !== "object"
    || !nativeObjectHasOwn(operation, "authorization")
    || !nativeReflectApply(nativeArrayIncludes, ["delete", "move"], [operation.operation])
    || typeof operation.operationId !== "string"
    || typeof operation.metadata?.path !== "string") return null;
  const parts = nativeReflectApply(nativeRegExpExec,
    /^webdav-(.+)-([a-f0-9]{24})$/, [operation.operationId]);
  if (!parts || parts[1].length > 100) return null;
  const digest = stringSlice(sha256Hex(`${operation.operation}:${operation.metadata.path}`), 0, 24);
  return parts[2] === digest ? parts[1] : null;
}

function assertAtomicSignedOverwritePair(deleted, moved) {
  const event = signedWebDavEventId(deleted);
  if (!event || event !== signedWebDavEventId(moved)
    || deleted.operation !== "delete" || moved.operation !== "move"
    || deleted.metadata.path !== moved.metadata.path
    || !moved.metadata.sourcePath || deleted.deviceId !== moved.deviceId
    || deleted.compartmentId !== moved.compartmentId
    || deleted.keyEpoch !== moved.keyEpoch
    || deleted.objectId === moved.objectId || deleted.fileId === moved.fileId
    || deleted.operationId === moved.operationId
    || deleted.authorization.replayId === moved.authorization.replayId
    || deleted.authorization.idempotencyKey === moved.authorization.idempotencyKey) {
    fail("Signed WebDAV overwrite batch identity or order mismatch", "authorization_rejected");
  }
  return true;
}

function fail(message, code = "sync_engine_error") {
  throw nativeObjectAssign(new Error(message), { code });
}

function ownDataValue(value, key) {
  if (!value || (typeof value !== "object" && typeof value !== "function")
    || nativeIsProxy(value)) return undefined;
  const descriptor = nativeObjectGetOwnPropertyDescriptor(value, key);
  return descriptor && nativeObjectHasOwn(descriptor, "value") ? descriptor.value : undefined;
}

function ownDataOption(options, key) {
  if (!options || typeof options !== "object" || nativeIsProxy(options)) {
    fail("Sync options must be a non-proxy data object", "invalid_sync_options");
  }
  const descriptor = nativeObjectGetOwnPropertyDescriptor(options, key);
  if (descriptor && !nativeObjectHasOwn(descriptor, "value")) {
    fail(`Sync option ${key} must be an own data property`, "invalid_sync_options");
  }
  return descriptor ? descriptor.value : undefined;
}

function assertPlainJsonDataGraph(value, label, seen = new NativeSet(), checked = new NativeSet(),
  budget = { nodes: 0 }, depth = 1) {
  if (depth > 24) fail(`${label} exceeds the owner JSON depth budget`, "authorization_required");
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!nativeNumberIsFinite(value)) fail(`${label} contains a non-finite number`, "authorization_required");
    return;
  }
  if (!value || typeof value !== "object" || nativeIsProxy(value)) {
    fail(`${label} must contain only plain JSON data`, "authorization_required");
  }
  if (nativeReflectApply(nativeSetHas, seen, [value])) fail(`${label} must not contain cycles`, "authorization_required");
  // Only visit a shared object once. The protocol's memoized expansion budget
  // separately counts every alias in the eventual serialized JSON.
  if (nativeReflectApply(nativeSetHas, checked, [value])) return;
  if (++budget.nodes > 1024) fail(`${label} exceeds the owner JSON node budget`, "authorization_required");
  nativeReflectApply(nativeSetAdd, seen, [value]);
  if (nativeArrayIsArray(value)) {
    if (value.length > 1024 || nativeObjectGetPrototypeOf(value) !== NativeArray.prototype
      || nativeObjectKeys(value).length !== value.length
      || nativeReflectOwnKeys(value).length !== value.length + 1) {
      fail(`${label} contains an ambiguous array`, "authorization_required");
    }
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
      if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
        fail(`${label} contains an array accessor or hole`, "authorization_required");
      }
      assertPlainJsonDataGraph(descriptor.value, label, seen, checked, budget, depth + 1);
    }
    nativeReflectApply(nativeSetDelete, seen, [value]);
    nativeReflectApply(nativeSetAdd, checked, [value]);
    return;
  }
  const prototype = nativeObjectGetPrototypeOf(value);
  if (prototype !== NativeObjectPrototype && prototype !== null) {
    fail(`${label} must contain only plain objects`, "authorization_required");
  }
  const keys = nativeObjectKeys(value);
  if (keys.length > 1024 || nativeReflectOwnKeys(value).length !== keys.length) {
    fail(`${label} contains hidden or symbol properties`, "authorization_required");
  }
  for (let index = 0; index < keys.length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, keys[index]);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
      fail(`${label} contains an accessor`, "authorization_required");
    }
    assertPlainJsonDataGraph(descriptor.value, label, seen, checked, budget, depth + 1);
  }
  nativeReflectApply(nativeSetDelete, seen, [value]);
  nativeReflectApply(nativeSetAdd, checked, [value]);
}

function assertOwnerProvisionPrimitives() {
  if (NativeGlobalThis.Buffer !== NativeBuffer || NativeGlobalThis.Uint8Array !== NativeUint8Array
    || NativeGlobalThis.Array !== NativeArray || NativeGlobalThis.Object !== NativeObject
    || NativeGlobalThis.Reflect !== NativeReflect || NativeGlobalThis.Number !== NativeNumber
    || NativeGlobalThis.RegExp !== NativeRegExp || NativeGlobalThis.JSON !== NativeJSON
    || NativeBuffer.from !== nativeBufferFromProperty || NativeBuffer.isBuffer !== nativeBufferIsBufferProperty
    || NativeBuffer.prototype.toString !== nativeBufferToString || NativeBuffer.prototype.equals !== nativeBufferEquals
    || crypto.verify !== nativeCryptoVerifyProperty || crypto.createHash !== nativeCryptoCreateHashProperty
    || crypto.createPublicKey !== nativeCryptoCreatePublicKeyProperty || crypto.KeyObject !== NativeKeyObject
    || crypto.Hash.prototype.update !== nativeCryptoHashUpdateProperty
    || crypto.Hash.prototype.digest !== nativeCryptoHashDigestProperty
    || nativePublicKeyObjectPrototype.export !== nativeKeyObjectExport
    || NativeArray.isArray !== nativeArrayIsArray || NativeArray.prototype.includes !== nativeArrayIncludes
    || NativeArray.prototype.some !== nativeArraySome || NativeArray.prototype.every !== nativeArrayEvery
    || NativeRegExp.prototype.test !== nativeRegExpTest || NativeRegExp.prototype.exec !== nativeRegExpExec
    || NativeNumber.isSafeInteger !== nativeNumberIsSafeInteger || NativeReflect.ownKeys !== nativeReflectOwnKeys
    || NativeObject.freeze !== nativeObjectFreeze || NativeJSON.parse !== nativeJsonParseProperty
    || Function.prototype[Symbol.hasInstance] !== nativeFunctionHasInstance
    || protocol.canonicalJson !== canonicalJson) {
    fail("Atomic owner provisioning requires pristine native crypto and serialization primitives",
      "authorization_required");
  }
}

function captureDataMethod(receiver, key) {
  let current = receiver;
  while (current) {
    if (nativeIsProxy(current)) {
      fail(`Trusted method receiver for ${key} is a Proxy`, "restore_remote_admission_unproven");
    }
    const descriptor = nativeObjectGetOwnPropertyDescriptor(current, key);
    if (descriptor) {
      if (!nativeObjectHasOwn(descriptor, "value") || typeof descriptor.value !== "function"
        || nativeIsProxy(descriptor.value)) {
        fail(`Trusted method ${key} is not an own data method`, "restore_remote_admission_unproven");
      }
      return descriptor.value;
    }
    current = nativeObjectGetPrototypeOf(current);
  }
  fail(`Trusted method ${key} is unavailable`, "restore_remote_admission_unproven");
}

function captureMethodSet(receiver, names) {
  const methods = nativeObjectCreate(null);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    methods[name] = captureDataMethod(receiver, name);
  }
  return nativeObjectFreeze(methods);
}

function assertMethodSet(receiver, methods) {
  const names = nativeObjectKeys(methods);
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    if (captureDataMethod(receiver, name) !== methods[name]) {
      fail(`Trusted method ${name} changed during historical restore`,
        "restore_remote_admission_unproven");
    }
  }
}

const HISTORICAL_ENGINE_METHODS = nativeObjectFreeze([
  "keyFor", "verifyIncomingOperation", "buildOperation", "assertOutgoingAuthorized",
  "isSelected", "operationIsSelected", "localAdmissionDigestIfFresh", "retryPush",
  "confirmHistoricalRestorePhysicalAdmission", "hashPendingPayload", "rememberOperation",
  "persistSnapshot", "recoverConflict", "_apply", "_pushPending",
  "_applyExcludedPaths", "_reconcileLocal", "_pullRemote", "translateWebDavMutation", "_evictLocal",
]);
const HISTORICAL_JOURNAL_METHODS = nativeObjectFreeze([
  "commit", "recover", "enqueue", "discardUnsent", "markSeen", "markSeenMany",
  "markSeenExact", "replace", "update", "hasSeen",
  "durableSignedReceiptDigest", "recordRestoreMaterialization", "restoreStagingInfo",
  "hasMaterializedRestore", "atomicSignedGroups", "assertCompatibleAdmission",
  "hasLocalAdmission", "observeAdmission",
]);

function regexTest(pattern, value) {
  return nativeReflectApply(nativeRegExpExec, pattern, [value]) !== null;
}

function stringStartsWith(value, prefix) {
  return nativeReflectApply(nativeStringStartsWith, value, [prefix]);
}

function stringSlice(value, start, end) {
  return nativeReflectApply(nativeStringSlice, value, end === undefined ? [start] : [start, end]);
}

function stringToLowerCase(value) {
  return nativeReflectApply(nativeStringToLowerCase, value, []);
}

function stringSplit(value, separator, limit) {
  return nativeReflectApply(nativeStringSplit, value,
    limit === undefined ? [separator] : [separator, limit]);
}

function stringIncludes(value, search) {
  return nativeReflectApply(nativeStringIncludes, value, [search]);
}

function stringLocaleCompare(value, other) {
  return nativeReflectApply(nativeStringLocaleCompare, value, [other]);
}

function bigIntToString(value) {
  return nativeReflectApply(nativeBigIntToString, value, []);
}

function exportPublicKeySpki(key) {
  return nativeReflectApply(nativeKeyObjectExport, key, [{ type: "spki", format: "der" }]);
}

function buffersEqual(left, right) {
  return nativeReflectApply(nativeBufferEquals, left, [right]);
}

function snapshotArrayOfData(value, errorCode = "invalid_sync_response") {
  if (!nativeArrayIsArray(value)) fail("Expected an array of own data values", errorCode);
  const length = value.length;
  const keys = nativeObjectKeys(value);
  const ownKeys = nativeReflectOwnKeys(value);
  if (keys.length !== length || ownKeys.length !== length + 1) {
    fail("Array response contains holes, symbols, or hidden properties", errorCode);
  }
  const snapshot = new NativeArray(length);
  for (let index = 0; index < length; index += 1) {
    const descriptor = nativeObjectGetOwnPropertyDescriptor(value, `${index}`);
    if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      fail("Array response contains an accessor or missing index", errorCode);
    }
    snapshot[index] = descriptor.value;
  }
  nativeObjectSetPrototypeOf(snapshot, null);
  return nativeObjectFreeze(snapshot);
}

function transient(error) {
  let current = error;
  const visited = new NativeSet();
  for (let depth = 0; current && depth < 6; depth += 1) {
    // An adapter-supplied Proxy must not run prototype traps while deciding
    // whether a failed request can be replayed or independently witnessed.
    if (nativeIsProxy(current)) return false;
    if (nativeReflectApply(nativeSetHas, visited, [current])) break;
    nativeReflectApply(nativeSetAdd, visited, [current]);
    const code = ownDataValue(current, "code");
    if (typeof code === "string" && nativeReflectApply(nativeSetHas, TRANSIENT_REMOTE_CODES, [code])) return true;
    const message = ownDataValue(current, "message");
    if (nativeObjectGetPrototypeOf(current) === NativeTypeError.prototype && message === "fetch failed") return true;
    current = ownDataValue(current, "cause");
  }
  return false;
}

function uncertainHttpStatus(status) {
  if (typeof status !== "number" || !nativeNumberIsSafeInteger(status)) return false;
  const value = status;
  return value === 408 || value === 409 || value === 425 || value === 429
    || (value >= 500 && value <= 599);
}

function uncertainRemoteOutcome(error) {
  return transient(error) || uncertainHttpStatus(ownDataValue(error, "status"));
}

async function exists(filePath) {
  try {
    await fsp.lstat(filePath);
    return true;
  } catch (error) {
    if (ownDataValue(error, "code") === "ENOENT") return false;
    throw error;
  }
}

async function containedAbsolute(rootDir, target, allowMissing = true) {
  const root = path.resolve(rootDir);
  const resolved = path.resolve(target);
  if (!(resolved === root || stringStartsWith(resolved, `${root}${path.sep}`))) fail("Sync path escaped root", "unsafe_path");
  const rootStats = await fsp.lstat(root);
  if (rootStats.isSymbolicLink()) fail("Sync root symlink is not supported", "unsafe_path");
  let current = root;
  const segments = stringSplit(path.relative(root, resolved), path.sep);
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (!segment) continue;
    current = path.join(current, segment);
    try {
      const stats = await fsp.lstat(current);
      if (stats.isSymbolicLink()) fail("Sync symlink path is not supported", "unsafe_path");
    } catch (error) {
    if (!allowMissing || ownDataValue(error, "code") !== "ENOENT") throw error;
      break;
    }
  }
  return resolved;
}

async function contained(rootDir, relativePath, allowMissing = true) {
  const safe = protocol.safeRelativePath(relativePath, "path");
  return containedAbsolute(rootDir, path.resolve(rootDir, safe), allowMissing);
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.ino !== 0n;
}

function sameFileVersion(left, right) {
  return sameFileIdentity(left, right) && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs && left.mode === right.mode;
}

function isWithinPath(root, target) {
  const relative = path.relative(root, target);
  return relative === "" || (relative !== ".." && !stringStartsWith(relative, `..${path.sep}`) && !path.isAbsolute(relative));
}

async function readContainedFile(rootDir, relativePath, expectedStats = null, syncPhysical = false) {
  const root = path.resolve(rootDir);
  const target = await contained(root, relativePath, false);
  const before = expectedStats || await fsp.lstat(target, { bigint: true });
  // A hardlink into the selected root can alias an unrelated file outside it.
  // Canonical path and FD identity checks alone cannot detect that provenance.
  if (!before.isFile() || before.isSymbolicLink() || before.ino === 0n || before.nlink !== 1n) {
    fail("Sync file must be a regular file with a stable identity", "unsafe_path");
  }

  // A pending historical restore without a committed materialization witness
  // must re-flush its *actual opened file* and parent directory before POST.
  // A pathname hash alone cannot prove crash-durable bytes after a failed
  // materialization, including a failed directory fsync after hardlink().
  const flags = (syncPhysical ? fs.constants.O_RDWR : fs.constants.O_RDONLY)
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0);
  const handle = await fsp.open(target, flags);
  try {
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n || !sameFileVersion(before, opened)) fail("Sync file changed while opening", "unsafe_path");

    await containedAbsolute(root, target, false);
    const canonicalRoot = await fsp.realpath(root);
    const canonicalTarget = await fsp.realpath(target);
    if (!isWithinPath(canonicalRoot, canonicalTarget)) fail("Sync file escaped root", "unsafe_path");
    const pathStats = await fsp.lstat(target, { bigint: true });
    if (!pathStats.isFile() || pathStats.isSymbolicLink() || pathStats.nlink !== 1n
      || !sameFileIdentity(opened, pathStats)) {
      fail("Sync file changed while opening", "unsafe_path");
    }

    const data = await handle.readFile();
    try {
      const openedAfterRead = await handle.stat({ bigint: true });
      const pathAfterRead = await fsp.lstat(target, { bigint: true });
      if (!sameFileVersion(opened, openedAfterRead) || openedAfterRead.nlink !== 1n
        || !sameFileIdentity(openedAfterRead, pathAfterRead)
        || !pathAfterRead.isFile() || pathAfterRead.isSymbolicLink() || pathAfterRead.nlink !== 1n) {
        fail("Sync file changed while reading", "unsafe_path");
      }
      await containedAbsolute(root, target, false);
      const finalRoot = await fsp.realpath(root);
      const finalTarget = await fsp.realpath(target);
      if (!isWithinPath(finalRoot, finalTarget)) fail("Sync file escaped root", "unsafe_path");
      if (syncPhysical) {
        await handle.sync();
        await syncDirectoryChain(root, path.dirname(target));
        // Verify both the FD generation and pathname once more after the
        // durable file+directory barrier. A concurrent replacement must not
        // turn our fsync of A into authorization of a pathname now holding B.
        const afterSync = await handle.stat({ bigint: true });
        const linkedAfterSync = await fsp.lstat(target, { bigint: true });
        if (!sameFileVersion(opened, afterSync)
          || !sameFileVersion(afterSync, linkedAfterSync)
          || afterSync.nlink !== 1n || !linkedAfterSync.isFile()
          || linkedAfterSync.isSymbolicLink()) {
          fail("Sync file changed while durably flushing", "unsafe_path");
        }
        await containedAbsolute(root, target, false);
        const syncedRoot = await fsp.realpath(root);
        const syncedTarget = await fsp.realpath(target);
        if (!isWithinPath(syncedRoot, syncedTarget)) fail("Sync file escaped root", "unsafe_path");
      }
      return data;
    } catch (error) {
      zeroBuffer(data);
      throw error;
    }
  } finally {
    await handle.close();
  }
}

async function hashPinnedRestoredFile(handle, length) {
  // Never hash a path for restore materialization. The writer's original FD
  // stays open through link(target), so a swapped temporary pathname cannot
  // promote unrelated bytes into a durable signed restore witness.
  const initial = await handle.stat({ bigint: true });
  if (!initial.isFile() || initial.size !== BigInt(length)) {
    fail("Restore staging physical length changed", "restore_local_materialization_missing");
  }
  const block = nativeBufferAlloc(Math.min(length, 64 * 1024));
  const digest = createPinnedSha256();
  let offset = 0;
  try {
    while (offset < length) {
      const { bytesRead } = await handle.read(block, 0,
        Math.min(block.length, length - offset), offset);
      if (!bytesRead || bytesRead > block.length) {
        fail("Restore staging FD truncated while reading", "restore_local_materialization_missing");
      }
      digest.update(nativeReflectApply(nativeBufferSubarray, block, [0, bytesRead]));
      offset += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFileVersion(initial, after)) {
      fail("Restore staging FD changed while verifying signed bytes", "restore_local_materialization_missing");
    }
    return digest.digest("hex");
  } finally { zeroBuffer(block); }
}

async function syncDirectoryChain(rootDir, directoryName) {
  if (process.platform === "win32") return; // No portable directory fsync via Node/NTFS.
  const root = path.resolve(rootDir);
  let current = path.resolve(directoryName);
  if (!isWithinPath(root, current)) {
    fail("Restore durability directory escaped root", "unsafe_path");
  }
  while (true) {
    await containedAbsolute(root, current, false);
    const fd = await fsp.open(current, fs.constants.O_RDONLY
      | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
    try {
      const checked = await fd.stat({ bigint: true });
      if (!checked.isDirectory() || checked.isSymbolicLink()) {
        fail("Restore durability parent is not a directory", "unsafe_path");
      }
      await fd.sync();
    } finally { await fd.close(); }
    if (current === root) break;
    current = path.dirname(current);
  }
}

async function recoverHistoricalRestoreTempLink(rootDir, relativePath, expectedHash, staging) {
  // Never infer staging ownership from a filename pattern, content digest or
  // same-inode hardlink alone: a regular user can create all three. Require
  // the exact temp name + physical identity fsynced in the signed outbox
  // BEFORE the engine linked its private staging file into the target.
  if (!staging) return;
  const target = await contained(rootDir, relativePath, false);
  // Required after the held descriptor closes and the durable hardlink removal
  // has been verified; keep this scope outside the descriptor's try block.
  const directoryName = path.dirname(target);
  // Acquire and pin the target descriptor BEFORE using the pathname to
  // decide whether the old hardlink is eligible for recovery. A concurrent
  // writer may swap a name at any time; only fstat of this held descriptor
  // and a subsequent lstat equality check can authenticate the candidate.
  const handle = await fsp.open(target, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
  const current = await fsp.lstat(target, { bigint: true });
  if (!current.isFile() || current.isSymbolicLink() || current.ino === 0n
    || current.nlink !== 2n) return;
  const prefix = `${path.basename(target)}.tmp-`;
  if (!stringStartsWith(staging.name, prefix)
    || !regexTest(HISTORICAL_RESTORE_TEMP_SUFFIX,
      stringSlice(staging.name, path.basename(target).length))
    || bigIntToString(current.dev) !== staging.dev
    || bigIntToString(current.ino) !== staging.ino) {
    fail("Historical restore staging identity is not proven", "restore_local_materialization_missing");
  }
  const staged = path.join(directoryName, staging.name);
  await containedAbsolute(rootDir, staged, false);
  const stagedStats = await nativeReflectApply(nativePromiseCatch,
    fsp.lstat(staged, { bigint: true }), [(error) => {
    if (ownDataValue(error, "code") === "ENOENT") {
      fail("Recorded historical restore staging file missing", "restore_local_materialization_missing");
    }
    throw error;
  }]);
  if (!stagedStats.isFile() || stagedStats.isSymbolicLink()
    || !sameFileVersion(current, stagedStats) || stagedStats.nlink !== 2n
    || bigIntToString(stagedStats.dev) !== staging.dev
    || bigIntToString(stagedStats.ino) !== staging.ino) {
    fail("Recorded historical restore staging file changed", "restore_local_materialization_missing");
  }
    const opened = await handle.stat({ bigint: true });
    if (!sameFileVersion(current, opened) || opened.nlink !== 2n) {
      fail("Historical restore hardlink identity changed", "restore_local_materialization_missing");
    }
    const data = await handle.readFile();
    try {
      if (sha256Hex(data) !== expectedHash) {
        fail("Historical restore hardlink bytes differ from signed operation", "restore_local_materialization_missing");
      }
    } finally { zeroBuffer(data); }
    const afterRead = await handle.stat({ bigint: true });
    const liveTarget = await fsp.lstat(target, { bigint: true });
    const liveStaged = await fsp.lstat(staged, { bigint: true });
    if (!sameFileVersion(opened, afterRead)
      || !sameFileVersion(afterRead, liveTarget)
      || !sameFileVersion(afterRead, liveStaged)
      || afterRead.nlink !== 2n || liveTarget.nlink !== 2n) {
      fail("Historical restore hardlink changed during recovery", "restore_local_materialization_missing");
    }
    await containedAbsolute(rootDir, target, false);
    await containedAbsolute(rootDir, staged, false);
    const canonicalRoot = await fsp.realpath(rootDir);
    for (const location of [target, staged]) {
      if (!isWithinPath(canonicalRoot, await fsp.realpath(location))) {
        fail("Historical restore hardlink escaped root", "unsafe_path");
      }
    }
    await fsp.unlink(staged);
  } finally { await handle.close(); }
  await syncDirectoryChain(rootDir, directoryName);
  // The caller now reopens and physically flushes target as nlink=1, and
  // rechecks its signed bytes and pathname *after* this recovery barrier.
}

async function canonicalRelativePath(rootDir, relativePath) {
  const safe = protocol.safeRelativePath(relativePath, "path");
  if (process.platform !== "win32") return safe;
  const root = path.resolve(rootDir);
  await containedAbsolute(root, root, false);
  const segments = stringSplit(safe, "/");
  let current = root;
  for (let index = 0; index < segments.length; index += 1) {
    const requested = segments[index];
    const names = await fsp.readdir(current);
    const matches = [];
    let exactMatch = false;
    for (let nameIndex = 0; nameIndex < names.length; nameIndex += 1) {
      const name = names[nameIndex];
      if (name === requested) exactMatch = true;
      if (stringToLowerCase(name) === stringToLowerCase(requested)) matches[matches.length] = name;
    }
    const selected = exactMatch ? requested : matches.length === 1 ? matches[0] : null;
    if (!selected) {
      if (matches.length > 1) fail("Ambiguous case-insensitive sync path", "unsafe_path");
      let remaining = "";
      for (let restIndex = index; restIndex < segments.length; restIndex += 1) {
        if (remaining) remaining += path.sep;
        remaining += segments[restIndex];
      }
      current = path.join(current, remaining);
      break;
    }
    current = path.join(current, selected);
    const stats = await fsp.lstat(current);
    if (stats.isSymbolicLink()) fail("Sync symlink path is not supported", "unsafe_path");
    if (index < segments.length - 1 && !stats.isDirectory()) fail("Sync path parent must be a directory", "unsafe_path");
  }
  await containedAbsolute(root, current, true);
  const relative = stringSplit(path.relative(root, current), path.sep);
  let portable = "";
  for (let index = 0; index < relative.length; index += 1) {
    if (index > 0) portable += "/";
    portable += relative[index];
  }
  return portable;
}

function canonicalMapPath(relativePath, ...maps) {
  if (process.platform !== "win32") return relativePath;
  for (const map of maps) {
    if (nativeObjectHasOwn(map, relativePath)) return relativePath;
  }
  const matches = [];
  for (const map of maps) {
    const keys = nativeObjectKeys(map);
    for (let index = 0; index < keys.length; index += 1) {
      const candidate = keys[index];
      if (stringToLowerCase(candidate) === stringToLowerCase(relativePath)) {
        if (!nativeReflectApply(nativeArrayIncludes, matches, [candidate])) matches[matches.length] = candidate;
      }
    }
  }
  if (matches.length > 1) fail("Ambiguous case-insensitive sync snapshot path", "unsafe_path");
  return matches.length === 1 ? matches[0] : relativePath;
}

async function durableJson(filePath, value) {
  const temporary = `${filePath}.tmp-${process.pid}-${nativeRandomUUID()}`;
  const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
    | (fs.constants.O_SYNC || 0);
  // FileHandle.writeFile(string) consults mutable global Buffer.from inside
  // Node after its await. Persist already captured bytes through write().
  const serialized = nativeBufferFrom(`${safeJsonStringify(value)}\n`, "utf8");
  let handle;
  try {
    handle = await fsp.open(temporary, flags, 0o600);
    for (let offset = 0; offset < serialized.length;) {
      const { bytesWritten } = await handle.write(serialized, offset, serialized.length - offset, offset);
      if (!nativeNumberIsSafeInteger(bytesWritten) || bytesWritten <= 0
        || bytesWritten > serialized.length - offset) {
        fail("Durable snapshot write made no valid progress", "sync_disk_write_failed");
      }
      offset += bytesWritten;
    }
    await handle.sync();
    await handle.close();
    handle = null;
    await renameWithRetry(temporary, filePath);
    // Node cannot reliably fsync directory handles on Windows. Flush the
    // containing directory where the platform supports it; the file itself
    // is opened with O_SYNC and explicitly synced before the atomic rename.
    if (process.platform !== "win32") {
      const directory = await fsp.open(path.dirname(filePath), fs.constants.O_RDONLY);
      try { await directory.sync(); } finally { await directory.close(); }
    }
  } catch (error) {
    if (handle) await nativeReflectApply(nativePromiseCatch, handle.close(), [() => {}]);
    await nativeReflectApply(nativePromiseCatch, fsp.rm(temporary, { force: true }), [() => {}]);
    throw error;
  }
}

function normalizeWebDavPath(value) {
  let decoded;
  if (typeof value !== "string") fail("Invalid WebDAV path", "unsafe_path");
  try { decoded = nativeDecodeURIComponent(value); } catch { fail("Invalid WebDAV path", "unsafe_path"); }
  let start = 0;
  let end = decoded.length;
  while (start < end && decoded[start] === "/") start += 1;
  while (end > start && decoded[end - 1] === "/") end -= 1;
  return protocol.safeRelativePath(stringSlice(decoded, start, end), "path");
}

function pathWithin(relativePath, parentPath) {
  const relative = process.platform === "win32" ? stringToLowerCase(relativePath) : relativePath;
  const parent = process.platform === "win32" ? stringToLowerCase(parentPath) : parentPath;
  return relative === parent || stringStartsWith(relative, `${parent}/`);
}

function pathsEqual(left, right) {
  return pathWithin(left, right) && pathWithin(right, left);
}

function evictionError(code, message, cause, rollbackCause) {
  return nativeObjectAssign(new Error(message), { code, cause, ...(rollbackCause ? { rollbackCause } : {}) });
}

function normalizeExcludedPaths(value) {
  if (value == null) return [];
  if (!nativeArrayIsArray(value)) fail("Excluded paths must be an array", "invalid_excluded_paths");
  const snapshot = snapshotArrayOfData(value, "invalid_excluded_paths");
  const normalized = nativeReflectApply(nativeArrayMap, snapshot, [(item) => {
    try {
      return protocol.safeRelativePath(item, "excludedPath");
    } catch {
      fail("Excluded sync path is unsafe", "unsafe_path");
    }
  }]);
  const seen = new NativeSet();
  const unique = [];
  for (let index = 0; index < normalized.length; index += 1) {
    const item = normalized[index];
    if (!nativeReflectApply(nativeSetHas, seen, [item])) {
      nativeReflectApply(nativeSetAdd, seen, [item]);
      nativeReflectApply(nativeArrayPush, unique, [item]);
    }
  }
  nativeReflectApply(nativeArraySort, unique, [stringLocaleCompare]);
  return nativeObjectFreeze(unique);
}

function pathKey(relativePath) {
  return process.platform === "win32" ? stringToLowerCase(relativePath) : relativePath;
}

function sameSnapshotRevision(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino
    && left.size === right.size && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs);
}

function activeIdentityPath(files, operation, exceptPath) {
  const keys = nativeObjectKeys(files);
  for (let index = 0; index < keys.length; index += 1) {
    const relativePath = keys[index];
    const prior = ownDataValue(files, relativePath);
    if (relativePath !== exceptPath && prior && !prior.deleted && prior.directory
      && prior.objectId === operation.objectId && prior.fileId === operation.fileId) return relativePath;
  }
  return null;
}

function activeFileIdentityPath(files, operation, exceptPath) {
  const keys = nativeObjectKeys(files);
  for (let index = 0; index < keys.length; index += 1) {
    const relativePath = keys[index];
    const prior = ownDataValue(files, relativePath);
    if (relativePath !== exceptPath && prior && !prior.deleted && !prior.directory
      && prior.objectId === operation.objectId && prior.fileId === operation.fileId) return relativePath;
  }
  return null;
}

class SyncEngine {
  constructor(options = {}) {
    if (!options || typeof options !== "object" || nativeArrayIsArray(options) || nativeIsProxy(options)) {
      fail("Sync options must be a plain data object", "invalid_sync_options");
    }
    const option = (key) => ownDataOption(options, key);
    const adapterOption = option("adapter");
    const journalOption = option("journal");
    if (!adapterOption || typeof adapterOption !== "object" || nativeIsProxy(adapterOption)
      || typeof ownDataValue(adapterOption, "push") !== "function"
      || typeof ownDataValue(adapterOption, "list") !== "function") {
      fail("Sync adapter with push and list is required");
    }
    if (journalOption != null && (typeof journalOption !== "object" || nativeIsProxy(journalOption))) {
      fail("Sync journal must be a trusted non-proxy object", "invalid_sync_options");
    }
    this.rootDir = path.resolve(option("rootDir") || process.cwd());
    this.journal = journalOption || new SyncJournal(option("journalPath") || path.join(this.rootDir, ".rootark-sync-journal.json"));
    this.snapshotPath = path.resolve(option("snapshotPath") || path.join(this.rootDir, ".rootark-sync-index.json"));
    // The adapter reference is part of every authorization boundary. Keep the
    // injected object stable even for ordinary strict engines; callers may
    // still instrument its methods without replacing the transport identity.
    nativeObjectDefineProperty(this, "adapter", {
      configurable: false, enumerable: true, writable: false, value: adapterOption,
    });
    const deviceIdOption = option("deviceId");
    const keyEpochOption = option("keyEpoch");
    const compartmentIdOption = option("compartmentId");
    if ((deviceIdOption != null && typeof deviceIdOption !== "string")
      || (keyEpochOption != null && typeof keyEpochOption !== "string")
      || (compartmentIdOption != null && typeof compartmentIdOption !== "string")) {
      fail("Sync device, key epoch and compartment identifiers must be strings", "invalid_sync_identity");
    }
    this.deviceId = deviceIdOption || "";
    this.keyEpoch = keyEpochOption || "";
    this.compartmentId = compartmentIdOption || "";
    const clockOption = option("clock");
    const clock = clockOption === undefined ? nativeDateNow : clockOption;
    if (typeof clock !== "function") fail("Sync clock must be a trusted function", "invalid_sync_clock");
    nativeObjectDefineProperty(this, "clock", {
      configurable: false, enumerable: false, writable: false, value: clock,
    });
    const fallbackFileKey = option("fileKey");
    const fileKeyResolverOption = option("fileKeyResolver");
    const authorizeOption = option("authorize");
    const authorizeOutgoingOption = option("authorizeOutgoing");
    const currentDeviceAuthorizationOption = option("currentDeviceAuthorization");
    const authorizationFactoryOption = option("authorizationFactory");
    const verifyIncomingOption = option("verifyIncoming");
    const translateWebDavOperationOption = option("translateWebDavOperation");
    for (const [name, callback] of [
      ["fileKeyResolver", fileKeyResolverOption], ["authorize", authorizeOption],
      ["authorizeOutgoing", authorizeOutgoingOption], ["currentDeviceAuthorization", currentDeviceAuthorizationOption],
      ["authorizationFactory", authorizationFactoryOption], ["verifyIncoming", verifyIncomingOption],
      ["translateWebDavOperation", translateWebDavOperationOption],
    ]) {
      if (callback != null && (typeof callback !== "function" || nativeIsProxy(callback))) {
        fail(`Sync callback ${name} must be a trusted function`, "invalid_sync_options");
      }
    }
    this.fileKeyResolver = fileKeyResolverOption || (() => fallbackFileKey);
    this.authorize = authorizeOption || (() => true);
    this.authorizeOutgoing = authorizeOutgoingOption || (() => true);
    // Supplied by the embedding process from independently trusted, CURRENT
    // device policy. Config snapshots and the local journal are not authority.
    this.currentDeviceAuthorization = currentDeviceAuthorizationOption || null;
    this.requireCurrentOutgoingAuthorization = option("requireCurrentOutgoingAuthorization") === true;
    // Must be supplied from an independent, trusted owner-pinned source.
    // NEVER accept a key sent by the sync server or serialized in the journal.
    const witnessPublicKeyInput = option("atomicBatchWitnessPublicKey");
    const witnessReadbackInput = option("atomicBatchWitnessReadback");
    const witnessScopeInput = option("atomicBatchWitnessScope");
    const ownerIdentityInput = option("atomicBatchOwnerIdentity");
    const ownerProvisionerPublicKeyInput = option("atomicBatchOwnerProvisionerPublicKey");
    const ownerProvisioningInput = option("atomicBatchOwnerProvisioning");
    const ownerProvisionDigestInput = option("atomicBatchOwnerProvisionDigest");
    const casFloorPublicKeyInput = option("atomicBatchCasFloorPublicKey");
    const casFloorReadbackInput = option("atomicBatchCasFloorReadback");
    const hasPhysicalAuthorityOptions = witnessPublicKeyInput != null || witnessReadbackInput != null
      || witnessScopeInput != null || ownerIdentityInput != null || ownerProvisionerPublicKeyInput != null
      || ownerProvisioningInput != null || ownerProvisionDigestInput != null
      || casFloorPublicKeyInput != null || casFloorReadbackInput != null;
    if (hasPhysicalAuthorityOptions) assertOwnerProvisionPrimitives();
    // The adjacent owner verifier uses RegExp.test(expectedDigest), which
    // coerces objects via caller-controlled Symbol.toPrimitive/toString.
    // Pin a primitive digest before crossing its dynamic-crypto boundary.
    if (hasPhysicalAuthorityOptions && (typeof ownerProvisionDigestInput !== "string"
      || !regexTest(/^[a-f0-9]{64}$/, ownerProvisionDigestInput))) {
      fail("Atomic owner provision digest must be an independently pinned SHA256 string",
        "authorization_required");
    }
    if (ownerIdentityInput != null) assertPlainJsonDataGraph(ownerIdentityInput, "Atomic owner identity");
    let detachedOwnerIdentity = null;
    if (ownerIdentityInput != null) {
      try { detachedOwnerIdentity = nativeJsonParse(canonicalJson(ownerIdentityInput, true)); }
      catch { fail("Atomic owner identity exceeds safe JSON limits", "authorization_required"); }
    }
    let detachedOwnerProvisioning = null;
    if (typeof ownerProvisioningInput === "string") {
      if (nativeBufferByteLength(ownerProvisioningInput, "utf8") > 64 * 1024) {
        fail("Atomic owner provisioning exceeds safe JSON byte budget", "authorization_required");
      }
      detachedOwnerProvisioning = nativeJsonParse(ownerProvisioningInput);
      assertPlainJsonDataGraph(detachedOwnerProvisioning, "Atomic owner provisioning");
    } else if (ownerProvisioningInput != null) {
      assertPlainJsonDataGraph(ownerProvisioningInput, "Atomic owner provisioning");
      try { detachedOwnerProvisioning = nativeJsonParse(canonicalJson(ownerProvisioningInput, true)); }
      catch { fail("Atomic owner provisioning exceeds safe JSON limits", "authorization_required"); }
    }
    if ((ownerProvisionerPublicKeyInput != null && nativeIsProxy(ownerProvisionerPublicKeyInput))
      || (witnessReadbackInput != null && (typeof witnessReadbackInput !== "function" || nativeIsProxy(witnessReadbackInput)))
      || (casFloorReadbackInput != null && (typeof casFloorReadbackInput !== "function" || nativeIsProxy(casFloorReadbackInput)))) {
      fail("Atomic authority keys and readback callbacks must be trusted non-proxy values",
        "authorization_required");
    }
    const witnessPublicKey = pinnedAtomicWitnessKey(witnessPublicKeyInput);
    const witnessReadback = witnessReadbackInput || null;
    const witnessScope = witnessScopeInput || null;
    const ownerIdentity = pinnedAtomicOwnerIdentity(detachedOwnerIdentity);
    const casFloorPublicKey = pinnedAtomicWitnessKey(casFloorPublicKeyInput);
    const ownerProvisionerPublicKey = pinnedAtomicWitnessKey(ownerProvisionerPublicKeyInput);
    const casFloorReadback = casFloorReadbackInput || null;
    if (casFloorReadback !== null
      && typeof casFloorReadback !== "function") {
      fail("Independent external CAS floor reader must be a function",
        "authorization_required");
    }
    if (witnessPublicKey && casFloorPublicKey
      && buffersEqual(exportPublicKeySpki(witnessPublicKey), exportPublicKeySpki(casFloorPublicKey))) {
      fail("External CAS floor and physical witness require distinct pinned keys",
        "authorization_required");
    }
    if (witnessScope !== null
      && (typeof witnessScope !== "string"
        || !regexTest(/^[A-Za-z0-9._:-]{1,256}$/, witnessScope))) {
      fail("Atomic batch witness scope must be a trusted account/store identifier",
        "authorization_required");
    }
    if (witnessReadback !== null
      && typeof witnessReadback !== "function") {
      fail("Independent atomic batch witness readback must be a function",
        "authorization_required");
    }
    const ownerProvision = (witnessPublicKey || witnessReadback || witnessScope
      || ownerIdentity || casFloorPublicKey || casFloorReadback)
      ? (() => {
        // The adjacent verifier is synchronous but still uses some dynamic
        // intrinsics. It must only receive detached data/native KeyObjects,
        // with pristine primitives checked immediately at the boundary.
        assertOwnerProvisionPrimitives();
        const provision = verifyPinnedAtomicOwnerProvision({
        identity: ownerIdentity,
        scope: witnessScope,
        provisionerPublicKey: ownerProvisionerPublicKey,
        provisioning: detachedOwnerProvisioning,
        expectedDigest: ownerProvisionDigestInput,
        witnessPublicKey, casPublicKey: casFloorPublicKey,
        });
        assertOwnerProvisionPrimitives();
        return provision;
      })() : null;
    if (ownerProvision) {
      const authorityKeys = [witnessPublicKey, casFloorPublicKey];
      const ownerKeyDer = exportPublicKeySpki(ownerProvision.publicKey);
      for (let index = 0; index < authorityKeys.length; index += 1) {
        const key = authorityKeys[index];
        if (key && buffersEqual(exportPublicKeySpki(key), ownerKeyDer)) {
          fail("Owner provisioner, witness and CAS must have distinct pinned keys",
            "authorization_required");
        }
      }
    }
    // Never let an async callback swap the signer, CAS identity, scope or
    // direct-readback function after construction. Ordinary instance fields
    // would allow a witness callback to mutate `this.*` between awaited
    // signature checks and silently defeat the separate-authority contract.
    nativeObjectDefineProperty(this, "atomicBatchWitnessPublicKey", { value: witnessPublicKey });
    nativeObjectDefineProperty(this, "atomicBatchWitnessReadback", { value: witnessReadback });
    nativeObjectDefineProperty(this, "atomicBatchWitnessScope", { value: witnessScope });
    nativeObjectDefineProperty(this, "atomicBatchOwnerIdentity", { value: ownerIdentity });
    nativeObjectDefineProperty(this, "atomicBatchOwnerProvisionerPublicKey", { value: ownerProvision?.publicKey || null });
    nativeObjectDefineProperty(this, "atomicBatchCasFloorPublicKey", { value: casFloorPublicKey });
    nativeObjectDefineProperty(this, "atomicBatchCasFloorReadback", { value: casFloorReadback });
    if (this.requireCurrentOutgoingAuthorization && !this.currentDeviceAuthorization) {
      fail("Current device authorization callback is required", "authorization_required");
    }
    this.verifyIncoming = verifyIncomingOption || null;
    this.reverifySeenIncoming = option("reverifySeenIncoming") === true;
    this.authorizationFactory = authorizationFactoryOption || null;
    this.requireAuthorization = option("requireAuthorization") === true;
    this.translateWebDavOperation = translateWebDavOperationOption || null;
    const maxRetriesOption = option("maxRetries");
    if (maxRetriesOption !== undefined && (!nativeNumberIsSafeInteger(maxRetriesOption) || maxRetriesOption < 1)) {
      fail("Sync maxRetries must be a positive safe integer", "invalid_sync_options");
    }
    this.maxRetries = nativeMathMin(5, nativeMathMax(1, maxRetriesOption === undefined ? 3 : maxRetriesOption));
    const selectedPathsInput = option("selectedPaths");
    if (selectedPathsInput != null && !nativeArrayIsArray(selectedPathsInput)) {
      fail("Selected paths must be an array", "invalid_selected_paths");
    }
    if (selectedPathsInput == null) this.selectedPaths = null;
    else {
      const selectedSnapshot = snapshotArrayOfData(selectedPathsInput, "invalid_selected_paths");
      const selectedSet = new NativeSet();
      const selectedPaths = [];
      for (let index = 0; index < selectedSnapshot.length; index += 1) {
        const relative = protocol.safeRelativePath(selectedSnapshot[index], "selectedPath");
        if (!nativeReflectApply(nativeSetHas, selectedSet, [relative])) {
          nativeReflectApply(nativeSetAdd, selectedSet, [relative]);
          nativeReflectApply(nativeArrayPush, selectedPaths, [relative]);
        }
      }
      nativeReflectApply(nativeArraySort, selectedPaths, [stringLocaleCompare]);
      this.selectedPaths = nativeObjectFreeze(selectedPaths);
    }
    this.excludedPaths = normalizeExcludedPaths(option("excludedPaths"));
    this.snapshot = { version: SNAPSHOT_VERSION, files: {}, remoteOnly: {} };
    this.snapshotDiskRevision = null;
    this.opened = false;
    // Only trusted physical-authority engines can admit historical restores.
    // Leave ordinary SyncEngine instances instrumentable (cache eviction and
    // rollback tests replace methods), but pin the strict admission boundary.
    if (this.requireAuthorization && ownerProvision) {
      for (let index = 0; index < HISTORICAL_ENGINE_METHODS.length; index += 1) {
        const name = HISTORICAL_ENGINE_METHODS[index];
        const descriptor = nativeObjectGetOwnPropertyDescriptor(SyncEngine.prototype, name);
        if (!descriptor || !nativeObjectHasOwn(descriptor, "value") || typeof descriptor.value !== "function") {
          fail(`Historical restore method ${name} is unavailable`, "authorization_required");
        }
        nativeObjectDefineProperty(this, name, {
          configurable: false, enumerable: false, writable: false, value: descriptor.value,
        });
      }
    }
  }

  withMutationLock(work) {
    const queueKey = process.platform === "win32" ? stringToLowerCase(this.rootDir) : this.rootDir;
    if (nativeReflectApply(nativeAsyncLocalStorageGetStore, ROOT_MUTATION_CONTEXT, []) === queueKey) {
      fail("Sync mutations cannot re-enter a root operation", "sync_root_busy");
    }
    const previous = nativeReflectApply(nativeMapGet, ROOT_MUTATION_QUEUES, [queueKey]) || nativePromiseResolve();
    let releaseQueue;
    const queueGate = new NativePromise((resolve) => { releaseQueue = resolve; });
    nativeReflectApply(nativeMapSet, ROOT_MUTATION_QUEUES, [queueKey, queueGate]);
    const run = async () => {
      await fsp.mkdir(this.rootDir, { recursive: true });
      await containedAbsolute(this.rootDir, this.rootDir, false);
      const processLock = await this.acquireProcessLock();
      try {
        await this._open();
        return await nativeReflectApply(nativeAsyncLocalStorageRun, ROOT_MUTATION_CONTEXT, [queueKey, work]);
      } finally {
        await this.releaseProcessLock(processLock);
      }
    };
    const operation = nativeReflectApply(nativePromiseThen, previous, [run, run]);
    return nativeReflectApply(nativePromiseFinally, operation, [() => {
      releaseQueue();
      if (nativeReflectApply(nativeMapGet, ROOT_MUTATION_QUEUES, [queueKey]) === queueGate) {
        nativeReflectApply(nativeMapDelete, ROOT_MUTATION_QUEUES, [queueKey]);
      }
    }]);
  }

  async open() {
    return this.withMutationLock(async () => this);
  }

  async acquireProcessLock() {
    const lockPath = path.join(this.rootDir, ".rootark-sync.lock");
    try {
      // mkdir is an atomic no-overwrite claim. The lock directory is empty so
      // release can use rmdir, which itself refuses to remove a replacement
      // directory if it contains anything.
      await fsp.mkdir(lockPath, { mode: 0o700 });
      return lockPath;
    } catch (error) {
      if (ownDataValue(error, "code") === "EEXIST") {
        fail("Another sync writer owns this folder, or its leftover lock needs manual recovery", "sync_root_busy");
      }
      throw error;
    }
  }

  async releaseProcessLock(lockPath) {
    try {
      // The operation is atomic with respect to directory contents: if an
      // unexpected actor replaced this marker with a nonempty lock directory,
      // rmdir refuses to remove it instead of deleting by checked pathname.
      await fsp.rmdir(lockPath);
    } catch (error) {
      if (ownDataValue(error, "code") !== "ENOENT") throw error;
    }
  }

  async _open() {
    await fsp.mkdir(this.rootDir, { recursive: true });
    await containedAbsolute(this.rootDir, this.rootDir, false);
    const journal = ownDataValue(this, "journal");
    const journalOpen = captureDataMethod(journal, "open");
    const openedJournal = await nativeReflectApply(journalOpen, journal, []);
    if (openedJournal !== journal) fail("Sync journal identity changed while opening", "invalid_sync_options");
    const journalDescriptor = nativeObjectGetOwnPropertyDescriptor(this, "journal");
    if (journalDescriptor?.writable) {
      nativeObjectDefineProperty(this, "journal", {
        configurable: false, enumerable: true, writable: false, value: journal,
      });
    } else if (ownDataValue(this, "journal") !== journal) {
      fail("Sync journal identity changed while opening", "invalid_sync_options");
    }
    let snapshotStats;
    try {
      snapshotStats = await fsp.lstat(this.snapshotPath, { bigint: true });
    } catch (error) {
      if (ownDataValue(error, "code") !== "ENOENT" || this.opened) fail("Sync snapshot is unavailable", "invalid_snapshot");
      await durableJson(this.snapshotPath, this.snapshot);
      snapshotStats = await fsp.lstat(this.snapshotPath, { bigint: true });
    }
    if (!snapshotStats.isFile() || snapshotStats.isSymbolicLink()) fail("Sync snapshot is not a regular file", "invalid_snapshot");
    if (!sameSnapshotRevision(this.snapshotDiskRevision, snapshotStats)) {
      let parsed;
      try {
        parsed = nativeJsonParse(await fsp.readFile(this.snapshotPath, "utf8"));
      } catch {
        fail("Invalid sync snapshot", "invalid_snapshot");
      }
      if (parsed.version !== SNAPSHOT_VERSION || !parsed.files || typeof parsed.files !== "object" || Array.isArray(parsed.files)) fail("Invalid sync snapshot", "invalid_snapshot");
      if (parsed.remoteOnly === undefined) parsed.remoteOnly = {};
      if (!parsed.remoteOnly || typeof parsed.remoteOnly !== "object" || Array.isArray(parsed.remoteOnly)) fail("Invalid remote-only sync state", "invalid_snapshot");
      if (parsed.excludedPaths !== undefined) {
        try { parsed.excludedPaths = normalizeExcludedPaths(parsed.excludedPaths); } catch { fail("Invalid excluded sync paths", "invalid_snapshot"); }
      }
      if (parsed.pendingEvictions !== undefined) {
        if (!parsed.pendingEvictions || typeof parsed.pendingEvictions !== "object" || Array.isArray(parsed.pendingEvictions)) fail("Invalid pending evictions", "invalid_snapshot");
        const pendingEvictionEntries = nativeObjectEntries(parsed.pendingEvictions);
        for (let index = 0; index < pendingEvictionEntries.length; index += 1) {
          const entry = pendingEvictionEntries[index][1];
      if (!entry || typeof entry !== "object" || typeof entry.code !== "string" || !nativeNumberIsInteger(entry.attempts) || entry.attempts < 0) fail("Invalid pending eviction", "invalid_snapshot");
          try { protocol.safeRelativePath(entry.path, "path"); } catch { fail("Invalid pending eviction path", "invalid_snapshot"); }
        }
      }
      const remoteOnlyEntries = nativeObjectEntries(parsed.remoteOnly);
      for (let index = 0; index < remoteOnlyEntries.length; index += 1) {
        const objectId = remoteOnlyEntries[index][0];
        const item = remoteOnlyEntries[index][1];
        if (!item || typeof item !== "object" || item.objectId !== objectId || typeof item.path !== "string") fail("Invalid remote-only sync entry", "invalid_snapshot");
        try {
          protocol.safeRelativePath(item.path, "path");
          if (item.sourcePath) protocol.safeRelativePath(item.sourcePath, "sourcePath");
        } catch { fail("Invalid remote-only sync path", "invalid_snapshot"); }
      if (!nativeReflectApply(nativeArrayIncludes, ["excluded", "evicted"], [item.reason])
        || typeof item.deleted !== "boolean") fail("Invalid remote-only sync entry", "invalid_snapshot");
      }
      this.snapshot = parsed;
      this.snapshotDiskRevision = snapshotStats;
    }
    this.opened = true;
    return this;
  }

  async persistSnapshot() {
    await durableJson(this.snapshotPath, this.snapshot);
    this.snapshotDiskRevision = await fsp.lstat(this.snapshotPath, { bigint: true });
  }

  async keyFor(operation) {
    const captured = captureSignedEnvelope(operation);
    const authorize = ownDataValue(this, "authorize");
    const resolver = ownDataValue(this, "fileKeyResolver");
    const keyEpoch = ownDataValue(this, "keyEpoch");
    const adapter = ownDataValue(this, "adapter");
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    if (typeof authorize !== "function" || typeof resolver !== "function") {
      fail("Historical restore key callbacks are unavailable", "authorization_required");
    }
    if (typeof adapterPush !== "function") fail("Sync adapter is unavailable", "authorization_required");
    const assertKeySnapshot = () => {
      assertCapturedSignedEnvelope(captured);
      if (ownDataValue(this, "authorize") !== authorize || ownDataValue(this, "fileKeyResolver") !== resolver
        || this.adapter !== adapter || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate || ownDataValue(this, "keyEpoch") !== keyEpoch) {
        fail("Historical restore callback identity changed during key resolution",
          "historical_restore_callback_changed");
      }
    };
    if (await nativeReflectApply(authorize, undefined, [captured.operation]) !== true) {
      fail("Sync authorization rejected", "authorization_rejected");
    }
    assertKeySnapshot();
    if (ownDataValue(this, "keyEpoch") !== keyEpoch || (captured.operation.keyEpoch !== keyEpoch && keyEpoch)) {
      fail("Stale sync key epoch", "sync_key_epoch_mismatch");
    }
    const resolved = await nativeReflectApply(resolver, undefined, [captured.operation]);
    assertKeySnapshot();
    if (ownDataValue(this, "keyEpoch") !== keyEpoch || (captured.operation.keyEpoch !== keyEpoch && keyEpoch)) {
      fail("Stale sync key epoch", "sync_key_epoch_mismatch");
    }
    if (!resolved) fail("No authorized file key is available", "key_unavailable");
    return nativeBufferFrom(resolved);
  }

  // Restore by creating a NEW signed CAS update. A historical envelope is
  // untrusted until the existing incoming authority and AEAD checks accept it.
  async restoreHistoricalVersion(objectId, versionId) {
    return this.withMutationLock(() => this._restoreHistoricalVersion(objectId, versionId));
  }

  async _restoreHistoricalVersion(objectId, versionId) {
    if (!this.opened) await this._open();
    const journal = this.journal;
    const journalMethods = captureMethodSet(journal, HISTORICAL_JOURNAL_METHODS);
    const engineMethods = captureMethodSet(this, HISTORICAL_ENGINE_METHODS);
    const adapter = this.adapter;
    const adapterHistory = ownDataValue(adapter, "history");
    const adapterList = ownDataValue(adapter, "list");
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    const assertAdapterSnapshot = () => {
      if (this.adapter !== adapter || ownDataValue(adapter, "history") !== adapterHistory
        || ownDataValue(adapter, "list") !== adapterList || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate) {
        fail("Historical restore adapter identity changed during a callback",
          "historical_restore_callback_changed");
      }
    };
    const assertRestoreRuntime = () => {
      if (this.journal !== journal) {
        fail("Historical restore journal identity changed during a callback",
          "historical_restore_callback_changed");
      }
      assertMethodSet(journal, journalMethods);
      assertMethodSet(this, engineMethods);
      assertAdapterSnapshot();
    };
    const validId = (value) => typeof value === "string" && regexTest(/^[A-Za-z0-9._:-]{1,160}$/, value);
    if (!validId(objectId) || !validId(versionId)) fail("Invalid historical restore identifier", "invalid_restore_id");
    // Without separately provisioned physical witness and CURRENT CAS, do
    // not start a restore that could stage local bytes and strand its outbox.
    assertHistoricalRestorePhysicalAuthority(this);
    if (typeof adapterHistory !== "function" || typeof adapterList !== "function"
      || typeof adapterPush !== "function") fail("Sync history is unavailable", "history_unavailable");
    if ((await nativeReflectApply(journalMethods.recover, journal, [])).length) {
      fail("Sync pending writes must be settled before restore", "sync_operation_pending");
    }
    assertRestoreRuntime();
    const historyResult = await nativeReflectApply(adapterHistory, adapter, [objectId]);
    assertRestoreRuntime();
    const historySource = snapshotArrayOfData(ownDataValue(historyResult, "versions"), "invalid_history");
    if (historySource.length < 1 || historySource.length > 256) {
      fail("Invalid historical version list", "invalid_history");
    }
    const versions = new NativeArray(historySource.length);
    for (let index = 0; index < historySource.length; index += 1) {
      versions[index] = protocol.validateStoredOperation(historySource[index]);
    }
    for (let index = 0; index < versions.length; index += 1) {
      if (versions[index].objectId !== objectId) {
        fail("History contains another object", "invalid_history");
      }
    }
    const selected = [];
    for (let index = 0; index < versions.length; index += 1) {
      if (versions[index].versionId === versionId) selected[selected.length] = versions[index];
    }
    if (selected.length !== 1 || selected[0].tombstone) fail("Restorable historical version not found", "history_version_unavailable");
    const remote = await nativeReflectApply(adapterList, adapter, [objectId]);
    assertRestoreRuntime();
    let records;
    if (nativeArrayIsArray(remote)) records = snapshotArrayOfData(remote, "invalid_history");
    else {
      const remoteObjects = ownDataValue(remote, "objects");
      if (nativeArrayIsArray(remoteObjects)) records = snapshotArrayOfData(remoteObjects, "invalid_history");
      else if (remote && typeof remote === "object") {
        records = new NativeArray(1);
        records[0] = remote;
      } else records = new NativeArray(0);
    }
    if (records.length !== 1) fail("Current sync version unavailable", "history_version_unavailable");
    const currentCandidate = protocol.validateStoredOperation(records[0]);
    const historicalCandidate = selected[0];
    if (currentCandidate.objectId !== objectId || currentCandidate.fileId !== historicalCandidate.fileId
      || currentCandidate.compartmentId !== historicalCandidate.compartmentId
      || signedEnvelopeDigest(versions[versions.length - 1]) !== signedEnvelopeDigest(currentCandidate)) {
      fail("Current signed version does not match history", "invalid_history");
    }
    // The selected historical source and current head cross verifier and key
    // resolver callbacks. Detach both signed envelopes before the first await.
    const currentCapture = captureSignedEnvelope(currentCandidate);
    const historicalCapture = captureSignedEnvelope(historicalCandidate);
    const current = currentCapture.operation;
    const historical = historicalCapture.operation;
    await nativeReflectApply(engineMethods.verifyIncomingOperation, this,
      [historical, { preObserve: false }]);
    assertRestoreRuntime();
    assertCapturedSignedEnvelope(historicalCapture);
    await nativeReflectApply(engineMethods.verifyIncomingOperation, this,
      [current, { preObserve: false }]);
    assertRestoreRuntime();
    assertCapturedSignedEnvelope(currentCapture);
    if (historical.metadata.contentType === "inode/directory"
      || (!current.tombstone && current.metadata.contentType === "inode/directory")) {
      fail("Directory restoration is not supported", "history_version_unavailable");
    }
    const relative = await canonicalRelativePath(this.rootDir, current.metadata.path);
    if (!this.isSelected(relative)) fail("Historical restore path is excluded", "path_not_selected");
    const existing = this.snapshot.files[relative];
    if (existing && !existing.deleted && (existing.objectId !== objectId || existing.fileId !== current.fileId)) {
      fail("Historical restore would overwrite a different local object", "restore_local_conflict");
    }
    const assertNoStaleLocalIdentity = () => {
      // A remote MOVE may be signed and current while our local snapshot still
      // tracks the same file at its old path. Restoring directly to the new
      // path would duplicate that identity instead of reconciling the MOVE.
      // fileId is not immutable across signed updates, so an old tracked
      // revision can retain the same objectId with a DIFFERENT fileId.
      const trackedEntries = nativeObjectEntries(this.snapshot.files);
      for (let index = 0; index < trackedEntries.length; index += 1) {
        const trackedPath = trackedEntries[index][0];
        const prior = trackedEntries[index][1];
        if (trackedPath !== relative && prior && !prior.deleted && prior.objectId === objectId) {
          fail("Historical restore requires local MOVE reconciliation", "restore_local_conflict");
        }
      }
    };
    assertNoStaleLocalIdentity();
    const destination = await contained(this.rootDir, relative, true);
    const assertCleanDestination = async () => {
      const present = await exists(destination);
      if (present && (!existing || existing.deleted)) {
        fail("Historical restore would overwrite an untracked local file", "restore_local_conflict");
      }
      if (existing && !existing.deleted) {
        // A tracked identity is not permission to overwrite unsent local edits
        // (including local deletion). Require the exact last-synchronized bytes.
        if (!present || existing.directory || !regexTest(/^[a-f0-9]{64}$/, existing.hash || "")) {
          fail("Historical restore requires a clean local file", "restore_local_conflict");
        }
        const actual = await readContainedFile(this.rootDir, relative);
        if (sha256Hex(actual) !== existing.hash) {
          fail("Historical restore would overwrite unsent local edits", "restore_local_conflict");
        }
      }
    };
    await assertCleanDestination();
    assertCapturedSignedEnvelope(historicalCapture);
    const key = await nativeReflectApply(engineMethods.keyFor, this, [historical]);
    assertRestoreRuntime();
    assertCapturedSignedEnvelope(historicalCapture);
    const decrypted = protocol.decryptPayload(historical, key);
    const plaintext = historical.operation === "move"
      ? protocol.decodeMovePayload(decrypted, key) : decrypted;
    if (plaintext === null) fail("Historical MOVE has no recoverable content", "history_version_unavailable");
    let restored;
    try {
      const { sourcePath: _oldMoveSource, ...historicalMetadata } = historical.metadata;
      const currentKeyCapture = captureSignedEnvelope({ ...current, keyEpoch: this.keyEpoch });
      const currentKey = await nativeReflectApply(engineMethods.keyFor, this, [currentKeyCapture.operation]);
      assertRestoreRuntime();
      assertCapturedSignedEnvelope(currentCapture);
      assertCapturedSignedEnvelope(historicalCapture);
      assertCapturedSignedEnvelope(currentKeyCapture);
      restored = await nativeReflectApply(engineMethods.buildOperation, this, [{ operation: "update", objectId, fileId: current.fileId,
        operationId: `histrestore-${nativeRandomUUID()}`,
        baseRevision: current.revision, revision: protocol.nextRevision(current.revision, this.deviceId),
        metadata: { ...historicalMetadata, path: relative, name: path.basename(relative), size: plaintext.length },
        plaintext, fileKey: currentKey }]);
      assertRestoreRuntime();
      assertCapturedSignedEnvelope(currentCapture);
      assertCapturedSignedEnvelope(historicalCapture);
    } finally { zeroBuffer(plaintext); }
    // Signing may await an external key provider. Recheck after that boundary,
    // before the signed outbox can cause a later remote write.
    await assertCleanDestination();
    assertNoStaleLocalIdentity();
    // The outbox is durable BEFORE local materialization. Failure to send is
    // recoverable by the existing signed journal; no old operation is replayed.
    await nativeReflectApply(engineMethods.assertOutgoingAuthorized, this, [restored, () => {
      assertRestoreRuntime();
      return nativeReflectApply(journalMethods.enqueue, journal, [restored]);
    }]);
    assertRestoreRuntime();
    try {
      await nativeReflectApply(engineMethods._apply, this,
        [restored, null, existing && !existing.deleted ? existing.hash : null]);
      assertRestoreRuntime();
    } catch (error) {
      if (ownDataValue(error, "code") === "restore_local_conflict") {
        assertRestoreRuntime();
        await nativeReflectApply(journalMethods.discardUnsent, journal, [restored]);
      }
      throw error;
    }
    // The already-fsynced physical materialization and snapshot precede a
    // separate exact-envelope durable journal observation. A later user edit
    // is NOT proof that this earlier signed restore was never materialized.
    await nativeReflectApply(journalMethods.recordRestoreMaterialization, journal, [restored]);
    assertRestoreRuntime();
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    await nativeReflectApply(engineMethods._pushPending, this, [summary]);
    assertRestoreRuntime();
    if (summary.offline) return { restored: true, pushed: false, pending: true,
      objectId, sourceVersionId: versionId, versionId: restored.versionId };
    // _pushPending has authenticated the physical CURRENT and committed our
    // local journal/snapshot. A server-controlled LIST cannot add evidence;
    // rejecting or accepting an ACK on LIST would reintroduce the same bug.
    return { restored: true, pushed: true, objectId, sourceVersionId: versionId,
      versionId: restored.versionId, operationId: restored.operationId };
  }

  async verifyIncomingOperation(operation, { preObserve = true } = {}) {
    const captured = captureSignedEnvelope(operation);
    operation = captured.operation;
    const digest = captured.digest;
    const journal = ownDataValue(this, "journal");
    const journalRecover = captureDataMethod(journal, "recover");
    const journalAssertCompatibleAdmission = captureDataMethod(journal, "assertCompatibleAdmission");
    const journalHasLocalAdmission = captureDataMethod(journal, "hasLocalAdmission");
    const journalObserveAdmission = captureDataMethod(journal, "observeAdmission");
    const adapter = ownDataValue(this, "adapter");
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    const authorize = ownDataValue(this, "authorize");
    const verifyIncoming = ownDataValue(this, "verifyIncoming");
    const requireAuthorization = ownDataValue(this, "requireAuthorization") === true;
    const keyEpoch = ownDataValue(this, "keyEpoch");
    const deviceId = ownDataValue(this, "deviceId");
    const compartmentId = ownDataValue(this, "compartmentId");
    const assertAdmissionSnapshot = () => {
      assertCapturedSignedEnvelope(captured);
      if (ownDataValue(this, "journal") !== journal
        || captureDataMethod(journal, "recover") !== journalRecover
        || captureDataMethod(journal, "assertCompatibleAdmission") !== journalAssertCompatibleAdmission
        || captureDataMethod(journal, "hasLocalAdmission") !== journalHasLocalAdmission
        || captureDataMethod(journal, "observeAdmission") !== journalObserveAdmission
        || this.adapter !== adapter || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate
        || ownDataValue(this, "authorize") !== authorize || ownDataValue(this, "verifyIncoming") !== verifyIncoming
        || ownDataValue(this, "requireAuthorization") !== requireAuthorization
        || ownDataValue(this, "keyEpoch") !== keyEpoch || ownDataValue(this, "deviceId") !== deviceId
        || ownDataValue(this, "compartmentId") !== compartmentId) {
        fail("Remote sync admission configuration changed during verification", "remote_authorization_rejected");
      }
    };
    // Strict mode is local policy, never a request-controlled proof opt-in.
    // Historical expiry is allowed only for a structurally bound SIGNED
    // record; the trusted verifier below must still check key and revocation.
    if (requireAuthorization) {
      if (!operation || !nativeObjectHasOwn(operation, "authorization")) {
        fail("Remote sync device authorization is required", "remote_authorization_rejected");
      }
      try { protocol.validateStoredOperation(operation); }
      catch { fail("Remote sync device authorization is invalid", "remote_authorization_rejected"); }
    }
    // A valid signer can sign two different envelopes using one operation ID.
    // Reject a conflicting identity BEFORE mutating the filesystem or snapshot.
    if (typeof journalAssertCompatibleAdmission !== "function") {
      fail("Sync admission journal is unavailable", "remote_authorization_rejected");
    }
    nativeReflectApply(journalAssertCompatibleAdmission, journal, [operation.operationId, digest]);
    // A remote LIST/materialization can race with an unsent signed local
    // operation. `markSeen` removes pending by ID: require the FULL exact
    // signed envelope match so an incoming same-ID variant cannot erase it.
    if (typeof journalRecover !== "function") fail("Sync admission journal is unavailable", "remote_authorization_rejected");
    const queuedOperations = await nativeReflectApply(journalRecover, journal, []);
    assertAdmissionSnapshot();
    for (let index = 0; index < queuedOperations.length; index += 1) {
      const queued = queuedOperations[index];
      if (queued.operationId !== operation.operationId) continue;
      let queuedDigest;
      try {
        queuedDigest = signedEnvelopeDigest(protocol.validateStoredOperation(queued));
      } catch {
        fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
      }
      if (queuedDigest !== digest) {
        fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
      }
    }
    if (!verifyIncoming) {
      if (requireAuthorization) fail("Remote sync authorization verifier is required", "remote_authorization_rejected");
      return null;
    }
    // Capture freshness before asynchronous verification and I/O. Successful
    // authentication can cross the expiry deadline before the journal fsync.
    const candidate = this.localAdmissionDigestIfFresh(operation);
    if (typeof journalHasLocalAdmission !== "function" || typeof authorize !== "function") {
      fail("Remote sync authorization callbacks are required", "remote_authorization_rejected");
    }
    const locallyAdmitted = nativeReflectApply(journalHasLocalAdmission, journal, [operation.operationId, digest]);
    if (await nativeReflectApply(verifyIncoming, undefined, [operation, { locallyAdmitted }]) !== true) {
      fail("Remote sync authorization rejected", "remote_authorization_rejected");
    }
    assertAdmissionSnapshot();
    // A well-signed remote envelope must not consume finite durable journal
    // capacity if this client does not authorize its operation at all.
    if (await nativeReflectApply(authorize, undefined, [operation]) !== true) {
      fail("Sync authorization rejected", "authorization_rejected");
    }
    assertAdmissionSnapshot();
    nativeReflectApply(journalAssertCompatibleAdmission, journal, [operation.operationId, digest]);
    if (candidate && preObserve) {
      if (typeof journalObserveAdmission !== "function") fail("Sync admission journal is unavailable", "remote_authorization_rejected");
      await nativeReflectApply(journalObserveAdmission, journal, [operation.operationId, candidate]);
      assertAdmissionSnapshot();
    }
    // The exact historical digest already pinned locally can complete its
    // observed->admitted transition after a crash, even after expiry. Never
    // derive this from operation-ID-only legacy `seen` entries.
    return candidate || (locallyAdmitted ? digest : null);
  }
  localAdmissionDigestIfFresh(operation) {
    return this.requireAuthorization && this.verifyIncoming && operation.authorization
        && nativeNumberIsSafeInteger(operation.authorization.expiresAt)
        && operation.authorization.expiresAt > this.clock()
      ? signedEnvelopeDigest(operation) : null;
  }

  isInScope(relativePath) {
    if (this.selectedPaths === null) return true;
    for (let index = 0; index < this.selectedPaths.length; index += 1) {
      if (pathWithin(relativePath, this.selectedPaths[index])) return true;
    }
    return false;
  }

  isExcluded(relativePath) {
    for (let index = 0; index < this.excludedPaths.length; index += 1) {
      if (pathWithin(relativePath, this.excludedPaths[index])) return true;
    }
    return false;
  }

  isSelected(relativePath) {
    return this.isInScope(relativePath) && !this.isExcluded(relativePath);
  }

  needsTraversal(relativePath) {
    if (this.isExcluded(relativePath)) return false;
    if (this.selectedPaths === null || this.isSelected(relativePath)) return true;
    for (let index = 0; index < this.selectedPaths.length; index += 1) {
      if (pathWithin(this.selectedPaths[index], relativePath)) return true;
    }
    return false;
  }

  operationIsSelected(operation) {
    const pathName = operation.metadata?.path;
    const sourcePath = operation.metadata?.sourcePath;
    if (typeof pathName !== "string" && typeof sourcePath !== "string") return false;
    return (typeof pathName !== "string" || this.isSelected(pathName))
      && (typeof sourcePath !== "string" || this.isSelected(sourcePath));
  }

  operationDestinationIsSelected(operation) {
    return typeof operation.metadata?.path === "string" && this.isSelected(operation.metadata.path);
  }

  async browseRemoteInventory({ limit = 64, cursor = null } = {}) {
    if (typeof this.adapter.listInventory !== "function") {
      fail("Metadata inventory is not supported by this sync adapter", "inventory_unavailable");
    }
    // Browsing is read-only and advisory. No remote-only pins, journal entries
    // or local files may be created from metadata without fetching and
    // independently verifying the complete signed envelope.
    const page = await this.adapter.listInventory({ limit, cursor });
    if (!page || !Array.isArray(page.objects)) fail("Invalid metadata inventory page", "invalid_inventory");
    return {
      ...page, advisory: true,
      objects: page.objects.map((record) => ({
        ...record, selectedOnDevice: this.operationDestinationIsSelected(record),
      })),
    };
  }

  rememberRemoteOnly(operation, reason, options = {}) {
    const pathName = operation.metadata?.path;
    if (!pathName) return;
    const prior = this.snapshot.remoteOnly[operation.objectId] || {};
    this.snapshot.remoteOnly[operation.objectId] = {
      objectId: operation.objectId,
      fileId: operation.fileId,
      versionId: operation.versionId,
      revision: operation.revision,
      path: pathName,
      ...(operation.metadata.sourcePath ? { sourcePath: operation.metadata.sourcePath } : {}),
      directory: operation.metadata.contentType === "inode/directory" || options.directory === true || prior.directory === true,
      deleted: Boolean(operation.tombstone || operation.operation === "delete"),
      reason: prior.reason === "evicted" ? "evicted" : reason,
      ...(prior.hash ? { hash: prior.hash } : {}),
    };
  }

  async reconcileOutOfScopeMove(operation, summary, options = {}) {
    // No pull/reconciliation entry point may separately advance a member of
    // a locally durable signed DELETE+MOVE remote transaction. A partial LIST
    // or out-of-scope sweep is not a two-envelope atomic admission receipt.
    if (nativeObjectKeys(this.journal.atomicSignedGroups?.() || {}).length) {
      fail("Cannot reconcile remote changes while an atomic WebDAV batch is pending",
        "sync_atomic_batch_indeterminate");
    }
    const tombstone = Boolean(operation.tombstone || operation.operation === "delete");
    const directoryMove = operation.operation === "update" && operation.metadata?.contentType === "inode/directory";
    if ((operation.operation !== "move" && !directoryMove && !tombstone)
      || typeof operation.metadata?.path !== "string" || this.isSelected(operation.metadata.path)) return false;
    if (!tombstone && !directoryMove && !operation.metadata?.sourcePath) return false;

    let sourcePath;
    if (tombstone) {
      sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path)
        || activeFileIdentityPath(this.snapshot.files, operation, operation.metadata.path);
    } else if (directoryMove) {
      sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path);
    } else {
      sourcePath = activeFileIdentityPath(this.snapshot.files, operation, operation.metadata.path)
        || (this.snapshot.files[operation.metadata.sourcePath]?.objectId === operation.objectId
        && this.snapshot.files[operation.metadata.sourcePath]?.fileId === operation.fileId
        && !this.snapshot.files[operation.metadata.sourcePath]?.deleted
        && !this.snapshot.files[operation.metadata.sourcePath]?.directory
        ? operation.metadata.sourcePath : null);
    }
    if (!sourcePath || !this.isSelected(sourcePath)) return false;

    const prior = this.snapshot.files[sourcePath];
    const directoryRecord = directoryMove || (tombstone && Boolean(prior?.directory));
    if (!prior || prior.deleted || Boolean(prior.directory) !== directoryRecord
      || prior.objectId !== operation.objectId || prior.fileId !== operation.fileId) return false;

    const recoveredPending = await this.journal.recover();
    const pending = [];
    for (let index = 0; index < recoveredPending.length; index += 1) {
      const item = recoveredPending[index];
      if (item.protocolVersion && item.objectId === operation.objectId) {
        nativeReflectApply(nativeArrayPush, pending, [item]);
      }
    }
    const target = await contained(this.rootDir, sourcePath, true);
    const sourceExists = await exists(target);
    let changedLocally = false;
    if (sourceExists) {
      const stats = await fsp.lstat(target, { bigint: true });
      if (stats.isSymbolicLink() || (directoryRecord ? !stats.isDirectory() : !stats.isFile())) {
        fail("Tracked sync source has an unexpected type", "unsafe_path");
      }
      if (directoryRecord) {
        const currentFiles = await this.scanFiles();
        const snapshotEntries = nativeObjectEntries(this.snapshot.files);
        const trackedEntries = [];
        const trackedKeys = [];
        for (let index = 0; index < snapshotEntries.length; index += 1) {
          const relativePath = snapshotEntries[index][0];
          const item = snapshotEntries[index][1];
          if (!item.deleted && pathWithin(relativePath, sourcePath)) {
            nativeReflectApply(nativeArrayPush, trackedEntries, [[relativePath, item]]);
            nativeReflectApply(nativeArrayPush, trackedKeys, [pathKey(relativePath)]);
          }
        }
        for (let index = 0; index < trackedEntries.length; index += 1) {
          const relativePath = trackedEntries[index][0];
          const item = trackedEntries[index][1];
          const currentPath = canonicalMapPath(relativePath, currentFiles);
          const current = currentFiles[currentPath];
          if (!current || current.hash !== item.hash || Boolean(current.directory) !== Boolean(item.directory)) changedLocally = true;
        }
        const currentKeys = nativeObjectKeys(currentFiles);
        for (let index = 0; index < currentKeys.length; index += 1) {
          const relativePath = currentKeys[index];
          if (pathWithin(relativePath, sourcePath)
            && !nativeReflectApply(nativeArrayIncludes, trackedKeys, [pathKey(relativePath)])) {
            changedLocally = true;
            break;
          }
        }
      } else {
        const bytes = await readContainedFile(this.rootDir, sourcePath, stats);
        changedLocally = sha256Hex(bytes) !== prior.hash;
      }
    }

    const hasLocalConflict = changedLocally || pending.length > 0;
    if (hasLocalConflict) {
      for (const item of pending) {
        if (item.protocolVersion && !nativeReflectApply(nativeArrayIncludes,
          options.preservedOperationIds || [], [item.operationId])) await this.recoverConflict(item, summary);
      }
      if (sourceExists && !directoryRecord) {
        const conflictRoot = path.join(this.rootDir, ".rootark-conflicts");
        await fsp.mkdir(conflictRoot, { recursive: true });
        await containedAbsolute(this.rootDir, conflictRoot, false);
      const operationKey = stringSlice(sha256Hex(operation.operationId), 0, 16);
        const conflictPath = path.join(conflictRoot, `${operationKey}-${nativeRandomUUID()}.local.conflict`);
        await containedAbsolute(this.rootDir, conflictPath, true);
        await fsp.rename(target, conflictPath);
      }
      if (!directoryRecord && !nativeReflectApply(nativeArrayIncludes,
        options.preservedOperationIds || [], [operation.operationId])) await this.recoverConflict(operation, summary);
      summary.conflicts ||= [];
      let conflictAlreadyPresent = false;
      for (let index = 0; index < summary.conflicts.length; index += 1) {
        if (summary.conflicts[index].operationId === operation.operationId) {
          conflictAlreadyPresent = true;
          break;
        }
      }
      if (!options.conflictAlreadyRecorded && !conflictAlreadyPresent) {
        nativeReflectApply(nativeArrayPush, summary.conflicts, [{ operationId: operation.operationId,
          policy: "preserve-local-and-remote", reason: tombstone
            ? "remote-delete-outside-selected-scope" : "remote-move-outside-selected-scope" }]);
      }
    } else if (sourceExists) {
      if (!directoryRecord) {
        await this.stageExisting(target);
      } else if ((await fsp.readdir(target)).length === 0) {
        let hasActiveDescendant = false;
        const snapshotEntries = nativeObjectEntries(this.snapshot.files);
        for (let index = 0; index < snapshotEntries.length; index += 1) {
          const relativePath = snapshotEntries[index][0];
          const item = snapshotEntries[index][1];
          if (relativePath !== sourcePath && !item.deleted && pathWithin(relativePath, sourcePath)) {
            hasActiveDescendant = true;
            break;
          }
        }
        if (!hasActiveDescendant) await this.stageExisting(target);
      }
    }

    for (const relativePath of nativeObjectKeys(this.snapshot.files)) {
      if (pathsEqual(relativePath, sourcePath)) delete this.snapshot.files[relativePath];
    }
    this.rememberRemoteOnly(operation, "excluded", { directory: directoryRecord });
    for (const item of pending) await this.journal.markSeen(item.operationId);
    await this.pruneEmptyUntrackedParents(path.dirname(target));
    await this.persistSnapshot();
    return true;
  }

  async buildOperation(input) {
    const keyEpoch = ownDataValue(this, "keyEpoch");
    const deviceId = ownDataValue(this, "deviceId");
    const compartmentId = ownDataValue(this, "compartmentId");
    const fileKeyResolver = ownDataValue(this, "fileKeyResolver");
    const authorizationFactory = ownDataValue(this, "authorizationFactory");
    const adapter = ownDataValue(this, "adapter");
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    const requireAuthorization = ownDataValue(this, "requireAuthorization") === true;
    const assertBuildConfiguration = () => {
      if (ownDataValue(this, "keyEpoch") !== keyEpoch || ownDataValue(this, "deviceId") !== deviceId
        || ownDataValue(this, "compartmentId") !== compartmentId
        || ownDataValue(this, "fileKeyResolver") !== fileKeyResolver
        || ownDataValue(this, "authorizationFactory") !== authorizationFactory
        || this.adapter !== adapter || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate) {
        fail("Sync signing configuration changed during operation construction",
          "historical_restore_callback_changed");
      }
    };
    let key = input.fileKey;
    if (!key) {
      if (typeof fileKeyResolver !== "function") fail("No authorized file key resolver is available", "key_unavailable");
      key = await nativeReflectApply(fileKeyResolver, undefined, [input]);
      assertBuildConfiguration();
    }
    let operationInput = input;
    if (input.operation === "move") {
      let movePlaintext = input.plaintext;
      if (movePlaintext === undefined) {
        const target = await contained(this.rootDir, input.metadata?.path, false);
        const stats = await fsp.lstat(target, { bigint: true });
        if (stats.isFile()) movePlaintext = await readContainedFile(this.rootDir, input.metadata?.path, stats);
        else if (!stats.isDirectory()) fail("Sync move source must be a regular file or directory", "unsafe_path");
      }
      if (movePlaintext !== undefined) operationInput = { ...input, plaintext: protocol.encodeMovePayload(movePlaintext, key) };
    }
    const operation = protocol.createOperation({
      ...operationInput,
      deviceId: input.deviceId || deviceId,
      keyEpoch: input.keyEpoch || keyEpoch,
      compartmentId: input.compartmentId || compartmentId,
      operationId: input.operationId || nativeRandomUUID(),
      fileKey: key,
    });
    const unsignedCapture = captureSignedEnvelope(operation);
    await this.assertOutgoingAuthorized(unsignedCapture.operation);
    assertCapturedSignedEnvelope(unsignedCapture);
    assertBuildConfiguration();
    if (!authorizationFactory) {
      if (requireAuthorization) fail("Device authorization is required", "authorization_required");
      return unsignedCapture.operation;
    }
    let authorization;
    try { authorization = await nativeReflectApply(authorizationFactory, undefined, [unsignedCapture.operation]); }
    catch { fail("Device authorization signing failed", "authorization_required"); }
    assertCapturedSignedEnvelope(unsignedCapture);
    assertBuildConfiguration();
    let detachedAuthorization;
    try {
      detachedAuthorization = nativeJsonParse(canonicalJson(authorization));
      deepFreezeJson(detachedAuthorization);
    } catch {
      fail("Device authorization proof could not be detached safely", "authorization_required");
    }
    const signedOperation = protocol.validateOperation({
      ...unsignedCapture.operation,
      authorization: detachedAuthorization,
    });
    const signedCapture = captureSignedEnvelope(signedOperation);
    // Signing can await an external key provider. Revocation after the initial
    // check must stop the signed operation before it reaches the journal.
    await this.assertOutgoingAuthorized(signedCapture.operation);
    assertCapturedSignedEnvelope(signedCapture);
    assertBuildConfiguration();
    return signedCapture.operation;
  }

  async assertOutgoingAuthorized(operation, authorizedAction = null) {
    const authorizeOutgoing = ownDataValue(this, "authorizeOutgoing");
    const currentDeviceAuthorization = ownDataValue(this, "currentDeviceAuthorization");
    const requireCurrentOutgoingAuthorization = ownDataValue(this, "requireCurrentOutgoingAuthorization") === true;
    const requireAuthorization = ownDataValue(this, "requireAuthorization") === true;
    const keyEpoch = ownDataValue(this, "keyEpoch");
    const deviceId = ownDataValue(this, "deviceId");
    const compartmentId = ownDataValue(this, "compartmentId");
    const adapter = ownDataValue(this, "adapter");
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    if (typeof authorizeOutgoing !== "function") fail("Local sync authorization callback is unavailable", "authorization_required");
    const assertAuthorizationConfiguration = () => {
      if (ownDataValue(this, "authorizeOutgoing") !== authorizeOutgoing
        || ownDataValue(this, "currentDeviceAuthorization") !== currentDeviceAuthorization
        || ownDataValue(this, "requireCurrentOutgoingAuthorization") !== requireCurrentOutgoingAuthorization
        || ownDataValue(this, "requireAuthorization") !== requireAuthorization
        || ownDataValue(this, "keyEpoch") !== keyEpoch || ownDataValue(this, "deviceId") !== deviceId
        || ownDataValue(this, "compartmentId") !== compartmentId
        || this.adapter !== adapter || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate) {
        fail("Sync authorization configuration changed during admission", "historical_restore_callback_changed");
      }
    };
    let locallyAuthorized;
    try { locallyAuthorized = await nativeReflectApply(authorizeOutgoing, undefined, [operation]); } catch {
      fail("Local sync authorization rejected", "authorization_rejected");
    }
    assertAuthorizationConfiguration();
    if (locallyAuthorized !== true) {
      fail("Local sync authorization rejected", "authorization_rejected");
    }
    if (requireCurrentOutgoingAuthorization && operation.deviceId !== deviceId) {
      fail("Local sync device authorization rejected", "authorization_rejected");
    }
    if (currentDeviceAuthorization) {
      let currentDecision;
      try { currentDecision = nativeReflectApply(currentDeviceAuthorization, undefined, [operation]); } catch {
        fail("Current sync device authorization rejected", "authorization_rejected");
      }
      assertAuthorizationConfiguration();
      if (requireCurrentOutgoingAuthorization) {
        // Strict mode must use a synchronous, operator-trusted current policy.
        // Awaiting even a resolved Promise would let a queued microtask revoke
        // the device between reading true and beginning the HTTP PUT.
        const isAsyncDecision = currentDecision !== null
          && (typeof currentDecision === "object" || typeof currentDecision === "function");
        if (isAsyncDecision) {
          if (nativeIsPromise(currentDecision)) {
            nativeReflectApply(nativePromiseCatch, currentDecision, [() => {}]);
          }
          fail("Synchronous current device authorization is required", "authorization_required");
        }
        if (currentDecision !== true) {
          fail("Current sync device authorization rejected", "authorization_rejected");
        }
      } else if (await currentDecision !== true) {
        // Backward compatibility for explicitly non-strict integrations.
        fail("Current sync device authorization rejected", "authorization_rejected");
      }
      assertAuthorizationConfiguration();
    }
    // Local journals and translation callbacks are NOT an authorization
    // authority. Enforce the mandatory signed-envelope boundary at every
    // action (journal enqueue or HTTP dispatch), not just during creation.
    // Build-time pre-sign current-device checks intentionally have no action.
    if (authorizedAction && requireAuthorization) {
      const authorization = ownDataValue(operation, "authorization");
      const expiresAt = ownDataValue(authorization, "expiresAt");
      if (!nativeNumberIsSafeInteger(expiresAt) || expiresAt <= this.clock()) {
        fail("Fresh outgoing sync device authorization is required", "authorization_expired");
      }
      try { protocol.validateFreshSignedOperation(operation); }
      catch { fail("Fresh outgoing sync device authorization is required",
        "authorization_required"); }
    }
    // No await after the strict synchronous policy + signed-envelope checks.
    // HTTP dispatch runs here, before a queued revocation microtask can run.
    if (authorizedAction) return authorizedAction();
  }

  async enqueueChange(input) {
    return this.withMutationLock(() => this._enqueueChange(input));
  }

  async _enqueueChange(input) {
    if (!this.opened) await this._open();
    const remoteOnly = this.snapshot.remoteOnly[input.objectId];
    if (remoteOnly?.reason === "evicted") fail("Materialize a remote-only file before enqueuing changes", "remote_only_object");
    const key = input.fileKey || await this.fileKeyResolver(input);
    const operation = captureSignedEnvelope(protocol.validateOperation(
      await this.buildOperation({ ...input, fileKey: key }),
    )).operation;
    await this.assertOutgoingAuthorized(operation, () => this.journal.enqueue(operation));
    let hash;
    if (operation.operation === "move") {
      const plaintext = protocol.decodeMovePayload(protocol.decryptPayload(operation, key), key);
      if (plaintext !== null) hash = sha256Hex(plaintext);
    }
    this.rememberOperation(operation, hash);
    await this.persistSnapshot();
    return operation;
  }

  async translateWebDavMutation(event) {
    if (!this.opened) await this.open();
    if (!event || typeof event !== "object" || nativeIsProxy(event)) {
      fail("WebDAV mutation must be a non-proxy data object", "invalid_webdav_mutation");
    }
    const eventOperationId = ownDataValue(event, "operationId");
    const kind = ownDataValue(event, "kind");
    const eventSource = ownDataValue(event, "source");
    const eventPath = ownDataValue(event, "path");
    const eventDestination = ownDataValue(event, "destination");
    if (typeof eventOperationId !== "string" || !eventOperationId) {
      fail("WebDAV mutation id is required", "invalid_webdav_mutation");
    }
    if (typeof kind !== "string" || !nativeReflectApply(nativeArrayIncludes,
      ["put", "move", "delete"], [kind])) {
      fail("Unsupported WebDAV mutation", "invalid_webdav_mutation");
    }
    const operationPrefixes = [`webdav-${eventOperationId}-`, `webdavsolo-${eventOperationId}-`];
    const recoveredForEvent = await this.journal.recover();
    const pendingForEvent = [];
    for (let index = 0; index < recoveredForEvent.length; index += 1) {
      const operation = recoveredForEvent[index];
      const operationId = ownDataValue(operation, "operationId");
      if (typeof operationId !== "string") continue;
      let matchesPrefix = false;
      for (let prefixIndex = 0; prefixIndex < operationPrefixes.length; prefixIndex += 1) {
        if (stringStartsWith(operationId, operationPrefixes[prefixIndex])) {
          matchesPrefix = true;
          break;
        }
      }
      if (matchesPrefix) nativeReflectApply(nativeArrayPush, pendingForEvent, [operation]);
    }
    if (pendingForEvent.length) return pendingForEvent;
    const journalState = ownDataValue(this.journal, "state");
    const seen = ownDataValue(journalState, "seen");
    if (nativeArrayIsArray(seen)) {
      for (let index = 0; index < seen.length; index += 1) {
        const descriptor = nativeObjectGetOwnPropertyDescriptor(seen, `${index}`);
        if (!descriptor || !nativeObjectHasOwn(descriptor, "value")) {
          fail("WebDAV mutation journal seen list is ambiguous", "invalid_sync_journal");
        }
        const operationId = descriptor.value;
        if (typeof operationId !== "string") continue;
        for (let prefixIndex = 0; prefixIndex < operationPrefixes.length; prefixIndex += 1) {
          if (stringStartsWith(operationId, operationPrefixes[prefixIndex])) return [];
        }
      }
    }
    const requestedSourcePath = normalizeWebDavPath(eventSource || eventPath);
    const requestedDestinationPath = normalizeWebDavPath(eventDestination || eventPath || eventSource);
    const current = await this.scanFiles();
    const snapshotFiles = { ...this.snapshot.files };
    for (const pending of await this.journal.recover()) {
      if (!pending.protocolVersion || pending.journalType) continue;
      const relativePath = pending.metadata?.path;
      if (!relativePath) continue;
      const source = pending.operation === "move" ? pending.metadata.sourcePath
        : (pending.operation === "update" && pending.metadata.contentType === "inode/directory"
          ? activeIdentityPath(snapshotFiles, pending, relativePath) : null);
      const prior = source
        ? snapshotFiles[source] || (source === relativePath ? snapshotFiles[relativePath] : null) || {}
        : snapshotFiles[relativePath] || {};
      if (source && source !== relativePath) delete snapshotFiles[source];
      snapshotFiles[relativePath] = {
        ...prior,
        objectId: pending.objectId,
        fileId: pending.fileId,
        versionId: pending.versionId,
        revision: pending.revision,
        deleted: Boolean(pending.tombstone || pending.operation === "delete"),
        directory: pending.metadata.contentType === "inode/directory"
          || ((pending.operation === "move" || pending.operation === "delete") && Boolean(prior.directory)),
      };
    }
    const sourcePath = canonicalMapPath(requestedSourcePath, snapshotFiles, current);
    const destinationPath = canonicalMapPath(requestedDestinationPath, current, snapshotFiles);
    const operations = [];
    const mappedSourcePaths = new NativeSet();
    const stableOperationId = (verbAndPath) => {
      // Standalone DELETE has distinct Ed25519-bound ID namespace. A legacy
      // `webdav-` DELETE alone is ambiguous with a displaced-target tombstone
      // from an atomic overwrite and must never be pushed by itself after a
      // local journal manifest was deleted/corrupted. The same applies to an
      // orphaned atomic MOVE if its DELETE and group manifest were stripped.
      const soloDelete = kind === "delete" && stringStartsWith(verbAndPath, "delete:");
      const soloMove = kind === "move" && !event.previousDestinationIdentity
        && stringStartsWith(verbAndPath, "move:");
    return `${soloDelete || soloMove ? "webdavsolo" : "webdav"}-${event.operationId}-${stringSlice(sha256Hex(verbAndPath), 0, 24)}`;
    };
    const identityFor = (relativePath, prior) => {
      const deletedPrior = snapshotFiles[relativePath]?.deleted ? snapshotFiles[relativePath] : null;
      const identitySeed = deletedPrior ? nativeReflectApply(nativeStringReplace, nativeRandomUUID(), [/-/g, ""])
      : stringSlice(sha256Hex(relativePath), 0, 32);
      return {
        objectId: prior?.objectId || `object-${identitySeed}`,
        fileId: prior?.fileId || `file-${identitySeed}`,
      };
    };
    const buildForPath = async ({ operation, relativePath, source, prior, content, directory }) => {
      const identity = identityFor(relativePath, prior);
      const fileContext = { ...prior, ...identity, path: source || relativePath, keyEpoch: this.keyEpoch };
      const fileKey = await this.fileKeyResolver(fileContext);
      if (!fileKey) fail("No authorized file key is available", "key_unavailable");
      const baseRevision = prior?.revision || null;
      const revision = { counter: (baseRevision?.counter || 0) + 1, deviceId: this.deviceId };
      const metadata = operation === "delete"
        ? { path: relativePath }
        : operation === "move"
          ? { path: relativePath, sourcePath: source }
          : { path: relativePath, name: path.posix.basename(relativePath), size: content.length, ...(directory ? { contentType: "inode/directory" } : {}) };
      return protocol.validateOperation(await this.buildOperation({
        operation,
        objectId: identity.objectId,
        fileId: identity.fileId,
        versionId: nativeRandomUUID(),
        operationId: stableOperationId(`${operation}:${relativePath}`),
        baseRevision,
        revision,
        metadata,
        plaintext: operation === "delete" ? undefined : content,
        fileKey,
      }));
    };

    if (kind === "delete") {
      const deletedPaths = [];
      const snapshotEntries = nativeObjectEntries(snapshotFiles);
      for (let index = 0; index < snapshotEntries.length; index += 1) {
        const relativePath = snapshotEntries[index][0];
        const prior = snapshotEntries[index][1];
        if (pathWithin(relativePath, sourcePath) && !prior.deleted) {
          nativeReflectApply(nativeArrayPush, deletedPaths, [{ relativePath, prior }]);
        }
      }
      nativeReflectApply(nativeArraySort, deletedPaths, [(left, right) =>
        stringSplit(right.relativePath, "/").length - stringSplit(left.relativePath, "/").length]);
      for (const { relativePath, prior } of deletedPaths) {
        operations.push(await buildForPath({ operation: "delete", relativePath, prior }));
      }
      return operations;
    }

    let destinationStats;
    if (kind === "move") {
      await contained(this.rootDir, sourcePath, true);
      const destinationTarget = await contained(this.rootDir, destinationPath, false);
      destinationStats = await fsp.lstat(destinationTarget);
      if (destinationStats.isDirectory()) {
    for (const [priorPath, prior] of nativeObjectEntries(snapshotFiles)) {
          if (!pathWithin(priorPath, sourcePath) || prior.deleted || !prior.directory) continue;
        const suffix = priorPath === sourcePath ? "" : stringSlice(priorPath, sourcePath.length);
          const mappedPath = `${destinationPath}${suffix}`;
          if (current[mappedPath]) continue;
          const mappedTarget = await contained(this.rootDir, mappedPath, true);
          if (await exists(mappedTarget) && (await fsp.lstat(mappedTarget)).isDirectory()) current[mappedPath] = { size: 0, directory: true };
        }
      }
    }

    if (kind === "put" || destinationStats?.isFile()) {
      const relativePath = destinationPath;
      const file = current[relativePath];
      if (!file || file.directory) fail("WebDAV file mutation is missing its destination", "unsafe_path");
      const priorSource = kind === "move" ? snapshotFiles[sourcePath] : null;
      const priorDestination = snapshotFiles[relativePath];
      const sourceIsActive = priorSource && !priorSource.deleted;
      const destinationIsActive = priorDestination && !priorDestination.deleted;
      const content = await readContainedFile(this.rootDir, relativePath);
      if (sourceIsActive && destinationIsActive
        && (priorSource.objectId !== priorDestination.objectId || priorSource.fileId !== priorDestination.fileId)) {
        nativeReflectApply(nativeSetAdd, mappedSourcePaths, [sourcePath]);
        operations.push(await buildForPath({ operation: "delete", relativePath, prior: priorDestination }));
        operations.push(await buildForPath({ operation: "move", relativePath, source: sourcePath, prior: priorSource, content, directory: false }));
      } else {
        const prior = sourceIsActive ? priorSource : (destinationIsActive ? priorDestination : null);
        if (sourceIsActive && !priorSource.directory) nativeReflectApply(nativeSetAdd, mappedSourcePaths, [sourcePath]);
        const operation = kind === "move" && sourceIsActive && !priorSource.directory
          ? "move"
          : prior ? "update" : "create";
        operations.push(await buildForPath({ operation, relativePath, source: operation === "move" ? sourcePath : null, prior, content, directory: false }));
      }
    } else if (kind === "move" && destinationStats?.isDirectory()) {
      const destinationTypes = {};
      const walkTypes = async (relativePath) => {
        const target = await contained(this.rootDir, relativePath, false);
        const stats = await fsp.lstat(target);
        destinationTypes[relativePath] = stats.isDirectory();
        if (!stats.isDirectory()) return;
        for (const entry of await fsp.readdir(target, { withFileTypes: true })) {
          const childPath = `${relativePath}/${entry.name}`;
          try { protocol.safeRelativePath(childPath, "path"); } catch { continue; }
          await containedAbsolute(this.rootDir, path.join(target, entry.name), false);
          if (entry.isDirectory()) await walkTypes(childPath);
          else if (entry.isFile()) destinationTypes[childPath] = false;
        }
      };
      await walkTypes(destinationPath);
      const priorDescendantPaths = new NativeSet();
    for (const [priorPath, prior] of nativeObjectEntries(snapshotFiles)) {
        if (!pathWithin(priorPath, destinationPath) || prior.deleted) continue;
        let ancestor = path.posix.dirname(priorPath);
        while (ancestor !== "." && pathWithin(ancestor, destinationPath)) {
          nativeReflectApply(nativeSetAdd, priorDescendantPaths, [ancestor]);
          if (ancestor === destinationPath) break;
          ancestor = path.posix.dirname(ancestor);
        }
      }
    for (const [relativePath, currentType] of nativeObjectEntries(destinationTypes)) {
        if (!pathWithin(relativePath, destinationPath)) continue;
        const prior = snapshotFiles[relativePath];
        const priorIsActive = prior && !prior.deleted;
        const priorHasActiveChildren = nativeReflectApply(nativeSetHas, priorDescendantPaths, [relativePath]);
        if (!priorIsActive && !priorHasActiveChildren) continue;
        const priorType = Boolean(priorIsActive && prior.directory) || priorHasActiveChildren;
        if (priorType !== currentType) {
          throw nativeObjectAssign(new Error("Cannot overwrite a nested file with a collection or vice versa"), { statusCode: 409, code: "webdav_type_conflict" });
        }
      }

      const movedPaths = [];
      const currentKeys = nativeObjectKeys(current);
      for (let index = 0; index < currentKeys.length; index += 1) {
        const relativePath = currentKeys[index];
        if (stringStartsWith(relativePath, `${destinationPath}/`)
          || (relativePath === destinationPath && current[relativePath].directory)) {
          nativeReflectApply(nativeArrayPush, movedPaths, [relativePath]);
        }
      }
      nativeReflectApply(nativeArraySort, movedPaths, [stringLocaleCompare]);
      const mappedDestinationPaths = new NativeSet();
      for (let index = 0; index < movedPaths.length; index += 1) {
        nativeReflectApply(nativeSetAdd, mappedDestinationPaths, [movedPaths[index]]);
      }
      const destinationDeletes = new NativeMap();
    for (const [relativePath, prior] of nativeObjectEntries(snapshotFiles)) {
        if (pathWithin(relativePath, destinationPath) && !prior.deleted
          && !nativeReflectApply(nativeSetHas, mappedDestinationPaths, [relativePath])) {
          nativeReflectApply(nativeMapSet, destinationDeletes, [relativePath, prior]);
        }
      }
      for (const relativePath of movedPaths) {
        if (!current[relativePath].directory) continue;
        const suffix = relativePath === destinationPath ? "" : stringSlice(relativePath, destinationPath.length);
        const priorSource = snapshotFiles[`${sourcePath}${suffix}`];
        const priorDestination = snapshotFiles[relativePath];
        if (priorSource && !priorSource.deleted && priorSource.directory
          && priorDestination && !priorDestination.deleted
          && (priorDestination.objectId !== priorSource.objectId || priorDestination.fileId !== priorSource.fileId)) {
          nativeReflectApply(nativeMapSet, destinationDeletes, [relativePath, priorDestination]);
        }
      }
      const orderedDestinationDeletes = [];
      nativeReflectApply(nativeMapForEach, destinationDeletes, [(prior, relativePath) => {
        nativeReflectApply(nativeArrayPush, orderedDestinationDeletes, [{ relativePath, prior }]);
      }]);
      nativeReflectApply(nativeArraySort, orderedDestinationDeletes, [(left, right) =>
        stringSplit(right.relativePath, "/").length - stringSplit(left.relativePath, "/").length
          || stringLocaleCompare(left.relativePath, right.relativePath)]);
      for (const { relativePath, prior } of orderedDestinationDeletes) {
        operations.push(await buildForPath({ operation: "delete", relativePath, prior }));
      }
      for (const relativePath of movedPaths) {
        const suffix = relativePath === destinationPath ? "" : stringSlice(relativePath, destinationPath.length);
        const oldPath = `${sourcePath}${suffix}`;
        const file = current[relativePath];
        const priorSource = snapshotFiles[oldPath];
        const priorDestination = snapshotFiles[relativePath];
        const sourceIsActive = priorSource && !priorSource.deleted;
        const destinationIsActive = priorDestination && !priorDestination.deleted;
        if (sourceIsActive) nativeReflectApply(nativeSetAdd, mappedSourcePaths, [oldPath]);

        if (file.directory) {
          if (sourceIsActive && priorSource.directory) {
            operations.push(await buildForPath({ operation: "update", relativePath, prior: priorSource, content: nativeBufferAlloc(0), directory: true }));
          } else {
            if (sourceIsActive) operations.push(await buildForPath({ operation: "delete", relativePath: oldPath, prior: priorSource }));
            const directoryPrior = destinationIsActive ? priorDestination : null;
            operations.push(await buildForPath({ operation: directoryPrior ? "update" : "create", relativePath, prior: directoryPrior, content: nativeBufferAlloc(0), directory: true }));
          }
          continue;
        }

        const content = await readContainedFile(this.rootDir, relativePath);
        if (sourceIsActive && destinationIsActive
          && (priorSource.objectId !== priorDestination.objectId || priorSource.fileId !== priorDestination.fileId)) {
          operations.push(await buildForPath({ operation: "delete", relativePath, prior: priorDestination }));
          operations.push(await buildForPath({ operation: "move", relativePath, source: oldPath, prior: priorSource, content, directory: false }));
        } else {
          const prior = sourceIsActive && !priorSource.directory ? priorSource : (destinationIsActive && !priorDestination.directory ? priorDestination : null);
          const operation = sourceIsActive && !priorSource.directory ? "move" : (prior ? "update" : "create");
          operations.push(await buildForPath({ operation, relativePath, source: operation === "move" ? oldPath : null, prior, content, directory: false }));
        }
      }
    for (const [oldPath, prior] of nativeObjectEntries(snapshotFiles)) {
        if (!pathWithin(oldPath, sourcePath) || prior.deleted
          || nativeReflectApply(nativeSetHas, mappedSourcePaths, [oldPath])) continue;
        operations.push(await buildForPath({ operation: "delete", relativePath: oldPath, prior }));
      }
    } else {
      fail("WebDAV move destination is not a regular file or directory", "unsafe_path");
    }

    return operations;
  }

  async retryPush(operation, guard = null) {
    let lastError;
    const assertOutgoingAuthorized = captureDataMethod(this, "assertOutgoingAuthorized");
    const maxRetries = this.maxRetries;
    for (let attempt = 0; attempt < maxRetries; attempt += 1) {
      // The journal's prior authorization is not a live device grant. Check
      // again on EVERY attempt, after all queue/retry waits, before HTTP PUT.
      // An in-flight request still needs independent server-side revocation
      // fencing in the atomic PUT transaction.
      let result;
      try {
        result = await nativeReflectApply(assertOutgoingAuthorized, this, [operation, () => {
          guard?.beforeDispatch?.();
          if (typeof guard?.push === "function") return guard.push();
          return this.adapter.push(operation);
        }]);
        if (captureDataMethod(this, "assertOutgoingAuthorized") !== assertOutgoingAuthorized) {
          fail("Sync authorization method changed during retry", "authorization_required");
        }
      } catch (error) {
        guard?.afterAttempt?.();
        lastError = error;
        const errorCode = ownDataValue(error, "code");
        if (errorCode === "authorization_rejected" || errorCode === "authorization_required"
          || errorCode === "authorization_expired") throw error;
        if (!transient(error) || attempt + 1 === maxRetries) throw error;
        continue;
      }
      guard?.afterAttempt?.();
      return result;
    }
    throw lastError;
  }

  async recoverConflict(operation, summary) {
    if (operation.operation === "delete" || operation.tombstone) return;
    const key = await this.keyFor(operation);
    const decrypted = protocol.decryptPayload(operation, key);
    const plaintext = operation.operation === "move" ? (protocol.decodeMovePayload(decrypted, key) || decrypted) : decrypted;
    const conflictRoot = path.join(this.rootDir, ".rootark-conflicts");
    await fsp.mkdir(conflictRoot, { recursive: true });
    await containedAbsolute(this.rootDir, conflictRoot, false);
    const target = path.join(conflictRoot, `${operation.operationId}.conflict`);
    await containedAbsolute(this.rootDir, target, true);
    await fsp.writeFile(target, plaintext, { mode: 0o600 });
    summary.conflictRecovery = (summary.conflictRecovery || 0) + 1;
  }

  async pushPending(summary) {
    return this.withMutationLock(() => this._pushPending(summary));
  }

  assertHistoricalRestorePhysicalAuthority() {
    assertHistoricalRestorePhysicalAuthority(this);
  }

  assertHistoricalRestorePending(captured) {
    assertCapturedHistoricalRestorePending(this, captured);
  }

  async confirmHistoricalRestorePhysicalAdmission(captured) {
    assertHistoricalRestorePhysicalAuthority(this);
    const authority = captureHistoricalRestoreAuthority(this);
    assertCapturedHistoricalRestorePending(this, captured);
    // A client Ed25519 signature authenticates the request, not its fsync.
    // A fresh challenge goes directly to an independently pinned witness,
    // then a second nonce to a separate physical CURRENT CAS signer.
    const entry = captured.operation;
    // `entry` is the detached, frozen copy of the exact signed envelope.
    // Recheck its digest and pending identity around each untrusted readback.
    if (entry.operation !== "update" || !stringStartsWith(entry.operationId, "histrestore-")
      || !entry.authorization) {
      fail("Historical restore operation identity is invalid",
        "restore_remote_admission_unproven");
    }
    const witnessNonce = randomBase64Url(32);
    let signedWitness;
    try {
      const witnessReadback = await nativeReflectApply(authority.witnessReadback, undefined, [{
        scope: authority.scope,
        accountId: authority.ownerIdentity.accountId,
        storeId: authority.ownerIdentity.storeId,
        nonce: witnessNonce,
        operationIds: [captured.operationId],
        envelopeDigests: [captured.digest],
      }]);
      assertCapturedHistoricalRestorePending(this, captured);
      assertHistoricalRestoreAuthoritySnapshot(this, authority);
      signedWitness = nativeJsonParse(canonicalJson(witnessReadback));
      if (signedWitness?.statement?.nonce !== witnessNonce) throw new Error("Witness replay");
      verifyAtomicBatchAdmission({ atomicAdmission: signedWitness }, [entry],
        authority.witnessPublicKey, authority.scope, authority.ownerIdentity, true);
      assertCapturedHistoricalRestorePending(this, captured);
      assertHistoricalRestoreAuthoritySnapshot(this, authority);
    } catch {
      fail("Historical restore has no independently signed physical admission",
        "restore_remote_admission_unproven");
    }
    const physical = signedWitness.statement;
    const casNonce = randomBase64Url(32);
    try {
      const floor = await nativeReflectApply(authority.casFloorReadback, undefined, [{
        scope: authority.scope,
        accountId: authority.ownerIdentity.accountId,
        storeId: authority.ownerIdentity.storeId,
        nonce: casNonce, commitId: physical.commitId,
        storeHeadSha256: physical.storeHeadSha256,
        fencingEpoch: physical.fencingEpoch,
      }]);
      assertCapturedHistoricalRestorePending(this, captured);
      assertHistoricalRestoreAuthoritySnapshot(this, authority);
      verifyAtomicBatchCasFloor(floor, physical, authority.casFloorPublicKey,
        authority.scope, casNonce, authority.ownerIdentity, true);
      assertCapturedHistoricalRestorePending(this, captured);
      assertHistoricalRestoreAuthoritySnapshot(this, authority);
    } catch {
      fail("Historical restore has no independently signed CURRENT physical head",
        "restore_remote_admission_unproven");
    }
    assertCapturedHistoricalRestorePending(this, captured);
  }

  async pushAtomicSignedOverwritePair(pending, summary) {
    if (!this.requireAuthorization || !this.requireCurrentOutgoingAuthorization
      || typeof this.currentDeviceAuthorization !== "function"
      || typeof this.adapter.pushBatch !== "function"
      || typeof this.journal.markSeenMany !== "function"
      || !this.atomicBatchWitnessPublicKey
      || !this.atomicBatchWitnessReadback || !this.atomicBatchWitnessScope
      || !this.atomicBatchOwnerIdentity
      || !this.atomicBatchCasFloorPublicKey || !this.atomicBatchCasFloorReadback) {
      fail("Atomic protected WebDAV remote batch transport unavailable",
        "sync_atomic_batch_unavailable");
    }
    // A persisted batch can be older than the device grant that admitted it.
    // Historical readback MUST NOT turn an expired/revoked grant into a new
    // POST. Structural validation is enough to identify immutable bytes for
    // an independently signed physical witness; live policy is still required
    // by assertOutgoingAuthorized before EVERY new network write.
    const deleted = protocol.validateStoredOperation(pending[0]);
    const moved = protocol.validateStoredOperation(pending[1]);
    if (!deleted.authorization || !moved.authorization) {
      fail("Atomic protected WebDAV batch lacks original signed envelopes",
        "sync_atomic_batch_indeterminate");
    }
    assertAtomicSignedOverwritePair(deleted, moved);
    if (!this.operationIsSelected(deleted) || !this.operationIsSelected(moved)) {
      fail("Atomic WebDAV destination selection cannot split the batch",
        "sync_atomic_batch_unavailable");
    }
    const digests = [signedEnvelopeDigest(deleted), signedEnvelopeDigest(moved)];
    const currentDeviceAuthorization = ownDataValue(this, "currentDeviceAuthorization");
    let response;
    const expiredBeforeRequest = !nativeNumberIsSafeInteger(deleted.authorization.expiresAt)
      || deleted.authorization.expiresAt <= this.clock()
      || !nativeNumberIsSafeInteger(moved.authorization.expiresAt)
      || moved.authorization.expiresAt <= this.clock();
    let uncertainRequest = expiredBeforeRequest
      ? nativeObjectAssign(new Error("Historical signed batch requires read-only witness"),
        { code: "authorization_required" }) : null;
    if (!expiredBeforeRequest) try {
      // The second member's async authorizeOutgoing() can outlive the first
      // member's expiry or current revocation decision. Recheck BOTH signed
      // envelopes and the synchronous owner-trusted policy in one no-await
      // window immediately before beginning the single remote batch POST.
      const dispatchIfBothStillFresh = () => {
        const members = [deleted, moved];
        for (let index = 0; index < members.length; index += 1) {
          const member = members[index];
          // Both grants must also remain fresh under the constructor-pinned
          // engine clock after the second asynchronous authorization. The
          // protocol's independently pinned native clock is an additional
          // check, not a replacement for this per-engine expiry barrier.
          if (!nativeNumberIsSafeInteger(member.authorization.expiresAt)
            || member.authorization.expiresAt <= this.clock()) {
            fail("Atomic batch member expired before dispatch", "authorization_required");
          }
          try { protocol.validateFreshSignedOperation(member); }
          catch { fail("Atomic batch member expired before dispatch", "authorization_required"); }
          let current;
      try {
        if (typeof currentDeviceAuthorization !== "function") throw new Error("missing current device policy");
        current = nativeReflectApply(currentDeviceAuthorization, undefined, [member]);
      }
          catch { fail("Atomic batch current device grant unavailable", "authorization_rejected"); }
          if (current !== true) {
        if (current !== null && (typeof current === "object" || typeof current === "function")
          && nativeIsPromise(current)) {
          nativeReflectApply(nativePromiseCatch, current, [() => {}]);
        }
            fail("Atomic batch device grant changed before dispatch", "authorization_rejected");
          }
        }
        return this.adapter.pushBatch([deleted, moved]);
      };
      // The final synchronous current-policy checks begin ONE network
      // request. Remote registry must fence BOTH signatures under one lock.
      response = await this.assertOutgoingAuthorized(deleted, () =>
        this.assertOutgoingAuthorized(moved, () =>
          dispatchIfBothStillFresh()));
    } catch (error) {
      // A 409 or a dropped ACK may mean the remote atomic transaction was
      // committed, or may mean neither write happened. A plain LIST echo of
      // the two envelopes proves neither signed server admission nor durable
      // physical custody. Never fabricate a successful pair ACK from LIST.
      // Preserve both pending until independently signed atomic admission
      // readback proves the exact pair; no remote-wins partial repair. A
      // genuine commit followed by a lost HTTP ACK can return 409 on retry.
      // That must be checked with a fresh direct witness challenge, not kept
      // in a permanent 409 loop.
            if (transient(error) || nativeReflectApply(nativeArrayIncludes, [403, 409, 423, 503],
              [ownDataValue(error, "status")])
              || nativeReflectApply(nativeArrayIncludes, ["authorization_rejected", "authorization_required"],
                [ownDataValue(error, "code")])) {
        // Revocation and current-policy denial prohibit another write, not
        // the separate read-only verification of an old physical commit.
        // A remote denial after previous admission may also arrive after
        // an earlier lost ACK; only the separate witness can disambiguate.
        uncertainRequest = error;
      }
      else fail("Atomic signed WebDAV remote batch outcome indeterminate",
        "sync_atomic_batch_indeterminate");
    }
    if (!uncertainRequest) {
      if (!nativeArrayIsArray(response?.objects) || response.objects.length !== 2) {
        fail("Atomic signed WebDAV remote batch lacks exact two-envelope ACK", "sync_atomic_batch_indeterminate");
      }
      for (let index = 0; index < response.objects.length; index += 1) {
        let acknowledgedDigest;
        try { acknowledgedDigest = signedEnvelopeDigest(protocol.validateStoredOperation(response.objects[index])); }
        catch { fail("Atomic signed WebDAV remote batch lacks exact two-envelope ACK", "sync_atomic_batch_indeterminate"); }
        if (acknowledgedDigest !== digests[index]) {
          fail("Atomic signed WebDAV remote batch lacks exact two-envelope ACK", "sync_atomic_batch_indeterminate");
        }
      }
    }
    // A successful HTTP status (including an exact two-envelope echo) does
    // not authenticate remote fsync, CAS fencing, or physical admission.
    // In the absence of an independent signed durable witness, keep BOTH
    // original operations pending and never persist an invented success.
    // Fresh unpredictable challenge goes DIRECTLY to the independent witness
    // AFTER HTTP admission. A cached receipt in the sync server's response
    // can be replayed after the server rolls its physical state backwards.
    // The readback transport must independently attest its current durable
    // head/floor, not fetch unsigned LIST or re-sign the server's JSON.
    const witnessNonce = randomBase64Url(32);
    let witnessed;
    try {
      witnessed = await this.atomicBatchWitnessReadback({
        scope: this.atomicBatchWitnessScope,
        accountId: this.atomicBatchOwnerIdentity.accountId,
        storeId: this.atomicBatchOwnerIdentity.storeId,
        nonce: witnessNonce,
        operationIds: [deleted.operationId, moved.operationId],
        envelopeDigests: digests,
      });
    } catch {
      if (uncertainRequest && transient(uncertainRequest)) {
        summary.offline = true;
        return;
      }
      fail("Independent atomic admission readback unavailable",
        "sync_atomic_batch_indeterminate");
    }
    let detachedWitness;
    try { detachedWitness = nativeJsonParse(canonicalJson(witnessed)); }
    catch { fail("Independent witness receipt is not canonical JSON",
      "sync_atomic_batch_indeterminate"); }
    if (detachedWitness?.statement?.nonce !== witnessNonce) {
      if (uncertainRequest && transient(uncertainRequest) && !witnessed) {
        summary.offline = true;
        return;
      }
      fail("Independent atomic admission readback nonce mismatch",
        "sync_atomic_batch_indeterminate");
    }
    // The independent readback callback returns the receipt itself, not the
    // sync server's unsigned HTTP payload. Keep that distinction explicit:
    // accepting a server-supplied `atomicAdmission` would undermine the
    // separate witness and a valid direct receipt must not be rejected.
    verifyAtomicBatchAdmission({ atomicAdmission: detachedWitness }, [deleted, moved],
      this.atomicBatchWitnessPublicKey, this.atomicBatchWitnessScope,
      this.atomicBatchOwnerIdentity);
    // An independently retained CAS floor must independently sign a second
    // fresh challenge AFTER witness verification. Only an exact current
    // physical head can authorize a local ACK; never use a journal/PG row or
    // the original sync HTTP response as this readback.
    const verifiedWitnessStatement = detachedWitness.statement;
    const floorNonce = randomBase64Url(32);
    let floor;
    try {
      floor = await this.atomicBatchCasFloorReadback({
        scope: this.atomicBatchWitnessScope,
        accountId: this.atomicBatchOwnerIdentity.accountId,
        storeId: this.atomicBatchOwnerIdentity.storeId,
        nonce: floorNonce,
        commitId: verifiedWitnessStatement.commitId,
        storeHeadSha256: verifiedWitnessStatement.storeHeadSha256,
        fencingEpoch: verifiedWitnessStatement.fencingEpoch,
      });
    } catch {
      fail("Independent external CAS floor unavailable",
        "sync_atomic_batch_indeterminate");
    }
    verifyAtomicBatchCasFloor(floor, verifiedWitnessStatement,
      this.atomicBatchCasFloorPublicKey, this.atomicBatchWitnessScope, floorNonce,
      this.atomicBatchOwnerIdentity);
    // Remote admission is one transaction. Local advancement may still crash;
    // keep BOTH original outbox entries pending until one atomic markSeenMany
    // after the verified response and local snapshot are durably written.
    let moveHash = null;
    let historicalKeyUnavailable = false;
    try {
      moveHash = await this.hashPendingPayload(moved);
    } catch (error) {
      // A cryptographically verified PHYSICAL historical admission is not a
      // new decrypt permission. After rekey or device revocation the old file
      // key can be unavailable; that must not make a previously committed
      // remote pair forever unacknowledgeable. Never invent a new plaintext
      // hash: rememberOperation may only carry forward a previously trusted
      // snapshot hash, if one exists. Any other error still fails closed.
        if (!nativeReflectApply(nativeArrayIncludes,
          ["authorization_rejected", "stale_key_epoch", "sync_key_epoch_mismatch", "key_unavailable"], [ownDataValue(error, "code")])) {
        throw error;
      }
      historicalKeyUnavailable = true;
    }
    const members = [deleted, moved];
    const observed = [];
    for (let index = 0; index < members.length; index += 1) {
      observed[index] = this.localAdmissionDigestIfFresh(members[index]) === digests[index] ? digests[index] : null;
    }
    for (let index = 0; index < pending.length; index++) {
      if (observed[index]) await this.journal.observeAdmission(pending[index].operationId, observed[index]);
    }
    this.rememberOperation(deleted);
    this.rememberOperation(moved, moveHash);
    if (historicalKeyUnavailable) {
      // Even a previously trusted source hash cannot certify CURRENT local
      // bytes after the file key becomes unavailable. Preserve the signed
      // remote admission, but make local content identity explicitly unknown.
      this.snapshot.files[moved.metadata.path].hash = null;
    }
    await this.persistSnapshot();
    const seenEntries = [];
    for (let index = 0; index < pending.length; index += 1) {
      seenEntries[index] = { operationId: pending[index].operationId, admittedDigest: observed[index] };
    }
    await this.journal.markSeenMany(seenEntries);
    summary.pushed += 2;
  }

  async _pushPending(summary) {
    const journal = this.journal;
    const journalMethods = captureMethodSet(journal, HISTORICAL_JOURNAL_METHODS);
    const engineMethods = captureMethodSet(this, HISTORICAL_ENGINE_METHODS);
    const adapter = this.adapter;
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    const translateWebDavOperation = this.translateWebDavOperation;
    const assertPushRuntime = () => {
      if (this.journal !== journal || this.adapter !== adapter
        || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate
        || this.translateWebDavOperation !== translateWebDavOperation) {
        fail("Historical restore runtime identity changed during push admission",
          "restore_remote_admission_unproven");
      }
      assertMethodSet(journal, journalMethods);
      assertMethodSet(this, engineMethods);
    };
    const recovered = await nativeReflectApply(journalMethods.recover, journal, []);
    assertPushRuntime();
    // The journal's durable group manifest—not adjacency—is the local
    // evidence that the DELETE and MOVE entered the outbox together.
    // enqueueMany can leave unrelated records between two group members.
    const groups = nativeReflectApply(journalMethods.atomicSignedGroups, journal, []);
    const groupedById = new NativeMap();
    const pendingById = new NativeMap();
    for (let index = 0; index < recovered.length; index += 1) {
      const item = recovered[index];
      nativeReflectApply(nativeMapSet, pendingById, [item.operationId, item]);
    }
    const groupEntries = nativeObjectEntries(groups);
    for (let index = 0; index < groupEntries.length; index += 1) {
      const eventId = groupEntries[index][0];
      const pair = groupEntries[index][1];
      if (!pair || typeof pair.deleteId !== "string" || typeof pair.moveId !== "string"
        || nativeReflectApply(nativeMapHas, groupedById, [pair.deleteId])
        || nativeReflectApply(nativeMapHas, groupedById, [pair.moveId])
        || !nativeReflectApply(nativeMapHas, pendingById, [pair.deleteId])
        || !nativeReflectApply(nativeMapHas, pendingById, [pair.moveId])
        || signedWebDavEventId(nativeReflectApply(nativeMapGet, pendingById, [pair.deleteId])) !== eventId
        || signedWebDavEventId(nativeReflectApply(nativeMapGet, pendingById, [pair.moveId])) !== eventId) {
        fail("Atomic signed WebDAV outbox group has missing/mismatched member",
          "sync_atomic_batch_indeterminate");
      }
      assertAtomicSignedOverwritePair(nativeReflectApply(nativeMapGet, pendingById, [pair.deleteId]),
        nativeReflectApply(nativeMapGet, pendingById, [pair.moveId]));
      nativeReflectApply(nativeMapSet, groupedById, [pair.deleteId, pair]);
      nativeReflectApply(nativeMapSet, groupedById, [pair.moveId, pair]);
    }
    // Old local outboxes can contain two valid-looking WebDAV envelopes
    // admitted separately before group provenance existed. Detect pairs
    // across the ENTIRE queue; never let an intervening unrelated item cause
    // the DELETE to escape via adapter.push. Without durable enqueueMany
    // provenance there is no safe automatic remote transaction to infer.
    const ungroupedCandidates = new NativeMap();
    const ungroupedCandidateLists = [];
    for (const operation of recovered) {
      const event = signedWebDavEventId(operation);
      if (!event || nativeReflectApply(nativeMapHas, groupedById, [operation.operationId])) continue;
      let candidates = nativeReflectApply(nativeMapGet, ungroupedCandidates, [event]);
      if (!candidates) {
        candidates = [];
        nativeReflectApply(nativeMapSet, ungroupedCandidates, [event, candidates]);
        nativeReflectApply(nativeArrayPush, ungroupedCandidateLists, [candidates]);
      }
      nativeReflectApply(nativeArrayPush, candidates, [operation]);
    }
    for (let index = 0; index < ungroupedCandidateLists.length; index += 1) {
      if (ungroupedCandidateLists[index].length > 1) {
        fail("Unproven historical atomic WebDAV outbox group", "sync_atomic_batch_indeterminate");
      }
    }
    const pushedGroups = new NativeSet();
    for (let index = 0; index < recovered.length; index += 1) {
      assertPushRuntime();
      const original = recovered[index];
      if (nativeReflectApply(journalMethods.hasSeen, journal, [original.operationId])) continue;
      const group = nativeReflectApply(nativeMapGet, groupedById, [original.operationId]);
      if (group) {
        if (nativeReflectApply(nativeSetHas, pushedGroups, [group.deleteId])) continue;
        await this.pushAtomicSignedOverwritePair([
          nativeReflectApply(nativeMapGet, pendingById, [group.deleteId]),
          nativeReflectApply(nativeMapGet, pendingById, [group.moveId]),
        ], summary);
        nativeReflectApply(nativeSetAdd, pushedGroups, [group.deleteId]);
        if (summary.offline) break;
        continue;
      }
      const next = recovered[index + 1];
      const event = signedWebDavEventId(original);
      if (event && next && signedWebDavEventId(next) === event) {
        // Two adjacent lookalikes are not proof of one fsynced group.
        fail("Unproven atomic WebDAV journal batch provenance",
          "sync_atomic_batch_indeterminate");
      }
      // A prior version may have acknowledged DELETE but crashed before the
      // companion MOVE. Such legacy partial evidence must NOT send MOVE as a
      // standalone remote write; only manual independent reconciliation can
      // determine whether the DELETE was ever committed remotely.
      if (event && original.operation === "move") {
        // An old `webdav-` MOVE can be the surviving half of a tampered
        // overwrite batch. Its signature says MOVE, not that a destination
        // tombstone was never required. Only new `webdavsolo-` IDs may be
        // independently dispatched without a durable group manifest.
        fail("Ambiguous legacy WebDAV MOVE cannot be remotely committed alone",
          "sync_atomic_batch_indeterminate");
      }
      if (event && original.operation === "delete") {
        // The only secure standalone WebDAV DELETE namespace is the new
        // signed `webdavsolo-` variant. Old `webdav-` DELETE IDs could be a
        // missing half of a poisoned DELETE+MOVE journal; presence/absence of
        // locally editable manifest or seen IDs is not cryptographic proof.
        fail("Ambiguous legacy WebDAV DELETE cannot be remotely committed alone",
          "sync_atomic_batch_indeterminate");
      }
      let pending = original;
      if (pending.journalType === "webdav-mutation") {
        if (!translateWebDavOperation) continue;
        const translated = await nativeReflectApply(translateWebDavOperation, undefined, [pending]);
        assertPushRuntime();
        if (!translated) continue;
        if (typeof journalMethods.replace === "function") {
          await nativeReflectApply(journalMethods.replace, journal, [pending.operationId, translated]);
        } else await nativeReflectApply(journalMethods.update, journal, [pending.operationId, translated]);
        assertPushRuntime();
        pending = translated;
      }
      let operation;
      let historicalRestoreEnvelope = null;
      let historicalRestorePayloadHash = null;
      try {
        const pendingOperationId = ownDataValue(pending, "operationId");
        const isHistoricalRestorePending = typeof pendingOperationId === "string"
          && stringStartsWith(pendingOperationId, "histrestore-");
        // An expired grant cannot authorize another PUT, but it must not make
        // an already-committed lost-ACK restore impossible to verify read-only.
        operation = isHistoricalRestorePending
          ? protocol.validateStoredOperation(pending)
          : protocol.validateOperation(pending);
        if (!nativeReflectApply(engineMethods.operationIsSelected, this, [operation])) continue;
        if (stringStartsWith(operation.operationId, "histrestore-")) {
          historicalRestoreEnvelope = captureHistoricalRestoreEnvelope(operation, this);
          operation = historicalRestoreEnvelope.operation;
          assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          // The signed outbox can survive a crash between staging and local
          // materialization. An exact signed-envelope journal observation is
          // recorded only AFTER _apply has durably persisted restored local
          // bytes and its snapshot. Never trust a replaceable snapshot alone
          // as evidence; a local edit or deletion after successful restore
          // must still be reconciled in a later signed CAS revision.
          const expected = await nativeReflectApply(historicalRestoreEnvelope.engineMethods.hashPendingPayload,
            this, [operation]);
          historicalRestorePayloadHash = expected;
          assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          const snapshot = this.snapshot.files[operation.metadata.path];
          const durablyMaterialized = nativeReflectApply(historicalRestoreEnvelope.journalMethods.hasMaterializedRestore,
            journal, [operation])
            && snapshot && !snapshot.deleted && !snapshot.directory
            && snapshot.objectId === operation.objectId
            && snapshot.fileId === operation.fileId
            && snapshot.versionId === operation.versionId
            && snapshot.hash === expected
            && canonicalJson(snapshot.revision) === canonicalJson(operation.revision);
          if (!durablyMaterialized) {
            let observed;
            try {
              const relative = await canonicalRelativePath(this.rootDir, operation.metadata.path);
              assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
              await recoverHistoricalRestoreTempLink(this.rootDir, relative, expected,
                nativeReflectApply(historicalRestoreEnvelope.journalMethods.restoreStagingInfo,
                  journal, [operation]));
              assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
              const local = await readContainedFile(this.rootDir, relative, null, true);
              assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
              try { observed = sha256Hex(local); }
              finally { zeroBuffer(local); }
            } catch {
              fail("Historical restore was not materialized locally", "restore_local_materialization_missing");
            }
            if (observed !== expected) {
              fail("Historical restore local bytes differ from the signed outbox", "restore_local_materialization_missing");
            }
            // A crash can occur after the physical file and parent directories
            // were flushed but before _apply's snapshot or the journal witness
            // became durable. Re-establish both records before any remote POST.
            nativeReflectApply(historicalRestoreEnvelope.engineMethods.rememberOperation,
              this, [operation, expected]);
            await nativeReflectApply(historicalRestoreEnvelope.engineMethods.persistSnapshot, this, []);
            assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
            await nativeReflectApply(historicalRestoreEnvelope.journalMethods.recordRestoreMaterialization,
              journal, [operation]);
            // The awaited witness commit must not bless a changed transport or
            // engine/journal method when the durable pending state is recaptured.
            assertPushRuntime();
            // recordRestoreMaterialization commits a new journal state object;
            // capture that exact pending envelope again before transport.
            historicalRestoreEnvelope = captureHistoricalRestoreEnvelope(operation, this);
          }
        }
        const outboundFreshDigest = historicalRestoreEnvelope
          ? nativeReflectApply(historicalRestoreEnvelope.engineMethods.localAdmissionDigestIfFresh, this, [operation])
          : nativeReflectApply(engineMethods.localAdmissionDigestIfFresh, this, [operation]);
        const historicalRestore = stringStartsWith(operation.operationId, "histrestore-");
        let result;
        if (historicalRestore) {
          assertHistoricalRestorePhysicalAuthority(this);
          assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          let uncertain = null;
          try {
            result = await nativeReflectApply(historicalRestoreEnvelope.engineMethods.retryPush, this, [operation, {
              beforeDispatch: () => assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope),
              afterAttempt: () => assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope),
              push: () => {
                const pushed = pushCapturedHistoricalRestore(historicalRestoreEnvelope);
                assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
                return pushed;
              },
            }]);
            assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          }
          catch (error) {
            assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
            const errorCode = ownDataValue(error, "code");
            if (uncertainRemoteOutcome(error)
              || nativeReflectApply(nativeArrayIncludes,
                ["authorization_rejected", "authorization_required", "authorization_expired", "sync_conflict"], [errorCode])) {
              // A lost ACK may be followed by 409, an offline retry, or an
              // expired grant. None of those responses proves the exact
              // restore is durable. The independent read is still allowed.
              uncertain = error;
            } else throw error;
          }
          if (result && (typeof result === "object" || typeof result === "function")
            && nativeIsProxy(result)) {
            fail("Historical restore transport returned a proxy response",
              "restore_remote_admission_unproven");
          }
          const resultStatusDescriptor = result && typeof result === "object"
            ? nativeObjectGetOwnPropertyDescriptor(result, "status") : null;
          if (resultStatusDescriptor && !nativeObjectHasOwn(resultStatusDescriptor, "value")) {
            fail("Historical restore transport returned an accessor status", "restore_remote_admission_unproven");
          }
          const resultStatus = resultStatusDescriptor ? resultStatusDescriptor.value : undefined;
          if (resultStatus !== undefined && !nativeNumberIsSafeInteger(resultStatus)) {
            fail("Historical restore transport returned an invalid status", "restore_remote_admission_unproven");
          }
          if (uncertainHttpStatus(resultStatus)) {
            uncertain = nativeObjectAssign(new Error(`Historical restore HTTP response ${resultStatus} is ambiguous`), {
              status: resultStatus,
              code: resultStatus === 409 ? "sync_conflict" : "sync_remote_uncertain",
            });
          }
          if (typeof resultStatus === "number" && resultStatus >= 400 && !uncertainHttpStatus(resultStatus)) {
            fail("Historical restore HTTP admission rejected", "restore_remote_admission_unproven");
          }
          try {
            await nativeReflectApply(historicalRestoreEnvelope.engineMethods.confirmHistoricalRestorePhysicalAdmission,
              this, [historicalRestoreEnvelope]);
            assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          }
          catch (error) {
            // A disconnected readback cannot prove a lost transport ACK. Keep
            // the exact signed operation queued for a later independent read.
            if (uncertain && uncertainRemoteOutcome(uncertain)) { summary.offline = true; continue; }
            throw error;
          }
          result = null;
        } else result = await nativeReflectApply(engineMethods.retryPush, this, [operation]);
        assertPushRuntime();
        if (result?.status >= 400) {
          if (result.status !== 409) fail("Sync push rejected", "push_rejected");
          throw new SyncConflictError(result);
        }
        // Persist the exact pre-expiry observation BEFORE snapshot writes. A
        // later journal fsync failure must not make this verified ciphertext
        // impossible to authenticate after authorization expires.
        // The restore branch reached this line only AFTER the independent
        // physical witness and CURRENT CAS floor both proved exact admission.
        // Promote its earlier durable pre-observation to an admitted receipt;
        // otherwise thousands of successful restores strand `observed` slots.
        const acknowledgedDigest = historicalRestore ? historicalRestoreEnvelope.digest
          : outboundFreshDigest && result?.operationId === operation.operationId
            && signedEnvelopeDigest(result) === outboundFreshDigest ? outboundFreshDigest : null;
        if (acknowledgedDigest) await nativeReflectApply(journalMethods.observeAdmission, journal,
          [operation.operationId, acknowledgedDigest]);
        if (operation.operation === "move" || operation.operation === "delete") {
          const hash = operation.operation === "move"
            ? await nativeReflectApply(engineMethods.hashPendingPayload, this, [operation]) : undefined;
          assertPushRuntime();
          if (historicalRestore) assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          nativeReflectApply(historicalRestoreEnvelope
            ? historicalRestoreEnvelope.engineMethods.rememberOperation : engineMethods.rememberOperation,
          this, [operation, hash]);
          await nativeReflectApply(historicalRestoreEnvelope
            ? historicalRestoreEnvelope.engineMethods.persistSnapshot : engineMethods.persistSnapshot, this, []);
        } else {
          const hash = historicalRestore ? historicalRestorePayloadHash
            : await nativeReflectApply(engineMethods.hashPendingPayload, this, [operation]);
          assertPushRuntime();
          if (historicalRestore) assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
          nativeReflectApply(historicalRestoreEnvelope
            ? historicalRestoreEnvelope.engineMethods.rememberOperation : engineMethods.rememberOperation,
          this, [operation, hash]);
          await nativeReflectApply(historicalRestoreEnvelope
            ? historicalRestoreEnvelope.engineMethods.persistSnapshot : engineMethods.persistSnapshot, this, []);
        }
        if (historicalRestore) assertCapturedHistoricalRestorePending(this, historicalRestoreEnvelope);
        // For ordinary operations an HTTP 2xx still does not pin admission:
        // only our locally signed exact echo can carry a fresh local digest.
        // Historical restores reached here only after an independently
        // signed physical witness and a second CURRENT CAS confirmation.
        if (historicalRestore) {
          await nativeReflectApply(historicalRestoreEnvelope.journalMethods.markSeenExact, journal, [
            historicalRestoreEnvelope.operationId, historicalRestoreEnvelope.digest, acknowledgedDigest,
          ]);
          if (!nativeReflectApply(historicalRestoreEnvelope.journalMethods.hasSeen, journal,
            [historicalRestoreEnvelope.operationId])
            || nativeReflectApply(historicalRestoreEnvelope.journalMethods.durableSignedReceiptDigest, journal,
              [historicalRestoreEnvelope.operationId])
              !== historicalRestoreEnvelope.digest) {
            fail("Historical restore exact ACK was not durably recorded",
              "restore_remote_admission_unproven");
          }
        } else await nativeReflectApply(journalMethods.markSeen, journal,
          [operation.operationId, acknowledgedDigest]);
        assertPushRuntime();
        summary.pushed += 1;
      } catch (error) {
        // A local authorization failure is never an HTTP conflict. Even a
        // callback that throws status:409 must not consume a pending journal
        // operation or trigger remote-wins recovery without a real response.
        const errorCode = ownDataValue(error, "code");
        const errorStatus = ownDataValue(error, "status");
        if (errorCode === "authorization_rejected" || errorCode === "authorization_required") throw error;
        if (errorStatus === 409 || errorCode === "sync_conflict") {
          const errorCurrent = ownDataValue(error, "current");
          const current = errorCurrent
            ? envelopeCopy(protocol.validateStoredOperation(errorCurrent)) : null;
          if (current?.operationId === operation?.operationId
            && signedEnvelopeDigest(current) !== signedEnvelopeDigest(operation)) {
            fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
          }
          // A conflict response for A can point to B, whose operation ID may
          // already be reserved by a DIFFERENT pending signed envelope. Never
          // let markSeen(B) silently consume that still-unsent local operation.
          if (current) {
            const currentDigest = signedEnvelopeDigest(current);
            const queuedOperations = await nativeReflectApply(journalMethods.recover, journal, []);
            assertPushRuntime();
            for (let index = 0; index < queuedOperations.length; index += 1) {
              const queued = queuedOperations[index];
              if (queued.operationId !== current.operationId) continue;
              let queuedDigest;
              try {
                queuedDigest = signedEnvelopeDigest(protocol.validateStoredOperation(queued));
              } catch {
                fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
              }
              if (queuedDigest !== currentDigest) {
                fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
              }
            }
          }
          summary.conflicts.push({ operationId: operation?.operationId || pending.operationId, policy: "remote-wins", currentRevision: error.currentRevision || error.payload?.currentRevision || null });
          await this.recoverConflict(operation, summary);
          if (current) {
            let verifiedFreshDigest;
            if (this.operationDestinationIsSelected(current)) {
              verifiedFreshDigest = await this._apply(current, summary);
            } else {
              verifiedFreshDigest = await this.verifyIncomingOperation(current);
              const reconciled = await this.reconcileOutOfScopeMove(current, summary, {
                preservedOperationIds: [operation.operationId], conflictAlreadyRecorded: true,
              });
              if (!reconciled) {
                this.rememberRemoteOnly(current, "excluded");
                await this.persistSnapshot();
              }
            }
            // A verified remote winner is not the local pending operation.
            // Its separately signed envelope needs its own durable admission
            // pin after the remote snapshot/materialization is persisted.
            await this.journal.markSeen(current.operationId, verifiedFreshDigest);
          }
          await this.journal.markSeen(operation.operationId);
          summary.pushed += 1;
          continue;
        }
        if (transient(error)) { summary.offline = true; continue; }
        throw error;
      }
    }
  }

  async hashPendingPayload(operation) {
    const keyFor = captureDataMethod(this, "keyFor");
    const key = await nativeReflectApply(keyFor, this, [operation]);
    if (captureDataMethod(this, "keyFor") !== keyFor) {
      fail("Historical restore key lookup changed during payload verification",
        "restore_remote_admission_unproven");
    }
    const decrypted = protocol.decryptPayload(operation, key);
    const content = operation.operation === "move"
      ? protocol.decodeMovePayload(decrypted, key) || decrypted
      : decrypted;
    return sha256Hex(content);
  }

  async stageExisting(target) {
    if (!(await exists(target))) return null;
    const trashDir = path.join(this.rootDir, ".rootark-trash");
    await fsp.mkdir(trashDir, { recursive: true });
    await containedAbsolute(this.rootDir, trashDir, false);
      const trashTarget = path.join(trashDir, `${nativeDateNow()}-${nativeRandomUUID()}-${path.basename(target)}`);
    await containedAbsolute(this.rootDir, trashTarget, true);
    await fsp.rename(target, trashTarget);
    return trashTarget;
  }

  async stageHistoricalRestore(target, relative, expectedHash) {
    const present = await exists(target);
    if (expectedHash === null) {
      if (present) fail("Historical restore would overwrite a new local file", "restore_local_conflict");
      return null;
    }
    if (!present) fail("Historical restore would overwrite an unsent local deletion", "restore_local_conflict");
    let before;
    try {
      before = await fsp.lstat(target, { bigint: true });
      const current = await readContainedFile(this.rootDir, relative, before);
      if (sha256Hex(current) !== expectedHash) {
        fail("Historical restore would overwrite unsent local edits", "restore_local_conflict");
      }
    } catch (error) {
        if (ownDataValue(error, "code") === "restore_local_conflict") throw error;
      fail("Historical restore target changed before replacement", "restore_local_conflict");
    }
    const staged = await this.stageExisting(target);
    if (!staged) fail("Historical restore target disappeared", "restore_local_conflict");
    let unchanged = false;
    try {
      // Hold the staged inode before consulting its mutable pathname. This
      // prevents a check-then-open from inadvertently reading a substitute.
      await containedAbsolute(this.rootDir, staged, false);
      const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
        | (fs.constants.O_NONBLOCK || 0);
      const handle = await fsp.open(staged, flags);
      try {
        const opened = await handle.stat({ bigint: true });
        const after = await fsp.lstat(staged, { bigint: true });
        // Windows rename may update ctimeNs. Compare stable inode, size,
        // mtime, birthtime and mode, plus an independently held FD and a
        // post-read path binding. Never trust same-size/same-mtime bytes alone.
        unchanged = opened.isFile() && !opened.isSymbolicLink()
          && after.isFile() && !after.isSymbolicLink()
          && opened.nlink === 1n && after.nlink === 1n
          && sameFileIdentity(before, opened) && sameFileIdentity(opened, after)
          && before.size === opened.size && opened.size === after.size
          && before.mtimeNs === opened.mtimeNs && opened.mtimeNs === after.mtimeNs
          && before.birthtimeNs === opened.birthtimeNs && opened.birthtimeNs === after.birthtimeNs
          && before.mode === opened.mode && opened.mode === after.mode;
        if (unchanged) {
          const bytes = await handle.readFile();
          try {
            const readEnd = await handle.stat({ bigint: true });
            const pathEnd = await fsp.lstat(staged, { bigint: true });
            unchanged = sameFileVersion(opened, readEnd)
              && sameFileVersion(readEnd, pathEnd)
              && sha256Hex(bytes) === expectedHash;
          } finally { zeroBuffer(bytes); }
        }
      } finally { await handle.close(); }
    } catch { /* Reject unexpected staging identity and preserve the old bytes. */ }
    if (!unchanged) {
      await this.replaceStagedIfVacant(staged, target);
      fail("Historical restore target changed during replacement", "restore_local_conflict");
    }
    return staged;
  }

  async replaceStagedIfVacant(staged, target) {
    try {
      // A hard link claims an absent path atomically; unlike rename, it never
      // replaces another writer's file. The staged bytes remain if it fails.
      await fsp.link(staged, target);
      await fsp.unlink(staged);
    } catch { /* Retain the staged data for manual recovery when path is occupied. */ }
  }

  async apply(operation, summary = null) {
    return this.withMutationLock(() => this._apply(operation, summary));
  }

  async _apply(operation, summary = null, historicalRestoreHash = undefined) {
    operation = envelopeCopy(operation);
    const verifiedFreshDigest = await this.verifyIncomingOperation(operation, { preObserve: false });
    const key = await this.keyFor(operation);
    const plaintext = protocol.decryptPayload(operation, key);
    const incomingMetadata = operation.metadata || {};
    if (!incomingMetadata.path) fail("Sync operation path is required", "unsafe_path");
    const canonicalSourcePath = incomingMetadata.sourcePath
      ? await canonicalRelativePath(this.rootDir, incomingMetadata.sourcePath)
      : null;
    let canonicalPath = await canonicalRelativePath(this.rootDir, incomingMetadata.path);
    const requestedPath = incomingMetadata.path;
    const sourceName = canonicalSourcePath ? path.posix.basename(canonicalSourcePath) : null;
    const requestedName = path.posix.basename(requestedPath);
    const requestedCaseOnlyMove = process.platform === "win32" && operation.operation === "move"
      && typeof incomingMetadata.sourcePath === "string"
      && stringToLowerCase(incomingMetadata.sourcePath) === stringToLowerCase(requestedPath)
      && incomingMetadata.sourcePath !== requestedPath;
    if (process.platform === "win32" && operation.operation === "move" && canonicalSourcePath
      && stringToLowerCase(canonicalSourcePath) === stringToLowerCase(canonicalPath)
      && stringToLowerCase(sourceName) === stringToLowerCase(requestedName) && sourceName !== requestedName) {
      canonicalPath = path.posix.join(path.posix.dirname(canonicalSourcePath), path.posix.basename(incomingMetadata.path));
    }
    const metadata = {
      ...incomingMetadata,
      path: canonicalPath,
      ...(canonicalSourcePath ? { sourcePath: canonicalSourcePath } : {}),
    };
    operation = { ...operation, metadata };
    const target = await contained(this.rootDir, metadata.path, true);
    // Credential/key/AEAD/path preflight is complete. Fsync the exact verified
    // envelope before the first filesystem or snapshot mutation; failure here
    // must not leave an applied object with no restart-safe observation.
    if (verifiedFreshDigest) await this.journal.observeAdmission(operation.operationId, verifiedFreshDigest);
    let cleanupPath = null;
    if (operation.operation === "delete" || operation.tombstone) {
      const priorAtTarget = this.snapshot.files[metadata.path];
      const targetMatchesIdentity = priorAtTarget && !priorAtTarget.deleted
        && priorAtTarget.objectId === operation.objectId && priorAtTarget.fileId === operation.fileId;
      const sourcePath = targetMatchesIdentity ? metadata.path
        : (activeIdentityPath(this.snapshot.files, operation, metadata.path)
          || activeFileIdentityPath(this.snapshot.files, operation, metadata.path));
      if (!sourcePath) {
        delete this.snapshot.remoteOnly[operation.objectId];
        await this.persistSnapshot();
        return verifiedFreshDigest;
      }
      cleanupPath = sourcePath;
      const pathOccupiedByOther = priorAtTarget && !priorAtTarget.deleted
        && (priorAtTarget.objectId !== operation.objectId || priorAtTarget.fileId !== operation.fileId);
      const tombstonePath = pathOccupiedByOther ? sourcePath : metadata.path;
      const deleteTarget = await contained(this.rootDir, sourcePath, true);
      await this.stageExisting(deleteTarget);
      this.rememberOperation({ ...operation, metadata: { ...metadata, path: tombstonePath } }, undefined, sourcePath);
    } else if (operation.operation === "move") {
      if (!metadata.sourcePath) fail("Move source path is required", "unsafe_path");
      if (metadata.sourcePath === metadata.path && !requestedCaseOnlyMove) fail("Move source and destination must differ", "move_source_missing");
      const priorAtSource = this.snapshot.files[metadata.sourcePath];
      const sourceMatchesIdentity = priorAtSource && !priorAtSource.deleted && !priorAtSource.directory
        && priorAtSource.objectId === operation.objectId && priorAtSource.fileId === operation.fileId;
      const sourcePath = sourceMatchesIdentity ? metadata.sourcePath
        : activeFileIdentityPath(this.snapshot.files, operation, metadata.path);
      cleanupPath = sourcePath;
      const source = sourcePath ? await contained(this.rootDir, sourcePath, true) : null;
      const sourceExists = source ? await exists(source) : false;
      const movePayload = protocol.decodeMovePayload(plaintext, key);
      if (!sourceExists && movePayload === null) fail("Moved file is unavailable and the operation has no recovery payload", "move_source_missing");
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await containedAbsolute(this.rootDir, path.dirname(target), false);
      let hash;
      if (sourceExists) {
        if (source !== target) {
          const sameWindowsPath = process.platform === "win32"
            && stringToLowerCase(path.resolve(source)) === stringToLowerCase(path.resolve(target));
          if (!sameWindowsPath && await exists(target)) await this.stageExisting(target);
          await fsp.rename(source, target);
        }
        const movedStats = await fsp.lstat(target, { bigint: true });
        if (movedStats.isFile()) hash = sha256Hex(await readContainedFile(this.rootDir, metadata.path, movedStats));
      } else {
        if (await exists(target)) await this.stageExisting(target);
        const temporary = `${target}.tmp-${process.pid}-${nativeRandomUUID()}`;
        try {
          await fsp.writeFile(temporary, movePayload, { mode: 0o600, flag: "wx" });
          await fsp.rename(temporary, target);
        } finally { await nativeReflectApply(nativePromiseCatch,
          fsp.rm(temporary, { force: true }), [() => {}]); }
        hash = sha256Hex(movePayload);
      }
      this.rememberOperation(operation, hash, sourcePath);
    } else {
      await fsp.mkdir(path.dirname(target), { recursive: true });
      await containedAbsolute(this.rootDir, path.dirname(target), false);
      if (metadata.contentType === "inode/directory") {
        const sourcePath = operation.operation === "update" ? activeIdentityPath(this.snapshot.files, operation, metadata.path) : null;
        let relocated = false;
        if (sourcePath) {
          const source = await contained(this.rootDir, sourcePath, true);
          if (await exists(source)) {
            if (!(await fsp.lstat(source)).isDirectory()) fail("Tracked directory identity points to a non-directory", "unsafe_path");
            if (source !== target) {
              if (await exists(target)) await this.stageExisting(target);
              await fsp.rename(source, target);
            }
            relocated = true;
          }
        }
        if (!relocated) {
          try {
            await fsp.mkdir(target, { recursive: false });
          } catch (error) {
        if (ownDataValue(error, "code") !== "EEXIST") throw error;
            if (!(await fsp.lstat(target)).isDirectory()) {
              await this.stageExisting(target);
              await fsp.mkdir(target, { recursive: false });
            }
          }
        }
      } else {
        const temporary = `${target}.tmp-${process.pid}-${nativeRandomUUID()}`;
        let restoreHandle = null;
        let restoreTempCreated = false;
        try {
          if (historicalRestoreHash !== undefined) {
            // A signed historical restore must not acquire a durable
            // "materialized" witness for a file that only reached the OS
            // page cache. Flush the exact plaintext before linking it into
            // the visible directory and before persisting snapshot/journal.
            // Record the exact random pathname BEFORE creating ANY plaintext
            // staging file. A process kill before binding its inode now fails
            // closed on restart instead of treating the temp as a user CREATE.
            await this.journal.recordRestoreStagingIntent(operation, path.basename(temporary));
            restoreHandle = await fsp.open(temporary,
              fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL
                | (fs.constants.O_SYNC || 0), 0o600);
            restoreTempCreated = true;
            await restoreHandle.writeFile(plaintext);
            await restoreHandle.sync();
            const physical = await restoreHandle.stat({ bigint: true });
            if (!physical.isFile() || physical.isSymbolicLink()
              || physical.ino === 0n || physical.nlink !== 1n) {
              fail("Historical restore staging file identity is invalid", "unsafe_path");
            }
            const named = await fsp.lstat(temporary, { bigint: true });
            if (!sameFileVersion(physical, named)) {
              fail("Historical restore staging pathname changed", "unsafe_path");
            }
            await this.journal.bindRestoreStagingIdentity(operation,
              path.basename(temporary), {
      dev: bigIntToString(physical.dev), ino: bigIntToString(physical.ino),
              });
          } else {
            await fsp.writeFile(temporary, plaintext, { mode: 0o600 });
          }
          if (historicalRestoreHash !== undefined) {
            const staged = await this.stageHistoricalRestore(target, metadata.path, historicalRestoreHash);
            try {
              if (staged) {
                // The old revision is recoverable in trash only after the
                // trash entry and every newly-created ancestor is durable.
                // Flushing the target parent alone cannot prove rollback.
                await syncDirectoryChain(this.rootDir, path.dirname(staged));
                await syncDirectoryChain(this.rootDir, path.dirname(target));
              }
              // Atomic no-replace materialization; do not clobber files
              // created by another process after the last restore preflight.
              const recordedStage = this.journal.restoreStagingInfo(operation);
              if (!recordedStage || recordedStage.name !== path.basename(temporary)) {
                fail("Restore staging has no durable signed provenance", "restore_local_materialization_missing");
              }
              const beforeLink = await restoreHandle.stat({ bigint: true });
              const namedBeforeLink = await fsp.lstat(temporary, { bigint: true });
              if (!sameFileVersion(beforeLink, namedBeforeLink) || beforeLink.nlink !== 1n
      || bigIntToString(beforeLink.dev) !== recordedStage.dev
      || bigIntToString(beforeLink.ino) !== recordedStage.ino) {
                fail("Restore staged pathname replaced before linking", "restore_local_materialization_missing");
              }
              await fsp.link(temporary, target);
              const linkedStage = await fsp.lstat(temporary, { bigint: true });
              const linkedTarget = await fsp.lstat(target, { bigint: true });
              const openedLinked = await restoreHandle.stat({ bigint: true });
              if (!linkedStage.isFile() || linkedStage.isSymbolicLink()
                || linkedStage.nlink !== 2n || !linkedTarget.isFile()
                || linkedTarget.isSymbolicLink() || linkedTarget.nlink !== 2n
                || !sameFileVersion(linkedStage, linkedTarget)
                || !sameFileVersion(openedLinked, linkedTarget)
      || bigIntToString(linkedStage.dev) !== recordedStage.dev) {
                fail("Linked restore physical identity changed", "restore_local_materialization_missing");
              }
              // historicalRestoreHash identifies the PREVIOUS local bytes;
              // the new payload must match the authenticated decrypted
              // signed operation's plaintext, not that prior local hash.
              if (await hashPinnedRestoredFile(restoreHandle, plaintext.length)
                !== sha256Hex(plaintext)) {
                fail("Linked restore FD differs from signed historical content",
                  "restore_local_materialization_missing");
              }
              // Some Windows filesystems can report a new file index when a
              // second hardlink is created. The exact two-name linked inode
              // must become journal-durable before the alias can be cleaned.
      if (bigIntToString(linkedStage.ino) !== recordedStage.ino) {
                await this.journal.recordLinkedRestoreStagingIdentity(operation,
                  recordedStage.name, recordedStage, {
        dev: bigIntToString(linkedStage.dev), ino: bigIntToString(linkedStage.ino),
                  });
              }
              // Close the verified original FD before unlinking, including on
              // Windows where unlinking an open file can be disallowed.
              await restoreHandle.close();
              restoreHandle = null;
              // Remove the temporary hardlink before the durable parent-dir
              // barrier. Without this, a crash can resurrect an unflushed
              // tmp name and strand an otherwise valid signed outbox on nlink=2.
              await fsp.unlink(temporary);
              // Both the target link and temporary unlink, as well as any
              // freshly created nested parent chain, must become durable
              // before independently committed restore evidence is allowed.
              await syncDirectoryChain(this.rootDir, path.dirname(target));
            } catch (error) {
              if (staged) await this.replaceStagedIfVacant(staged, target);
          if (ownDataValue(error, "code") === "EEXIST") fail("Historical restore path was recreated", "restore_local_conflict");
              throw error;
            }
          } else {
            if (await exists(target)) await this.stageExisting(target);
            await fsp.rename(temporary, target);
          }
        } finally {
          // A durable intent is NOT proof of file ownership: O_EXCL may
          // collide with a user-created file after the intent was persisted.
          // Never delete that foreign pathname (or a substituted name).
          let owned = null;
          if (restoreHandle) {
            try { owned = await restoreHandle.stat({ bigint: true }); }
            finally { await restoreHandle.close(); }
          }
          if (historicalRestoreHash === undefined) {
            await nativeReflectApply(nativePromiseCatch, fsp.rm(temporary, { force: true }), [() => {}]);
          } else if (restoreTempCreated) {
            const current = await nativeReflectApply(nativePromiseCatch,
              fsp.lstat(temporary, { bigint: true }), [(error) => ownDataValue(error, "code") === "ENOENT"
                ? null : nativePromiseReject(error)]);
            const pinned = owned || this.journal.restoreStagingInfo(operation);
            const matchesPinned = pinned && current && current.isFile()
              && !current.isSymbolicLink()
        && bigIntToString(current.dev) === (owned ? bigIntToString(owned.dev) : pinned.dev)
        && bigIntToString(current.ino) === (owned ? bigIntToString(owned.ino) : pinned.ino);
            if (matchesPinned) {
              // A failed unlink must preserve the signed staging intent. Do
              // not swallow cleanup errors and then discard provenance while
              // a plaintext temp file can still be discovered by scanFiles().
              await fsp.rm(temporary, { force: true });
            }
            const remaining = await nativeReflectApply(nativePromiseCatch,
              fsp.lstat(temporary, { bigint: true }), [(error) => ownDataValue(error, "code") === "ENOENT"
                ? null : nativePromiseReject(error)]);
            if (remaining) {
              fail("Historical restore staging cleanup is incomplete; explicit recovery is required",
                "restore_local_materialization_missing");
            }
          }
        }
      }
      this.rememberOperation(operation, sha256Hex(plaintext));
    }
    if (operation.operation === "move" && cleanupPath) {
      await this.pruneEmptyUntrackedParents(path.dirname(await contained(this.rootDir, cleanupPath, true)));
    } else if (operation.operation === "delete" || operation.tombstone) {
      await this.pruneEmptyUntrackedParents(path.dirname(await contained(this.rootDir, cleanupPath || metadata.path, true)));
    }
    await this.persistSnapshot();
    if (summary) summary.applied = (summary.applied || 0) + 1;
    return verifiedFreshDigest;
  }

  async scanFiles() {
    const result = {};
    const emptyHash = sha256Hex(nativeBufferAlloc(0));
    const walk = async (directory, prefix = "") => {
      let hasSyncEntries = false;
      for (const entry of await fsp.readdir(directory, { withFileTypes: true })) {
        let internalName = false;
        if (prefix === "") {
          const normalizedEntryName = stringToLowerCase(entry.name);
          for (let index = 0; index < INTERNAL_NAMES.length; index += 1) {
            if (stringToLowerCase(INTERNAL_NAMES[index]) === normalizedEntryName) internalName = true;
          }
          for (let index = 0; index < INTERNAL_NAME_PREFIXES.length; index += 1) {
            if (stringStartsWith(normalizedEntryName, INTERNAL_NAME_PREFIXES[index])) internalName = true;
          }
        }
        if (internalName) continue;
        if (stringStartsWith(entry.name, ".rootark-put-") || stringStartsWith(entry.name, ".rootark-move-")) continue;
        const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
        try { protocol.safeRelativePath(relative, "path"); } catch { continue; }
        const target = path.join(directory, entry.name);
        await containedAbsolute(this.rootDir, target, false);
        if (entry.isDirectory()) {
          if (!this.needsTraversal(relative)) continue;
          const childHasSyncEntries = await walk(target, relative);
          const prior = this.snapshot.files[relative];
          if (this.selectedPaths === null
            ? (!childHasSyncEntries || (prior && !prior.deleted && prior.directory))
            : (this.isSelected(relative) && (!childHasSyncEntries || (prior && !prior.deleted && prior.directory)))) {
            result[relative] = { hash: emptyHash, size: 0, directory: true };
          }
          if (childHasSyncEntries || this.isSelected(relative) || this.selectedPaths === null) hasSyncEntries = true;
        } else if (entry.isFile() && this.isSelected(relative)) {
          const data = await readContainedFile(this.rootDir, relative);
          result[relative] = { hash: sha256Hex(data), size: data.length, directory: false };
          hasSyncEntries = true;
        }
      }
      return hasSyncEntries;
    };
    await walk(this.rootDir);
    return result;
  }

  async pruneEmptyUntrackedParents(directory) {
    const root = path.resolve(this.rootDir);
    let current = path.resolve(directory);
    while (current !== root && stringStartsWith(current, `${root}${path.sep}`)) {
      await containedAbsolute(root, current, true);
    const relativeParts = stringSplit(path.relative(root, current), path.sep);
    let relative = "";
    for (let index = 0; index < relativeParts.length; index += 1) {
      if (index > 0) relative += "/";
      relative += relativeParts[index];
    }
      const prior = this.snapshot.files[relative];
      if (prior && !prior.deleted && prior.directory) break;
      try {
        await fsp.rmdir(current);
      } catch (error) {
        if (ownDataValue(error, "code") === "ENOENT") {
          current = path.dirname(current);
          continue;
        }
          if (nativeReflectApply(nativeArrayIncludes, ["ENOTEMPTY", "EEXIST"], [ownDataValue(error, "code")])) break;
        throw error;
      }
      current = path.dirname(current);
    }
  }

  async reconcileLocal() {
    return this.withMutationLock(() => this._reconcileLocal());
  }

  async _reconcileLocal() {
    for (const operation of await this.journal.recover()) {
      if (typeof operation.operationId !== "string"
        || !stringStartsWith(operation.operationId, "histrestore-")
        || typeof operation.metadata?.path !== "string") continue;
      const relative = await canonicalRelativePath(this.rootDir, operation.metadata.path);
      const staging = this.journal.restoreStagingInfo(operation);
      if (!staging) continue;
      const restoreTarget = await contained(this.rootDir, relative, true);
      const recordedPath = path.join(path.dirname(restoreTarget), staging.name);
      await containedAbsolute(this.rootDir, recordedPath, true);
      const stagedStats = await nativeReflectApply(nativePromiseCatch,
        fsp.lstat(recordedPath, { bigint: true }), [(error) => ownDataValue(error, "code") === "ENOENT"
          ? null : nativePromiseReject(error)]);
      if (stagedStats && (staging.dev === null || staging.ino === null)) {
        // The durable name intent preceded file creation, but no physical FD
        // binding ever committed. Never turn that orphan into a user CREATE.
        fail("Unbound historical restore staging requires explicit recovery",
          "restore_local_materialization_missing");
      }
    if (stagedStats && bigIntToString(stagedStats.dev) === staging.dev
      && bigIntToString(stagedStats.ino) === staging.ino
        && stagedStats.nlink === 1n) {
        // The producer's fsynced temp survived a kill BEFORE link(target).
        // Do not mistake that plaintext staging file for a user CREATE in
        // scanFiles. Explicit recovery must choose a safe destination.
        fail("Unlinked historical restore staging requires explicit recovery",
          "restore_local_materialization_missing");
      }
      // A kill between link(temp,target) and unlink(temp) leaves a legitimate
      // signed restore with nlink=2. Only the physically recorded exact
      // inode/name may be cleaned; never hide a filename by its suffix.
      try {
        const expected = await this.hashPendingPayload(operation);
        await recoverHistoricalRestoreTempLink(this.rootDir, relative, expected, staging);
      } catch (error) {
        if (ownDataValue(error, "code") !== "ENOENT") throw error;
      }
      // recoverHistoricalRestoreTempLink can return early when the target is
      // absent or no longer has the expected hardlink identity. An ENOENT
      // target is also swallowed above. Never let a still-present recorded
      // staging pathname reach scanFiles() as an ordinary user CREATE.
      const remainingStage = await nativeReflectApply(nativePromiseCatch,
        fsp.lstat(recordedPath, { bigint: true }), [(error) => ownDataValue(error, "code") === "ENOENT"
          ? null : nativePromiseReject(error)]);
      if (remainingStage) {
        fail("Unresolved historical restore staging file requires explicit recovery",
          "restore_local_materialization_missing");
      }
    }
    const scanned = await this.scanFiles();
    const current = {};
    const snapshotPathByKey = new NativeMap();
    if (process.platform === "win32") {
    for (const relative of nativeObjectKeys(this.snapshot.files)) {
        const key = pathKey(relative);
        const prior = nativeReflectApply(nativeMapGet, snapshotPathByKey, [key]);
        if (prior && prior !== relative) fail("Ambiguous case-insensitive sync snapshot path", "unsafe_path");
        nativeReflectApply(nativeMapSet, snapshotPathByKey, [key, relative]);
      }
    }
    for (const [relative, file] of nativeObjectEntries(scanned)) {
      const canonical = process.platform === "win32"
        ? nativeReflectApply(nativeMapGet, snapshotPathByKey, [pathKey(relative)]) || relative : relative;
      current[canonical] = file;
    }
    const evictedByPath = new NativeMap();
    for (const item of nativeObjectValues(this.snapshot.remoteOnly)) {
      if (item.reason !== "evicted" || item.deleted || item.directory) continue;
      const key = pathKey(item.path);
      const matches = nativeReflectApply(nativeMapGet, evictedByPath, [key]) || [];
      nativeReflectApply(nativeArrayPush, matches, [item]);
      nativeReflectApply(nativeMapSet, evictedByPath, [key, matches]);
    }
    const protectedPaths = new NativeSet();
    for (const operation of await this.journal.recover()) {
      if (operation.metadata?.path) nativeReflectApply(nativeSetAdd, protectedPaths, [pathKey(operation.metadata.path)]);
      if (operation.metadata?.sourcePath) nativeReflectApply(nativeSetAdd, protectedPaths, [pathKey(operation.metadata.sourcePath)]);
      if (operation.operation === "update" && operation.metadata?.contentType === "inode/directory") {
        const sourcePath = activeIdentityPath(this.snapshot.files, operation, operation.metadata.path);
        if (sourcePath) nativeReflectApply(nativeSetAdd, protectedPaths, [pathKey(sourcePath)]);
      }
      if (operation.journalType === "webdav-mutation") {
        for (const value of [operation.path, operation.source, operation.destination]) {
          if (typeof value !== "string") continue;
          try {
            const decoded = nativeDecodeURIComponent(value);
            let start = 0;
            while (start < decoded.length && decoded[start] === "/") start += 1;
            nativeReflectApply(nativeSetAdd, protectedPaths,
              [pathKey(protocol.safeRelativePath(stringSlice(decoded, start), "path"))]);
          } catch {}
        }
      }
    }
    for (const [relative, prior] of nativeObjectEntries(this.snapshot.files)) {
      if (nativeReflectApply(nativeSetHas, protectedPaths, [pathKey(relative)])) continue;
      if (!this.isSelected(relative)) continue;
      if (prior.deleted || current[relative]) continue;
      const eviction = this.snapshot.remoteOnly[prior.objectId];
      if (eviction?.reason === "evicted" && pathsEqual(eviction.path, relative)) {
        delete this.snapshot.files[relative];
        continue;
      }
      const key = await this.fileKeyResolver(prior);
      const operation = await this.buildOperation({ operation: "delete", objectId: prior.objectId, fileId: prior.fileId, versionId: nativeRandomUUID(), baseRevision: prior.revision, revision: { counter: (prior.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata: { path: relative }, fileKey: key });
      await this.assertOutgoingAuthorized(operation, () => this.journal.enqueue(operation));
      this.rememberOperation(operation);
    }
    for (const [relative, file] of nativeObjectEntries(current)) {
      if (nativeReflectApply(nativeSetHas, protectedPaths, [pathKey(relative)])) continue;
      let prior = this.snapshot.files[relative];
      if (prior && !prior.deleted && this.snapshot.remoteOnly[prior.objectId]?.reason === "evicted"
        && pathsEqual(this.snapshot.remoteOnly[prior.objectId].path, relative)) delete this.snapshot.remoteOnly[prior.objectId];
      const evicted = !prior || prior.deleted
        ? nativeReflectApply(nativeMapGet, evictedByPath, [pathKey(relative)]) || [] : [];
      if (evicted.length > 1) fail("More than one evicted remote object matches this path", "remote_object_ambiguous");
      const evictedEntry = evicted[0] || null;
      if (evictedEntry) {
        prior = evictedEntry;
        if (prior.hash === file.hash) {
          this.snapshot.files[relative] = { ...prior, hash: file.hash, deleted: false };
          delete this.snapshot.remoteOnly[prior.objectId];
          continue;
        }
      }
      const isDirectory = Boolean(file.directory);
      if (prior && !prior.deleted && prior.hash === file.hash && Boolean(prior.directory) === isDirectory) continue;
      const isUpdate = prior && !prior.deleted;
      const identitySeed = prior?.deleted
        ? nativeReflectApply(nativeStringReplace, nativeRandomUUID(), [/-/g, ""])
      : stringSlice(sha256Hex(relative), 0, 32);
      const objectId = isUpdate ? prior.objectId : `object-${identitySeed}`;
      const fileId = isUpdate ? prior.fileId : `file-${identitySeed}`;
      const data = isDirectory ? nativeBufferAlloc(0) : await readContainedFile(this.rootDir, relative);
      const contentHash = sha256Hex(data);
      const key = await this.fileKeyResolver({ objectId, fileId, path: relative, keyEpoch: this.keyEpoch });
      const metadata = { path: relative, name: path.basename(relative), size: data.length, ...(isDirectory ? { contentType: "inode/directory" } : {}) };
      const operation = await this.buildOperation({ operation: isUpdate ? "update" : "create", objectId, fileId, versionId: nativeRandomUUID(), baseRevision: isUpdate ? prior.revision : null, revision: { counter: (prior?.revision?.counter || 0) + 1, deviceId: this.deviceId }, metadata, plaintext: data, fileKey: key });
      await this.assertOutgoingAuthorized(operation, () => this.journal.enqueue(operation));
      this.rememberOperation(operation, contentHash);
    }
    await this.persistSnapshot();
  }

  rememberOperation(operation, hash, sourcePathOverride) {
    const pathName = operation.metadata?.path;
    if (!pathName) return;
    const sourcePath = sourcePathOverride !== undefined ? sourcePathOverride
      : operation.operation === "move" ? operation.metadata.sourcePath
        : (operation.operation === "update" && operation.metadata.contentType === "inode/directory"
          ? activeIdentityPath(this.snapshot.files, operation, pathName) : null);
    const prior = sourcePath
      ? this.snapshot.files[sourcePath] || (sourcePath === pathName ? this.snapshot.files[pathName] : null) || {}
      : this.snapshot.files[pathName] || {};
    if (sourcePath && sourcePath !== pathName) delete this.snapshot.files[sourcePath];
    this.snapshot.files[pathName] = {
      objectId: operation.objectId, fileId: operation.fileId, versionId: operation.versionId,
      revision: operation.revision, hash: hash || prior.hash, deleted: Boolean(operation.tombstone),
      directory: operation.tombstone || operation.operation === "move" || operation.operation === "delete"
        ? Boolean(prior.directory)
        : operation.metadata?.contentType === "inode/directory",
    };
    delete this.snapshot.remoteOnly[operation.objectId];
  }

  async evictLocal(relativePath) {
    return this.withMutationLock(() => this._evictLocal(relativePath));
  }

  async _evictLocal(relativePath) {
    if (!this.opened) await this._open();
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    if (!this.isInScope(safePath)) fail("Only selected paths can be evicted", "path_not_selected");
    const prior = this.snapshot.files[safePath];
    if (!prior || prior.deleted || prior.directory || !regexTest(/^[a-f0-9]{64}$/, prior.hash || "")) fail("Only a tracked file can be evicted", "cache_entry_unavailable");
    const pending = await this.journal.recover();
    let hasPendingOperation = false;
    for (let index = 0; index < pending.length; index += 1) {
      const operation = pending[index];
      const metadata = ownDataValue(operation, "metadata");
      if (ownDataValue(operation, "objectId") === prior.objectId
        || ownDataValue(metadata, "path") === safePath
        || ownDataValue(metadata, "sourcePath") === safePath) {
        hasPendingOperation = true;
        break;
      }
    }
    if (hasPendingOperation) {
      fail("A pending sync operation prevents cache eviction", "sync_operation_pending");
    }
    const target = await contained(this.rootDir, safePath, false);
    const before = await fsp.lstat(target, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink()) fail("Only regular files can be evicted", "unsafe_path");
    const bytes = await readContainedFile(this.rootDir, safePath, before);
    const hash = sha256Hex(bytes);
    const afterRead = await fsp.lstat(target, { bigint: true });
    if (hash !== prior.hash || !sameFileVersion(before, afterRead)) fail("Local file changed since its last sync", "local_changes_pending");

    const remoteResult = await this.adapter.list(prior.objectId);
    const remoteRecords = Array.isArray(remoteResult) ? remoteResult
      : Array.isArray(remoteResult?.objects) ? remoteResult.objects : remoteResult ? [remoteResult] : [];
    if (remoteRecords.length !== 1) fail("Current remote object is unavailable", "remote_object_missing");
    const remote = protocol.validateStoredOperation(remoteRecords[0]);
    if (remote.objectId !== prior.objectId || remote.fileId !== prior.fileId || !pathsEqual(remote.metadata.path, safePath)) {
      fail("Current remote object no longer matches the local cache", "remote_object_changed");
    }
    await this.verifyIncomingOperation(remote);
    if (remote.tombstone || remote.operation === "delete") fail("Current remote object has been deleted", "remote_object_deleted");
    const remoteKey = await this.keyFor(remote);
    const remotePlaintext = protocol.decryptPayload(remote, remoteKey);
    const remoteContent = remote.operation === "move"
      ? protocol.decodeMovePayload(remotePlaintext, remoteKey) || remotePlaintext
      : remotePlaintext;
    if (sha256Hex(remoteContent) !== hash) {
      fail("Current remote content differs from the local cache", "remote_content_changed");
    }

    const beforeStage = await fsp.lstat(target, { bigint: true });
    if (!sameFileVersion(before, beforeStage)) fail("Local file changed during cache verification", "local_changes_pending");
    const confirmedBytes = await readContainedFile(this.rootDir, safePath, beforeStage);
    const afterConfirm = await fsp.lstat(target, { bigint: true });
    if (sha256Hex(confirmedBytes) !== hash || !sameFileVersion(beforeStage, afterConfirm)) {
      fail("Local file changed during cache verification", "local_changes_pending");
    }

    const hadPriorMarker = nativeObjectHasOwn(this.snapshot.remoteOnly, prior.objectId);
    const priorMarker = hadPriorMarker ? this.snapshot.remoteOnly[prior.objectId] : undefined;
    const restoreMemoryMarker = () => {
      if (hadPriorMarker) this.snapshot.remoteOnly[prior.objectId] = priorMarker;
      else delete this.snapshot.remoteOnly[prior.objectId];
    };
    // Only used while the file is back at its path, so a failed rollback persist leaves a state the
    // next reconcile resolves (the file is local and the stale marker is dropped) without a remote delete.
    const rollbackEviction = async (cause) => {
      restoreMemoryMarker();
      try {
        await this.persistSnapshot();
      } catch (persistError) {
        throw evictionError("eviction_rollback_failed", "Eviction rollback could not be persisted; the next sync reconciles this file", cause, persistError);
      }
      throw cause;
    };

    // The marker is committed before the file leaves its path, so the file is never outside its path
    // without a durable record that the remote object is the only copy.
    this.snapshot.remoteOnly[prior.objectId] = {
      objectId: remote.objectId, fileId: remote.fileId, versionId: remote.versionId,
      revision: remote.revision, path: safePath, directory: false, deleted: false, reason: "evicted", hash,
    };
    try {
      await this.persistSnapshot();
    } catch (error) {
      await rollbackEviction(error);
    }

    let staged;
    try {
      staged = await this.stageExisting(target);
      if (!staged) fail("Local cache entry disappeared during eviction", "cache_entry_unavailable");
    } catch (error) {
      await rollbackEviction(error);
    }
    // Renames the staged copy back only if nothing now occupies the path. Never deletes the staged copy.
    const restoreStagedFile = async () => {
      if (await exists(target)) return false;
      await fsp.rename(staged, target);
      return true;
    };
    try {
      const stagedStats = await fsp.lstat(staged, { bigint: true });
      if (!stagedStats.isFile() || !sameFileIdentity(beforeStage, stagedStats) || stagedStats.size !== beforeStage.size
        || stagedStats.mtimeNs !== beforeStage.mtimeNs || stagedStats.mode !== beforeStage.mode) {
        fail("Local file changed during cache eviction", "unsafe_path");
      }
    } catch (error) {
      // The marker is committed and the file is out of its path. Restore the file when possible; otherwise
      // keep the eviction (marker stays) and the staged copy, so reconciliation never pushes a delete.
      let restored;
      try {
        restored = await restoreStagedFile();
      } catch (restoreError) {
        throw evictionError("eviction_restore_failed", "Eviction could not restore the local file; the staged copy is kept in the trash folder", error, restoreError);
      }
      if (!restored) throw evictionError("eviction_restore_failed", "The local path was recreated during eviction; the staged copy is kept in the trash folder", error);
      await rollbackEviction(error);
    }
    // The eviction is committed and the file is out of its path, so a failed cleanup only leaves the staged copy in the trash folder.
    await nativeReflectApply(nativePromiseCatch, fsp.unlink(staged), [() => {}]);
    if (this.snapshot.files[safePath]?.objectId === prior.objectId) delete this.snapshot.files[safePath];
    await this.persistSnapshot();
    return true;
  }

  async materializeRemote(relativePath) {
    return this.withMutationLock(() => this._materializeRemote(relativePath));
  }

  async _materializeRemote(relativePath) {
    if (!this.opened) await this._open();
    const safePath = await canonicalRelativePath(this.rootDir, relativePath);
    if (!this.isSelected(safePath)) fail("Remote-only path is outside the selected scope", "path_not_selected");
    const remoteOnlyItems = nativeObjectValues(this.snapshot.remoteOnly);
    const matches = [];
    for (let index = 0; index < remoteOnlyItems.length; index += 1) {
      if (pathsEqual(remoteOnlyItems[index].path, safePath)) {
        nativeReflectApply(nativeArrayPush, matches, [remoteOnlyItems[index]]);
      }
    }
    const activeMatches = nativeReflectApply(nativeArrayFilter, matches,
      [(item) => !ownDataValue(item, "deleted")]);
    if (activeMatches.length > 1) fail("More than one remote-only object matches this path", "remote_object_ambiguous");
    const entry = activeMatches[0] || matches[0];
    if (!entry) fail("No remote-only object is recorded for this path", "remote_object_unavailable");
    const result = await this.adapter.list(entry.objectId);
    const records = nativeArrayIsArray(result) ? result
      : nativeArrayIsArray(result?.objects) ? result.objects : result ? [result] : [];
    if (!records.length) fail("Remote object is no longer available", "remote_object_unavailable");
    const operation = envelopeCopy(protocol.validateStoredOperation(records[0]));
    if (operation.objectId !== entry.objectId || !this.operationDestinationIsSelected(operation)) {
      fail("Remote object is outside the selected scope", "path_not_selected");
    }
    const verifiedFreshDigest = await this.verifyIncomingOperation(operation, { preObserve: false });
    if (operation.tombstone) {
      if (verifiedFreshDigest) await this.journal.observeAdmission(operation.operationId, verifiedFreshDigest);
      this.rememberRemoteOnly(operation, entry.reason);
      await this.persistSnapshot();
      return false;
    }
    const appliedDigest = await this._apply(operation);
    await this.journal.markSeen(operation.operationId, verifiedFreshDigest || appliedDigest);
    return true;
  }

  async pullRemote(summary) {
    return this.withMutationLock(() => this._pullRemote(summary));
  }

  async _pullRemote(summary) {
    // A remotely visible single side of a just-committed/lost-ACK pair must
    // NOT consume that local pending ID via _apply, markSeen or the excluded-
    // path reconciliation path. Recover the atomic pair through its outbound
    // transaction/readback first; never split a journal group in pullRemote.
    if (nativeObjectKeys(this.journal.atomicSignedGroups?.() || {}).length) {
      fail("Remote pull blocked by pending atomic signed WebDAV batch",
        "sync_atomic_batch_indeterminate");
    }
    // LIST is not a physical admission receipt. If an excluded/offline
    // historical restore is still queued, an exact echo must never reach an
    // ordinary markSeen(), which would discard the durable signed outbox and
    // its local materialization without consulting the independent witness.
    const pendingRestoreDigests = nativeObjectCreate(null);
    const pendingRestores = await this.journal.recover();
    for (let index = 0; index < pendingRestores.length; index += 1) {
      const pending = pendingRestores[index];
      if (typeof pending?.operationId !== "string"
        || !stringStartsWith(pending.operationId, "histrestore-")) continue;
      const restore = protocol.validateStoredOperation(pending);
      const digest = signedEnvelopeDigest(restore);
      if (nativeObjectHasOwn(pendingRestoreDigests, restore.operationId)
        && pendingRestoreDigests[restore.operationId] !== digest) {
        fail("Conflicting pending historical restore identity", "remote_authorization_rejected");
      }
      pendingRestoreDigests[restore.operationId] = digest;
    }
    let result;
    try {
      result = await this.adapter.list();
    } catch (error) {
      if (transient(error)) { summary.offline = true; return; }
      throw error;
    }
    const records = nativeArrayIsArray(result) ? result : result?.objects;
    if (!nativeArrayIsArray(records)) fail("Sync pull returned an invalid record list", "invalid_pull");
    const rank = (operation) => {
      if (operation.tombstone || operation.operation === "delete") return 0;
      if (operation.metadata?.contentType === "inode/directory"
        || (operation.operation === "move" && activeIdentityPath(this.snapshot.files, operation, operation.metadata?.path))) return 1;
      return 2;
    };
    const ordered = [];
    for (let index = 0; index < records.length; index += 1) ordered[ordered.length] = records[index];
    nativeReflectApply(nativeArraySort, ordered, [(left, right) => {
      const rankDifference = rank(left) - rank(right);
      if (rankDifference) return rankDifference;
      if (rank(left) === 1) {
        const leftDepth = stringSplit(left.metadata.path, "/").length;
        const rightDepth = stringSplit(right.metadata.path, "/").length;
        if (leftDepth !== rightDepth) return leftDepth - rightDepth;
        const pathOrder = stringLocaleCompare(left.metadata.path, right.metadata.path);
        if (pathOrder) return pathOrder;
      }
      return stringLocaleCompare(left.objectId, right.objectId)
        || stringLocaleCompare(left.versionId, right.versionId);
    }]);
    // Fail before touching any local state if this single untrusted response
    // contains incompatible signatures for one operation ID. Remote-only pins
    // are intentionally fsynced after the snapshot and cannot guard the batch.
    const batchDigests = nativeObjectCreate(null);
    const inspected = [];
    for (let index = 0; index < ordered.length; index += 1) {
      inspected[inspected.length] = envelopeCopy(protocol.validateStoredOperation(ordered[index]));
    }
    for (let index = 0; index < inspected.length; index += 1) {
      const operation = inspected[index];
      const digest = signedEnvelopeDigest(operation);
      this.journal.assertCompatibleAdmission(operation.operationId, digest);
      if (nativeObjectHasOwn(pendingRestoreDigests, operation.operationId)
        && pendingRestoreDigests[operation.operationId] !== digest) {
        fail("Remote LIST conflicts with pending historical restore", "remote_authorization_rejected");
      }
      const previous = nativeObjectHasOwn(batchDigests, operation.operationId)
        ? batchDigests[operation.operationId] : undefined;
      if (previous !== undefined && previous !== digest) {
        fail("Conflicting local sync admission evidence", "remote_authorization_rejected");
      }
      batchDigests[operation.operationId] = digest;
    }
    const REMOTE_ONLY_ADMISSION_BATCH = 128;
    const observedRemoteOnly = [];
    const flushRemoteOnly = async () => {
      if (!observedRemoteOnly.length) return;
      // Bounded durability boundaries: a 10k-object response must not hold
      // 10k unpromoted pre-observations until the very end of the LIST.
      // Fsync the current snapshot before converting any pin to applied.
      await this.persistSnapshot();
      for (let index = 0; index < observedRemoteOnly.length; index += 1) {
        const { operation, verifiedFreshDigest } = observedRemoteOnly[index];
        await this.journal.markSeen(operation.operationId, verifiedFreshDigest);
      }
      observedRemoteOnly.length = 0;
    };
    for (let index = 0; index < inspected.length; index += 1) {
      const operation = inspected[index];
      if (nativeObjectHasOwn(pendingRestoreDigests, operation.operationId)) {
        // Only the outbound independent admission flow may consume this ID.
        // It remains queued even if its destination is currently excluded.
        continue;
      }
      if (!this.operationDestinationIsSelected(operation)) {
        const verifiedFreshDigest = await this.verifyIncomingOperation(operation);
        await this.reconcileOutOfScopeMove(operation, summary);
        this.rememberRemoteOnly(operation, "excluded");
        observedRemoteOnly[observedRemoteOnly.length] = { operation, verifiedFreshDigest };
        if (observedRemoteOnly.length >= REMOTE_ONLY_ADMISSION_BATCH) await flushRemoteOnly();
        continue;
      }
      const remoteOnly = this.snapshot.remoteOnly[operation.objectId];
      if (remoteOnly?.reason === "evicted") {
        const verifiedFreshDigest = await this.verifyIncomingOperation(operation);
        this.rememberRemoteOnly(operation, "evicted");
        observedRemoteOnly[observedRemoteOnly.length] = { operation, verifiedFreshDigest };
        if (observedRemoteOnly.length >= REMOTE_ONLY_ADMISSION_BATCH) await flushRemoteOnly();
        continue;
      }
      // A folder re-included after an exclusion must hydrate even if this operation was seen before.
      if (this.journal.hasSeen(operation.operationId) && remoteOnly?.reason !== "excluded") {
        // The local seen JSON is mutable. In independently enforced historical
        // mode it cannot suppress verification of remote signed envelopes on
        // a restarted pull; a forged seen ID only risks local availability.
        if (this.reverifySeenIncoming) await this.verifyIncomingOperation(operation,
          { preObserve: false });
        continue;
      }
      const verifiedFreshDigest = await this._apply(operation, summary);
      await this.journal.markSeen(operation.operationId, verifiedFreshDigest);
      summary.pulled += 1;
    }
    await flushRemoteOnly();
  }

  // Applies the configured exclusions once per change. Excluded tracked files are evicted
  // through the guarded _evictLocal path; excluded files with no local copy become remote-only
  // records so that no remote delete can ever be pushed for them. Remote objects are never deleted.
  async _applyExcludedPaths() {
    const applied = this.snapshot.excludedPaths || [];
    const listChanged = safeJsonStringify(applied) !== safeJsonStringify(this.excludedPaths);
    this.snapshot.pendingEvictions = this.snapshot.pendingEvictions || {};
    const pendingEvictions = this.snapshot.pendingEvictions;
    if (!listChanged && !nativeObjectKeys(pendingEvictions).length) return null;
    const report = { evicted: 0, released: 0, kept: [], failed: [] };
    const pending = await this.journal.recover();
    const excludedObjectIds = new NativeSet();
    for (const [relative, prior] of nativeObjectEntries(this.snapshot.files)) {
      if (prior.deleted || prior.directory || !this.isExcluded(relative)) continue;
      const retry = pendingEvictions[prior.objectId];
      if (!listChanged && !retry) continue;
      nativeReflectApply(nativeSetAdd, excludedObjectIds, [prior.objectId]);
      if (retry && retry.attempts >= MAX_EVICTION_ATTEMPTS) {
        report.failed.push({ path: relative, code: retry.code });
        continue;
      }
      delete pendingEvictions[prior.objectId];
      let hasPendingOperation = false;
      for (let pendingIndex = 0; pendingIndex < pending.length; pendingIndex += 1) {
        const operation = pending[pendingIndex];
        const metadata = ownDataValue(operation, "metadata");
        if (ownDataValue(operation, "objectId") === prior.objectId
          || ownDataValue(metadata, "path") === relative
          || ownDataValue(metadata, "sourcePath") === relative) {
          hasPendingOperation = true;
          break;
        }
      }
      if (hasPendingOperation) {
        report.kept.push({ path: relative, code: "sync_operation_pending" });
        continue;
      }
      const target = await contained(this.rootDir, relative, true);
      if (!(await exists(target))) {
        this.snapshot.remoteOnly[prior.objectId] = {
          objectId: prior.objectId, fileId: prior.fileId, versionId: prior.versionId, revision: prior.revision,
          path: relative, directory: false, deleted: false, reason: "excluded", ...(prior.hash ? { hash: prior.hash } : {}),
        };
        delete this.snapshot.files[relative];
        report.released += 1;
        continue;
      }
      try {
        await this._evictLocal(relative);
        report.evicted += 1;
      } catch (error) {
      const code = ownDataValue(error, "code") || "unknown";
        // Transient failures (for example a file held open on Windows) are retried on later cycles, up to a bound.
        // Other failures, including local edits, are reported once and never retried.
        if (nativeReflectApply(nativeSetHas, TRANSIENT_EVICTION_CODES, [code])) {
          const attempts = (retry?.attempts || 0) + 1;
          pendingEvictions[prior.objectId] = { path: relative, code, attempts };
          if (attempts >= MAX_EVICTION_ATTEMPTS) report.failed.push({ path: relative, code });
          else report.kept.push({ path: relative, code });
        } else {
          report.kept.push({ path: relative, code });
        }
      }
    }
    // Drop retry records for objects that are no longer tracked as excluded local files.
    for (const objectId of nativeObjectKeys(pendingEvictions)) {
      if (!nativeReflectApply(nativeSetHas, excludedObjectIds, [objectId])) delete pendingEvictions[objectId];
    }
    if (nativeObjectKeys(pendingEvictions).length) this.snapshot.pendingEvictions = pendingEvictions;
    else delete this.snapshot.pendingEvictions;
    // The applied list is stored only when exclusions are configured, so snapshots of devices that never use them keep their existing shape.
    if (this.excludedPaths.length) this.snapshot.excludedPaths = [...this.excludedPaths];
    else delete this.snapshot.excludedPaths;
    await this.persistSnapshot();
    return report;
  }

  async syncOnce() {
    return this.withMutationLock(() => this._syncOnce());
  }

  async _syncOnce() {
    if (!this.opened) await this._open();
    const adapter = this.adapter;
    const adapterPush = ownDataValue(adapter, "push");
    const adapterValidate = ownDataValue(adapter, "validate");
    const journal = this.journal;
    const journalMethods = captureMethodSet(journal, HISTORICAL_JOURNAL_METHODS);
    const engineMethods = captureMethodSet(this, HISTORICAL_ENGINE_METHODS);
    const assertSyncRuntime = () => {
      if (this.adapter !== adapter || this.journal !== journal
        || ownDataValue(adapter, "push") !== adapterPush
        || ownDataValue(adapter, "validate") !== adapterValidate) {
        fail("Sync runtime identity changed during a remote callback",
          "restore_remote_admission_unproven");
      }
      assertMethodSet(journal, journalMethods);
      assertMethodSet(this, engineMethods);
    };
    const summary = { pushed: 0, pulled: 0, applied: 0, conflicts: [], offline: false };
    const excluded = await this._applyExcludedPaths();
    assertSyncRuntime();
    if (excluded) summary.excluded = excluded;
    await this._reconcileLocal();
    assertSyncRuntime();
    await this._pushPending(summary);
    assertSyncRuntime();
    if (!summary.offline) await this._pullRemote(summary);
    assertSyncRuntime();
    return summary;
  }
}

module.exports = { SyncEngine, contained, containedAbsolute, normalizeExcludedPaths };
