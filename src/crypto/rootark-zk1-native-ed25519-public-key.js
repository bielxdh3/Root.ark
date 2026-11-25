"use strict";

// Pin checks must not dispatch to an attacker-controlled KeyObject instance's
// overridable .export method. Capture Node's intrinsic PublicKeyObject method
// once, without generating or retaining any private key.
const { createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  timingSafeEqual: NATIVE_TIMING_SAFE_EQUAL, ownSymbols: NATIVE_OWN_SYMBOLS,
  ownDescriptor: NATIVE_OWN_DESCRIPTOR, hasOwn: NATIVE_HAS_OWN,
  getPrototype: NATIVE_GET_PROTOTYPE, isProxy: NATIVE_IS_PROXY,
  isKeyObject: NATIVE_IS_KEY_OBJECT, apply: NATIVE_APPLY,
  bufferFrom: NATIVE_BUFFER_FROM, nativeHandlePrototype: NATIVE_HANDLE_PROTOTYPE,
  nativeHandleSymbol: NATIVE_HANDLE_SYMBOL,
  nativeHandleExportOwner: NATIVE_HANDLE_EXPORT_OWNER,
  nativeHandleExport: NATIVE_HANDLE_EXPORT } =
  require("./rootark-zk10-native-intrinsics-v1");
// After a caller-owned KeyObject.type getter, even PUBLIC_EXPORT.call(...) is
// not native authority: Function.prototype.call may have been replaced.
const ZERO_ED25519_SPKI = NATIVE_BUFFER_FROM(
  "302a300506032b6570032100" + "00".repeat(32), "hex");
const PUBLIC_KEY_OBJECT_PROTOTYPE = NATIVE_GET_PROTOTYPE(NATIVE_CREATE_PUBLIC_KEY({
  key: ZERO_ED25519_SPKI, format: "der", type: "spki",
}));
const publicExportDescriptor = NATIVE_OWN_DESCRIPTOR(PUBLIC_KEY_OBJECT_PROTOTYPE, "export");
const PUBLIC_EXPORT = publicExportDescriptor && NATIVE_HAS_OWN(publicExportDescriptor, "value")
  ? publicExportDescriptor.value : null;
if (!NATIVE_HANDLE_PROTOTYPE || typeof NATIVE_HANDLE_EXPORT !== "function")
  throw new TypeError("ED25519_NATIVE_HANDLE_UNAVAILABLE");
if (typeof PUBLIC_EXPORT !== "function") throw new TypeError("ED25519_PUBLIC_EXPORT_UNAVAILABLE");

function assertNativeKeyObjectHandle(publicKey) {
  if (!publicKey || NATIVE_IS_PROXY(publicKey) || !NATIVE_IS_KEY_OBJECT(publicKey)) {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  let cursor = publicKey;
  let handleSymbol = null;
  let handleOwner = null;
  for (let depth = 0; cursor && depth < 8; depth++) {
    if (NATIVE_IS_PROXY(cursor)) throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
    const prototype = NATIVE_GET_PROTOTYPE(cursor);
    const symbols = NATIVE_OWN_SYMBOLS(cursor);
    let ownHandleSymbol = null;
    for (let index = 0; index < symbols.length; index++) {
      if (symbols[index] !== NATIVE_HANDLE_SYMBOL) continue;
      if (ownHandleSymbol) throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
      ownHandleSymbol = symbols[index];
    }
    if (prototype === PUBLIC_KEY_OBJECT_PROTOTYPE) {
      handleSymbol = ownHandleSymbol;
      handleOwner = cursor;
      break;
    }
    if (ownHandleSymbol) throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
    cursor = prototype;
  }
  if (!handleSymbol || !handleOwner) throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  const descriptor = NATIVE_OWN_DESCRIPTOR(handleOwner, handleSymbol);
  if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  const handle = descriptor.value;
  let exportOwner = NATIVE_HANDLE_PROTOTYPE;
  let handleExportDescriptor = null;
  for (let depth = 0; exportOwner && depth < 8; depth += 1) {
    handleExportDescriptor = NATIVE_OWN_DESCRIPTOR(exportOwner, "export");
    if (handleExportDescriptor) break;
    exportOwner = NATIVE_GET_PROTOTYPE(exportOwner);
  }
  if (!handle || typeof handle !== "object" || NATIVE_IS_PROXY(handle)
    || NATIVE_GET_PROTOTYPE(handle) !== NATIVE_HANDLE_PROTOTYPE
    || exportOwner !== NATIVE_HANDLE_EXPORT_OWNER
    || !handleExportDescriptor || !NATIVE_HAS_OWN(handleExportDescriptor, "value")
    || handleExportDescriptor.value !== NATIVE_HANDLE_EXPORT
    || NATIVE_OWN_DESCRIPTOR(handle, "export")) {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
}

function nativeEd25519Spki(publicKey) {
  assertNativeKeyObjectHandle(publicKey);
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  // Caller-owned type/algorithm getters may have mutated the native handle.
  assertNativeKeyObjectHandle(publicKey);
  const raw = NATIVE_BUFFER_FROM(NATIVE_APPLY(PUBLIC_EXPORT, publicKey, [{
    type: "spki", format: "der",
  }]));
  if (raw.length !== 44) throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  for (let index = 0; index < 12; index += 1) {
    if (raw[index] !== ZERO_ED25519_SPKI[index]) {
      throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
    }
  }
  return raw;
}

function pinNativeEd25519PublicKey(publicKey) {
  // Observe the native handle BEFORE any overridable KeyObject.type getter.
  // A malicious getter can synchronously swap B for A, and an async decode
  // can swap it again before verification. Require stable native SPKI across
  // the getter boundary, then verify only with our own fresh native key.
  assertNativeKeyObjectHandle(publicKey);
  const before = NATIVE_BUFFER_FROM(NATIVE_APPLY(PUBLIC_EXPORT, publicKey, [{
    type: "spki", format: "der",
  }]));
  const after = nativeEd25519Spki(publicKey);
  if (before.length !== after.length || !NATIVE_TIMING_SAFE_EQUAL(before, after)) {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  return NATIVE_CREATE_PUBLIC_KEY({ key: before, type: "spki", format: "der" });
}

module.exports = { nativeEd25519Spki, pinNativeEd25519PublicKey };
