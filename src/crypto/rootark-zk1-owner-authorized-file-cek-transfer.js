"use strict";

// DEV-OFF client-side only. No server route consumes this envelope. The owner
// explicitly rewraps an already-held FILE CEK; a device epoch key alone never
// grants access to historical file CEKs. No off-host or production claim.
const crypto = require("node:crypto");
const path = require("node:path");
const { createRequire } = require("node:module");
const { Worker, MessagePort } = require("node:worker_threads");
const nativeEventOn = require("node:events").EventEmitter.prototype.on;
const nativeEventEmit = require("node:events").EventEmitter.prototype.emit;
const nativeSetTimeout = setTimeout;
const nativeClearTimeout = clearTimeout;
const NativePromise = Promise;
const nativePromiseThen = Promise.prototype.then;
const nativeTypes = require("node:util").types;
const nativeIsProxy = nativeTypes.isProxy;
const nativeIsUint8Array = nativeTypes.isUint8Array;
const nativeIsArrayBuffer = nativeTypes.isArrayBuffer;
const nativeIsCryptoKey = nativeTypes.isCryptoKey;
const nativeIsKeyObject = nativeTypes.isKeyObject;
const nativeNumberIsFinite = Number.isFinite;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeMathFloor = Math.floor;
const nativeMathAbs = Math.abs;
const nativeMathMin = Math.min;
const nativeMathCeil = Math.ceil;
const z = require("./rootark-zk-1");
const commitment = require("./rootark-zk1-offline-commitment-receipt");
const committedApproval = require("../../public/client/rootark-zk1-v2-committed-approval");
const browserPop = require("../../public/client/rootark-zk1-v2-browser-pop");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const roots = require("../../public/client/rootark-zk1-ciphertext-chunk-root");
const nativeApply = Reflect.apply;
const nativeObjectPrototype = Object.prototype;
const nativeGetPrototypeOf = Object.getPrototypeOf;
const nativeGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const nativeHasOwn = Object.hasOwn;
const nativeCreate = Object.create;
const nativeFreeze = Object.freeze;
const nativeDefineProperty = Object.defineProperty;
const nativeOwnKeys = Reflect.ownKeys;
const nativeArrayIsArray = Array.isArray;
const nativeArrayBufferIsView = ArrayBuffer.isView;
const nativeArrayBuffer = ArrayBuffer;
const nativeArrayBufferConstructorPrototype = nativeGetPrototypeOf(nativeArrayBuffer);
const nativeFunctionHasInstanceDescriptor = nativeGetOwnPropertyDescriptor(
  Function.prototype, Symbol.hasInstance);
const nativeUint8Array = Uint8Array;
const nativeTypedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const nativeTypedByteLength = Object.getOwnPropertyDescriptor(nativeTypedPrototype, "byteLength").get;
const nativeTypedBuffer = Object.getOwnPropertyDescriptor(nativeTypedPrototype, "buffer").get;
const nativeTypedByteOffset = Object.getOwnPropertyDescriptor(nativeTypedPrototype, "byteOffset").get;
const nativeTypedSet = Uint8Array.prototype.set;
const nativeArrayBufferByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
const nativeTypedFill = Uint8Array.prototype.fill;
const nativeBufferFrom = Buffer.from.bind(Buffer);
const nativeBufferPrototype = Buffer.prototype;
const nativeBufferAlloc = Buffer.alloc.bind(Buffer);
const nativeBufferConcat = Buffer.concat.bind(Buffer);
const nativeBufferToString = Buffer.prototype.toString;
const nativeTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeCreateHash = crypto.createHash.bind(crypto);
const nativeCreateHmac = crypto.createHmac.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeSign = crypto.sign.bind(crypto);
const nativeVerify = crypto.verify.bind(crypto);
const nativeRandomBytes = crypto.randomBytes.bind(crypto);
const nativeKeyObject = crypto.KeyObject;
// Node 22 defines export on PublicKeyObject's prototype, not on the generic
// KeyObject base. Pin the real native method through a fixed public test key;
// no caller-supplied owner key is inspected while capturing the intrinsic.
const nativeKeyObjectExport = nativeGetPrototypeOf(nativeCreatePublicKey({
  key: nativeBufferFrom("302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "hex"),
  format: "der", type: "spki",
})).export;
const nativeSubtle = crypto.webcrypto.subtle;
const nativeSubtleExportKey = nativeSubtle.exportKey;
const nativeSubtleEncrypt = nativeSubtle.encrypt;
const nativeWorkerPostMessage = Worker.prototype.postMessage;
const nativeWorkerTerminate = Worker.prototype.terminate;
const nativeMessagePortPrototype = MessagePort.prototype;
const nativeMessagePortPostMessage = MessagePort.prototype.postMessage;
const hpkeSealWorkerPath = path.join(__dirname,
  "rootark-zk1-owner-authorized-hpke-seal-worker.js");
const nativeJsonStringify = JSON.stringify;
const nativeDecodeDeterministic = z.decodeDeterministic.bind(z);
const nativeEncodeDeterministic = z.encodeDeterministic.bind(z);
const nativeHpkeSuite = z.hpkeSuite.bind(z);
const nativeHpkeOpen = z.hpkeOpen.bind(z);
// A captured @hpke/core method is not sufficient: its internal async mutex
// and AEAD dispatch are still callback-mutable. Only an isolated V8 realm may
// receive this CEK after the independent authority callback has executed.
const hpkeRequire = createRequire(require.resolve("@hpke/core"));
const hpkeAesContextPrototype = hpkeRequire("./src/aeads/aesGcm.js")
  .AesGcmContext.prototype;
const nativeHpkeAesSeal = hpkeAesContextPrototype.seal;
const nativeDecryptFile = fileContent.decryptFile.bind(fileContent);
const nativeImportFileCek = fileContent.importFileCek.bind(fileContent);
const nativeComputeCiphertextRoot = roots.computeCiphertextRoot.bind(roots);
const nativeVerifySignedReceipt = commitment.verifySignedReceipt.bind(commitment);
const nativeCommitmentSigningBytes = commitment.commitmentSigningBytes.bind(commitment);
const nativeVerifyCommittedApproval = committedApproval.verifyCommittedApproval.bind(committedApproval);
const nativeTargetDigest = browserPop.targetDigest.bind(browserPop);
const nativeHashPrototype = nativeGetPrototypeOf(nativeCreateHash("sha256"));
const nativeHashUpdate = nativeHashPrototype.update;
const nativeHashDigest = nativeHashPrototype.digest;
const nativeHmacPrototype = nativeGetPrototypeOf(nativeCreateHmac("sha256", nativeBufferAlloc(32)));
const nativeHmacUpdate = nativeHmacPrototype.update;
const nativeHmacDigest = nativeHmacPrototype.digest;
const HPKE_WORKER_ACK_DOMAIN = nativeBufferFrom("Root.ark/zk-1/owner-hpke-worker-ack/v1\0");
function nativeSha256(value) {
  const hash = nativeCreateHash("sha256");
  nativeApply(nativeHashUpdate, hash, [value]);
  return nativeApply(nativeHashDigest, hash, []);
}
function copyOwnedBytes(view, asBuffer = false) {
  // Typed-array internal slots cannot run caller-replaced @@hasInstance,
  // @@iterator, length or byteLength accessors after an authority callback.
  if (!nativeIsUint8Array(view) || nativeIsProxy(view)) deny();
  const size = nativeApply(nativeTypedByteLength, view, []);
  const target = asBuffer ? nativeBufferAlloc(size) : new nativeUint8Array(size);
  nativeApply(nativeTypedSet, target, [view]);
  return target;
}
function nativeBase64Url(value) {
  return nativeApply(nativeBufferToString, nativeBufferFrom(value), ["base64url"]);
}
function fieldsObject(keys, source) {
  const output = nativeCreate(null);
  for (const key of keys) nativeDefineProperty(output, key, {
    value: source[key], enumerable: true, writable: false, configurable: false });
  return output;
}
const DOMAIN = nativeBufferFrom("Root.ark/zk-1/owner-authorized-file-cek-transfer/v1\0");
const INFO = nativeBufferFrom("Root.ark/zk-1/owner-authorized-file-cek-info/v1\0");
const AAD = nativeBufferFrom("Root.ark/zk-1/owner-authorized-file-cek-aad/v1\0");
const FORMAT = "rootark-zk1-owner-device-file-cek-hpke/v1";
const GRANT = ["schema", "account_id", "compartment_id", "keyring_id", "device_id",
  "authorization_key_id", "authorization_public_key", "manifest_revision",
  "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const REQUEST = ["schema", "device_id", "authorization_key_id",
  "authorization_public_key", "hpke_key_id", "hpke_public_key", "challenge", "approval"];
const APPROVAL = ["schema", "request_sha256", "operation_id",
  "target_device_key_digest", "pop_challenge_id", "manifest_revision",
  "manifest_digest", "epoch", "grant_sha256", "issued_at", "expires_at"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const META = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
const BINDING = [...META, "object_revision", "device_id", "authorization_key_id",
  "hpke_key_id", "hpke_public_key", "owner_revision", "owner_digest", "owner_epoch",
  "witness_sequence", "witness_receipt_sha256", "signed_grant_sha256",
  "ciphertext_root", "ciphertext_sha256"];
const CORE = ["schema", ...BINDING, "nonce", "expires_at"];
function deny() { throw Error("ZK_OWNER_FILE_CEK_DENIED"); }
// Capture *all* caller-owned trust material synchronously, before the first
// await. Frozen plain objects cannot hide accessor reentrancy, and copying
// typed arrays prevents subsequent caller writes from changing pin/AEAD bytes.
// Native private/public keys are opaque handles, not caller-owned dictionaries.
function snapshotFields(value, depth = 0, budget = { count: 0, bytes: 0 }) {
  if (depth > 12 || ++budget.count > 512) deny();
  if (value !== null && (typeof value === "object" || typeof value === "function")
    && nativeIsProxy(value)) deny();
  if (value === null || typeof value === "boolean" || typeof value === "number"
    || typeof value === "string") {
    if (typeof value === "string" && value.length > 524288) deny();
    return value;
  }
  if (nativeIsUint8Array(value) || nativeIsArrayBuffer(value)) {
    const length = nativeIsUint8Array(value)
      ? nativeApply(nativeTypedByteLength, value, [])
      : nativeApply(nativeArrayBufferByteLength, value, []);
    budget.bytes += length;
    if (!nativeNumberIsSafeInteger(length) || length > 4 * 1024 * 1024
      || budget.bytes > 8 * 1024 * 1024) deny();
    // Buffer.isBuffer invokes mutable Uint8Array Symbol.hasInstance internally.
    // Use the pinned actual Buffer prototype without dispatching callbacks.
    if (nativeIsUint8Array(value) && nativeGetPrototypeOf(value) === nativeBufferPrototype) {
      return copyOwnedBytes(value, true);
    }
    if (nativeIsUint8Array(value)) return copyOwnedBytes(value);
    const target = new nativeArrayBuffer(length);
    nativeApply(nativeTypedSet, new nativeUint8Array(target), [new nativeUint8Array(value)]);
    return target;
  }
  if (nativeIsKeyObject(value)
    || nativeIsCryptoKey(value)) return value;
  // @hpke uses XCryptoKey wrapping mutable 32-byte private raw material.
  // Copy that material synchronously; reconstruct a fresh HPKE handle only
  // after all other authorization checks. Never keep the caller's raw array.
  const prototype = value && typeof value === "object"
    ? nativeGetPrototypeOf(value) : null;
  const ctor = prototype && nativeGetOwnPropertyDescriptor(prototype, "constructor");
  if (ctor && nativeHasOwn(ctor, "value")
    && ctor.value?.name === "XCryptoKey") {
    const d = nativeGetOwnPropertyDescriptors(value);
    const expected = ["key", "type", "extractable", "algorithm", "usages"];
    const keys = nativeOwnKeys(d);
    if (keys.length !== expected.length
      || d.type.value !== "private" || !nativeIsUint8Array(d.key.value)
      || nativeApply(nativeTypedByteLength, d.key.value, []) !== 32
      || !nativeArrayIsArray(d.usages.value)
      || d.usages.value.length > 8) deny();
    for (const name of expected)
      if (!d[name] || !nativeHasOwn(d[name], "value")) deny();
    const algorithm = snapshotFields(d.algorithm.value, depth + 1, budget);
    if (algorithm.name !== "X25519") deny();
    const usages = nativeGetOwnPropertyDescriptors(d.usages.value);
    for (let i = 0; i < d.usages.value.length; i++) {
      if (!nativeHasOwn(usages[i] ?? {}, "value")
        || typeof usages[i].value !== "string") deny();
    }
    return nativeFreeze({ hpkePrivateRaw: copyOwnedBytes(d.key.value) });
  }
  const plainPrototype = nativeGetPrototypeOf(value);
  if (typeof value !== "object" || nativeArrayIsArray(value)
    || (plainPrototype !== nativeObjectPrototype && plainPrototype !== null)) deny();
  const descriptors = nativeGetOwnPropertyDescriptors(value);
  const entries = nativeOwnKeys(descriptors);
  const out = nativeCreate(prototype);
  for (const name of entries) {
    if (typeof name !== "string" || !nativeHasOwn(descriptors[name], "value")) deny();
    nativeDefineProperty(out, name, { value: snapshotFields(
      descriptors[name].value, depth + 1, budget),
    enumerable: true, writable: false, configurable: false });
  }
  return nativeFreeze(out);
}
function exact(v, keys) {
  if (!v || nativeIsProxy(v) || typeof v !== "object" || nativeArrayIsArray(v)) deny();
  const prototype = nativeGetPrototypeOf(v);
  if (prototype !== nativeObjectPrototype && prototype !== null) deny();
  if (nativeOwnKeys(v).length !== keys.length) deny();
  for (const key of keys) if (!nativeHasOwn(v, key)) deny();
  return v;
}
function raw(v, length) {
  if (nativeIsProxy(v) || !nativeIsUint8Array(v)
    || nativeApply(nativeTypedByteLength, v, []) !== length) deny();
  // A signed authority read can invoke arbitrary JS callbacks. Never read
  // v.buffer/byteOffset/byteLength through replaceable inherited accessors:
  // the underlying view may contain the raw owner CEK when this is called.
  return nativeBufferFrom(nativeApply(nativeTypedBuffer, v, []),
    nativeApply(nativeTypedByteOffset, v, []), length);
}
function from64(v, n) {
  if (typeof v !== "string" || !/^[A-Za-z0-9_-]+$/.test(v)
    || v.length > nativeMathCeil(n * 4 / 3) + 3) deny();
  const b = nativeBufferFrom(v, "base64url");
  if (b.length !== n || nativeBase64Url(b) !== v) deny();
  return b;
}
const b64 = nativeBase64Url;
const sha = nativeSha256;
function compare(a, b) { return a.length === b.length && nativeTimingSafeEqual(a, b); }
function positive(v) { if (!nativeNumberIsSafeInteger(v) || v < 1) deny(); return v; }
function requireUnexpiredAtRelease(expiresAt, wallClock) {
  if (!nativeNumberIsSafeInteger(expiresAt)
    || Date.now !== wallClock || !nativeNumberIsFinite(wallClock())
    || nativeMathFloor(wallClock() / 1000) >= expiresAt) deny();
}
function wipeOwnedBytes(value) {
  // Never dispatch an attacker-replaced Buffer/Uint8Array prototype method:
  // the final authority callback can run after the actual CEK is in memory.
  if (value && !nativeIsProxy(value) && nativeIsUint8Array(value)) {
    nativeApply(nativeTypedFill, value, [0]);
  }
}
function newPrivateHpkeWorker() {
  // Construct a fresh worker only after valid owner authorization. No
  // authority callback can mutate this worker's separate V8 realm, even when
  // those callbacks have already changed the caller realm's prototypes.
  const options = nativeCreate(null);
  options.execArgv = [];
  // Do not inherit unrelated process credentials/environment into a helper
  // that only needs the already-pinned module and explicit public inputs.
  options.env = nativeCreate(null);
  const worker = new Worker(hpkeSealWorkerPath, options);
  let deadline;
  try {
  // Node 22 Worker.postMessage internally delegates to two private native
  // MessagePorts. A callback can poison MessagePort.prototype.postMessage
  // and observe the 32-byte CEK despite a captured Worker.postMessage. Pin
  // the native method ON EACH actual internal port before any secret transfer.
  // Inspect own value descriptors only; never invoke inherited getters.
  const ownedPorts = nativeGetOwnPropertyDescriptors(worker);
  let pinnedPorts = 0;
  for (const key of nativeOwnKeys(ownedPorts)) {
    const descriptor = ownedPorts[key];
    if (!nativeHasOwn(descriptor, "value")) continue;
    const port = descriptor.value;
    if (!port || typeof port !== "object" || nativeIsProxy(port)
      || nativeGetPrototypeOf(port) !== nativeMessagePortPrototype) continue;
    nativeDefineProperty(port, "postMessage", {
      value: nativeMessagePortPostMessage, writable: false, configurable: false,
    });
    pinnedPorts++;
  }
  // Fail closed if a future Node version changes the Worker transport layout.
  if (pinnedPorts !== 2) deny();
  // Worker inherits EventEmitter.emit from the caller's mutable realm. An
  // authority callback can replace that method after the worker is started
  // and substitute a valid HPKE envelope for a different CEK. Pin the native
  // dispatcher on this instance before registering any response handlers.
  nativeDefineProperty(worker, "emit", {
    value: nativeEventEmit, writable: false, configurable: false,
  });
  let completed = false;
  let resolveReply, rejectReply;
  const reply = new NativePromise((resolve, reject) => {
    resolveReply = resolve;
    rejectReply = reject;
  });
  // An early worker failure may precede the eventual await; consume that
  // rejection immediately without changing what await(reply) will observe.
  nativeApply(nativePromiseThen, reply, [undefined, () => {}]);
  const settle = (ok, value) => {
    if (completed) return;
    completed = true;
    nativeClearTimeout(deadline);
    if (ok) resolveReply(value);
    else rejectReply(Error(value));
  };
  nativeApply(nativeEventOn, worker, ["message", (message) => {
    settle(true, message);
  }]);
  nativeApply(nativeEventOn, worker, ["error", () => {
    settle(false, "ZK_OWNER_HPKE_WORKER_FAILED");
  }]);
  nativeApply(nativeEventOn, worker, ["exit", () => {
    settle(false, "ZK_OWNER_HPKE_WORKER_EXITED");
  }]);
  // Never wait indefinitely with a sensitive CEK detached into a worker.
  // Terminate a stalled worker and deny, without accepting a late ciphertext.
  deadline = nativeSetTimeout(() => {
    if (completed) return;
    settle(false, "ZK_OWNER_HPKE_WORKER_TIMEOUT");
    try {
      const dying = nativeApply(nativeWorkerTerminate, worker, []);
      nativeApply(nativePromiseThen, dying, [() => {}, () => {}]);
    } catch (_) { /* only the denial may escape */ }
  }, 45_000);
  return { worker, reply };
  } catch (error) {
    // A malicious callback can poison Promise[Symbol.species] or another
    // mutable intrinsic between construction and listener installation. Do
    // not leak a live worker when any part of its setup throws: no CEK has
    // crossed the boundary at this point, and no worker handle was returned.
    nativeClearTimeout(deadline);
    try { nativeApply(nativeWorkerTerminate, worker, []); }
    catch (_) { /* preserve the original fail-closed setup error */ }
    throw error;
  }
}
async function sealPrivateCekHpke(isolatedWorker, recipientPublicKeyRaw, plaintext, info, aad) {
  // The only secret-bearing message crosses the native structured-clone
  // boundary via a transferred ArrayBuffer. No mutable HPKE JS prototype in
  // the authority callback's realm can observe those 32 bytes.
  const isolated = new nativeArrayBuffer(32);
  const view = new nativeUint8Array(isolated);
  // A malicious authority callback can replace the native transport's
  // MessagePort.on handler and forge a syntactically valid HPKE response. A
  // per-operation MAC key is transferred privately along with the CEK; the
  // receiving realm can inspect a response but cannot forge its authenticator.
  const ackSecret = nativeRandomBytes(32);
  const ackKey = new nativeArrayBuffer(32);
  const ackView = new nativeUint8Array(ackKey);
  nativeApply(nativeTypedSet, ackView, [ackSecret]);
  nativeApply(nativeTypedSet, view, [plaintext]);
  try {
    // Retain the earlier fail-closed policy for directly poisoned HPKE or
    // WebCrypto methods. The worker isolation is the decisive protection for
    // mutations installed after these checks (for example, via mutex.lock).
    if (nativeGetPrototypeOf(nativeArrayBuffer) !== nativeArrayBufferConstructorPrototype
      || nativeGetOwnPropertyDescriptor(nativeArrayBuffer, Symbol.hasInstance)
      || nativeGetOwnPropertyDescriptor(Function.prototype, Symbol.hasInstance)?.value
        !== nativeFunctionHasInstanceDescriptor.value
      || nativeGetOwnPropertyDescriptor(hpkeAesContextPrototype, "seal")?.value
        !== nativeHpkeAesSeal
      || nativeSubtle.encrypt !== nativeSubtleEncrypt) deny();
    const request = nativeCreate(null);
    request.type = "seal";
    request.cek = isolated;
    request.ackKey = ackKey;
    request.recipientPublicKey = copyOwnedBytes(recipientPublicKeyRaw);
    request.info = copyOwnedBytes(info);
    request.aad = copyOwnedBytes(aad);
    // The native Worker method is pinned at module initialization, and the
    // transfer detaches the CEK bytes from this realm synchronously.
    nativeApply(nativeWorkerPostMessage, isolatedWorker.worker, [request, [isolated, ackKey]]);
    const response = await isolatedWorker.reply;
    if (!response || response.ok !== true) deny();
    const enc = copyOwnedBytes(response.enc, true);
    const ciphertext = copyOwnedBytes(response.ciphertext, true);
    const ackMac = copyOwnedBytes(response.ackMac, true);
    if (nativeApply(nativeTypedByteLength, enc, []) !== 32
      || nativeApply(nativeTypedByteLength, ciphertext, []) !== 48
      || nativeApply(nativeTypedByteLength, ackMac, []) !== 32) deny();
    const verifier = nativeCreateHmac("sha256", ackSecret);
    nativeApply(nativeHmacUpdate, verifier, [HPKE_WORKER_ACK_DOMAIN]);
    nativeApply(nativeHmacUpdate, verifier, [enc]);
    nativeApply(nativeHmacUpdate, verifier, [ciphertext]);
    if (!nativeTimingSafeEqual(nativeApply(nativeHmacDigest, verifier, []), ackMac)) deny();
    return { enc, ciphertext };
  } finally {
    nativeApply(nativeTypedFill, ackSecret, [0]);
    if (nativeApply(nativeArrayBufferByteLength, ackKey, []) !== 0)
      nativeApply(nativeTypedFill, ackView, [0]);
    // Detachment is expected. On a failed transfer the original view remains
    // attached, and must be erased by the original native typed-array method.
    if (nativeApply(nativeArrayBufferByteLength, isolated, []) !== 0)
      nativeApply(nativeTypedFill, view, [0]);
  }
}
function metadataCopy(meta) {
  exact(meta, META);
  for (const n of ["account_id", "keyring_id", "object_id", "version_id"])
    from64(meta[n], 16);
  const compartment = nativeBufferFrom(meta.compartment_id, "base64url");
  if (!compartment.length || compartment.length > 128
    || b64(compartment) !== meta.compartment_id) deny();
  if (meta.parent_version_id !== null) from64(meta.parent_version_id, 16);
  positive(meta.epoch);
  if (meta.kind !== "file") deny();
  return fieldsObject(META, meta);
}
function headFrom(a) {
  const h = a.currentHead || a.pinnedCurrentHead;
  if (!h) deny();
  return { revision: positive(h.revision), epoch: positive(h.epoch),
    digest: raw(h.digest, 32) };
}
function toNodePub(publicKey) {
  if (publicKey && !nativeIsProxy(publicKey) && nativeIsKeyObject(publicKey)
    && nativeApply(nativeGetOwnPropertyDescriptor(nativeKeyObject.prototype, "type").get,
      publicKey, []) === "public") return publicKey;
  deny();
}
async function verifyOwnerApprovedHpkeRecipient(a, trusted, owner, nowSeconds) {
  // An Ed25519 device grant does NOT authenticate its unrelated X25519 key.
  // The owner's separate V2 approval commits to the complete request and
  // target PoP digest. Verify it before exposing an A-held CEK to that key.
  const request = exact(a.request, REQUEST);
  const approval = exact(a.approval, [...APPROVAL, "signature"]);
  if (request.schema !== "rootark-zk1-device-enrollment-request/v1"
    || request.approval !== "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT"
    || approval.schema !== "rootark-zk1-offline-v2-device-approval/v1"
    || !nativeNumberIsSafeInteger(approval.issued_at)
    || !nativeNumberIsSafeInteger(approval.expires_at)
    || approval.expires_at <= approval.issued_at
    || approval.expires_at - approval.issued_at > 300
    || approval.issued_at > nowSeconds + 30
    || approval.expires_at < nowSeconds) deny();
  from64(request.challenge, 32);
  for (const field of ["request_sha256", "target_device_key_digest",
    "manifest_digest", "grant_sha256"]) from64(approval[field], 32);
  for (const field of ["operation_id", "pop_challenge_id"]) from64(approval[field], 16);
  if (approval.request_sha256 !== b64(sha(nativeBufferFrom(nativeJsonStringify(request))))
    || approval.grant_sha256 !== b64(sha(nativeBufferFrom(nativeJsonStringify(
      fieldsObject(GRANT, trusted.grant)))))
    || approval.target_device_key_digest !== await nativeTargetDigest(request)
    || approval.manifest_revision !== trusted.head.revision
    || approval.manifest_digest !== b64(trusted.head.digest)
    || approval.epoch !== trusted.head.epoch
    || approval.operation_id !== a.committedReceipt.operation_id
    || approval.pop_challenge_id !== a.committedReceipt.pop_challenge_id
    || request.challenge !== a.committedReceipt.request_nonce) deny();
  const approvedMessage = nativeBufferConcat([
    nativeBufferFrom("Root.ark/zk-1/v2-offline-device-approval/v1\0"),
    nativeBufferFrom(nativeJsonStringify(fieldsObject(APPROVAL, approval)))]);
  if (!nativeVerify(null, approvedMessage, owner, from64(approval.signature, 64))) deny();

  // The witness-pinned head identifies the exact signed V2 manifest, not a
  // JSON self-assertion. Ensure its committed target public keys match B.
  const manifestBytes = nativeBufferFrom(a.signedV2Manifest, "base64url");
  if (manifestBytes.length < 128 || manifestBytes.length > 262144
    || b64(manifestBytes) !== a.signedV2Manifest
    || !compare(sha(nativeBufferConcat([
      nativeBufferFrom("Root.ark/zk-1/recovery-manifest-digest/v1\0"), manifestBytes])),
    trusted.head.digest)) deny();
  const v2 = await nativeDecodeDeterministic(manifestBytes);
  let device = null;
  if (nativeArrayIsArray(v2.devices)) {
    for (const candidate of v2.devices)
      if (candidate?.device_id === request.device_id) { device = candidate; break; }
  }
  if (!device
    || !compare(nativeBufferFrom(device.hpke_public_key), from64(request.hpke_public_key, 32))
    || !compare(nativeBufferFrom(device.hpke_key_id), from64(request.hpke_key_id, 16))
    || !compare(nativeBufferFrom(device.authorization_public_key),
      from64(request.authorization_public_key, 32))
    || !compare(nativeBufferFrom(device.authorization_key_id),
      from64(request.authorization_key_id, 16))
    || !compare(nativeBufferFrom(v2.operation?.target_device_key_digest),
      from64(approval.target_device_key_digest, 32))) deny();
  return nativeBufferFrom(device.hpke_public_key);
}
async function normalizedAuthority(a, minimumSequence, nowSeconds, nodeKeys, wallClock) {
  positive(minimumSequence); positive(nowSeconds);
  // A caller-supplied old time cannot resurrect an expired signed grant.
  if (Date.now !== wallClock
    || nativeMathAbs(nativeMathFloor(wallClock() / 1000) - nowSeconds) > 30) deny();
  const grant = exact(snapshotFields(a.signedDeviceGrant), [...GRANT, "signature"]);
  const request = snapshotFields(a.request);
  if (!request || typeof request !== "object") deny();
  const owner = nodeKeys.owner, witness = nodeKeys.witness;
  const ownerHash = sha(nativeApply(nativeKeyObjectExport, owner,
    [{ type: "spki", format: "der" }]));
  if (!compare(ownerHash, raw(a.independentOwnerSpkiSha256, 32))) deny();
  const head = headFrom(a);
  for (const k of SCOPE) {
    const value = nativeBufferFrom(grant[k], "base64url");
    if (!value.length || value.length > (k === "compartment_id" ? 128 : 16)
      || (k !== "compartment_id" && value.length !== 16)
      || b64(value) !== grant[k]) deny();
  }
  if (!request || typeof request.device_id !== "string" || !request.device_id
    || request.device_id !== grant.device_id
    || request.authorization_key_id !== grant.authorization_key_id
    || request.authorization_public_key !== grant.authorization_public_key
    || grant.revoked_at_epoch !== null
    || grant.manifest_revision !== head.revision
    || grant.manifest_digest !== b64(head.digest)
    || grant.current_epoch !== head.epoch) deny();
  from64(request.hpke_key_id, 16);
  from64(request.hpke_public_key, 32);
  from64(request.authorization_public_key, 32);
  if (grant.enrolled_epoch > head.epoch) deny();
  const signatureInput = nativeBufferConcat([
    nativeBufferFrom("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
    nativeBufferFrom(nativeJsonStringify(fieldsObject(GRANT, grant)))]);
  if (!nativeVerify(null, signatureInput, owner, from64(grant.signature, 64))) deny();
  const expectedScope = nativeCreate(null);
  for (const key of SCOPE) nativeDefineProperty(expectedScope, key, {
    value: nativeBufferFrom(grant[key], "base64url"), enumerable: true,
    writable: false, configurable: false });
  const receipt = nativeVerifySignedReceipt({
    receipt: a.committedReceipt, signerPublicKey: witness,
    independentSignerSpkiSha256: b64(raw(a.independentWitnessSpkiSha256, 32)),
    expectedScope, expectedHead: head,
    nowSeconds, previousReceipt: a.previousReceipt,
  });
  if (receipt.sequence < minimumSequence) deny();
  const signedReceiptBytes = nativeBufferConcat([
    nativeCommitmentSigningBytes(fieldsObject(commitment.FIELDS, a.committedReceipt)),
    from64(a.committedReceipt.signature, 64)]);
  return { grant, request, head, scope: expectedScope, sequence: receipt.sequence,
    receiptDigest: sha(signedReceiptBytes), grantDigest: sha(signatureInput),
    expiresAt: nativeMathMin(a.committedReceipt.expires_at, nowSeconds + 300) };
}
async function binding({ metadata, revision, ciphertext, ciphertextRoot, authority }) {
  const meta = metadataCopy(metadata);
  positive(revision);
  const data = nativeBufferFrom(ciphertext);
  if (!data.length || data.length > 4 * 1024 * 1024) deny();
  const pin = raw(ciphertextRoot, 32);
  if (!compare(nativeBufferFrom(await nativeComputeCiphertextRoot([data])), pin)) deny();
  for (const name of SCOPE) if (!compare(nativeBufferFrom(meta[name], "base64url"),
    authority.scope[name])) deny();
  if (meta.epoch > authority.head.epoch) deny();
  return { ...meta, object_revision: revision,
    device_id: authority.request.device_id,
    authorization_key_id: authority.request.authorization_key_id,
    hpke_key_id: authority.request.hpke_key_id,
    hpke_public_key: authority.request.hpke_public_key,
    owner_revision: authority.head.revision,
    owner_digest: b64(authority.head.digest),
    owner_epoch: authority.head.epoch,
    witness_sequence: authority.sequence,
    witness_receipt_sha256: b64(authority.receiptDigest),
    signed_grant_sha256: b64(authority.grantDigest),
    ciphertext_root: b64(pin),
    ciphertext_sha256: b64(sha(data)) };
}
async function sealOwnerAuthorizedFileCek(input) {
  const wallClock = Date.now;
  let cek, checked, stable, isolatedWorker;
  try {
    stable = snapshotFields(input);
    exact(stable, ["ownerPrivateKey", "ownerHeldCek", "metadata",
      "objectRevision", "ciphertext", "ciphertextRoot", "authority"]);
    const a = stable.authority;
    const owner = nativeCreatePublicKey(stable.ownerPrivateKey);
    const witness = toNodePub(a.witnessPublicKey);
    const trusted = await normalizedAuthority(a, a.operatorMinimumSequence,
      a.nowSeconds, { owner, witness }, wallClock);
    const ownerApprovedHpkePublicKey = await verifyOwnerApprovedHpkeRecipient(
      a, trusted, owner, a.nowSeconds);
    cek = nativeBufferFrom(raw(stable.ownerHeldCek, 32));
    // Possession of arbitrary 32 bytes is not proof of owning this particular
    // file's CEK. The authorizing owner must demonstrate an AEAD open of the
    // exact pinned ciphertext before exporting a recipient-specific envelope.
    checked = await nativeDecryptFile({
      cek: await nativeImportFileCek(cek),
      metadata: stable.metadata, envelopeBytes: stable.ciphertext });
    const core = { schema: FORMAT, ...await binding({
      metadata: stable.metadata, revision: stable.objectRevision,
      ciphertext: stable.ciphertext, ciphertextRoot: stable.ciphertextRoot, authority: trusted }),
      nonce: b64(nativeRandomBytes(16)),
      expires_at: nativeMathMin(trusted.expiresAt, a.approval.expires_at) };
    exact(core, CORE);
    if (!compare(from64(core.hpke_public_key, 32), ownerApprovedHpkePublicKey)) deny();
    const context = nativeBufferFrom(await nativeEncodeDeterministic(core));
    isolatedWorker = newPrivateHpkeWorker();
    const sealed = await sealPrivateCekHpke(isolatedWorker, ownerApprovedHpkePublicKey, cek,
      nativeBufferConcat([INFO, context]), nativeBufferConcat([AAD, context]));
    // The helper wipes its CEK before returning ciphertext. Ensure the
    // worker exits before the signed release's final wall-clock check.
    await nativeApply(nativeWorkerTerminate, isolatedWorker.worker, []);
    isolatedWorker = null;
    const message = nativeBufferConcat([DOMAIN, await nativeEncodeDeterministic({
      core, enc: sealed.enc, ciphertext: sealed.ciphertext })]);
    // AEAD and HPKE are asynchronous. The signed approval can expire while
    // the owner holds the CEK; gate its final export using the real wall clock.
    requireUnexpiredAtRelease(core.expires_at, wallClock);
    return nativeFreeze({ schema: FORMAT, core, enc: b64(sealed.enc),
      ciphertext: b64(sealed.ciphertext),
      owner_signature: b64(nativeSign(null, message, stable.ownerPrivateKey)),
      authorizesProductionRestore: false, externalCustodyProven: false });
  } catch (_) { deny(); }
  finally {
    wipeOwnedBytes(checked?.data);
    wipeOwnedBytes(cek);
    wipeOwnedBytes(stable?.ownerHeldCek);
    if (isolatedWorker) {
      try { await nativeApply(nativeWorkerTerminate, isolatedWorker.worker, []); }
      catch (_) { /* keep the original denial and scrub regardless */ }
    }
  }
}
async function openOwnerAuthorizedFileCek(input) {
  const wallClock = Date.now;
  let cek, stable;
  try {
    stable = snapshotFields(input);
    exact(stable, ["envelope", "authority", "operatorMinimumSequence", "metadata",
      "objectRevision", "ciphertext", "ciphertextRoot", "deviceHpkePrivateKey",
      "nowSeconds"]);
    const { envelope: wire, authority: a } = stable;
    exact(wire, ["schema", "core", "enc", "ciphertext", "owner_signature",
      "authorizesProductionRestore", "externalCustodyProven"]);
    if (wire.schema !== FORMAT || wire.authorizesProductionRestore !== false
      || wire.externalCustodyProven !== false) deny();
    const approved = await nativeVerifyCommittedApproval({
      ...a, nowSeconds: stable.nowSeconds });
    if (approved.committedOwnerApprovalVerified !== true
      || approved.authorizesProductionIo !== false) deny();
    const ownerSpki = await nativeApply(nativeSubtleExportKey, nativeSubtle,
      ["spki", a.ownerPublicKey]);
    const witnessSpki = await nativeApply(nativeSubtleExportKey, nativeSubtle,
      ["spki", a.witnessPublicKey]);
    const owner = nativeCreatePublicKey({ key: nativeBufferFrom(ownerSpki),
      format: "der", type: "spki" });
    const witness = nativeCreatePublicKey({ key: nativeBufferFrom(witnessSpki),
      format: "der", type: "spki" });
    const trusted = await normalizedAuthority(a, stable.operatorMinimumSequence,
      stable.nowSeconds, { owner, witness }, wallClock);
    const core = wire.core;
    exact(core, CORE);
    if (core.schema !== FORMAT || !nativeNumberIsSafeInteger(core.expires_at)
      || core.expires_at < stable.nowSeconds) deny();
    const expected = await binding({
      metadata: stable.metadata, revision: stable.objectRevision,
      ciphertext: stable.ciphertext, ciphertextRoot: stable.ciphertextRoot, authority: trusted });
    for (const key of BINDING) if (core[key] !== expected[key]) deny();
    from64(core.nonce, 16);
    const context = nativeBufferFrom(await nativeEncodeDeterministic(core));
    const enc = from64(wire.enc, 32);
    const ciphertext = from64(wire.ciphertext, 48);
    const signed = nativeBufferConcat([DOMAIN,
      await nativeEncodeDeterministic({ core, enc, ciphertext })]);
    if (!nativeVerify(null, signed, owner, from64(wire.owner_signature, 64))) deny();
    if (!nativeIsUint8Array(stable.deviceHpkePrivateKey?.hpkePrivateRaw)
      || stable.deviceHpkePrivateKey.hpkePrivateRaw.length !== 32) deny();
    const deviceHpkeKey = await nativeHpkeSuite().kem.deserializePrivateKey(
      stable.deviceHpkePrivateKey.hpkePrivateRaw);
    cek = nativeBufferFrom(await nativeHpkeOpen({ recipientKey: deviceHpkeKey,
      enc, ciphertext, info: nativeBufferConcat([INFO, context]),
      aad: nativeBufferConcat([AAD, context]) }));
    if (cek.length !== 32) deny();
    // Last use: reject a now-expired owner approval/receipt before returning
    // plaintext-equivalent CEK bytes to B, even if HPKE was valid at entry.
    // Release the minimum expiration from the exact owner-approved envelope,
    // committed approval and independently verified witness snapshot, rather
    // than forcing a later caller to reread mutable untrusted authority.
    const verifiedReleaseExpiresAt = nativeMathMin(core.expires_at,
      a.approval.expires_at, a.committedReceipt.expires_at);
    requireUnexpiredAtRelease(verifiedReleaseExpiresAt, wallClock);
    return nativeFreeze({ cek: nativeBufferFrom(cek), verifiedReleaseExpiresAt,
      authorizesProductionRestore: false,
      externalCustodyProven: false });
  } catch (_) { deny(); }
  finally {
    wipeOwnedBytes(cek);
    wipeOwnedBytes(stable?.deviceHpkePrivateKey?.hpkePrivateRaw);
  }
}
module.exports = { sealOwnerAuthorizedFileCek, openOwnerAuthorizedFileCek };
