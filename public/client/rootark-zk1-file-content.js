(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("node:crypto").webcrypto);
  else root.RootarkZk1FileContent = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // Browser-side sealed content for a freshly generated per-version CEK.
  // This module does NOT own the device key hierarchy, CEK wrapping, trusted
  // bootstrap, recovery or the online witness gate. Its wire is independently
  // versioned and must not be substituted for the signed zk-1 keyring format.
  const subtle = webCrypto && webCrypto.subtle;
  // These references are captured before any owner/recipient authority
  // callback can mutate shared JS prototypes or WebCrypto methods. In
  // particular importKey receives raw CEK bytes; a replaced method could
  // otherwise copy them before returning a legitimate CryptoKey.
  const nativeApply = Reflect.apply;
  const NativeUint8Array = Uint8Array;
  const nativeIsView = ArrayBuffer.isView;
  const nativeTypedSet = Uint8Array.prototype.set;
  const nativeTypedProto = Object.getPrototypeOf(Uint8Array.prototype);
  const nativeTypedLength = Object.getOwnPropertyDescriptor(
    nativeTypedProto, "length").get;
  const nativeTypedByteLength = Object.getOwnPropertyDescriptor(
    nativeTypedProto, "byteLength").get;
  const nativeTypedBuffer = Object.getOwnPropertyDescriptor(nativeTypedProto, "buffer").get;
  const nativeTypedByteOffset = Object.getOwnPropertyDescriptor(nativeTypedProto, "byteOffset").get;
  const nativeDataViewBuffer = Object.getOwnPropertyDescriptor(DataView.prototype, "buffer").get;
  const nativeDataViewByteOffset = Object.getOwnPropertyDescriptor(DataView.prototype, "byteOffset").get;
  const nativeDataViewByteLength = Object.getOwnPropertyDescriptor(DataView.prototype, "byteLength").get;
  const nativeArrayBufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, "byteLength").get;
  const nativeArrayBufferSlice = ArrayBuffer.prototype.slice;
  const nativeTypedFill = Uint8Array.prototype.fill;
  const nativeImportKey = subtle && subtle.importKey;
  const nativeEncrypt = subtle && subtle.encrypt;
  const nativeDecrypt = subtle && subtle.decrypt;
  const nativeTextEncode = TextEncoder.prototype.encode;
  const nativeTextDecode = TextDecoder.prototype.decode;
  const nativeJsonParse = JSON.parse;
  const nativeJsonStringify = JSON.stringify;
  const nativeAtob = atob;
  const nativeBtoa = btoa;
  const nativeCharCodeAt = String.prototype.charCodeAt;
  const nativeFromCharCode = String.fromCharCode;
  const nativeGetPrototypeOf = Object.getPrototypeOf;
  const nativeOwnKeys = Reflect.ownKeys;
  const nativeHasOwn = Object.hasOwn;
  const nativeArrayIsArray = Array.isArray;
  const nativeObjectPrototype = Object.prototype;
  function wipeOwned(value) {
    if (value) nativeApply(nativeTypedFill, value, [0]);
  }
  const encode = new TextEncoder();
  const decode = new TextDecoder("utf-8", { fatal: true });
  const FORMAT = "rootark-zk1-file-v1";
  const DOMAIN = "Root.ark/zk-1/content-aead/v1\0";
  const MOVE_FORMAT = "rootark-zk1-file-v2";
  const MOVE_DOMAIN = "Root.ark/zk-1/content-aead/v2\0";
  const MAX_PLAIN = 2 * 1024 * 1024;
  const MAX_WIRE = 4 * 1024 * 1024;
  const METADATA_FIELDS = ["account_id", "compartment_id", "keyring_id", "object_id",
    "version_id", "parent_version_id", "epoch", "kind"];
  function fail() { throw new Error("ZK_FILE_INVALID"); }
  function strict(obj, fields) {
    if (!obj || typeof obj !== "object" || nativeArrayIsArray(obj)) fail();
    const proto = nativeGetPrototypeOf(obj);
    if (proto !== nativeObjectPrototype && proto !== null) fail();
    const ownKeys = nativeOwnKeys(obj);
    if (ownKeys.length !== fields.length) fail();
    // The owner callback can replace Array.some/includes as well as the
    // Object/Reflect methods. Do not dispatch any of them on decoded payload.
    for (let i = 0; i < fields.length; i++) {
      if (!nativeHasOwn(obj, fields[i])) fail();
      let known = false;
      for (let k = 0; k < fields.length; k++) {
        if (ownKeys[i] === fields[k]) { known = true; break; }
      }
      if (!known) fail();
    }
  }
  function asBytes(value) {
    if (nativeIsView(value)) {
      // No instanceof: Uint8Array Symbol.hasInstance can be replaced by an
      // authority callback to observe the raw owner CEK. Capture intrinsic
      // buffer getters and copy internal byte slots without an iterator.
      let buffer, offset, size;
      try {
        buffer = nativeApply(nativeTypedBuffer, value, []);
        offset = nativeApply(nativeTypedByteOffset, value, []);
        size = nativeApply(nativeTypedByteLength, value, []);
      } catch (_) {
        buffer = nativeApply(nativeDataViewBuffer, value, []);
        offset = nativeApply(nativeDataViewByteOffset, value, []);
        size = nativeApply(nativeDataViewByteLength, value, []);
      }
      const originalBytes = new NativeUint8Array(buffer, offset, size);
      const copy = new NativeUint8Array(size);
      nativeApply(nativeTypedSet, copy, [originalBytes]);
      return copy;
    }
    try {
      nativeApply(nativeArrayBufferLength, value, []);
      return new NativeUint8Array(nativeApply(nativeArrayBufferSlice, value, [0]));
    } catch (_) { fail(); }
  }
  function b64(bytes) {
    let binary = "";
    const size = nativeApply(nativeTypedLength, bytes, []);
    for (let index = 0; index < size; index++) {
      binary += nativeFromCharCode(bytes[index]);
    }
    const base = nativeBtoa(binary);
    let result = "";
    for (let index = 0; index < base.length; index++) {
      const code = nativeApply(nativeCharCodeAt, base, [index]);
      if (code === 61) continue; // terminal '=' padding from genuine btoa
      result += nativeFromCharCode(code === 43 ? 45 : code === 47 ? 95 : code);
    }
    return result;
  }
  function from64(value, min = 1, max = 128) {
    if (typeof value !== "string" || (value.length === 0 && min !== 0)
      || value.length > max * 2 + 4) fail();
    // Neither String.replace(regex) nor RegExp.test is safe after executable
    // independent authority: both dispatch mutable RegExp @@replace/exec.
    let standard = "";
    for (let i = 0; i < value.length; i++) {
      const code = nativeApply(nativeCharCodeAt, value, [i]);
      if (code >= 65 && code <= 90 || code >= 97 && code <= 122
        || code >= 48 && code <= 57) standard += nativeFromCharCode(code);
      else if (code === 45) standard += "+";
      else if (code === 95) standard += "/";
      else fail();
    }
    let binary;
    try {
      while (standard.length % 4 !== 0) standard += "=";
      binary = nativeAtob(standard);
    } catch (_) { fail(); }
    // Never call an attacker-overridden string iterator on decrypted data.
    const result = new NativeUint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
      result[index] = nativeApply(nativeCharCodeAt, binary, [index]);
    }
    const size = nativeApply(nativeTypedLength, result, []);
    if (size < min || size > max || b64(result) !== value) fail();
    return result;
  }
  function id(value, min = 16, max = 16) {
    if (min === 16 && max === 16 && (typeof value !== "string"
      || value.length !== 22)) fail();
    from64(value, min, max);
    return value;
  }
  function normalizedMetadata(metadata) {
    strict(metadata, METADATA_FIELDS);
    const normalized = {
      account_id: id(metadata.account_id),
      compartment_id: id(metadata.compartment_id, 1, 128),
      keyring_id: id(metadata.keyring_id),
      object_id: id(metadata.object_id),
      version_id: id(metadata.version_id),
      parent_version_id: metadata.parent_version_id === null
        ? null : id(metadata.parent_version_id),
      epoch: metadata.epoch, kind: metadata.kind,
    };
    if (!Number.isSafeInteger(normalized.epoch) || normalized.epoch < 1
      || !["file", "derived-data"].includes(normalized.kind)) fail();
    return normalized;
  }
  function keyIsValid(cek) {
    if (!cek || cek.type !== "secret" || cek.extractable !== false
      || cek.algorithm?.name !== "AES-GCM" || cek.algorithm?.length !== 256
      || !cek.usages.includes("encrypt") || !cek.usages.includes("decrypt")) fail();
  }
  function aadFor(metadata, format = FORMAT) {
    return nativeApply(nativeTextEncode, encode, [
      (format === MOVE_FORMAT ? MOVE_DOMAIN : DOMAIN)
        + nativeJsonStringify(normalizedMetadata(metadata))]);
  }
  function validName(name) {
    if (typeof name !== "string" || name.length < 1 || name.length > 255) return false;
    for (let i = 0; i < name.length; i++) {
      const code = nativeApply(nativeCharCodeAt, name, [i]);
      if (code <= 31 || code === 127 || code === 47 || code === 92) return false;
    }
    return true;
  }
  function hasControlCharacters(value) {
    for (let i = 0; i < value.length; i++) {
      const code = nativeApply(nativeCharCodeAt, value, [i]);
      if (code <= 31 || code === 127) return true;
    }
    return false;
  }
  async function generateFileCek() {
    if (!subtle) fail();
    const raw = webCrypto.getRandomValues(new NativeUint8Array(32));
    try {
      return await nativeApply(nativeImportKey, subtle, ["raw", raw,
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]]);
    } finally { wipeOwned(raw); }
  }
  async function importFileCek(rawCek) {
    if (!subtle) fail();
    const source = asBytes(rawCek);
    if (nativeApply(nativeTypedLength, source, []) !== 32) fail();
    try {
      return await nativeApply(nativeImportKey, subtle, ["raw", source,
        { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]]);
    } finally { wipeOwned(source); }
  }
  async function encryptFile({ cek, metadata, name, mediaType, data }) {
    return sealFile({ cek, metadata, name, mediaType, data }, FORMAT, undefined);
  }
  // A folder reference stays inside the AEAD payload; the store only sees an
  // opaque object/version chain. The new domain prevents V1/V2 substitution.
  async function encryptFileWithParent({ cek, metadata, name, mediaType, data,
    parentFolderId }) {
    if (parentFolderId !== null) id(parentFolderId);
    return sealFile({ cek, metadata, name, mediaType, data }, MOVE_FORMAT, parentFolderId);
  }
  async function sealFile({ cek, metadata, name, mediaType, data }, format, parentFolderId) {
    if (!subtle) fail();
    keyIsValid(cek);
    const context = normalizedMetadata(metadata);
    if (!validName(name) || typeof mediaType !== "string" || mediaType.length > 128
      || hasControlCharacters(mediaType)) fail();
    const raw = asBytes(data);
    const rawSize = nativeApply(nativeTypedLength, raw, []);
    if (rawSize > MAX_PLAIN) fail();
    const payload = nativeApply(nativeTextEncode, encode, [nativeJsonStringify({
      name, mediaType, length: rawSize, content: b64(raw),
      ...(format === MOVE_FORMAT ? { parentFolderId } : {}),
    })]);
    const nonce = webCrypto.getRandomValues(new NativeUint8Array(12));
    try {
      const sealed = new NativeUint8Array(await nativeApply(nativeEncrypt, subtle, [{
        name: "AES-GCM", iv: nonce, additionalData: aadFor(context, format), tagLength: 128,
      }, cek, payload]));
      const wire = nativeApply(nativeTextEncode, encode, [nativeJsonStringify({
        format, algorithm: "AES-256-GCM", metadata: context,
        nonce: b64(nonce), ciphertext: b64(sealed),
      })]);
      if (nativeApply(nativeTypedLength, wire, []) > MAX_WIRE) fail();
      return wire;
    } catch (_) { fail(); }
    finally { wipeOwned(payload); wipeOwned(raw); }
  }
  async function decryptFile({ cek, metadata, envelopeBytes }) {
    if (!subtle) fail();
    keyIsValid(cek);
    const expected = normalizedMetadata(metadata);
    const encoded = asBytes(envelopeBytes);
    const encodedSize = nativeApply(nativeTypedLength, encoded, []);
    if (encodedSize > MAX_WIRE || !encodedSize) fail();
    let decrypted;
    try {
      const value = nativeJsonParse(nativeApply(nativeTextDecode, decode, [encoded]));
      strict(value, ["format", "algorithm", "metadata", "nonce", "ciphertext"]);
      if (![FORMAT, MOVE_FORMAT].includes(value.format)
        || value.algorithm !== "AES-256-GCM") fail();
      const receivedMetadata = normalizedMetadata(value.metadata);
      if (nativeJsonStringify(expected) !== nativeJsonStringify(receivedMetadata)) fail();
      // Reject any ambiguous or alternative serialization before accepting
      // a versioned wire object from an untrusted storage provider.
      if (nativeJsonStringify(value) !== nativeApply(nativeTextDecode, decode, [encoded])) fail();
      decrypted = new NativeUint8Array(await nativeApply(nativeDecrypt, subtle, [{
        name: "AES-GCM", iv: from64(value.nonce, 12, 12),
        additionalData: aadFor(expected, value.format), tagLength: 128,
      }, cek, from64(value.ciphertext, 16, MAX_WIRE)]));
      const payload = nativeJsonParse(nativeApply(nativeTextDecode, decode, [decrypted]));
      strict(payload, ["name", "mediaType", "length", "content",
        ...(value.format === MOVE_FORMAT ? ["parentFolderId"] : [])]);
      if (value.format === MOVE_FORMAT && payload.parentFolderId !== null)
        id(payload.parentFolderId);
      if (!validName(payload.name) || typeof payload.mediaType !== "string"
        || payload.mediaType.length > 128
        || hasControlCharacters(payload.mediaType)
        || !Number.isSafeInteger(payload.length) || payload.length < 0
        || payload.length > MAX_PLAIN) fail();
      const data = from64(payload.content, 0, MAX_PLAIN);
      if (payload.length !== nativeApply(nativeTypedLength, data, [])) fail();
      return { name: payload.name, mediaType: payload.mediaType, data,
        ...(value.format === MOVE_FORMAT
          ? { parentFolderId: payload.parentFolderId } : {}) };
    } catch (_) { fail(); }
    finally { wipeOwned(decrypted); }
  }
  return Object.freeze({ generateFileCek, importFileCek, encryptFile,
    encryptFileWithParent, decryptFile });
}));
