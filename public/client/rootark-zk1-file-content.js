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
  const encode = new TextEncoder();
  const decode = new TextDecoder("utf-8", { fatal: true });
  const FORMAT = "rootark-zk1-file-v1";
  const DOMAIN = "Root.ark/zk-1/content-aead/v1\0";
  const MAX_PLAIN = 2 * 1024 * 1024;
  const MAX_WIRE = 4 * 1024 * 1024;
  const B64 = /^[A-Za-z0-9_-]+$/;
  const OPAQUE_ID = /^[A-Za-z0-9_-]{22}$/;
  const METADATA_FIELDS = ["account_id", "compartment_id", "keyring_id", "object_id",
    "version_id", "parent_version_id", "epoch", "kind"];
  function fail() { throw new Error("ZK_FILE_INVALID"); }
  function strict(obj, fields) {
    if (!obj || typeof obj !== "object" || Array.isArray(obj)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))
      || Reflect.ownKeys(obj).length !== fields.length
      || fields.some((key) => !Object.hasOwn(obj, key))
      || Reflect.ownKeys(obj).some((key) => !fields.includes(key))) fail();
  }
  function asBytes(value) {
    if (value instanceof Uint8Array) return new Uint8Array(value);
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(
      value.byteOffset, value.byteOffset + value.byteLength));
    fail();
  }
  function b64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(value, min = 1, max = 128) {
    if (typeof value !== "string" || (value.length === 0 && min !== 0)
      || (value.length > 0 && !B64.test(value)) || value.length > max * 2 + 4) fail();
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")
      .padEnd(Math.ceil(value.length / 4) * 4, "=")); } catch (_) { fail(); }
    const result = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (result.length < min || result.length > max || b64(result) !== value) fail();
    return result;
  }
  function id(value, min = 16, max = 16) {
    if (min === 16 && max === 16 && (typeof value !== "string" || !OPAQUE_ID.test(value))) fail();
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
  function aadFor(metadata) {
    return encode.encode(DOMAIN + JSON.stringify(normalizedMetadata(metadata)));
  }
  function validName(name) {
    return typeof name === "string" && name.length >= 1 && name.length <= 255
      && !/[\\/\u0000-\u001f\u007f]/.test(name);
  }
  async function generateFileCek() {
    if (!subtle) fail();
    const raw = webCrypto.getRandomValues(new Uint8Array(32));
    try {
      return await subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]);
    } finally { raw.fill(0); }
  }
  async function importFileCek(rawCek) {
    if (!subtle) fail();
    const source = asBytes(rawCek);
    if (source.length !== 32) fail();
    try {
      return await subtle.importKey("raw", source, { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]);
    } finally { source.fill(0); }
  }
  async function encryptFile({ cek, metadata, name, mediaType, data }) {
    if (!subtle) fail();
    keyIsValid(cek);
    const context = normalizedMetadata(metadata);
    if (!validName(name) || typeof mediaType !== "string" || mediaType.length > 128
      || /[\u0000-\u001f\u007f]/.test(mediaType)) fail();
    const raw = asBytes(data);
    if (raw.length > MAX_PLAIN) fail();
    const payload = encode.encode(JSON.stringify({
      name, mediaType, length: raw.length, content: b64(raw),
    }));
    const nonce = webCrypto.getRandomValues(new Uint8Array(12));
    try {
      const sealed = new Uint8Array(await subtle.encrypt({
        name: "AES-GCM", iv: nonce, additionalData: aadFor(context), tagLength: 128,
      }, cek, payload));
      const wire = encode.encode(JSON.stringify({
        format: FORMAT, algorithm: "AES-256-GCM", metadata: context,
        nonce: b64(nonce), ciphertext: b64(sealed),
      }));
      if (wire.length > MAX_WIRE) fail();
      return wire;
    } catch (_) { fail(); }
    finally { payload.fill(0); raw.fill(0); }
  }
  async function decryptFile({ cek, metadata, envelopeBytes }) {
    if (!subtle) fail();
    keyIsValid(cek);
    const expected = normalizedMetadata(metadata);
    const encoded = asBytes(envelopeBytes);
    if (encoded.length > MAX_WIRE || !encoded.length) fail();
    let decrypted;
    try {
      const value = JSON.parse(decode.decode(encoded));
      strict(value, ["format", "algorithm", "metadata", "nonce", "ciphertext"]);
      if (value.format !== FORMAT || value.algorithm !== "AES-256-GCM") fail();
      const receivedMetadata = normalizedMetadata(value.metadata);
      if (JSON.stringify(expected) !== JSON.stringify(receivedMetadata)) fail();
      // Reject any ambiguous or alternative serialization before accepting
      // a versioned wire object from an untrusted storage provider.
      if (JSON.stringify(value) !== decode.decode(encoded)) fail();
      decrypted = new Uint8Array(await subtle.decrypt({
        name: "AES-GCM", iv: from64(value.nonce, 12, 12),
        additionalData: aadFor(expected), tagLength: 128,
      }, cek, from64(value.ciphertext, 16, MAX_WIRE)));
      const payload = JSON.parse(decode.decode(decrypted));
      strict(payload, ["name", "mediaType", "length", "content"]);
      if (!validName(payload.name) || typeof payload.mediaType !== "string"
        || payload.mediaType.length > 128 || /[\u0000-\u001f\u007f]/.test(payload.mediaType)
        || !Number.isSafeInteger(payload.length) || payload.length < 0
        || payload.length > MAX_PLAIN) fail();
      const data = from64(payload.content, 0, MAX_PLAIN);
      if (payload.length !== data.length) fail();
      return { name: payload.name, mediaType: payload.mediaType, data };
    } catch (_) { fail(); }
    finally { decrypted?.fill(0); }
  }
  return Object.freeze({ generateFileCek, importFileCek, encryptFile, decryptFile });
}));
