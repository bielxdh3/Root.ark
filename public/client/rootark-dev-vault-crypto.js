(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory(require("node:crypto").webcrypto);
  else root.RootarkDevVaultCrypto = factory(root.crypto);
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto) {
  "use strict";

  // Deliberately separate from zk-1's frozen CBOR/HPKE profile: this is a
  // working development-only encrypted transfer, NOT a recovery/keyring v1.
  const subtle = webCrypto && webCrypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const FORMAT = "rootark-dev-file-v1";
  const CONTEXT = "Root.ark/dev-opaque-file/v1\0";
  const MAX_PLAINTEXT_BYTES = 4 * 1024 * 1024;
  const B64 = /^[A-Za-z0-9_-]+$/;
  const ID = /^[A-Za-z0-9_-]{22}$/;

  function fail() { throw new Error("Protected file format or key invalid"); }
  function asBytes(value) {
    if (value instanceof Uint8Array) return new Uint8Array(value);
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer.slice(
      value.byteOffset, value.byteOffset + value.byteLength));
    fail();
  }
  function base64url(value) {
    const bytes = asBytes(value);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function decode64(value, size = null) {
    if (typeof value !== "string" || !B64.test(value) || value.length % 4 === 1 || value.length > 8 * 1024 * 1024) fail();
    let binary;
    try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=")); }
    catch (_) { fail(); }
    const out = Uint8Array.from(binary, (v) => v.charCodeAt(0));
    if (base64url(out) !== value || (size !== null && out.byteLength !== size)) fail();
    return out;
  }
  function exactFields(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)) fail();
    const keys = Object.keys(value);
    if (keys.length !== fields.length || fields.some((k) => !Object.hasOwn(value, k))
      || keys.some((k) => !fields.includes(k))) fail();
  }
  function trustedContext(username, id) {
    if (typeof username !== "string" || username.length < 1 || username.length > 256
      || /[\u0000-\u001f\u007f]/.test(username) || !ID.test(id)) fail();
    decode64(id, 16);
    return encoder.encode(CONTEXT + username + "\0" + id);
  }
  async function keyCommitment(recoveryKey, username) {
    if (!subtle || typeof username !== "string" || username.length < 1
      || username.length > 256 || /[\u0000-\u001f\u007f]/.test(username)) fail();
    const raw = decode64(recoveryKey, 32);
    const scope = encoder.encode("Root.ark/dev-vault-key-commitment/v1\0" + username + "\0");
    const message = new Uint8Array(scope.length + raw.length);
    message.set(scope);
    message.set(raw, scope.length);
    try {
      return base64url(new Uint8Array(await subtle.digest("SHA-256", message)));
    } finally { raw.fill(0); message.fill(0); }
  }
  function canSaveDeviceKey(existing, newKeyId) {
    if (typeof newKeyId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(newKeyId)) return false;
    return existing == null || (typeof existing === "object"
      && Object.hasOwn(existing, "keyId") && existing.keyId === newKeyId);
  }
  async function importRecoveryKey(recoveryKey) {
    if (!subtle) fail();
    const raw = decode64(recoveryKey, 32);
    try {
      return await subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]);
    } finally { raw.fill(0); }
  }
  async function generateRecoveryKey() {
    if (!subtle) fail();
    const raw = webCrypto.getRandomValues(new Uint8Array(32));
    const recoveryKey = base64url(raw);
    try {
      const key = await subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 },
        false, ["encrypt", "decrypt"]);
      return { key, recoveryKey };
    } finally { raw.fill(0); }
  }
  function checkKey(key) {
    if (!key || key.type !== "secret" || key.extractable !== false
      || key.algorithm?.name !== "AES-GCM" || key.algorithm?.length !== 256
      || !key.usages?.includes("encrypt") || !key.usages?.includes("decrypt")) fail();
    return key;
  }
  async function encryptFile({ key, id, username, name, mediaType, data }) {
    checkKey(key);
    const aad = trustedContext(username, id);
    if (typeof name !== "string" || name.length < 1 || name.length > 255
      || /[\\/\u0000-\u001f\u007f]/.test(name)
      || typeof mediaType !== "string" || mediaType.length > 128) fail();
    const raw = asBytes(data);
    if (raw.length > MAX_PLAINTEXT_BYTES) fail();
    const json = encoder.encode(JSON.stringify({
      format: "rootark-dev-file-payload-v1", name, mediaType,
      byteLength: raw.length, content: base64url(raw),
    }));
    const iv = webCrypto.getRandomValues(new Uint8Array(12));
    try {
      const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv,
        additionalData: aad, tagLength: 128 }, key, json);
      return { format: FORMAT, algorithm: "AES-256-GCM",
        iv: base64url(iv), ciphertext: base64url(new Uint8Array(ciphertext)) };
    } finally { raw.fill(0); json.fill(0); }
  }
  async function decryptFile({ key, id, username, envelope }) {
    checkKey(key);
    const aad = trustedContext(username, id);
    exactFields(envelope, ["format", "algorithm", "iv", "ciphertext"]);
    if (envelope.format !== FORMAT || envelope.algorithm !== "AES-256-GCM") fail();
    const iv = decode64(envelope.iv, 12);
    const ciphertext = decode64(envelope.ciphertext);
    if (ciphertext.byteLength < 16 || ciphertext.byteLength > 7 * 1024 * 1024) fail();
    let plaintext;
    try {
      plaintext = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv,
        additionalData: aad, tagLength: 128 }, key, ciphertext));
      const obj = JSON.parse(decoder.decode(plaintext));
      exactFields(obj, ["format", "name", "mediaType", "byteLength", "content"]);
      if (obj.format !== "rootark-dev-file-payload-v1"
        || typeof obj.name !== "string" || !obj.name.length || obj.name.length > 255
        || /[\\/\u0000-\u001f\u007f]/.test(obj.name)
        || typeof obj.mediaType !== "string" || obj.mediaType.length > 128
        || !Number.isSafeInteger(obj.byteLength) || obj.byteLength < 0
        || obj.byteLength > MAX_PLAINTEXT_BYTES) fail();
      const data = decode64(obj.content);
      if (data.byteLength !== obj.byteLength) fail();
      return { name: obj.name, mediaType: obj.mediaType, data };
    } finally { plaintext?.fill(0); }
  }

  // Read-after-write verification for a newly imported/copied file.
  // A successful POST alone is not proof that the remote opaque bytes are
  // readable or equal to the original. The original remains untouched.
  async function verifyStoredCopy({ key, username, id, keyId, expectedEnvelope,
    original, name, mediaType, record }) {
    if (!record || typeof record !== "object" || Array.isArray(record)
      || record.id !== id || record.keyId !== keyId
      || record.revision !== 1
      || typeof keyId !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(keyId)) fail();
    exactFields(expectedEnvelope, ["format", "algorithm", "iv", "ciphertext"]);
    exactFields(record.envelope, ["format", "algorithm", "iv", "ciphertext"]);
    for (const field of ["format", "algorithm", "iv", "ciphertext"]) {
      if (record.envelope[field] !== expectedEnvelope[field]) fail();
    }
    const opened = await decryptFile({
      key, username, id, envelope: record.envelope,
    });
    try {
      const bytes = asBytes(original);
      if (opened.name !== name || opened.mediaType !== mediaType
        || opened.data.length !== bytes.length) fail();
      let mismatch = 0;
      for (let i = 0; i < bytes.length; i += 1) mismatch |= bytes[i] ^ opened.data[i];
      if (mismatch !== 0) fail();
      return true;
    } finally { opened.data.fill(0); }
  }

  return Object.freeze({ generateRecoveryKey, importRecoveryKey, keyCommitment,
    canSaveDeviceKey,
    encryptFile, decryptFile, verifyStoredCopy, MAX_PLAINTEXT_BYTES });
}));
