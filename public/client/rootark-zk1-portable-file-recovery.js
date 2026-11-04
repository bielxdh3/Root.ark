(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto,
      require("./rootark-zk1-file-content"),
      require("./rootark-zk1-ciphertext-chunk-root"));
  } else {
    root.RootarkZk1PortableFileRecovery = factory(root.crypto,
      root.RootarkZk1FileContent, root.RootarkZk1CiphertextRoot);
  }
}(typeof globalThis === "object" ? globalThis : this, function (webCrypto, files, roots) {
  "use strict";

  // Portable *offline* user-held-key ciphertext recovery for one file.
  // This is NOT a password KDF, online enrollment/revocation check, or
  // production recovery authority. A separate 256-bit random recovery secret
  // and independently owner-pinned ciphertext root MUST stay outside the server.
  const format = "rootark-zk1-portable-file-recovery/v1";
  const domain = "Root.ark/zk-1/portable-file-cek/v1\0";
  const metadataFields = ["account_id", "compartment_id", "keyring_id",
    "object_id", "version_id", "parent_version_id", "epoch", "kind"];
  const bundleFields = ["format", "metadata", "objectRevision", "ciphertextBase64",
    "ciphertextSha256", "ciphertextRoot", "wrap"];
  const wrapFields = ["format", "salt", "nonce", "sealedCek"];
  const wrapFormat = "HKDF-SHA256/AES-256-GCM";
  const maxCiphertext = 4 * 1024 * 1024;
  const re64 = /^[A-Za-z0-9_-]+$/;
  const te = new TextEncoder();
  function deny() { throw new Error("ZK_PORTABLE_FILE_RECOVERY_DENIED"); }
  function exact(value, fields) {
    if (!value || typeof value !== "object" || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
      || Reflect.ownKeys(value).length !== fields.length
      || Reflect.ownKeys(value).some((key) => typeof key !== "string"
        || !fields.includes(key))
      || fields.some((key) => !Object.hasOwn(value, key))) deny();
  }
  function bytes(input, min, max = min) {
    if (!(input instanceof ArrayBuffer) && !ArrayBuffer.isView(input)
      || input.byteLength < min || input.byteLength > max) deny();
    return input instanceof ArrayBuffer ? new Uint8Array(input.slice(0))
      : new Uint8Array(input.buffer.slice(input.byteOffset,
        input.byteOffset + input.byteLength));
  }
  function b64(raw) {
    let binary = "";
    for (const byte of raw) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  function from64(input, min, max = min) {
    if (typeof input !== "string" || (!input && min !== 0)
      || (input && !re64.test(input)) || input.length > Math.ceil(max * 4 / 3) + 4) deny();
    let binary;
    try {
      binary = atob(input.replace(/-/g, "+").replace(/_/g, "/")
        .padEnd(Math.ceil(input.length / 4) * 4, "="));
    } catch (_) { deny(); }
    const raw = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (raw.length < min || raw.length > max || b64(raw) !== input) deny();
    return raw;
  }
  function metadata(input) {
    exact(input, metadataFields);
    const out = Object.fromEntries(metadataFields.map((key) => [key, input[key]]));
    const id = (value, min = 16, max = min) => from64(value, min, max);
    for (const key of ["account_id", "keyring_id", "object_id", "version_id"])
      id(out[key]);
    id(out.compartment_id, 1, 128);
    if (out.parent_version_id !== null) id(out.parent_version_id);
    if (!Number.isSafeInteger(out.epoch) || out.epoch < 1
      || out.kind !== "file") deny();
    return out;
  }
  function same(left, right) {
    if (left.length !== right.length) return false;
    let diff = 0;
    for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
    return diff === 0;
  }
  async function checksum(data) {
    return new Uint8Array(await webCrypto.subtle.digest("SHA-256", data));
  }
  function revision(value) {
    if (!Number.isSafeInteger(value) || value < 1) deny();
    return value;
  }
  function authenticatedContext(meta, digest, root, objectRevision) {
    return te.encode(domain + JSON.stringify({
      format, metadata: meta, objectRevision,
      ciphertextSha256: b64(digest), ciphertextRoot: b64(root),
    }));
  }
  async function wrappingKey(secret, salt, context) {
    const base = await webCrypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveKey"]);
    return webCrypto.subtle.deriveKey({
      name: "HKDF", hash: "SHA-256", salt, info: context,
    }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  function generateRecoverySecret() {
    if (!webCrypto?.getRandomValues || !webCrypto?.subtle) deny();
    return webCrypto.getRandomValues(new Uint8Array(32));
  }
  async function sealForUserHeldSecret({ recoverySecret, metadata: inputMetadata,
    name, mediaType, data, objectRevision = 1 }) {
    let rawCek, secret, plaintext, ciphertext, salt, nonce;
    try {
      if (!webCrypto?.subtle || !files?.importFileCek || !roots?.computeCiphertextRoot) deny();
      const meta = metadata(inputMetadata);
      const archiveRevision = revision(objectRevision);
      secret = bytes(recoverySecret, 32);
      plaintext = bytes(data, 0, 2 * 1024 * 1024);
      rawCek = webCrypto.getRandomValues(new Uint8Array(32));
      const cek = await files.importFileCek(rawCek);
      ciphertext = bytes(await files.encryptFile({
        cek, metadata: meta, name, mediaType, data: plaintext,
      }), 1, maxCiphertext);
      const digest = await checksum(ciphertext);
      const root = bytes(await roots.computeCiphertextRoot([ciphertext]), 32);
      salt = webCrypto.getRandomValues(new Uint8Array(32));
      nonce = webCrypto.getRandomValues(new Uint8Array(12));
      const context = authenticatedContext(meta, digest, root, archiveRevision);
      const key = await wrappingKey(secret, salt, context);
      const sealedCek = new Uint8Array(await webCrypto.subtle.encrypt({
        name: "AES-GCM", iv: nonce, additionalData: context, tagLength: 128,
      }, key, rawCek));
      return Object.freeze({
        format, metadata: meta, objectRevision: archiveRevision,
        ciphertextBase64: b64(ciphertext),
        ciphertextSha256: b64(digest), ciphertextRoot: b64(root),
        wrap: Object.freeze({ format: wrapFormat, salt: b64(salt),
          nonce: b64(nonce), sealedCek: b64(sealedCek) }),
      });
    } catch (_) { deny(); }
    finally {
      rawCek?.fill(0); secret?.fill(0); plaintext?.fill(0); ciphertext?.fill(0);
      salt?.fill(0); nonce?.fill(0);
    }
  }
  async function openWithIndependentRoot({ recoverySecret, bundle, expectedMetadata,
    independentlyPinnedCiphertextRoot }) {
    let secret, ciphertext, rawCek, opened;
    try {
      if (!webCrypto?.subtle || !files?.decryptFile || !roots?.computeCiphertextRoot) deny();
      exact(bundle, bundleFields);
      exact(bundle.wrap, wrapFields);
      if (bundle.format !== format || bundle.wrap.format !== wrapFormat) deny();
      const archiveRevision = revision(bundle.objectRevision);
      const expected = metadata(expectedMetadata);
      const received = metadata(bundle.metadata);
      if (JSON.stringify(received) !== JSON.stringify(expected)) deny();
      secret = bytes(recoverySecret, 32);
      const externalRoot = bytes(independentlyPinnedCiphertextRoot, 32);
      ciphertext = from64(bundle.ciphertextBase64, 1, maxCiphertext);
      const digest = await checksum(ciphertext);
      const root = bytes(await roots.computeCiphertextRoot([ciphertext]), 32);
      if (!same(root, externalRoot)
        || !same(digest, from64(bundle.ciphertextSha256, 32))
        || !same(root, from64(bundle.ciphertextRoot, 32))) deny();
      const salt = from64(bundle.wrap.salt, 32);
      const nonce = from64(bundle.wrap.nonce, 12);
      const sealed = from64(bundle.wrap.sealedCek, 48);
      const context = authenticatedContext(expected, digest, root, archiveRevision);
      const key = await wrappingKey(secret, salt, context);
      rawCek = new Uint8Array(await webCrypto.subtle.decrypt({
        name: "AES-GCM", iv: nonce, additionalData: context, tagLength: 128,
      }, key, sealed));
      if (rawCek.length !== 32) deny();
      const cek = await files.importFileCek(rawCek);
      opened = await files.decryptFile({ cek, metadata: expected, envelopeBytes: ciphertext });
      return Object.freeze({
        name: opened.name, mediaType: opened.mediaType,
        data: opened.data,
        ciphertextRootVerifiedAgainstIndependentPin: true,
        persistentOfflineSecretRequired: true,
        ownerPinProvenanceVerifiedByModule: false,
        currentOnlineRevocationVerified: false, authorizesProductionRestore: false,
      });
    } catch (_) { opened?.data?.fill(0); deny(); }
    finally { rawCek?.fill(0); secret?.fill(0); ciphertext?.fill(0); }
  }
  return Object.freeze({ generateRecoverySecret, sealForUserHeldSecret,
    openWithIndependentRoot });
}));
