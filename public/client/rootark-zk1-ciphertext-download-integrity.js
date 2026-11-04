(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(
      require("./rootark-zk1-ciphertext-chunk-root"),
      require("./rootark-zk1-file-content"));
  } else {
    root.RootarkZk1CiphertextDownloadIntegrity = factory(
      root.RootarkZk1CiphertextRoot, root.RootarkZk1FileContent);
  }
}(typeof globalThis === "object" ? globalThis : this, function (chunkRoot, fileContent) {
  "use strict";

  // A byte-integrity check against the root supplied by the caller is NOT
  // evidence that that root came from an active device, owner or live witness.
  // This deliberately never authorizes GET, publish, release or recovery.
  const MAX_CHUNKS = 4096;
  const MAX_BUFFER_BYTES = 4 * 1024 * 1024;
  const checkedCiphertext = new WeakMap();
  function invalid() { throw new Error("ZK_DOWNLOAD_INTEGRITY_INVALID"); }
  function exact(object, fields) {
    if (!object || typeof object !== "object" || Array.isArray(object)) invalid();
    const keys = Reflect.ownKeys(object);
    if (keys.length !== fields.length || keys.some((key) =>
      typeof key !== "string" || !fields.includes(key))
      || fields.some((field) => !Object.hasOwn(object, field))) invalid();
  }
  function byteCopy(value) {
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer.slice(
        value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    invalid();
  }
  function equal32(a, b) {
    if (a.length !== 32 || b.length !== 32) invalid();
    let difference = 0;
    for (let i = 0; i < 32; ++i) difference |= a[i] ^ b[i];
    return difference === 0;
  }
  async function inspectCiphertextDownload(input) {
    exact(input, ["frames", "expectedChunkCount", "expectedRoot", "maxCiphertextBytes"]);
    const count = input.expectedChunkCount;
    const limit = input.maxCiphertextBytes;
    if (!Number.isSafeInteger(count) || count < 1 || count > MAX_CHUNKS
      || !Number.isSafeInteger(limit) || limit < 1 || limit > MAX_BUFFER_BYTES
      || !Array.isArray(input.frames) || input.frames.length !== count
      || !chunkRoot || typeof chunkRoot.createCiphertextRootBuilder !== "function") invalid();
    // Copy ALL caller-owned bytes synchronously before the first digest await.
    // The service must never be able to change a chunk/root between checking
    // and decrypting. Enforce a bounded aggregate size before allocation.
    const root = byteCopy(input.expectedRoot);
    if (root.length !== 32) invalid();
    const pieces = [];
    let size = 0;
    for (let index = 0; index < count; ++index) {
      const frame = input.frames[index];
      exact(frame, ["index", "bytes"]);
      if (frame.index !== index) invalid();
      const bytes = byteCopy(frame.bytes);
      if (bytes.length < 1 || bytes.length > MAX_BUFFER_BYTES
        || bytes.length > limit - size) invalid();
      pieces.push(bytes);
      size += bytes.length;
    }
    let commitment;
    try {
      const builder = chunkRoot.createCiphertextRootBuilder(count);
      for (const part of pieces) await builder.append(part);
      commitment = await builder.finish();
    } catch (_) { invalid(); }
    if (!equal32(root, byteCopy(commitment))) invalid();
    const authenticatedBytes = new Uint8Array(size);
    let offset = 0;
    for (const part of pieces) {
      authenticatedBytes.set(part, offset);
      offset += part.length;
      part.fill(0);
    }
    const result = Object.freeze({
      integrityMatchesProvidedRoot: true,
      trustedRootProvenanceVerified: false,
      liveDeviceVerified: false,
      authorizesRelease: false,
      authorizesRecovery: false,
      ciphertext: new Uint8Array(authenticatedBytes),
      bytes: size,
      chunks: count,
    });
    // The returned ciphertext view may be altered by the caller, but the
    // only decrypt entrypoint uses this *private* previously-checked copy.
    checkedCiphertext.set(result, authenticatedBytes);
    return result;
  }
  async function decryptVerifiedCiphertext({ inspection, cek, metadata } = {}) {
    if (!inspection || !checkedCiphertext.has(inspection)
      || inspection.authorizesRelease !== false
      || inspection.integrityMatchesProvidedRoot !== true
      || !fileContent || typeof fileContent.decryptFile !== "function") invalid();
    // This executes exclusively with a CEK already held in the user's client.
    // No other actor can obtain plaintext from the integrity inspection.
    const sealedBytes = new Uint8Array(checkedCiphertext.get(inspection));
    let decoded;
    try {
      decoded = await fileContent.decryptFile({ cek, metadata,
        envelopeBytes: sealedBytes });
    } finally { sealedBytes.fill(0); }
    return { ...decoded, authorizesRelease: false };
  }
  return Object.freeze({ inspectCiphertextDownload, decryptVerifiedCiphertext });
}));
