(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory(require("node:crypto").webcrypto);
  } else {
    root.RootarkZk1CiphertextRoot = factory(root.crypto);
  }
}(typeof globalThis === "object" ? globalThis : this, function (defaultWebCrypto) {
  "use strict";

  // Browser-compatible ciphertext commitment identical to the independently
  // verified PostgreSQL/Node v1 root. This does NOT sign or approve release:
  // only an authorized, currently active owner device may do that under a
  // separately verified live witness/CAS protocol.
  const DOMAIN = new TextEncoder().encode("Root.ark/zk-1/ciphertext-chunk-root/v1\0");
  const MAX_CHUNKS = 4096;
  const MAX_CHUNK_BYTES = 4 * 1024 * 1024;
  function invalid() { throw new Error("ZK_CHUNK_ROOT_INVALID"); }
  function u32(value) {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) invalid();
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, value, false);
    return out;
  }
  function copyBytes(value) {
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer.slice(
        value.byteOffset, value.byteOffset + value.byteLength));
    }
    if (value instanceof ArrayBuffer) return new Uint8Array(value.slice(0));
    invalid();
  }
  function concat(parts) {
    const length = parts.reduce((n, part) => n + part.length, 0);
    const output = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      output.set(part, offset);
      offset += part.length;
    }
    return output;
  }
  function createCiphertextRootBuilder(expectedChunkCount, webCrypto = defaultWebCrypto) {
    if (!Number.isSafeInteger(expectedChunkCount)
      || expectedChunkCount < 1 || expectedChunkCount > MAX_CHUNKS
      || !webCrypto?.subtle || typeof webCrypto.subtle.digest !== "function") invalid();
    const records = [];
    let nextIndex = 0;
    let pending = false;
    let finished = false;
    let invalidated = false;
    return Object.freeze({
      async append(part) {
        if (finished || pending || invalidated || nextIndex >= expectedChunkCount) invalid();
        const bytes = copyBytes(part);
        if (bytes.length < 1 || bytes.length > MAX_CHUNK_BYTES) invalid();
        pending = true;
        const index = nextIndex++;
        try {
          const digest = new Uint8Array(await webCrypto.subtle.digest("SHA-256", bytes));
          if (digest.length !== 32) invalid();
          records.push(u32(index), u32(bytes.length), digest);
          return Object.freeze({ written: true });
        } catch (_) {
          invalidated = true;
          invalid();
        } finally {
          bytes.fill(0);
          pending = false;
        }
      },
      async finish() {
        if (finished || pending || invalidated || nextIndex !== expectedChunkCount
          || records.length !== expectedChunkCount * 3) invalid();
        finished = true;
        const transcript = concat([DOMAIN, u32(expectedChunkCount), ...records]);
        try {
          const raw = new Uint8Array(await webCrypto.subtle.digest("SHA-256", transcript));
          if (raw.length !== 32) invalid();
          return raw;
        } catch (_) { invalid(); }
        finally { transcript.fill(0); }
      },
    });
  }
  async function computeCiphertextRoot(chunks) {
    if (!Array.isArray(chunks)) invalid();
    const builder = createCiphertextRootBuilder(chunks.length);
    for (const chunk of chunks) await builder.append(chunk);
    return builder.finish();
  }
  return Object.freeze({ createCiphertextRootBuilder, computeCiphertextRoot });
}));
