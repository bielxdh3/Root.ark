"use strict";

// Versioned, length-prefixed commitment to the complete ordered ciphertext
// chunk sequence. Independent owner/device must authenticate this digest;
// a storage gateway must never self-authorize it.
const crypto = require("node:crypto");
const DOMAIN = Buffer.from("Root.ark/zk-1/ciphertext-chunk-root/v1\0", "ascii");
function invalid() { throw new Error("ZK_CHUNK_ROOT_INVALID"); }
function part(index, bytes) {
  if (!Number.isSafeInteger(index) || index < 0 || index > 4095
    || (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array))
    || bytes.length < 1 || bytes.length > 4 * 1024 * 1024) invalid();
  const header = Buffer.allocUnsafe(8);
  header.writeUInt32BE(index, 0);
  header.writeUInt32BE(bytes.length, 4);
  return [header, crypto.createHash("sha256").update(bytes).digest()];
}
function builder(count) {
  if (!Number.isSafeInteger(count) || count < 1 || count > 4096) invalid();
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(count, 0);
  const hash = crypto.createHash("sha256").update(DOMAIN).update(header);
  let next = 0;
  return Object.freeze({
    append(bytes) {
      if (next >= count) invalid();
      for (const item of part(next++, bytes)) hash.update(item);
    },
    finish() {
      if (next !== count) invalid();
      return hash.digest();
    },
  });
}
function computeZk1CiphertextRoot(chunks) {
  if (!Array.isArray(chunks)) invalid();
  const stream = builder(chunks.length);
  for (const chunk of chunks) stream.append(chunk);
  return stream.finish();
}
module.exports = { computeZk1CiphertextRoot, createZk1CiphertextRootBuilder: builder };
