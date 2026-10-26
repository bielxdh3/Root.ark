"use strict";

// Audit the complete immutable ciphertext-version inventory before accepting a
// successor catalog head. A new ACTIVE device may attest old versions after a
// signer is revoked, but cannot rewrite their opaque metadata or AEAD epoch.
// The server deliberately has no metadata decryption key or filename.
const crypto = require("node:crypto");

function reject(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function rowKey(row) { return `${row.object_id}:${row.revision}`; }
function equal(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}

function indexPages(pages, code) {
  const found = new Map();
  for (const page of pages) for (const entry of page) {
    const key = rowKey(entry);
    if (found.has(key)) reject(code);
    found.set(key, entry);
  }
  return found;
}

function auditZk1CatalogReendorsement({ previousPages, proposedPages, physicalVersions = null }) {
  const previous = indexPages(previousPages, "ZK_CATALOG_UNAVAILABLE");
  const proposed = indexPages(proposedPages, "ZK_CATALOG_CONFLICT");
  if (previous.size > proposed.size) reject("ZK_CATALOG_CONFLICT");
  for (const [key, archived] of previous) {
    const present = proposed.get(key);
    // A rename/move is a NEW ciphertext revision with its own AEAD AAD;
    // already archived (object_id, revision) metadata is immutable forever.
    if (!present || archived.epoch !== present.epoch
      || !equal(archived.ciphertext_digest, present.ciphertext_digest)
      || !equal(archived.metadata_ciphertext, present.metadata_ciphertext)) {
      reject("ZK_CATALOG_CONFLICT");
    }
  }
  if (physicalVersions !== null) {
    if (!Array.isArray(physicalVersions) || physicalVersions.length !== proposed.size) {
      reject("ZK_CATALOG_CONFLICT");
    }
    for (const row of physicalVersions) {
      const indexed = proposed.get(`${row.id}:${row.revision}`);
      if (!indexed || !Buffer.isBuffer(row.ciphertext)
        || !equal(crypto.createHash("sha256").update(row.ciphertext).digest(), row.ciphertext_digest)
        || indexed.epoch !== row.epoch
        || !equal(indexed.ciphertext_digest, row.ciphertext_digest)) {
        reject("ZK_CATALOG_CONFLICT");
      }
    }
  }
  return true;
}

module.exports = { auditZk1CatalogReendorsement };
