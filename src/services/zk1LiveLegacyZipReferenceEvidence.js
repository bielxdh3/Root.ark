"use strict";

// Opt-in, read-only central-directory enumeration of independently checksummed
// legacy archive bytes. Deliberately does not inflate ZIP content or treat
// discovered paths as a complete account, derived, or cloud corpus.
const crypto = require("node:crypto");
const MAX_ENTRIES = 1024;
const MAX_ENTRY_BYTES = 32 * 1024 * 1024;
const MAX_DECLARED_BYTES = 64 * 1024 * 1024;
const MAX_NAMES = 255;
const UTF8 = new TextDecoder("utf-8", { fatal: true });

function deny() {
  const error = new Error("ZK_LIVE_LEGACY_ZIP_REFERENCES_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function checked(condition) { if (!condition) deny(); }
function decodeName(name) {
  checked(name.length > 0 && name.length <= MAX_NAMES);
  let text;
  try { text = UTF8.decode(name); } catch { deny(); }
  checked(text.length > 0 && !text.includes("\\")
    && !/[\u0000-\u001f\u007f:]/.test(text)
    && !text.startsWith("/") && !text.startsWith("//")
    && !text.startsWith("./") && !text.includes("//"));
  const directory = text.endsWith("/");
  const parts = (directory ? text.slice(0, -1) : text).split("/");
  checked(parts.every((part) => part.length > 0 && part !== "." && part !== ".."));
  return { name: text, directory };
}
function centralDirectory(buffer, mac) {
  checked(Buffer.isBuffer(buffer) && buffer.length >= 22
    && buffer.length <= 32 * 1024 * 1024);
  // EOCD is at the end except for its explicitly bounded ZIP comment.
  // Requiring one valid EOCD and all central bytes prevents false zero-entry
  // results when a legacy format or another file is renamed to .zip.
  const start = Math.max(0, buffer.length - 22 - 0xffff);
  let endAt = -1;
  for (let offset = buffer.length - 22; offset >= start; offset--) {
    if (buffer.readUInt32LE(offset) === 0x06054b50
      && offset + 22 + buffer.readUInt16LE(offset + 20) === buffer.length) {
      if (endAt !== -1) deny();
      endAt = offset;
    }
  }
  checked(endAt !== -1 && buffer.readUInt16LE(endAt + 4) === 0
    && buffer.readUInt16LE(endAt + 6) === 0);
  const count = buffer.readUInt16LE(endAt + 10);
  const onDisk = buffer.readUInt16LE(endAt + 8);
  const length = buffer.readUInt32LE(endAt + 12);
  const begin = buffer.readUInt32LE(endAt + 16);
  checked(count === onDisk && count <= MAX_ENTRIES
    && count !== 0xffff && length !== 0xffffffff && begin !== 0xffffffff
    && begin + length === endAt);

  let offset = begin;
  let declared = 0;
  const seen = new Set();
  const report = { entries: 0, directories: 0, manifests: 0,
    sqliteCandidates: 0, derivedCandidates: 0, unknownEntries: 0 };
  for (let n = 0; n < count; n++) {
    checked(offset + 46 <= endAt && buffer.readUInt32LE(offset) === 0x02014b50);
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const packed = buffer.readUInt32LE(offset + 20);
    const unpacked = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const disk = buffer.readUInt16LE(offset + 34);
    const localOffset = buffer.readUInt32LE(offset + 42);
    checked((flags & ~(0x800 | 0x8)) === 0 && (method === 0 || method === 8)
      && packed !== 0xffffffff && unpacked !== 0xffffffff
      && (method !== 0 || packed === unpacked)
      && packed <= MAX_ENTRY_BYTES && unpacked <= MAX_ENTRY_BYTES
      && disk === 0 && localOffset !== 0xffffffff
      && extraLength <= 1024 && commentLength <= 255
      && offset + 46 + nameLength + extraLength + commentLength <= endAt);
    declared += unpacked;
    checked(declared <= MAX_DECLARED_BYTES);
    const nameBytes = buffer.subarray(offset + 46, offset + 46 + nameLength);
    const { name, directory } = decodeName(nameBytes);
    const identity = name.toLowerCase();
    checked(!seen.has(identity));
    seen.add(identity);
    checked(localOffset + 30 <= begin && buffer.readUInt32LE(localOffset) === 0x04034b50);
    const localFlags = buffer.readUInt16LE(localOffset + 6);
    const localMethod = buffer.readUInt16LE(localOffset + 8);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    checked(localFlags === flags && localMethod === method
      && localNameLength === nameLength && localExtraLength <= 1024
      && localOffset + 30 + localNameLength + localExtraLength + packed <= begin
      && buffer.subarray(localOffset + 30, localOffset + 30 + nameLength).equals(nameBytes));
    if (!(flags & 0x8)) {
      checked(buffer.readUInt32LE(localOffset + 18) === packed
        && buffer.readUInt32LE(localOffset + 22) === unpacked
        && buffer.readUInt32LE(localOffset + 14) === buffer.readUInt32LE(offset + 16));
    }
    mac.update(JSON.stringify([name, method, packed, unpacked, localOffset]));
    mac.update("\n");
    report.entries++;
    if (directory) {
      checked(packed === 0 && unpacked === 0);
      report.directories++;
    } else if (name === "backup-manifest.json") report.manifests++;
    else if (name === "data/rootark.sqlite") report.sqliteCandidates++;
    else if (/(?:^|\/)(?:derived|previews?|thumbnails?|search-index)(?:\/|$)/i.test(name)) {
      report.derivedCandidates++;
    } else report.unknownEntries++;
    offset += 46 + nameLength + extraLength + commentLength;
  }
  checked(offset === endAt);
  return report;
}

function inspectZk1LiveLegacyZipReferenceEvidence({ archives, runSecret }) {
  if (!(archives instanceof Map) || !Buffer.isBuffer(runSecret) || runSecret.length !== 32
    || archives.size > 5000) deny();
  try {
    const mac = crypto.createHmac("sha256", runSecret)
      .update("rootark-zk1-legacy-zip-central-directory/v1\0");
    const counts = { archivesInspected: 0, entries: 0, directories: 0,
      manifests: 0, sqliteCandidates: 0, derivedCandidates: 0, unknownEntries: 0 };
    for (const [filename, bytes] of archives) {
      checked(typeof filename === "string" && filename.length < 512);
      mac.update(crypto.createHash("sha256").update(filename).digest());
      const current = centralDirectory(bytes, mac);
      counts.archivesInspected++;
      for (const [key, value] of Object.entries(current)) counts[key] += value;
    }
    return Object.freeze({
      observation: "partial-local-zip-central-directory-only",
      ...counts, ephemeralFingerprint: mac.digest("base64url"),
      contentReadbackVerified: false, derivedCoverage: "unknown",
      providerCoverage: "unknown", archiveCompleteness: "unknown",
      globallyComplete: false,
    });
  } catch (_) { deny(); }
}

module.exports = { inspectZk1LiveLegacyZipReferenceEvidence };
