"use strict";

// Bounded, opt-in observation of historical temp/derived payloads not covered
// by the file_search_index. Names and bytes remain on the legacy host.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const MAX_ENTRIES = 512;
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_FILE_BYTES = 16 * 1024 * 1024;

function deny() { throw new Error("ZK_LEGACY_DERIVED_INVENTORY_UNAVAILABLE"); }
function stat(target, directory) {
  const s = fs.lstatSync(target, { bigint: true });
  if (s.isSymbolicLink() || (!directory && s.nlink !== 1n)
    || (directory ? !s.isDirectory() : !s.isFile())) deny();
  return s;
}
function same(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.nlink === b.nlink
    && a.size === b.size && a.ctimeNs === b.ctimeNs && a.mtimeNs === b.mtimeNs;
}
function directory(target) {
  const first = stat(target, true);
  const resolved = fs.realpathSync.native(target);
  const expected = path.resolve(target);
  if ((process.platform === "win32" ? resolved.toLowerCase() : resolved)
    !== (process.platform === "win32" ? expected.toLowerCase() : expected)) deny();
  return first;
}
function inspectZk1LiveLegacyDerivedLocalEvidence({ tempDir, runSecret }) {
  if (typeof tempDir !== "string" || !path.isAbsolute(tempDir)
    || !Buffer.isBuffer(runSecret) || runSecret.byteLength !== 32) deny();
  try {
    const snapshots = [], visited = new Set();
    const mac = crypto.createHmac("sha256", runSecret)
      .update("rootark-zk1-legacy-derived-local/v1\0");
    let count = 0, size = 0, entriesVisited = 0;
    function scan(folder, prefix, depth = 0) {
      if (depth > 16) deny();
      const before = directory(folder);
      const names = fs.readdirSync(folder).sort();
      entriesVisited += names.length;
      if (entriesVisited > MAX_ENTRIES
        || new Set(names.map((name) => name.toLowerCase())).size !== names.length) deny();
      for (const name of names) {
        if (!name || name === "." || name === ".." || name.endsWith(".") || name.endsWith(" ")
          || /[\\/\x00-\x1f<>:"|?*]/.test(name)) deny();
        const full = path.join(folder, name);
        const candidate = fs.lstatSync(full, { bigint: true });
        if (candidate.isSymbolicLink()) deny();
        if (candidate.isDirectory()) {
          scan(full, prefix + name + "/", depth + 1);
          continue;
        }
        if (!candidate.isFile() || candidate.nlink !== 1n
          || candidate.size > BigInt(MAX_FILE_BYTES)) deny();
        const id = candidate.dev + ":" + candidate.ino;
        if (visited.has(id)) deny();
        visited.add(id);
        let fd;
        try {
          fd = fs.openSync(full, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
          if (!same(candidate, fs.fstatSync(fd, { bigint: true }))) deny();
          const bytes = fs.readFileSync(fd);
          if (BigInt(bytes.length) !== candidate.size
            || !same(candidate, fs.fstatSync(fd, { bigint: true }))
            || !same(candidate, stat(full, false))) deny();
          count++;
          size += bytes.length;
          if (count > MAX_ENTRIES || size > MAX_BYTES) deny();
          mac.update(JSON.stringify([prefix + name, bytes.length,
            crypto.createHash("sha256").update(bytes).digest("hex")]) + "\n");
          snapshots.push([full, candidate]);
        } finally { if (fd !== undefined) fs.closeSync(fd); }
      }
      if (!same(before, directory(folder))) deny();
    }
    scan(tempDir, "");
    for (const [name, saved] of snapshots) if (!same(saved, stat(name, false))) deny();
    return Object.freeze({ observation: "bounded-nonfts-temp-files-only",
      potentialDerivedReferences: count, totalObservedBytes: size,
      ephemeralFingerprint: mac.digest("base64url"),
      derivedSemanticsVerified: false, globallyComplete: false });
  } catch (_) { deny(); }
}
module.exports = { inspectZk1LiveLegacyDerivedLocalEvidence };
