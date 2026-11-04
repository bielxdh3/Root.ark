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
      const names = fs.readdirSync(folder, { withFileTypes: true })
        .sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
      entriesVisited += names.length;
      if (entriesVisited > MAX_ENTRIES
        || new Set(names.map((entry) => entry.name.toLowerCase())).size !== names.length) deny();
      for (const entry of names) {
        const name = entry.name;
        if (!name || name === "." || name === ".." || name.endsWith(".") || name.endsWith(" ")
          || /[\\/\x00-\x1f<>:"|?*]/.test(name)) deny();
        const full = path.join(folder, name);
        // Dirent is only a routing hint. Directory traversal rechecks the
        // named directory; file admission instead pins a nonblocking FD first.
        if (entry.isDirectory()) {
          scan(full, prefix + name + "/", depth + 1);
          continue;
        }
        if (!entry.isFile()) deny();
        let fd;
        try {
          // No leaf lstat before native open: an attacker may substitute a FIFO
          // or inode between enumeration and access. Pin first, then validate.
          fd = fs.openSync(full, fs.constants.O_RDONLY
            | (fs.constants.O_NONBLOCK || 0) | (fs.constants.O_NOFOLLOW || 0));
          const opened = fs.fstatSync(fd, { bigint: true });
          const candidate = fs.lstatSync(full, { bigint: true });
          if (!opened.isFile() || opened.isSymbolicLink() || opened.nlink !== 1n
            || opened.size > BigInt(MAX_FILE_BYTES)
            || !candidate.isFile() || candidate.isSymbolicLink()
            || !same(opened, candidate)) deny();
          const id = opened.dev + ":" + opened.ino;
          if (visited.has(id)) deny();
          visited.add(id);
          // A writer may grow this inode after fstat. readFileSync(fd) can
          // allocate the new size before our post-read identity check rejects
          // it; only read the already-pinned (<= MAX_FILE_BYTES) byte budget.
          const bytes = Buffer.alloc(Number(opened.size));
          let offset = 0;
          while (offset < bytes.length) {
            const count = fs.readSync(fd, bytes, offset,
              Math.min(64 * 1024, bytes.length - offset), offset);
            if (count <= 0 || count > bytes.length - offset) deny();
            offset += count;
          }
          if (BigInt(bytes.length) !== opened.size
            || !same(opened, fs.fstatSync(fd, { bigint: true }))
            || !same(opened, stat(full, false))) deny();
          count++;
          size += bytes.length;
          if (count > MAX_ENTRIES || size > MAX_BYTES) deny();
          mac.update(JSON.stringify([prefix + name, bytes.length,
            crypto.createHash("sha256").update(bytes).digest("hex")]) + "\n");
          snapshots.push([full, opened]);
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
