"use strict";

// SQLite opens databases and their WAL/SHM sidecars by pathname. File-only
// lstat/fstat comparisons cannot detect an ancestor junction into another
// storage authority. Require a private, real directory ancestry before SQLite
// opens or creates anything. Privileged host actors remain outside this guard.
const fs = require("node:fs");
const path = require("node:path");

function checkDirectory(filename) {
  let current = path.dirname(filename);
  const containing = current;
  while (true) {
    const stat = fs.lstatSync(current, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error("UNTRUSTED_SQLITE_PATH");
    const canonical = fs.realpathSync.native(current);
    const same = process.platform === "win32"
      ? path.resolve(canonical).toLowerCase() === path.resolve(current).toLowerCase()
      : path.resolve(canonical) === path.resolve(current);
    if (!same) throw Error("UNTRUSTED_SQLITE_PATH");
    if (process.platform !== "win32") {
      const owner = BigInt(process.getuid());
      const writable = (stat.mode & 0o022n) !== 0n;
      const sticky = (stat.mode & 0o1000n) !== 0n;
      if ((current === containing && (stat.uid !== owner || writable))
        || (current !== containing && writable
          && !(sticky && (stat.uid === 0n || stat.uid === owner)))) {
        throw Error("UNTRUSTED_SQLITE_PATH");
      }
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

function assertPrivateSqliteDirectory(filename) {
  checkDirectory(filename);
}

function assertPrivateSqliteAuthorityDirectory(filename) {
  checkDirectory(filename);
  if (process.platform === "win32") {
    // SQLite opens its main DB and WAL/SHM files by name. A less-privileged
    // local principal with Modify/DELETE_CHILD on this directory can replace
    // a perfectly valid earlier signed floor after restart. NTFS mode bits
    // cannot describe that right. Require a protected owner-only DACL and
    // safe ancestry before opening or creating any authority database.
    const { verifyWindowsChunkUploadTree } =
      require("../../services/chunkUploadWindowsAcl");
    verifyWindowsChunkUploadTree(path.dirname(filename));
  }
}

function ensurePrivateSqliteDirectory(filename) {
  // Verify the existing ancestors BEFORE mkdir. mkdir(recursive) otherwise
  // follows a preinstalled symlink and creates files in a foreign directory.
  let existing = path.dirname(filename);
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) throw Error("UNTRUSTED_SQLITE_PATH");
    existing = parent;
  }
  checkDirectory(path.join(existing, "_sqlite_db"));
  fs.mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
  checkDirectory(filename);
}

function assertPrivateSqliteFile(filename) {
  checkDirectory(filename);
  const before = fs.lstatSync(filename, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw Error("UNTRUSTED_SQLITE_PATH");
  }
  if (process.platform !== "win32"
    && (before.uid !== BigInt(process.getuid()) || (before.mode & 0o077n) !== 0n)) {
    throw Error("UNTRUSTED_SQLITE_PATH");
  }
  const fd = fs.openSync(filename,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
      | (fs.constants.O_CLOEXEC || 0));
  try {
    const pinned = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(filename, { bigint: true });
    checkDirectory(filename);
    for (const stat of [pinned, named]) {
      if (!stat.isFile() || stat.nlink !== 1n || stat.dev !== before.dev
        || stat.ino !== before.ino
        || (process.platform !== "win32"
          && (stat.uid !== before.uid || (stat.mode & 0o077n) !== 0n))) {
        throw Error("UNTRUSTED_SQLITE_PATH");
      }
    }
    return Object.freeze({ dev: pinned.dev, ino: pinned.ino });
  } finally { fs.closeSync(fd); }
}

module.exports = { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteDirectory, assertPrivateSqliteAuthorityDirectory };
