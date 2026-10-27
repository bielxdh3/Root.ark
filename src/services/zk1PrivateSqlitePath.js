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
      // Even a 0755 ancestor is unsafe if a different unprivileged UID owns
      // it: that owner can chmod it or rename its children between our
      // pathname checks and SQLite's later open of the DB/WAL/SHM files.
      // Only the service UID and root may own ancestors. Writable ancestors
      // must be root-owned sticky directories (e.g. /tmp).
      if ((current === containing && (stat.uid !== owner || writable))
        || (current !== containing && (
          (stat.uid !== owner && stat.uid !== 0n)
          || (writable && !(sticky && stat.uid === 0n))))) {
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
  // A recursive mkdir can follow an attacker-planted junction in a missing
  // ancestor AFTER the preflight, creating a foreign child before we refuse.
  // Pin the nearest existing ancestor, then create each absent name exactly
  // once. EEXIST is a hostile race, never permission to follow that name.
  const missing = [];
  let existing = path.dirname(filename);
  while (true) {
    try {
      const stat = fs.lstatSync(existing);
      if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error("UNTRUSTED_SQLITE_PATH");
      break;
    } catch (error) {
      if (error?.code !== "ENOENT") throw Error("UNTRUSTED_SQLITE_PATH");
      const parent = path.dirname(existing);
      if (parent === existing) throw Error("UNTRUSTED_SQLITE_PATH");
      missing.push(path.basename(existing));
      existing = parent;
    }
  }
  checkDirectory(path.join(existing, "_sqlite_db"));
  for (const name of missing.reverse()) {
    existing = path.join(existing, name);
    try { fs.mkdirSync(existing, { recursive: false, mode: 0o700 }); }
    catch (_) { throw Error("UNTRUSTED_SQLITE_PATH"); }
    // Do not descend into an untrusted replacement of the directory just
    // created, even if the original mkdir returned successfully.
    checkDirectory(path.join(existing, "_sqlite_db"));
  }
  checkDirectory(filename);
}

function assertPrivateSqliteFile(filename) {
  checkDirectory(filename);
  // Open first and compare the actual descriptor with the named entry.
  // A prior pathname lstat is not a stable authorization for this open.
  const fd = fs.openSync(filename,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
      | (fs.constants.O_CLOEXEC || 0));
  try {
    const pinned = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(filename, { bigint: true });
    checkDirectory(filename);
    for (const stat of [pinned, named]) {
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
        || stat.dev !== pinned.dev || stat.ino !== pinned.ino
        || (process.platform !== "win32"
          && (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o077n) !== 0n))) {
        throw Error("UNTRUSTED_SQLITE_PATH");
      }
    }
    return Object.freeze({ dev: pinned.dev, ino: pinned.ino });
  } finally { fs.closeSync(fd); }
}

module.exports = { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteDirectory, assertPrivateSqliteAuthorityDirectory };
