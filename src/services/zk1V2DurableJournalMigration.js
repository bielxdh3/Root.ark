"use strict";

// Private single-directory namespace publication. This is intentionally NOT a
// generic cross-filesystem move or a replacement of existing database paths.
// Filesystem/host administrative rollback remains outside this local barrier.
const fs = require("node:fs");
const path = require("node:path");
const { assertPrivateSqliteDirectory, assertPrivateSqliteFile } =
  require("./zk1PrivateSqlitePath");

function fail() { throw new Error("ZK_V2_DIRECTORY_DURABILITY_UNAVAILABLE"); }

function syncPrivateParent(filename) {
  assertPrivateSqliteDirectory(filename);
  const parent = path.dirname(filename);
  const fd = fs.openSync(parent, fs.constants.O_RDONLY
    | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0));
  try {
    if (!fs.fstatSync(fd).isDirectory()) fail();
    // Node/Windows cannot FlushFileBuffers on a directory descriptor; EPERM
    // is intentionally fatal. Never substitute fsync(file) for fsync(parent).
    fs.fsyncSync(fd);
    assertPrivateSqliteDirectory(filename);
  } finally { fs.closeSync(fd); }
}

function publishStagedJournal(staged, destination, reopen) {
  if (typeof staged !== "string" || typeof destination !== "string"
    || !path.isAbsolute(staged) || !path.isAbsolute(destination)
    || path.dirname(staged) !== path.dirname(destination)
    || staged === destination || typeof reopen !== "function") fail();
  const identity = assertPrivateSqliteFile(staged);
  if (fs.existsSync(destination)
    || ["-wal", "-shm", "-journal"].some((suffix) => fs.existsSync(destination + suffix))) fail();
  // Windows FlushFileBuffers needs a writable file handle even for an fsync.
  const fd = fs.openSync(staged, fs.constants.O_RDWR | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (opened.dev !== identity.dev || opened.ino !== identity.ino) fail();
    fs.fsyncSync(fd);
  } finally { fs.closeSync(fd); }
  // Establish durability of the newly CREATED staging name before publishing.
  syncPrivateParent(staged);
  let linked = false;
  try {
    // Atomic NO_REPLACE for the destination name, never modify the old journal.
    fs.linkSync(staged, destination);
    linked = true;
    const named = fs.lstatSync(destination, { bigint: true });
    const stagedStat = fs.lstatSync(staged, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.dev !== identity.dev
      || named.ino !== identity.ino || stagedStat.dev !== identity.dev
      || stagedStat.ino !== identity.ino || named.nlink !== 2n) fail();
    syncPrivateParent(destination); // durable LINK before removing staging name
    fs.unlinkSync(staged);
    syncPrivateParent(destination); // durable UNLINK before successful admission
    return reopen();
  } catch (error) {
    if (linked) {
      // Roll back only the alias this invocation created. A swapped or altered
      // path belongs to the operator for manual recovery, not blind deletion.
      let named;
      try { named = fs.lstatSync(destination, { bigint: true }); }
      catch (e) { if (e.code !== "ENOENT") throw e; }
      if (named) {
        if (!named.isFile() || named.isSymbolicLink()
          || named.dev !== identity.dev || named.ino !== identity.ino
          || ["-wal", "-shm", "-journal"].some((suffix) =>
            fs.existsSync(destination + suffix))) fail();
        fs.unlinkSync(destination);
        syncPrivateParent(destination);
      }
    }
    throw error;
  }
}

module.exports = { syncPrivateParent, publishStagedJournal };
