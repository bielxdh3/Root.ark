"use strict";

// Sync v2's independently provisioned policy includes a bearer credential.
// A config selected from a writable CWD must never choose its network origin.
// This guard is read-only: it cannot create or migrate a config implicitly.
const fs = require("node:fs");
const path = require("node:path");
const { assertPrivateSqliteAuthorityDirectory, assertPrivateSqliteFile } =
  require("../src/services/zk1PrivateSqlitePath");

// A full trusted policy can legitimately enumerate up to 10,000 device keys
// and revocations; keep that supported cardinality while bounding reads.
const MAX_CONFIG_BYTES = 8n * 1024n * 1024n;
const READ_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
  | (fs.constants.O_NONBLOCK || 0);

function unsafe() {
  return Object.assign(new Error("SYNC_V2_UNSAFE_CONFIG: use --config with a regular, "
    + "single-link private file inside a protected owner-only directory"),
  { code: "SYNC_V2_UNSAFE_CONFIG" });
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function admit(filename) {
  assertPrivateSqliteAuthorityDirectory(filename);
  const checked = assertPrivateSqliteFile(filename);
  if (process.platform === "win32") {
    require("../services/chunkUploadWindowsAcl").verifyWindowsAuthorityFilePath(filename);
  }
  return checked;
}

function readPrivateV2Config(filename) {
  const fullPath = path.resolve(filename);
  let descriptor;
  let bytes;
  try {
    const prior = admit(fullPath);
    descriptor = fs.openSync(fullPath, READ_FLAGS);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const named = fs.lstatSync(fullPath, { bigint: true });
    if (!opened.isFile() || !named.isFile() || named.isSymbolicLink()
      || opened.nlink !== 1n || named.nlink !== 1n
      || !sameFile(opened, named) || !sameFile(opened, prior)
      || opened.size < 1n || opened.size > MAX_CONFIG_BYTES) throw unsafe();

    // Bounded descriptor-based read: an actor changing the same inode cannot
    // induce an unbounded allocation after the initial size admission.
    bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const read = fs.readSync(descriptor, bytes, offset,
        Math.min(64 * 1024, bytes.length - offset), offset);
      if (read <= 0) throw unsafe();
      offset += read;
    }
    const after = fs.fstatSync(descriptor, { bigint: true });
    const current = admit(fullPath);
    if (!sameFile(opened, after) || !sameFile(opened, current)
      || after.nlink !== 1n || opened.size !== after.size
      || opened.mtimeNs !== after.mtimeNs || opened.ctimeNs !== after.ctimeNs) {
      throw unsafe();
    }
  } catch (_) {
    throw unsafe();
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  try { return JSON.parse(bytes.toString("utf8")); }
  catch (_) {
    throw Object.assign(new Error("SYNC_V2_INVALID_CONFIG: private config is not valid JSON"),
      { code: "SYNC_V2_INVALID_CONFIG" });
  }
}

module.exports = { readPrivateV2Config };
