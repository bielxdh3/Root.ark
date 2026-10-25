"use strict";

// Startup trust material (Ed25519 witness/CAS signing keys, TLS keys, pins,
// CA certificates and standalone JSON) must come from the *same* regular file
// before and after the bounded read. A path-based stat->readFile sequence can
// load a substituted authority key across a local rename/junction race.
const fs = require("node:fs");
const path = require("node:path");
const { assertPrivateSqliteDirectory } = require("./zk1PrivateSqlitePath");
const { verifyWindowsAuthorityFilePath } =
  require("../../services/chunkUploadWindowsAcl");

const LIMIT = 65536;
function denied() {
  const error = new Error("ZK_AUTHORITY_FILE_UNTRUSTED");
  error.code = error.message;
  throw error;
}
function same(first, last) {
  return first.isFile() && last.isFile() && !first.isSymbolicLink()
    && !last.isSymbolicLink() && first.nlink === 1n && last.nlink === 1n
    && first.dev === last.dev && first.ino === last.ino
    && first.size === last.size && first.mode === last.mode
    && first.ctimeNs === last.ctimeNs && first.mtimeNs === last.mtimeNs;
}
function directoryIdentity(filename) {
  // Existing authority-directory guard traverses every ancestor, refuses
  // symlinks/junctions (also those pointing to the SAME inode) and enforces
  // POSIX owner/write rules, including the root-owned sticky /tmp exception.
  assertPrivateSqliteDirectory(filename);
  const chain = [];
  let current = path.dirname(filename);
  for (;;) {
    const info = fs.lstatSync(current, { bigint: true });
    if (!info.isDirectory() || info.isSymbolicLink()) denied();
    // Ancestor ctime/mtime changes when an unrelated process creates temp
    // files below it (including native ACL checker compilation). That is not
    // an identity change: track inode/dev/mode; the native ACL gate is separate.
    chain.push({ name: current, dev: info.dev, ino: info.ino,
      mode: info.mode });
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return chain;
}
function sameDirectories(first, filename) {
  const last = directoryIdentity(filename);
  if (first.length !== last.length) denied();
  for (let i = 0; i < first.length; i += 1) {
    const a = first[i], b = last[i];
    if (a.name !== b.name || a.dev !== b.dev || a.ino !== b.ino
      || a.mode !== b.mode) denied();
  }
}
function checkAuthorityPermissions(filename, stat) {
  if (process.platform === "win32") {
    // Native GetNamedSecurityInfoW traverses the ancestor DACLs and rejects
    // their reparse points, unsafe owners and DELETE_CHILD rights. The leaf
    // must have no non-operator read/write ACEs. The helper invokes only the
    // fixed system PowerShell, never PATH-selected code.
    verifyWindowsAuthorityFilePath(filename);
  } else if (stat.uid !== BigInt(process.getuid())
    || (stat.mode & 0o077n) !== 0n) denied();
}
function readAuthorityPinnedFile(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) denied();
  let fd;
  let content;
  try {
    const directories = directoryIdentity(value);
    const before = fs.lstatSync(value, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.size < 1n || before.size > BigInt(LIMIT)) denied();
    checkAuthorityPermissions(value, before);
    fd = fs.openSync(value, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0)
      | (fs.constants.O_CLOEXEC || 0));
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!same(before, opened)) denied();
    content = Buffer.alloc(Number(opened.size));
    for (let offset = 0; offset < content.length;) {
      const count = fs.readSync(fd, content, offset, content.length - offset, null);
      if (count <= 0) denied();
      offset += count;
    }
    if (fs.readSync(fd, Buffer.alloc(1), 0, 1, null) !== 0) denied();
    const after = fs.fstatSync(fd, { bigint: true });
    const namedAfter = fs.lstatSync(value, { bigint: true });
    if (!same(opened, after) || !same(opened, namedAfter)) denied();
    sameDirectories(directories, value);
    // The native DACL gate above already proved that no untrusted principal
    // can modify this leaf or replace its parents. Only a privileged operator
    // outside this guard's threat model can change that policy during a read.
    fs.closeSync(fd); fd = undefined;
    return content;
  } catch (_) {
    if (content) content.fill(0);
    denied();
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch (_) { /* operation already denied */ }
    }
  }
}
module.exports = { readAuthorityPinnedFile };
