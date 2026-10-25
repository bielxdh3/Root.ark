"use strict";

// Startup trust material (Ed25519 witness/CAS signing keys, TLS keys, pins,
// CA certificates and standalone JSON) must come from the *same* regular file
// before and after the bounded read. A path-based stat->readFile sequence can
// load a substituted authority key across a local rename/junction race.
const fs = require("node:fs");
const path = require("node:path");

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
function readAuthorityPinnedFile(value) {
  if (typeof value !== "string" || !path.isAbsolute(value)) denied();
  let fd;
  let content;
  try {
    const before = fs.lstatSync(value, { bigint: true });
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
      || before.size < 1n || before.size > BigInt(LIMIT)) denied();
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
