"use strict";

const fs = require("node:fs");

// Test-only injection of same-inode growth *after* the selected descriptor's
// identity/size check. Preserve all hooks even if a security guard throws.
async function withInodeGrowthAfterFstat({ target, openOrdinal = 1, extraBytes, run }) {
  const realOpen = fs.openSync;
  const realFstat = fs.fstatSync;
  const realReadFile = fs.readFileSync;
  let opens = 0;
  let selectedFd;
  let attacked = false;
  const numericFdReadLengths = [];
  fs.openSync = function (name, ...args) {
    const fd = realOpen.call(fs, name, ...args);
    if (name === target && ++opens === openOrdinal) selectedFd = fd;
    return fd;
  };
  fs.fstatSync = function (fd, ...args) {
    const before = realFstat.call(fs, fd, ...args);
    if (fd === selectedFd && !attacked) {
      attacked = true;
      fs.truncateSync(target, Number(before.size) + extraBytes);
    }
    return before;
  };
  fs.readFileSync = function (source, ...args) {
    const bytes = realReadFile.call(fs, source, ...args);
    if (attacked && typeof source === "number" && source === selectedFd)
      numericFdReadLengths.push(bytes.length);
    return bytes;
  };
  try { await run(); }
  finally {
    fs.openSync = realOpen;
    fs.fstatSync = realFstat;
    fs.readFileSync = realReadFile;
  }
  return { attacked, numericFdReadLengths };
}

module.exports = { withInodeGrowthAfterFstat };
