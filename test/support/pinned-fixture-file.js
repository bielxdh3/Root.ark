"use strict";

// Snapshot assertions must not re-open a mutable pathname after checking it.
// This helper reads from the opened descriptor, and verifies that the name
// still refers to the same regular inode before and after the read.
const fs = require("node:fs");
const fsp = require("node:fs/promises");

const READ_FLAGS = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);

function unchanged(opened, named, { allowHardlinks = false } = {}) {
  return named.isFile() && !named.isSymbolicLink()
    && opened.isFile() && opened.dev === named.dev && opened.ino === named.ino
    && opened.nlink === named.nlink && (allowHardlinks || opened.nlink === 1n);
}

function stable(before, after, options) {
  return unchanged(before, after, options) && before.size === after.size
    && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs;
}

function verify(opened, named, options) {
  if (!unchanged(opened, named, options)) throw Error("FIXTURE_FILE_CHANGED");
}

function readPinnedFixtureFileSync(filename, encoding, options) {
  const fd = fs.openSync(filename, READ_FLAGS);
  try {
    const before = fs.fstatSync(fd, { bigint: true });
    verify(before, fs.lstatSync(filename, { bigint: true }), options);
    const content = fs.readFileSync(fd, encoding);
    const after = fs.fstatSync(fd, { bigint: true });
    if (!stable(before, after, options)) throw Error("FIXTURE_FILE_CHANGED");
    verify(after, fs.lstatSync(filename, { bigint: true }), options);
    return content;
  } finally {
    fs.closeSync(fd);
  }
}

async function readPinnedFixtureFile(filename, encoding, options) {
  const handle = await fsp.open(filename, READ_FLAGS);
  try {
    const before = await handle.stat({ bigint: true });
    verify(before, await fsp.lstat(filename, { bigint: true }), options);
    const content = await handle.readFile(encoding);
    const after = await handle.stat({ bigint: true });
    if (!stable(before, after, options)) throw Error("FIXTURE_FILE_CHANGED");
    verify(after, await fsp.lstat(filename, { bigint: true }), options);
    return content;
  } finally {
    await handle.close();
  }
}

function writeExistingFixtureFileSync(filename, content) {
  const fd = fs.openSync(filename, fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    verify(opened, fs.lstatSync(filename, { bigint: true }));
    if (opened.nlink !== 1n) throw Error("FIXTURE_FILE_CHANGED");
    // Truncate only after verifying the descriptor is the intended private inode.
    fs.ftruncateSync(fd, 0);
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    verify(after, fs.lstatSync(filename, { bigint: true }));
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.nlink !== 1n) {
      throw Error("FIXTURE_FILE_CHANGED");
    }
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = { readPinnedFixtureFileSync, readPinnedFixtureFile,
  writeExistingFixtureFileSync };
