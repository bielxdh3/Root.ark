"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { inspectZk1LiveLegacyDerivedLocalEvidence } = require("../src/services/zk1LiveLegacyDerivedLocalEvidence");
const { canonicalTestTemp } = require("./support/issue-65-canonical-temp-fixture");

const runSecret = Buffer.alloc(32, 0x42);

test("derived local observation includes only the stable bounded source bytes", (t) => {
  const directory = fs.mkdtempSync(path.join(canonicalTestTemp(), "zk65-derived-stable-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  fs.writeFileSync(path.join(directory, "artifact.bin"), Buffer.from("ok"));
  const result = inspectZk1LiveLegacyDerivedLocalEvidence({ tempDir: directory, runSecret });
  assert.equal(result.potentialDerivedReferences, 1);
  assert.equal(result.totalObservedBytes, 2);
  assert.equal(result.derivedSemanticsVerified, false);
});

test("derived local observation never allocates an inode grown after descriptor fstat", (t) => {
  const directory = fs.mkdtempSync(path.join(canonicalTestTemp(), "zk65-derived-growth-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  const target = path.join(directory, "artifact.bin");
  fs.writeFileSync(target, Buffer.from("x"));

  const realOpen = fs.openSync;
  const realFstat = fs.fstatSync;
  const realReadFile = fs.readFileSync;
  let selectedFd;
  let attacked = false;
  const numericFdReadLengths = [];
  fs.openSync = function (name, ...args) {
    const fd = realOpen.call(fs, name, ...args);
    if (name === target && selectedFd === undefined) selectedFd = fd;
    return fd;
  };
  fs.fstatSync = function (fd, ...args) {
    const before = realFstat.call(fs, fd, ...args);
    if (fd === selectedFd && !attacked) {
      attacked = true;
      fs.appendFileSync(target, Buffer.alloc(20 * 1024 * 1024, 0x58));
    }
    return before;
  };
  fs.readFileSync = function (source, ...args) {
    const bytes = realReadFile.call(fs, source, ...args);
    if (typeof source === "number") numericFdReadLengths.push(bytes.length);
    return bytes;
  };
  try {
    assert.throws(() => inspectZk1LiveLegacyDerivedLocalEvidence({ tempDir: directory, runSecret }),
      /ZK_LEGACY_DERIVED_INVENTORY_UNAVAILABLE/);
  } finally {
    fs.openSync = realOpen;
    fs.fstatSync = realFstat;
    fs.readFileSync = realReadFile;
  }
  assert.equal(attacked, true, "exercise a real growth race after descriptor validation");
  assert.deepEqual(numericFdReadLengths, [],
    "inode growth must not trigger readFileSync(fd) allocation before fail-closed rejection");
});
