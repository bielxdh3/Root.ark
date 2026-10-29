"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const { inspectZk1LiveLegacyDerivedLocalEvidence } = require("../src/services/zk1LiveLegacyDerivedLocalEvidence");
const { canonicalTestTemp } = require("./support/issue-65-canonical-temp-fixture");

const runSecret = Buffer.alloc(32, 0x42);

test("derived local inventory must not block when a scanned file becomes an actual FIFO at open", (t) => {
  if (process.platform !== "linux") return t.skip("native Linux FIFO required");
  const directory = fs.mkdtempSync(path.join(canonicalTestTemp(), "zk65-derived-fifo-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, "artifact.bin");
  fs.writeFileSync(target, "signed-only-observation");
  const fifo = path.join(os.tmpdir(), "zk65-derived-fifo-" + crypto.randomBytes(12).toString("hex"));
  t.after(() => { try { fs.unlinkSync(fifo); } catch {} });
  const created = spawnSync("mkfifo", [fifo], { encoding: "utf8", timeout: 2000 });
  assert.equal(created.status, 0, created.stderr);
  const script = [
    'const fs = require("node:fs");',
    'const [root, target, fifo, modulePath] = process.argv.slice(1);',
    'const original = fs.openSync; let raced = false;',
    'fs.openSync = function(p, ...args) {',
    '  if (p === target && !raced) {',
    '    fs.renameSync(target, target + ".old"); fs.renameSync(fifo, target); raced = true;',
    '  }',
    '  return original.call(fs, p, ...args);',
    '};',
    'const {inspectZk1LiveLegacyDerivedLocalEvidence} = require(modulePath);',
    'try { inspectZk1LiveLegacyDerivedLocalEvidence({tempDir:root,runSecret:Buffer.alloc(32,0x42)});',
    '  process.stderr.write("UNEXPECTED_SUCCESS"); process.exitCode = 2;',
    '} catch (err) {',
    '  if (!raced || err.message !== "ZK_LEGACY_DERIVED_INVENTORY_UNAVAILABLE") {',
    '    process.stderr.write("WRONG_ERROR "+err.message); process.exitCode = 3;',
    '  } else process.stdout.write("FIFO_DENIED_WITHOUT_STALL");',
    '}',
  ].join("\n");
  const outcome = spawnSync(process.execPath, ["-e", script, directory, target, fifo,
    require.resolve("../src/services/zk1LiveLegacyDerivedLocalEvidence")],
  { encoding: "utf8", timeout: 2500 });
  assert.equal(outcome.status, 0,
    "FIFO swap must refuse without hanging: " + outcome.error + " " + outcome.stderr);
  assert.match(outcome.stdout, /FIFO_DENIED_WITHOUT_STALL/);
});

test("derived local reader opens the leaf before trusting its mutable name", (t) => {
  const directory = fs.mkdtempSync(path.join(canonicalTestTemp(), "zk65-derived-fd-first-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 5 }));
  const target = path.join(directory, "artifact.bin");
  fs.writeFileSync(target, "stable");
  const nativeOpen = fs.openSync;
  const nativeLstat = fs.lstatSync;
  let pinned = false, premature = 0;
  fs.openSync = function (name, ...args) {
    if (name === target) pinned = true;
    return nativeOpen.call(fs, name, ...args);
  };
  fs.lstatSync = function (name, ...args) {
    if (name === target && !pinned) premature++;
    return nativeLstat.call(fs, name, ...args);
  };
  let result;
  try { result = inspectZk1LiveLegacyDerivedLocalEvidence({ tempDir: directory, runSecret }); }
  finally { fs.openSync = nativeOpen; fs.lstatSync = nativeLstat; }
  assert.equal(result.potentialDerivedReferences, 1);
  assert.equal(pinned, true);
  assert.equal(premature, 0, "a mutable leaf lstat must not precede its nonblocking FD");
});

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
