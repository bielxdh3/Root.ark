"use strict";

// Test-only provenance receipt for a binary produced in THIS test run.
// This is NOT a Windows CreateProcess image-identity lock or a security
// authorization for executable paths. A same-principal writer can still race
// the check and path-based CreateProcess. See the accompanying tests/docs.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const RECEIPTS = new WeakMap();
const NAMES = new Map([
  ["acl-preflight.exe", "rootark-cfapi-acl-test-"],
  ["inherit-only-fixture.exe", "rootark-cfapi-ace-native-"],
]);
const FAIL = "UNTRUSTED_EXECUTABLE";

function comparable(value) {
  const result = path.normalize(value);
  return process.platform === "win32" ? result.toLowerCase() : result;
}

function unchangedDirectory(scratch, prefix) {
  assert.equal(typeof scratch, "string", FAIL);
  assert.ok(path.isAbsolute(scratch), FAIL);
  assert.match(path.basename(scratch), new RegExp(`^${prefix}[A-Za-z0-9_-]{6,}$`), FAIL);
  assert.equal(comparable(path.dirname(scratch)), comparable(os.tmpdir()), FAIL);
  const actual = fs.realpathSync.native(scratch);
  assert.equal(comparable(actual), comparable(scratch), FAIL);
  const stat = fs.lstatSync(scratch, { bigint: true });
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), FAIL);
  return stat;
}

function inspect(scratch, name) {
  assert.ok(NAMES.has(name), FAIL);
  const root = unchangedDirectory(scratch, NAMES.get(name));
  const executable = path.join(scratch, name);
  assert.equal(comparable(fs.realpathSync.native(executable)), comparable(executable), FAIL);
  const fd = fs.openSync(executable, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(executable, { bigint: true });
    assert.ok(opened.isFile() && named.isFile() && !named.isSymbolicLink()
      && opened.nlink === 1n && named.nlink === 1n
      && opened.dev === named.dev && opened.ino === named.ino, FAIL);
    assert.ok(opened.size >= 1024n && opened.size <= 20n * 1024n * 1024n, FAIL);
    const bytes = fs.readFileSync(fd);
    assert.equal(BigInt(bytes.length), opened.size, FAIL);
    assert.equal(bytes.toString("ascii", 0, 2), "MZ", FAIL);
    const offset = bytes.readUInt32LE(0x3c);
    assert.ok(offset >= 64 && offset + 24 <= bytes.length, FAIL);
    assert.equal(bytes.toString("ascii", offset, offset + 4), "PE\0\0", FAIL);
    assert.equal(bytes.readUInt16LE(offset + 4), 0x8664, FAIL);
    assert.ok((bytes.readUInt16LE(offset + 22) & 0x0002) !== 0, FAIL);
    const after = fs.lstatSync(executable, { bigint: true });
    const afterRoot = fs.lstatSync(scratch, { bigint: true });
    assert.ok(after.isFile() && after.dev === opened.dev && after.ino === opened.ino
      && afterRoot.dev === root.dev && afterRoot.ino === root.ino, FAIL);
    return { executable, scratch, rootDev: root.dev, rootIno: root.ino,
      dev: opened.dev, ino: opened.ino, size: opened.size,
      digest: crypto.createHash("sha256").update(bytes).digest("hex") };
  } finally { fs.closeSync(fd); }
}

function buildCompiledFixture(scratch, name, batch, timeout = 40000) {
  assert.equal(process.platform, "win32", FAIL);
  assert.ok(NAMES.has(name), FAIL);
  unchangedDirectory(scratch, NAMES.get(name));
  // A pre-existing file — even one containing plausible PE headers — is
  // never accepted as the result of the build performed by this helper.
  const executable = path.join(scratch, name);
  // existsSync follows a dangling symlink and would incorrectly report false.
  // A native compiler may then follow that alias while writing its output.
  try {
    fs.lstatSync(executable);
    throw new Error(FAIL);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  assert.equal(comparable(batch), comparable(path.join(scratch, "build.cmd")), FAIL);
  assert.equal(comparable(fs.realpathSync.native(batch)), comparable(batch), FAIL);
  const batchStat = fs.lstatSync(batch, { bigint: true });
  assert.ok(batchStat.isFile() && !batchStat.isSymbolicLink() && batchStat.nlink === 1n, FAIL);
  const recipe = fs.readFileSync(batch, "utf8");
  assert.ok(recipe.includes(`/Fe:"${executable}"`) && recipe.includes("/std:c++17")
    && recipe.includes("/W4") && recipe.includes("/WX"), FAIL);
  const buildResult = spawnSync("C:\\Windows\\System32\\cmd.exe", ["/d", "/c", batch], {
    cwd: scratch, encoding: "utf8", timeout, windowsHide: true,
  });
  assert.ok(buildResult.status === 0 && !buildResult.error, FAIL);
  const snapshot = inspect(scratch, name);
  const receipt = Object.freeze({});
  RECEIPTS.set(receipt, snapshot);
  return { receipt, buildResult };
}

function runCompiledFixture(receipt, args, timeout = 10000) {
  const previous = RECEIPTS.get(receipt);
  assert.ok(previous, FAIL);
  assert.ok(Array.isArray(args) && args.every(v => typeof v === "string"), FAIL);
  const next = inspect(previous.scratch, path.basename(previous.executable));
  assert.ok(next.rootDev === previous.rootDev && next.rootIno === previous.rootIno
    && next.dev === previous.dev && next.ino === previous.ino
    && next.size === previous.size && next.digest === previous.digest, FAIL);
  // Path-based spawn remains racy against a writer with the caller's SID.
  // This API only refuses arbitrary caller-selected names and preexisting
  // unrelated/stale binaries. It is not an executable-custody guarantee.
  return spawnSync(previous.executable, args, {
    cwd: previous.scratch, encoding: "utf8", timeout, windowsHide: true,
  });
}

module.exports = { buildCompiledFixture, runCompiledFixture };
