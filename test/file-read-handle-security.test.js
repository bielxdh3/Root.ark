"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { finished } = require("node:stream/promises");
const test = require("node:test");
const { openReadHandle, readBoundedRegularFile } = require("../services/fileReadHandle");

test("opened file descriptor keeps the authorized bytes after path replacement", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-handle-"));
  const filePath = path.join(directory, "file.txt");
  const displacedPath = path.join(directory, "displaced.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  const handle = openReadHandle(filePath);
  let stream;
  try {
    fs.renameSync(filePath, displacedPath);
    fs.writeFileSync(filePath, "replacement bytes");
    stream = fs.createReadStream(null, { fd: handle.fd, autoClose: true });
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(chunk));
    await finished(stream);
    assert.equal(Buffer.concat(chunks).toString("utf8"), "authorized bytes");
  } finally {
    if (!stream) {
      try { fs.closeSync(handle.fd); } catch {}
    }
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
test("opening pins the descriptor before checking path identity", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-order-"));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  const originalOpenSync = fs.openSync;
  const originalLstatSync = fs.lstatSync;
  const calls = [];
  fs.openSync = function (target, ...args) {
    if (target === filePath) calls.push("open");
    return originalOpenSync.call(this, target, ...args);
  };
  fs.lstatSync = function (target, ...args) {
    if (target === filePath) calls.push("lstat");
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    const handle = openReadHandle(filePath);
    fs.closeSync(handle.fd);
    assert.deepEqual(calls.slice(0, 2), ["open", "lstat"]);
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("opening rejects an in-place rewrite after the descriptor is pinned", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-in-place-race-"));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, "before");
  const originalLstatSync = fs.lstatSync;
  let rewritten = false;
  fs.lstatSync = function (target, ...args) {
    if (target === filePath && !rewritten) {
      rewritten = true;
      fs.writeFileSync(filePath, "rewritten bytes with a different length");
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(rewritten, true);
  } finally {
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("opening rejects a path replaced after its descriptor is pinned", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-descriptor-first-"));
  const filePath = path.join(directory, "file.txt");
  const replacementPath = path.join(directory, "replacement.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  fs.writeFileSync(replacementPath, "replacement bytes");
  const originalOpenSync = fs.openSync;
  const originalLstatSync = fs.lstatSync;
  const calls = [];
  let replaced = false;
  fs.openSync = function (target, ...args) {
    if (target === filePath) calls.push("open");
    return originalOpenSync.call(this, target, ...args);
  };
  fs.lstatSync = function (target, ...args) {
    if (target === filePath) {
      calls.push("lstat");
      if (!replaced && calls.filter((call) => call === "lstat").length === 1) {
        replaced = true;
        fs.renameSync(filePath, `${filePath}.opened`);
        fs.renameSync(replacementPath, filePath);
      }
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(calls[0], "open");
    assert.equal(calls[1], "lstat");
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("bounded reader accepts regular files within the limit and rejects oversized files", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-size-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  fs.writeFileSync(filePath, "safe");

  assert.equal(readBoundedRegularFile(filePath, 4).contents.toString("utf8"), "safe");
  assert.throws(() => readBoundedRegularFile(filePath, 3), { code: "INVALID_INTERNAL_FILE" });
});

test("bounded reader rejects directories", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-types-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  assert.throws(() => readBoundedRegularFile(directory, 64), { code: "INVALID_INTERNAL_FILE" });
});

test("bounded reader rejects symlinks where supported", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-symlink-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const targetPath = path.join(directory, "target.json");
  const symlinkPath = path.join(directory, "link.json");
  fs.writeFileSync(targetPath, "safe");
  try {
    fs.symlinkSync(targetPath, symlinkPath);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
      t.skip(`symlinks unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  assert.throws(() => readBoundedRegularFile(symlinkPath, 64), { code: "INVALID_INTERNAL_FILE" });
});

test("bounded reader rejects a symlink substituted immediately before open without reading it", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-open-symlink-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  const outsidePath = path.join(directory, "outside.json");
  fs.writeFileSync(filePath, "safe");
  fs.writeFileSync(outsidePath, "outside");
  try {
    const probePath = path.join(directory, "probe");
    fs.symlinkSync(outsidePath, probePath);
    fs.unlinkSync(probePath);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
      t.skip(`symlinks unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  const originalOpenSync = fs.openSync;
  const originalReadSync = fs.readSync;
  let readCount = 0;
  let swapped = false;
  fs.openSync = function (target, ...args) {
    if (!swapped && path.resolve(String(target)) === path.resolve(filePath)) {
      swapped = true;
      fs.unlinkSync(filePath);
      fs.symlinkSync(outsidePath, filePath);
    }
    return originalOpenSync.call(this, target, ...args);
  };
  fs.readSync = function (...args) {
    readCount += 1;
    return originalReadSync.apply(this, args);
  };
  try {
    assert.throws(() => readBoundedRegularFile(filePath, 64), { code: "INVALID_INTERNAL_FILE" });
    assert.equal(swapped, true);
    assert.equal(readCount, 0);
  } finally {
    fs.openSync = originalOpenSync;
    fs.readSync = originalReadSync;
  }
});

test("bounded reader rejects path substitution during read", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-read-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  const displacedPath = path.join(directory, "displaced.json");
  const replacementPath = path.join(directory, "replacement.json");
  fs.writeFileSync(filePath, "safe");
  fs.writeFileSync(replacementPath, "other");
  const originalReadSync = fs.readSync;
  let swapped = false;
  fs.readSync = function (...args) {
    const count = originalReadSync.apply(this, args);
    if (!swapped && count > 0) {
      swapped = true;
      fs.renameSync(filePath, displacedPath);
      fs.renameSync(replacementPath, filePath);
    }
    return count;
  };
  try {
    assert.throws(() => readBoundedRegularFile(filePath, 64), { code: "INVALID_INTERNAL_FILE" });
    assert.equal(swapped, true);
  } finally {
    fs.readSync = originalReadSync;
  }
});

test("bounded reader returns the stat from the validated read snapshot", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-stat-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  const contents = "original";
  fs.writeFileSync(filePath, contents);
  const originalStat = fs.statSync(filePath);
  const changedTime = new Date("2040-01-01T00:00:00.000Z");
  const originalLstatSync = fs.lstatSync;
  let pathSnapshots = 0;
  let mutated = false;
  fs.lstatSync = function (target, ...args) {
    const stat = originalLstatSync.call(this, target, ...args);
    if (target === filePath && ++pathSnapshots === 2) {
      fs.writeFileSync(filePath, "mutated!");
      fs.utimesSync(filePath, changedTime, changedTime);
      mutated = true;
    }
    return stat;
  };
  try {
    const result = readBoundedRegularFile(filePath, 64);
    assert.equal(mutated, true);
    assert.equal(result.contents.toString("utf8"), contents);
    const changedStat = fs.statSync(filePath);
    assert.equal(result.stat.size, originalStat.size);
    assert.equal(result.stat.mtimeMs, originalStat.mtimeMs);
    assert.notEqual(result.stat.mtimeMs, changedStat.mtimeMs);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});
