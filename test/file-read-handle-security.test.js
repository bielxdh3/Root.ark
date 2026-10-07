"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { finished } = require("node:stream/promises");
const test = require("node:test");
const { openReadHandle } = require("../services/fileReadHandle");

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
test("opening rejects a path replaced between metadata check and descriptor open", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-race-"));
  const filePath = path.join(directory, "file.txt");
  const displacedPath = path.join(directory, "displaced.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  const originalOpenSync = fs.openSync;
  let replaced = false;
  fs.openSync = function (target, ...args) {
    if (target === filePath && !replaced) {
      replaced = true;
      fs.renameSync(filePath, displacedPath);
      fs.writeFileSync(filePath, "replacement bytes");
    }
    return originalOpenSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(replaced, true);
  } finally {
    fs.openSync = originalOpenSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("opening rejects an in-place rewrite between the initial check and descriptor open", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-in-place-race-"));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, "before");
  const originalOpenSync = fs.openSync;
  let rewritten = false;
  fs.openSync = function (target, ...args) {
    if (target === filePath && !rewritten) {
      rewritten = true;
      fs.writeFileSync(filePath, "rewritten bytes with a different length");
    }
    return originalOpenSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(rewritten, true);
  } finally {
    fs.openSync = originalOpenSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("opening revalidates its descriptor after the path changes", () => {
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
      if (!replaced && calls.filter((call) => call === "lstat").length === 2) {
        replaced = true;
        fs.renameSync(filePath, `${filePath}.opened`);
        fs.renameSync(replacementPath, filePath);
      }
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(calls[0], "lstat");
    assert.equal(calls[1], "open", "the path is revalidated only after the descriptor is open");
    assert.equal(calls[2], "lstat");
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
