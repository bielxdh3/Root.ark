"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { once } = require("node:events");
const test = require("node:test");
const { openReadHandle } = require("../services/fileReadHandle");

test("opened file descriptor keeps the authorized bytes after path replacement", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-handle-"));
  const filePath = path.join(directory, "file.txt");
  const displacedPath = path.join(directory, "displaced.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  const handle = openReadHandle(filePath);
  try {
    fs.renameSync(filePath, displacedPath);
    fs.writeFileSync(filePath, "replacement bytes");
    const stream = fs.createReadStream(null, { fd: handle.fd, autoClose: true });
    const chunks = [];
    stream.on("data", (chunk) => chunks.push(chunk));
    await once(stream, "end");
    assert.equal(Buffer.concat(chunks).toString("utf8"), "authorized bytes");
  } finally {
    try { fs.closeSync(handle.fd); } catch {}
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
