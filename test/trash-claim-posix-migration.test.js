"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const Module = require("node:module");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

// Keep this POSIX permissions test independent of the optional native SQLite
// dependency: the real lock-directory check runs before DB coordination.
function loadTrashServiceWithoutDatabase() {
  const original = Module._load;
  const service = path.resolve(__dirname, "../services/trashService.js");
  const runtimePaths = require.resolve("../src/runtime-paths");
  class TestDatabase {
    constructor() { this.inTransaction = false; }
    pragma() {}
    exec(command) { this.inTransaction = command === "BEGIN IMMEDIATE"; }
    close() {}
  }
  Module._load = function (...args) {
    const [name, parent] = args;
    if (parent?.filename === service && name === "better-sqlite3") return TestDatabase;
    if (parent?.filename === service && name === "../repositories/trashRepository") {
      return { getTrashItem: () => null, saveTrashItem: (item) => item,
        usesSqliteTrashStore: () => false };
    }
    return original.apply(this, args);
  };
  try {
    delete require.cache[service];
    delete require.cache[runtimePaths];
    return require(service);
  } finally {
    Module._load = original;
    delete require.cache[service];
    delete require.cache[runtimePaths];
  }
}

test("existing owned 0775 data parent and remote lock directory are privately migrated", (t) => {
  if (process.platform === "win32") return t.skip("requires native POSIX permissions");
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-posix-upgrade-"));
  t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
  const originalCwd = process.cwd();
  try {
    const data = path.join(runtime, "data");
    const directory = path.join(data, "trash-remote-locks");
    fs.mkdirSync(data, { mode: 0o775 });
    fs.chmodSync(data, 0o775);
    fs.mkdirSync(directory, { mode: 0o775 });
    fs.chmodSync(directory, 0o775);
    assert.equal(fs.statSync(data).mode & 0o777, 0o775);
    assert.equal(fs.statSync(directory).mode & 0o777, 0o775);
    process.chdir(runtime);
    const svc = loadTrashServiceWithoutDatabase();
    const claim = svc.claimRemoteDeletion({ item: {
      id: "owned-upgrade-fixture", metadata: { remoteDeletion: {
        operationId: "owned-upgrade-fixture", state: "pending",
      } },
    } });
    assert.ok(claim, "old 0775 directory under trusted private parent must be migrated");
    assert.equal(fs.lstatSync(data).mode & 0o777, 0o700);
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o700);
    assert.equal(fs.lstatSync(directory).isSymbolicLink(), false);
  } finally {
    process.chdir(originalCwd);
  }
});

test("remote lock directory migration refuses a group-writable runtime ancestor", (t) => {
  if (process.platform === "win32") return t.skip("requires native POSIX permissions");
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-posix-parent-"));
  t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
  const originalCwd = process.cwd();
  try {
    const data = path.join(runtime, "data");
    const directory = path.join(data, "trash-remote-locks");
    fs.mkdirSync(data, { mode: 0o775 });
    fs.chmodSync(data, 0o775);
    fs.mkdirSync(directory, { mode: 0o775 });
    fs.chmodSync(directory, 0o775);
    fs.chmodSync(runtime, 0o775);
    process.chdir(runtime);
    const svc = loadTrashServiceWithoutDatabase();
    assert.throws(() => svc.claimRemoteDeletion({ item: {
      id: "unsafe-parent-fixture", metadata: { remoteDeletion: {
        operationId: "unsafe-parent-fixture", state: "pending",
      } },
    } }), /unsafe/i);
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o775);
    assert.equal(fs.lstatSync(data).mode & 0o777, 0o775);
  } finally {
    process.chdir(originalCwd);
  }
});

test("existing owner-only write-and-search POSIX claim directories remain usable", (t) => {
  if (process.platform === "win32" || process.getuid?.() === 0) {
    return t.skip("requires an unprivileged POSIX owner");
  }
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-private-wx-"));
  const data = path.join(runtime, "data");
  const directory = path.join(data, "trash-remote-locks");
  const originalCwd = process.cwd();
  fs.mkdirSync(data, { mode: 0o300 });
  fs.mkdirSync(directory, { mode: 0o300 });
  fs.chmodSync(data, 0o300);
  fs.chmodSync(directory, 0o300);
  try {
    assert.equal(fs.lstatSync(data).mode & 0o777, 0o300);
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o300);
    process.chdir(runtime);
    const svc = loadTrashServiceWithoutDatabase();
    const claim = svc.claimRemoteDeletion({ item: {
      id: "private-wx-fixture", metadata: { remoteDeletion: {
        operationId: "private-wx-fixture", state: "pending",
      } },
    } });
    assert.ok(claim, "an existing owner-private wx directory needs no migration or read permission");
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o300);
  } finally {
    process.chdir(originalCwd);
    fs.chmodSync(data, 0o700);
    fs.chmodSync(directory, 0o700);
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("failed exclusive claim-token writes close their pinned descriptor", (t) => {
  if (process.platform === "win32") return t.skip("POSIX fault-injection fixture");
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-claim-write-failure-"));
  const originalCwd = process.cwd();
  const originalOpen = fs.openSync;
  const originalWrite = fs.writeFileSync;
  let tokenFd = null;
  try {
    process.chdir(runtime);
    const svc = loadTrashServiceWithoutDatabase();
    fs.openSync = function (file, flags, ...args) {
      const fd = originalOpen.call(this, file, flags, ...args);
      if (String(file).endsWith(".lock") && flags === "wx") tokenFd = fd;
      return fd;
    };
    fs.writeFileSync = function (file, ...args) {
      if (file === tokenFd) throw new Error("INJECTED_CLAIM_TOKEN_WRITE_FAILURE");
      return originalWrite.call(this, file, ...args);
    };
    assert.throws(() => svc.claimRemoteDeletion({ item: {
      id: "write-failure-fixture", metadata: { remoteDeletion: {
        operationId: "write-failure-fixture", state: "pending",
      } },
    } }), /INJECTED_CLAIM_TOKEN_WRITE_FAILURE/);
    assert.ok(Number.isInteger(tokenFd), "exclusive file descriptor was acquired");
    assert.throws(() => fs.fstatSync(tokenFd), { code: "EBADF" },
      "a failed write must not leak a usable claim-lock descriptor");
  } finally {
    fs.openSync = originalOpen;
    fs.writeFileSync = originalWrite;
    process.chdir(originalCwd);
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});
