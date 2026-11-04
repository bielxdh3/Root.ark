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
      return { getTrashItem: () => null, saveTrashItem: (item) => item };
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

test("existing owned 0775 remote lock directory is privately migrated before claiming", (t) => {
  if (process.platform === "win32") return t.skip("requires native POSIX permissions");
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-posix-upgrade-"));
  t.after(() => fs.rmSync(runtime, { recursive: true, force: true }));
  const originalCwd = process.cwd();
  try {
    const data = path.join(runtime, "data");
    const directory = path.join(data, "trash-remote-locks");
    fs.mkdirSync(data, { mode: 0o700 });
    fs.mkdirSync(directory, { mode: 0o775 });
    fs.chmodSync(directory, 0o775);
    assert.equal(fs.statSync(directory).mode & 0o777, 0o775);
    process.chdir(runtime);
    const svc = loadTrashServiceWithoutDatabase();
    const claim = svc.claimRemoteDeletion({ item: {
      id: "owned-upgrade-fixture", metadata: { remoteDeletion: {
        operationId: "owned-upgrade-fixture", state: "pending",
      } },
    } });
    assert.ok(claim, "old 0775 directory under trusted private parent must be migrated");
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o700);
    assert.equal(fs.lstatSync(directory).isSymbolicLink(), false);
  } finally {
    process.chdir(originalCwd);
  }
});

test("remote lock directory migration refuses a group-writable parent", (t) => {
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
    process.chdir(runtime);
    const svc = loadTrashServiceWithoutDatabase();
    assert.throws(() => svc.claimRemoteDeletion({ item: {
      id: "unsafe-parent-fixture", metadata: { remoteDeletion: {
        operationId: "unsafe-parent-fixture", state: "pending",
      } },
    } }), /unsafe/i);
    assert.equal(fs.lstatSync(directory).mode & 0o777, 0o775);
  } finally {
    process.chdir(originalCwd);
  }
});
