"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { spawnSync } = require("node:child_process");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { assertPrivateSqliteFile, ensurePrivateSqliteDirectory,
  assertPrivateSqliteAuthorityDirectory } =
  require("../src/services/zk1PrivateSqlitePath");

test("private SQLite checks validate opened descriptor and deny hard-linked files", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-zk-private-sqlite-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const filename = path.join(dir, "store.sqlite");
  const alias = path.join(dir, "alias.sqlite");
  fs.writeFileSync(filename, "disposable", { mode: 0o600 });
  assert.doesNotThrow(() => assertPrivateSqliteFile(filename));
  fs.linkSync(filename, alias);
  assert.throws(() => assertPrivateSqliteFile(filename), /UNTRUSTED_SQLITE_PATH/);
  assert.throws(() => assertPrivateSqliteFile(alias), /UNTRUSTED_SQLITE_PATH/);
  fs.unlinkSync(alias);
  assert.doesNotThrow(() => assertPrivateSqliteFile(filename));
});

test("private SQLite bootstrap refuses a junction planted after the ancestor check without creating foreign directories", (t) => {
  const root = createPrivateAuthorityFixture("rootark-zk-sqlite-mkdir-race-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const foreign = path.join(root, "foreign");
  fs.mkdirSync(foreign, { mode: 0o700 });
  const entry = path.join(root, "attacker-entry");
  const target = path.join(entry, "new-authority");
  const filename = path.join(target, "journal.sqlite");
  const outside = path.join(foreign, "new-authority");
  const mkdir = fs.mkdirSync;
  const native = process.platform === "win32"
    ? require("../services/chunkUploadWindowsAcl") : null;
  const nativeCreate = native?.ensureWindowsChunkUploadRoot;
  let injected = false;
  function insertBeforeFirstCreate(name) {
    // Deterministically model a foreign user creating the first missing
    // ancestor after preflight but before the actual mkdir syscall.
    if (!injected && (name === entry || name === target)) {
      injected = true;
      fs.symlinkSync(foreign, entry, process.platform === "win32" ? "junction" : "dir");
    }
  }
  fs.mkdirSync = function (name, options) {
    if (!native) insertBeforeFirstCreate(name);
    return mkdir.apply(this, arguments);
  };
  if (native) native.ensureWindowsChunkUploadRoot = function (name) {
    // Invoke the genuine native ACL-aware CreateDirectoryW implementation;
    // inject just before it, never mock an allowed/denied result.
    insertBeforeFirstCreate(name);
    return nativeCreate.apply(this, arguments);
  };
  try {
    assert.equal(fs.existsSync(outside), false);
    assert.throws(() => ensurePrivateSqliteDirectory(filename), /UNTRUSTED_SQLITE_PATH|EEXIST/);
  } finally {
    fs.mkdirSync = mkdir;
    if (native) native.ensureWindowsChunkUploadRoot = nativeCreate;
  }
  assert.equal(injected, true, "a real concurrent directory insertion must be exercised");
  assert.equal(fs.lstatSync(entry).isSymbolicLink(), true);
  assert.equal(fs.existsSync(outside), false,
    "rejected bootstrap must not create a child through the attacker junction");
});

test("private SQLite bootstrap preserves legitimate nested creation and restart", (t) => {
  const root = createPrivateAuthorityFixture("rootark-zk-sqlite-new-nested-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const containing = path.join(root, "first", "second", "third");
  const filename = path.join(containing, "authority.sqlite");
  assert.equal(fs.existsSync(containing), false);
  assert.doesNotThrow(() => ensurePrivateSqliteDirectory(filename));
  assert.equal(fs.statSync(containing).isDirectory(), true);
  assert.doesNotThrow(() => assertPrivateSqliteAuthorityDirectory(filename),
    "a newly created private Windows journal must pass the unchanged native ACL guard");
  assert.doesNotThrow(() => ensurePrivateSqliteDirectory(filename),
    "a legitimate second bootstrap must leave existing private directories intact");
  if (process.platform !== "win32") {
    for (const part of [path.join(root, "first"), path.join(root, "first", "second"), containing]) {
      assert.equal(fs.statSync(part).mode & 0o077, 0, "every newly created POSIX parent is private");
    }
  }
});

test("Windows SQLite bootstrap accepts unrelated Everyone Read sibling without weakening a new private child", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = createPrivateAuthorityFixture("rootark-zk-sqlite-read-sibling-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  // The pre-existing private root is safe for mkdir. An unrelated sibling
  // intentionally allows READ (not Modify) and is outside the new DB subtree.
  const sibling = path.join(root, "public-read-only.txt");
  fs.writeFileSync(sibling, "unrelated disposable public data");
  const grant = spawnSync("C:\\Windows\\System32\\icacls.exe",
    [sibling, "/grant", "*S-1-1-0:R"],
    { windowsHide: true, encoding: "utf8", timeout: 12000 });
  assert.equal(grant.status, 0, "real NTFS Everyone Read ACE must be installed");
  const child = path.join(root, "private-sqlite", "nested");
  const filename = path.join(child, "authority.sqlite");
  assert.equal(fs.existsSync(child), false);
  assert.doesNotThrow(() => ensurePrivateSqliteDirectory(filename),
    "an unrelated safe READ-only sibling must not deny private SQLite creation");
  assert.equal(fs.statSync(child).isDirectory(), true);
  assert.doesNotThrow(() => assertPrivateSqliteAuthorityDirectory(filename),
    "new SQLite child still must have the native protected owner-only DACL");
  assert.doesNotThrow(() => ensurePrivateSqliteDirectory(filename),
    "restart of the private SQLite child must remain supported");
});

test("private SQLite bootstrap does not descend through a later component swapped for a junction", (t) => {
  const root = createPrivateAuthorityFixture("rootark-zk-sqlite-later-swap-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const foreign = path.join(root, "foreign");
  fs.mkdirSync(foreign, { mode: 0o700 });
  const first = path.join(root, "one");
  const moved = path.join(root, "one-original");
  const filename = path.join(first, "two", "three", "main.sqlite");
  const outside = path.join(foreign, "two");
  const originalRealpath = fs.realpathSync.native;
  let injected = false;
  fs.realpathSync.native = function (name, ...args) {
    const canonical = originalRealpath.call(this, name, ...args);
    if (!injected && name === first) {
      injected = true;
      fs.renameSync(first, moved);
      fs.symlinkSync(foreign, first, process.platform === "win32" ? "junction" : "dir");
    }
    return canonical;
  };
  try {
    assert.throws(() => ensurePrivateSqliteDirectory(filename), /UNTRUSTED_SQLITE_PATH/);
  } finally {
    fs.realpathSync.native = originalRealpath;
  }
  assert.equal(injected, true, "the first created directory must be swapped after its identity check");
  assert.equal(fs.lstatSync(first).isSymbolicLink(), true);
  assert.equal(fs.existsSync(outside), false,
    "second mkdir must not follow a late-swapped earlier ancestor into foreign storage");
});

test("Windows SQLite bootstrap refuses an existing Everyone Modify ancestor before any mkdir", {
  skip: process.platform !== "win32",
}, (t) => {
  const root = createPrivateAuthorityFixture("rootark-zk-sqlite-foreign-acl-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const weak = path.join(root, "untrusted-parent");
  fs.mkdirSync(weak);
  const grant = spawnSync("C:\\Windows\\System32\\icacls.exe",
    [weak, "/grant", "*S-1-1-0:(OI)(CI)M"],
    { windowsHide: true, encoding: "utf8", timeout: 12000 });
  assert.equal(grant.status, 0, "real NTFS Everyone Modify ACE must be installed");
  const child = path.join(weak, "new-authority");
  const filename = path.join(child, "floor.sqlite");
  assert.equal(fs.existsSync(child), false);
  assert.throws(() => ensurePrivateSqliteDirectory(filename),
    /UNTRUSTED_SQLITE_PATH|Windows chunk staging ACL validation failed/);
  assert.equal(fs.existsSync(child), false,
    "unsafe existing ancestor must be rejected before filesystem side effects");
});

test("POSIX SQLite bootstrap refuses group-writable existing ancestor before any mkdir", {
  skip: process.platform === "win32",
}, (t) => {
  const root = createPrivateAuthorityFixture("rootark-zk-sqlite-writable-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const writable = path.join(root, "untrusted-parent");
  fs.mkdirSync(writable, { mode: 0o700 });
  fs.chmodSync(writable, 0o770);
  const child = path.join(writable, "new-authority");
  assert.equal(fs.existsSync(child), false);
  assert.throws(() => ensurePrivateSqliteDirectory(path.join(child, "floor.sqlite")),
    /UNTRUSTED_SQLITE_PATH/);
  assert.equal(fs.existsSync(child), false,
    "a group-writable ancestor must be rejected before creating any descendants");
});
