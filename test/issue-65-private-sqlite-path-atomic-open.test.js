"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { assertPrivateSqliteFile, ensurePrivateSqliteDirectory } =
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
  let injected = false;
  fs.mkdirSync = function (name, options) {
    // Deterministically model a foreign user creating the first missing
    // ancestor after preflight but before the actual mkdir syscall.
    if (!injected && (name === entry || name === target)) {
      injected = true;
      fs.symlinkSync(foreign, entry, process.platform === "win32" ? "junction" : "dir");
    }
    return mkdir.apply(this, arguments);
  };
  try {
    assert.equal(fs.existsSync(outside), false);
    assert.throws(() => ensurePrivateSqliteDirectory(filename), /UNTRUSTED_SQLITE_PATH|EEXIST/);
  } finally {
    fs.mkdirSync = mkdir;
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
  assert.doesNotThrow(() => ensurePrivateSqliteDirectory(filename),
    "a legitimate second bootstrap must leave existing private directories intact");
  if (process.platform !== "win32") {
    for (const part of [path.join(root, "first"), path.join(root, "first", "second"), containing]) {
      assert.equal(fs.statSync(part).mode & 0o077, 0, "every newly created POSIX parent is private");
    }
  }
});
