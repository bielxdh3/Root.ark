"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile } =
  require("../src/services/zk1PrivateSqlitePath");

function create(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-dir-gate-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }));
  const privateDir = path.join(root, "private");
  fs.mkdirSync(privateDir, { mode: 0o700 });
  return { root, privateDir };
}

test("private DB path admits a regular file and preserves bigint dev/ino across an FD", (t) => {
  const f = create(t);
  const filename = path.join(f.privateDir, "db.sqlite");
  ensurePrivateSqliteDirectory(filename);
  fs.writeFileSync(filename, "dummy", { mode: 0o600 });
  const pinned = assertPrivateSqliteFile(filename);
  const observed = fs.lstatSync(filename, { bigint: true });
  assert.equal(typeof pinned.ino, "bigint");
  assert.equal(pinned.ino, observed.ino);
  assert.equal(pinned.dev, observed.dev);
});

test("ancestor symlink/junction reaching the exact same file fails closed", (t) => {
  const f = create(t);
  const filename = path.join(f.privateDir, "db.sqlite");
  fs.writeFileSync(filename, "dummy", { mode: 0o600 });
  const alias = path.join(f.root, "alias");
  fs.symlinkSync(f.privateDir, alias, process.platform === "win32" ? "junction" : "dir");
  const redirected = path.join(alias, "db.sqlite");
  assert.equal(fs.statSync(redirected, { bigint: true }).ino,
    fs.statSync(filename, { bigint: true }).ino);
  assert.throws(() => assertPrivateSqliteFile(redirected), /UNTRUSTED_SQLITE_PATH/);
  assert.throws(() => ensurePrivateSqliteDirectory(path.join(alias, "other.sqlite")),
    /UNTRUSTED_SQLITE_PATH/);
});

test("leaf symlinks are rejected before any database read", (t) => {
  const f = create(t);
  const filename = path.join(f.privateDir, "db.sqlite");
  const alias = path.join(f.privateDir, "alias.sqlite");
  fs.writeFileSync(filename, "dummy", { mode: 0o600 });
  try { fs.symlinkSync(filename, alias, "file"); }
  catch (error) {
    if (process.platform === "win32" && error.code === "EPERM") {
      return t.skip("Creating file symlinks requires Windows Developer Mode or elevation");
    }
    throw error;
  }
  assert.throws(() => assertPrivateSqliteFile(alias), /UNTRUSTED_SQLITE_PATH/);
});

test("Unix writable parent and writable DB file are rejected", (t) => {
  if (process.platform === "win32") return t.skip("Windows ACLs are not modeled by POSIX mode bits");
  const f = create(t);
  const filename = path.join(f.privateDir, "db.sqlite");
  fs.writeFileSync(filename, "dummy", { mode: 0o600 });
  fs.chmodSync(filename, 0o644);
  assert.throws(() => assertPrivateSqliteFile(filename), /UNTRUSTED_SQLITE_PATH/);
  fs.chmodSync(filename, 0o600);
  fs.chmodSync(f.privateDir, 0o777);
  assert.throws(() => assertPrivateSqliteFile(filename), /UNTRUSTED_SQLITE_PATH/);
  assert.throws(() => ensurePrivateSqliteDirectory(path.join(f.privateDir, "other.sqlite")),
    /UNTRUSTED_SQLITE_PATH/);
});
