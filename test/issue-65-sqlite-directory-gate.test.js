"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteFile,
  assertPrivateSqliteDirectory } =
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

test("POSIX rejects an unwritable-looking 0755 ancestor owned by another local UID", (t) => {
  if (process.platform === "win32") return t.skip("POSIX uid ownership only");
  const f = create(t);
  const foreignParent = path.join(f.privateDir, "foreign-owned-parent");
  const privateChild = path.join(foreignParent, "service-private");
  fs.mkdirSync(foreignParent, { mode: 0o755 });
  fs.mkdirSync(privateChild, { mode: 0o700 });
  const filename = path.join(privateChild, "ledger.sqlite");
  fs.writeFileSync(filename, "dummy", { mode: 0o600 });
  const actual = fs.lstatSync(foreignParent, { bigint: true });
  assert.equal(actual.uid, BigInt(process.getuid()));
  assert.equal(actual.mode & 0o777n, 0o755n);
  // No chown/privilege change: simulate the one POSIX stat field which an
  // unprivileged caller cannot assign to another UID on a disposable tree.
  // A 0755 directory owner can still chmod it or rename descendants, even
  // if another service has a private 0700 child below it.
  const realLstat = fs.lstatSync;
  let observedForeign = 0;
  fs.lstatSync = function (target, options) {
    const stat = realLstat.call(fs, target, options);
    if (path.resolve(target) !== foreignParent) return stat;
    observedForeign += 1;
    return Object.assign(Object.create(stat), {
      uid: typeof stat.uid === "bigint"
        ? BigInt(process.getuid() + 10000) : process.getuid() + 10000,
    });
  };
  try {
    assert.throws(() => assertPrivateSqliteDirectory(filename), /UNTRUSTED_SQLITE_PATH/);
    assert.throws(() => assertPrivateSqliteFile(filename), /UNTRUSTED_SQLITE_PATH/);
    assert.throws(() => ensurePrivateSqliteDirectory(path.join(privateChild,
      "new-ledger.sqlite")), /UNTRUSTED_SQLITE_PATH/);
  } finally { fs.lstatSync = realLstat; }
  assert.ok(observedForeign >= 3, "all checks must traverse the untrusted ancestor");
});

test("POSIX accepts real root-owned sticky tmp ancestor and rejects foreign-owned sticky ancestor", (t) => {
  if (process.platform === "win32") return t.skip("POSIX uid ownership only");
  const tmp = fs.lstatSync(os.tmpdir(), { bigint: true });
  if (tmp.uid !== 0n || (tmp.mode & 0o1777n) !== 0o1777n) {
    return t.skip("Platform temp directory is not root-owned sticky 1777");
  }
  const f = create(t);
  const filename = path.join(f.privateDir, "ledger.sqlite");
  assert.doesNotThrow(() => assertPrivateSqliteDirectory(filename),
    "real /tmp as root-owned sticky ancestor must remain usable");
  const realLstat = fs.lstatSync;
  fs.lstatSync = function (target, options) {
    const stat = realLstat.call(fs, target, options);
    if (path.resolve(target) !== path.resolve(os.tmpdir())) return stat;
    return Object.assign(Object.create(stat), {
      uid: typeof stat.uid === "bigint"
        ? BigInt(process.getuid() + 10000) : process.getuid() + 10000,
    });
  };
  try {
    assert.throws(() => assertPrivateSqliteDirectory(filename), /UNTRUSTED_SQLITE_PATH/,
      "untrusted UID on a sticky directory cannot receive root's exception");
  } finally { fs.lstatSync = realLstat; }
});

test("POSIX refuses a writable sticky ancestor owned by the service rather than root", (t) => {
  if (process.platform === "win32") return t.skip("POSIX uid ownership only");
  const f = create(t);
  const ancestor = path.join(f.privateDir, "sticky-owned-by-service");
  const containing = path.join(ancestor, "private");
  fs.mkdirSync(ancestor, { mode: 0o700 });
  fs.mkdirSync(containing, { mode: 0o700 });
  fs.chmodSync(ancestor, 0o1777);
  assert.equal(fs.lstatSync(ancestor, { bigint: true }).uid, BigInt(process.getuid()));
  assert.throws(() => assertPrivateSqliteDirectory(path.join(containing, "ledger.sqlite")),
    /UNTRUSTED_SQLITE_PATH/);
});
