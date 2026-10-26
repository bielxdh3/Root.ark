"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { assertAtomicRegistryStoragePermissions } =
  require("../src/services/syncAtomicRegistryStoragePermissions");

const UNSAFE = { code: "SYNC_ATOMIC_REGISTRY_STORAGE_UNSAFE" };

test("POSIX: foreign non-sticky ancestor 0755 cannot authorize private atomic registry", (t) => {
  if (process.platform === "win32") return t.skip("POSIX ownership only; Windows NTFS ACL is separate");
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-atomic-parent-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const parent = path.join(root, "ancestor");
  const privateDir = path.join(parent, "registry");
  fs.mkdirSync(privateDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(root, 0o700);
  fs.chmodSync(parent, 0o755);
  fs.chmodSync(privateDir, 0o700);
  const file = path.join(privateDir, "state.json");
  assert.equal(assertAtomicRegistryStoragePermissions(file), true,
    "same-UID owner of the read-only ancestor is trusted");

  // A real foreign UID requires privileged chown; change only the stat of the
  // single 0755 ancestor so the test is reproducible as an unprivileged user.
  // Its owner can rename/chmod the ancestor despite mode 0755.
  const original = fs.lstatSync;
  let sampled = 0;
  try {
    fs.lstatSync = function (target, ...options) {
      const stat = original.call(this, target, ...options);
      if (target !== parent) return stat;
      sampled++;
      return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
        uid: process.getuid() === 0 ? 31415 : process.getuid() + 1,
      });
    };
    assert.throws(() => assertAtomicRegistryStoragePermissions(file), UNSAFE,
      "an unrelated owner with mode 0755 can still rename the ancestor");
    assert.ok(sampled > 0, "actual POSIX ancestor must be checked");
    assert.equal(fs.existsSync(file), false, "denial must not create or migrate a registry");
  } finally { fs.lstatSync = original; }
});

test("POSIX: root-owned sticky /tmp remains valid; foreign sticky ancestor does not", (t) => {
  if (process.platform === "win32") return t.skip("POSIX ownership only");
  const tempRoot = fs.realpathSync(os.tmpdir());
  const sticky = fs.lstatSync(tempRoot);
  if (sticky.uid !== 0 || (sticky.mode & 0o1002) !== 0o1002) {
    return t.skip("requires a real root-owned world-writable sticky /tmp");
  }
  const directory = fs.mkdtempSync(path.join(tempRoot, "zk65-atomic-sticky-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "state.json");
  assert.equal(assertAtomicRegistryStoragePermissions(file), true,
    "the root-owned sticky ancestor is an explicitly trusted exception");
  const original = fs.lstatSync;
  try {
    fs.lstatSync = function (target, ...options) {
      const stat = original.call(this, target, ...options);
      if (target !== tempRoot) return stat;
      return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, {
        uid: process.getuid() === 0 ? 31415 : process.getuid() + 1,
      });
    };
    assert.throws(() => assertAtomicRegistryStoragePermissions(file), UNSAFE,
      "a world-writable sticky ancestor only qualifies when root-owned");
  } finally { fs.lstatSync = original; }
});
