const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { readBoundedRegularFile } = require("../services/internalFile");

test("reads a bounded regular file through one descriptor and rejects oversized or non-regular paths", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const regular = path.join(directory, "journal.json");
  fs.writeFileSync(regular, "{\"phase\":\"prepared\"}");
  assert.equal(readBoundedRegularFile(regular, 64).contents.toString("utf8"), "{\"phase\":\"prepared\"}");

  const oversized = path.join(directory, "oversized.json");
  fs.writeFileSync(oversized, Buffer.alloc(65, 0x61));
  assert.throws(() => readBoundedRegularFile(oversized, 64), /regular file|size|limit/i);
  assert.throws(() => readBoundedRegularFile(directory, 64), /regular file|size|limit/i);
});

test("rejects a path replaced with a symlink before any descriptor reads", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, "journal.json");
  const outside = path.join(directory, "outside.json");
  fs.writeFileSync(target, "safe");
  fs.writeFileSync(outside, "sensitive outside data");

  const originalOpenSync = fs.openSync;
  const originalReadSync = fs.readSync;
  let replaced = false;
  let reads = 0;
  const probe = path.join(directory, "symlink-probe");
  try {
    fs.symlinkSync(outside, probe);
    assert.equal(fs.lstatSync(probe).isSymbolicLink(), true, "test preflight must confirm symlink support");
    fs.unlinkSync(probe);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
      t.skip(`symbolic links unsupported in this environment: ${error.code}`);
      return;
    }
    throw error;
  }
  fs.openSync = function (filePath, flags, ...args) {
    if (!replaced && path.resolve(String(filePath)) === path.resolve(target)) {
      replaced = true;
      fs.unlinkSync(target);
      fs.symlinkSync(outside, target);
      assert.equal(fs.lstatSync(target).isSymbolicLink(), true, "race setup must actually create the symlink");
    }
    return originalOpenSync.call(this, filePath, flags, ...args);
  };
  fs.readSync = function (...args) { reads += 1; return originalReadSync.apply(this, args); };
  try {
    assert.throws(() => readBoundedRegularFile(target, 64));
    assert.equal(replaced, true);
    assert.equal(reads, 0, "replacement is rejected before any bytes are read");
  } finally {
    fs.openSync = originalOpenSync;
    fs.readSync = originalReadSync;
  }
});

test("rejects a same-directory path replacement during open before reading its bytes", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-identity-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, "journal.json");
  const saved = path.join(directory, "saved.json");
  const replacement = path.join(directory, "replacement.json");
  fs.writeFileSync(target, "safe");
  fs.writeFileSync(replacement, "replacement bytes");

  const originalOpenSync = fs.openSync;
  const originalReadSync = fs.readSync;
  let replaced = false;
  let reads = 0;
  fs.openSync = function (filePath, flags, ...args) {
    if (!replaced && path.resolve(String(filePath)) === path.resolve(target)) {
      replaced = true;
      fs.renameSync(target, saved);
      fs.linkSync(replacement, target);
    }
    return originalOpenSync.call(this, filePath, flags, ...args);
  };
  fs.readSync = function (...args) { reads += 1; return originalReadSync.apply(this, args); };
  try {
    assert.throws(() => readBoundedRegularFile(target, 64));
    assert.equal(replaced, true);
    assert.equal(reads, 0, "a descriptor whose identity differs from the pre-open path must not be read");
  } finally {
    fs.openSync = originalOpenSync;
    fs.readSync = originalReadSync;
  }
});

test("fails closed before reading when filesystem metadata has no stable inode", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-no-inode-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, "journal.json");
  const saved = path.join(directory, "saved.json");
  const replacement = path.join(directory, "replacement.json");
  fs.writeFileSync(target, "safe!");
  fs.writeFileSync(replacement, "bad!!");

  const originalOpenSync = fs.openSync;
  const originalLstatSync = fs.lstatSync;
  const originalFstatSync = fs.fstatSync;
  const originalReadSync = fs.readSync;
  let reads = 0;
  fs.lstatSync = () => ({ dev: 7, ino: 0, size: 5, mtimeMs: 10, ctimeMs: 20, isFile: () => true, isSymbolicLink: () => false });
  fs.fstatSync = () => ({ dev: 7, ino: 0, size: 5, mtimeMs: 10, ctimeMs: 20, isFile: () => true, isSymbolicLink: () => false });
  fs.openSync = function (filePath, flags, ...args) {
    if (path.resolve(String(filePath)) === path.resolve(target)) {
      fs.renameSync(target, saved);
      fs.linkSync(replacement, target);
    }
    return originalOpenSync.call(this, filePath, flags, ...args);
  };
  fs.readSync = function (...args) { reads += 1; return originalReadSync.apply(this, args); };
  try {
    assert.throws(() => readBoundedRegularFile(target, 64));
    assert.equal(reads, 0, "missing stable identity must reject the opened descriptor before reading");
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.fstatSync = originalFstatSync;
    fs.readSync = originalReadSync;
  }
});

test("rejects a Windows open-time symlink swap restored as a hard link before reading bytes", (t) => {
  if (process.platform !== "win32") {
    t.skip("models the Windows fallback where O_NOFOLLOW is unavailable");
    return;
  }
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-bounded-file-open-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const target = path.join(directory, "journal.json");
  const saved = path.join(directory, "saved.json");
  const outside = path.join(directory, "outside.json");
  fs.writeFileSync(target, "safe journal");
  fs.writeFileSync(outside, "outside data must not be read");

  const originalOpenSync = fs.openSync;
  const originalReadSync = fs.readSync;
  let reads = 0;
  let swapped = false;
  let openedDescriptor;
  fs.openSync = function (filePath, flags, ...args) {
    if (!swapped && path.resolve(String(filePath)) === path.resolve(target)) {
      swapped = true;
      fs.renameSync(target, saved);
      try {
        fs.symlinkSync(outside, target);
        assert.equal(fs.lstatSync(target).isSymbolicLink(), true, "race setup must actually create the symlink");
        openedDescriptor = originalOpenSync.call(this, filePath, flags, ...args);
        fs.unlinkSync(target);
        fs.linkSync(outside, target);
        return openedDescriptor;
      } catch (error) {
        if (openedDescriptor !== undefined) {
          fs.closeSync(openedDescriptor);
          openedDescriptor = undefined;
        }
        try { if (fs.existsSync(target)) fs.unlinkSync(target); } catch {}
        try { fs.renameSync(saved, target); } catch {}
        if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
          t.skip(`symlink or hard-link replacement unsupported: ${error.code}`);
          throw Object.assign(new Error("test setup skipped"), { code: "TEST_SETUP_SKIPPED" });
        }
        throw error;
      }
    }
    return originalOpenSync.call(this, filePath, flags, ...args);
  };
  fs.readSync = function (...args) { reads += 1; return originalReadSync.apply(this, args); };
  try {
    assert.throws(() => readBoundedRegularFile(target, 64));
    assert.equal(swapped, true);
    assert.equal(reads, 0, "the opened descriptor must be rejected before reading outside bytes");
  } catch (error) {
    if (error.code === "TEST_SETUP_SKIPPED") return;
    throw error;
  } finally {
    fs.openSync = originalOpenSync;
    fs.readSync = originalReadSync;
  }
});
