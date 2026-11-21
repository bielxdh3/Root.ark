"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { finished } = require("node:stream/promises");
const test = require("node:test");
const { cleanupOrphanPrivateShareSnapshots, cleanupReadHandle, openReadHandle, readBoundedRegularFile,
  ensurePrivateShareSnapshotDirectory, getPrivateShareSnapshotCleanupState, getPrivateShareSnapshotDirectory,
  getPrivateShareSnapshotProcessInstance,
  retryPendingPrivateShareSnapshotCleanup, snapshotReadHandle } = require("../services/fileReadHandle");
const { createPrivateShareSnapshotBudget } = require("../services/privateShareSnapshotBudget");

function testTempDirectoryRoot() {
  return process.platform === "win32" && process.env.LOCALAPPDATA
    ? process.env.LOCALAPPDATA : os.tmpdir();
}

test("opened file descriptor keeps the authorized bytes after path replacement", async () => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-open-file-handle-"));
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
test("opening pins the descriptor before checking path identity", () => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-open-file-order-"));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  const originalOpenSync = fs.openSync;
  const originalLstatSync = fs.lstatSync;
  const calls = [];
  fs.openSync = function (target, ...args) {
    if (target === filePath) calls.push("open");
    return originalOpenSync.call(this, target, ...args);
  };
  fs.lstatSync = function (target, ...args) {
    if (target === filePath) calls.push("lstat");
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    const handle = openReadHandle(filePath);
    fs.closeSync(handle.fd);
    assert.deepEqual(calls.slice(0, 2), ["open", "lstat"]);
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("opening rejects an in-place rewrite after the descriptor is pinned", () => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-open-file-in-place-race-"));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, "before");
  const originalLstatSync = fs.lstatSync;
  let rewritten = false;
  fs.lstatSync = function (target, ...args) {
    if (target === filePath && !rewritten) {
      rewritten = true;
      fs.writeFileSync(filePath, "rewritten bytes with a different length");
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(rewritten, true);
  } finally {
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("opening rejects a path replaced after its descriptor is pinned", () => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-open-file-descriptor-first-"));
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
      if (!replaced && calls.filter((call) => call === "lstat").length === 1) {
        replaced = true;
        fs.renameSync(filePath, `${filePath}.opened`);
        fs.renameSync(replacementPath, filePath);
      }
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => openReadHandle(filePath), { code: "FILE_HANDLE_CHANGED" });
    assert.equal(calls[0], "open");
    assert.equal(calls[1], "lstat");
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("share snapshot preserves authorized bytes after same-inode mutation and cleans up without double-closing the stream fd", async (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, "authorized bytes");
  const snapshot = await snapshotReadHandle(filePath);
  assert.equal(snapshot.fdOwned, true);
  fs.writeFileSync(filePath, "mutated bytes!!!");
  const stream = fs.createReadStream(null, { fd: snapshot.fd, autoClose: true });
  snapshot.fdOwned = false;
  const chunks = [];
  stream.on("data", (chunk) => chunks.push(chunk));
  await finished(stream);
  assert.equal(Buffer.concat(chunks).toString("utf8"), "authorized bytes");
  const snapshotPath = snapshot.cleanupPath;
  const originalCloseSync = fs.closeSync;
  let duplicateCloseCalls = 0;
  fs.closeSync = function (fd) {
    if (fd === snapshot.fd) duplicateCloseCalls += 1;
    return originalCloseSync.call(this, fd);
  };
  try { cleanupReadHandle(snapshot); }
  finally { fs.closeSync = originalCloseSync; }
  assert.equal(duplicateCloseCalls, 0, "cleanup must not close an fd already owned and closed by ReadStream");
  assert.equal(fs.existsSync(snapshotPath), false, "the private snapshot is removed after stream close");
});

test("share snapshot abort signal cancels the pipeline and removes its temporary file", async (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-abort-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, Buffer.alloc(32 * 1024 * 1024, 0x61));
  const snapshotDirectory = getPrivateShareSnapshotDirectory();
  const ownedSnapshotPrefix = `rootark-share-egress-${process.pid}-${getPrivateShareSnapshotProcessInstance()}-`;
  const before = new Set(fs.existsSync(snapshotDirectory)
    ? fs.readdirSync(snapshotDirectory).filter((name) => name.startsWith(ownedSnapshotPrefix)) : []);
  const controller = new AbortController();
  const originalCreateReadStream = fs.createReadStream;
  const originalHandle = openReadHandle(filePath);
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 64 * 1024 * 1024 });
  originalHandle.cleanupCallback = budget.reserve(originalHandle.stats.size);
  assert.equal(typeof originalHandle.cleanupCallback, "function");
  fs.createReadStream = function (...args) {
    const stream = originalCreateReadStream.apply(this, args);
    setImmediate(() => controller.abort(new Error("test client disconnect")));
    return stream;
  };
  try {
    await assert.rejects(snapshotReadHandle(filePath, originalHandle, { signal: controller.signal }),
      (error) => error.name === "AbortError" || error.code === "ABORT_ERR");
  } finally {
    fs.createReadStream = originalCreateReadStream;
  }
  assert.throws(() => fs.fstatSync(originalHandle.fd), { code: "EBADF" },
    "aborted snapshot must close the original authorized descriptor");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 },
    "aborted snapshot cleanup must release its reservation");
  const after = fs.existsSync(snapshotDirectory)
    ? fs.readdirSync(snapshotDirectory).filter((name) => name.startsWith(ownedSnapshotPrefix)) : [];
  assert.deepEqual(after.filter((name) => !before.has(name)), [], "aborted snapshot must not leave a TEMP file");
});

test("private share snapshot budget bounds active copies separately from retained bytes", () => {
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 2, maxBytes: 10 });
  const releaseA = budget.reserve(6);
  assert.equal(typeof releaseA, "function");
  assert.equal(budget.reserve(5), null, "aggregate byte budget must reject overcommit");
  const releaseB = budget.reserve(4);
  assert.equal(typeof releaseB, "function");
  assert.equal(budget.reserve(0), null, "concurrency budget must reject another active copy");
  releaseA.releaseActive();
  assert.deepEqual(budget.getState(), { active: 1, reservedBytes: 10 },
    "closing a stream releases its active slot without releasing snapshot bytes");
  const releaseC = budget.reserve(0);
  assert.equal(typeof releaseC, "function", "a completed stream frees a concurrency slot");
  releaseC();
  releaseA();
  releaseA();
  assert.deepEqual(budget.getState(), { active: 1, reservedBytes: 4 });
  const releaseD = budget.reserve(6);
  assert.equal(typeof releaseD, "function");
  releaseB();
  releaseD();
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
});

test("private share snapshot budget remains reserved when TEMP cleanup fails and releases after retry", async (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-cleanup-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, Buffer.from("authorized snapshot bytes"));
  const snapshot = await snapshotReadHandle(filePath);
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(snapshot.stats.size);
  assert.equal(typeof release, "function");
  snapshot.cleanupCallback = release;
  const originalUnlinkSync = fs.unlinkSync;
  const quarantinePrefix = `${snapshot.cleanupPath.slice(0, -4)}.cleanup-`;
  fs.unlinkSync = function (target) {
    if (String(target).startsWith(quarantinePrefix)) {
      const error = new Error("simulated TEMP cleanup failure");
      error.code = "EACCES";
      throw error;
    }
    return originalUnlinkSync.call(this, target);
  };
  try {
    assert.equal(cleanupReadHandle(snapshot), false,
      "cleanup must report failure when the private snapshot could not be unlinked");
  } finally {
    fs.unlinkSync = originalUnlinkSync;
  }
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: snapshot.stats.size },
    "failed TEMP deletion retains byte quota but releases the completed request slot");
  const nextRelease = budget.reserve(1);
  assert.equal(typeof nextRelease, "function", "failed unlink must not permanently exhaust active slots");
  nextRelease();
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: snapshot.stats.size });
  assert.ok(fs.readdirSync(path.dirname(snapshot.cleanupPath)).some((name) => name.startsWith(path.basename(quarantinePrefix))),
    "failed unlink must retain its verified quarantine name until retry");
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 1,
    "the production cleanup reaper must retry and remove the private snapshot");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 },
    "successful cleanup retry must release the reservation");
  assert.equal(fs.existsSync(snapshot.cleanupPath), false);
  assert.equal(fs.readdirSync(path.dirname(snapshot.cleanupPath)).some((name) => name.startsWith(path.basename(quarantinePrefix))), false,
    "successful reaping must remove the previously quarantined inode");
});

test("identity-null cleanup recovers only from its still-owned descriptor, never from pathname metadata", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-identity-retry-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000003.tmp`);
  fs.writeFileSync(cleanupPath, "private snapshot");
  const descriptor = fs.openSync(cleanupPath, "r");
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("private snapshot"));
  const originalFstatSync = fs.fstatSync;
  const originalLstatSync = fs.lstatSync;
  let failFirstFstat = true;
  let cleanupPathLookups = 0;
  fs.fstatSync = function (fd, ...args) {
    if (fd === descriptor && failFirstFstat) {
      failFirstFstat = false;
      const error = new Error("transient descriptor identity failure");
      error.code = "EIO";
      throw error;
    }
    return originalFstatSync.call(this, fd, ...args);
  };
  fs.lstatSync = function (target, ...args) {
    if (target === cleanupPath) cleanupPathLookups++;
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: descriptor, fdOwned: true, allowIdentityRetry: true,
      cleanupPath, cleanupIdentity: null, fdIdentity: null, cleanupCallback: release }), false);
  } finally {
    fs.fstatSync = originalFstatSync;
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(cleanupPathLookups, 0,
    "identity recovery must not inspect or adopt the current pathname");
  assert.equal(fs.existsSync(cleanupPath), true,
    "an unproven snapshot path must remain untouched while its descriptor identity is unknown");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: Buffer.byteLength("private snapshot") });
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 1);
  assert.equal(fs.existsSync(cleanupPath), false);
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
  assert.equal(getPrivateShareSnapshotCleanupState().identityUnproven, 0,
    "the pending state clears only after fstat proves the original descriptor identity");
});

test("ambiguous close errors retry only while fstat confirms the original inode", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-close-ambiguous-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000004.tmp`);
  fs.writeFileSync(cleanupPath, "private snapshot");
  const descriptor = fs.openSync(cleanupPath, "r");
  const identity = fs.fstatSync(descriptor, { bigint: true });
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("private snapshot"));
  const originalCloseSync = fs.closeSync;
  let closeCalls = 0;
  fs.closeSync = function (fd) {
    if (fd === descriptor) {
      closeCalls++;
      if (closeCalls === 1) {
        fs.appendFileSync(cleanupPath, " metadata drift");
        const error = new Error("transient close I/O failure");
        error.code = "EIO";
        throw error;
      }
    }
    return originalCloseSync.call(this, fd);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: descriptor, fdOwned: true,
      allowIdentityRetry: true,
      fdIdentity: identity,
      cleanupPath, cleanupIdentity: { dev: identity.dev, ino: identity.ino },
      cleanupCallback: release }), true);
  } finally {
    fs.closeSync = originalCloseSync;
  }
  assert.equal(fs.existsSync(cleanupPath), false,
    "the path is removed after the identity-verified close retry");
  assert.equal(closeCalls, 2, "one identity-verified retry is permitted");
  assert.equal(budget.getState().active, 0,
    "successful close and unlink release the reservation");
  assert.throws(() => fs.fstatSync(descriptor), { code: "EBADF" });
});

test("ambiguous close remains charged until a later retry proves closure and removes the quarantine", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-close-pending-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000008.tmp`);
  fs.writeFileSync(cleanupPath, "private snapshot");
  const descriptor = fs.openSync(cleanupPath, "r");
  const identity = fs.fstatSync(descriptor, { bigint: true });
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("private snapshot"));
  const originalCloseSync = fs.closeSync;
  fs.closeSync = function (fd) {
    if (fd === descriptor) {
      const error = new Error("persistent close uncertainty");
      error.code = "EIO";
      throw error;
    }
    return originalCloseSync.call(this, fd);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: descriptor, fdOwned: true, allowIdentityRetry: true,
      fdIdentity: identity, cleanupPath, cleanupIdentity: { dev: identity.dev, ino: identity.ino },
      cleanupCallback: release }), false);
  } finally {
    fs.closeSync = originalCloseSync;
  }
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: Buffer.byteLength("private snapshot") });
  const nextRelease = budget.reserve(1);
  assert.equal(typeof nextRelease, "function", "uncertain close must not permanently exhaust active slots");
  nextRelease();
  assert.equal(getPrivateShareSnapshotCleanupState().descriptorClosePending, 1);
  assert.equal(fs.existsSync(cleanupPath), true,
    "the path remains available while the descriptor may still be open");
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 1,
    "the periodic reaper must retry the same identity-verified fd and finish cleanup");
  assert.throws(() => fs.fstatSync(descriptor), { code: "EBADF" });
  assert.equal(fs.existsSync(cleanupPath), false);
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
});

test("atomic quarantine verifies the moved inode before unlinking a raced replacement", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-quarantine-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000009.tmp`);
  const replacementPath = path.join(directory, "replacement.txt");
  const displacedPath = path.join(directory, "displaced-original.tmp");
  fs.writeFileSync(cleanupPath, "authorized snapshot");
  fs.writeFileSync(replacementPath, "unrelated replacement");
  const descriptor = fs.openSync(cleanupPath, "r");
  const identity = fs.fstatSync(descriptor, { bigint: true });
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("authorized snapshot"));
  const originalRenameSync = fs.renameSync;
  let raced = false;
  fs.renameSync = function (source, target) {
    if (!raced && source === cleanupPath && String(target).includes(".cleanup-")) {
      raced = true;
      originalRenameSync.call(this, cleanupPath, displacedPath);
      originalRenameSync.call(this, replacementPath, cleanupPath);
    }
    return originalRenameSync.call(this, source, target);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: descriptor, fdOwned: true, allowIdentityRetry: true,
      fdIdentity: identity, cleanupPath, cleanupIdentity: { dev: identity.dev, ino: identity.ino },
      cleanupCallback: release }), false);
  } finally {
    fs.renameSync = originalRenameSync;
  }
  assert.equal(raced, true);
  assert.equal(fs.readFileSync(cleanupPath, "utf8"), "unrelated replacement",
    "a replacement moved into quarantine must be restored without being deleted");
  assert.equal(fs.readFileSync(displacedPath, "utf8"), "authorized snapshot");
  assert.equal(budget.getState().active, 0,
    "the active request slot is released while bytes remain charged for the quarantined inode");
  fs.renameSync(cleanupPath, replacementPath);
  fs.renameSync(displacedPath, cleanupPath);
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 1,
    "once the original inode is restored, the pending cleanup can finish safely");
  assert.equal(fs.existsSync(cleanupPath), false);
  assert.equal(fs.readFileSync(replacementPath, "utf8"), "unrelated replacement");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
});

test("ambiguous close never closes a reused fd whose inode differs from the owned snapshot", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-fd-reuse-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000007.tmp`);
  const replacementPath = path.join(directory, "replacement.txt");
  fs.writeFileSync(cleanupPath, "private snapshot");
  fs.writeFileSync(replacementPath, "unrelated descriptor owner");
  const descriptor = fs.openSync(cleanupPath, "r");
  const identity = fs.fstatSync(descriptor, { bigint: true });
  const replacementIdentity = fs.statSync(replacementPath, { bigint: true });
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("private snapshot"));
  const originalCloseSync = fs.closeSync;
  const originalOpenSync = fs.openSync;
  let closeCalls = 0;
  let replacementFd;
  fs.closeSync = function (fd) {
    if (fd === descriptor) {
      closeCalls++;
      originalCloseSync.call(this, fd);
      replacementFd = originalOpenSync.call(fs, replacementPath, "r");
      assert.equal(replacementFd, descriptor, "the OS should reuse the just-closed numeric fd");
      const error = new Error("ambiguous close after descriptor reuse");
      error.code = "EIO";
      throw error;
    }
    return originalCloseSync.call(this, fd);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: descriptor, fdOwned: true,
      allowIdentityRetry: true,
      fdIdentity: identity,
      cleanupPath, cleanupIdentity: { dev: identity.dev, ino: identity.ino },
      cleanupCallback: release }), true);
  } finally {
    fs.closeSync = originalCloseSync;
  }
  assert.equal(closeCalls, 1, "the reused numeric descriptor must not be closed again");
  assert.equal(fs.existsSync(cleanupPath), false, "the original snapshot path is removed");
  const stillOpen = fs.fstatSync(replacementFd, { bigint: true });
  assert.equal(stillOpen.dev, replacementIdentity.dev);
  assert.equal(stillOpen.ino, replacementIdentity.ino,
    "the replacement descriptor remains owned by its unrelated file");
  retryPendingPrivateShareSnapshotCleanup();
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 },
    "a different inode proves the private snapshot fd was released, so cleanup may release its reservation");
  originalCloseSync(replacementFd);
});

test("cleanup preflight never closes a numeric fd already reused before cleanup begins", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-fd-preflight-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000010.tmp`);
  const replacementPath = path.join(directory, "replacement.txt");
  fs.writeFileSync(cleanupPath, "private snapshot");
  fs.writeFileSync(replacementPath, "unrelated descriptor owner");
  const descriptor = fs.openSync(cleanupPath, "r");
  const identity = fs.fstatSync(descriptor, { bigint: true });
  const originalCloseSync = fs.closeSync;
  originalCloseSync(descriptor);
  const replacementFd = fs.openSync(replacementPath, "r");
  assert.equal(replacementFd, descriptor, "the OS should reuse the released numeric fd");
  const replacementIdentity = fs.fstatSync(replacementFd, { bigint: true });
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("private snapshot"));
  let closeCalls = 0;
  fs.closeSync = function (fd) {
    if (fd === replacementFd) closeCalls++;
    return originalCloseSync.call(this, fd);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: descriptor, fdOwned: true, allowIdentityRetry: false,
      fdIdentity: identity, cleanupPath, cleanupIdentity: { dev: identity.dev, ino: identity.ino },
      cleanupCallback: release }), true);
    assert.equal(closeCalls, 0,
      "a preflight dev/ino mismatch must prevent closeSync from touching the reused descriptor");
    const stillOpen = fs.fstatSync(replacementFd, { bigint: true });
    assert.equal(stillOpen.dev, replacementIdentity.dev);
    assert.equal(stillOpen.ino, replacementIdentity.ino);
  } finally {
    fs.closeSync = originalCloseSync;
    originalCloseSync(replacementFd);
  }
  assert.equal(fs.existsSync(cleanupPath), false, "the original snapshot path is cleaned safely");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
});

test("partial snapshot copy retries the same inode after an ambiguous close", async (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-partial-close-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "file.txt");
  fs.writeFileSync(filePath, Buffer.alloc(512 * 1024, 0x61));
  const handle = openReadHandle(filePath);
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 * 1024 });
  const release = budget.reserve(handle.stats.size);
  assert.equal(typeof release, "function");
  handle.cleanupCallback = release;

  const originalCreateReadStream = fs.createReadStream;
  const originalCreateWriteStream = fs.createWriteStream;
  const originalCloseSync = fs.closeSync;
  let snapshotFd;
  let sourceFailed = false;
  let injectedCloseError = false;
  let snapshotCloseCalls = 0;
  let partialBytesAtClose = 0n;
  fs.createReadStream = function (...args) {
    const stream = originalCreateReadStream.apply(this, args);
    stream.once("data", () => {
      if (sourceFailed) return;
      sourceFailed = true;
      const error = new Error("injected partial source failure");
      error.code = "EIO";
      setImmediate(() => stream.destroy(error));
    });
    return stream;
  };
  fs.createWriteStream = function (target, options) {
    snapshotFd = options.fd;
    return originalCreateWriteStream.call(this, target, options);
  };
  fs.closeSync = function (fd) {
    if (fd === snapshotFd) {
      snapshotCloseCalls++;
      if (!injectedCloseError) {
        injectedCloseError = true;
        partialBytesAtClose = fs.fstatSync(fd, { bigint: true }).size;
        const error = new Error("injected ambiguous close after partial write");
        error.code = "EIO";
        throw error;
      }
    }
    return originalCloseSync.call(this, fd);
  };
  try {
    await assert.rejects(snapshotReadHandle(filePath, handle), /injected partial source failure/);
  } finally {
    fs.createReadStream = originalCreateReadStream;
    fs.createWriteStream = originalCreateWriteStream;
    fs.closeSync = originalCloseSync;
  }
  assert.equal(sourceFailed, true, "the fixture must fail after a partial snapshot write begins");
  if (injectedCloseError) {
    assert.ok(partialBytesAtClose > 0n,
      "the destination descriptor must contain partial bytes when its first close fails");
    assert.equal(snapshotCloseCalls, 2, "the same-inode descriptor receives one identity-verified retry");
  } else {
    // Some Node pipeline implementations close a destroyed destination stream
    // before cleanupReadHandle reaches closeSync; no numeric fd can be retried.
    assert.equal(snapshotCloseCalls, 0);
  }
  assert.throws(() => fs.fstatSync(snapshotFd), { code: "EBADF" },
    "partial-copy cleanup must not leave the snapshot descriptor open");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 },
    "quota is released only after the snapshot fd closes and its path is removed");
});

test("private share snapshot copies no bytes appended after its initial fstat size", async (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-growth-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "file.txt");
  const initial = Buffer.alloc(1024 * 1024, 0x61);
  fs.writeFileSync(filePath, initial);
  const handle = openReadHandle(filePath);
  const originalCreateReadStream = fs.createReadStream;
  let copiedBytes = 0;
  fs.createReadStream = function (...args) {
    fs.appendFileSync(filePath, Buffer.alloc(1024 * 1024, 0x62));
    const stream = originalCreateReadStream.apply(this, args);
    stream.on("data", (chunk) => { copiedBytes += chunk.length; });
    return stream;
  };
  try {
    await assert.rejects(snapshotReadHandle(filePath, handle),
      (error) => error.code === "FILE_HANDLE_CHANGED");
  } finally {
    fs.createReadStream = originalCreateReadStream;
  }
  assert.equal(copiedBytes, initial.length,
    "the source stream must stop at the byte count reserved before the copy");
});

test("startup cleanup removes only orphaned private share snapshots from dead PIDs", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-orphans-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const orphan = path.join(directory,
    "rootark-share-egress-2147483647-00000000-0000-4000-8000-000000000001.tmp");
  const orphanQuarantine = path.join(directory,
    "rootark-share-egress-2147483647-00000000-0000-4000-8000-000000000004.cleanup-00000000-0000-4000-8000-000000000005.tmp");
  const live = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000002.tmp`);
  const liveCurrentInstance = path.join(directory,
    `rootark-share-egress-${process.pid}-${getPrivateShareSnapshotProcessInstance()}-00000000-0000-4000-8000-000000000011.tmp`);
  const previousProcessInstance = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000006-00000000-0000-4000-8000-000000000007.tmp`);
  const unrelated = path.join(directory, "other.tmp");
  fs.writeFileSync(orphan, "orphan");
  fs.writeFileSync(orphanQuarantine, "orphan quarantine");
  fs.writeFileSync(live, "live");
  fs.writeFileSync(liveCurrentInstance, "live current instance");
  fs.writeFileSync(previousProcessInstance, "previous process instance");
  fs.writeFileSync(unrelated, "unrelated");
  assert.equal(cleanupOrphanPrivateShareSnapshots(directory), 4);
  assert.equal(fs.existsSync(orphan), false);
  assert.equal(fs.existsSync(orphanQuarantine), false,
    "startup cleanup must recognize and remove an orphaned atomic quarantine");
  assert.equal(fs.existsSync(live), false,
    "a legacy filename with a reused current PID has no instance proof and belongs to the old process");
  assert.equal(fs.existsSync(liveCurrentInstance), true,
    "the reaper must parse the process-instance component before deciding a PID is stale");
  assert.equal(fs.existsSync(previousProcessInstance), false,
    "a reused PID with a different process-instance ID must not strand old snapshots");
  assert.equal(fs.existsSync(unrelated), true);
});

test("private snapshot directory validates owner and restrictive permissions on both directory levels", (t) => {
  if (process.platform === "win32") {
    const root = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-acl-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const parent = path.join(root, "temp");
    const child = path.join(parent, "share-snapshots");
    ensurePrivateShareSnapshotDirectory(parent);
    ensurePrivateShareSnapshotDirectory(child);
    const icacls = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "icacls.exe");
    const runIcacls = (...args) => execFileSync(icacls, args, { windowsHide: true, stdio: "ignore" });

    runIcacls(child, "/grant", "*S-1-1-0:(OI)(CI)(M)");
    assert.throws(() => ensurePrivateShareSnapshotDirectory(child),
      { code: "PRIVATE_SNAPSHOT_DIRECTORY_INVALID" },
      "a pre-existing private directory granting Everyone modify access must fail closed");
    runIcacls(child, "/remove:g", "*S-1-1-0");

    runIcacls(parent, "/grant", "*S-1-1-0:(OI)(CI)(M)");
    assert.throws(() => ensurePrivateShareSnapshotDirectory(child),
      { code: "PRIVATE_SNAPSHOT_DIRECTORY_INVALID" },
      "a pre-existing parent granting Everyone modify access must fail closed");
    return;
  }
  const root = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-directory-mode-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const parent = path.join(root, "temp");
  const child = path.join(parent, "share-snapshots");
  fs.mkdirSync(parent, { mode: 0o700 });
  fs.mkdirSync(child, { mode: 0o700 });

  fs.chmodSync(parent, 0o777);
  assert.throws(() => ensurePrivateShareSnapshotDirectory(child),
    { code: "PRIVATE_SNAPSHOT_DIRECTORY_INVALID" },
    "a pre-existing parent writable by other principals must fail closed");

  fs.chmodSync(parent, 0o700);
  fs.chmodSync(child, 0o755);
  assert.throws(() => ensurePrivateShareSnapshotDirectory(child),
    { code: "PRIVATE_SNAPSHOT_DIRECTORY_INVALID" },
    "a pre-existing snapshot directory readable by other principals must fail closed");

  fs.chmodSync(child, 0o700);
  assert.equal(ensurePrivateShareSnapshotDirectory(child), child,
    "owner-only snapshot and trusted parent permissions are accepted");
});

test("startup cleanup refuses to traverse a symlinked private snapshot directory", (t) => {
  const parent = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-symlink-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const target = path.join(parent, "target");
  const link = path.join(parent, "share-snapshots");
  fs.mkdirSync(target);
  const orphan = path.join(target,
    "rootark-share-egress-2147483647-00000000-0000-4000-8000-000000000005.tmp");
  fs.writeFileSync(orphan, "must not be traversed");
  try {
    fs.symlinkSync(target, link, process.platform === "win32" ? "junction" : "dir");
  } catch {
    t.skip("directory symlink creation is unavailable in this environment");
    return;
  }
  assert.equal(cleanupOrphanPrivateShareSnapshots(link), 0);
  assert.equal(fs.existsSync(orphan), true,
    "startup cleanup must not follow a symlink/junction to an unrelated directory");
});

test("bounded reader accepts regular files within the limit and rejects oversized files", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-bounded-file-size-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  fs.writeFileSync(filePath, "safe");

  assert.equal(readBoundedRegularFile(filePath, 4).contents.toString("utf8"), "safe");
  assert.throws(() => readBoundedRegularFile(filePath, 3), { code: "INVALID_INTERNAL_FILE" });
});

test("bounded reader rejects directories", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-bounded-file-types-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  assert.throws(() => readBoundedRegularFile(directory, 64), { code: "INVALID_INTERNAL_FILE" });
});

test("bounded reader rejects symlinks where supported", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-bounded-file-symlink-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const targetPath = path.join(directory, "target.json");
  const symlinkPath = path.join(directory, "link.json");
  fs.writeFileSync(targetPath, "safe");
  try {
    fs.symlinkSync(targetPath, symlinkPath);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
      t.skip(`symlinks unavailable: ${error.code}`);
      return;
    }
    throw error;
  }
  assert.throws(() => readBoundedRegularFile(symlinkPath, 64), { code: "INVALID_INTERNAL_FILE" });
});

test("bounded reader rejects a symlink substituted immediately before open without reading it", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-bounded-file-open-symlink-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  const outsidePath = path.join(directory, "outside.json");
  fs.writeFileSync(filePath, "safe");
  fs.writeFileSync(outsidePath, "outside");
  try {
    const probePath = path.join(directory, "probe");
    fs.symlinkSync(outsidePath, probePath);
    fs.unlinkSync(probePath);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP"].includes(error.code)) {
      t.skip(`symlinks unavailable: ${error.code}`);
      return;
    }
    throw error;
  }

  const originalOpenSync = fs.openSync;
  const originalReadSync = fs.readSync;
  let readCount = 0;
  let swapped = false;
  fs.openSync = function (target, ...args) {
    if (!swapped && path.resolve(String(target)) === path.resolve(filePath)) {
      swapped = true;
      fs.unlinkSync(filePath);
      fs.symlinkSync(outsidePath, filePath);
    }
    return originalOpenSync.call(this, target, ...args);
  };
  fs.readSync = function (...args) {
    readCount += 1;
    return originalReadSync.apply(this, args);
  };
  try {
    assert.throws(() => readBoundedRegularFile(filePath, 64), { code: "INVALID_INTERNAL_FILE" });
    assert.equal(swapped, true);
    assert.equal(readCount, 0);
  } finally {
    fs.openSync = originalOpenSync;
    fs.readSync = originalReadSync;
  }
});

test("bounded reader rejects path substitution during read", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-bounded-file-read-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  const displacedPath = path.join(directory, "displaced.json");
  const replacementPath = path.join(directory, "replacement.json");
  fs.writeFileSync(filePath, "safe");
  fs.writeFileSync(replacementPath, "other");
  const originalReadSync = fs.readSync;
  let swapped = false;
  fs.readSync = function (...args) {
    const count = originalReadSync.apply(this, args);
    if (!swapped && count > 0) {
      swapped = true;
      fs.renameSync(filePath, displacedPath);
      fs.renameSync(replacementPath, filePath);
    }
    return count;
  };
  try {
    assert.throws(() => readBoundedRegularFile(filePath, 64), { code: "INVALID_INTERNAL_FILE" });
    assert.equal(swapped, true);
  } finally {
    fs.readSync = originalReadSync;
  }
});

test("bounded reader returns the stat from the validated read snapshot", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-bounded-file-stat-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, "state.json");
  const contents = "original";
  fs.writeFileSync(filePath, contents);
  const originalStat = fs.statSync(filePath, { bigint: true });
  const changedTime = new Date("2040-01-01T00:00:00.000Z");
  const originalLstatSync = fs.lstatSync;
  let pathSnapshots = 0;
  let mutated = false;
  fs.lstatSync = function (target, ...args) {
    const stat = originalLstatSync.call(this, target, ...args);
    if (target === filePath && ++pathSnapshots === 2) {
      fs.writeFileSync(filePath, "mutated!");
      fs.utimesSync(filePath, changedTime, changedTime);
      mutated = true;
    }
    return stat;
  };
  try {
    const result = readBoundedRegularFile(filePath, 64);
    assert.equal(mutated, true);
    assert.equal(result.contents.toString("utf8"), contents);
    const changedStat = fs.statSync(filePath, { bigint: true });
    assert.equal(typeof result.stat.ino, "bigint");
    assert.equal(result.stat.size, originalStat.size);
    assert.equal(result.stat.mtimeNs, originalStat.mtimeNs);
    assert.notEqual(result.stat.mtimeNs, changedStat.mtimeNs);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});

test("identity-null cleanup without the original descriptor preserves the file and reservation", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-identity-unavailable-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000010.tmp`);
  fs.writeFileSync(cleanupPath, "must remain until identity is proven");
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 1, maxBytes: 1024 });
  const release = budget.reserve(Buffer.byteLength("must remain until identity is proven"));
  const originalLstatSync = fs.lstatSync;
  let pathLookups = 0;
  fs.lstatSync = function (target, ...args) {
    if (target === cleanupPath) pathLookups++;
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.equal(cleanupReadHandle({ cleanupPath, cleanupIdentity: null, cleanupCallback: release }), false);
    assert.equal(retryPendingPrivateShareSnapshotCleanup(), 0);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
  assert.equal(pathLookups, 0,
    "cleanup must not lstat and adopt a pathname when the original descriptor identity is unavailable");
  assert.equal(fs.existsSync(cleanupPath), true);
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: Buffer.byteLength("must remain until identity is proven") });
  assert.ok(getPrivateShareSnapshotCleanupState().identityUnproven >= 1,
    "the unresolved reservation must remain visible in cleanup telemetry");
});

test("identity-null pending cleanup never adopts identity from a different handle for the same path", (t) => {
  const earlierCleanup = getPrivateShareSnapshotCleanupState();
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-identity-cross-handle-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000011.tmp`);
  const replacementPath = path.join(directory, "replacement.tmp");
  const displacedPath = path.join(directory, "displaced-original.tmp");
  fs.writeFileSync(cleanupPath, "original authorized snapshot");
  fs.writeFileSync(replacementPath, "unrelated replacement snapshot");
  const replacementStat = fs.lstatSync(replacementPath, { bigint: true });
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 2, maxBytes: 1024 });
  const originalBytes = Buffer.byteLength("original authorized snapshot");
  const replacementBytes = Buffer.byteLength("unrelated replacement snapshot");
  const releaseOriginal = budget.reserve(originalBytes);
  const releaseReplacement = budget.reserve(replacementBytes);
  let replacementReleaseCalls = 0;
  const originalLstatSync = fs.lstatSync;
  let cleanupPathLookups = 0;
  fs.lstatSync = function (target, ...args) {
    if (target === cleanupPath) cleanupPathLookups++;
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.equal(cleanupReadHandle({ cleanupPath, cleanupIdentity: null,
      cleanupCallback: releaseOriginal }), false);
    assert.equal(cleanupPathLookups, 0,
      "the unproven original must not inspect or adopt its pathname");
    assert.equal(cleanupReadHandle({ cleanupPath,
      cleanupIdentity: { dev: replacementStat.dev, ino: replacementStat.ino },
      cleanupCallback: Object.assign(() => {
        replacementReleaseCalls++;
        releaseReplacement();
      }, {
        releaseActive: releaseReplacement.releaseActive,
      }) }), false);
    assert.deepEqual(budget.getState(), {
      active: 0, reservedBytes: originalBytes + replacementBytes,
    }, "independently owned snapshots retain both byte quotas and release active slots");
    assert.equal(getPrivateShareSnapshotCleanupState().pending >= 2, true,
      "different inodes at the same pathname must get distinct pending cleanup records");
    fs.renameSync(cleanupPath, displacedPath);
    fs.renameSync(replacementPath, cleanupPath);
    assert.equal(retryPendingPrivateShareSnapshotCleanup(), 1,
      "only the proven replacement inode may be cleaned and its own quota released");
  } finally { fs.lstatSync = originalLstatSync; }
  assert.equal(fs.existsSync(cleanupPath), false,
    "the matched replacement must be deleted after the identity-verified retry");
  assert.equal(fs.readFileSync(displacedPath, "utf8"), "original authorized snapshot",
    "the unproven original remains untouched even though another inode was removed");
  assert.equal(replacementReleaseCalls, 1,
    "the proven second reservation must be released exactly once");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: originalBytes },
    "only the still-unproven original reservation retains its byte quota");
  assert.equal(getPrivateShareSnapshotCleanupState().identityUnproven,
    earlierCleanup.identityUnproven + 1,
    "only the intentionally unproven original remains newly pending");
});

test("multiple reservations for a proven inode survive a failed rename and release once on retry", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-same-inode-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000012.tmp`);
  fs.writeFileSync(cleanupPath, "one proven inode");
  const identity = fs.lstatSync(cleanupPath, { bigint: true });
  const cleanupIdentity = { dev: identity.dev, ino: identity.ino };
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 2, maxBytes: 1024 });
  const bytes = Buffer.byteLength("one proven inode");
  const releaseFirst = budget.reserve(bytes);
  const releaseSecond = budget.reserve(bytes);
  const originalRename = fs.renameSync;
  let attemptedRenames = 0;
  fs.renameSync = function (from, destination) {
    if (from === cleanupPath) {
      attemptedRenames++;
      const error = new Error("simulated temporary directory rename denial");
      error.code = "EACCES";
      throw error;
    }
    return originalRename.call(this, from, destination);
  };
  try {
    assert.equal(cleanupReadHandle({ cleanupPath, cleanupIdentity,
      cleanupCallback: releaseFirst }), false);
    assert.equal(cleanupReadHandle({ cleanupPath, cleanupIdentity,
      cleanupCallback: releaseSecond }), false);
  } finally { fs.renameSync = originalRename; }
  assert.ok(attemptedRenames >= 2);
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: bytes * 2 },
    "a second verified reservation must not be discarded by the first pending cleanup");
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 1);
  assert.equal(fs.existsSync(cleanupPath), false);
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 },
    "one proven unlink releases both independently reserved byte quotas");
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 0);
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
});

test("a second owned descriptor for a pending inode must close independently", (t) => {
  const directory = fs.mkdtempSync(path.join(testTempDirectoryRoot(), "rootark-share-snapshot-two-fds-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const cleanupPath = path.join(directory,
    `rootark-share-egress-${process.pid}-00000000-0000-4000-8000-000000000013.tmp`);
  fs.writeFileSync(cleanupPath, "native handle custody");
  const fdFirst = fs.openSync(cleanupPath, "r");
  const fdSecond = fs.openSync(cleanupPath, "r");
  const stat = fs.fstatSync(fdFirst, { bigint: true });
  const secondStat = fs.fstatSync(fdSecond, { bigint: true });
  assert.equal(secondStat.dev, stat.dev);
  assert.equal(secondStat.ino, stat.ino);
  const identity = { dev: stat.dev, ino: stat.ino };
  const budget = createPrivateShareSnapshotBudget({ maxConcurrent: 2, maxBytes: 1024 });
  const bytes = stat.size;
  const releaseFirst = budget.reserve(Number(bytes));
  const releaseSecond = budget.reserve(Number(bytes));
  const originalRename = fs.renameSync;
  fs.renameSync = function (from, destination) {
    if (from === cleanupPath) {
      const error = new Error("simulate retryable rename failure");
      error.code = "EACCES";
      throw error;
    }
    return originalRename.call(this, from, destination);
  };
  try {
    assert.equal(cleanupReadHandle({ fd: fdFirst, fdOwned: true, fdIdentity: identity,
      cleanupPath, cleanupIdentity: identity, cleanupCallback: releaseFirst }), false);
    assert.equal(cleanupReadHandle({ fd: fdSecond, fdOwned: true, fdIdentity: identity,
      cleanupPath, cleanupIdentity: identity, cleanupCallback: releaseSecond }), false);
  } finally { fs.renameSync = originalRename; }
  assert.throws(() => fs.fstatSync(fdFirst), { code: "EBADF" });
  assert.throws(() => fs.fstatSync(fdSecond), { code: "EBADF" },
    "the second owned numeric fd must not be absorbed without being closed");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: Number(bytes) * 2 });
  assert.equal(retryPendingPrivateShareSnapshotCleanup(), 2,
    "both pending descriptors were proven closed; their byte quotas release after the inode is gone");
  assert.deepEqual(budget.getState(), { active: 0, reservedBytes: 0 });
});
