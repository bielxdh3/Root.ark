const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { createFileLifecycleLock } = require("../services/fileLifecycleLock");

function findAbsentPid() {
  for (let candidate = 2_147_000_000, attempts = 0; candidate > 1_000_000 && attempts < 4096; candidate -= 1, attempts += 1) {
    try {
      process.kill(candidate, 0);
    } catch (error) {
      if (error.code === "ESRCH") return candidate;
      if (error.code === "EPERM" || error.code === "EACCES") continue;
      throw error;
    }
  }
  throw new Error("Could not find a provably absent process id for the disposable lock fixture");
}

test("file lifecycle lock serializes the same file and permits reentrant work", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  let signalFirstStarted;
  let releaseFirst;
  const firstStarted = new Promise((resolve) => { signalFirstStarted = resolve; });
  const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
  let secondStarted = false;

  const first = lock.run("root", "same.txt", async () => {
    signalFirstStarted();
    await firstGate;
    return lock.run("root", "same.txt", async () => "nested work");
  });
  await firstStarted;
  const second = lock.run("root", "same.txt", async () => { secondStarted = true; return "second work"; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(secondStarted, false);
  releaseFirst();
  assert.equal(await first, "nested work");
  assert.equal(await second, "second work");
  assert.equal(secondStarted, true);
});

test("detached lifecycle work clears inherited lock ownership and reacquires before entering", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-detached-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  let releaseOuter;
  let signalOuter;
  let secondStarted = false;
  const outerGate = new Promise((resolve) => { releaseOuter = resolve; });
  const outerEntered = new Promise((resolve) => { signalOuter = resolve; });
  let detachedTask;

  const outer = lock.run("root", "same.txt", async () => {
    signalOuter();
    setImmediate(() => {
      detachedTask = lock.runDetached(() => lock.run("root", "same.txt", async () => { secondStarted = true; }));
    });
    await outerGate;
  });
  await outerEntered;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(secondStarted, false, "detached work must not inherit the outer operation's held-lock marker");
  releaseOuter();
  await outer;
  await detachedTask;
  assert.equal(secondStarted, true, "detached work reacquires the lock after the original owner releases it");
});

test("file lifecycle lock follows filesystem case sensitivity for file-name aliases", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-case-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  let releaseFirst;
  let signalFirst;
  let signalSecond;
  const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
  const firstEntered = new Promise((resolve) => { signalFirst = resolve; });
  const secondEntered = new Promise((resolve) => { signalSecond = resolve; });
  let secondStarted = false;

  const runFile = (fileName, work) => lock.runAcrossFolders([], "root", fileName, work);
  const first = runFile("Report.txt", async () => {
    signalFirst();
    await firstGate;
  });
  await firstEntered;
  const second = runFile("report.txt", async () => {
    secondStarted = true;
    signalSecond();
  });

  if (process.platform === "win32") {
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(secondStarted, false, "case aliases must share a lock on case-insensitive filesystems");
  } else {
    await secondEntered;
    assert.equal(secondStarted, true, "case-distinct names must retain separate locks on POSIX filesystems");
  }

  releaseFirst();
  await Promise.all([first, second]);
});

test("file lifecycle lock fails closed on an existing owner and never steals it", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-stale-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 20, pollMs: 5 });
  const identityHash = crypto.createHash("sha256").update("root\0stale.txt").digest("hex");
  const lockPath = path.join(directory, `${identityHash}.lock`);
  fs.writeFileSync(lockPath, JSON.stringify({ token: "preserved-owner", pid: 999999, hostname: "unknown", createdAt: new Date(0).toISOString() }), { flag: "wx" });

  await assert.rejects(lock.run("root", "stale.txt", async () => assert.fail("stale lock must not enter protected work")), { code: "FILE_LIFECYCLE_LOCK_TIMEOUT" });
  assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).token, "preserved-owner", "potentially stale owner is preserved for operator recovery");
});

test("file lifecycle lock cleans an incomplete temporary owner record after a write failure", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-partial-owner-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  const lockPath = path.join(directory, `${crypto.createHash("sha256").update("folder:root").digest("hex")}.lock`);
  const originalWriteFileSync = fs.writeFileSync;
  let injected = false;
  fs.writeFileSync = function (target, data, ...args) {
    if (!injected && typeof target === "number" && String(data).includes('"createdAt"')) {
      injected = true;
      originalWriteFileSync.call(this, target, '{"token":"incomplete-owner"', ...args);
      const error = new Error("injected lifecycle owner write failure");
      error.code = "EIO";
      throw error;
    }
    return originalWriteFileSync.call(this, target, data, ...args);
  };
  try {
    await assert.rejects(lock.runFolder("root", async () => assert.fail("incomplete lock owner must not enter protected work")), { code: "FILE_LIFECYCLE_LOCK_UNAVAILABLE" });
  } finally {
    fs.writeFileSync = originalWriteFileSync;
  }

  assert.equal(injected, true, "the owner-record write failure was injected after exclusive file creation");
  assert.equal(fs.existsSync(lockPath), false, "failed acquisition does not publish a malformed lock path");
  assert.equal(fs.readdirSync(directory).some((name) => name.endsWith(".tmp")), false, "failed acquisition removes its incomplete temporary owner record");
  assert.equal(await lock.runFolder("root", async () => "recovered"), "recovered", "a later operation can acquire the same folder lock");
  assert.equal(fs.existsSync(lockPath), false, "the recovered operation releases its lock normally");
});

test("process interruption during lock initialization cannot publish a partial owner file", { timeout: 10_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-interrupted-init-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }));
  const markerPath = path.join(directory, "owner-write-paused");
  const lockPath = path.join(directory, `${crypto.createHash("sha256").update("folder:root").digest("hex")}.lock`);
  const childSource = [
    'const fs = require("node:fs");',
    `const marker = ${JSON.stringify(markerPath)};`,
    'const originalWrite = fs.writeFileSync;',
    `fs.writeFileSync = function (target, data, ...args) { if (typeof target === "number" && String(data).includes(${JSON.stringify('"createdAt"')})) { originalWrite.call(this, target, ${JSON.stringify('{"token":"partial-before-crash"')}); originalWrite.call(this, marker, "paused"); const wait = new Int32Array(new SharedArrayBuffer(4)); while (true) Atomics.wait(wait, 0, 0, 1000); } return originalWrite.call(this, target, data, ...args); };`,
    `const { createFileLifecycleLock } = require(${JSON.stringify(path.resolve(__dirname, "../services/fileLifecycleLock.js"))});`,
    `createFileLifecycleLock({ directory: ${JSON.stringify(directory)}, timeoutMs: 5000 }).runFolder("root", async () => { throw new Error("interrupted owner must not enter protected work"); }).catch(() => {});`,
  ].join("\n");
  const childPath = path.join(directory, "interrupt-lock-init.cjs");
  fs.writeFileSync(childPath, childSource);
  const child = spawn(process.execPath, [childPath], { stdio: "ignore", windowsHide: true });
  let exited = false;
  child.once("exit", () => { exited = true; });
  t.after(async () => {
    if (!exited) child.kill();
    if (!exited) await new Promise((resolve) => child.once("exit", resolve));
  });

  const deadline = Date.now() + 5000;
  while (!fs.existsSync(markerPath) && !exited && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  try {
    assert.equal(fs.existsSync(markerPath), true, "the child reached the owner-record write boundary");
    assert.equal(fs.existsSync(lockPath), false, "the final lock path is not visible before its complete owner record is published");
  } finally {
    if (!exited) child.kill();
    if (!exited) await new Promise((resolve) => child.once("exit", resolve));
  }

  assert.equal(fs.existsSync(lockPath), false, "interrupting initialization leaves no blocking lock path");
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  assert.equal(await lock.runFolder("root", async () => "recovered"), "recovered", "a later process can acquire the folder lock after interruption");
  assert.equal(fs.readdirSync(directory).some((name) => name.endsWith(".tmp")), false, "a later process removes the dead owner's partial temporary record");
});

test("file lifecycle lock reclaims a valid owner after abrupt same-host process death", { timeout: 10_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-interrupted-owner-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }));
  const markerPath = path.join(directory, "owner-work-started");
  const lockPath = path.join(directory, `${crypto.createHash("sha256").update("folder:root").digest("hex")}.lock`);
  const childSource = [
    'const fs = require("node:fs");',
    `const marker = ${JSON.stringify(markerPath)};`,
    `const { createFileLifecycleLock } = require(${JSON.stringify(path.resolve(__dirname, "../services/fileLifecycleLock.js"))});`,
    `createFileLifecycleLock({ directory: ${JSON.stringify(directory)}, timeoutMs: 5000 }).runFolder("root", async () => { fs.writeFileSync(marker, String(process.pid)); const wait = new Int32Array(new SharedArrayBuffer(4)); while (true) Atomics.wait(wait, 0, 0, 1000); }).catch(() => {});`,
  ].join("\n");
  const childPath = path.join(directory, "hold-published-lock.cjs");
  fs.writeFileSync(childPath, childSource);
  const child = spawn(process.execPath, [childPath], { stdio: "ignore", windowsHide: true });
  let exited = false;
  child.once("exit", () => { exited = true; });
  t.after(async () => {
    if (!exited) child.kill();
    if (!exited) await new Promise((resolve) => child.once("exit", resolve));
  });

  const deadline = Date.now() + 5000;
  while (!fs.existsSync(markerPath) && !exited && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  try {
    assert.equal(fs.existsSync(markerPath), true, "the child entered the protected work while holding the published lock");
    const owner = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    assert.equal(owner.pid, child.pid, "the lock records the actual child process owner");
    assert.equal(owner.hostname, os.hostname(), "the owner record is scoped to this host");
  } finally {
    if (!exited) child.kill();
    if (!exited) await new Promise((resolve) => child.once("exit", resolve));
  }

  assert.equal(fs.existsSync(lockPath), true, "abrupt process death leaves the published lease for liveness-checked recovery");
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  assert.equal(await lock.runFolder("root", async () => "recovered"), "recovered", "a later process reclaims the proven-dead same-host owner");
  assert.equal(fs.existsSync(lockPath), false, "recovery releases the dead owner's lock path");
});

test("file lifecycle lock reclaims only a provably dead same-host owner", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-dead-owner-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 5_000, pollMs: 5 });
  const identityHash = crypto.createHash("sha256").update("root\0dead-owner.txt").digest("hex");
  const lockPath = path.join(directory, `${identityHash}.lock`);
  fs.writeFileSync(lockPath, JSON.stringify({ token: "dead-owner", pid: findAbsentPid(), hostname: os.hostname(), createdAt: new Date(0).toISOString() }), { flag: "wx" });

  assert.equal(await lock.run("root", "dead-owner.txt", async () => "reclaimed"), "reclaimed");
  assert.equal(fs.existsSync(lockPath), false);
});

test("file lifecycle lock fails closed on a stranded reaper until an operator removes that exact stale marker", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-stale-reaper-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 20, pollMs: 5 });
  const lockPath = path.join(directory, `${crypto.createHash("sha256").update("root\0stale-reaper.txt").digest("hex")}.lock`);
  const reaperPath = `${lockPath}.reaper`;
  const deadPid = findAbsentPid();
  const deadOwner = { token: "dead-owner", pid: deadPid, hostname: os.hostname(), createdAt: new Date(0).toISOString() };
  const deadReaper = { token: "interrupted-reaper", pid: deadPid, hostname: os.hostname() };
  fs.writeFileSync(lockPath, JSON.stringify(deadOwner), { flag: "wx" });
  fs.writeFileSync(reaperPath, JSON.stringify(deadReaper), { flag: "wx" });

  await assert.rejects(lock.run("root", "stale-reaper.txt", async () => assert.fail("a stranded reaper must keep protected work closed")), { code: "FILE_LIFECYCLE_LOCK_TIMEOUT" });
  assert.deepEqual(JSON.parse(fs.readFileSync(lockPath, "utf8")), deadOwner, "the dead owner's lock remains available for safe operator recovery");
  assert.deepEqual(JSON.parse(fs.readFileSync(reaperPath, "utf8")), deadReaper, "the reaper marker is not automatically stolen");

  // Disposable fixture: this models the documented operator action after all
  // processes sharing the lock directory have been stopped and both PIDs checked.
  fs.unlinkSync(reaperPath);
  const recoveryLock = createFileLifecycleLock({ directory, timeoutMs: 5_000, pollMs: 5 });
  assert.equal(await recoveryLock.run("root", "stale-reaper.txt", async () => "recovered"), "recovered");
  assert.equal(fs.existsSync(lockPath), false);
  assert.equal(fs.existsSync(reaperPath), false);
});

test("file lifecycle lock release does not remove a replacement owner lease", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-owner-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000 });
  const identityHash = crypto.createHash("sha256").update("root\0owner.txt").digest("hex");
  const lockPath = path.join(directory, `${identityHash}.lock`);

  await lock.run("root", "owner.txt", async () => {
    fs.writeFileSync(lockPath, JSON.stringify({ token: "replacement-owner" }));
  });
  assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).token, "replacement-owner");
});

test("file lifecycle release preserves a same-token lease replaced during ownership validation", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-release-race-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000 });
  const lockPath = path.join(directory, crypto.createHash("sha256").update("root\0release-race.txt").digest("hex") + ".lock");
  const replacementPath = path.join(directory, "replacement-lease.json");
  const originalLstatSync = fs.lstatSync;
  let pathChecks = 0;
  let replacement;
  fs.lstatSync = function (target, ...args) {
    if (target === lockPath && ++pathChecks === 2) {
      replacement = fs.readFileSync(lockPath, "utf8");
      fs.writeFileSync(replacementPath, replacement);
      fs.renameSync(lockPath, lockPath + ".displaced");
      fs.renameSync(replacementPath, lockPath);
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    await lock.run("root", "release-race.txt", async () => {});
    assert.equal(pathChecks >= 2, true);
    assert.equal(JSON.parse(fs.readFileSync(lockPath, "utf8")).token.length > 0, true);
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});

test("file lifecycle lock refuses symlinked owner records without touching their targets", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-symlink-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 20, pollMs: 5 });
  const lockPath = path.join(directory, `${crypto.createHash("sha256").update("root\0linked.txt").digest("hex")}.lock`);
  const targetPath = path.join(directory, "outside-owner.json");
  const target = JSON.stringify({ token: "protected", pid: 999999, hostname: require("node:os").hostname() });
  fs.writeFileSync(targetPath, target);
  try {
    fs.symlinkSync(targetPath, lockPath);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip(`symlink creation unavailable: ${error.code}`);
    throw error;
  }

  await assert.rejects(lock.run("root", "linked.txt", async () => assert.fail("a linked owner record must never be reclaimed")), { code: "FILE_LIFECYCLE_LOCK_TIMEOUT" });
  assert.equal(fs.readFileSync(targetPath, "utf8"), target);
  assert.equal(fs.lstatSync(lockPath).isSymbolicLink(), true);
});

test("file lifecycle lock does not reclaim an owner replaced after its descriptor opens", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-lock-path-swap-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 30, pollMs: 5 });
  const lockPath = path.join(directory, `${crypto.createHash("sha256").update("root\0swapped.txt").digest("hex")}.lock`);
  const replacementPath = path.join(directory, "replacement-owner.json");
  fs.writeFileSync(lockPath, JSON.stringify({ token: "initial-dead-owner", pid: findAbsentPid(), hostname: os.hostname() }));
  const replacement = JSON.stringify({ token: "replacement-owner", pid: process.pid, hostname: require("node:os").hostname() });
  fs.writeFileSync(replacementPath, replacement);
  const originalLstatSync = fs.lstatSync;
  const originalOpenSync = fs.openSync;
  const calls = [];
  let swapped = false;
  fs.openSync = function (target, flags, ...args) {
    if (target === lockPath && typeof flags === "number") calls.push("read-open");
    return originalOpenSync.call(this, target, flags, ...args);
  };
  fs.lstatSync = function (target, ...args) {
    if (target === lockPath && !swapped) {
      calls.push("lstat");
      swapped = true;
      fs.renameSync(lockPath, `${lockPath}.displaced`);
      fs.renameSync(replacementPath, lockPath);
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    await assert.rejects(lock.run("root", "swapped.txt", async () => assert.fail("replaced owner must not be reclaimed")), { code: "FILE_LIFECYCLE_LOCK_TIMEOUT" });
    assert.equal(swapped, true);
    assert.equal(calls[0], "read-open", "the owner record must be opened before its path is validated");
    assert.equal(fs.readFileSync(lockPath, "utf8"), replacement);
  } finally {
    fs.lstatSync = originalLstatSync;
    fs.openSync = originalOpenSync;
  }
});

test("folder lifecycle lock serializes every trash action for the same stable folder id", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-folder-lock-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  let releaseRestore;
  let restoreStarted;
  const restoreGate = new Promise((resolve) => { releaseRestore = resolve; });
  const restoreEntered = new Promise((resolve) => { restoreStarted = resolve; });
  const restore = lock.runFolder("folder-123", async () => {
    restoreStarted();
    await restoreGate;
    return "restored";
  });
  await restoreEntered;
  let deleteStarted = false;
  let fileStarted = false;
  const deletion = lock.runFolder("folder-123", async () => { deleteStarted = true; return "deleted"; });
  const fileOperation = lock.run("folder-123", "during-restore.txt", async () => { fileStarted = true; return "file operation"; });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(deleteStarted, false, "a second process-level trash action for the same folder must wait for restore");
  assert.equal(fileStarted, false, "file cache and trash operations in a folder must wait while the folder itself changes lifecycle state");
  releaseRestore();
  assert.equal(await restore, "restored");
  assert.equal(await deletion, "deleted");
  assert.equal(await fileOperation, "file operation");
  assert.equal(deleteStarted, true);
  assert.equal(fileStarted, true);
});

test("cross-folder move locks both folders in a stable order", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-move-lock-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const lock = createFileLifecycleLock({ directory, timeoutMs: 1000, pollMs: 5 });
  let releaseDestination;
  let destinationStarted;
  const destinationGate = new Promise((resolve) => { releaseDestination = resolve; });
  const destinationEntered = new Promise((resolve) => { destinationStarted = resolve; });
  const deletion = lock.runFolder("destination", async () => {
    destinationStarted();
    await destinationGate;
  });
  await destinationEntered;
  let moveStarted = false;
  const move = lock.runAcrossFolders(["source", "destination"], "source", "moving.txt", async () => {
    moveStarted = true;
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(moveStarted, false, "a move must wait for lifecycle changes in its destination folder");
  releaseDestination();
  await deletion;
  await move;
  assert.equal(moveStarted, true);

  await Promise.all([
    lock.runAcrossFolders(["z-folder", "a-folder"], "z-folder", "left.txt", async () => "left"),
    lock.runAcrossFolders(["a-folder", "z-folder"], "a-folder", "right.txt", async () => "right"),
  ]);
});
