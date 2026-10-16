const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { ZipArchive } = require("archiver");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-archive-settlement-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupService = require("../services/backupService");
const backupRepository = require("../repositories/backupRepository");
const restoreProviderOrphans = require("../services/restoreProviderOrphans");

function reset() {
  fs.rmSync(path.join(runtime, "data"), { recursive: true, force: true });
  fs.rmSync(path.join(runtime, "uploads"), { recursive: true, force: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  fs.mkdirSync(backupService.BACKUPS_DIR, { recursive: true });
}

function archiveInput() {
  return { backup_id: "settlement", included_files: [] };
}

async function rejectFromArchiverError(archivePath) {
  const originalFinalize = ZipArchive.prototype.finalize;
  ZipArchive.prototype.finalize = function finalizeWithError() {
    process.nextTick(() => this.emit("error", Object.assign(new Error("archive failed"), { code: "ARCHIVER_FAILED" })));
    return Promise.resolve();
  };
  let error;
  try {
    await backupService.createZipArchive(archivePath, archiveInput(), []);
  } catch (caught) {
    error = caught;
  } finally {
    ZipArchive.prototype.finalize = originalFinalize;
  }
  assert.equal(error?.code, "ARCHIVER_FAILED");
  return error;
}

test("archive failure settles the pipeline before owned cleanup", async (t) => {
  await t.test("Archiver failure removes only the owned archive", async () => {
    reset();
    const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-01-01-00-00-00.zip");
    await rejectFromArchiverError(archivePath);
    assert.equal(fs.existsSync(archivePath), false);
  });

  await t.test("output failure preserves the primary error and has no late close event", async () => {
    reset();
    const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-01-01-00-00-01.zip");
    const originalCreateWriteStream = fs.createWriteStream;
    let stream;
    let rejected = false;
    let lateClose = false;
    fs.createWriteStream = (...args) => {
      stream = originalCreateWriteStream(...args);
      stream.on("close", () => { if (rejected) lateClose = true; });
      process.nextTick(() => stream.emit("error", Object.assign(new Error("output failed"), { code: "OUTPUT_FAILED" })));
      return stream;
    };
    try {
      await assert.rejects(backupService.createZipArchive(archivePath, archiveInput(), []), { code: "OUTPUT_FAILED" });
      rejected = true;
      await new Promise((resolve) => setImmediate(resolve));
    } finally {
      fs.createWriteStream = originalCreateWriteStream;
    }
    assert.equal(lateClose, false);
    assert.equal(fs.existsSync(archivePath), false);
  });

  await t.test("output failure destroys an active verified source stream", async () => {
    reset();
    const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-01-01-00-00-04.zip");
    const sourcePath = path.join(runtime, "uploads", "pending.bin");
    fs.writeFileSync(sourcePath, "source data");
    const originalCreateReadStream = fs.createReadStream;
    const originalCreateWriteStream = fs.createWriteStream;
    let source;
    let notifySourceOpened;
    let notifySourceClosed;
    const sourceOpened = new Promise((resolve) => { notifySourceOpened = resolve; });
    const sourceClosed = new Promise((resolve) => { notifySourceClosed = resolve; });
    fs.createReadStream = (...args) => {
      source = originalCreateReadStream(...args);
      source.pause();
      source.once("close", notifySourceClosed);
      notifySourceOpened();
      return source;
    };
    fs.createWriteStream = (...args) => {
      const output = originalCreateWriteStream(...args);
      void sourceOpened.then(() => process.nextTick(() => {
        output.emit("error", Object.assign(new Error("output failed during source read"), { code: "OUTPUT_FAILED" }));
      }));
      return output;
    };
    try {
      await assert.rejects(backupService.createZipArchive(archivePath, archiveInput(), [
        { absolutePath: sourcePath, entryPath: "uploads/pending.bin" },
      ]), { code: "OUTPUT_FAILED" });
      await sourceClosed;
    } finally {
      fs.createReadStream = originalCreateReadStream;
      fs.createWriteStream = originalCreateWriteStream;
    }
    assert.equal(source?.destroyed, true);
    assert.equal(source?.closed, true);
    assert.equal(fs.existsSync(archivePath), false);
  });

  await t.test("Windows-style cleanup retries do not replace the primary error", async () => {
    reset();
    const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-01-01-00-00-02.zip");
    const originalRmSync = fs.rmSync;
    let attempts = 0;
    fs.rmSync = (target, options) => {
      if (path.resolve(target) === path.resolve(archivePath)) {
        attempts += 1;
        if (attempts < 3) throw Object.assign(new Error("busy"), { code: "EBUSY" });
      }
      return originalRmSync(target, options);
    };
    try { await rejectFromArchiverError(archivePath); } finally { fs.rmSync = originalRmSync; }
    assert.equal(attempts, 3);
    assert.equal(fs.existsSync(archivePath), false);
  });

  await t.test("persistent cleanup failure remains attached without masking the primary error", async () => {
    reset();
    const archivePath = path.join(backupService.BACKUPS_DIR, "rootark-backup-2026-01-01-00-00-03.zip");
    const originalRmSync = fs.rmSync;
    fs.rmSync = (target, options) => {
      if (path.resolve(target) === path.resolve(archivePath)) throw Object.assign(new Error("permission denied"), { code: "EPERM" });
      return originalRmSync(target, options);
    };
    let error;
    try { error = await rejectFromArchiverError(archivePath); } finally { fs.rmSync = originalRmSync; }
    assert.equal(error.code, "ARCHIVER_FAILED");
    assert.equal(error.cleanupError.code, "EPERM");
    assert.equal(fs.existsSync(archivePath), true);
    originalRmSync(archivePath, { force: true });
  });
});

test("history failure is not reported as archive failure", async () => {
  reset();
  const originalSaveBackup = backupRepository.saveBackup;
  let calls = 0;
  backupRepository.saveBackup = (entry) => {
    calls += 1;
    if (calls === 1) throw new Error("history write failed");
    return originalSaveBackup(entry);
  };
  try {
    await assert.rejects(backupService.createBackup(), { message: "history write failed" });
  } finally {
    backupRepository.saveBackup = originalSaveBackup;
  }
  assert.equal(calls, 2);
  assert.equal(fs.readdirSync(backupService.BACKUPS_DIR).some((name) => name.endsWith(".zip")), false);
});

test("post-rename history durability failure preserves the archive if failed-history recovery also fails", async () => {
  reset();
  const historyPath = path.join(runtime, "data", "backup-history.json");
  const historyDirectory = path.dirname(historyPath);
  const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
  const originalOpenSync = fs.openSync;
  const originalFsyncSync = fs.fsyncSync;
  const originalCloseSync = fs.closeSync;
  const fakeDirectoryDescriptors = new Map();
  let nextFakeDescriptor = 0x7fff0000;
  let historyTemporaryOpens = 0;

  Object.defineProperty(process, "platform", { ...originalPlatform, value: "linux" });
  fs.openSync = function openWithInjectedRecoveryFailure(target, flags, ...rest) {
    const targetPath = String(target);
    if (targetPath.startsWith(`${historyPath}.`) && targetPath.endsWith(".tmp")) {
      historyTemporaryOpens += 1;
      if (historyTemporaryOpens === 2) {
        throw Object.assign(new Error("injected failed-history temp open error"), { code: "EIO" });
      }
    }
    try {
      if (fs.statSync(targetPath).isDirectory()) {
        const descriptor = nextFakeDescriptor++;
        fakeDirectoryDescriptors.set(descriptor, targetPath);
        return descriptor;
      }
    } catch {}
    return originalOpenSync.call(this, target, flags, ...rest);
  };
  fs.fsyncSync = function failHistoryDirectorySync(descriptor) {
    if (fakeDirectoryDescriptors.get(descriptor) === historyDirectory) {
      throw Object.assign(new Error("injected history directory fsync error"), { code: "EIO" });
    }
    if (fakeDirectoryDescriptors.has(descriptor)) return;
    return originalFsyncSync.call(this, descriptor);
  };
  fs.closeSync = function closeFakeDirectory(descriptor) {
    if (fakeDirectoryDescriptors.has(descriptor)) return;
    return originalCloseSync.call(this, descriptor);
  };

  let failure;
  try {
    await backupService.createBackup();
  } catch (error) {
    failure = error;
  } finally {
    fs.openSync = originalOpenSync;
    fs.fsyncSync = originalFsyncSync;
    fs.closeSync = originalCloseSync;
    Object.defineProperty(process, "platform", originalPlatform);
  }

  assert.equal(historyTemporaryOpens, 1, "the post-rename failure must not attempt a second history replacement");
  assert.equal(failure?.code, "EIO");
  const visibleSuccess = backupRepository.listBackups().find((entry) => entry.status === "success");
  assert.ok(visibleSuccess, "the first history rename remains visible after directory fsync fails");
  assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, visibleSuccess.filename)), true,
    "a visible success history row must never be left without its archive");
  assert.equal(failure.backupOperationState, "created-history-durability-uncertain");
});

test("retention failure preserves a backup whose success history is already committed", async () => {
  reset();
  const historyPath = path.join(runtime, "data", "backup-history.json");
  const originalAcquireInventoryLock = restoreProviderOrphans.acquireInventoryLock;
  const originalOpenSync = fs.openSync;
  let historyTemporaryOpens = 0;
  restoreProviderOrphans.acquireInventoryLock = async () => {
    throw Object.assign(new Error("injected retention lock failure"), { code: "RETENTION_LOCK_FAILED" });
  };
  fs.openSync = function failFallbackHistoryWrite(target, flags, ...rest) {
    const targetPath = String(target);
    if (targetPath.startsWith(`${historyPath}.`) && targetPath.endsWith(".tmp")) {
      historyTemporaryOpens += 1;
      if (historyTemporaryOpens === 2) {
        throw Object.assign(new Error("injected failed-history temp open error"), { code: "EIO" });
      }
    }
    return originalOpenSync.call(this, target, flags, ...rest);
  };

  let failure;
  try {
    await backupService.createBackup();
  } catch (error) {
    failure = error;
  } finally {
    restoreProviderOrphans.acquireInventoryLock = originalAcquireInventoryLock;
    fs.openSync = originalOpenSync;
  }

  assert.equal(failure?.code, "RETENTION_LOCK_FAILED");
  assert.equal(historyTemporaryOpens, 1, "committed success history must not be rewritten as a failed backup");
  const visibleSuccess = backupRepository.listBackups().find((entry) => entry.status === "success");
  assert.ok(visibleSuccess);
  assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, visibleSuccess.filename)), true,
    "retention maintenance failure must not remove an already-created backup");
  assert.equal(failure.backup.id, visibleSuccess.id);
  assert.equal(failure.backupOperationState, "created-post-processing-failed");
  assert.match(failure.message, /Backup was created/);
});

test("staging cleanup failure keeps created backup visible and returns a safe partial outcome", async () => {
  reset();
  const stageRoot = path.join(backupService.BACKUPS_DIR, ".cloud-stage");
  const originalRmSync = fs.rmSync;
  let stagePath = null;
  let failure = null;
  fs.rmSync = function failStageCleanup(target, options) {
    if (!stagePath && typeof target === "string" && path.dirname(path.resolve(target)) === stageRoot) {
      stagePath = path.resolve(target);
      fs.mkdirSync(stagePath, { recursive: true });
      fs.writeFileSync(path.join(stagePath, "private-fixture.txt"), "disposable staging fixture");
      throw Object.assign(new Error(`EACCES: permission denied, removing '${stagePath}'`), { code: "EACCES" });
    }
    return originalRmSync.call(this, target, options);
  };

  try {
    await backupService.createBackup();
  } catch (error) {
    failure = error;
  } finally {
    fs.rmSync = originalRmSync;
    if (stagePath) originalRmSync(stagePath, { recursive: true, force: true });
    try { originalRmSync(stageRoot, { recursive: true, force: true }); } catch {}
  }

  const created = backupRepository.listBackups().find((entry) => entry.status === "success");
  assert.ok(created, "the archive and successful history row remain committed");
  assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, created.filename)), true);
  assert.equal(failure?.backup?.id, created.id);
  assert.equal(failure?.backupHistoryState, "durable");
  assert.equal(failure?.backupOperationState, "created-post-processing-failed");
  assert.equal(failure?.code, "BACKUP_STAGE_CLEANUP_FAILED");
  assert.equal(failure.message.includes(stagePath), false, "local staging paths are not exposed in the outcome");
});

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
