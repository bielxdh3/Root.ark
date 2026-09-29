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

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
