const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

test("pre-image copy preserves a pre-existing destination when exclusive staging fails", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preimage-copy-runtime-"));
  const source = path.join(runtime, "source.bin");
  const destination = path.join(runtime, "destination.bin");
  fs.writeFileSync(source, "source bytes");
  fs.writeFileSync(destination, "preserve existing bytes");
  try {
    const preimage = require("../services/restorePreimage");
    assert.throws(() => preimage.copyVerifiedFile(source, destination), { code: "EEXIST" });
    assert.equal(fs.readFileSync(destination, "utf8"), "preserve existing bytes");
  } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
});

test("pre-image copy rejects a source replaced after open but before path validation", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preimage-open-race-runtime-"));
  const source = path.join(runtime, "source.bin");
  const replacement = path.join(runtime, "replacement.bin");
  const displaced = path.join(runtime, "displaced.bin");
  const destination = path.join(runtime, "staged.bin");
  fs.writeFileSync(source, "opened bytes");
  fs.writeFileSync(replacement, "replacement bytes");
  const originalOpenSync = fs.openSync;
  const originalLstatSync = fs.lstatSync;
  let sourceOpened = false;
  let validatedAfterOpen = false;
  fs.openSync = function (pathname, ...args) {
    if (pathname === source) sourceOpened = true;
    return originalOpenSync.call(this, pathname, ...args);
  };
  fs.lstatSync = function (pathname, ...args) {
    if (pathname === source && sourceOpened && !validatedAfterOpen) {
      validatedAfterOpen = true;
      fs.renameSync(source, displaced);
      fs.renameSync(replacement, source);
    }
    return originalLstatSync.call(this, pathname, ...args);
  };
  try {
    const preimage = require("../services/restorePreimage");
    assert.throws(() => preimage.copyVerifiedFile(source, destination), /changed while opening/);
    assert.equal(validatedAfterOpen, true, "the pathname must be checked after its descriptor is opened");
    assert.equal(fs.existsSync(destination), false, "changed source must be rejected before staging bytes");
    assert.equal(fs.readFileSync(displaced, "utf8"), "opened bytes");
    assert.equal(fs.readFileSync(source, "utf8"), "replacement bytes");
  } finally {
    fs.openSync = originalOpenSync;
    fs.lstatSync = originalLstatSync;
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("tree hashing rejects a source replaced after open before staging it", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preimage-tree-open-race-runtime-"));
  const treeRoot = path.join(runtime, "tree");
  const source = path.join(treeRoot, "entry.txt");
  const replacement = path.join(runtime, "replacement.txt");
  const displaced = path.join(runtime, "displaced.txt");
  const snapshotRoot = path.join(runtime, "snapshot");
  fs.mkdirSync(treeRoot);
  fs.writeFileSync(source, "opened bytes");
  fs.writeFileSync(replacement, "replacement bytes");
  const originalOpenSync = fs.openSync;
  let sourceOpened = false;
  fs.openSync = function (pathname, ...args) {
    const fd = originalOpenSync.call(this, pathname, ...args);
    if (pathname === source && !sourceOpened) {
      sourceOpened = true;
      fs.renameSync(source, displaced);
      fs.renameSync(replacement, source);
    }
    return fd;
  };
  try {
    const preimage = require("../services/restorePreimage");
    assert.throws(() => preimage.snapshotTree(treeRoot, snapshotRoot), /file changed while opening/);
    assert.equal(sourceOpened, true);
    assert.equal(fs.existsSync(path.join(snapshotRoot, "entry.txt")), false);
    assert.equal(fs.readFileSync(displaced, "utf8"), "opened bytes");
    assert.equal(fs.readFileSync(source, "utf8"), "replacement bytes");
  } finally {
    fs.openSync = originalOpenSync;
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("pre-image copy and tree hashing reject FIFO sources without blocking", (t) => {
  if (process.platform === "win32" || typeof fs.constants.O_NONBLOCK !== "number") {
    t.skip("FIFO or O_NONBLOCK is unavailable");
    return;
  }
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preimage-fifo-runtime-"));
  const copyFifo = path.join(runtime, "copy.fifo");
  const copyDestination = path.join(runtime, "copy-staged.bin");
  const treeRoot = path.join(runtime, "tree");
  const treeFile = path.join(treeRoot, "entry.txt");
  const replacementFifo = path.join(runtime, "replacement.fifo");
  const displaced = path.join(runtime, "displaced.txt");
  const snapshotRoot = path.join(runtime, "snapshot");
  try {
    fs.mkdirSync(treeRoot);
    fs.writeFileSync(treeFile, "tree source");
    const fifo = spawnSync("mkfifo", [copyFifo, replacementFifo], { encoding: "utf8" });
    if (fifo.error?.code === "ENOENT") {
      t.skip("mkfifo is unavailable");
      return;
    }
    assert.equal(fifo.status, 0, fifo.stderr || fifo.stdout);
    const preimagePath = path.resolve(__dirname, "../services/restorePreimage.js");
    const script = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const preimage = require(${JSON.stringify(preimagePath)});
      const [copyFifo, copyDestination, treeFile, replacementFifo, displaced, treeRoot, snapshotRoot] = process.argv.slice(1);
      assert.throws(() => preimage.copyVerifiedFile(copyFifo, copyDestination), /source is aliased or invalid/);
      assert.equal(fs.existsSync(copyDestination), false);
      const originalOpenSync = fs.openSync;
      let swapped = false;
      fs.openSync = function (pathname, ...args) {
        if (pathname === treeFile && !swapped) {
          swapped = true;
          fs.renameSync(treeFile, displaced);
          fs.renameSync(replacementFifo, treeFile);
        }
        return originalOpenSync.call(this, pathname, ...args);
      };
      try {
        assert.throws(() => preimage.snapshotTree(treeRoot, snapshotRoot), /file is aliased or invalid/);
      } finally { fs.openSync = originalOpenSync; }
      assert.equal(swapped, true, "the tree entry must be replaced after lstat and before open");
      assert.equal(fs.existsSync(path.join(snapshotRoot, "entry.txt")), false);
    `;
    const result = spawnSync(process.execPath, ["-e", script, copyFifo, copyDestination, treeFile, replacementFifo, displaced, treeRoot, snapshotRoot], {
      encoding: "utf8",
      timeout: 2000,
    });
    assert.equal(result.error, undefined, result.error?.message);
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
});

function runFixture(body, envOverrides = {}) {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-boundary-runtime-"));
  const quarantineDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-boundary-quarantine-"));
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const dataDir = path.join(process.cwd(), "data");
    const uploadsDir = path.join(process.cwd(), "uploads");
    const quarantineDir = process.env.UPLOAD_QUARANTINE_DIR;
    const write = (pathname, value) => { fs.mkdirSync(path.dirname(pathname), { recursive: true }); fs.writeFileSync(pathname, value); };
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(uploadsDir, { recursive: true });
    fs.mkdirSync(quarantineDir, { recursive: true });
    ${body}
  `;
  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_)/i.test(key))),
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "fixture-single",
    UPLOAD_QUARANTINE_DIR: quarantineDir,
    ...envOverrides,
  };
  try {
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    const outcome = JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
    assert.equal(outcome.ok, true);
    return outcome;
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(quarantineDir, { recursive: true, force: true });
  }
}

test("invalid restore ids cannot delete paths outside the restore temp directory", () => {
  runFixture(`
    const victimDir = path.join(process.cwd(), "victim");
    const sentinelPath = path.join(victimDir, "sentinel.txt");
    write(sentinelPath, "preserve unrelated data");
    (async () => {
      await assert.rejects(restoreService.restoreBackup("../../../victim", { confirmation: "RESTORE" }), /Backup invalido/);
      assert.equal(fs.readFileSync(sentinelPath, "utf8"), "preserve unrelated data");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore refuses a symlinked staging root before deleting or extracting outside it", (t) => {
  const outcome = runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      const stagingRoot = path.join(dataDir, "backups", ".restore-tmp");
      const externalRoot = path.join(process.cwd(), "external-restore-staging");
      const sentinelPath = path.join(externalRoot, backup.id, "sentinel.txt");
      write(sentinelPath, "preserve aliased data");
      try { fs.symlinkSync(externalRoot, stagingRoot, process.platform === "win32" ? "junction" : "dir"); }
      catch (error) {
        if (["EACCES", "EPERM", "ENOTSUP", "EINVAL"].includes(error.code)) {
          console.log(JSON.stringify({ ok: true, skipped: "directory symlink unavailable: " + error.code }));
          return;
        }
        throw error;
      }
      await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /unsafe directory|staging root is unsafe/i);
      assert.equal(fs.readFileSync(sentinelPath, "utf8"), "preserve aliased data");
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "live-state");
      assert.equal(restoreService.isWholeRestoreBlocked(), false, "unsafe staging must be rejected before a restore coordinator is written");

      if (process.platform === "win32") fs.rmdirSync(stagingRoot);
      else fs.unlinkSync(stagingRoot);
      fs.mkdirSync(stagingRoot);
      const externalStage = path.join(process.cwd(), "external-stage-target");
      const stageSentinel = path.join(externalStage, "sentinel.txt");
      write(stageSentinel, "preserve aliased stage data");
      try { fs.symlinkSync(externalStage, path.join(stagingRoot, backup.id), process.platform === "win32" ? "junction" : "dir"); }
      catch (error) {
        if (["EACCES", "EPERM", "ENOTSUP", "EINVAL"].includes(error.code)) {
          console.log(JSON.stringify({ ok: true, skipped: "stage symlink unavailable: " + error.code }));
          return;
        }
        throw error;
      }
      await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /staging directory is unsafe/i);
      assert.equal(fs.readFileSync(stageSentinel, "utf8"), "preserve aliased stage data");
      assert.equal(restoreService.isWholeRestoreBlocked(), false, "aliased stage must be rejected before a restore coordinator is written");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
  if (outcome.skipped) t.skip(outcome.skipped);
});

test("valid restore cleanup preserves unrelated restore temp siblings", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "restore-state");
    const siblingSentinel = path.join(dataDir, "backups", ".restore-tmp", "unrelated", "sentinel.txt");
    write(siblingSentinel, "preserve sibling staging data");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(fs.readFileSync(siblingSentinel, "utf8"), "preserve sibling staging data");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("backup archives exclude whole-restore coordinator files", () => {
  runFixture(`
    write(path.join(dataDir, ".rootark-restore-coordinator.json"), JSON.stringify({ version: 1, phase: "prepared", backupId: "fixture" }));
    write(path.join(dataDir, ".rootark-restore-provider-orphans.json"), JSON.stringify({ version: 1, objects: [{ area: "uploads", folderId: "root", name: "private-name.txt" }] }));
    write(path.join(dataDir, ".rootark-active-requests", "active.json"), JSON.stringify({ pid: 1 }));
    write(path.join(dataDir, ".rootark-restore-restart-acks", "transaction", "instance.json"), JSON.stringify({ transactionId: "fixture" }));
    (async () => {
      const created = await backupService.createBackup({ createdBy: "fixture" });
      const { backup, archivePath } = backupService.getBackupOrThrow(created.id);
      const { zip } = await restoreService.validateBackupArchive(backup, archivePath);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-restore-coordinator")), false);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase() === "data/.rootark-restore-provider-orphans.json"), false, "restore-derived provider names are not copied into future backup archives");
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-active-requests/")), false);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-restore-restart-acks/")), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("successful whole restore preserves both recovery records and blocks service until startup", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "backup-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      const result = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "backup-state");
      assert.equal(result.restartRecommended, true);
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      assert.equal(coordinator.phase, "restart_required");
      assert.equal(coordinator.directorySync, process.platform === "win32" ? "unsupported" : "fsync");
      assert.equal(coordinator.requiredRestartInstances, 1);
      assert.equal(coordinator.selectedBackup.id, backup.id);
      assert.equal(coordinator.preRestoreBackup.id, result.preRestore.id);
      assert.deepEqual(new Set(backupService.listBackups().map((entry) => entry.id)), new Set([backup.id, result.preRestore.id]));
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(restoreService.assertNoPendingWholeRestore().restartRequired, true);
      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      assert.equal(fs.existsSync(coordinatorPath), false);
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("temporary cleanup failure after commit preserves restart barrier and releases backup lock", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "backup-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      const restoreDirectory = path.join(dataDir, "backups", ".restore-tmp", backup.id);
      const originalRemove = fs.rmSync;
      fs.rmSync = function failRestoreTempCleanup(pathname, ...args) {
        if (path.resolve(String(pathname)) === path.resolve(restoreDirectory)
          && restoreService.getWholeRestorePhase() === "restart_required") {
          throw Object.assign(new Error("injected restore temp cleanup failure"), { code: "EIO" });
        }
        return originalRemove.call(this, pathname, ...args);
      };
      try {
        await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /injected restore temp cleanup failure/);
      } finally {
        fs.rmSync = originalRemove;
      }
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "backup-state");
      const coordinator = JSON.parse(fs.readFileSync(path.join(dataDir, ".rootark-restore-coordinator.json"), "utf8"));
      assert.equal(coordinator.phase, "restart_required");
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(fs.existsSync(restoreDirectory), true, "failed cleanup must retain the staging data until restart recovery");
      const release = backupService.acquireLock("backup");
      release();
      assert.equal(restoreService.prepareWholeRestoreStartup().backupId, backup.id);
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      assert.equal(fs.existsSync(restoreDirectory), false, "restart acknowledgement must retry staging cleanup before clearing the barrier");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("multi-instance restore remains blocked until each stable instance acknowledges the restored startup", () => {
  runFixture(`
    process.env.ROOTARK_RESTORE_INSTANCE_COUNT = "2";
    process.env.ROOTARK_INSTANCE_ID = "replica-a";
    write(path.join(dataDir, "runtime.json"), "backup-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const result = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      assert.equal(coordinator.requiredRestartInstances, 2);
      assert.equal(restoreService.assertNoPendingWholeRestore().restartRequired, true);
      restoreService.prepareWholeRestoreStartup();
      process.env.ROOTARK_RESTORE_INSTANCE_COUNT = "3";
      assert.throws(() => restoreService.acknowledgeWholeRestoreInstance("replica-a"), /instance count/i);
      assert.equal(fs.existsSync(coordinatorPath), true, "configuration drift must leave the service blocked");
      process.env.ROOTARK_RESTORE_INSTANCE_COUNT = "2";
      assert.deepEqual(restoreService.acknowledgeWholeRestoreInstance("replica-a"), {
        acknowledgedInstances: 1, requiredInstances: 2, complete: false,
      });
      assert.deepEqual(restoreService.acknowledgeWholeRestoreInstance("replica-a"), {
        acknowledgedInstances: 1, requiredInstances: 2, complete: false,
      });
      assert.equal(fs.existsSync(coordinatorPath), true, "duplicate startup must not count as a second instance");
      assert.deepEqual(restoreService.acknowledgeWholeRestoreInstance("replica-b"), {
        acknowledgedInstances: 2, requiredInstances: 2, complete: true,
      });
      assert.equal(fs.existsSync(coordinatorPath), false);
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      assert.equal(result.restartRecommended, true);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("pre-image cleanup failure keeps a committed restore behind the service barrier until cleanup retries", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "backup-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const result = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      restoreService.prepareWholeRestoreStartup();
      const originalRemove = fs.rmSync;
      fs.rmSync = function failPreimageCleanup(pathname, ...args) {
        if (String(pathname).includes(".restore-preimages")) throw Object.assign(new Error("injected pre-image cleanup failure"), { code: "EIO" });
        return originalRemove.call(this, pathname, ...args);
      };
      try {
        assert.throws(() => restoreService.acknowledgeWholeRestoreInstance(), /injected pre-image cleanup failure/);
      } finally {
        fs.rmSync = originalRemove;
      }
      assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "restart_required");
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(fs.existsSync(path.join(dataDir, "backups", ".restore-preimages", coordinator.transactionId)), true);
      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      assert.equal(fs.existsSync(coordinatorPath), false);
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      assert.equal(fs.existsSync(path.join(dataDir, "backups", ".restore-preimages", coordinator.transactionId)), false);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "backup-state");
      assert.equal(result.restartRecommended, true);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("startup fails closed on an ambiguous preparing coordinator instead of clearing a live restore", () => {
  runFixture(`
    const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
    write(coordinatorPath, JSON.stringify({
      version: 2, phase: "preparing", backupId: "fixture",
      transactionId: "00000000-0000-4000-8000-000000000000", requiredRestartInstances: 1,
    }));
    assert.throws(() => restoreService.assertNoPendingWholeRestore(), /recovery is pending/i);
    assert.equal(fs.existsSync(coordinatorPath), true);
    console.log(JSON.stringify({ ok: true }));
  `);
});

test("successful SQLite restore reinserts selected and pre-restore records into the restored index", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-history-runtime-"));
  const databaseDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-history-db-"));
  const databasePath = path.join(databaseDir, "configured.sqlite");
  const script = `
    const assert = require("node:assert/strict");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const { runMigrations } = require(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    new Database(process.env.DATABASE_URL).close();
    runMigrations({ backup: false });
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const result = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      const ids = backupService.listBackups().map((entry) => entry.id);
      assert.deepEqual(new Set(ids), new Set([backup.id, result.preRestore.id]));
      restoreService.prepareWholeRestoreStartup();
      restoreService.acknowledgeWholeRestoreInstance();
      assert.deepEqual(new Set(backupService.listBackups().map((entry) => entry.id)), new Set([backup.id, result.preRestore.id]));
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const env = {
    ...process.env,
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "false",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "fixture-sqlite",
  };
  try {
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(databaseDir, { recursive: true, force: true });
  }
});

test("restore quiescence timeout fails before creating pre-restore state or mutating runtime data", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "backup-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        async waitForRequestQuiescence() { throw new Error("active request still writing"); },
      }), /active request still writing/);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "live-state");
      assert.deepEqual(backupService.listBackups().map((entry) => entry.id), [backup.id]);
      assert.equal(fs.existsSync(path.join(dataDir, ".rootark-restore-coordinator.json")), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore failure after quarantine commit rolls quarantine, JSON, and uploads back to the pre-restore state", () => {
  runFixture(`
    const metadata = path.join(dataDir, "quarantine.json");
    const archivedPayload = path.join(quarantineDir, "archived.bin");
    write(path.join(dataDir, "runtime.json"), "archived-json");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    write(metadata, JSON.stringify({ items: [{ id: "archived", storedQuarantineFilename: "archived.bin" }] }));
    write(archivedPayload, "archived-payload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "current-json");
      write(path.join(uploadsDir, "file.txt"), "current-upload");
      fs.rmSync(archivedPayload);
      write(path.join(quarantineDir, "current.bin"), "current-payload");
      write(metadata, JSON.stringify({ items: [{ id: "current", storedQuarantineFilename: "current.bin" }] }));
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.quarantine.committed") throw new Error("injected boundary failure"); },
      }), /injected boundary failure/);
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(metadata, "utf8"), JSON.stringify({ items: [{ id: "current", storedQuarantineFilename: "current.bin" }] }));
      assert.equal(fs.readFileSync(path.join(quarantineDir, "current.bin"), "utf8"), "current-payload");
      assert.equal(fs.existsSync(archivedPayload), false);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "current-json");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "file.txt"), "utf8"), "current-upload");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("abrupt whole-restore interruptions automatically roll back before startup migrations", { timeout: 60_000 }, () => {
  for (const crashStep of ["restore.coordinator.persisted", "restore.before-local-commit", "restore.quarantine.committed", "restore.data.copied", "restore.uploads.cleared", "restore.sqlite.before-replacement", "restore.sqlite.committed", "restore.backup-history.reconciled", "restore.cloud-sync.persisted"]) {
    const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-coordinator-runtime-"));
    const quarantineDir = path.join(runtime, "quarantine");
    const env = {
      ...process.env,
      NODE_ENV: "test",
      DB_ENABLED: "true",
      DATABASE_URL: path.join(runtime, "data", "rootark.sqlite"),
      BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "true",
      BACKUP_INCLUDE_TEMP: "false",
      BACKUP_RETENTION_COUNT: "20",
      ROOTARK_RESTORE_INSTANCE_COUNT: "1",
      ROOTARK_INSTANCE_ID: "fixture-crash",
      UPLOAD_QUARANTINE_DIR: quarantineDir,
      JWT_SECRET: "j".repeat(48),
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      PORT: "0",
    };
    const restoreScript = `
    const fs = require("node:fs");
    const path = require("node:path");
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "fixture-object", area: "uploads", folderId: "root", name: "cloud.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, "cloud fixture"); return true; },
      upload: async () => { throw new Error("provider upload must not run during restore preparation"); },
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    const write = (pathname, value) => { fs.mkdirSync(path.dirname(pathname), { recursive: true }); fs.writeFileSync(pathname, value); };
    const dataDir = path.join(process.cwd(), "data");
    const uploadsDir = path.join(process.cwd(), "uploads");
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(uploadsDir, { recursive: true });
    fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
    const db = new Database(process.env.DATABASE_URL);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('backup-state');");
    db.close();
    write(path.join(dataDir, "runtime.json"), "backup-state");
    write(path.join(uploadsDir, "file.txt"), "backup-upload");
    write(path.join(dataDir, "quarantine.json"), JSON.stringify({ items: [{ id: "archived", storedQuarantineFilename: "archived.bin" }] }));
    write(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archived.bin"), "archived-quarantine");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      fs.rmSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archived.bin"), { force: true });
      write(path.join(process.env.UPLOAD_QUARANTINE_DIR, "live.bin"), "live-quarantine");
      write(path.join(dataDir, "quarantine.json"), JSON.stringify({ items: [{ id: "live", storedQuarantineFilename: "live.bin" }] }));
      const liveDb = new Database(process.env.DATABASE_URL);
      liveDb.prepare("UPDATE proof SET value = 'live-state'").run();
      liveDb.close();
      await restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) {
          if (step === ${JSON.stringify(crashStep)}) process.exit(86);
        },
      });
      process.exit(0);
    })().catch((error) => { console.error(error.message); process.exit(1); });
  `;
    const startupScript = `
    const assert=require("node:assert/strict");
    const fs=require("node:fs");
    const Database=require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    setTimeout(() => {
      try {
        assert.equal(fs.readFileSync("data/runtime.json", "utf8"), "live-state");
        assert.equal(fs.readFileSync("uploads/file.txt", "utf8"), "live-upload");
        assert.equal(fs.readFileSync("quarantine/live.bin", "utf8"), "live-quarantine");
        assert.equal(fs.existsSync("quarantine/archived.bin"), false);
        assert.equal(fs.readFileSync("data/quarantine.json", "utf8"), JSON.stringify({ items: [{ id: "live", storedQuarantineFilename: "live.bin" }] }));
        const db=new Database(process.env.DATABASE_URL,{readonly:true});
        try { assert.equal(db.prepare("SELECT value FROM proof").get().value,"live-state"); } finally { db.close(); }
        assert.equal(fs.existsSync("data/.rootark-restore-coordinator.json"), false);
        process.exit(0);
      } catch(error) { console.error(error); process.exit(4); }
    }, 100);
  `;
    try {
      const interrupted = spawnSync(process.execPath, ["-e", restoreScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
      assert.equal(interrupted.status, 86, `${crashStep}: ${interrupted.stderr || interrupted.stdout}`);
      const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
      assert.ok(fs.existsSync(coordinatorPath), `${crashStep}: durable restore intent must remain`);
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      assert.equal(coordinator.version, 3);
      assert.equal(coordinator.phase, "prepared");
      assert.equal(coordinator.providerReconciliation.sync.state, "pending");
      assert.equal(coordinator.providerReconciliation.sync.entries[0].path, "uploads/cloud.txt");

      const startup = spawnSync(process.execPath, ["-e", startupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
      assert.equal(startup.status, 0, `${crashStep}: ${startup.stderr || startup.stdout}`);
    } finally {
      fs.rmSync(runtime, { recursive: true, force: true });
    }
  }
});

test("restore failure after uploads are cleared rolls JSON and uploads back to the pre-restore state", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-json");
    write(path.join(uploadsDir, "old.txt"), "current-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "current-json");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected clear failure"); },
      }), /injected clear failure/);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "current-json");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "old.txt"), "utf8"), "current-upload");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("startup rolls back an interrupted JSON and uploads restore from verified local preimages", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archive-json");
    write(path.join(uploadsDir, "file.txt"), "archive-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-json");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      write(path.join(uploadsDir, "new-live.txt"), "preserve-this-too");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected interruption"); },
      }), /injected interruption/);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "live-json");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "file.txt"), "utf8"), "live-upload");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "new-live.txt"), "utf8"), "preserve-this-too");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("pre-image staging failure removes its barrier before any restore destination changes", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.preimage.data-files.verified") throw new Error("injected snapshot failure"); },
      }), /injected snapshot failure/);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "live-state");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "file.txt"), "utf8"), "live-upload");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("corrupt rollback pre-image keeps the service fail-closed for manual recovery", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected interruption"); },
      }), /injected interruption/);
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      const manifestPath = path.join(dataDir, "backups", ".restore-preimages", coordinator.transactionId, "manifest.json");
      fs.appendFileSync(manifestPath, "tampered");
      assert.throws(() => restoreService.assertNoPendingWholeRestore(), /rollback failed/i);
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "manual_recovery");
      assert.throws(() => restoreService.assertNoPendingWholeRestore(), /manual recovery/i);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("rollback write failure retains the durable barrier after partial recovery", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected interruption"); },
      }), /injected interruption/);
      assert.throws(() => restoreService.assertNoPendingWholeRestore({
        failureInjector(step) { if (step === "restore.rollback.uploads-tree.completed") throw new Error("injected rollback write failure"); },
      }), /rollback failed/i);
      const coordinator = JSON.parse(fs.readFileSync(path.join(dataDir, ".rootark-restore-coordinator.json"), "utf8"));
      assert.equal(coordinator.phase, "manual_recovery");
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.throws(() => restoreService.assertNoPendingWholeRestore(), /manual recovery/i);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("rollback cleanup retries after partial pre-image removal without revalidating deleted files", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected interruption"); },
      }), /injected interruption/);

      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      const preimageRoot = path.join(dataDir, "backups", ".restore-preimages", coordinator.transactionId);
      const manifestPath = path.join(preimageRoot, "manifest.json");
      const originalRemove = fs.rmSync;
      let interruptedCleanup = false;
      fs.rmSync = function failAfterDeletingPreimageManifest(pathname, ...args) {
        if (!interruptedCleanup && path.resolve(String(pathname)) === path.resolve(preimageRoot)) {
          originalRemove.call(this, manifestPath, { force: true });
          interruptedCleanup = true;
          throw Object.assign(new Error("injected partial pre-image cleanup failure"), { code: "EIO" });
        }
        return originalRemove.call(this, pathname, ...args);
      };
      try {
        assert.throws(() => restoreService.assertNoPendingWholeRestore(), /rollback failed/i);
      } finally {
        fs.rmSync = originalRemove;
      }

      assert.equal(interruptedCleanup, true);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "live-state");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "file.txt"), "utf8"), "live-upload");
      assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "rollback_complete");
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.existsSync(preimageRoot), false);
      assert.equal(fs.existsSync(coordinatorPath), false);
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restart resumes rollback interrupted after one local domain", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-rollback-restart-"));
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "fixture-rollback-restart",
    JWT_SECRET: "j".repeat(48),
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    PORT: "0",
  };
  const prepare = `
    const fs=require("node:fs"),path=require("node:path");
    const backup=require(${JSON.stringify(path.join(ROOT,"services","backupService"))});
    const restore=require(${JSON.stringify(path.join(ROOT,"services","restoreService"))});
    const write=(p,v)=>{fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,v)};
    fs.mkdirSync("data",{recursive:true});fs.mkdirSync("uploads",{recursive:true});
    write("data/runtime.json","archived-json");write("uploads/file.txt","archived-upload");
    (async()=>{
      const saved=await backup.createBackup({createdBy:"fixture"});
      write("data/runtime.json","live-json");write("uploads/file.txt","live-upload");
      try { await restore.restoreBackup(saved.id,{confirmation:"RESTORE",failureInjector(step){if(step==="restore.uploads.cleared")throw new Error("injected interruption")}}); }
      catch(error) { if(error.message!=="injected interruption") throw error; }
      console.log(JSON.stringify({ok:true}));
    })().catch(error=>{console.error(error);process.exit(2)});
  `;
  const interruptRollback = `
    const preimage=require(${JSON.stringify(path.join(ROOT,"services","restorePreimage"))});
    const original=preimage.restoreTree;
    preimage.restoreTree=(...args)=>{const result=original(...args);process.exit(87);return result};
    require(${JSON.stringify(path.join(ROOT,"services","restoreService"))}).assertNoPendingWholeRestore();
    process.exit(3);
  `;
  const finishStartup = `
    const assert=require("node:assert/strict"),fs=require("node:fs");
    require(${JSON.stringify(path.join(ROOT,"server.js"))});
    setTimeout(()=>{try{assert.equal(fs.readFileSync("data/runtime.json","utf8"),"live-json");assert.equal(fs.readFileSync("uploads/file.txt","utf8"),"live-upload");assert.equal(fs.existsSync("data/.rootark-restore-coordinator.json"),false);process.exit(0)}catch(error){console.error(error);process.exit(4)}},100);
  `;
  try {
    const first = spawnSync(process.execPath, ["-e", prepare], { cwd: runtime, env, encoding: "utf8", timeout: 15_000 });
    assert.equal(first.status, 0, first.stderr || first.stdout);
    const interrupted = spawnSync(process.execPath, ["-e", interruptRollback], { cwd: runtime, env, encoding: "utf8", timeout: 15_000 });
    assert.equal(interrupted.status, 87, interrupted.stderr || interrupted.stdout);
    const coordinator = JSON.parse(fs.readFileSync(path.join(runtime,"data",".rootark-restore-coordinator.json"),"utf8"));
    assert.equal(coordinator.phase,"rolling_back");
    assert.equal(coordinator.rollbackDomain, "uploads-tree");
    const restarted = spawnSync(process.execPath, ["-e", finishStartup], { cwd: runtime, env, encoding: "utf8", timeout: 20_000 });
    assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
  } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
});

test("restore failure before an upload copy rolls earlier JSON and upload changes back", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-json");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "current-json");
      write(path.join(uploadsDir, "file.txt"), "current-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.before-copy") throw new Error("injected copy failure"); },
      }), /injected copy failure/);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "current-json");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "file.txt"), "utf8"), "current-upload");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore failure after SQLite commit rolls database, JSON, and uploads back", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-sqlite-boundary-runtime-"));
  const databaseDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-sqlite-boundary-db-"));
  const databasePath = path.join(databaseDir, "configured.sqlite");
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const dataPath = path.join(process.cwd(), "data", "runtime.json");
    const uploadPath = path.join(process.cwd(), "uploads", "file.txt");
    const write = (pathname, value) => { fs.mkdirSync(path.dirname(pathname), { recursive: true }); fs.writeFileSync(pathname, value); };
    const readDatabaseValue = () => { const db = new Database(process.env.DATABASE_URL, { readonly: true }); try { return db.prepare("SELECT value FROM proof").get().value; } finally { db.close(); } };
    fs.mkdirSync(path.dirname(dataPath), { recursive: true });
    fs.mkdirSync(path.dirname(uploadPath), { recursive: true });
    const db = new Database(process.env.DATABASE_URL);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('archived-db');");
    db.close();
    write(dataPath, "archived-json");
    write(uploadPath, "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(dataPath, "current-json");
      write(uploadPath, "current-upload");
      const mutated = new Database(process.env.DATABASE_URL);
      mutated.prepare("UPDATE proof SET value = 'current-db'").run();
      mutated.close();
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.sqlite.committed") throw new Error("injected SQLite boundary failure"); },
      }), /injected SQLite boundary failure/);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(dataPath, "utf8"), "current-json");
      assert.equal(fs.readFileSync(uploadPath, "utf8"), "current-upload");
      assert.equal(readDatabaseValue(), "current-db");
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const env = {
    ...process.env,
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "fixture-uploads",
  };
  try {
    const result = spawnSync(process.execPath, ["-e", script], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    assert.equal(JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
    fs.rmSync(databaseDir, { recursive: true, force: true });
  }
});

test("restart recovers whole-restore pre-images after an interrupted SQLite journal update", { timeout: 60_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-journal-restart-"));
  const databasePath = path.join(runtime, "data", "rootark.sqlite");
  const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    DB_AUTO_BACKUP_ON_START: "false",
    JWT_SECRET: "j".repeat(48),
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "journal-restart-fixture",
    PORT: "0",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
  };
  const interruptDuringSqliteJournalUpdate = `
    const fs=require("node:fs"),path=require("node:path");
    const Database=require(${JSON.stringify(path.join(ROOT,"node_modules","better-sqlite3"))});
    const backup=require(${JSON.stringify(path.join(ROOT,"services","backupService"))});
    const restore=require(${JSON.stringify(path.join(ROOT,"services","restoreService"))});
    const write=(p,v)=>{fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,v)};
    fs.mkdirSync(path.dirname(process.env.DATABASE_URL),{recursive:true});
    fs.mkdirSync("uploads",{recursive:true});
    let db=new Database(process.env.DATABASE_URL);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('archived-db');");
    db.close();
    write("data/runtime.json","archived-json");write("uploads/file.txt","archived-upload");
    const originalWrite=fs.writeFileSync;
    const journalPrefix=process.env.DATABASE_URL+".restore-journal.json.";
    fs.writeFileSync=function interrupt(pathname,data,options){
      if(String(pathname).startsWith(journalPrefix)&&String(pathname).endsWith(".tmp")&&String(data).includes("replacement.move.primary")){
        originalWrite.call(this,pathname,String(data).slice(0,12),options);
        process.exit(87);
      }
      return originalWrite.call(this,pathname,data,options);
    };
    (async()=>{
      const saved=await backup.createBackup({createdBy:"fixture"});
      write("data/runtime.json","live-json");write("uploads/file.txt","live-upload");
      db=new Database(process.env.DATABASE_URL);db.prepare("UPDATE proof SET value='live-db'").run();db.close();
      await restore.restoreBackup(saved.id,{confirmation:"RESTORE"});
      throw new Error("journal interruption was not reached");
    })().catch(error=>{console.error(error);process.exit(2)});
  `;
  const restart = `
    const assert=require("node:assert/strict"),fs=require("node:fs"),Database=require(${JSON.stringify(path.join(ROOT,"node_modules","better-sqlite3"))});
    require(${JSON.stringify(path.join(ROOT,"server.js"))});
    setTimeout(()=>{
      try{
        assert.equal(fs.readFileSync("data/runtime.json","utf8"),"live-json");
        assert.equal(fs.readFileSync("uploads/file.txt","utf8"),"live-upload");
        assert.equal(fs.existsSync(${JSON.stringify(coordinatorPath)}),false);
        const db=new Database(process.env.DATABASE_URL,{readonly:true});
        try{assert.equal(db.prepare("SELECT value FROM proof").get().value,"live-db")}finally{db.close()}
        process.exit(0);
      }catch(error){console.error(error);process.exit(4)}
    },100);
  `;
  try {
    const interrupted = spawnSync(process.execPath, ["-e", interruptDuringSqliteJournalUpdate], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(interrupted.status, 87, interrupted.stderr || interrupted.stdout);
    const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
    assert.equal(coordinator.phase, "prepared");
    const restarted = spawnSync(process.execPath, ["-e", restart], { cwd: runtime, env, encoding: "utf8", timeout: 25_000 });
    assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
  } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
});

test("post-migration startup failure keeps the whole-restore barrier until a later listener acknowledgement", { timeout: 60_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-post-migration-"));
  const databasePath = path.join(runtime, "data", "rootark.sqlite");
  const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    DB_AUTO_BACKUP_ON_START: "false",
    JWT_SECRET: "j".repeat(48),
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "post-migration-recovery",
    PORT: "0",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "false",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
  };
  const setupScript = `
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const { runMigrations } = require(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    fs.mkdirSync(path.dirname(process.env.DATABASE_URL), { recursive: true });
    runMigrations({ backup: false });
    let db = new Database(process.env.DATABASE_URL);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('archive-before-migration');");
    db.exec("ALTER TABLE users DROP COLUMN totp_enrolled_at; ALTER TABLE users DROP COLUMN totp_last_used_step; ALTER TABLE users DROP COLUMN totp_recovery_hashes_json; ALTER TABLE users DROP COLUMN totp_pending_secret_json; ALTER TABLE users DROP COLUMN totp_secret_json; ALTER TABLE users DROP COLUMN totp_enabled; DELETE FROM schema_migrations WHERE version = 5;");
    db.close();
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      db = new Database(process.env.DATABASE_URL);
      db.prepare("UPDATE proof SET value = 'live-before-restore'").run();
      db.close();
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      const coordinator = JSON.parse(fs.readFileSync(${JSON.stringify(coordinatorPath)}, "utf8"));
      if (coordinator.phase !== "restart_required") throw new Error("restore did not persist restart-required state");
    })().catch((error) => { console.error(error); process.exit(1); });
  `;
  const failedStartupScript = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const migrationPath = require.resolve(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    const migrations = require(migrationPath);
    const runMigrations = migrations.runMigrations;
    migrations.runMigrations = (options) => {
      const result = runMigrations(options);
      if (result.applied.length !== 1 || result.applied[0] !== 5) throw new Error("expected the fixture's pending migration to apply");
      throw new Error("injected post-migration startup failure");
    };
    try {
      require(${JSON.stringify(path.join(ROOT, "server.js"))});
      throw new Error("expected the injected startup failure");
    } catch (error) {
      if (error.message !== "injected post-migration startup failure") throw error;
    }
    const coordinator = JSON.parse(fs.readFileSync(${JSON.stringify(coordinatorPath)}, "utf8"));
    assert.equal(coordinator.phase, "restart_required");
    const db = new Database(process.env.DATABASE_URL, { readonly: true });
    try {
      const versions = db.prepare("SELECT version FROM schema_migrations ORDER BY version").all().map((row) => row.version);
      assert.deepEqual(versions, [1, 2, 3, 4, 5]);
      const columns = new Set(db.prepare("PRAGMA table_info(users)").all().map((row) => row.name));
      assert.equal(columns.has("totp_enabled"), true);
      assert.equal(columns.has("session_version"), true);
      assert.equal(db.prepare("SELECT value FROM proof").get().value, "archive-before-migration");
    } finally { db.close(); }
    process.exit(0);
  `;
  const recoveredStartupScript = `
    const fs = require("node:fs");
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    setTimeout(() => {
      try {
        if (fs.existsSync(${JSON.stringify(coordinatorPath)})) throw new Error("whole-restore barrier was not acknowledged");
        process.exit(0);
      } catch (error) { console.error(error); process.exit(4); }
    }, 150);
  `;
  try {
    const setup = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(setup.status, 0, setup.stderr || setup.stdout);
    const failedStartup = spawnSync(process.execPath, ["-e", failedStartupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(failedStartup.status, 0, failedStartup.stderr || failedStartup.stdout);
    assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "restart_required");
    const recoveredStartup = spawnSync(process.execPath, ["-e", recoveredStartupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(recoveredStartup.status, 0, recoveredStartup.stderr || recoveredStartup.stdout);
    assert.equal(fs.existsSync(coordinatorPath), false);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("successful migrations before listener acknowledgement preserve the restore barrier and provider queue across restart", { timeout: 60_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-migration-before-ack-"));
  const databasePath = path.join(runtime, "data", "rootark.sqlite");
  const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
  const backupIdPath = path.join(runtime, "data", "restore-backup-id.txt");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    DB_AUTO_BACKUP_ON_START: "false",
    JWT_SECRET: "j".repeat(48),
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "migration-before-ack",
    CLOUD_STORAGE_PROVIDER: "local",
    PORT: "0",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "false",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
  };
  const setupScript = `
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const { runMigrations } = require(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "fixture-object", area: "uploads", folderId: "root", name: "cloud.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, "cloud fixture"); return true; },
      upload: async () => { throw new Error("provider upload must wait for restore startup acknowledgement"); },
    };
    fs.mkdirSync(path.dirname(process.env.DATABASE_URL), { recursive: true });
    runMigrations({ backup: false });
    let db = new Database(process.env.DATABASE_URL);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('archive-before-migration');");
    db.exec("ALTER TABLE users DROP COLUMN totp_enrolled_at; ALTER TABLE users DROP COLUMN totp_last_used_step; ALTER TABLE users DROP COLUMN totp_recovery_hashes_json; ALTER TABLE users DROP COLUMN totp_pending_secret_json; ALTER TABLE users DROP COLUMN totp_secret_json; ALTER TABLE users DROP COLUMN totp_enabled; DELETE FROM schema_migrations WHERE version = 5;");
    db.close();
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      fs.writeFileSync(${JSON.stringify(backupIdPath)}, backup.id);
      db = new Database(process.env.DATABASE_URL);
      db.prepare("UPDATE proof SET value = 'live-before-restore'").run();
      db.close();
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      if (restored.cloudSync.state !== "pending") throw new Error("restore did not persist provider reconciliation");
      if (restoreService.getWholeRestorePhase() !== "restart_required") throw new Error("restore did not persist restart-required state");
    })().catch((error) => { console.error(error); process.exit(1); });
  `;
  const interruptedBeforeAcknowledgement = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const net = require("node:net");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    const restoreServicePath = ${JSON.stringify(path.join(ROOT, "services", "restoreService"))};
    const restore = require(restoreServicePath);
    const originalListen = net.Server.prototype.listen;
    net.Server.prototype.listen = function () { throw new Error("injected listener bind interruption"); };
    try {
      assert.throws(() => require(${JSON.stringify(path.join(ROOT, "server.js"))}), /injected listener bind interruption/);
    } finally { net.Server.prototype.listen = originalListen; }
    assert.equal(JSON.parse(fs.readFileSync(${JSON.stringify(coordinatorPath)}, "utf8")).phase, "restart_required");
    assert.equal(restore.assertNoPendingWholeRestore().restartRequired, true);
    const backup = backupRepository.getBackup(fs.readFileSync(${JSON.stringify(backupIdPath)}, "utf8"));
    assert.equal(backup.metadata.restoreSync.state, "pending");
    assert.equal(backup.metadata.restoreSync.entries.length, 1);
    const db = new Database(process.env.DATABASE_URL, { readonly: true });
    try {
      assert.deepEqual(db.prepare("SELECT version FROM schema_migrations ORDER BY version").all().map((row) => row.version), [1, 2, 3, 4, 5]);
      assert.equal(db.prepare("SELECT value FROM proof").get().value, "archive-before-migration");
    } finally { db.close(); }
    process.exit(0);
  `;
  const recoveredStartup = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const migrationPath = require.resolve(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    const migrations = require(migrationPath);
    const runMigrations = migrations.runMigrations;
    let applied;
    migrations.runMigrations = (options) => { const result = runMigrations(options); applied = result.applied; return result; };
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    setTimeout(() => {
      try {
        assert.deepEqual(applied, [], "the successfully migrated restored database should not rerun migrations");
        assert.equal(fs.existsSync(${JSON.stringify(coordinatorPath)}), false, "a later listener acknowledgement should clear the barrier");
        const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
        const backup = backupRepository.getBackup(fs.readFileSync(${JSON.stringify(backupIdPath)}, "utf8"));
        assert.equal(backup.metadata.restoreSync.state, "pending", "provider reconciliation must remain durable until a provider can process it");
        process.exit(0);
      } catch (error) { console.error(error); process.exit(4); }
    }, 200);
  `;
  try {
    const setup = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(setup.status, 0, setup.stderr || setup.stdout);
    const interrupted = spawnSync(process.execPath, ["-e", interruptedBeforeAcknowledgement], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(interrupted.status, 0, interrupted.stderr || interrupted.stdout);
    assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "restart_required");
    const recovered = spawnSync(process.execPath, ["-e", recoveredStartup], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
    assert.equal(fs.existsSync(coordinatorPath), false);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("application startup recovers an interrupted SQLite restore before migrations read the database", { timeout: 60_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-startup-recovery-"));
  const databasePath = path.join(runtime, "data", "rootark.sqlite");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    DB_AUTO_BACKUP_ON_START: "false",
    JWT_SECRET: "j".repeat(48),
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    PORT: "0",
    BACKUP_ENABLED: "false",
  };
  const setupScript = `
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const destination = process.env.DATABASE_URL;
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    let db = new Database(destination);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('before-restore');");
    db.close();
    const sourceRoot = path.join(process.cwd(), "archive");
    const sourcePath = path.join(sourceRoot, "data", "rootark.sqlite");
    fs.mkdirSync(path.dirname(sourcePath), { recursive: true });
    db = new Database(sourcePath);
    db.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('restored-backup');");
    db.close();
    try {
      restoreService.restoreDatabaseFiles(sourceRoot, { failAt: "replacement.move.primary", simulateCrash: true });
      throw new Error("expected the injected restore crash");
    } catch (error) {
      if (error.code !== "SQLITE_RESTORE_INJECTED_FAILURE") throw error;
    }
    if (!fs.existsSync(restoreService.databaseJournalPath(destination))) throw new Error("restore journal was not preserved");
    console.log("interrupted restore fixture ready");
  `;
  const startupScript = `
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    const db = new Database(process.env.DATABASE_URL, { readonly: true });
    try {
      const value = db.prepare("SELECT value FROM proof").get()?.value;
      if (value !== "before-restore") throw new Error("startup exposed unexpected restored database value: " + value);
      console.log(JSON.stringify({ value }));
    } finally {
      db.close();
    }
    setTimeout(() => process.exit(0), 50);
  `;
  try {
    const interrupted = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(interrupted.status, 0, interrupted.stderr || interrupted.stdout);
    const startup = spawnSync(process.execPath, ["-e", startupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(startup.status, 0, startup.stderr || startup.stdout);
    assert.ok(startup.stdout.split(/\r?\n/).includes(JSON.stringify({ value: "before-restore" })), startup.stdout);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("startup checks whole-restore coordinator before WebDAV journal recovery", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-webdav-order-"));
  const transactionId = "00000000-0000-4000-8000-000000000000";
  const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
  const webDavJournalPath = path.join(runtime, "temp", ".incoming", `rootark-webdav-move-${transactionId}.json`);
  fs.mkdirSync(path.dirname(coordinatorPath), { recursive: true });
  fs.mkdirSync(path.dirname(webDavJournalPath), { recursive: true });
  fs.writeFileSync(coordinatorPath, JSON.stringify({
    version: 2,
    transactionId,
    phase: "prepared",
    backupId: "fixture",
    preRestoreBackupId: "pre-fixture",
    requiredRestartInstances: 1,
  }));
  fs.writeFileSync(webDavJournalPath, "not-json");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "false",
    JWT_SECRET: "j".repeat(48),
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "fixture-webdav-order",
    WEBDAV_ENABLED: "true",
    PORT: "0",
    BACKUP_ENABLED: "false",
  };
  try {
    const script = `require(${JSON.stringify(path.join(ROOT, "server.js"))});`;
    const startup = spawnSync(process.execPath, ["-e", script], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.notEqual(startup.status, 0);
    assert.match(startup.stderr, /whole-restore recovery is pending/i);
    assert.doesNotMatch(startup.stderr, /Journal WebDAV invalido/i);
    assert.equal(fs.readFileSync(webDavJournalPath, "utf8"), "not-json");
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("server startup acknowledges restored state only once its listener binds and counts distinct instances", { timeout: 60_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-multi-instance-startup-"));
  const quarantineDir = path.join(runtime, "quarantine");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "false",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    UPLOAD_QUARANTINE_DIR: quarantineDir,
    ROOTARK_RESTORE_INSTANCE_COUNT: "2",
    ROOTARK_INSTANCE_ID: "replica-a",
  };
  const setupScript = `
    const fs = require("node:fs");
    const path = require("node:path");
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    fs.mkdirSync("data", { recursive: true });
    fs.mkdirSync("uploads", { recursive: true });
    fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
    fs.writeFileSync(path.join("data", "runtime.json"), "selected-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      fs.writeFileSync(path.join("data", "runtime.json"), "live-state");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const serverScript = `
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    setTimeout(() => process.exit(0), 150);
  `;
  try {
    const setup = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(setup.status, 0, setup.stderr || setup.stdout);
    const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
    assert.equal(fs.existsSync(coordinatorPath), true);

    for (const instanceId of ["replica-a", "replica-a"]) {
      const started = spawnSync(process.execPath, ["-e", serverScript], {
        cwd: runtime,
        env: { ...env, ROOTARK_INSTANCE_ID: instanceId, JWT_SECRET: "j".repeat(48), PORT: "0", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" },
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.equal(started.status, 0, started.stderr || started.stdout);
      assert.match(started.stdout, /startup acknowledgement 1\/2/);
      assert.equal(fs.existsSync(coordinatorPath), true, "a repeated instance identity must not release the gate");
    }

    const second = spawnSync(process.execPath, ["-e", serverScript], {
      cwd: runtime,
      env: { ...env, ROOTARK_INSTANCE_ID: "replica-b", JWT_SECRET: "j".repeat(48), PORT: "0", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(second.status, 0, second.stderr || second.stdout);
    assert.match(second.stdout, /startup acknowledgement 2\/2/);
    assert.equal(fs.existsSync(coordinatorPath), false);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("provider reconciliation queued before local commit is removed when restore rolls back", () => {
  runFixture(`
    const backupRepositoryPath = require.resolve(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "fixture-object", area: "uploads", folderId: "root", name: "cloud.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, "cloud fixture"); return true; },
      upload: async () => { throw new Error("provider upload must not run during restore queue persistence"); },
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.cloud-sync.persisted") throw new Error("injected queue boundary failure"); },
      }), /injected queue boundary failure/);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      delete require.cache[backupRepositoryPath];
      const reloadedRepository = require(backupRepositoryPath);
      const persisted = reloadedRepository.getBackup(backup.id);
      assert.equal(persisted.metadata.restoreSync, undefined);
      assert.equal(fs.existsSync(path.join(uploadsDir, "cloud.txt")), false);
      assert.equal(restoreService.isWholeRestoreBlocked(), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore suppresses provider objects absent from the selected backup and keeps the suppression after restart", () => {
  runFixture(`
    let selectedBackup = false;
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [
        { provider: "s3", providerIdentity: "restored", area: "uploads", folderId: "root", name: "restored.txt" },
        ...(selectedBackup ? [
          { provider: "s3", providerIdentity: "orphan", area: "uploads", folderId: "root", name: "after-backup.txt" },
          { provider: "s3", providerIdentity: "pending-orphan", area: "temp", folderId: "root", name: "pending-after-backup.txt" },
        ] : []),
      ],
      download: async (_folderId, name, target) => { fs.writeFileSync(target, name === "restored.txt" ? "selected bytes" : "later bytes"); return true; },
      upload: async () => {},
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      write(path.join(uploadsDir, "restored.txt"), "selected bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      selectedBackup = true;
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(restored.cloudSync.state, "pending");
      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      const child = require("node:child_process").spawnSync(process.execPath, ["-e", "const fs=require('node:fs');const policy=JSON.parse(fs.readFileSync('data/.rootark-restore-provider-orphans.json','utf8'));process.stdout.write(JSON.stringify(policy));"], { cwd: process.cwd(), encoding: "utf8" });
      assert.equal(child.status, 0, child.stderr);
      assert.deepEqual(JSON.parse(child.stdout), {
        version: 1,
        objects: [
          { area: "temp", folderId: "root", name: "pending-after-backup.txt" },
          { area: "uploads", folderId: "root", name: "after-backup.txt" },
        ],
      });
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore keeps the existing fail-closed behavior for archives containing temp payloads", () => {
  runFixture(`
    const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(dataDir, "restore-state.json"), "archive state");
      write(path.join(process.cwd(), "temp", "archived-pending.txt"), "pending archive bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "restore-state.json"), "live state");
      write(policyPath, JSON.stringify({ version: 1, objects: [{ area: "uploads", folderId: "root", name: "prior-orphan.txt" }] }));
      await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /Entrada nao permitida no backup: temp\\/archived-pending.txt/);
      assert.equal(fs.readFileSync(path.join(dataDir, "restore-state.json"), "utf8"), "live state");
      assert.deepEqual(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects, [{ area: "uploads", folderId: "root", name: "prior-orphan.txt" }]);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `, { BACKUP_INCLUDE_TEMP: "true" });
});

test("restore inventory failure aborts before local commit", () => {
  runFixture(`
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(dataDir, "restore-state.json"), "backup state");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "restore-state.json"), "live state");
      const failingCloud = {
        enabled: () => true,
        inventory: async () => { throw new Error("injected provider inventory outage"); },
      };
      backupService.setCloudStorage(failingCloud);
      restoreService.setCloudStorage(failingCloud);
      await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /injected provider inventory outage/);
      assert.equal(fs.readFileSync(path.join(dataDir, "restore-state.json"), "utf8"), "live state");
      assert.equal(fs.existsSync(path.join(dataDir, ".rootark-restore-provider-orphans.json")), false);
      assert.equal(restoreService.assertNoPendingWholeRestore().reason, "no_pending_restore");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore rollback restores the prior provider-orphan suppression file", () => {
  runFixture(`
    const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
    const priorPolicy = JSON.stringify({ version: 1, objects: [{ area: "uploads", folderId: "root", name: "prior-orphan.txt" }] });
    write(policyPath, priorPolicy);
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "restored", area: "uploads", folderId: "root", name: "restore.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, "archive bytes"); return true; },
      upload: async () => {},
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      write(path.join(uploadsDir, "restore.txt"), "archive bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.provider-orphans.persisted") throw new Error("injected suppression commit failure"); },
      }), /injected suppression commit failure/);
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(policyPath, "utf8"), priorPolicy);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("abrupt exit after provider-orphan policy persistence restores pre-restore state on restart", () => {
  runFixture(`
    const childProcess = require("node:child_process");
    (async () => {
      backupService.setCloudStorage({ enabled: () => false });
      restoreService.setCloudStorage({ enabled: () => false });
      const statePath = path.join(dataDir, "restore-state.json");
      write(statePath, "backup state");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(statePath, "live state");
      const quotedBackupId = JSON.stringify(backup.id);
      const restoreCode = [
        "const backupService = require(" + JSON.stringify(${JSON.stringify(path.join(ROOT, "services", "backupService"))}) + ");",
        "const restoreService = require(" + JSON.stringify(${JSON.stringify(path.join(ROOT, "services", "restoreService"))}) + ");",
        'const cloud = { enabled: () => true, provider: "fixture", inventory: async () => [{ area: "temp", folderId: "root", name: "post-backup-pending.txt" }] };',
        'backupService.setCloudStorage(cloud);',
        'restoreService.setCloudStorage(cloud);',
        'restoreService.restoreBackup(' + quotedBackupId + ', { confirmation: "RESTORE", failureInjector(step) { if (step === "restore.provider-orphans.persisted") process.exit(86); } }).catch(() => process.exit(87));',
      ].join("\\n");
      const crashed = childProcess.spawnSync(process.execPath, ["-e", restoreCode], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 });
      assert.equal(crashed.status, 86, crashed.stderr || crashed.stdout);
      const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
      assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((entry) => entry.area === "temp" && entry.name === "post-backup-pending.txt"), true, "the abrupt exit occurs after the new suppression policy is durable");
      const recoveryCode = [
        'const fs = require("node:fs");',
        "const restoreService = require(" + JSON.stringify(${JSON.stringify(path.join(ROOT, "services", "restoreService"))}) + ");",
        'const result = restoreService.assertNoPendingWholeRestore();',
        'const state = fs.readFileSync("data/restore-state.json", "utf8");',
        'const policyExists = fs.existsSync("data/.rootark-restore-provider-orphans.json");',
        'process.stdout.write(JSON.stringify({ result, state, policyExists }));',
      ].join("\\n");
      const restarted = childProcess.spawnSync(process.execPath, ["-e", recoveryCode], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 });
      assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
      const recovered = JSON.parse(restarted.stdout);
      assert.equal(recovered.result.recovered, true);
      assert.equal(recovered.state, "live state");
      assert.equal(recovered.policyExists, false, "restart rolls back the newly persisted suppression with the other local preimages");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("provider reconciliation waits for the final distinct restore startup acknowledgement", () => {
  runFixture(`
    const { createRestoreRequestGate } = require(${JSON.stringify(path.join(ROOT, "services", "restoreRequestGate"))});
    process.env.ROOTARK_RESTORE_INSTANCE_COUNT = "2";
    process.env.ROOTARK_INSTANCE_ID = "restore-worker-fixture";
    const providerCalls = [];
    let remoteBytes = "restored cloud bytes";
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "fixture-object", area: "uploads", folderId: "root", name: "cloud.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, remoteBytes); return true; },
      upload: async (filePath, folderId, name, area) => {
        providerCalls.push({ contents: fs.readFileSync(filePath, "utf8"), folderId, name, area });
      },
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "cloud.txt"), "live bytes before restore");
      remoteBytes = "live bytes before restore";
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(restored.cloudSync.state, "pending");
      assert.equal(restoreService.getWholeRestorePhase(), "restart_required");
      restoreService.prepareWholeRestoreStartup();

      const gate = createRestoreRequestGate({
        directory: path.join(dataDir, ".rootark-active-requests"),
        isBlocked: restoreService.isWholeRestoreBlocked,
      });
      const reconcile = () => gate.run(() => restoreService.processRestoreSync({
        backupId: backup.id,
        workerId: "fixture-provider-worker",
        uploader: cloud,
      }));

      const firstAck = restoreService.acknowledgeWholeRestoreInstance("replica-a");
      assert.deepEqual([firstAck.acknowledgedInstances, firstAck.requiredInstances, firstAck.complete], [1, 2, false]);
      assert.equal(await reconcile(), undefined);
      assert.deepEqual(providerCalls, []);
      assert.equal(backupService.listBackups().find((entry) => entry.id === backup.id).metadata.restoreSync.state, "pending");

      const duplicateAck = restoreService.acknowledgeWholeRestoreInstance("replica-a");
      assert.deepEqual([duplicateAck.acknowledgedInstances, duplicateAck.requiredInstances, duplicateAck.complete], [1, 2, false]);
      assert.equal(await reconcile(), undefined);
      assert.deepEqual(providerCalls, []);

      const finalAck = restoreService.acknowledgeWholeRestoreInstance("replica-b");
      assert.deepEqual([finalAck.acknowledgedInstances, finalAck.requiredInstances, finalAck.complete], [2, 2, true]);
      const completed = await reconcile();
      assert.equal(completed.metadata.restoreSync.state, "completed");
      assert.deepEqual(providerCalls, [{ contents: "restored cloud bytes", folderId: "root", name: "cloud.txt", area: "uploads" }]);
      await reconcile();
      assert.equal(providerCalls.length, 1, "a completed queue must not upload again");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("provider upload failure survives restart and retry keeps the provider object idempotent", { timeout: 60_000 }, () => {
  runFixture(`
    const { spawnSync } = require("node:child_process");
    const backupRepositoryPath = require.resolve(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    const restoreServicePath = require.resolve(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const providerStatePath = path.join(dataDir, "provider-state.json");
    const uploadPath = path.join(uploadsDir, "provider-retry.txt");
    write(uploadPath, "restored provider bytes");
    write(providerStatePath, JSON.stringify({ requests: 0, objects: {} }));
    const cloud = {
      enabled: () => true,
      provider: "s3",
      inventory: async () => [{ provider: "s3", providerIdentity: "fixture-object", area: "uploads", folderId: "root", name: "provider-retry.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, fs.readFileSync(uploadPath)); return true; },
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(uploadPath, "live bytes before restore");
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(fs.readFileSync(uploadPath, "utf8"), "restored provider bytes");
      assert.equal(restored.backup.metadata.restoreSync.entries[0].state, "pending");
      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);

      const initialNow = Date.now();
      await restoreService.processRestoreSync({
        backupId: backup.id,
        workerId: "provider-failure-worker",
        clock: () => initialNow,
        uploader: { enabled: () => true, provider: "s3", upload: async () => { throw new Error("injected provider outage"); } },
      });
      let saved = require(backupRepositoryPath).getBackup(backup.id);
      let entry = saved.metadata.restoreSync.entries[0];
      assert.equal(entry.state, "retry_wait");
      assert.equal(entry.attempts, 1);
      assert.equal(entry.failureCategory, "provider_error");
      assert.equal(entry.leaseToken, null);
      assert.equal(Date.parse(entry.nextAttemptAt), initialNow + 1000);

      const worker = (workerNow, crashBeforeCompletion) => \`
        const assert = require("node:assert/strict");
        const fs = require("node:fs");
        const path = require("node:path");
        const repository = require(\${JSON.stringify(backupRepositoryPath)});
        const restore = require(\${JSON.stringify(restoreServicePath)});
        const originalMutation = repository.mutateRestoreSyncEntry;
        if (\${crashBeforeCompletion}) {
          repository.mutateRestoreSyncEntry = (options) => originalMutation({
            ...options,
            mutate(entry, backup) {
              const result = options.mutate(entry, backup);
              if (result.entry.state === "completed") process.exit(87);
              return result;
            },
          });
        }
        const statePath = \${JSON.stringify(providerStatePath)};
        const provider = {
          enabled: () => true,
          provider: "s3",
          upload: async (filePath, folderId, name, area) => {
            const state = JSON.parse(fs.readFileSync(statePath, "utf8"));
            state.requests += 1;
            state.objects[area + "/" + folderId + "/" + name] = fs.readFileSync(filePath, "base64");
            fs.writeFileSync(statePath, JSON.stringify(state));
          },
        };
        restore.processRestoreSync({ backupId: \${JSON.stringify(backup.id)}, workerId: "restarted-worker", clock: () => \${workerNow}, leaseMs: 1000, uploader: provider })
          .then((result) => { assert.equal(result.metadata.restoreSync.entries[0].state, "completed"); })
          .catch((error) => { console.error(error); process.exitCode = 1; });
      \`;
      const interrupted = spawnSync(process.execPath, ["-e", worker(initialNow + 2000, true)], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(interrupted.status, 87, interrupted.stderr || interrupted.stdout);
      let providerState = JSON.parse(fs.readFileSync(providerStatePath, "utf8"));
      assert.equal(providerState.objects["uploads/root/provider-retry.txt"], Buffer.from("restored provider bytes").toString("base64"));
      saved = require(backupRepositoryPath).getBackup(backup.id);
      entry = saved.metadata.restoreSync.entries[0];
      assert.equal(entry.state, "in_progress", "the process interruption must leave a leased reconciliation for recovery");
      assert.equal(entry.attempts, 2);

      const retried = spawnSync(process.execPath, ["-e", worker(initialNow + 5000, false)], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(retried.status, 0, retried.stderr || retried.stdout);
      saved = require(backupRepositoryPath).getBackup(backup.id);
      entry = saved.metadata.restoreSync.entries[0];
      assert.equal(entry.state, "completed");
      assert.equal(entry.attempts, 3);
      providerState = JSON.parse(fs.readFileSync(providerStatePath, "utf8"));
      assert.equal(providerState.requests, 2, "the provider must see the retry after the interrupted upload");
      assert.deepEqual(Object.keys(providerState.objects), ["uploads/root/provider-retry.txt"], "retries overwrite one stable provider key");
      assert.equal(providerState.objects["uploads/root/provider-retry.txt"], Buffer.from("restored provider bytes").toString("base64"));

      const repeated = spawnSync(process.execPath, ["-e", worker(initialNow + 6000, false)], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(repeated.status, 0, repeated.stderr || repeated.stdout);
      assert.equal(JSON.parse(fs.readFileSync(providerStatePath, "utf8")).requests, 2, "completed reconciliation must not upload again");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});
