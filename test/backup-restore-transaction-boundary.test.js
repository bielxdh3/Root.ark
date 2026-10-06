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

function runFixture(body) {
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
    ...process.env,
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "fixture-single",
    UPLOAD_QUARANTINE_DIR: quarantineDir,
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
    write(path.join(dataDir, ".rootark-active-requests", "active.json"), JSON.stringify({ pid: 1 }));
    write(path.join(dataDir, ".rootark-restore-restart-acks", "transaction", "instance.json"), JSON.stringify({ transactionId: "fixture" }));
    (async () => {
      const created = await backupService.createBackup({ createdBy: "fixture" });
      const { backup, archivePath } = backupService.getBackupOrThrow(created.id);
      const { zip } = await restoreService.validateBackupArchive(backup, archivePath);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-restore-coordinator")), false);
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
