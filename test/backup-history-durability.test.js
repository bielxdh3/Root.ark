const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const test = require("node:test");
require("./isolated-runtime")(test, "rootark-backup-history-durability-");
const ROOT = path.resolve(__dirname, "..");

test("failed exclusive history temp-file creation does not delete a file it did not create", () => {
  process.env.DB_ENABLED = "false";
  const repository = require("../repositories/backupRepository");
  const history = path.resolve("data", "backup-history.json");
  const collisionId = "preexisting-owner";
  const collisionPath = `${history}.${process.pid}.${collisionId}.tmp`;
  fs.mkdirSync(path.dirname(history), { recursive: true });
  fs.writeFileSync(collisionPath, "owned by another writer");
  const originalRandomUUID = crypto.randomUUID;
  crypto.randomUUID = () => collisionId;

  try {
    assert.throws(
      () => repository.saveBackup({ id: "temp-collision-fixture", filename: "collision.zip", metadata: {} }),
      { code: "EEXIST" }
    );
  } finally {
    crypto.randomUUID = originalRandomUUID;
  }

  try {
    assert.equal(fs.readFileSync(collisionPath, "utf8"), "owned by another writer");
  } finally {
    fs.rmSync(collisionPath, { force: true });
  }
});

test("JSON backup history is synced before rename and its directory is synced where supported", () => {
  process.env.DB_ENABLED = "false";
  const repository = require("../repositories/backupRepository");
  const history = path.resolve("data", "backup-history.json");
  const historyDirectory = path.dirname(history);
  const events = [];
  const originalOpenSync = fs.openSync;
  const originalWriteFileSync = fs.writeFileSync;
  const originalFsyncSync = fs.fsyncSync;
  const originalRenameSync = fs.renameSync;
  let temporaryFd = null;
  let directoryFd = null;

  fs.openSync = function (pathname, ...args) {
    const fd = originalOpenSync.call(this, pathname, ...args);
    if (String(pathname).startsWith(`${history}.`) && String(pathname).endsWith(".tmp")) {
      temporaryFd = fd;
      events.push("open-temporary");
    } else if (pathname === historyDirectory) {
      directoryFd = fd;
      events.push("open-directory");
    }
    return fd;
  };
  fs.writeFileSync = function (target, ...args) {
    if (target === temporaryFd || (typeof target === "string" && target.startsWith(`${history}.`) && target.endsWith(".tmp"))) {
      events.push("write-temporary");
    }
    return originalWriteFileSync.call(this, target, ...args);
  };
  fs.fsyncSync = function (fd) {
    if (fd === directoryFd) events.push("sync-directory");
    else if (fd === temporaryFd) events.push("sync-temporary");
    return originalFsyncSync.call(this, fd);
  };
  fs.renameSync = function (source, destination) {
    if (destination === history) events.push("rename-history");
    return originalRenameSync.call(this, source, destination);
  };

  try {
    repository.saveBackup({ id: "durability-fixture", filename: "fixture.zip", metadata: {} });
  } finally {
    fs.openSync = originalOpenSync;
    fs.writeFileSync = originalWriteFileSync;
    fs.fsyncSync = originalFsyncSync;
    fs.renameSync = originalRenameSync;
  }

  const expected = ["open-temporary", "write-temporary", "sync-temporary", "rename-history"];
  if (process.platform !== "win32") expected.push("open-directory", "sync-directory");
  assert.deepEqual(events, expected);
});

test("JSON backup history corruption fails closed and preserves the original bytes", () => {
  process.env.DB_ENABLED = "false";
  const repository = require("../repositories/backupRepository");
  const history = path.resolve("data", "backup-history.json");
  fs.mkdirSync(path.dirname(history), { recursive: true });
  for (const [index, corruptHistory] of ["{not-json", "{\"not\":\"a backup list\"}", "[null]", "[{}]"].entries()) {
    fs.writeFileSync(history, corruptHistory);
    assert.throws(
      () => repository.saveBackup({ id: `must-not-overwrite-${index}`, filename: "new.zip", metadata: {} }),
      { code: "BACKUP_HISTORY_INVALID" }
    );
    assert.equal(fs.readFileSync(history, "utf8"), corruptHistory);
  }

  const unreadableHistory = "[]";
  fs.writeFileSync(history, unreadableHistory);
  const originalReadFileSync = fs.readFileSync;
  fs.readFileSync = function failHistoryRead(target, ...args) {
    if (String(target) === history) throw Object.assign(new Error(`EACCES: denied '${history}'`), { code: "EACCES" });
    return originalReadFileSync.call(this, target, ...args);
  };
  try {
    assert.throws(
      () => repository.saveBackup({ id: "must-not-overwrite-unreadable", filename: "new.zip", metadata: {} }),
      { code: "BACKUP_HISTORY_READ_FAILED" }
    );
  } finally {
    fs.readFileSync = originalReadFileSync;
  }
  assert.equal(fs.readFileSync(history, "utf8"), unreadableHistory);
});

test("whole-restore startup rehydration blocks on corrupt history without replacing it", () => {
  process.env.DB_ENABLED = "false";
  process.env.ROOTARK_RESTORE_INSTANCE_COUNT = "1";
  process.env.ROOTARK_INSTANCE_ID = "corrupt-history-recovery-fixture";
  const history = path.resolve("data", "backup-history.json");
  const coordinator = path.resolve("data", ".rootark-restore-coordinator.json");
  const backupId = crypto.randomUUID();
  const preRestoreBackupId = crypto.randomUUID();
  const corruptHistory = "{broken history must be preserved";
  fs.mkdirSync(path.dirname(history), { recursive: true });
  fs.writeFileSync(history, corruptHistory);
  fs.writeFileSync(coordinator, JSON.stringify({
    version: 4,
    transactionId: crypto.randomUUID(),
    phase: "restart_required",
    backupId,
    preRestoreBackupId,
    requiredRestartInstances: 1,
    providerPolicyRequired: false,
    selectedBackup: { id: backupId, filename: `${backupId}.zip`, status: "success", metadata: {} },
    preRestoreBackup: { id: preRestoreBackupId, filename: `${preRestoreBackupId}.zip`, status: "success", metadata: {} },
  }));
  const restoreService = require("../services/restoreService");

  try {
    assert.throws(() => restoreService.prepareWholeRestoreStartup(), { code: "BACKUP_HISTORY_INVALID" });
    assert.equal(fs.readFileSync(history, "utf8"), corruptHistory);
    assert.equal(fs.existsSync(coordinator), true, "the durable coordinator remains available for safe recovery");
  } finally {
    // This corruption is the input under test. Restore a valid isolated fixture
    // so following tests can exercise their own backup-history behavior.
    fs.writeFileSync(history, "[]");
    fs.rmSync(coordinator, { force: true });
  }
});

test("SQLite backup history probe failures do not fall back to the JSON history", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-sqlite-history-failure-"));
  const databasePath = path.join(runtime, "not-a-sqlite-database.sqlite");
  const historyPath = path.join(runtime, "data", "backup-history.json");
  const backupRepositoryPath = path.join(ROOT, "repositories", "backupRepository.js");
  const existingHistory = JSON.stringify([{ id: "json-only-entry", filename: "existing.zip", metadata: {} }]);

  try {
    fs.mkdirSync(path.dirname(historyPath), { recursive: true });
    fs.writeFileSync(databasePath, "not a SQLite database");
    fs.writeFileSync(historyPath, existingHistory);
    const script = [
      'const assert = require("node:assert/strict");',
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      `const repository = require(${JSON.stringify(backupRepositoryPath)});`,
      'assert.throws(() => repository.listBackups(), "SQLite history probe errors must be surfaced");',
      'assert.throws(() => repository.saveBackup({ id: "must-not-fall-back", filename: "new.zip", metadata: {} }), "SQLite history writes must not switch stores");',
      `assert.equal(fs.readFileSync(${JSON.stringify(historyPath)}, "utf8"), ${JSON.stringify(existingHistory)});`,
    ].join("\n");
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "true", DB_READ_FALLBACK_JSON: "false", DATABASE_URL: databasePath },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("a valid SQLite database without backup_history preserves the existing JSON fallback", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-sqlite-history-legacy-"));
  const databasePath = path.join(runtime, "empty.sqlite");
  const historyPath = path.join(runtime, "data", "backup-history.json");
  const backupRepositoryPath = path.join(ROOT, "repositories", "backupRepository.js");
  const sqliteModulePath = path.join(ROOT, "node_modules", "better-sqlite3");
  const existingHistory = JSON.stringify([{ id: "legacy-json-entry", filename: "legacy.zip", metadata: {} }]);

  try {
    fs.mkdirSync(path.dirname(historyPath), { recursive: true });
    fs.writeFileSync(historyPath, existingHistory);
    const script = [
      `const Database = require(${JSON.stringify(sqliteModulePath)});`,
      'const db = new Database(process.env.DATABASE_URL); db.close();',
      'const assert = require("node:assert/strict");',
      'const repository = require(' + JSON.stringify(backupRepositoryPath) + ');',
      'assert.equal(repository.listBackups()[0].id, "legacy-json-entry");',
      'repository.saveBackup({ id: "legacy-json-write", filename: "legacy-write.zip", metadata: {} });',
      'assert.equal(repository.getBackup("legacy-json-write").filename, "legacy-write.zip");',
    ].join("\n");
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env: { ...process.env, DB_ENABLED: "true", DB_READ_FALLBACK_JSON: "false", DATABASE_URL: databasePath },
      encoding: "utf8",
      timeout: 10_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout || result.error?.message);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("JSON history persistence failures preserve the old entry until rename and clean temporary files", async (t) => {
  process.env.DB_ENABLED = "false";
  const repository = require("../repositories/backupRepository");
  const history = path.resolve("data", "backup-history.json");
  const directory = path.dirname(history);
  fs.mkdirSync(directory, { recursive: true });

  const afterRename = new Set(["open-directory", "directory-sync", "close-directory"]);
  for (const stage of ["open-temporary", "write", "file-sync", "close-temporary", "rename", "open-directory", "directory-sync", "close-directory"]) {
    await t.test(stage, (subtest) => {
      if (afterRename.has(stage) && process.platform === "win32") {
        subtest.skip("Parent-directory fsync/open/close is unsupported on Windows through this Node.js path");
        return;
      }
      const id = `failure-${stage}`;
      repository.saveBackup({ id, filename: `${id}.zip`, metadata: { revision: 1 } });
      const originalOpenSync = fs.openSync;
      const originalWriteFileSync = fs.writeFileSync;
      const originalFsyncSync = fs.fsyncSync;
      const originalRenameSync = fs.renameSync;
      const originalCloseSync = fs.closeSync;
      let temporaryFd = null;
      let directoryFd = null;
      let injected = false;

      fs.openSync = function (pathname, ...args) {
        if ((stage === "open-temporary" && String(pathname).startsWith(`${history}.`) && String(pathname).endsWith(".tmp"))
          || (stage === "open-directory" && pathname === directory)) {
          injected = true;
          throw Object.assign(new Error(`injected history ${stage} failure`), { code: "EIO" });
        }
        const fd = originalOpenSync.call(this, pathname, ...args);
        if (String(pathname).startsWith(`${history}.`) && String(pathname).endsWith(".tmp")) temporaryFd = fd;
        else if (pathname === directory) directoryFd = fd;
        return fd;
      };
      fs.writeFileSync = function (target, ...args) {
        if (stage === "write" && target === temporaryFd && !injected) {
          injected = true;
          throw Object.assign(new Error("injected history write failure"), { code: "EIO" });
        }
        return originalWriteFileSync.call(this, target, ...args);
      };
      fs.fsyncSync = function (fd) {
        if ((stage === "file-sync" && fd === temporaryFd) || (stage === "directory-sync" && fd === directoryFd)) {
          if (!injected) {
            injected = true;
            throw Object.assign(new Error(`injected history ${stage} failure`), { code: "EIO" });
          }
        }
        return originalFsyncSync.call(this, fd);
      };
      fs.renameSync = function (source, destination) {
        if (stage === "rename" && destination === history && !injected) {
          injected = true;
          throw Object.assign(new Error("injected history rename failure"), { code: "EIO" });
        }
        return originalRenameSync.call(this, source, destination);
      };
      fs.closeSync = function (fd) {
        if ((stage === "close-temporary" && fd === temporaryFd) || (stage === "close-directory" && fd === directoryFd)) {
          if (!injected) {
            injected = true;
            originalCloseSync.call(this, fd);
            throw Object.assign(new Error(`injected history ${stage} failure`), { code: "EIO" });
          }
        }
        return originalCloseSync.call(this, fd);
      };

      try {
        let persistenceError;
        assert.throws(
          () => repository.saveBackup({ id, filename: `${id}.zip`, metadata: { revision: 2 } }),
          (error) => {
            persistenceError = error;
            return /injected history/.test(error.message);
          }
        );
        assert.equal(persistenceError.historyRenameVisible, afterRename.has(stage),
          "the caller must be told whether the replacement already became visible");
      } finally {
        fs.openSync = originalOpenSync;
        fs.writeFileSync = originalWriteFileSync;
        fs.fsyncSync = originalFsyncSync;
        fs.renameSync = originalRenameSync;
        fs.closeSync = originalCloseSync;
      }

      assert.equal(injected, true, `the ${stage} failure must be reached`);
      assert.equal(repository.getBackup(id).metadata.revision, afterRename.has(stage) ? 2 : 1,
        "before rename the old entry remains; after rename a directory open, sync, or close error may leave the new entry visible and retryable");
      assert.equal(fs.readdirSync(directory).some((name) => name.startsWith("backup-history.json.") && name.endsWith(".tmp")), false,
        "failed persistence must not leave temporary history files");
    });
  }
});

test("backup startup recovery removes only recognized orphan cloud staging directories", async () => {
  process.env.DB_ENABLED = "false";
  const service = require("../services/backupService");
  const stageRoot = path.join(service.BACKUPS_DIR, ".cloud-stage");
  const transactionId = crypto.randomUUID();
  const stageDirectory = path.join(stageRoot, transactionId);
  fs.mkdirSync(stageDirectory, { recursive: true });
  fs.writeFileSync(path.join(stageDirectory, "private-fixture.txt"), "disposable staging data");

  await service.recoverRetentionAtStartup();

  assert.equal(fs.existsSync(stageDirectory), false, "a prior interrupted backup stage is retried before the listener can open");
  assert.equal(fs.existsSync(stageRoot), false, "the empty staging root is removed after its children");
});

test("backup startup recovery removes recognized orphan SQLite snapshot directories", async () => {
  process.env.DB_ENABLED = "false";
  const service = require("../services/backupService");
  const dataDir = path.join(process.cwd(), "data");
  const stageDirectory = path.join(dataDir, `.sqlite-backup-${crypto.randomUUID()}`);
  fs.mkdirSync(stageDirectory, { recursive: true });
  fs.writeFileSync(path.join(stageDirectory, "rootark.sqlite"), "disposable interrupted snapshot");

  await service.recoverRetentionAtStartup();

  assert.equal(fs.existsSync(stageDirectory), false, "a prior interrupted SQLite snapshot is removed before startup accepts requests");
});

test("backup startup recovery refuses SQLite snapshot symlinks without deleting their targets", async (t) => {
  process.env.DB_ENABLED = "false";
  const service = require("../services/backupService");
  const dataDir = path.join(process.cwd(), "data");
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-stage-target-"));
  const targetFile = path.join(outside, "sentinel.sqlite");
  const stageLink = path.join(dataDir, `.sqlite-backup-${crypto.randomUUID()}`);
  fs.writeFileSync(targetFile, "preserve external target");
  try {
    fs.symlinkSync(outside, stageLink, "junction");
  } catch (error) {
    fs.rmSync(outside, { recursive: true, force: true });
    t.skip(`directory symlink is unavailable: ${error.code || error.message}`);
    return;
  }

  try {
    await assert.rejects(service.recoverRetentionAtStartup(), /sqlite.*staging.*unsafe/i);
    assert.equal(fs.readFileSync(targetFile, "utf8"), "preserve external target");
    assert.equal(fs.lstatSync(stageLink).isSymbolicLink(), true);
  } finally {
    fs.rmSync(stageLink, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("backup startup recovery fails closed on unrecognized cloud staging entries", async (t) => {
  process.env.DB_ENABLED = "false";
  const service = require("../services/backupService");
  const stageRoot = path.join(service.BACKUPS_DIR, ".cloud-stage");
  const outside = path.join(process.cwd(), "data", "staging-outside-fixture");
  const link = path.join(stageRoot, crypto.randomUUID());
  fs.mkdirSync(outside, { recursive: true });
  fs.writeFileSync(path.join(outside, "private-fixture.txt"), "preserve target");
  fs.mkdirSync(stageRoot, { recursive: true });
  try {
    fs.symlinkSync(outside, link, "junction");
  } catch (error) {
    fs.rmSync(stageRoot, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
    t.skip(`directory symlink is unavailable: ${error.code || error.message}`);
    return;
  }

  try {
    await assert.rejects(service.recoverRetentionAtStartup(), /staging.*unsafe/i);
    assert.equal(fs.readFileSync(path.join(outside, "private-fixture.txt"), "utf8"), "preserve target");
    assert.equal(fs.lstatSync(link).isSymbolicLink() || fs.lstatSync(link).isDirectory(), true);
  } finally {
    fs.rmSync(link, { recursive: true, force: true });
    fs.rmSync(stageRoot, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("explicit JSON backup deletion recovers an archive after process death removes history", { timeout: 30_000 }, () => {
  const id = crypto.randomUUID();
  const filename = `rootark-backup-2026-10-09-00-00-00-000-${crypto.randomUUID().slice(0, 8)}.zip`;
  const archivePath = path.join(process.cwd(), "data", "backups", filename);
  const script = `
    const fs = require("node:fs");
    const service = require(${JSON.stringify(path.join(ROOT, "services/backupService.js"))});
    const repository = require(${JSON.stringify(path.join(ROOT, "repositories/backupRepository.js"))});
    fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
    fs.writeFileSync(${JSON.stringify(archivePath)}, "disposable crash fixture");
    repository.saveBackup({ id: ${JSON.stringify(id)}, filename: ${JSON.stringify(filename)}, status: "success", metadata: {} });
    const removeHistory = repository.deleteBackup;
    repository.deleteBackup = (...args) => { removeHistory(...args); process.exit(0); };
    service.deleteBackup(${JSON.stringify(id)}).catch((error) => { console.error(error); process.exit(1); });
  `;
  const crashed = spawnSync(process.execPath, ["-e", script], {
    cwd: process.cwd(),
    env: { ...process.env, DB_ENABLED: "false" },
    encoding: "utf8",
    timeout: 20_000,
  });
  assert.equal(crashed.status, 0, crashed.stderr || crashed.stdout);
  assert.equal(fs.existsSync(archivePath), false, "the archive must be moved before history removal");
  assert.equal(fs.existsSync(`${archivePath}.retention-tombstone`), true,
    "the crash must leave the journaled archive tombstone for restart recovery");

  // This test targets history/archive recovery; leave the independent operation lock to its own recovery tests.
  fs.rmSync(path.join(process.cwd(), "data", "backups", ".backup.lock"), { force: true });
  process.env.DB_ENABLED = "false";
  const service = require("../services/backupService");
  const repository = require("../repositories/backupRepository");
  service.recoverRetentionTombstones();
  assert.equal(repository.getBackup(id), null, "explicit deletion remains committed after restart recovery");
  assert.equal(fs.existsSync(archivePath), false, "recovery must finish deleting the archive instead of leaving it unlisted");
});

test("failed startup history rehydration keeps restore blocked and a later restart retries both history entries", { timeout: 60_000 }, async (t) => {
  const runtime = process.cwd();
  const dataDirectory = path.join(runtime, "data");
  const history = path.join(dataDirectory, "backup-history.json");
  const coordinatorPath = path.join(dataDirectory, ".rootark-restore-coordinator.json");
  const backupId = crypto.randomUUID();
  const preRestoreBackupId = crypto.randomUUID();
  const selectedBackup = {
    id: backupId,
    filename: `${backupId}.zip`,
    type: "manual",
    status: "success",
    createdAt: new Date().toISOString(),
    metadata: {
      restoreSync: {
        state: "pending",
        entries: [{ entryId: "provider-fixture", path: "uploads/root/provider-fixture.txt", area: "uploads", folderId: "root", name: "provider-fixture.txt", state: "pending" }],
      },
    },
  };
  const preRestoreBackup = {
    id: preRestoreBackupId,
    filename: `${preRestoreBackupId}.zip`,
    type: "pre-restore",
    status: "success",
    createdAt: new Date().toISOString(),
    metadata: {},
  };
  fs.mkdirSync(dataDirectory, { recursive: true });
  fs.writeFileSync(coordinatorPath, JSON.stringify({
    version: 4,
    transactionId: crypto.randomUUID(),
    phase: "restart_required",
    backupId,
    preRestoreBackupId,
    requiredRestartInstances: 1,
    providerPolicyRequired: false,
    selectedBackup,
    preRestoreBackup,
  }));
  fs.rmSync(history, { force: true });

  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "false",
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "history-retry-fixture",
    JWT_SECRET: "j".repeat(48),
    BACKUP_ENABLED: "true",
    CLOUD_STORAGE_PROVIDER: "local",
    PORT: "0",
  };
  const failureScript = (stage, failureNumber) => `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const net = require("node:net");
    const path = require("node:path");
    const history = ${JSON.stringify(history)};
    const coordinatorPath = ${JSON.stringify(coordinatorPath)};
    const originalOpenSync = fs.openSync;
    const originalFsyncSync = fs.fsyncSync;
    const originalCloseSync = fs.closeSync;
    const originalListen = net.Server.prototype.listen;
    let historyFd = null;
    let historyFilesOpened = 0;
    let directoryFd = null;
    let listenCalls = 0;
    let injected = false;
    fs.openSync = function (pathname, ...args) {
      if (String(pathname).startsWith(history + ".") && String(pathname).endsWith(".tmp")) {
        historyFilesOpened += 1;
        if (${JSON.stringify(stage)} === "open-temporary" && historyFilesOpened === ${failureNumber}) {
          injected = true;
          throw Object.assign(new Error("injected startup history ${stage}"), { code: "EIO" });
        }
        const fd = originalOpenSync.call(this, pathname, ...args);
        historyFd = fd;
        return fd;
      }
      if (pathname === path.dirname(history)) {
        if (${JSON.stringify(stage)} === "open-directory" && historyFilesOpened === ${failureNumber}) {
          injected = true;
          throw Object.assign(new Error("injected startup history ${stage}"), { code: "EIO" });
        }
        const fd = originalOpenSync.call(this, pathname, ...args);
        directoryFd = fd;
        return fd;
      }
      const fd = originalOpenSync.call(this, pathname, ...args);
      return fd;
    };
    fs.fsyncSync = function (fd) {
      if ((fd === historyFd && ${JSON.stringify(stage)} === "file-sync" && historyFilesOpened === ${failureNumber})
        || (fd === directoryFd && ${JSON.stringify(stage)} === "directory-sync" && historyFilesOpened === ${failureNumber})) {
        injected = true;
        throw Object.assign(new Error("injected startup history ${stage}"), { code: "EIO" });
      }
      return originalFsyncSync.call(this, fd);
    };
    fs.closeSync = function (fd) {
      if ((fd === historyFd && ${JSON.stringify(stage)} === "close-temporary" && historyFilesOpened === ${failureNumber})
        || (fd === directoryFd && ${JSON.stringify(stage)} === "close-directory" && historyFilesOpened === ${failureNumber})) {
        injected = true;
        originalCloseSync.call(this, fd);
        throw Object.assign(new Error("injected startup history ${stage}"), { code: "EIO" });
      }
      return originalCloseSync.call(this, fd);
    };
    net.Server.prototype.listen = function () { listenCalls += 1; throw new Error("listener must remain blocked"); };
    let startupError;
    try { require(${JSON.stringify(path.join(ROOT, "server.js"))}); } catch (error) { startupError = error; }
    try {
      assert.match(startupError?.message || "", /injected startup history/);
      assert.equal(injected, true);
      assert.equal(listenCalls, 0, "the HTTP listener must not start after rehydration fails");
      assert.equal(fs.existsSync(coordinatorPath), true, "the restore coordinator must remain available for retry");
      const restore = require(${JSON.stringify(path.join(ROOT, "services/restoreService.js"))});
      assert.equal(restore.assertNoPendingWholeRestore().restartRequired, true);
      if (${failureNumber} === 2 || ${JSON.stringify(["open-directory", "directory-sync", "close-directory"].includes(stage))}) {
        const entries = JSON.parse(fs.readFileSync(history, "utf8"));
        assert.equal(entries.length, 1, "the selected backup remains visible when a later history write or post-rename sync fails");
      }
      process.exit(0);
    } catch (error) { console.error(error); process.exit(1); }
  `;
  for (const [stage, failureNumber] of [["file-sync", 1], ["close-temporary", 2], ["open-directory", 1], ["directory-sync", 1], ["close-directory", 1]]) {
    await t.test(`${stage} failure during startup rehydration`, (subtest) => {
      if (["open-directory", "directory-sync", "close-directory"].includes(stage) && process.platform === "win32") {
        subtest.skip("Parent-directory fsync/open/close is unsupported on Windows through this Node.js path");
        return;
      }
      const failed = spawnSync(process.execPath, ["-e", failureScript(stage, failureNumber)], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
      assert.equal(failed.status, 0, failed.stderr || failed.stdout);
      assert.equal(fs.existsSync(coordinatorPath), true, "failed startup must retain the retryable coordinator");
    });
  }

  const recoveryScript = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const coordinatorPath = ${JSON.stringify(coordinatorPath)};
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    setTimeout(() => {
      try {
        assert.equal(fs.existsSync(coordinatorPath), false, "successful listener acknowledgement clears the barrier only after both records are rehydrated");
        const entries = JSON.parse(fs.readFileSync(${JSON.stringify(history)}, "utf8"));
        const selected = entries.find((entry) => entry.id === ${JSON.stringify(backupId)});
        assert.equal(selected.metadata.restoreSync.entries[0].entryId, "provider-fixture", "provider reconciliation remains durable across retry");
        process.exit(0);
      } catch (error) { console.error(error); process.exit(1); }
    }, 300);
  `;
  const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
  assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
});
