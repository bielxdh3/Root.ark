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

test("restore does not persist restart-required until restored files are flushed", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const target = path.join(dataDir, "runtime.json");
      write(target, "live-state");
      const originalOpenSync = fs.openSync;
      const originalFsyncSync = fs.fsyncSync;
      const openedPaths = new Map();
      let failed = false;
      fs.openSync = function trackOpenedPath(pathname, ...args) {
        const fd = originalOpenSync.call(this, pathname, ...args);
        if (typeof pathname === "string") openedPaths.set(fd, path.resolve(pathname));
        return fd;
      };
      fs.fsyncSync = function failRestoredTargetOnce(fd) {
        if (!failed && openedPaths.get(fd) === path.resolve(target)) {
          failed = true;
          throw Object.assign(new Error("injected restored file flush failure"), { code: "EIO" });
        }
        return originalFsyncSync.call(this, fd);
      };
      try {
        await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /injected restored file flush failure/);
      } finally {
        fs.openSync = originalOpenSync;
        fs.fsyncSync = originalFsyncSync;
      }
      assert.equal(failed, true, "the restored data file must be flushed before the commit marker");
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      assert.notEqual(coordinator.phase, "restart_required", "a failed restored-file flush must not commit the local restore");
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(target, "utf8"), "live-state", "startup recovers the preimage after the failed flush");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore rejects a missing archived file instead of persisting restart-required", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const target = path.join(dataDir, "runtime.json");
      write(target, "live-state");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) {
          if (step === "restore.data.copied") fs.rmSync(target, { force: true });
        },
      }), /durability target is missing/i);
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      assert.notEqual(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "restart_required");
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true);
      assert.equal(fs.readFileSync(target, "utf8"), "live-state");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("rollback does not persist rollback-complete until restored targets are flushed", () => {
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const target = path.join(uploadsDir, "file.txt");
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(target, "live-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected interruption"); },
      }), /injected interruption/);
      const originalOpenSync = fs.openSync;
      const originalFsyncSync = fs.fsyncSync;
      const openedPaths = new Map();
      let failed = false;
      fs.openSync = function trackOpenedPath(pathname, ...args) {
        const fd = originalOpenSync.call(this, pathname, ...args);
        if (typeof pathname === "string") openedPaths.set(fd, path.resolve(pathname));
        return fd;
      };
      fs.fsyncSync = function failRollbackTargetOnce(fd) {
        if (!failed && openedPaths.get(fd) === path.resolve(target)) {
          failed = true;
          throw Object.assign(new Error("injected rollback target flush failure"), { code: "EIO" });
        }
        return originalFsyncSync.call(this, fd);
      };
      try {
        assert.throws(() => restoreService.assertNoPendingWholeRestore(), /rollback failed/i);
      } finally {
        fs.openSync = originalOpenSync;
        fs.fsyncSync = originalFsyncSync;
      }
      assert.equal(failed, true, "rollback must flush restored payloads before recording completion");
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      assert.notEqual(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "rollback_complete");
      assert.equal(restoreService.assertNoPendingWholeRestore().recovered, true, "a later startup retries rollback after the transient flush failure");
      assert.equal(fs.readFileSync(target, "utf8"), "live-upload");
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
    write(path.join(dataDir, ".rootark-restore-provider-orphans-state.json"), JSON.stringify({ version: 1, initializedAt: new Date().toISOString() }));
    write(path.join(dataDir, ".rootark-active-requests", "active.json"), JSON.stringify({ pid: 1 }));
    write(path.join(dataDir, ".rootark-restore-restart-acks", "transaction", "instance.json"), JSON.stringify({ transactionId: "fixture" }));
    (async () => {
      const created = await backupService.createBackup({ createdBy: "fixture" });
      const { backup, archivePath } = backupService.getBackupOrThrow(created.id);
      const { zip } = await restoreService.validateBackupArchive(backup, archivePath);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-restore-coordinator")), false);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase() === "data/.rootark-restore-provider-orphans.json"), false, "restore-derived provider names are not copied into future backup archives");
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase() === "data/.rootark-restore-provider-orphans-state.json"), false, "restore policy state is not copied into future backup archives");
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-active-requests/")), false);
      assert.equal(zip.files.some((entry) => entry.path.toLowerCase().startsWith("data/.rootark-restore-restart-acks/")), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("successful whole restore preserves both recovery records and blocks service until startup", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    const legacyCloudStartup = {
      restartRequired: true,
      coordinator: { providerReconciliation: { backupId: "fixture", sync: { state: "pending" } } },
    };
    const ambiguousLegacyStartup = { restartRequired: true, coordinator: { providerReconciliation: [] } };
    assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup({
      restartRequired: true,
      coordinator: { providerPolicyRequired: true },
    }), true, "the committed restore requirement survives a provider being disabled before restart");
    assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup({
      restartRequired: true,
      coordinator: { providerPolicyRequired: false },
    }), false, "a local-only restore does not require cloud suppression state");
    assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup(legacyCloudStartup), true, "legacy cloud reconciliation remains fail-closed without its suppression policy");
    assert.throws(() => providerOrphans.initialize({ requirePolicy: restoreService.requiresProviderOrphanPolicyAtStartup(legacyCloudStartup) }), /missing after cloud restore/);
    assert.equal(fs.existsSync(providerOrphans.POLICY_PATH), false, "a legacy cloud restore cannot silently initialize an empty policy");
    assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup(ambiguousLegacyStartup), true, "an empty legacy reconciliation list cannot prove the provider inventory was not captured");
    assert.throws(() => providerOrphans.initialize({ requirePolicy: restoreService.requiresProviderOrphanPolicyAtStartup(ambiguousLegacyStartup) }), /missing after cloud restore/);
    assert.equal(fs.existsSync(providerOrphans.POLICY_PATH), false, "an ambiguous legacy restore cannot initialize an empty policy and unhide provider objects");
    assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup({
      restartRequired: true,
      coordinator: {},
    }), true, "legacy pending coordinators fail closed when their provider requirement is unknown");
    assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup({ restartRequired: false }), false);
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
      assert.equal(coordinator.providerPolicyRequired, false);
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

test("local-only restore keeps cloud inventory unknown until selected-archive reconciliation succeeds", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "archived.txt"), "archived bytes");
      write(path.join(dataDir, "restore-state.json"), "selected archive");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "restore-state.json"), "live state");
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(restored.restartRecommended, true);

      providerOrphans.initialize();
      assert.deepEqual(providerOrphans.getInventoryStatus(), { state: "unknown", backupId: backup.id },
        "a local-only restore durably records the selected archive as the provider inventory baseline");

      const childProcess = require("node:child_process");
      const serverPath = ${JSON.stringify(path.join(ROOT, "server.js"))};
      const localStartupCode = [
        'const net = require("node:net"); let listened = false; const original = net.Server.prototype.listen;',
        'net.Server.prototype.listen = function (...args) { listened = true; return original.apply(this, args); };',
        "require(" + JSON.stringify(serverPath) + ");",
        'setTimeout(() => { if (!listened) process.exit(2); process.stdout.write("local-cloud-disabled-listening"); process.exit(0); }, 150);',
      ].join("\\n");
      const localStartup = childProcess.spawnSync(process.execPath, ["-e", localStartupCode], {
        cwd: process.cwd(),
        env: { ...process.env, PORT: "0", NODE_ENV: "test", JWT_SECRET: "j".repeat(48), ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", CLOUD_STORAGE_PROVIDER: "local" },
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.equal(localStartup.status, 0, localStartup.stderr || localStartup.stdout);
      assert.match(localStartup.stdout, /local-cloud-disabled-listening/,
        "local server startup remains available while cloud inventory is unresolved and cloud is disabled");

      const calls = [];
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        inventory: async () => {
          calls.push("inventory");
          return [
            { provider: "fixture", providerIdentity: "archived", area: "uploads", folderId: "root", name: "archived.txt" },
            { provider: "fixture", providerIdentity: "orphan", area: "uploads", folderId: "root", name: "orphan.txt" },
          ];
        },
        list: async () => { calls.push("list"); return []; },
        download: async () => { calls.push("download"); return true; },
        upload: async () => { calls.push("upload"); return true; },
        remove: async () => { calls.push("remove"); return true; },
        removePrefix: async () => { calls.push("removePrefix"); return true; },
      };
      const guarded = providerOrphans.guardProvider(cloud);
      for (const operation of [
        () => guarded.inventory(),
        () => guarded.list("root"),
        () => guarded.download("root", "orphan.txt", path.join(process.cwd(), "download.txt")),
        () => guarded.upload(path.join(process.cwd(), "upload.txt"), "root", "orphan.txt"),
        () => guarded.remove("root", "orphan.txt"),
        () => guarded.removePrefix("root"),
      ]) await assert.rejects(operation(), { code: "PROVIDER_INVENTORY_UNKNOWN" });
      assert.deepEqual(calls, [], "unknown inventory prevents all provider reads and mutations");

      backupService.setCloudStorage(cloud);
      restoreService.setCloudStorage(cloud);
      cloud.inventory = async () => { throw new Error("injected provider inventory outage"); };
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /injected provider inventory outage/);
      const retryableStatus = providerOrphans.getInventoryStatus();
      assert.equal(retryableStatus.state, "unknown");
      assert.equal(retryableStatus.backupId, backup.id);
      assert.match(retryableStatus.inventoryContext, /^[a-f0-9]{64}$/);
      assert.equal(retryableStatus.previousInventoryContext, retryableStatus.inventoryContext,
        "failed inventory leaves the provider context and selected baseline durable and retryable");

      const restoreServicePath = ${JSON.stringify(path.join(ROOT, "services", "restoreService"))};
      const restartFailureCode = [
        "const restore = require(" + JSON.stringify(restoreServicePath) + ");",
        'restore.setCloudStorage({ enabled: () => true, upload: async () => true, inventory: async () => { throw new Error("injected restart inventory outage"); } });',
        'restore.reconcileUnknownProviderInventory().then(() => process.exit(2), (error) => { if (!/injected restart inventory outage/.test(error.message)) process.exit(3); process.stdout.write("retryable"); });',
      ].join("\\n");
      const restartFailure = childProcess.spawnSync(process.execPath, ["-e", restartFailureCode], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 });
      assert.equal(restartFailure.status, 0, restartFailure.stderr || restartFailure.stdout);
      assert.match(restartFailure.stdout, /retryable/);
      const restartFailureStatus = providerOrphans.getInventoryStatus();
      assert.equal(restartFailureStatus.state, "unknown");
      assert.equal(restartFailureStatus.backupId, backup.id);
      assert.match(restartFailureStatus.inventoryContext, /^[a-f0-9]{64}$/);
      assert.equal(restartFailureStatus.previousInventoryContext, restartFailureStatus.inventoryContext,
        "inventory failure after restart preserves the fail-closed marker and provider context");

      const restartSuccessCode = [
        "const restore = require(" + JSON.stringify(restoreServicePath) + ");",
        "let inventoryCalls = 0;",
        "restore.setCloudStorage({ enabled: () => true, upload: async () => true, inventory: async () => { inventoryCalls += 1; return ["
          + '{ provider: "fixture", providerIdentity: "archived", area: "uploads", folderId: "root", name: "archived.txt" },'
          + '{ provider: "fixture", providerIdentity: "orphan", area: "uploads", folderId: "root", name: "orphan.txt" }'
          + "]; } });",
        '(async () => { await restore.reconcileUnknownProviderInventory(); await restore.reconcileUnknownProviderInventory(); process.stdout.write(JSON.stringify({ inventoryCalls })); })().catch((error) => { console.error(error); process.exitCode = 1; });',
      ].join("\\n");
      const restartSuccess = childProcess.spawnSync(process.execPath, ["-e", restartSuccessCode], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 });
      assert.equal(restartSuccess.status, 0, restartSuccess.stderr || restartSuccess.stdout);
      assert.deepEqual(JSON.parse(restartSuccess.stdout), { inventoryCalls: 1 }, "successful retry remains idempotent across process restarts");

      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      assert.equal(providerOrphans.getInventoryStatus().backupId, backup.id);
      assert.deepEqual(providerOrphans.read(), [{ area: "uploads", folderId: "root", name: "orphan.txt" }],
        "provider objects absent from the selected archive remain suppressed");
      assert.equal(providerOrphans.isSuppressed("root", "archived.txt"), false,
        "an archived provider object is permitted after reconciliation");
      assert.equal(providerOrphans.isSuppressed("root", "orphan.txt"), true);
      await guarded.list("root");
      assert.equal(calls.includes("list"), true, "provider access resumes after the policy commits");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("a reconciled provider inventory is scoped to its provider configuration", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      const backupId = "11111111-1111-4111-8111-111111111111";
      await providerOrphans.markInventoryUnknown(backupId);
      const contextA = "a".repeat(64);
      const contextB = "b".repeat(64);
      await providerOrphans.reconcileInventory(backupId, [], contextA);
      const original = { enabled: () => true, inventoryContext: () => contextA, list: async () => [] };
      assert.equal(providerOrphans.getInventoryStatus(original).state, "reconciled");

      const changed = { enabled: () => true, inventoryContext: () => contextB, list: async () => [] };
      const guarded = providerOrphans.guardProvider(changed);
      await assert.rejects(guarded.list(), { code: "PROVIDER_INVENTORY_UNKNOWN" });
      assert.deepEqual(providerOrphans.getInventoryStatus(changed), { state: "unknown", backupId, inventoryContext: contextB, previousInventoryContext: contextA },
        "a different provider namespace invalidates the prior reconciled marker and keeps its backup baseline");
      await providerOrphans.markInventoryUnknown(providerOrphans.getInventoryStatus(changed).backupId);
      assert.deepEqual(providerOrphans.getInventoryStatus(), { state: "unknown", backupId },
        "startup can durably persist invalidation while cloud is disabled");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("dynamic provider identity blocks guarded access and aborts restore reconciliation on the same instance", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    const { createCloudStorage } = require(${JSON.stringify(path.join(ROOT, "services", "cloudStorage"))});
    (async () => {
      let principal = "drive-principal-a";
      let uploadCalls = 0;
      let listCalls = 0;
      let inventoryCalls = 0;
      const cloud = createCloudStorage({
        provider: "gdrive",
        gdrive: { folderId: "fixture-folder" },
        resolvePrincipalIdentity: async () => principal,
      });
      cloud.inventory = async () => { inventoryCalls += 1; return []; };
      cloud.resolveUploadId = async () => "fixture-drive-id";
      cloud.upload = async () => { uploadCalls += 1; principal = "drive-principal-c"; return true; };
      cloud.list = async () => { listCalls += 1; return []; };
      backupService.setCloudStorage(cloud);
      write(path.join(uploadsDir, "root", "file.txt"), "local bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const contextA = cloud.inventoryContext();
      await providerOrphans.markInventoryUnknown(backup.id, { inventoryContext: contextA });
      await providerOrphans.reconcileInventory(backup.id, [], contextA);

      principal = "drive-principal-b";
      const contextB = await cloud.resolveInventoryContext();
      assert.notEqual(contextA, contextB, "the same adapter detects an authenticated principal change");
      await assert.rejects(providerOrphans.guardProvider(cloud).list(), { code: "PROVIDER_INVENTORY_UNKNOWN" });
      assert.equal(listCalls, 0, "guarded cloud access is blocked before provider I/O");

      restoreService.setCloudStorage(cloud);
      inventoryCalls = 0;
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /Selected archive uploads are not fully reconciled/);
      const marker = providerOrphans.getInventoryStatus();
      assert.equal(marker.state, "unknown");
      assert.equal(marker.inventoryContext, contextB, "the attempted reconciliation context is durably recorded");
      assert.equal(marker.previousInventoryContext, contextA);
      assert.equal(uploadCalls, 1, "the upload runs under the expected principal before the injected identity switch");
      assert.equal(inventoryCalls, 0, "inventory is never certified after the provider identity changes mid-reconciliation");
      assert.equal(providerOrphans.getInventoryStatus(cloud).state, "unknown");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("cloud-disabled provider change persists invalidation and protects its backup baseline", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      backupService.setCloudStorage({ enabled: () => false });
      restoreService.setCloudStorage({ enabled: () => false });
      write(path.join(uploadsDir, "root", "baseline.txt"), "baseline");
      const baseline = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "root", "newer.txt"), "newer");
      await backupService.createBackup({ createdBy: "fixture" });
      await providerOrphans.markInventoryUnknown(baseline.id);
      await providerOrphans.reconcileInventory(baseline.id, [], "a".repeat(64));

      restoreService.setCloudStorage({ enabled: () => false, inventoryContext: () => "b".repeat(64) });
      const result = await restoreService.reconcileUnknownProviderInventory();
      assert.deepEqual(result, { state: "unknown", providerDisabled: true, changed: false });
      assert.deepEqual(providerOrphans.getInventoryStatus(), {
        state: "unknown", backupId: baseline.id, inventoryContext: "b".repeat(64), previousInventoryContext: "a".repeat(64),
      }, "the attempted and previous contexts must be durable even while cloud access is disabled");

      process.env.BACKUP_RETENTION_COUNT = "1";
      process.env.BACKUP_RETENTION_DAYS = "0";
      await backupService.cleanupRetention();
      assert.equal(backupService.listBackups().find((item) => item.id === baseline.id)?.exists, true,
        "the retained marker baseline remains available to future reconciliation");
      await assert.rejects(backupService.deleteBackup(baseline.id), /provider inventory baseline/i);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("an explicit replacement baseline recovers a legacy marker whose archive was deleted", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
      restoreService.setCloudStorage({ enabled: () => false });
      const deletedBaseline = await backupService.createBackup({ createdBy: "fixture" });
      const replacement = await backupService.createBackup({ createdBy: "fixture" });
      await providerOrphans.markInventoryUnknown(deletedBaseline.id);
      await providerOrphans.reconcileInventory(deletedBaseline.id, []);
      await backupService.deleteBackup(deletedBaseline.id);

      const provider = { enabled: () => true, inventoryContext: () => "d".repeat(64), inventory: async () => [] };
      backupService.setCloudStorage(provider);
      restoreService.setCloudStorage(provider);
      const result = await restoreService.reconcileUnknownProviderInventory({ baselineBackupId: replacement.id });
      assert.deepEqual(result, { state: "reconciled", backupId: replacement.id, suppressed: 0, changed: true });
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      assert.equal(providerOrphans.getInventoryStatus().backupId, replacement.id);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("retention and deletion revalidate provider context under the shared marker lock", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      const baseline = await backupService.createBackup({ createdBy: "fixture" });
      await backupService.createBackup({ createdBy: "fixture" });
      await providerOrphans.markInventoryUnknown(baseline.id);
      await providerOrphans.reconcileInventory(baseline.id, [], "a".repeat(64));
      const changedProvider = { enabled: () => true, inventoryContext: () => "b".repeat(64) };
      backupService.setCloudStorage(changedProvider);

      await assert.rejects(backupService.deleteBackup(baseline.id), /provider inventory baseline/i,
        "deletion sees the changed principal/configuration even before startup rewrites the marker");
      process.env.BACKUP_RETENTION_COUNT = "1";
      process.env.BACKUP_RETENTION_DAYS = "0";
      await backupService.cleanupRetention();
      assert.equal(backupService.listBackups().find((item) => item.id === baseline.id)?.exists, true,
        "retention uses the same current-context check and shared marker lock");
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled",
        "the check remains safe even before marker invalidation is persisted");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("deletion-first interleaving cannot publish an unresolved marker for a missing baseline", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      backupService.setCloudStorage({ enabled: () => false });
      const baseline = await backupService.createBackup({ createdBy: "fixture" });
      await backupService.deleteBackup(baseline.id);
      await assert.rejects(providerOrphans.markInventoryUnknown(baseline.id, {}, {
        validateBaseline: () => backupService.getBackupOrThrow(baseline.id),
      }), /Backup nao encontrado|Arquivo de backup nao encontrado/i,
      "the validator runs after deletion has won the shared inventory lock");
      assert.equal(providerOrphans.getInventoryStatus().state, "known",
        "a deleted baseline is never persisted as unresolved provider inventory state");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("cloud-disabled startup routes a deleted legacy baseline through guarded reconciliation", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      backupService.setCloudStorage({ enabled: () => false });
      restoreService.setCloudStorage({ enabled: () => false });
      const baseline = await backupService.createBackup({ createdBy: "fixture" });
      await providerOrphans.markInventoryUnknown(baseline.id);
      await providerOrphans.reconcileInventory(baseline.id, [], "a".repeat(64));
      await backupService.deleteBackup(baseline.id);
      const statePath = providerOrphans.STATE_PATH;
      const policyPath = providerOrphans.POLICY_PATH;
      const stateBefore = fs.readFileSync(statePath, "utf8");
      const policyBefore = fs.readFileSync(policyPath, "utf8");
      const listenMarker = path.join(process.cwd(), "local-listener-started");
      const serverPath = ${JSON.stringify(path.join(ROOT, "server.js"))};
      const script = [
        'const fs=require("node:fs");const net=require("node:net");const original=net.Server.prototype.listen;',
        'net.Server.prototype.listen=function(...args){fs.writeFileSync(' + JSON.stringify(listenMarker) + ',"started");const server=original.apply(this,args);setTimeout(()=>process.exit(0),100);return server;};',
        'require(' + JSON.stringify(serverPath) + ');',
      ].join("\\n");
      const child = require("node:child_process").spawnSync(process.execPath, ["-e", script], {
        cwd: process.cwd(),
        env: { ...process.env, PORT: "0", NODE_ENV: "test", JWT_SECRET: "j".repeat(48), ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", CLOUD_STORAGE_PROVIDER: "local", DB_ENABLED: "false" },
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.equal(child.status, 0, child.stderr || child.stdout);
      assert.equal(fs.existsSync(listenMarker), true, "cloud-disabled local startup remains available");
      assert.equal(fs.readFileSync(statePath, "utf8"), stateBefore, "startup does not publish a new marker referencing a missing baseline");
      assert.equal(fs.readFileSync(policyPath, "utf8"), policyBefore, "both durable marker copies remain unchanged");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("provider context change resets a failed Drive restore pin before retry", () => {
  runFixture(`
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "drive.txt"), "local current bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      const oldContext = "a".repeat(64);
      const newContext = "b".repeat(64);
      const oldProvider = {
        enabled: () => true, provider: "gdrive", inventoryContext: () => oldContext,
        resolveUploadId: async () => "old-pin",
        upload: async () => { throw Object.assign(new Error("old namespace failed"), { code: "provider_error" }); },
        inventory: async () => [],
      };
      restoreService.setCloudStorage(oldProvider);
      await assert.rejects(restoreService.reconcileUnknownProviderInventory({ sleep: async () => {} }), /not fully reconciled/);
      const failedEntry = backupRepository.getBackup(backup.id).metadata.restoreSync.entries[0];
      assert.equal(failedEntry.providerFileId, "old-pin");
      assert.equal(backupRepository.getBackup(backup.id).metadata.restoreSync.providerContext, oldContext);

      const pins = [];
      const newProvider = {
        enabled: () => true, provider: "gdrive", inventoryContext: () => newContext,
        resolveUploadId: async () => "new-pin",
        upload: async (_source, _folder, _name, _area, options) => { pins.push(options.providerFileId); return true; },
        inventory: async () => [{ area: "uploads", folderId: "root", name: "drive.txt" }],
      };
      restoreService.setCloudStorage(newProvider);
      await restoreService.reconcileUnknownProviderInventory({ sleep: async () => {} });
      const retried = backupRepository.getBackup(backup.id).metadata.restoreSync.entries[0];
      assert.deepEqual(pins, ["new-pin"], "retry reserves a new file ID under the new provider identity");
      assert.equal(retried.providerFileId, "new-pin");
      assert.equal(backupRepository.getBackup(backup.id).metadata.restoreSync.providerContext, newContext);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restart after a failed inventory recomputes and uploads a newer local delta", () => {
  runFixture(`
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      const localFile = path.join(uploadsDir, "root", "changed.txt");
      write(localFile, "ARCHIVE bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      write(localFile, "first local delta");
      const uploaded = [];
      let inventoryAttempts = 0;
      const provider = {
        enabled: () => true, provider: "fixture", inventoryContext: () => "e".repeat(64),
        upload: async (sourcePath) => { uploaded.push(fs.readFileSync(sourcePath, "utf8")); return true; },
        inventory: async () => {
          inventoryAttempts += 1;
          if (inventoryAttempts === 1) throw new Error("injected inventory interruption");
          return [{ area: "uploads", folderId: "root", name: "changed.txt" }];
        },
      };
      restoreService.setCloudStorage(provider);
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /injected inventory interruption/);
      write(localFile, "newer local delta after restart");
      await restoreService.reconcileUnknownProviderInventory();
      assert.deepEqual(uploaded, ["first local delta", "newer local delta after restart"],
        "a changed local-tree fingerprint resets completed sync entries and never replays old archive bytes");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("cloud-disabled local edits are preserved and uploaded after restart", () => {
  runFixture(`
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "edited.txt"), "ARCHIVED bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      write(path.join(uploadsDir, "root", "edited.txt"), "USER EDIT after restore");
      const restoreServicePath = ${JSON.stringify(path.join(ROOT, "services", "restoreService"))};
      const childProcess = require("node:child_process");
      const script = [
        'const fs = require("node:fs");',
        'const originalMkdtempSync = fs.mkdtempSync;',
        'fs.mkdtempSync = function(prefix, ...args) { if (String(prefix).includes("rootark-restore-sync-")) throw new Error("untracked restore payload staging is forbidden"); return originalMkdtempSync.call(this, prefix, ...args); };',
        'const restore = require(' + JSON.stringify(restoreServicePath) + ');',
        'let providerBytes = null;',
        'restore.setCloudStorage({ enabled: () => true, provider: "fixture", inventoryContext: () => "' + "c".repeat(64) + '", upload: async (sourcePath) => { providerBytes = fs.readFileSync(sourcePath, "utf8"); return true; }, inventory: async () => [{ area: "uploads", folderId: "root", name: "edited.txt" }] });',
        'restore.reconcileUnknownProviderInventory({ sleep: async () => {} }).then(() => process.stdout.write(JSON.stringify({ providerBytes })), (error) => { console.error(error); process.exitCode = 1; });',
      ].join("\\n");
      const restarted = childProcess.spawnSync(process.execPath, ["-e", script], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 });
      assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
      assert.equal(JSON.parse(restarted.stdout).providerBytes, "USER EDIT after restore", "after restart, reconciliation uploads the current local delta rather than stale archive bytes");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "root", "edited.txt"), "utf8"), "USER EDIT after restore",
        "reconciliation does not overwrite the local edit");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("cloud-disabled edits, deletions, and renames reconcile the current local delta", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "edited.txt"), "ARCHIVED edit bytes");
      write(path.join(uploadsDir, "root", "deleted.txt"), "ARCHIVED deleted bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "root", "edited.txt"), "LIVE mutable bytes");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      write(path.join(uploadsDir, "root", "edited.txt"), "USER EDIT after restore");
      fs.rmSync(path.join(uploadsDir, "root", "deleted.txt"));
      write(path.join(uploadsDir, "root", "renamed.txt"), "USER RENAMED bytes");

      const uploaded = {};
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        inventoryContext: () => "c".repeat(64),
        upload: async (sourcePath, _folderId, name) => { uploaded[name] = fs.readFileSync(sourcePath, "utf8"); return true; },
        inventory: async () => [
          { area: "uploads", folderId: "root", name: "edited.txt" },
          { area: "uploads", folderId: "root", name: "deleted.txt" },
          { area: "uploads", folderId: "root", name: "renamed.txt" },
        ],
      };
      restoreService.setCloudStorage(cloud);
      await restoreService.reconcileUnknownProviderInventory({ sleep: async () => {} });
      assert.deepEqual(uploaded, { "edited.txt": "USER EDIT after restore", "renamed.txt": "USER RENAMED bytes" },
        "startup reconciliation uploads changed and renamed local content without recreating deleted archive files");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "root", "edited.txt"), "utf8"), "USER EDIT after restore",
        "provider reconciliation preserves the user's local edit");
      assert.equal(fs.readFileSync(path.join(uploadsDir, "root", "renamed.txt"), "utf8"), "USER RENAMED bytes");
      assert.equal(fs.existsSync(path.join(uploadsDir, "root", "deleted.txt")), false);
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      assert.equal(providerOrphans.isSuppressed("root", "deleted.txt"), true,
        "remote bytes for a locally deleted file remain suppressed after reconciliation");
      assert.equal(providerOrphans.isSuppressed("root", "renamed.txt"), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("provider inventory refuses an incomplete backup baseline and gives replacement guidance", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    (async () => {
      backupService.setCloudStorage({ enabled: () => false });
      restoreService.setCloudStorage({ enabled: () => false });
      const backup = await backupService.createBackup({ label: "incomplete-baseline" });
      providerOrphans.initialize();
      await providerOrphans.markInventoryUnknown(backup.id);
      const enabledProvider = {
        provider: "gdrive", enabled: () => true, inventoryContext: () => "${"a".repeat(64)}",
        resolveInventoryContext: async () => "${"a".repeat(64)}", inventory: async () => [],
      };
      restoreService.setCloudStorage(enabledProvider);
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID.*complete backup/i);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("provider inventory reconciliation fails closed on symlink and unsupported upload entries", () => {
  for (const kind of ["symlink", "unsupported"]) runFixture(`
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "source.txt"), "complete baseline");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      let inventoryCalls = 0;
      const originalReaddir = fs.readdirSync;
      fs.readdirSync = function (directory, options) {
        const entries = originalReaddir.call(this, directory, options);
        if (options?.withFileTypes && path.resolve(directory) === path.resolve(path.join(uploadsDir, "root"))) {
          return [...entries, {
            name: "alias.txt",
            isSymbolicLink: () => ${JSON.stringify(kind)} === "symlink",
            isDirectory: () => false,
            isFile: () => false,
          }];
        }
        return entries;
      };
      restoreService.setCloudStorage({
        enabled: () => true, provider: "fixture", inventoryContext: () => "${"f".repeat(64)}",
        inventory: async () => { inventoryCalls += 1; return []; },
        upload: async () => { throw new Error("upload must not start for an ambiguous local tree"); },
      });
      const expected = ${JSON.stringify(kind)} === "symlink" ? /contains a symlink.*blocked/i : /unsupported filesystem entry.*blocked/i;
      try { await assert.rejects(restoreService.reconcileUnknownProviderInventory(), expected); }
      finally { fs.readdirSync = originalReaddir; }
      assert.equal(inventoryCalls, 0, "the provider inventory is not certified from a partial local tree");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("selected archive bytes overwrite stale provider content before inventory reopens and retry after restart", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "same.txt"), "ARCHIVED bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "root", "same.txt"), "live bytes");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(fs.readFileSync(path.join(uploadsDir, "root", "same.txt"), "utf8"), "ARCHIVED bytes");

      let providerBytes = "STALE bytes";
      let uploadCalls = 0;
      let inventoryCalls = 0;
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        inventory: async () => { inventoryCalls += 1; return [{ area: "uploads", folderId: "root", name: "same.txt" }]; },
        upload: async (sourcePath) => {
          uploadCalls += 1;
          if (uploadCalls === 1) throw new Error("injected provider outage");
          providerBytes = fs.readFileSync(sourcePath, "utf8");
          return true;
        },
        download: async (_folderId, _name, target) => { write(target, providerBytes); return true; },
      };
      restoreService.setCloudStorage(cloud);
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /Selected archive uploads are not fully reconciled/);
      const queued = backupService.listBackups().find((item) => item.id === backup.id);
      assert.equal(queued.metadata.restoreSync.state, "pending");
      assert.equal(queued.metadata.restoreSync.entries[0].state, "retry_wait");
      assert.equal(providerOrphans.isInventoryUnknown(), true);
      assert.equal(inventoryCalls, 0, "provider inventory remains closed until selected bytes are uploaded");
      await assert.rejects(restoreService.processRestoreSync({ backupId: backup.id, uploader: cloud }), { code: "PROVIDER_INVENTORY_UNKNOWN" });

      await new Promise((resolve) => setTimeout(resolve, 1100));
      const restorePath = require.resolve(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      delete require.cache[restorePath];
      const restartedRestore = require(restorePath);
      restartedRestore.setCloudStorage(cloud);
      await restartedRestore.reconcileUnknownProviderInventory();
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      assert.equal(backupService.listBackups().find((item) => item.id === backup.id).metadata.restoreSync.state, "completed");
      assert.equal(providerBytes, "ARCHIVED bytes", "startup retry uploads selected archive bytes over stale provider content");

      fs.rmSync(path.join(uploadsDir, "root", "same.txt"));
      const guarded = providerOrphans.guardProvider(cloud);
      assert.equal(await guarded.download("root", "same.txt", path.join(uploadsDir, "root", "same.txt")), true);
      assert.equal(fs.readFileSync(path.join(uploadsDir, "root", "same.txt"), "utf8"), "ARCHIVED bytes",
        "a missing local cache can hydrate only after the selected bytes replaced the stale provider object");
      assert.equal(uploadCalls, 2);
      assert.equal(inventoryCalls, 1);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("unknown inventory reuploads completed entries from a pending legacy restore queue before inventory", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "already-completed.txt"), "SELECTED first bytes");
      write(path.join(uploadsDir, "root", "pending.txt"), "SELECTED second bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "root", "already-completed.txt"), "live first bytes");
      write(path.join(uploadsDir, "root", "pending.txt"), "live second bytes");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(providerOrphans.isInventoryUnknown(), true);

      const entries = [
        { entryId: "legacy-completed", path: "uploads/root/already-completed.txt", area: "uploads", folderId: "root", name: "already-completed.txt", providerIdentity: "fixture", providerFileId: null, state: "completed", attempts: 1, nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null },
        { entryId: "legacy-pending", path: "uploads/root/pending.txt", area: "uploads", folderId: "root", name: "pending.txt", providerIdentity: null, providerFileId: null, state: "pending", attempts: 0, nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null },
      ];
      backupRepository.saveBackup({
        ...backupRepository.getBackup(backup.id),
        metadata: {
          ...backupRepository.getBackup(backup.id).metadata,
          restoreSync: {
            operationId: "legacy-restore-sync",
            revision: 0,
            state: "pending",
            queuedAt: new Date().toISOString(),
            lastAttemptAt: null,
            completedAt: null,
            failureCategory: null,
            entries,
            transitions: [{ state: "pending", at: new Date().toISOString() }],
          },
        },
      });

      const providerBytes = { "already-completed.txt": "STALE provider bytes", "pending.txt": "STALE provider bytes" };
      const operations = [];
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        upload: async (sourcePath, _folderId, name) => {
          operations.push("upload:" + name);
          providerBytes[name] = fs.readFileSync(sourcePath, "utf8");
          return true;
        },
        inventory: async () => {
          operations.push("inventory");
          return ["already-completed.txt", "pending.txt"].map((name) => ({ area: "uploads", folderId: "root", name }));
        },
        download: async (_folderId, name, target) => { write(target, providerBytes[name]); return true; },
      };
      restoreService.setCloudStorage(cloud);
      await restoreService.reconcileUnknownProviderInventory();
      assert.deepEqual(operations, [
        "upload:already-completed.txt",
        "upload:pending.txt",
        "inventory",
      ], "every selected archive object must be uploaded before provider inventory is released");
      assert.deepEqual(providerBytes, {
        "already-completed.txt": "SELECTED first bytes",
        "pending.txt": "SELECTED second bytes",
      }, "a legacy completed marker cannot certify stale provider bytes");
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("unknown inventory recovery waits for persisted leases and backoff before reopening provider access", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "leased.txt"), "ARCHIVED lease bytes");
      write(path.join(uploadsDir, "root", "retry.txt"), "ARCHIVED retry bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "root", "leased.txt"), "live lease bytes");
      write(path.join(uploadsDir, "root", "retry.txt"), "live retry bytes");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });

      const interruptedCloud = {
        enabled: () => true,
        upload: async () => { throw new Error("injected interrupted upload"); },
        inventory: async () => [],
      };
      restoreService.setCloudStorage(interruptedCloud);
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /Selected archive uploads are not fully reconciled/);

      let now = Date.now();
      const leaseDueAt = now + 5000;
      const retryDueAt = now + 8000;
      const saved = backupRepository.getBackup(backup.id);
      const entries = saved.metadata.restoreSync.entries.map((entry) => entry.name === "leased.txt"
        ? { ...entry, state: "in_progress", attempts: 1, leaseToken: "interrupted-worker", leaseUntil: new Date(leaseDueAt).toISOString() }
        : { ...entry, state: "retry_wait", attempts: 1, nextAttemptAt: new Date(retryDueAt).toISOString(), failureCategory: "provider_error", leaseToken: null, leaseUntil: null });
      backupRepository.saveBackup({
        ...saved,
        metadata: { ...saved.metadata, restoreSync: { ...saved.metadata.restoreSync, state: "pending", entries } },
      });

      const operations = [];
      const providerBytes = {};
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        upload: async (sourcePath, _folderId, name) => {
          operations.push("upload:" + name);
          providerBytes[name] = fs.readFileSync(sourcePath, "utf8");
          return true;
        },
        inventory: async () => {
          operations.push("inventory");
          return ["leased.txt", "retry.txt"].map((name) => ({ area: "uploads", folderId: "root", name }));
        },
      };
      restoreService.setCloudStorage(cloud);
      await restoreService.reconcileUnknownProviderInventory({
        clock: () => now,
        sleep: async (milliseconds) => { operations.push("wait:" + milliseconds); now += milliseconds; },
      });

      assert.deepEqual(operations, ["wait:5000", "upload:leased.txt", "wait:3000", "upload:retry.txt", "inventory"],
        "startup waits for each durable due time, resumes the work, and inventories only after all uploads complete");
      assert.deepEqual(providerBytes, { "leased.txt": "ARCHIVED lease bytes", "retry.txt": "ARCHIVED retry bytes" });
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("unknown inventory recovery processes eligible uploads before waiting for future entries", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "ready.txt"), "ARCHIVED ready bytes");
      write(path.join(uploadsDir, "root", "later.txt"), "ARCHIVED later bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(uploadsDir, "root", "ready.txt"), "live ready bytes");
      write(path.join(uploadsDir, "root", "later.txt"), "live later bytes");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });

      restoreService.setCloudStorage({
        enabled: () => true,
        upload: async () => { throw new Error("injected interruption"); },
        inventory: async () => [],
      });
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /Selected archive uploads are not fully reconciled/);

      let now = Date.now();
      const futureAt = now + 5000;
      const saved = backupRepository.getBackup(backup.id);
      const entries = saved.metadata.restoreSync.entries.map((entry) => entry.name === "later.txt"
        ? { ...entry, state: "in_progress", attempts: 1, leaseToken: "interrupted-worker", leaseUntil: new Date(futureAt).toISOString(), nextAttemptAt: null }
        : { ...entry, state: "pending", attempts: 0, leaseToken: null, leaseUntil: null, nextAttemptAt: null });
      backupRepository.saveBackup({
        ...saved,
        metadata: { ...saved.metadata, restoreSync: { ...saved.metadata.restoreSync, state: "pending", entries } },
      });

      const operations = [];
      restoreService.setCloudStorage({
        enabled: () => true,
        provider: "fixture",
        upload: async (_sourcePath, _folderId, name) => {
          operations.push("upload:" + name);
          return { provider: "fixture" };
        },
        inventory: async () => { operations.push("inventory"); return []; },
      });
      await restoreService.reconcileUnknownProviderInventory({
        clock: () => now,
        sleep: async (milliseconds) => { operations.push("wait:" + milliseconds); now += milliseconds; },
      });

      assert.deepEqual(operations, ["upload:ready.txt", "wait:5000", "upload:later.txt", "inventory"],
        "eligible work is committed before startup waits for another entry's valid future lease");
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("unknown inventory rejects persisted restore deadlines beyond the retry bound", () => {
  for (const kind of ["lease", "retry", "invalid-lease", "invalid-retry", "mixed"]) {
    runFixture(`
      const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
      const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
      backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
      restoreService.setCloudStorage({ enabled: () => false });
      (async () => {
        write(path.join(uploadsDir, "root", "bounded.txt"), "ARCHIVED bytes");
        if (${JSON.stringify(kind)} === "mixed") write(path.join(uploadsDir, "root", "pending.txt"), "PENDING bytes");
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        write(path.join(uploadsDir, "root", "bounded.txt"), "live bytes");
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });

        restoreService.setCloudStorage({
          enabled: () => true,
          upload: async () => { throw new Error("injected interruption"); },
          inventory: async () => [],
        });
        await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /Selected archive uploads are not fully reconciled/);

        let now = Date.now();
        const deadline = ${JSON.stringify(kind)}.startsWith("invalid")
          ? "not-a-date"
          : new Date(now + 2 * 60 * 60 * 1000).toISOString();
        const saved = backupRepository.getBackup(backup.id);
        const entries = saved.metadata.restoreSync.entries.map((entry) => {
          if (${JSON.stringify(kind)} === "mixed" && entry.name === "pending.txt") {
            return { ...entry, state: "pending", leaseToken: null, leaseUntil: null, nextAttemptAt: null };
          }
          return ${JSON.stringify(kind)}.endsWith("lease")
            ? { ...entry, state: "in_progress", leaseToken: "interrupted-worker", leaseUntil: deadline, nextAttemptAt: null }
            : { ...entry, state: "retry_wait", leaseToken: null, leaseUntil: null, nextAttemptAt: deadline };
        });
        backupRepository.saveBackup({
          ...saved,
          metadata: { ...saved.metadata, restoreSync: { ...saved.metadata.restoreSync, state: "pending", entries } },
        });

        let waited = 0;
        let uploads = 0;
        let inventories = 0;
        restoreService.setCloudStorage({
          enabled: () => true,
          upload: async () => { uploads += 1; return { provider: "fixture" }; },
          inventory: async () => { inventories += 1; return []; },
        });
        await assert.rejects(restoreService.reconcileUnknownProviderInventory({
          clock: () => now,
          sleep: async (milliseconds) => { waited += milliseconds; now += milliseconds; },
        }), /Persisted provider restore deadline (exceeds the supported one-hour limit|is invalid)/);
        assert.equal(waited, 0, "invalid or out-of-range deadlines cannot create an unbounded startup wait");
        assert.equal(uploads, 0, "invalid scheduling metadata cannot trigger provider writes before validation completes");
        assert.equal(inventories, 0, "invalid scheduling metadata cannot reopen provider inventory");
        assert.equal(providerOrphans.isInventoryUnknown(), true);
        console.log(JSON.stringify({ ok: true }));
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `);
  }
});

test("cloud-complete selected archives upload selected bytes before opening same-key provider objects", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      const uploadPath = path.join(uploadsDir, "root", "same.txt");
      write(uploadPath, "ARCHIVED bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const stored = backupService.getBackupOrThrow(backup.id);
      fs.rmSync(stored.archivePath);
      await backupService.createZipArchive(stored.archivePath, {
        backup_id: backup.id,
        included_files: [{ path: "uploads/root/same.txt", size: 14 }],
        cloud_complete: true,
      }, [{ absolutePath: uploadPath, entryPath: "uploads/root/same.txt", size: 14 }]);
      await backupRepository.saveBackup({ ...backup, checksum: null });
      write(uploadPath, "live bytes");
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });

      const operations = [];
      let providerBytes = "STALE bytes";
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        upload: async (source) => { operations.push("upload"); providerBytes = fs.readFileSync(source, "utf8"); return true; },
        inventory: async () => { operations.push("inventory"); return [{ area: "uploads", folderId: "root", name: "same.txt" }]; },
        download: async (_folderId, _name, target) => { write(target, providerBytes); return true; },
      };
      restoreService.setCloudStorage(cloud);
      await restoreService.reconcileUnknownProviderInventory();
      assert.deepEqual(operations, ["upload", "inventory"], "selected archive bytes replace same-key provider bytes before inventory is released");
      assert.equal(providerBytes, "ARCHIVED bytes");
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      fs.rmSync(uploadPath);
      assert.equal(await providerOrphans.guardProvider(cloud).download("root", "same.txt", uploadPath), true);
      assert.equal(fs.readFileSync(uploadPath, "utf8"), "ARCHIVED bytes",
        "a missing cache cannot hydrate the stale bytes that existed before reconciliation");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("cloud startup keeps the listener closed when selected archive uploads fail", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "startup.txt"), "selected bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      providerOrphans.initialize();

      const childProcess = require("node:child_process");
      const marker = path.join(process.cwd(), "unexpected-cloud-listener");
      const serverPath = ${JSON.stringify(path.join(ROOT, "server.js"))};
      const cloudPath = ${JSON.stringify(path.join(ROOT, "services", "cloudStorage"))};
      const script = [
        'const fs=require("node:fs");const net=require("node:net");',
        'const cloud=require(' + JSON.stringify(cloudPath) + ');',
        'cloud.createCloudStorage=()=>({provider:"fixture",enabled:()=>true,status:()=>({provider:"fixture",enabled:true}),key:()=>"",inventory:async()=>[],list:async()=>[],download:async()=>false,upload:async()=>{throw new Error("injected startup upload failure")},remove:async()=>{},removePrefix:async()=>{},resolveUploadId:async()=>"id"});',
        'const original=net.Server.prototype.listen;net.Server.prototype.listen=function(...args){fs.writeFileSync(' + JSON.stringify(marker) + ',"listened");return original.apply(this,args)};',
        'require(' + JSON.stringify(serverPath) + ');',
      ].join("\\n");
      const result = childProcess.spawnSync(process.execPath, ["-e", script], {
        cwd: process.cwd(),
        env: { ...process.env, PORT: "0", NODE_ENV: "test", JWT_SECRET: "j".repeat(48), ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", CLOUD_STORAGE_PROVIDER: "fixture" },
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.equal(result.status, 1, result.stderr || result.stdout);
      assert.match(result.stderr, /provider inventory initialization or reconciliation failed; startup blocked/);
      assert.equal(fs.existsSync(marker), false);
      assert.equal(providerOrphans.isInventoryUnknown(), true);
      const queued = backupService.listBackups().find((entry) => entry.id === backup.id);
      assert.equal(queued.metadata.restoreSync.entries[0].state, "retry_wait");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("quarantine restore persists the provider policy pair before the next backup preflight", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(dataDir, "quarantine.json"), JSON.stringify({ items: [{ id: "archived", storedQuarantineFilename: "archived.bin" }] }));
      write(path.join(quarantineDir, "archived.bin"), "archived quarantine bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "quarantine.json"), JSON.stringify({ items: [{ id: "live", storedQuarantineFilename: "live.bin" }] }));
      fs.rmSync(path.join(quarantineDir, "archived.bin"), { force: true });
      write(path.join(quarantineDir, "live.bin"), "live quarantine bytes");

      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(JSON.parse(fs.readFileSync(providerOrphans.STATE_PATH, "utf8")).providerInventory.state, "unknown");
      assert.equal(JSON.parse(fs.readFileSync(providerOrphans.POLICY_PATH, "utf8")).providerInventory.state, "unknown",
        "the policy witness is committed with the unknown-inventory state before startup initialization");
      await backupService.createBackup({ createdBy: "fixture" });
      assert.equal(fs.existsSync(providerOrphans.POLICY_PATH), true,
        "a subsequent backup preflight does not fail because quarantine restore left its policy missing");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("markerless provider control files require an explicit backup baseline and survive single-file loss", () => {
  runFixture(`
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
    backupService.setCloudStorage({ enabled: () => true, inventory: async () => [] });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(uploadsDir, "root", "archive.txt"), "archive bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(providerOrphans.STATE_PATH, JSON.stringify({ version: 1, initializedAt: "2026-01-01T00:00:00.000Z" }));
      write(providerOrphans.POLICY_PATH, JSON.stringify({ version: 1, objects: [] }));
      assert.deepEqual(providerOrphans.getInventoryStatus(), { state: "unknown", backupId: null },
        "markerless v1 state and policy from an older installation cannot prove the selected provider baseline");

      providerOrphans.initialize();
      const migratedState = JSON.parse(fs.readFileSync(providerOrphans.STATE_PATH, "utf8"));
      const migratedPolicy = JSON.parse(fs.readFileSync(providerOrphans.POLICY_PATH, "utf8"));
      const policyWitness = fs.readFileSync(providerOrphans.POLICY_PATH, "utf8");
      assert.equal(migratedState.providerInventory.state, "unknown");
      assert.equal(migratedPolicy.providerInventory.state, "unknown", "the policy carries an independent durable witness");
      assert.equal(migratedState.providerInventory.backupId, undefined);
      assert.equal(migratedPolicy.providerInventory.backupId, undefined);

      fs.rmSync(providerOrphans.STATE_PATH);
      assert.equal(providerOrphans.getInventoryStatus().state, "unknown", "losing state cannot reopen provider access while policy remains");
      providerOrphans.initialize();
      assert.equal(JSON.parse(fs.readFileSync(providerOrphans.STATE_PATH, "utf8")).providerInventory.state, "unknown",
        "startup recreates the missing state from the policy witness");
      fs.rmSync(providerOrphans.POLICY_PATH);
      assert.equal(providerOrphans.getInventoryStatus().state, "unknown", "losing policy cannot reopen provider access while state remains");
      assert.throws(() => providerOrphans.initialize(), /policy.*missing|missing.*policy/i,
        "startup remains blocked rather than recreating a policy whose suppression objects were lost");
      assert.equal(providerOrphans.isInventoryUnknown(), true);
      write(providerOrphans.POLICY_PATH, policyWitness);
      providerOrphans.initialize();

      let inventoryCalls = 0;
      const cloud = {
        enabled: () => true,
        upload: async () => true,
        inventory: async () => {
          inventoryCalls += 1;
          return [
            { provider: "fixture", providerIdentity: "archived", area: "uploads", folderId: "root", name: "archive.txt" },
            { provider: "fixture", providerIdentity: "orphan", area: "uploads", folderId: "root", name: "orphan.txt" },
          ];
        },
        list: async () => [],
      };
      restoreService.setCloudStorage(cloud);
      await assert.rejects(restoreService.reconcileUnknownProviderInventory(), /explicit.*backup baseline/i);
      assert.equal(inventoryCalls, 0, "legacy unknown state cannot guess the latest backup");

      process.env.ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID = "11111111-1111-4111-8111-111111111111";
      await assert.rejects(restoreService.reconcileUnknownProviderInventory());
      assert.equal(providerOrphans.getInventoryStatus().state, "unknown", "an unavailable explicit baseline remains fail-closed");
      assert.equal(inventoryCalls, 0, "an invalid explicit baseline is rejected before querying the provider");

      process.env.ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID = backup.id;
      const result = await restoreService.reconcileUnknownProviderInventory();
      assert.equal(result.backupId, backup.id, "only the explicitly selected backup becomes the reconciliation baseline");
      assert.equal(providerOrphans.getInventoryStatus().state, "reconciled");
      assert.equal(inventoryCalls, 1);
      assert.equal(providerOrphans.isSuppressed("root", "orphan.txt"), true);
      assert.equal(providerOrphans.isSuppressed("root", "archive.txt"), false);
      delete process.env.ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID;
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { delete process.env.ROOTARK_PROVIDER_INVENTORY_BASELINE_BACKUP_ID; console.error(error); process.exitCode = 1; });
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
    const migrations=require(${JSON.stringify(path.join(ROOT, "db", "migrations.js"))});
    const runMigrations=migrations.runMigrations;
    migrations.runMigrations=(options)=>{
      assert.equal(fs.readFileSync("data/runtime.json", "utf8"), "live-state", "whole-restore recovery completes before startup migrations");
      assert.equal(fs.readFileSync("uploads/file.txt", "utf8"), "live-upload");
      assert.equal(fs.readFileSync("quarantine/live.bin", "utf8"), "live-quarantine");
      assert.equal(fs.existsSync("data/.rootark-restore-coordinator.json"), false);
      const db=new Database(process.env.DATABASE_URL,{readonly:true});
      try { assert.equal(db.prepare("SELECT value FROM proof").get().value,"live-state"); } finally { db.close(); }
      return runMigrations(options);
    };
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

test("abrupt exit during partial whole-restore pre-image creation cleans preparing state", { timeout: 30_000 }, () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-partial-preimage-"));
  const quarantineDir = path.join(runtime, "quarantine");
  const env = {
    ...process.env,
    NODE_ENV: "test",
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "partial-preimage-fixture",
    UPLOAD_QUARANTINE_DIR: quarantineDir,
  };
  const runScript = `
    const fs = require("node:fs");
    const path = require("node:path");
    const backup = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restore = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const write = (p, value) => { fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, value); };
    fs.mkdirSync("data", { recursive: true }); fs.mkdirSync("uploads", { recursive: true }); fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
    write("data/quarantine.json", JSON.stringify({ items: [{ id: "archived", storedQuarantineFilename: "archived.bin" }] }));
    write(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archived.bin"), "archive payload");
    (async () => {
      const selected = await backup.createBackup({ createdBy: "fixture" });
      write("data/runtime.json", "live state");
      write("data/quarantine.json", JSON.stringify({ items: [{ id: "live", storedQuarantineFilename: "live.bin" }] }));
      fs.rmSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archived.bin"), { force: true });
      write(path.join(process.env.UPLOAD_QUARANTINE_DIR, "live.bin"), "live payload");
      await restore.restoreBackup(selected.id, { confirmation: "RESTORE", failureInjector(step) { if (step === "restore.preimage.quarantine-files.verified") process.exit(86); } });
      process.exit(0);
    })().catch((error) => { console.error(error); process.exit(1); });
  `;
  const recoverScript = `
    const assert = require("node:assert/strict"); const fs = require("node:fs"); const path = require("node:path");
    const restore = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const result = restore.assertNoPendingWholeRestore();
    assert.equal(result.recovered, true);
    assert.equal(fs.readFileSync("data/runtime.json", "utf8"), "live state");
    assert.deepEqual(JSON.parse(fs.readFileSync("data/quarantine.json", "utf8")), { items: [{ id: "live", storedQuarantineFilename: "live.bin" }] });
    assert.equal(fs.readFileSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "live.bin"), "utf8"), "live payload");
    assert.equal(fs.existsSync(path.join(process.env.UPLOAD_QUARANTINE_DIR, "archived.bin")), false);
    assert.equal(fs.existsSync("data/.rootark-restore-coordinator.json"), false);
  `;
  try {
    const interrupted = spawnSync(process.execPath, ["-e", runScript], { cwd: runtime, env, encoding: "utf8", timeout: 20_000 });
    assert.equal(interrupted.status, 86, interrupted.stderr || interrupted.stdout);
    const coordinator = JSON.parse(fs.readFileSync(path.join(runtime, "data", ".rootark-restore-coordinator.json"), "utf8"));
    assert.equal(coordinator.phase, "preparing");
    assert.deepEqual(coordinator.preimageProgress, ["quarantine-files"]);
    const recovered = spawnSync(process.execPath, ["-e", recoverScript], { cwd: runtime, env, encoding: "utf8", timeout: 20_000 });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
  } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
});

test("restart rolls back crashes inside quarantine journal and commit boundaries", { timeout: 60_000 }, () => {
  const crashSteps = ["restore.quarantine.journal.persisted", "restore.quarantine.old-payload.moved", "restore.quarantine.new-payload.installed", "restore.quarantine.metadata.installed", "restore.quarantine.committed-marker.persisted"];
  for (const crashStep of crashSteps) {
    runFixture(`
      const { spawnSync } = require("node:child_process");
      const restorePath = require.resolve(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const metadataPath = path.join(dataDir, "quarantine.json");
      const currentPayload = path.join(quarantineDir, "live.bin");
      const archivedPayload = path.join(quarantineDir, "archived.bin");
      write(metadataPath, JSON.stringify({ items: [{ id: "archived", storedQuarantineFilename: "archived.bin" }] }));
      write(archivedPayload, "archive payload");
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "fixture" });
        write(metadataPath, JSON.stringify({ items: [{ id: "live", storedQuarantineFilename: "live.bin" }] }));
        fs.rmSync(archivedPayload, { force: true });
        write(currentPayload, "live payload");
        write(path.join(dataDir, "runtime.json"), "live state");
        const crashScript = "const restore=require(" + JSON.stringify(restorePath) + ");restore.restoreBackup(" + JSON.stringify(backup.id) + ",{confirmation:'RESTORE',failureInjector(step){if(step===" + JSON.stringify(process.env.CRASH_STEP) + ")process.exit(86)}}).then(()=>process.exit(0)).catch(error=>{console.error(error);process.exit(1)});";
        const crashed = spawnSync(process.execPath, ["-e", crashScript], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 20_000 });
        assert.equal(crashed.status, 86, crashed.stderr || crashed.stdout);
        const recoveryScript = [
          "const assert=require('node:assert/strict'),fs=require('node:fs'),restore=require(" + JSON.stringify(restorePath) + ");",
          "const result=restore.assertNoPendingWholeRestore();assert.equal(result.recovered,true);",
          "assert.deepEqual(JSON.parse(fs.readFileSync(" + JSON.stringify(metadataPath) + ",'utf8')),{items:[{id:'live',storedQuarantineFilename:'live.bin'}]});",
          "assert.equal(fs.readFileSync(" + JSON.stringify(currentPayload) + ",'utf8'),'live payload');",
          "assert.equal(fs.existsSync(" + JSON.stringify(archivedPayload) + "),false);",
          "assert.equal(fs.readFileSync('data/runtime.json','utf8'),'live state');",
          "assert.equal(fs.existsSync('data/.rootark-quarantine-restore-journal.json'),false);",
          "assert.equal(fs.existsSync('data/.rootark-restore-coordinator.json'),false);",
        ].join(" ");
        const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 20_000 });
        assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
        console.log(JSON.stringify({ ok: true }));
      })().catch(error => { console.error(error); process.exitCode = 1; });
    `, { CRASH_STEP: crashStep });
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

test("rollback write failure is retried from a verified pre-image on fresh startup", () => {
  const recoveryScript = [
    'const assert = require("node:assert/strict");',
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});`,
    'const dataDir = path.join(process.cwd(), "data");',
    'const uploadsDir = path.join(process.cwd(), "uploads");',
    'const recovered = restoreService.assertNoPendingWholeRestore();',
    'assert.equal(recovered.recovered, true);',
    'assert.equal(restoreService.isWholeRestoreBlocked(), false);',
    'assert.equal(fs.readFileSync(path.join(dataDir, "runtime.json"), "utf8"), "live-state");',
    'assert.equal(fs.readFileSync(path.join(uploadsDir, "file.txt"), "utf8"), "live-upload");',
    'console.log(JSON.stringify({ ok: true }));',
  ].join("\n");
  runFixture(`
    write(path.join(dataDir, "runtime.json"), "archived-state");
    write(path.join(uploadsDir, "file.txt"), "archived-upload");
    (async () => {
      const { spawnSync } = require("node:child_process");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(path.join(dataDir, "runtime.json"), "live-state");
      write(path.join(uploadsDir, "file.txt"), "live-upload");
      await assert.rejects(restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.uploads.cleared") throw new Error("injected interruption"); },
      }), /injected interruption/);
      const originalOpenSync = fs.openSync;
      let failedRestoreWrite = false;
      fs.openSync = function (pathname, flags, ...args) {
        if (!failedRestoreWrite && typeof pathname === "string"
          && pathname.startsWith(path.join(uploadsDir, "file.txt") + ".")
          && pathname.endsWith(".restore-preimage") && flags === "wx") {
          failedRestoreWrite = true;
          const error = new Error("injected rollback storage write failure");
          error.code = "EIO";
          throw error;
        }
        return originalOpenSync.call(this, pathname, flags, ...args);
      };
      try {
        assert.throws(() => restoreService.assertNoPendingWholeRestore(), /rollback failed/i);
      } finally { fs.openSync = originalOpenSync; }
      assert.equal(failedRestoreWrite, true, "the rollback failed while recreating the uploads tree");
      const coordinator = JSON.parse(fs.readFileSync(path.join(dataDir, ".rootark-restore-coordinator.json"), "utf8"));
      assert.equal(coordinator.phase, "manual_recovery");
      assert.equal(restoreService.isWholeRestoreBlocked(), true);
      assert.equal(fs.existsSync(path.join(uploadsDir, "file.txt")), false, "the injected I/O failure leaves an incomplete tree behind the barrier");
      const restarted = spawnSync(process.execPath, ["-e", ${JSON.stringify(recoveryScript)}], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
      assert.equal(JSON.parse(restarted.stdout.trim().split(String.fromCharCode(10)).at(-1)).ok, true);
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
      fs.writeFileSync(path.join(process.cwd(), "data", "restore-backup-id.txt"), backup.id);
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
  const migrationFailureStartupScript = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const migrationPath = require.resolve(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    const migrations = require(migrationPath);
    const migration = migrations.MIGRATIONS.find((entry) => entry.version === 5);
    assert.ok(migration, "the fixture must have migration 5 pending");
    const apply = migration.up;
    migration.up = (db) => {
      apply(db);
      throw new Error("injected failure during migration apply");
    };
    try {
      require(${JSON.stringify(path.join(ROOT, "server.js"))});
      throw new Error("expected the injected migration failure");
    } catch (error) {
      if (error.message !== "injected failure during migration apply") throw error;
    }
    const coordinator = JSON.parse(fs.readFileSync(${JSON.stringify(coordinatorPath)}, "utf8"));
    assert.equal(coordinator.phase, "restart_required");
    const preimageRoot = path.join("data", "backups", ".restore-preimages", coordinator.transactionId);
    assert.equal(fs.existsSync(path.join(preimageRoot, "manifest.json")), true, "the committed restore must retain its rollback preimage");
    assert.equal(fs.existsSync(path.join("data", ".rootark-restore-restart-acks", coordinator.transactionId)), false, "failed startup must not acknowledge a listener");
    const db = new Database(process.env.DATABASE_URL, { readonly: true });
    try {
      const versions = db.prepare("SELECT version FROM schema_migrations ORDER BY version").all().map((row) => row.version);
      assert.deepEqual(versions, [1, 2, 3, 4], "the failed migration transaction must not record version 5");
      const columns = new Set(db.prepare("PRAGMA table_info(users)").all().map((row) => row.name));
      assert.equal(columns.has("totp_enabled"), false, "the failed migration's schema changes must roll back");
      assert.equal(db.prepare("SELECT value FROM proof").get().value, "archive-before-migration");
    } finally { db.close(); }
    process.exit(0);
  `;
  const retryAfterMigrationFailureScript = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const migrationPath = require.resolve(${JSON.stringify(path.join(ROOT, "db", "migrations"))});
    const migrations = require(migrationPath);
    const runMigrations = migrations.runMigrations;
    let applied;
    migrations.runMigrations = (options) => {
      const result = runMigrations(options);
      applied = result.applied;
      return result;
    };
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    assert.deepEqual(applied, [5], "normal retry must apply the migration that failed previously");
    const db = new Database(process.env.DATABASE_URL, { readonly: true });
    try {
      const columns = new Set(db.prepare("PRAGMA table_info(users)").all().map((row) => row.name));
      assert.equal(columns.has("totp_enabled"), true);
      assert.equal(db.prepare("SELECT value FROM proof").get().value, "archive-before-migration");
    } finally { db.close(); }
    setTimeout(() => {
      try {
        assert.equal(fs.existsSync(${JSON.stringify(coordinatorPath)}), false, "successful listener acknowledgement must clear the barrier");
        process.exit(0);
      } catch (error) { console.error(error); process.exit(4); }
    }, 150);
  `;
  const rearmPostMigrationFailureScript = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    (async () => {
      const backupId = fs.readFileSync(path.join("data", "restore-backup-id.txt"), "utf8");
      const db = new Database(process.env.DATABASE_URL);
      db.prepare("UPDATE proof SET value = 'live-before-restore'").run();
      db.close();
      await restoreService.restoreBackup(backupId, { confirmation: "RESTORE" });
      assert.equal(JSON.parse(fs.readFileSync(${JSON.stringify(coordinatorPath)}, "utf8")).phase, "restart_required");
      process.exit(0);
    })().catch((error) => { console.error(error); process.exit(1); });
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
    const migrationFailureStartup = spawnSync(process.execPath, ["-e", migrationFailureStartupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(migrationFailureStartup.status, 0, migrationFailureStartup.stderr || migrationFailureStartup.stdout);
    assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "restart_required");
    const retryAfterMigrationFailure = spawnSync(process.execPath, ["-e", retryAfterMigrationFailureScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(retryAfterMigrationFailure.status, 0, retryAfterMigrationFailure.stderr || retryAfterMigrationFailure.stdout);
    assert.equal(fs.existsSync(coordinatorPath), false);
    const rearmPostMigrationFailure = spawnSync(process.execPath, ["-e", rearmPostMigrationFailureScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(rearmPostMigrationFailure.status, 0, rearmPostMigrationFailure.stderr || rearmPostMigrationFailure.stdout);
    const failedStartup = spawnSync(process.execPath, ["-e", failedStartupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(failedStartup.status, 0, failedStartup.stderr || failedStartup.stdout);
    assert.equal(JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).phase, "restart_required");
    const transactionId = JSON.parse(fs.readFileSync(coordinatorPath, "utf8")).transactionId;
    const recoveredStartup = spawnSync(process.execPath, ["-e", recoveredStartupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(recoveredStartup.status, 0, recoveredStartup.stderr || recoveredStartup.stdout);
    assert.equal(fs.existsSync(coordinatorPath), false);
    assert.equal(fs.existsSync(path.join(runtime, "data", "backups", ".restore-preimages", transactionId)), false, "successful retry must release the retained preimage");
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
    const originalExit = process.exit;
    let startupExitCode = null;
    process.exit = (code) => { startupExitCode = code; };
    const originalListen = net.Server.prototype.listen;
    net.Server.prototype.listen = function () { throw new Error("injected listener bind interruption"); };
    require(${JSON.stringify(path.join(ROOT, "server.js"))});
    setTimeout(() => {
      try {
        assert.equal(startupExitCode, 1, "an asynchronous listener failure exits startup without acknowledging the restore");
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
        net.Server.prototype.listen = originalListen;
        process.exit = originalExit;
        originalExit(0);
      } catch (error) { console.error(error); originalExit(1); }
    }, 150);
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

test("declared multi-instance startup fails closed without acknowledging or touching a pending restore", { timeout: 60_000 }, () => {
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
  const setupScript = "const fs=require('node:fs');\n"
    + "const path=require('node:path');\n"
    + "const backupService=require(" + JSON.stringify(path.join(ROOT, "services", "backupService")) + ");\n"
    + "const restoreService=require(" + JSON.stringify(path.join(ROOT, "services", "restoreService")) + ");\n"
    + "fs.mkdirSync('data',{recursive:true});fs.mkdirSync('uploads',{recursive:true});fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR,{recursive:true});\n"
    + "fs.writeFileSync(path.join('data','runtime.json'),'selected-state');\n"
    + "(async()=>{const backup=await backupService.createBackup({createdBy:'fixture'});fs.writeFileSync(path.join('data','runtime.json'),'live-state');await restoreService.restoreBackup(backup.id,{confirmation:'RESTORE'});})().catch(error=>{console.error(error);process.exitCode=1;});";
  const serverScript = "require(" + JSON.stringify(path.join(ROOT, "server.js")) + ");";
  try {
    const setup = spawnSync(process.execPath, ["-e", setupScript], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(setup.status, 0, setup.stderr || setup.stdout);
    const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
    assert.equal(fs.existsSync(coordinatorPath), true);

    const started = spawnSync(process.execPath, ["-e", serverScript], {
      cwd: runtime,
      env: { ...env, JWT_SECRET: "j".repeat(48), PORT: "0", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.notEqual(started.status, 0);
    assert.match(started.stderr, /Multiple server instances are unsupported while authentication state is process-local/i);
    assert.equal(fs.existsSync(coordinatorPath), true, "a refused app topology must preserve the pending restore coordinator");
    assert.equal(fs.existsSync(path.join(runtime, "data", ".rootark-restore-restart-acks")), false);
    assert.equal(fs.existsSync(path.join(runtime, "data", ".rootark-active-requests")), false);
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
    const providerOrphans = require(${JSON.stringify(path.join(ROOT, "services", "restoreProviderOrphans"))});
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
      upload: async () => ({ provider: "fixture" }),
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      write(path.join(uploadsDir, "restored.txt"), "selected bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      selectedBackup = true;
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(restored.cloudSync.state, "pending");
      const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
      const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
      assert.equal(coordinator.providerPolicyRequired, true, "a cloud restore durably records the policy requirement before local commit");
      const policyBytes = fs.readFileSync(providerOrphans.POLICY_PATH);
      restoreService.setCloudStorage({ enabled: () => false });
      fs.unlinkSync(providerOrphans.POLICY_PATH);
      const startup = restoreService.assertNoPendingWholeRestore();
      assert.equal(restoreService.requiresProviderOrphanPolicyAtStartup(startup), true,
        "the startup requirement is based on the committed transaction even while the provider is disabled");
      assert.throws(() => providerOrphans.initialize({ requirePolicy: restoreService.requiresProviderOrphanPolicyAtStartup(startup) }),
        /policy.*missing/i, "disabled provider configuration cannot replace a missing committed suppression policy with an empty one");
      fs.writeFileSync(providerOrphans.POLICY_PATH, policyBytes);
      providerOrphans.initialize({ requirePolicy: restoreService.requiresProviderOrphanPolicyAtStartup(startup) });
      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      const child = require("node:child_process").spawnSync(process.execPath, ["-e", "const fs=require('node:fs');const policy=JSON.parse(fs.readFileSync('data/.rootark-restore-provider-orphans.json','utf8'));process.stdout.write(JSON.stringify(policy));"], { cwd: process.cwd(), encoding: "utf8" });
      assert.equal(child.status, 0, child.stderr);
      assert.deepEqual(JSON.parse(child.stdout), {
        version: 1,
        providerInventory: { state: "known" },
        objects: [
          { area: "temp", folderId: "root", name: "pending-after-backup.txt" },
          { area: "uploads", folderId: "root", name: "after-backup.txt" },
        ],
      });
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("incomplete cloud backups reconcile same-name provider objects before clearing their restore suppression", () => {
  runFixture(`
    const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
    const uploadPath = path.join(uploadsDir, "same-name.txt");
    let remoteBytes = "stale provider bytes";
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "same-name-object", area: "uploads", folderId: "root", name: "same-name.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, remoteBytes); return true; },
      upload: async (source, _folderId, _name, area) => {
        assert.equal(area, "uploads");
        remoteBytes = fs.readFileSync(source, "utf8");
        return { provider: "fixture" };
      },
    };
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(uploadPath, "selected archive bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      assert.equal(backup.metadata.cloudComplete, false);
      write(uploadPath, "live bytes before restore");
      remoteBytes = "live bytes before restore";
      backupService.setCloudStorage(cloud);
      restoreService.setCloudStorage(cloud);

      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(fs.readFileSync(uploadPath, "utf8"), "selected archive bytes");
      assert.equal(restored.cloudSync.state, "pending", "selected archive objects need durable reconciliation even when the provider inventory was incomplete at backup time");
      assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((entry) => entry.name === "same-name.txt"), true, "the stale provider object stays suppressed until the selected bytes are uploaded");

      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      const retryAt = Date.parse("2026-10-07T14:00:00.000Z");
      await restoreService.processRestoreSync({
        backupId: backup.id,
        workerId: "incomplete-backup-worker",
        clock: () => retryAt,
        uploader: { enabled: () => true, provider: "fixture", upload: async () => { throw new Error("injected provider outage"); } },
      });
      assert.equal(backupService.listBackups().find((entry) => entry.id === backup.id).metadata.restoreSync.entries[0].state, "retry_wait");
      assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((entry) => entry.name === "same-name.txt"), true, "a provider outage must not reveal stale bytes");

      await restoreService.processRestoreSync({ backupId: backup.id, workerId: "incomplete-backup-retry", clock: () => retryAt + 1000, uploader: cloud });

      assert.equal(remoteBytes, "selected archive bytes", "the selected archive is authoritative for the shared provider key");
      assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((entry) => entry.name === "same-name.txt"), false, "successful provider reconciliation releases the suppression");
      assert.equal(backupService.listBackups().find((entry) => entry.id === backup.id).metadata.restoreSync.state, "completed");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("falsey provider upload results keep restore sync retryable and suppress stale bytes", () => {
  runFixture(`
    const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
    const uploadPath = path.join(uploadsDir, "falsey-upload.txt");
    const remote = { bytes: "stale provider bytes" };
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "fixture", providerIdentity: "falsey-target", area: "uploads", folderId: "root", name: "falsey-upload.txt" }],
      download: async (_folderId, _name, target) => { write(target, remote.bytes); return true; },
      upload: async (source) => { remote.bytes = fs.readFileSync(source, "utf8"); return { provider: "fixture" }; },
    };
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(uploadPath, "ARCHIVED bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      write(uploadPath, "live bytes");
      remote.bytes = "live bytes";
      backupService.setCloudStorage(cloud);
      restoreService.setCloudStorage(cloud);
      await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      restoreService.prepareWholeRestoreStartup();
      restoreService.acknowledgeWholeRestoreInstance();

      let now = Date.now();
      for (const [attempt, result] of [[1, null], [2, false]]) {
        const uploader = { ...cloud, upload: async () => result };
        const latest = await restoreService.processRestoreSync({
          backupId: backup.id,
          workerId: "falsey-" + attempt,
          clock: () => now,
          uploader,
        });
        const entry = latest.metadata.restoreSync.entries[0];
        assert.equal(entry.state, "retry_wait", "falsey upload result " + result + " must not commit the restore sync entry");
        assert.equal(entry.attempts, attempt);
        assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((item) => item.name === "falsey-upload.txt"), true);
        now = Date.parse(entry.nextAttemptAt) + 1;
      }

      await restoreService.processRestoreSync({
        backupId: backup.id,
        workerId: "falsey-retry-success",
        clock: () => now,
        uploader: cloud,
      });
      assert.equal(backupService.listBackups().find((item) => item.id === backup.id).metadata.restoreSync.state, "completed");
      assert.equal(remote.bytes, "ARCHIVED bytes");
      assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((item) => item.name === "falsey-upload.txt"), false);
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});

test("restore provider reconciliation remains retryable after five failures and restart", { timeout: 30_000 }, () => {
  runFixture(`
    const { spawnSync } = require("node:child_process");
    const restorePath = require.resolve(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const backupRepositoryPath = require.resolve(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
    const uploadPath = path.join(uploadsDir, "retry-after-five.txt");
    let remoteBytes = "live before restore";
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(uploadPath, "selected archive bytes");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const cloud = {
        enabled: () => true,
        provider: "fixture",
        inventory: async () => [{ provider: "fixture", providerIdentity: "retry-target", area: "uploads", folderId: "root", name: "retry-after-five.txt" }],
        download: async (_folder, _name, target) => { write(target, remoteBytes); return true; },
        upload: async () => { throw new Error("fixture provider outage"); },
      };
      write(uploadPath, "live before restore");
      backupService.setCloudStorage(cloud); restoreService.setCloudStorage(cloud);
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(restored.cloudSync.state, "pending");
      restoreService.prepareWholeRestoreStartup();
      assert.equal(restoreService.acknowledgeWholeRestoreInstance().complete, true);
      let now = Date.parse("2026-10-07T14:00:00.000Z");
      let latest;
      for (let attempt = 1; attempt <= 5; attempt += 1) {
        latest = await restoreService.processRestoreSync({ backupId: backup.id, workerId: "failure-" + attempt, clock: () => now, uploader: cloud });
        const entry = latest.metadata.restoreSync.entries[0];
        assert.equal(entry.attempts, attempt);
        assert.equal(entry.state, "retry_wait", "provider reconciliation must remain resumable after every failed attempt");
        assert.equal(restoreService.isWholeRestoreBlocked(), false);
        assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((value) => value.name === "retry-after-five.txt"), true, "failed provider writes must keep stale bytes suppressed");
        now = Date.parse(entry.nextAttemptAt) + 1;
      }
      const retryAt = latest.metadata.restoreSync.entries[0].nextAttemptAt;
      const repository = require(backupRepositoryPath);
      const legacyTerminal = repository.mutateRestoreSyncEntry({
        backupId: backup.id,
        operationId: latest.metadata.restoreSync.operationId,
        entryId: latest.metadata.restoreSync.entries[0].entryId,
        expectedState: "retry_wait",
        expectedLeaseToken: null,
        expectedRevision: latest.metadata.restoreSync.revision,
        mutate: (entry) => ({
          entry: { ...entry, state: "terminal_failure", nextAttemptAt: null },
          details: { failureCategory: "provider_error" },
          at: new Date(now).toISOString(),
        }),
      });
      assert.equal(legacyTerminal.metadata.restoreSync.state, "terminal_failure", "fixture represents a persisted pre-retry-format record");
      const recoveryScript = [
        "const assert=require('node:assert/strict'),fs=require('node:fs'),restore=require(" + JSON.stringify(restorePath) + "),repository=require(" + JSON.stringify(backupRepositoryPath) + ");",
        "const provider={enabled:()=>true,provider:'fixture',inventory:async()=>[{area:'uploads',folderId:'root',name:'retry-after-five.txt'}],upload:async(source)=>{fs.writeFileSync('data/provider-object.txt',fs.readFileSync(source));return {provider:'fixture'};}};",
        "(async()=>{await restore.processRestoreSync({backupId:" + JSON.stringify(backup.id) + ",workerId:'after-five-restart',clock:()=>Date.parse(" + JSON.stringify(retryAt) + ")+1,uploader:provider});",
        "const backup=repository.getBackup(" + JSON.stringify(backup.id) + ");assert.equal(backup.metadata.restoreSync.state,'completed');assert.equal(backup.metadata.restoreSync.entries[0].attempts,6);",
        "assert.equal(fs.readFileSync('data/provider-object.txt','utf8'),'selected archive bytes');const policy=JSON.parse(fs.readFileSync('data/.rootark-restore-provider-orphans.json','utf8'));assert.equal(policy.objects.some(value=>value.name==='retry-after-five.txt'),false);",
        "console.log(JSON.stringify({ok:true}));})().catch(error=>{console.error(error);process.exit(1)});",
      ].join(" ");
      const restarted = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 20_000 });
      assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
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

test("cloud restore leaves newer local and provider pending bytes unchanged when the archive contains temp payloads", () => {
  runFixture(`
    const pendingPath = path.join(process.cwd(), "temp", "archived-pending.txt");
    let providerBytes = "archive pending bytes";
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "fixture", providerIdentity: "pending-object", area: "temp", folderId: "root", name: "archived-pending.txt" }],
      download: async (_folderId, _name, target) => { write(target, providerBytes); return true; },
      upload: async () => ({ provider: "fixture" }),
    };
    backupService.setCloudStorage(cloud);
    restoreService.setCloudStorage(cloud);
    (async () => {
      write(pendingPath, providerBytes);
      write(path.join(dataDir, "restore-state.json"), "archive state");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      assert.equal(backup.metadata.cloudComplete, true);
      const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
      const archive = await unzipper.Open.file(backupService.getBackupOrThrow(backup.id).archivePath);
      const manifest = JSON.parse((await archive.files.find((entry) => entry.path === "backup-manifest.json").buffer()).toString("utf8"));
      assert.ok(manifest.included_files.some((entry) => entry.path === "temp/archived-pending.txt"));

      providerBytes = "newer live pending bytes";
      write(pendingPath, providerBytes);
      write(path.join(dataDir, "restore-state.json"), "live state");
      await assert.rejects(restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" }), /Entrada nao permitida no backup: temp\\/archived-pending.txt/);
      assert.equal(fs.readFileSync(pendingPath, "utf8"), "newer live pending bytes");
      assert.equal(providerBytes, "newer live pending bytes");
      assert.equal(fs.readFileSync(path.join(dataDir, "restore-state.json"), "utf8"), "live state");
      assert.equal(restoreService.assertNoPendingWholeRestore().reason, "no_pending_restore");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `, { BACKUP_INCLUDE_TEMP: "true" });
});

test("manifest-only temp paths cannot exempt live provider temp objects from restore suppression", () => {
  runFixture(`
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    let providerBytes = "newer provider pending bytes";
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "fixture", providerIdentity: "pending-object", area: "temp", folderId: "root", name: "pending.txt" }],
      download: async (_folderId, _name, target) => { write(target, providerBytes); return true; },
      upload: async () => ({ provider: "fixture" }),
    };
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });
    (async () => {
      write(path.join(dataDir, "restore-state.json"), "selected archive state");
      const backup = await backupService.createBackup({ createdBy: "fixture" });
      const stored = backupService.getBackupOrThrow(backup.id);
      fs.rmSync(stored.archivePath);
      await backupService.createZipArchive(stored.archivePath, {
        backup_id: backup.id,
        included_files: [{ path: "temp/pending.txt", size: 20 }],
        cloud_complete: true,
      }, []);
      await backupRepository.saveBackup({ ...backup, checksum: null });

      backupService.setCloudStorage(cloud);
      restoreService.setCloudStorage(cloud);
      const restored = await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
      assert.equal(restored.cloudSync.state, "not_required");
      const policy = JSON.parse(fs.readFileSync(path.join(dataDir, ".rootark-restore-provider-orphans.json"), "utf8"));
      assert.deepEqual(policy.objects, [{ area: "temp", folderId: "root", name: "pending.txt" }]);
      assert.equal(providerBytes, "newer provider pending bytes");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
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

test("restore rollback restores the prior provider-orphan suppression policy and state", () => {
  runFixture(`
    const policyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
    const statePath = path.join(dataDir, ".rootark-restore-provider-orphans-state.json");
    const priorPolicy = JSON.stringify({ version: 1, providerInventory: { state: "known" }, objects: [{ area: "uploads", folderId: "root", name: "prior-orphan.txt" }] });
    const priorState = JSON.stringify({ version: 1, initializedAt: "2026-01-01T00:00:00.000Z", providerInventory: { state: "known" } });
    write(policyPath, priorPolicy);
    write(statePath, priorState);
    const cloud = {
      enabled: () => true,
      provider: "fixture",
      inventory: async () => [{ provider: "s3", providerIdentity: "restored", area: "uploads", folderId: "root", name: "restore.txt" }],
      download: async (_folderId, _name, target) => { fs.writeFileSync(target, "archive bytes"); return true; },
      upload: async () => ({ provider: "fixture" }),
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
      assert.equal(fs.readFileSync(statePath, "utf8"), priorState, "rollback restores the marker paired with the prior policy");
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
      const policyStatePath = path.join(dataDir, ".rootark-restore-provider-orphans-state.json");
      assert.equal(JSON.parse(fs.readFileSync(policyPath, "utf8")).objects.some((entry) => entry.area === "temp" && entry.name === "post-backup-pending.txt"), true, "the abrupt exit occurs after the new suppression policy is durable");
      assert.equal(fs.existsSync(policyStatePath), true, "the marker is durable before the restore transaction advances");
      const recoveryCode = [
        'const fs = require("node:fs");',
        "const restoreService = require(" + JSON.stringify(${JSON.stringify(path.join(ROOT, "services", "restoreService"))}) + ");",
        'const result = restoreService.assertNoPendingWholeRestore();',
        'const state = fs.readFileSync("data/restore-state.json", "utf8");',
        'const policyExists = fs.existsSync("data/.rootark-restore-provider-orphans.json");',
        'const policyStateExists = fs.existsSync("data/.rootark-restore-provider-orphans-state.json");',
        'process.stdout.write(JSON.stringify({ result, state, policyExists, policyStateExists }));',
      ].join("\\n");
      const restarted = childProcess.spawnSync(process.execPath, ["-e", recoveryCode], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 30_000 });
      assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
      const recovered = JSON.parse(restarted.stdout);
      assert.equal(recovered.result.recovered, true);
      assert.equal(recovered.state, "live state");
      assert.equal(recovered.policyExists, false, "restart rolls back the newly persisted suppression with the other local preimages");
      assert.equal(recovered.policyStateExists, false, "restart rolls back the newly persisted policy marker with the other local preimages");
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
        return { provider: "fixture" };
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
      let failureClockCalls = 0;
      await restoreService.processRestoreSync({
        backupId: backup.id,
        workerId: "provider-failure-worker",
        clock: () => (failureClockCalls++ === 0 ? initialNow : initialNow + 30_000),
        uploader: { enabled: () => true, provider: "s3", upload: async () => { throw new Error("injected provider outage"); } },
      });
      let saved = require(backupRepositoryPath).getBackup(backup.id);
      let entry = saved.metadata.restoreSync.entries[0];
      assert.equal(entry.state, "retry_wait");
      assert.equal(entry.attempts, 1);
      assert.equal(entry.failureCategory, "provider_error");
      assert.equal(entry.leaseToken, null);
      assert.equal(Date.parse(entry.nextAttemptAt), initialNow + 31_000, "backoff starts when provider failure is recorded, not before provider I/O");
      const retryNow = Date.parse(entry.nextAttemptAt) + 1000;

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
            return { provider: "s3" };
          },
        };
        restore.processRestoreSync({ backupId: \${JSON.stringify(backup.id)}, workerId: "restarted-worker", clock: () => \${workerNow}, leaseMs: 1000, uploader: provider })
          .then((result) => { assert.equal(result.metadata.restoreSync.entries[0].state, "completed"); })
          .catch((error) => { console.error(error); process.exitCode = 1; });
      \`;
      const interrupted = spawnSync(process.execPath, ["-e", worker(retryNow, true)], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(interrupted.status, 87, interrupted.stderr || interrupted.stdout);
      let providerState = JSON.parse(fs.readFileSync(providerStatePath, "utf8"));
      assert.equal(providerState.objects["uploads/root/provider-retry.txt"], Buffer.from("restored provider bytes").toString("base64"));
      saved = require(backupRepositoryPath).getBackup(backup.id);
      entry = saved.metadata.restoreSync.entries[0];
      assert.equal(entry.state, "in_progress", "the process interruption must leave a leased reconciliation for recovery");
      assert.equal(entry.attempts, 2);

      const retried = spawnSync(process.execPath, ["-e", worker(retryNow + 3000, false)], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(retried.status, 0, retried.stderr || retried.stdout);
      saved = require(backupRepositoryPath).getBackup(backup.id);
      entry = saved.metadata.restoreSync.entries[0];
      assert.equal(entry.state, "completed");
      assert.equal(entry.attempts, 3);
      providerState = JSON.parse(fs.readFileSync(providerStatePath, "utf8"));
      assert.equal(providerState.requests, 2, "the provider must see the retry after the interrupted upload");
      assert.deepEqual(Object.keys(providerState.objects), ["uploads/root/provider-retry.txt"], "retries overwrite one stable provider key");
      assert.equal(providerState.objects["uploads/root/provider-retry.txt"], Buffer.from("restored provider bytes").toString("base64"));

      const repeated = spawnSync(process.execPath, ["-e", worker(retryNow + 4000, false)], { cwd: process.cwd(), env: process.env, encoding: "utf8", timeout: 10_000 });
      assert.equal(repeated.status, 0, repeated.stderr || repeated.stdout);
      assert.equal(JSON.parse(fs.readFileSync(providerStatePath, "utf8")).requests, 2, "completed reconciliation must not upload again");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
});
