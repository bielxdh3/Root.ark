const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const test = require("node:test");

const restorePreimage = require("../services/restorePreimage");
const restoreService = require("../services/restoreService");
const ROOT = path.resolve(__dirname, "..");

function makeDatabaseFixture() {
  const originalEnv = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL };
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-journal-version-"));
  const sourceRoot = path.join(runtime, "source");
  const sourceData = path.join(sourceRoot, "data");
  const sourcePath = path.join(sourceData, "rootark.sqlite");
  const destinationPath = path.join(runtime, "configured.sqlite");
  fs.mkdirSync(sourceData, { recursive: true });
  for (const [pathname, value] of [[sourcePath, "replacement"], [destinationPath, "original"]]) {
    const database = new Database(pathname);
    database.exec("CREATE TABLE proof (value TEXT NOT NULL);");
    database.prepare("INSERT INTO proof(value) VALUES (?)").run(value);
    database.close();
  }
  process.env.DB_ENABLED = "true";
  process.env.DATABASE_URL = destinationPath;
  return {
    runtime, sourceRoot, destinationPath,
    cleanup() {
      fs.rmSync(runtime, { recursive: true, force: true });
      if (originalEnv.DB_ENABLED === undefined) delete process.env.DB_ENABLED; else process.env.DB_ENABLED = originalEnv.DB_ENABLED;
      if (originalEnv.DATABASE_URL === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = originalEnv.DATABASE_URL;
    },
  };
}

function interruptDatabaseRestore(fixture, failAt = "replacement.move.primary") {
  assert.throws(() => restoreService.restoreDatabaseFiles(fixture.sourceRoot, { failAt, simulateCrash: true }), /Falha injetada/);
  const journalPath = restoreService.databaseJournalPath(fixture.destinationPath);
  return { journalPath, journal: JSON.parse(fs.readFileSync(journalPath, "utf8")) };
}

function readDatabaseValue(pathname) {
  const database = new Database(pathname, { readonly: true });
  try { return database.prepare("SELECT value FROM proof").get().value; }
  finally { database.close(); }
}

function interruptWholeRestore() {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-coordinator-version-"));
  const quarantineDir = path.join(runtime, "quarantine");
  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_)/i.test(key))),
    NODE_ENV: "test",
    DB_ENABLED: "false",
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "legacy-restore-fixture",
    UPLOAD_QUARANTINE_DIR: quarantineDir,
  };
  const script = `
    const fs = require("node:fs");
    const path = require("node:path");
    const backup = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restore = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const write = (pathname, contents) => { fs.mkdirSync(path.dirname(pathname), { recursive: true }); fs.writeFileSync(pathname, contents); };
    fs.mkdirSync("data", { recursive: true }); fs.mkdirSync("uploads", { recursive: true });
    fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
    write("data/runtime.json", "backup-json"); write("uploads/file.txt", "backup-upload");
    (async () => {
      const selected = await backup.createBackup({ createdBy: "fixture" });
      write("data/runtime.json", "live-json"); write("uploads/file.txt", "live-upload");
      await restore.restoreBackup(selected.id, {
        confirmation: "RESTORE",
        failureInjector(step) { if (step === "restore.preimage.completed") process.exit(86); },
      });
      process.exit(0);
    })().catch((error) => { console.error(error); process.exit(1); });
  `;
  const interrupted = spawnSync(process.execPath, ["-e", script], { cwd: runtime, env, encoding: "utf8", timeout: 30_000 });
  assert.equal(interrupted.status, 86, interrupted.stderr || interrupted.stdout);
  const coordinatorPath = path.join(runtime, "data", ".rootark-restore-coordinator.json");
  const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, "utf8"));
  const manifestPath = path.join(runtime, "data", "backups", ".restore-preimages", coordinator.transactionId, "manifest.json");
  return { runtime, env, coordinatorPath, coordinator, manifestPath };
}

test("tree rollback restores the source root directory mode", (t) => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-root-mode-"));
  const treeRoot = path.join(runtime, "tree");
  const snapshotRoot = path.join(runtime, "snapshot");
  const requestedMode = 0o751;
  try {
    fs.mkdirSync(treeRoot);
    fs.writeFileSync(path.join(treeRoot, "entry.txt"), "original");
    fs.chmodSync(treeRoot, requestedMode);
    const sourceMode = fs.statSync(treeRoot).mode & 0o777;
    const snapshot = restorePreimage.snapshotTree(treeRoot, snapshotRoot);

    assert.equal(snapshot.rootMode, sourceMode, "the snapshot contract retains the root mode");
    fs.rmSync(treeRoot, { recursive: true });
    restorePreimage.restoreTree(treeRoot, snapshotRoot, snapshot, crypto.randomUUID());

    if (process.platform === "win32" && sourceMode !== requestedMode) {
      t.diagnostic("Windows did not preserve the requested POSIX mode; root mode round-trip assertion skipped");
    } else {
      assert.equal(fs.statSync(treeRoot).mode & 0o777, sourceMode, "rollback restores the source root mode");
    }
    assert.equal(fs.readFileSync(path.join(treeRoot, "entry.txt"), "utf8"), "original");
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("tree rollback keeps recreated entries accessible when their pre-image used group-only modes", (t) => {
  if (process.platform === "win32") {
    t.skip("Windows does not expose portable POSIX owner/group permission semantics");
    return;
  }

  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-group-access-"));
  const treeRoot = path.join(runtime, "tree");
  const nestedRoot = path.join(treeRoot, "nested");
  const snapshotRoot = path.join(runtime, "snapshot");
  try {
    fs.mkdirSync(nestedRoot, { recursive: true });
    fs.writeFileSync(path.join(nestedRoot, "entry.txt"), "original");
    const snapshot = restorePreimage.snapshotTree(treeRoot, snapshotRoot);
    snapshot.rootMode = 0o070;
    for (const entry of snapshot.entries) entry.mode = entry.type === "directory" ? 0o070 : 0o060;

    fs.rmSync(treeRoot, { recursive: true });
    restorePreimage.restoreTree(treeRoot, snapshotRoot, snapshot, crypto.randomUUID());

    assert.equal(fs.statSync(treeRoot).mode & 0o777, 0o770, "group traversal is retained for the service-owned restored root");
    assert.equal(fs.statSync(nestedRoot).mode & 0o777, 0o770, "nested group traversal is retained for the service-owned directory");
    assert.equal(fs.statSync(path.join(nestedRoot, "entry.txt")).mode & 0o777, 0o660, "group file access is retained for the service-owned file");
    assert.equal(fs.readFileSync(path.join(nestedRoot, "entry.txt"), "utf8"), "original");
  } finally {
    if (fs.existsSync(treeRoot)) {
      fs.chmodSync(treeRoot, 0o700);
      if (fs.existsSync(nestedRoot)) {
        fs.chmodSync(nestedRoot, 0o700);
        const entryPath = path.join(nestedRoot, "entry.txt");
        if (fs.existsSync(entryPath)) fs.chmodSync(entryPath, 0o600);
      }
    }
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("tree rollback rejects invalid snapshot entry modes before removing the destination", () => {
  const cases = [
    { type: "directory", mode: 0o1000 },
    { type: "file", mode: -1 },
    { type: "directory", mode: 1.5 },
    { type: "file", mode: "0600" },
  ];
  for (const invalid of cases) {
    const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-invalid-mode-"));
    const sourceRoot = path.join(runtime, "source");
    const treeRoot = path.join(runtime, "tree");
    const snapshotRoot = path.join(runtime, "snapshot");
    try {
      fs.mkdirSync(path.join(sourceRoot, "nested"), { recursive: true });
      fs.writeFileSync(path.join(sourceRoot, "nested", "entry.txt"), "archived");
      const snapshot = restorePreimage.snapshotTree(sourceRoot, snapshotRoot);
      snapshot.entries.find((entry) => entry.type === invalid.type).mode = invalid.mode;
      fs.mkdirSync(path.join(treeRoot, "nested"), { recursive: true });
      fs.writeFileSync(path.join(treeRoot, "nested", "entry.txt"), "live destination");

      assert.throws(() => restorePreimage.restoreTree(treeRoot, snapshotRoot, snapshot, crypto.randomUUID()), /entry mode is invalid/i);
      assert.equal(fs.readFileSync(path.join(treeRoot, "nested", "entry.txt"), "utf8"), "live destination", "invalid metadata is rejected before destination content changes");
    } finally {
      fs.rmSync(runtime, { recursive: true, force: true });
    }
  }
});

test("journal recovery rejects a wrong destination when its original rollback file is missing", () => {
  const originalEnv = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL };
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-journal-hash-"));
  const sourceRoot = path.join(runtime, "source");
  const sourceData = path.join(sourceRoot, "data");
  const sourcePath = path.join(sourceData, "rootark.sqlite");
  const destinationPath = path.join(runtime, "configured.sqlite");
  let journalPath;
  let rollbackPath;
  fs.mkdirSync(sourceData, { recursive: true });
  for (const [pathname, value] of [[sourcePath, "replacement"], [destinationPath, "original"]]) {
    const database = new Database(pathname);
    database.exec("CREATE TABLE proof (value TEXT NOT NULL);");
    database.prepare("INSERT INTO proof(value) VALUES (?)").run(value);
    database.close();
  }
  process.env.DB_ENABLED = "true";
  process.env.DATABASE_URL = destinationPath;

  try {
    assert.throws(() => restoreService.restoreDatabaseFiles(sourceRoot, {
      failAt: "original.move.primary",
      simulateCrash: true,
    }), /Falha injetada/);
    journalPath = restoreService.databaseJournalPath(destinationPath);
    const journal = JSON.parse(fs.readFileSync(journalPath, "utf8"));
    rollbackPath = journal.rollbackPrefix;
    fs.rmSync(rollbackPath, { force: true });
    fs.writeFileSync(destinationPath, "wrong replacement at original path");

    assert.throws(() => restoreService.recoverDatabaseRestore(destinationPath), /hash|integrity|original/i);
    assert.equal(fs.readFileSync(destinationPath, "utf8"), "wrong replacement at original path", "failed recovery leaves the unverified destination untouched");
    assert.equal(fs.existsSync(journalPath), true, "failed recovery retains its journal for manual recovery");
  } finally {
    if (journalPath) fs.rmSync(journalPath, { force: true });
    if (rollbackPath) fs.rmSync(rollbackPath, { force: true });
    fs.rmSync(runtime, { recursive: true, force: true });
    if (originalEnv.DB_ENABLED === undefined) delete process.env.DB_ENABLED; else process.env.DB_ENABLED = originalEnv.DB_ENABLED;
    if (originalEnv.DATABASE_URL === undefined) delete process.env.DATABASE_URL; else process.env.DATABASE_URL = originalEnv.DATABASE_URL;
  }
});

test("new SQLite restore writes version 2 journals", () => {
  const fixture = makeDatabaseFixture();
  try {
    const { journal } = interruptDatabaseRestore(fixture, "stage.copy.primary");
    assert.equal(journal.version, 2);
    restoreService.recoverDatabaseRestore(fixture.destinationPath);
  } finally { fixture.cleanup(); }
});

test("legacy SQLite version 1 journal recovers when its original hashes verify", () => {
  const fixture = makeDatabaseFixture();
  try {
    const { journalPath, journal } = interruptDatabaseRestore(fixture);
    journal.version = 1;
    fs.writeFileSync(journalPath, JSON.stringify(journal));

    assert.equal(restoreService.recoverDatabaseRestore(fixture.destinationPath).phase, "rolled_back");
    assert.equal(readDatabaseValue(fixture.destinationPath), "original");
  } finally { fixture.cleanup(); }
});

test("legacy SQLite committed journal cleans up without requiring an unused original hash", () => {
  const fixture = makeDatabaseFixture();
  try {
    assert.equal(restoreService.restoreDatabaseFiles(fixture.sourceRoot), true);
    const journalPath = restoreService.databaseJournalPath(fixture.destinationPath);
    const transactionId = crypto.randomUUID();
    fs.writeFileSync(journalPath, JSON.stringify({
      version: 1,
      transactionId,
      destination: path.resolve(fixture.destinationPath),
      journalPath,
      stagePrefix: `${fixture.destinationPath}.restore-stage-${transactionId}`,
      rollbackPrefix: `${fixture.destinationPath}.restore-rollback-${transactionId}`,
      phase: "committed",
      originalPresent: { "": true, "-wal": false, "-shm": false },
      stagedPresent: { "": true, "-wal": false, "-shm": false },
      completedOperations: [],
    }));

    assert.equal(restoreService.recoverDatabaseRestore(fixture.destinationPath).phase, "committed");
    assert.equal(readDatabaseValue(fixture.destinationPath), "replacement");
  } finally { fixture.cleanup(); }
});

test("legacy SQLite version 1 journal without original hashes fails closed", () => {
  const fixture = makeDatabaseFixture();
  try {
    const { journalPath, journal } = interruptDatabaseRestore(fixture);
    journal.version = 1;
    delete journal.originalSha256;
    fs.writeFileSync(journalPath, JSON.stringify(journal));
    fs.rmSync(journal.rollbackPrefix, { force: true });

    assert.throws(() => restoreService.recoverDatabaseRestore(fixture.destinationPath), /ambiguous|manual recovery/i);
    assert.equal(readDatabaseValue(fixture.destinationPath), "replacement", "ambiguous recovery does not overwrite the unverified destination");
    assert.equal(fs.existsSync(journal.rollbackPrefix), false, "the fixture represents a lost legacy pre-image");
    assert.equal(fs.existsSync(journalPath), true, "ambiguous recovery retains its journal");
  } finally { fixture.cleanup(); }
});

test("legacy whole-restore version 3 pre-image recovery remains explicit about missing root modes", () => {
  const fixture = interruptWholeRestore();
  try {
    assert.equal(fixture.coordinator.version, 4, "new coordinators use the versioned root-mode contract");
    const manifest = JSON.parse(fs.readFileSync(fixture.manifestPath, "utf8"));
    assert.equal(manifest.version, 2, "new pre-image manifests use the root-mode contract");

    fixture.coordinator.version = 3;
    manifest.version = 1;
    for (const domain of manifest.domains) if (domain.kind === "tree") delete domain.snapshot.rootMode;
    const manifestContents = `${JSON.stringify(manifest)}\n`;
    fs.writeFileSync(fixture.manifestPath, manifestContents);
    fixture.coordinator.preimageHash = crypto.createHash("sha256").update(manifestContents).digest("hex");
    fs.writeFileSync(fixture.coordinatorPath, `${JSON.stringify(fixture.coordinator, null, 2)}\n`);

    const recoveryScript = `
      const assert = require("node:assert/strict");
      const fs = require("node:fs");
      const restore = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      const result = restore.assertNoPendingWholeRestore();
      assert.equal(result.recovered, true);
      assert.equal(result.legacyRootModeUnverifiable, true);
      assert.equal(fs.readFileSync("data/runtime.json", "utf8"), "live-json");
      assert.equal(fs.readFileSync("uploads/file.txt", "utf8"), "live-upload");
      console.log(JSON.stringify({ ok: true }));
    `;
    const recovered = spawnSync(process.execPath, ["-e", recoveryScript], { cwd: fixture.runtime, env: fixture.env, encoding: "utf8", timeout: 30_000 });
    assert.equal(recovered.status, 0, recovered.stderr || recovered.stdout);
    assert.equal(JSON.parse(recovered.stdout.trim().split(/\r?\n/).at(-1)).ok, true);
  } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
});
