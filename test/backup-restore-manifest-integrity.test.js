const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");

function runFixture(body, envOverrides = {}, timeoutMs = 30_000) {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-restore-manifest-runtime-"));
  const quarantineDir = path.join(runtime, "quarantine");
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const backupRepository = require(${JSON.stringify(path.join(ROOT, "repositories", "backupRepository"))});
    const database = require(${JSON.stringify(path.join(ROOT, "db"))});
    const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
    const dataDir = path.join(process.cwd(), "data");
    let archiveNumber = 0;
    fs.mkdirSync(dataDir, { recursive: true });
    fs.mkdirSync(path.join(process.cwd(), "uploads"), { recursive: true });
    fs.mkdirSync(path.join(process.cwd(), "temp"), { recursive: true });
    fs.mkdirSync(process.env.UPLOAD_QUARANTINE_DIR, { recursive: true });
    backupService.setCloudStorage({ enabled: () => false });
    restoreService.setCloudStorage({ enabled: () => false });

    const makeArchive = async (id, manifest, files) => {
      const archivePath = path.join(backupService.BACKUPS_DIR, "fixture-" + (++archiveNumber) + ".zip");
      fs.mkdirSync(path.dirname(archivePath), { recursive: true });
      const zipFiles = files.map(({ entryPath, contents }) => {
        const bytes = Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
        return { entryPath, contents: bytes, size: bytes.length };
      });
      await backupService.createZipArchive(archivePath, { ...manifest, backup_id: id }, zipFiles);
      return archivePath;
    };
    const readArchiveManifest = async (archivePath) => {
      const archive = await unzipper.Open.file(archivePath);
      const entry = archive.files.find((file) => file.path === "backup-manifest.json");
      return JSON.parse((await entry.buffer()).toString("utf8"));
    };

    (async () => {
      try {
        ${body}
        console.log(JSON.stringify({ ok: true }));
      } finally {
        database.closeDb();
      }
    })().catch((error) => {
      console.error(error.stack || error);
      process.exitCode = 1;
    });
  `;
  const env = {
    ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^(AWS_|GOOGLE_|CLOUD_STORAGE_|S3_|GDRIVE_|DRIVE_)/i.test(key))),
    NODE_ENV: "test",
    DB_ENABLED: "false",
    DATABASE_URL: path.join(runtime, "data", "rootark.sqlite"),
    BACKUP_ENABLED: "true",
    BACKUP_INCLUDE_UPLOADS: "true",
    BACKUP_INCLUDE_TEMP: "false",
    BACKUP_RETENTION_COUNT: "20",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "manifest-fixture-single",
    UPLOAD_QUARANTINE_DIR: quarantineDir,
    ...envOverrides,
  };

  try {
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: runtime,
      env,
      encoding: "utf8",
      timeout: timeoutMs,
    });
    assert.equal(result.status, 0, [
      `spawn error: ${result.error?.message || "none"}`,
      `signal: ${result.signal || "none"}`,
      `stderr:\\n${result.stderr || ""}`,
      `stdout:\\n${result.stdout || ""}`,
    ].join("\\n"));
    const outcome = JSON.parse(result.stdout.trim().split(/\\r?\\n/).at(-1));
    assert.equal(outcome.ok, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
}

test("included_files rejects a ZIP payload member omitted from the manifest", () => {
  runFixture(`
    const archivePath = await makeArchive("omitted-payload", {
      persistence_mode: "json",
      included_files: [],
    }, [{ entryPath: "data/extra.json", contents: "{}" }]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "omitted-payload" }, archivePath),
      /included_files/i,
    );
  `);
});

test("included_files rejects a manifest member omitted from the ZIP payload", () => {
  runFixture(`
    const archivePath = await makeArchive("missing-payload", {
      persistence_mode: "json",
      included_files: [{ path: "data/missing.json", size: 2 }],
    }, []);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "missing-payload" }, archivePath),
      /included_files/i,
    );
  `);
});

test("included_files rejects a payload size that differs from the ZIP member", () => {
  runFixture(`
    const archivePath = await makeArchive("wrong-size", {
      persistence_mode: "json",
      included_files: [{ path: "data/state.json", size: 3 }],
    }, [{ entryPath: "data/state.json", contents: "{}" }]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "wrong-size" }, archivePath),
      /included_files/i,
    );
  `);
});

test("backup creation fails when the source stream yields more bytes than collected", () => {
  runFixture(`
    const filePath = path.join(dataDir, "settings.json");
    const backupId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    fs.writeFileSync(filePath, "initial");
    const originalCreateReadStream = fs.createReadStream;
    const { Readable } = require("node:stream");
    fs.createReadStream = function (file, options) {
      if (file === null && options?.fd !== undefined) {
        const source = originalCreateReadStream.call(this, file, options);
        return Readable.from((async function* changedSourceStream() {
          for await (const chunk of source) yield chunk;
          yield Buffer.from("changed");
        })());
      }
      return originalCreateReadStream.apply(this, arguments);
    };
    try {
      await assert.rejects(backupService.createBackup({ createdBy: "fixture", backupId }));
    } finally {
      fs.createReadStream = originalCreateReadStream;
    }
    const failed = backupRepository.getBackup(backupId);
    assert.equal(failed.status, "failed");
    assert.equal(fs.existsSync(backupService.getArchivePath(failed.filename)), false);
  `);
});

test("backup creation fails when source contents change in place without changing size", () => {
  runFixture(`
    const filePath = path.join(dataDir, "settings.json");
    const backupId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    const originalBytes = Buffer.alloc(1024 * 1024, 0x41);
    const changedBytes = Buffer.alloc(originalBytes.length, 0x42);
    fs.writeFileSync(filePath, originalBytes);
    const originalCreateReadStream = fs.createReadStream;
    const { Readable } = require("node:stream");
    let mutated = false;
    fs.createReadStream = function (file, options) {
      if (file === null && options?.fd !== undefined && !mutated) {
        const source = originalCreateReadStream.call(this, file, options);
        return Readable.from((async function* changedSourceStream() {
          for await (const chunk of source) {
            yield chunk;
            if (!mutated) {
              mutated = true;
              fs.writeFileSync(filePath, changedBytes);
            }
          }
        })());
      }
      return originalCreateReadStream.apply(this, arguments);
    };
    try {
      await assert.rejects(backupService.createBackup({ createdBy: "fixture", backupId }));
    } finally {
      fs.createReadStream = originalCreateReadStream;
    }
    assert.equal(mutated, true);
    const failed = backupRepository.getBackup(backupId);
    assert.equal(failed.status, "failed");
    assert.equal(fs.existsSync(backupService.getArchivePath(failed.filename)), false);
  `);
});

test("restore rejects inflated ZIP payload bytes beyond the manifest and central-directory size", () => {
  runFixture(`
    const backupId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const filename = "rootark-backup-2026-01-01-00-00-00.zip";
    const archivePath = backupService.getArchivePath(filename);
    const expandedPath = "uploads/expanded.bin";
    const archiveBytesExpected = Buffer.alloc(38, 0x61);
    fs.mkdirSync(path.dirname(archivePath), { recursive: true });
    await backupService.createZipArchive(archivePath, {
      backup_id: backupId,
      persistence_mode: "json",
      included_files: [{ path: expandedPath, size: 0 }],
    }, [{ entryPath: expandedPath, contents: archiveBytesExpected, size: 0 }]);

    const zipBytes = fs.readFileSync(archivePath);
    const entryName = Buffer.from(expandedPath);
    let centralDirectoryOffset = -1;
    for (let offset = 0; offset <= zipBytes.length - 46; offset += 1) {
      if (zipBytes.readUInt32LE(offset) !== 0x02014b50) continue;
      const nameLength = zipBytes.readUInt16LE(offset + 28);
      if (zipBytes.subarray(offset + 46, offset + 46 + nameLength).equals(entryName)) {
        centralDirectoryOffset = offset;
        break;
      }
    }
    assert.notEqual(centralDirectoryOffset, -1);
    zipBytes.writeUInt32LE(0, centralDirectoryOffset + 24);
    fs.writeFileSync(archivePath, zipBytes);
    backupRepository.saveBackup({
      id: backupId,
      filename,
      status: "success",
      sizeBytes: zipBytes.length,
      checksum: null,
      metadata: {},
    });

    const liveFile = path.join(process.cwd(), expandedPath);
    fs.writeFileSync(liveFile, "live bytes");
    await assert.rejects(
      restoreService.restoreBackup(backupId, { confirmation: "RESTORE" }),
      /size|inflated|declared/i,
    );
    assert.equal(fs.readFileSync(liveFile, "utf8"), "live bytes");
    assert.equal(backupRepository.listBackups().some((backup) => backup.type === "pre-restore"), false);
  `);
});

test("a declared SQLite persistence mode is rejected by the JSON runtime", () => {
  runFixture(`
    const archivePath = await makeArchive("declared-sqlite", {
      persistence_mode: "sqlite",
      included_files: [],
    }, []);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "declared-sqlite" }, archivePath),
      /persistence mode/i,
    );
  `);
});

test("JSON persistence rejects a declared JSON archive containing SQLite payload", () => {
  runFixture(`
    const contents = Buffer.from("disposable sqlite fixture");
    const archivePath = await makeArchive("json-with-sqlite", {
      persistence_mode: "json",
      included_files: [{ path: "data/rootark.sqlite", size: contents.length }],
    }, [{ entryPath: "data/rootark.sqlite", contents }]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "json-with-sqlite" }, archivePath),
      /SQLite|database/i,
    );
  `);
});

test("legacy JSON runtime rejects an archive with a SQLite member", () => {
  runFixture(`
    const archivePath = await makeArchive("legacy-json-with-sqlite", {}, [
      { entryPath: "data/rootark.sqlite", contents: "disposable sqlite fixture" },
    ]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "legacy-json-with-sqlite" }, archivePath),
      /SQLite|database/i,
    );
  `);
});

test("SQLite runtime rejects a missing legacy primary database member", () => {
  runFixture(`
    const archivePath = await makeArchive("legacy-sqlite-missing", {}, [
      { entryPath: "data/settings.json", contents: "{}" },
    ]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "legacy-sqlite-missing" }, archivePath),
      /SQLite|database/i,
    );
  `, { DB_ENABLED: "true" });
});

test("SQLite runtime rejects a cased alias instead of silently skipping the database", () => {
  runFixture(`
    const archivePath = await makeArchive("legacy-sqlite-cased", {}, [
      { entryPath: "data/ROOTARK.SQLITE", contents: "disposable sqlite fixture" },
    ]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "legacy-sqlite-cased" }, archivePath),
      /canonical|SQLite|database/i,
    );
  `, { DB_ENABLED: "true" });
});

test("SQLite archives reject sidecar members instead of skipping them during replacement", () => {
  runFixture(`
    const archivePath = await makeArchive("sqlite-with-sidecar", {}, [
      { entryPath: "data/rootark.sqlite", contents: "disposable sqlite fixture" },
      { entryPath: "data/rootark.sqlite-wal", contents: "disposable wal fixture" },
    ]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "sqlite-with-sidecar" }, archivePath),
      /canonical|sidecar|SQLite|database/i,
    );
  `, { DB_ENABLED: "true" });
});

test("archives reject unsupported rootark.sqlite prefix members", () => {
  runFixture(`
    const archivePath = await makeArchive("sqlite-prefix", {}, [
      { entryPath: "data/rootark.sqlite-backup", contents: "disposable fixture" },
    ]);
    await assert.rejects(
      restoreService.validateBackupArchive({ id: "sqlite-prefix" }, archivePath),
      /canonical|SQLite|database/i,
    );
  `);
});

test("SQLite runtime accepts a legacy archive with the canonical primary database member", () => {
  runFixture(`
    const archivePath = await makeArchive("legacy-sqlite-valid", {}, [
      { entryPath: "data/rootark.sqlite", contents: "disposable sqlite fixture" },
    ]);
    await assert.doesNotReject(
      restoreService.validateBackupArchive({ id: "legacy-sqlite-valid" }, archivePath),
    );
  `, { DB_ENABLED: "true" });
});

test("JSON runtime accepts a legacy archive with no SQLite member", () => {
  runFixture(`
    const archivePath = await makeArchive("legacy-json-valid", {}, [
      { entryPath: "data/settings.json", contents: "{}" },
    ]);
    await assert.doesNotReject(
      restoreService.validateBackupArchive({ id: "legacy-json-valid" }, archivePath),
    );
  `);
});

test("new JSON backups declare JSON persistence mode", () => {
  runFixture(`
    fs.writeFileSync(path.join(dataDir, "settings.json"), "{}");
    const backup = await backupService.createBackup({ createdBy: "fixture" });
    const { archivePath } = backupService.getBackupOrThrow(backup.id);
    const manifest = await readArchiveManifest(archivePath);
    assert.equal(manifest.persistence_mode, "json");
    assert.ok(manifest.included_files.some((entry) => entry.path === "data/settings.json"));
    assert.equal(manifest.included_files.some((entry) => entry.path === "data/rootark.sqlite"), false);
  `);
});

test("restart recovery keeps a JSON restore blocked when SQLite is enabled after restart", () => {
  runFixture(`
    const { spawnSync } = require("node:child_process");
    const Database = require(process.env.ROOTARK_TEST_SQLITE_MODULE);
    const backupId = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const staleDb = new Database(process.env.DATABASE_URL);
    staleDb.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('stale-sqlite');");
    staleDb.close();
    const jsonPath = path.join(dataDir, "runtime.json");
    fs.writeFileSync(jsonPath, "backup-json");
    const backup = await backupService.createBackup({ createdBy: "fixture", backupId });
    fs.writeFileSync(jsonPath, "live-json");
    await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
    assert.equal(fs.readFileSync(jsonPath, "utf8"), "backup-json");

    const startupScript = [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const restoreService = require(process.env.ROOTARK_TEST_RESTORE_SERVICE);",
      "const Database = require(process.env.ROOTARK_TEST_SQLITE_MODULE);",
      "const database = require(process.env.ROOTARK_TEST_DATABASE_MODULE);",
      "const coordinatorPath = path.join(process.cwd(), 'data', '.rootark-restore-coordinator.json');",
      "const persistedMode = JSON.parse(fs.readFileSync(coordinatorPath, 'utf8')).persistenceMode || null;",
      "let startupRejected = false;",
      "let preparationRejected = false;",
      "let acknowledgementRejected = false;",
      "let acknowledgement = null;",
      "try { restoreService.assertNoPendingWholeRestore(); } catch { startupRejected = true; }",
      "try { restoreService.prepareWholeRestoreStartup(); } catch { preparationRejected = true; }",
      "try { acknowledgement = restoreService.acknowledgeWholeRestoreInstance(); } catch { acknowledgementRejected = true; }",
      "const staleDb = new Database(process.env.DATABASE_URL, { readonly: true });",
      "let staleSqliteValue;",
      "try { staleSqliteValue = staleDb.prepare('SELECT value FROM proof').get().value; } finally { staleDb.close(); }",
      "console.log(JSON.stringify({ configuredMode: database.isDbEnabled() ? 'sqlite' : 'json', persistedMode, startupRejected, preparationRejected, acknowledgementRejected, barrierRemaining: restoreService.isWholeRestoreBlocked(), acknowledgementComplete: acknowledgement?.complete || false, staleSqliteValue }));",
    ].join("\\n");
    const restarted = spawnSync(process.execPath, ["-e", startupScript], {
      cwd: process.cwd(),
      env: { ...process.env, DB_ENABLED: "true" },
      encoding: "utf8",
      timeout: 15_000,
    });
    assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
    const outcome = JSON.parse(restarted.stdout.trim().split(/\\r?\\n/).at(-1));
    assert.deepEqual(outcome, {
      configuredMode: "sqlite",
      persistedMode: "json",
      startupRejected: true,
      preparationRejected: true,
      acknowledgementRejected: true,
      barrierRemaining: true,
      acknowledgementComplete: false,
      staleSqliteValue: "stale-sqlite",
    }, "Restart with DB_ENABLED=true observed " + JSON.stringify(outcome));
  `, {
    ROOTARK_TEST_RESTORE_SERVICE: path.join(ROOT, "services", "restoreService"),
    ROOTARK_TEST_SQLITE_MODULE: path.join(ROOT, "node_modules", "better-sqlite3"),
    ROOTARK_TEST_DATABASE_MODULE: path.join(ROOT, "db"),
  });
});

test("restart recovery keeps a SQLite restore blocked when JSON is enabled after restart", () => {
  runFixture(`
    const { spawnSync } = require("node:child_process");
    const Database = require(process.env.ROOTARK_TEST_SQLITE_MODULE);
    const backupId = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";
    const sqlite = new Database(process.env.DATABASE_URL);
    sqlite.exec("CREATE TABLE proof (value TEXT NOT NULL); INSERT INTO proof VALUES ('backup-sqlite');");
    sqlite.close();
    const jsonPath = path.join(dataDir, "runtime.json");
    fs.writeFileSync(jsonPath, "backup-json");
    const backup = await backupService.createBackup({ createdBy: "fixture", backupId });
    fs.writeFileSync(jsonPath, "live-json");
    const liveDb = database.getDb();
    liveDb.exec("UPDATE proof SET value = 'live-sqlite';");
    database.closeDb();
    await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE" });
    assert.equal(fs.readFileSync(jsonPath, "utf8"), "backup-json");

    const startupScript = [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const restoreService = require(process.env.ROOTARK_TEST_RESTORE_SERVICE);",
      "const coordinatorPath = path.join(process.cwd(), 'data', '.rootark-restore-coordinator.json');",
      "const coordinator = JSON.parse(fs.readFileSync(coordinatorPath, 'utf8'));",
      "const acknowledgementPath = path.join(process.cwd(), 'data', '.rootark-restore-restart-acks', coordinator.transactionId);",
      "let startupRejected = false;",
      "let preparationRejected = false;",
      "let acknowledgementRejected = false;",
      "let acknowledgement = null;",
      "try { restoreService.assertNoPendingWholeRestore(); } catch { startupRejected = true; }",
      "try { restoreService.prepareWholeRestoreStartup(); } catch { preparationRejected = true; }",
      "try { acknowledgement = restoreService.acknowledgeWholeRestoreInstance(); } catch { acknowledgementRejected = true; }",
      "console.log(JSON.stringify({ configuredMode: 'json', persistedMode: coordinator.persistenceMode || null, startupRejected, preparationRejected, acknowledgementRejected, barrierRemaining: restoreService.isWholeRestoreBlocked(), acknowledgementComplete: acknowledgement?.complete || false, acknowledgementFiles: fs.existsSync(acknowledgementPath) ? fs.readdirSync(acknowledgementPath).length : 0 }));",
    ].join("\\n");
    const restarted = spawnSync(process.execPath, ["-e", startupScript], {
      cwd: process.cwd(),
      env: { ...process.env, DB_ENABLED: "false" },
      encoding: "utf8",
      timeout: 15_000,
    });
    assert.equal(restarted.status, 0, restarted.stderr || restarted.stdout);
    const outcome = JSON.parse(restarted.stdout.trim().split(/\\r?\\n/).at(-1));
    assert.deepEqual(outcome, {
      configuredMode: "json",
      persistedMode: "sqlite",
      startupRejected: true,
      preparationRejected: true,
      acknowledgementRejected: true,
      barrierRemaining: true,
      acknowledgementComplete: false,
      acknowledgementFiles: 0,
    }, "Restart with DB_ENABLED=false observed " + JSON.stringify(outcome));
  `, {
    DB_ENABLED: "true",
    ROOTARK_TEST_RESTORE_SERVICE: path.join(ROOT, "services", "restoreService"),
    ROOTARK_TEST_SQLITE_MODULE: path.join(ROOT, "node_modules", "better-sqlite3"),
  });
});

test("restart recovery keeps a legacy v4 coordinator without a persistence mode blocked", () => {
  runFixture(`
    const transactionId = "ffffffff-ffff-4fff-8fff-ffffffffffff";
    const backupId = "11111111-1111-4111-8111-111111111111";
    const preRestoreBackupId = "22222222-2222-4222-8222-222222222222";
    const coordinatorPath = path.join(dataDir, ".rootark-restore-coordinator.json");
    const acknowledgementPath = path.join(dataDir, ".rootark-restore-restart-acks", transactionId);
    fs.writeFileSync(coordinatorPath, JSON.stringify({
      version: 4,
      transactionId,
      phase: "restart_required",
      backupId,
      preRestoreBackupId,
      requiredRestartInstances: 1,
    }));

    assert.throws(() => restoreService.assertNoPendingWholeRestore(), /persistence mode is missing or invalid/i);
    assert.throws(() => restoreService.prepareWholeRestoreStartup(), /persistence mode is missing or invalid/i);
    assert.throws(() => restoreService.acknowledgeWholeRestoreInstance(), /persistence mode is missing or invalid/i);
    assert.equal(restoreService.isWholeRestoreBlocked(), true);
    assert.equal(fs.existsSync(coordinatorPath), true);
    assert.equal(fs.existsSync(acknowledgementPath), false, "missing-mode recovery must reject before writing an acknowledgement");
  `);
});

test("new SQLite backups declare SQLite mode and include the database snapshot", () => {
  runFixture(`
    const databasePath = database.getDatabasePath();
    const db = database.getDb();
    db.exec("CREATE TABLE fixture_state (value TEXT NOT NULL); INSERT INTO fixture_state VALUES ('disposable');");
    database.closeDb();
    const backup = await backupService.createBackup({ createdBy: "fixture" });
    const { archivePath } = backupService.getBackupOrThrow(backup.id);
    const manifest = await readArchiveManifest(archivePath);
    assert.equal(manifest.persistence_mode, "sqlite");
    assert.ok(manifest.included_files.some((entry) => entry.path === "data/rootark.sqlite"));
    assert.ok(fs.existsSync(databasePath));
  `, { DB_ENABLED: "true" });
});

test("SQLite backup creation fails closed when the database snapshot is absent", () => {
  runFixture(`
    await assert.rejects(backupService.createBackup({ createdBy: "fixture" }), /SQLite|database/i);
    const latest = backupService.latestStatus();
    assert.equal(latest.status, "failed");
    assert.equal(fs.existsSync(backupService.getArchivePath(latest.filename)), false);
  `, { DB_ENABLED: "true" });
});

test("JSON restore does not mark the SQLite stage complete when no database was restored", () => {
  runFixture(`
    fs.writeFileSync(path.join(dataDir, "settings.json"), "archived");
    const backup = await backupService.createBackup({ createdBy: "fixture" });
    fs.writeFileSync(path.join(dataDir, "settings.json"), "live");
    await assert.rejects(
      restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) {
          if (step === "restore.provider-inventory-unknown.before-persist") throw new Error("stop after database stage");
        },
      }),
      /stop after database stage/,
    );
    const coordinator = JSON.parse(fs.readFileSync(path.join(dataDir, ".rootark-restore-coordinator.json"), "utf8"));
    assert.equal(coordinator.lastCompletedStage, "uploads");
    assert.notEqual(coordinator.phase, "restart_required");
  `);
});

test("SQLite restore does not mark its stage complete when replacement returns false", () => {
  runFixture(`
    const db = database.getDb();
    db.exec("CREATE TABLE fixture_state (value TEXT NOT NULL); INSERT INTO fixture_state VALUES ('disposable');");
    database.closeDb();
    fs.writeFileSync(path.join(dataDir, "settings.json"), "archived");
    const backup = await backupService.createBackup({ createdBy: "fixture" });
    fs.writeFileSync(path.join(dataDir, "settings.json"), "live");
    await assert.rejects(
      restoreService.restoreBackup(backup.id, {
        confirmation: "RESTORE",
        failureInjector(step) {
          if (step === "restore.sqlite.before-replacement") process.env.DB_ENABLED = "false";
        },
      }),
      /SQLite|database.*restor/i,
    );
    const coordinator = JSON.parse(fs.readFileSync(path.join(dataDir, ".rootark-restore-coordinator.json"), "utf8"));
    assert.equal(coordinator.lastCompletedStage, "uploads");
    assert.notEqual(coordinator.phase, "restart_required");
  `, { DB_ENABLED: "true" });
});
