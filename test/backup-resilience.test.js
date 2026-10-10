const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const servicePath = path.join(__dirname, "..", "services", "backupService");

function run(script, env = {}) {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-lock-"));
  const result = spawnSync(process.execPath, ["-e", `process.chdir(${JSON.stringify(runtime)}); Object.assign(process.env, ${JSON.stringify({ DB_ENABLED: "false", ...env })}); ${script}`], { encoding: "utf8" });
  fs.rmSync(runtime, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout.trim());
}

test("backup names and lock recovery remain safe", async (t) => {
  await t.test("two backups created in one second receive distinct names", () => {
    const result = run(`const service = require(${JSON.stringify(servicePath)}); (async () => { const first = await service.createBackup(); const second = await service.createBackup(); console.log(JSON.stringify([first.filename, second.filename])); })().catch((error) => { console.error(error); process.exitCode = 1; });`);
    assert.notEqual(result[0], result[1]);
  });

  await t.test("dead stale locks are recovered", () => {
    const result = run(`const fs = require("fs"); const service = require(${JSON.stringify(servicePath)}); fs.mkdirSync(service.BACKUPS_DIR, { recursive: true }); fs.writeFileSync(service.LOCK_FILE, JSON.stringify({ pid: 99999999 })); fs.utimesSync(service.LOCK_FILE, new Date(0), new Date(0)); const release = service.acquireLock("backup"); release(); console.log(JSON.stringify({ exists: fs.existsSync(service.LOCK_FILE) }));`);
    assert.equal(result.exists, false);
  });

  await t.test("a live PID lock remains authoritative even when old", () => {
    const result = run(`const fs = require("fs"); const service = require(${JSON.stringify(servicePath)}); fs.mkdirSync(service.BACKUPS_DIR, { recursive: true }); fs.writeFileSync(service.LOCK_FILE, JSON.stringify({ pid: process.pid })); fs.utimesSync(service.LOCK_FILE, new Date(0), new Date(0)); try { service.acquireLock("backup"); process.exitCode = 2; } catch (error) { console.log(JSON.stringify(error.code)); }`);
    assert.equal(result, "BACKUP_LOCKED");
  });

  await t.test("old malformed locks recover but recent malformed locks do not", () => {
    for (const [age, expected] of [[0, true], [Date.now(), false]]) {
      const result = run(`const fs = require("fs"); const service = require(${JSON.stringify(servicePath)}); fs.mkdirSync(service.BACKUPS_DIR, { recursive: true }); fs.writeFileSync(service.LOCK_FILE, "broken"); fs.utimesSync(service.LOCK_FILE, new Date(${age}), new Date(${age})); try { const release = service.acquireLock("backup"); release(); console.log(JSON.stringify(true)); } catch { console.log(JSON.stringify(false)); }`);
      assert.equal(result, expected);
    }
  });
});

test("retention retains only eligible backups", async (t) => {
  const retention = (env) => run(`const fs = require("fs"); const path = require("path"); const service = require(${JSON.stringify(servicePath)}); const now = Date.now(); const entries = [
    { id: "00000000-0000-4000-8000-000000000001", filename: "rootark-backup-2020-01-01-00-00-00-000-11111111.zip", status: "success", type: "manual", createdAt: new Date(now - 3 * 86400000).toISOString() },
    { id: "00000000-0000-4000-8000-000000000002", filename: "rootark-backup-2020-01-01-00-00-01-000-22222222.zip", status: "success", type: "manual", createdAt: new Date(now - 2 * 86400000).toISOString() },
    { id: "00000000-0000-4000-8000-000000000003", filename: "rootark-pre-restore-2020-01-01-00-00-02-000-33333333.zip", status: "success", type: "pre-restore", createdAt: new Date(now - 3 * 86400000).toISOString() },
    { id: "00000000-0000-4000-8000-000000000004", filename: "rootark-backup-2020-01-01-00-00-03-000-44444444.zip", status: "failed", type: "manual", createdAt: new Date(now - 3 * 86400000).toISOString() }
  ]; fs.mkdirSync(service.BACKUPS_DIR, { recursive: true }); for (const item of entries) fs.writeFileSync(path.join(service.BACKUPS_DIR, item.filename), item.id); fs.mkdirSync("data", { recursive: true }); fs.writeFileSync("data/backup-history.json", JSON.stringify(entries)); (async () => { await service.cleanupRetention(); const left = JSON.parse(fs.readFileSync("data/backup-history.json", "utf8")).map((item) => item.id); console.log(JSON.stringify(left)); })().catch((error) => { console.error(error); process.exitCode = 1; });`, env);
  await t.test("count retains newest eligible item", () => assert.deepEqual(retention({ BACKUP_RETENTION_COUNT: "1", BACKUP_RETENTION_DAYS: "0" }), ["00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"]));
  await t.test("age removes old eligible items", () => assert.deepEqual(retention({ BACKUP_RETENTION_COUNT: "0", BACKUP_RETENTION_DAYS: "1" }), ["00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"]));
  await t.test("zero and negative limits disable their respective rule", () => {
    assert.equal(retention({ BACKUP_RETENTION_COUNT: "0", BACKUP_RETENTION_DAYS: "0" }).length, 4);
    assert.equal(retention({ BACKUP_RETENTION_COUNT: "-1", BACKUP_RETENTION_DAYS: "-1" }).length, 4);
  });
  await t.test("combined count and age retain excluded history only", () => assert.deepEqual(retention({ BACKUP_RETENTION_COUNT: "1", BACKUP_RETENTION_DAYS: "1" }), ["00000000-0000-4000-8000-000000000003", "00000000-0000-4000-8000-000000000004"]));
});

test("retention and explicit deletion renew the active JSON lease after slow archive hashing", async (t) => {
  await t.test("retention can commit multiple candidates beyond one lease TTL", () => {
    const result = run(`
      const fs = require("node:fs");
      const path = require("node:path");
      const { Transform } = require("node:stream");
      const service = require(${JSON.stringify(servicePath)});
      const originalCreateReadStream = fs.createReadStream;
      fs.createReadStream = function delayedRead(filePath, ...args) {
        const source = originalCreateReadStream.call(this, filePath, ...args);
        const delayed = new Transform({ transform(chunk, encoding, callback) { setTimeout(() => callback(null, chunk), 650); } });
        source.pipe(delayed);
        return delayed;
      };
      const entries = [
        { id: "00000000-0000-4000-8000-000000000001", filename: "rootark-backup-2020-01-01-00-00-00-000-11111111.zip", status: "success", type: "manual", createdAt: "2020-01-01T00:00:00.000Z" },
        { id: "00000000-0000-4000-8000-000000000002", filename: "rootark-backup-2020-01-02-00-00-00-000-22222222.zip", status: "success", type: "manual", createdAt: "2020-01-02T00:00:00.000Z" },
        { id: "00000000-0000-4000-8000-000000000003", filename: "rootark-backup-2020-01-03-00-00-00-000-33333333.zip", status: "success", type: "manual", createdAt: "2020-01-03T00:00:00.000Z" },
      ];
      fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
      for (const entry of entries) fs.writeFileSync(path.join(service.BACKUPS_DIR, entry.filename), entry.id);
      fs.mkdirSync("data", { recursive: true });
      fs.writeFileSync("data/backup-history.json", JSON.stringify(entries));
      service.cleanupRetention().then(() => console.log(JSON.stringify({
        ids: service.listBackups().map((entry) => entry.id),
        archives: entries.map((entry) => fs.existsSync(path.join(service.BACKUPS_DIR, entry.filename))),
      }))).catch((error) => { console.error(error); process.exitCode = 1; });
    `, { BACKUP_RETENTION_COUNT: "1", BACKUP_RETENTION_DAYS: "0", ROOTARK_JSON_LOCK_TTL_MS: "1000" });
    assert.deepEqual(result.ids, ["00000000-0000-4000-8000-000000000003"]);
    assert.deepEqual(result.archives, [false, false, true]);
  });

  await t.test("explicit delete renews after one hash exceeds the lease TTL", () => {
    const result = run(`
      const fs = require("node:fs");
      const path = require("node:path");
      const { Transform } = require("node:stream");
      const service = require(${JSON.stringify(servicePath)});
      const originalCreateReadStream = fs.createReadStream;
      fs.createReadStream = function delayedRead(filePath, ...args) {
        const source = originalCreateReadStream.call(this, filePath, ...args);
        const delayed = new Transform({ transform(chunk, encoding, callback) { setTimeout(() => callback(null, chunk), 1200); } });
        source.pipe(delayed);
        return delayed;
      };
      const entry = { id: "00000000-0000-4000-8000-000000000004", filename: "rootark-backup-2020-01-04-00-00-00-000-44444444.zip", status: "success", type: "manual", createdAt: "2020-01-04T00:00:00.000Z" };
      fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
      fs.writeFileSync(path.join(service.BACKUPS_DIR, entry.filename), "disposable archive fixture");
      fs.mkdirSync("data", { recursive: true });
      fs.writeFileSync("data/backup-history.json", JSON.stringify([entry]));
      service.deleteBackup(entry.id).then(() => console.log(JSON.stringify({
        history: service.listBackups().length,
        archive: fs.existsSync(path.join(service.BACKUPS_DIR, entry.filename)),
      }))).catch((error) => { console.error(error); process.exitCode = 1; });
    `, { ROOTARK_JSON_LOCK_TTL_MS: "1000" });
    assert.deepEqual(result, { history: 0, archive: false });
  });
});

test("retention and explicit deletion preserve an unresolved provider inventory baseline", () => {
  const result = run(`
    const fs = require("node:fs");
    const path = require("node:path");
    const service = require(${JSON.stringify(servicePath)});
    const orphans = require(${JSON.stringify(path.join(__dirname, "..", "services", "restoreProviderOrphans"))});
    const now = Date.now();
    const baselineId = "00000000-0000-4000-8000-000000000001";
    const otherId = "00000000-0000-4000-8000-000000000002";
    const entries = [
      { id: baselineId, filename: "rootark-backup-2026-01-01-00-00-00.zip", status: "success", type: "manual", createdAt: new Date(now - 3 * 86400000).toISOString() },
      { id: otherId, filename: "rootark-backup-2026-01-02-00-00-00.zip", status: "success", type: "manual", createdAt: new Date(now).toISOString() },
    ];
    fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
    for (const item of entries) fs.writeFileSync(path.join(service.BACKUPS_DIR, item.filename), item.id);
    fs.mkdirSync("data", { recursive: true });
    fs.writeFileSync("data/backup-history.json", JSON.stringify(entries));
    const marker = { state: "unknown", backupId: baselineId };
    fs.writeFileSync(orphans.POLICY_PATH, JSON.stringify({ version: 1, objects: [], providerInventory: marker }));
    fs.writeFileSync(orphans.STATE_PATH, JSON.stringify({ version: 1, providerInventory: marker }));
    (async () => {
      process.env.BACKUP_RETENTION_COUNT = "1";
      process.env.BACKUP_RETENTION_DAYS = "0";
      await service.cleanupRetention();
      let blocked = false;
      try { await service.deleteBackup(baselineId); } catch (error) { blocked = /provider inventory baseline/i.test(error.message); }
      console.log(JSON.stringify({ ids: service.listBackups().filter((item) => item.exists).map((item) => item.id), baselineExists: fs.existsSync(path.join(service.BACKUPS_DIR, entries[0].filename)), blocked }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `, { BACKUP_RETENTION_COUNT: "1", BACKUP_RETENTION_DAYS: "0" });
  assert.deepEqual(new Set(result.ids), new Set(["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"]),
    "the unresolved baseline is retained even when older than the retention limit, alongside the newest eligible backup");
  assert.equal(result.baselineExists, true);
  assert.equal(result.blocked, true, "manual deletion cannot discard the only unresolved provider baseline");
});

test("JSON metadata lock rejection keeps the backup archive and history entry together", () => {
  const result = run(`
    const fs = require("node:fs");
    const path = require("node:path");
    const service = require(${JSON.stringify(servicePath)});
    const repository = require(${JSON.stringify(path.join(__dirname, "..", "repositories", "backupRepository"))});
    const id = "00000000-0000-4000-8000-000000000099";
    const filename = "rootark-backup-2026-10-09-00-00-00.zip";
    const archivePath = path.join(service.BACKUPS_DIR, filename);
    fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
    fs.writeFileSync(archivePath, "disposable backup fixture");
    repository.saveBackup({ id, filename, status: "success", metadata: {} });
    const originalDeleteBackup = repository.deleteBackup;
    let deleteCalled = false;
    repository.deleteBackup = () => { deleteCalled = true; throw Object.assign(new Error("injected metadata lock rejection"), { code: "BACKUP_METADATA_LOCK_BUSY" }); };
    (async () => {
      let rejection = null;
      let rejectionMessage = null;
      try { await service.deleteBackup(id); } catch (error) { rejection = error.code; rejectionMessage = error.message; }
      repository.deleteBackup = originalDeleteBackup;
      console.log(JSON.stringify({
        rejection,
        rejectionMessage,
        deleteCalled,
        archiveExists: fs.existsSync(archivePath),
        historyExists: Boolean(repository.getBackup(id)),
      }));
    })().catch((error) => { repository.deleteBackup = originalDeleteBackup; console.error(error); process.exitCode = 1; });
  `);
  assert.equal(result.rejection, "BACKUP_METADATA_LOCK_BUSY", JSON.stringify(result));
  assert.equal(result.deleteCalled, true, "the injected repository metadata rejection must be reached");
  assert.equal(result.archiveExists, true, "a failed metadata deletion must not remove the archive first");
  assert.equal(result.historyExists, true, "a failed metadata deletion must preserve the history entry");
});

test("archive removal failure restores backup history so explicit deletion can be retried", () => {
  const result = run(`
    const fs = require("node:fs");
    const path = require("node:path");
    const service = require(${JSON.stringify(servicePath)});
    const repository = require(${JSON.stringify(path.join(__dirname, "..", "repositories", "backupRepository"))});
    const id = "00000000-0000-4000-8000-000000000098";
    const filename = "rootark-backup-2026-10-09-00-00-01.zip";
    const archivePath = path.join(service.BACKUPS_DIR, filename);
    fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
    fs.writeFileSync(archivePath, "disposable retry fixture");
    repository.saveBackup({ id, filename, status: "success", metadata: { retryMarker: true } });
    const originalRmSync = fs.rmSync;
    let injected = false;
    fs.rmSync = function (target, ...args) {
      if (!injected && target === archivePath + ".retention-tombstone") {
        injected = true;
        throw Object.assign(new Error("injected archive removal failure"), { code: "EACCES" });
      }
      return originalRmSync.call(this, target, ...args);
    };
    (async () => {
      let firstError = null;
      try { await service.deleteBackup(id); } catch (error) { firstError = error.message; }
      fs.rmSync = originalRmSync;
      const afterFailure = { archive: fs.existsSync(archivePath), history: repository.getBackup(id) };
      const retried = await service.deleteBackup(id);
      console.log(JSON.stringify({
        injected,
        firstError,
        archiveAfterFailure: afterFailure.archive,
        historyAfterFailure: Boolean(afterFailure.history),
        markerAfterFailure: afterFailure.history?.metadata?.retryMarker,
        retryId: retried.id,
        archiveAfterRetry: fs.existsSync(archivePath),
        historyAfterRetry: Boolean(repository.getBackup(id)),
      }));
    })().catch((error) => { fs.rmSync = originalRmSync; console.error(error); process.exitCode = 1; });
  `);
  assert.equal(result.injected, true);
  assert.match(result.firstError, /injected archive removal failure/);
  assert.equal(result.archiveAfterFailure, true);
  assert.equal(result.historyAfterFailure, true, "history must be compensated when archive removal fails");
  assert.equal(result.markerAfterFailure, true, "compensation must preserve backup metadata for retry");
  assert.equal(result.retryId, "00000000-0000-4000-8000-000000000098");
  assert.equal(result.archiveAfterRetry, false);
  assert.equal(result.historyAfterRetry, false);
});

test("repository deletion error after a visible commit restores history while retaining the archive", () => {
  const result = run(`
    const fs = require("node:fs");
    const path = require("node:path");
    const service = require(${JSON.stringify(servicePath)});
    const repository = require(${JSON.stringify(path.join(__dirname, "..", "repositories", "backupRepository"))});
    const id = "00000000-0000-4000-8000-000000000097";
    const filename = "rootark-backup-2026-10-09-00-00-02.zip";
    const archivePath = path.join(service.BACKUPS_DIR, filename);
    fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
    fs.writeFileSync(archivePath, "disposable compensation fixture");
    repository.saveBackup({ id, filename, status: "success", metadata: { recoveryMarker: "preserve" } });
    const originalDeleteBackup = repository.deleteBackup;
    let injected = false;
    repository.deleteBackup = (...args) => {
      originalDeleteBackup(...args);
      injected = true;
      throw Object.assign(new Error("injected post-commit repository error"), { code: "EIO" });
    };
    (async () => {
      let firstError = null;
      try { await service.deleteBackup(id); } catch (error) { firstError = error.message; }
      repository.deleteBackup = originalDeleteBackup;
      const backup = repository.getBackup(id);
      console.log(JSON.stringify({
        injected,
        firstError,
        archiveExists: fs.existsSync(archivePath),
        historyExists: Boolean(backup),
        recoveryMarker: backup?.metadata?.recoveryMarker,
      }));
    })().catch((error) => { repository.deleteBackup = originalDeleteBackup; console.error(error); process.exitCode = 1; });
  `);
  assert.equal(result.injected, true);
  assert.match(result.firstError, /injected post-commit repository error/);
  assert.equal(result.archiveExists, true);
  assert.equal(result.historyExists, true, "a repository error after a visible commit must compensate the history row");
  assert.equal(result.recoveryMarker, "preserve");
});

test("SQLite deletion compensation preserves restore metadata committed during archive hashing", () => {
  const result = run(`
    const fs = require("node:fs");
    const path = require("node:path");
    process.env.DB_ENABLED = "true";
    process.env.DATABASE_URL = path.join(process.cwd(), "data", "backup-delete-race.sqlite");
    const originalLog = console.log;
    console.log = () => {};
    require(${JSON.stringify(path.join(__dirname, "..", "db", "migrations.js"))}).runMigrations({ backup: false });
    console.log = originalLog;
    const service = require(${JSON.stringify(servicePath)});
    const repository = require(${JSON.stringify(path.join(__dirname, "..", "repositories", "backupRepository"))});
    const id = "00000000-0000-4000-8000-000000000096";
    const filename = "rootark-backup-2026-10-09-00-00-03.zip";
    const archivePath = path.join(service.BACKUPS_DIR, filename);
    fs.mkdirSync(service.BACKUPS_DIR, { recursive: true });
    fs.writeFileSync(archivePath, "disposable sqlite restore metadata race");
    repository.saveBackup({
      id, filename, status: "success", metadata: { restoreSync: {
        operationId: "operation-race", revision: 0, state: "pending",
        entries: [{ entryId: "entry-race", state: "pending", leaseToken: null, leaseUntil: null }], transitions: [],
      } },
    });
    const originalCreateReadStream = fs.createReadStream;
    const originalRmSync = fs.rmSync;
    let mutationCommitted = false;
    let removalFailed = false;
    fs.createReadStream = function (target, ...args) {
      const stream = originalCreateReadStream.call(this, target, ...args);
      if (target === archivePath) {
        stream.once("open", () => {
          stream.pause();
          repository.mutateRestoreSyncEntry({
            backupId: id, operationId: "operation-race", entryId: "entry-race",
            expectedState: "pending", expectedLeaseToken: null, expectedRevision: 0,
            mutate: (entry) => ({ entry: { ...entry, state: "completed" }, at: "2026-10-09T00:00:00.000Z" }),
          });
          mutationCommitted = true;
          stream.resume();
        });
      }
      return stream;
    };
    fs.rmSync = function (target, ...args) {
      if (!removalFailed && target === archivePath + ".retention-tombstone") {
        removalFailed = true;
        throw Object.assign(new Error("injected post-delete archive removal failure"), { code: "EIO" });
      }
      return originalRmSync.call(this, target, ...args);
    };
    (async () => {
      let failure = null;
      try { await service.deleteBackup(id); } catch (error) { failure = error.message; }
      fs.createReadStream = originalCreateReadStream;
      fs.rmSync = originalRmSync;
      const restored = repository.getBackup(id);
      console.log(JSON.stringify({
        mutationCommitted, removalFailed, failure,
        state: restored?.metadata?.restoreSync?.entries?.[0]?.state,
        revision: restored?.metadata?.restoreSync?.revision,
        archiveExists: fs.existsSync(archivePath),
      }));
      require(${JSON.stringify(path.join(__dirname, "..", "db"))}).closeDb();
    })().catch((error) => { fs.createReadStream = originalCreateReadStream; fs.rmSync = originalRmSync; console.error(error); process.exitCode = 1; });
  `);
  assert.equal(result.mutationCommitted, true);
  assert.equal(result.removalFailed, true);
  assert.match(result.failure, /injected post-delete archive removal failure/);
  assert.equal(result.archiveExists, true);
  assert.equal(result.state, "completed", "compensation must restore the exact SQLite row snapshot removed after the concurrent sync update");
  assert.equal(result.revision, 1);
});

test("a released lock permits a different backup operation", () => {
  const result = run(`const service = require(${JSON.stringify(servicePath)}); const release = service.acquireLock("backup"); let locked; try { service.acquireLock("delete"); } catch (error) { locked = error.code; } release(); const second = service.acquireLock("delete"); second(); console.log(JSON.stringify(locked));`);
  assert.equal(result, "BACKUP_LOCKED");
});

test("archive lookup accepts legacy and collision-safe filenames only", () => {
  const result = run(`const service = require(${JSON.stringify(servicePath)}); console.log(JSON.stringify([Boolean(service.getArchivePath("rootark-backup-2020-01-01-00-00-00.zip")), Boolean(service.getArchivePath("rootark-backup-2020-01-01-00-00-00-000-aabbccdd.zip")), Boolean(service.getArchivePath("../outside.zip"))]));`);
  assert.deepEqual(result, [true, true, false]);
});

test("backups do not traverse nested runtime lifecycle lock or provider queue directories", async () => {
  const result = run(`
    const fs = require("node:fs");
    const path = require("node:path");
    const unzipper = require("unzipper");
    const service = require(${JSON.stringify(servicePath)});
    const directories = [
      "data/.rootark-cloud-file-locks",
      "data/.rootark-cloud-temp-mutations",
      "data/.rootark-cloud-upload-mutations",
    ];
    for (const directory of directories) {
      fs.mkdirSync(directory, { recursive: true });
      fs.writeFileSync(path.join(directory, "live-queue.json"), "runtime coordination state");
    }
    (async () => {
      const backup = await service.createBackup();
      const archive = await unzipper.Open.file(service.getArchivePath(backup.filename));
      console.log(JSON.stringify(archive.files.map((entry) => entry.path)));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `);
  assert.equal(result.some((entry) => entry.startsWith("data/.rootark-cloud-")), false);
});
