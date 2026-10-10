const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-meta-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupService = require("../services/backupService");
const backupRepository = require("../repositories/backupRepository");
const { isValidTimezone, parseBackupTime, scheduleAutomaticBackups } = require("../services/backupScheduler");

function reset() {
  for (const name of ["data", "uploads", "temp"]) fs.rmSync(path.join(runtime, name), { recursive: true, force: true });
  fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  for (const name of ["BACKUP_ENABLED", "BACKUP_AUTO_ENABLED", "BACKUP_RETENTION_COUNT", "BACKUP_RETENTION_DAYS", "BACKUP_LOCK_STALE_MS"]) delete process.env[name];
}

function saveHistory(entries) {
  fs.mkdirSync(path.join(runtime, "data"), { recursive: true });
  fs.writeFileSync(path.join(runtime, "data", "backup-history.json"), JSON.stringify(entries));
  for (const entry of entries) {
    if (entry.filename) {
      fs.mkdirSync(backupService.BACKUPS_DIR, { recursive: true });
      fs.writeFileSync(path.join(backupService.BACKUPS_DIR, entry.filename), entry.id || "archive");
    }
  }
}

function entry(id, filename, createdAt, extra = {}) {
  return { id, filename, status: "success", type: "manual", createdAt, ...extra };
}

function cronHarness() {
  let callback;
  let stopped = 0;
  const cron = { schedule: (_expr, fn, options) => { callback = fn; return { options, stop: () => { stopped += 1; }, destroy: () => { stopped += 1; } }; } };
  return { cron, get callback() { return callback; }, get stopped() { return stopped; } };
}

test("scheduler, lock, filename, and retention meta-remediation matrix", async (t) => {
  await t.test("backups disabled", async () => { reset(); process.env.BACKUP_ENABLED = "false"; await assert.rejects(backupService.createBackup()); });
  await t.test("automatic disabled", () => { const h = cronHarness(); assert.equal(scheduleAutomaticBackups({ env: { BACKUP_AUTO_ENABLED: "false" }, cron: h.cron, createBackup: async () => {} }), null); });
  await t.test("valid time", () => assert.deepEqual(parseBackupTime("03:00"), { hour: 3, minute: 0 }));
  await t.test("invalid hour", () => assert.equal(parseBackupTime("24:00"), null));
  await t.test("invalid minute", () => assert.equal(parseBackupTime("03:60"), null));
  await t.test("malformed time", () => assert.equal(parseBackupTime("3:00"), null));
  await t.test("valid timezone", () => assert.equal(isValidTimezone("America/Cuiaba"), true));
  await t.test("invalid timezone", () => { const h = cronHarness(); let message; assert.equal(scheduleAutomaticBackups({ env: { BACKUP_TIMEZONE: "No/Such_Zone" }, cron: h.cron, createBackup: async () => {}, onInvalid: (value) => { message = value; } }), null); assert.match(message, /TIMEZONE/); });
  await t.test("duplicate registration", () => { const h = cronHarness(); const first = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); const second = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); assert.equal(first, second); first.destroy(); });
  await t.test("automatic type", async () => { const h = cronHarness(); let received; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async (value) => { received = value; return { id: "automatic" }; } }); await h.callback(); assert.equal(received.type, "automatic"); task.destroy(); });
  await t.test("overlap", async () => { const h = cronHarness(); let resolve; const wait = new Promise((done) => { resolve = done; }); let calls = 0; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => { calls += 1; await wait; return { id: "x" }; } }); const first = h.callback(); const second = h.callback(); resolve(); await Promise.all([first, second]); assert.equal(calls, 1); task.destroy(); });
  await t.test("success audit", async () => { const h = cronHarness(); const events = []; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => ({ id: "ok", filename: "x" }), auditLog: (...args) => events.push(args) }); await h.callback(); assert.equal(events[0][0], "backup.created"); assert.equal(task.latestStatus().state, "success"); task.destroy(); });
  await t.test("failure audit", async () => { const h = cronHarness(); const events = []; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => { throw new Error("failure"); }, auditLog: (...args) => events.push(args) }); await h.callback(); assert.equal(events[0][0], "backup.failed"); assert.equal(task.latestStatus().state, "failure"); task.destroy(); });
  await t.test("stop", () => { const h = cronHarness(); const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); task.stop(); assert.equal(h.stopped, 1); });
  await t.test("shutdown destroy", () => { const h = cronHarness(); const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); task.destroy(); assert.equal(task.latestStatus().state, "stopped"); });
  await t.test("same-millisecond backups", async () => { reset(); const first = await backupService.createBackup(); const second = await backupService.createBackup(); assert.notEqual(first.filename, second.filename); });
  await t.test("existing filename is never truncated", async () => { reset(); const existing = path.join(backupService.BACKUPS_DIR, "rootark-backup-2020-01-01-00-00-00.zip"); fs.writeFileSync(existing, "keep"); await backupService.createBackup(); assert.equal(fs.readFileSync(existing, "utf8"), "keep"); });
  await t.test("create failure releases lock", async () => { reset(); const original = fs.createWriteStream; fs.createWriteStream = () => { throw new Error("create failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { fs.createWriteStream = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("archive finalize failure path releases lock", async () => { reset(); const original = fs.createWriteStream; fs.createWriteStream = () => { throw new Error("finalize failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { fs.createWriteStream = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("checksum failure path releases lock", async () => { reset(); const original = fs.createReadStream; fs.createReadStream = () => { throw new Error("checksum failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { fs.createReadStream = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("history failure path releases lock", async () => { reset(); const original = backupRepository.saveBackup; backupRepository.saveBackup = () => { throw new Error("history failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { backupRepository.saveBackup = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("backup/backup exclusion", () => { const release = backupService.acquireLock("backup"); try { assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" }); } finally { release(); } });
  await t.test("backup/restore exclusion", () => { const release = backupService.acquireLock("backup"); try { assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" }); } finally { release(); } });
  await t.test("backup/delete exclusion", () => { const release = backupService.acquireLock("backup"); try { assert.throws(() => backupService.acquireLock("delete"), { code: "BACKUP_LOCKED" }); } finally { release(); } });
  await t.test("live external lock", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ token: "external", operation: "backup", pid: process.pid, runtimeRoot: runtime })); fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0)); assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" }); fs.rmSync(backupService.LOCK_FILE, { force: true }); });
  await t.test("same-process versioned lock identity remains live", () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(record));
    assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
    fs.rmSync(backupService.LOCK_FILE, { force: true });
  });
  await t.test("reused PID does not keep a prior process lock alive", () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ ...record, pid: process.pid, processInstanceId: "prior-process-instance" }));
    const recovered = backupService.acquireLock("restore");
    recovered();
  });
  await t.test("legacy versioned lock without process identity remains fail-closed", () => {
    reset();
    const record = {
      formatVersion: 1,
      token: "legacy-versioned-lock",
      operation: "restore",
      pid: process.pid,
      instanceId: process.env.ROOTARK_INSTANCE_ID || os.hostname() || "default",
      startedAt: new Date().toISOString(),
      runtimeRoot: runtime,
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(record));
    assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
    fs.rmSync(backupService.LOCK_FILE, { force: true });
  });
  await t.test("same PID from a distinct instance remains live", () => {
    reset();
    const previousInstanceId = process.env.ROOTARK_INSTANCE_ID;
    process.env.ROOTARK_INSTANCE_ID = "rootark-lock-test-local";
    try {
      const record = {
        formatVersion: 1,
        token: "remote-instance-lock",
        operation: "restore",
        pid: process.pid,
        processInstanceId: "remote-process-instance",
        instanceId: "rootark-lock-test-remote",
        startedAt: new Date().toISOString(),
        runtimeRoot: runtime,
      };
      fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(record));
      assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
    } finally {
      if (previousInstanceId === undefined) delete process.env.ROOTARK_INSTANCE_ID;
      else process.env.ROOTARK_INSTANCE_ID = previousInstanceId;
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("stale dead PID", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ token: "dead", pid: 99999999 })); fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0)); const release = backupService.acquireLock("backup"); release(); });
  await t.test("stale age", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, "broken"); fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0)); const release = backupService.acquireLock("backup"); release(); });
  await t.test("malformed recent lock", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, "broken"); assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" }); fs.rmSync(backupService.LOCK_FILE, { force: true }); });
  await t.test("malformed stale lock", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, "broken"); fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0)); const release = backupService.acquireLock("backup"); release(); });
  await t.test("lock-write failure", () => { reset(); const original = fs.openSync; fs.openSync = (target, flags) => { if (target === backupService.LOCK_FILE) throw Object.assign(new Error("denied"), { code: "EACCES" }); return original(target, flags); }; try { assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCK_WRITE_FAILED" }); } finally { fs.openSync = original; } });
  await t.test("release token mismatch", () => { reset(); const release = backupService.acquireLock("backup"); fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ token: "other" })); release(); assert.equal(fs.existsSync(backupService.LOCK_FILE), true); fs.rmSync(backupService.LOCK_FILE, { force: true }); });
  await t.test("retention count", async () => { reset(); const now = new Date().toISOString(); const entries = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", now), entry("2", "rootark-backup-2020-01-01-00-00-01.zip", now)]; saveHistory(entries); process.env.BACKUP_RETENTION_COUNT = "1"; process.env.BACKUP_RETENTION_DAYS = "0"; await backupService.cleanupRetention(); assert.equal(backupRepository.getBackup("1"), null); });
  await t.test("retention age", async () => { reset(); const entries = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(entries); process.env.BACKUP_RETENTION_COUNT = "0"; process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.equal(backupRepository.getBackup("1"), null); });
  await t.test("combined retention policy", async () => { reset(); const entries = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z"), entry("2", "rootark-backup-2020-01-01-00-00-01.zip", new Date().toISOString())]; saveHistory(entries); process.env.BACKUP_RETENTION_COUNT = "1"; process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.equal(backupRepository.getBackup("1"), null); assert.ok(backupRepository.getBackup("2")); });
  await t.test("zero semantics", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); process.env.BACKUP_RETENTION_COUNT = "0"; process.env.BACKUP_RETENTION_DAYS = "0"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("negative values", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); process.env.BACKUP_RETENTION_COUNT = "-1"; process.env.BACKUP_RETENTION_DAYS = "-1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("pre-restore exclusion", async () => { reset(); const items = [entry("1", "rootark-pre-restore-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z", { type: "pre-restore" })]; saveHistory(items); process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("failed-backup exclusion", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z", { status: "failed" })]; saveHistory(items); process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("missing archive", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; fs.mkdirSync(path.join(runtime, "data"), { recursive: true }); fs.writeFileSync(path.join(runtime, "data", "backup-history.json"), JSON.stringify(items)); process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("tombstone failure", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); const original = backupRepository.deleteBackup; backupRepository.deleteBackup = () => { throw new Error("repository"); }; process.env.BACKUP_RETENTION_DAYS = "1"; try { await assert.rejects(backupService.cleanupRetention()); } finally { backupRepository.deleteBackup = original; } assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, items[0].filename)), true); });
  await t.test("repository failure restores archive", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); const original = backupRepository.deleteBackup; backupRepository.deleteBackup = () => { throw new Error("fail"); }; process.env.BACKUP_RETENTION_DAYS = "1"; try { await assert.rejects(backupService.cleanupRetention()); } finally { backupRepository.deleteBackup = original; } assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, items[0].filename)), true); });
  await t.test("stale tombstone recovery", () => { reset(); const id = "1"; const filename = "rootark-backup-2020-01-01-00-00-00.zip"; saveHistory([entry(id, filename, new Date().toISOString(), { checksum: null })]); const original = path.join(backupService.BACKUPS_DIR, filename); const tombstone = `${original}.retention-tombstone`; fs.renameSync(original, tombstone); fs.writeFileSync(`${tombstone}.json`, JSON.stringify({ backupId: id, filename, checksum: null })); backupService.recoverRetentionTombstones(); assert.equal(fs.existsSync(original), true); });
  await t.test("repository-absent tombstone is finalized without recreating an orphan", () => { reset(); const filename = "rootark-backup-2020-01-01-00-00-00.zip"; const tombstone = path.join(backupService.BACKUPS_DIR, `${filename}.retention-tombstone`); fs.writeFileSync(tombstone, "archive"); fs.writeFileSync(`${tombstone}.json`, JSON.stringify({ backupId: "missing", filename, checksum: null })); backupService.recoverRetentionTombstones(); assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, filename)), false); assert.equal(fs.existsSync(tombstone), false); });
  await t.test("equal timestamp ordering", async () => { reset(); const at = new Date().toISOString(); const items = [entry("a", "rootark-backup-2020-01-01-00-00-00.zip", at), entry("b", "rootark-backup-2020-01-01-00-00-01.zip", at)]; saveHistory(items); process.env.BACKUP_RETENTION_COUNT = "1"; process.env.BACKUP_RETENTION_DAYS = "0"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("b")); });
  await t.test("outside-root protection", () => assert.equal(backupService.getArchivePath("../outside.zip"), null));
  await t.test("interrupted-retention restart", () => { reset(); const id = "restart"; const filename = "rootark-backup-2020-01-01-00-00-00.zip"; saveHistory([entry(id, filename, new Date().toISOString())]); const original = path.join(backupService.BACKUPS_DIR, filename); const tombstone = `${original}.retention-tombstone`; fs.renameSync(original, tombstone); fs.writeFileSync(`${tombstone}.json`, JSON.stringify({ backupId: id, filename, checksum: null })); backupService.recoverRetentionTombstones(); assert.equal(fs.readFileSync(original, "utf8"), "restart"); });
});

test.after(() => { process.chdir(originalCwd); fs.rmSync(runtime, { recursive: true, force: true }); });
