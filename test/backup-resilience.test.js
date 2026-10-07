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
