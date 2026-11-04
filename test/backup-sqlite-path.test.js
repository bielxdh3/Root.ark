const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFile } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ROOT = path.resolve(__dirname, "..");

function runNode(script, options) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, ["-e", script], options, (error, stdout, stderr) => error ? reject(Object.assign(error, { stderr })) : resolve(stdout));
  });
}

test("configured SQLite backup and restore preserve the database path", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-sqlite-runtime-"));
  const databaseDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-sqlite-db-"));
  const databasePath = path.join(databaseDir, "configured.sqlite");
  t.after(() => { fs.rmSync(sandbox, { recursive: true, force: true }); fs.rmSync(databaseDir, { recursive: true, force: true }); });
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const unzipper = require(${JSON.stringify(path.join(ROOT, "node_modules", "unzipper"))});
    const databasePath = process.env.DATABASE_URL;
    const db = new Database(databasePath);
    db.exec("CREATE TABLE proof (value TEXT); INSERT INTO proof VALUES ('configured-path');");
    assert.equal(db.prepare("SELECT name FROM sqlite_master WHERE name='audit_logs'").get(), undefined);
    db.close();
      const backupService = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
      const restoreService = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
      (async () => {
        const backup = await backupService.createBackup({ createdBy: "test" });
        const archivePath = backupService.getArchivePath(backup.filename);
        const zip = await unzipper.Open.file(archivePath);
        const entry = zip.files.find((file) => file.path === "data/rootark.sqlite");
        assert.ok(entry);
        const archived = await entry.buffer();
        const mutated = new Database(databasePath);
        mutated.prepare("UPDATE proof SET value = 'mutated'").run();
        mutated.close();
        await restoreService.restoreBackup(backup.id, { confirmation: "RESTORE", username: "test" });
        assert.deepEqual(fs.readFileSync(databasePath), archived);
      assert.equal(fs.existsSync(path.join(process.cwd(), "data", "backups")), true);
      assert.equal(fs.existsSync(path.join(process.cwd(), "data", "backup-history.json")), true);
      console.log(JSON.stringify({ ok: true, archivePath, databasePath }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const stdout = await runNode(script, { cwd: sandbox, env: { ...process.env, DB_ENABLED: "true", DATABASE_URL: databasePath, BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false" } });
  assert.equal(JSON.parse(stdout).ok, true);
});

test("legacy SQLite restores missing audit table while preserving post-backup sidecar evidence", { timeout: 30_000 }, async (t) => {
  const sandbox = createPrivateAuthorityFixture("rootark-legacy-sidecar-runtime-");
  const databasePath = path.join(sandbox, "data", "rootark.sqlite");
  t.after(() => fs.rmSync(sandbox, { recursive: true, force: true }));
  const script = `
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const path = require("node:path");
    const Database = require(${JSON.stringify(path.join(ROOT, "node_modules", "better-sqlite3"))});
    const backup = require(${JSON.stringify(path.join(ROOT, "services", "backupService"))});
    const restore = require(${JSON.stringify(path.join(ROOT, "services", "restoreService"))});
    const audit = require(${JSON.stringify(path.join(ROOT, "repositories", "auditRepository"))});
    const dbPath = process.env.DATABASE_URL;
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    const db = new Database(dbPath);
    db.exec("CREATE TABLE proof (value TEXT); INSERT INTO proof VALUES ('backup');");
    db.close();
    (async () => {
      const selected = await backup.createBackup({ createdBy: "fixture" });
      const updated = new Database(dbPath);
      updated.exec("UPDATE proof SET value='changed'");
      updated.close();
      const journal = path.join(dbPath + ".audit-private", "pending.sqlite");
      audit.ensurePendingAuditDatabase();
      const pending = new Database(journal);
      const event = { id: "legacy-pending-1", eventType: "legacy.fixture", timestamp: "2026-11-03T00:00:00Z" };
      pending.prepare("INSERT INTO pending_audit (id,event) VALUES (?,?)").run(event.id,
        JSON.stringify({ ...event, id: "forged-other-id" }));
      assert.throws(() => audit.loadAllAuditEvidenceForRestore(),
        /Durable pending audit journal unreadable/, "mismatched sidecar evidence must fail closed");
      pending.prepare("UPDATE pending_audit SET event=? WHERE id=?").run(JSON.stringify(event), event.id);
      pending.close();
      await restore.restoreBackup(selected.id, { confirmation: "RESTORE", username: "fixture" });
      const restored = new Database(dbPath, { readonly: true });
      assert.equal(restored.prepare("SELECT value FROM proof").get().value, "backup");
      assert.equal(restored.prepare("SELECT name FROM sqlite_master WHERE name='audit_logs'").get(), undefined);
      restored.close();
      const preserved = audit.loadAllAuditEvidenceForRestore();
      assert.ok(preserved.some(({ log }) => log.id === event.id), "pending sidecar evidence survives restore");
      console.log(JSON.stringify({ ok: true }));
    })().catch((error) => { console.error(error); process.exitCode = 1; });
  `;
  const stdout = await runNode(script, { cwd: sandbox, env: {
    ...process.env, DB_ENABLED: "true", DATABASE_URL: databasePath,
    BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
  } });
  assert.equal(JSON.parse(stdout).ok, true);
});

test("missing main audit table is rejected when strict enrollment or invalid table type is present", () => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-legacy-strict-schema-"));
  try {
    const Database = require(path.join(ROOT, "node_modules", "better-sqlite3"));
    const audit = require("../repositories/auditRepository");
    const db = new Database(path.join(sandbox, "fixture.sqlite"));
    try {
      db.exec("CREATE TABLE proof (value TEXT)");
      assert.equal(audit.hasMainAuditTableForRestore(db), false);
      db.exec("CREATE TABLE rootark_strict_sync_audit_mode (id INTEGER PRIMARY KEY, mode TEXT);"
        + "INSERT INTO rootark_strict_sync_audit_mode VALUES (1, 'append_only')");
      assert.throws(() => audit.hasMainAuditTableForRestore(db), /Strict SQLite restore is missing its audit authority/);
      db.exec("DROP TABLE rootark_strict_sync_audit_mode; CREATE VIEW audit_logs AS SELECT value FROM proof");
      assert.throws(() => audit.hasMainAuditTableForRestore(db), /Unexpected SQLite audit authority type/);
    } finally { db.close(); }
  } finally { fs.rmSync(sandbox, { recursive: true, force: true }); }
});
