"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const crypto = require("node:crypto");
const os = require("node:os");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { inspectZk1LiveLegacyReferencePreflight: inspect } =
  require("../src/services/zk1LiveLegacyReferencePreflight");
const { MIGRATIONS } = require("../db/migrations");

const MODE = { dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false };
const SECRET = "LEGACY-PRIVATE-REFERENCE-DO-NOT-EXPORT";
const ALL = ["versions", "backups", "trash", "links", "derived", "retention",
  "folders", "pending-uploads", "file-permissions", "encrypted-files",
  "actions-history", "analytics-events", "audit-logs", "users", "schema-migrations",
  "sync-resume-grants"];

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-legacy-coverage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const file = path.join(root, "fixture.sqlite");
  const db = new DatabaseSync(file);
  db.exec(`
    CREATE TABLE folders(id TEXT PRIMARY KEY, name TEXT, allowed_users_json TEXT, deleted_at TEXT, expires_at TEXT);
    CREATE TABLE file_versions(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, versions_json TEXT);
    CREATE TABLE backup_history(id TEXT PRIMARY KEY, filename TEXT, type TEXT, status TEXT, metadata_json TEXT);
    CREATE TABLE trash_items(id TEXT PRIMARY KEY, item_type TEXT, status TEXT, original_file_name TEXT,
      trash_path TEXT, metadata_json TEXT, restore_metadata_json TEXT);
    CREATE TABLE public_links(token TEXT PRIMARY KEY, folder_id TEXT, file_name TEXT, revoked_at TEXT, metadata_json TEXT);
    CREATE VIRTUAL TABLE file_search_index USING fts5(folder_id UNINDEXED, file_name,
      tokenize = 'trigram case_sensitive 0');
    CREATE TABLE file_expirations(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, expires_at TEXT);
    CREATE TABLE pending_uploads(id TEXT PRIMARY KEY, folder_id TEXT, file_name TEXT, metadata_json TEXT,
      FOREIGN KEY(folder_id) REFERENCES folders(id));
    CREATE TABLE file_permissions(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, allowed_users_json TEXT);
    CREATE TABLE encrypted_files(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, encryption_level TEXT, metadata_json TEXT);
    CREATE TABLE actions_history(id TEXT PRIMARY KEY, action_type TEXT, folder_id TEXT, file_name TEXT, details_json TEXT);
    CREATE TABLE analytics_events(id TEXT PRIMARY KEY, event_type TEXT, folder_id TEXT, file_name TEXT, details_json TEXT);
    CREATE TABLE audit_logs(id TEXT PRIMARY KEY, event_type TEXT, target_type TEXT, target_id TEXT, details_json TEXT);
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, permissions_json TEXT, deleted_at TEXT);
    CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT);
    CREATE TABLE sync_resume_factor_spend_grant(username TEXT, replay_digest TEXT,
      code_mac TEXT, device_id TEXT, pause_fence TEXT, committed_at TEXT);
  `);
  db.prepare("INSERT INTO folders VALUES (?,?,?,?,?)").run("root", SECRET, "{}", null, null);
  db.prepare("INSERT INTO file_versions VALUES (?,?,?,?)").run(1, "root", SECRET, '{"versions":[]}');
  db.prepare("INSERT INTO pending_uploads VALUES (?,?,?,?)").run("upload-1", "root", SECRET, "{}");
  db.prepare("INSERT INTO file_permissions VALUES (?,?,?,?)").run(1, "root", SECRET, "{}");
  db.prepare("INSERT INTO encrypted_files VALUES (?,?,?,?,?)").run(1, "root", SECRET, "legacy", "{}");
  db.prepare("INSERT INTO actions_history VALUES (?,?,?,?,?)").run("a", "upload", "root", SECRET, "{}");
  db.prepare("INSERT INTO public_links VALUES (?,?,?,?,?)").run("token-secret", "root", SECRET, null, "{}");
  db.prepare("INSERT INTO public_links VALUES (?,?,?,?,?)").run("revoked-token", "root", SECRET, "yesterday", "{}");
  db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("root", SECRET);
  db.close();
  return { root, file };
}

function scan(f, extra) {
  return inspect({ optIn: true, databasePath: f.file, persistence: MODE,
    sqlCoverageOptIn: true, ...extra });
}

test("explicit read-only SQL coverage observes all registered legacy references but never claims global completion", (t) => {
  const f = fixture(t);
  const original = fs.readFileSync(f.file);
  const a = scan(f), b = scan(f);
  assert.equal(a.legacy.coverage, "partial");
  assert.equal(a.legacy.sqlCoverage.observation, "bounded-registered-sqlite-sources-only");
  assert.deepEqual(a.legacy.sqlCoverage.sources.map((x) => x.kind), ALL);
  assert.deepEqual(a.legacy.sqlCoverage.sources.map((x) => x.observedRows),
    [1, 0, 0, 2, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]);
  assert.equal(a.legacy.sqlCoverage.unrecognizedTables, 0);
  assert.equal(a.legacy.sqlCoverage.registeredTableNamesOnly, true);
  assert.equal(a.legacy.sqlCoverage.registeredColumnNamesOnly, true);
  assert.equal(a.legacy.sqlCoverage.globallyComplete, false);
  assert.equal(a.legacy.sqlCoverage.providerCustodyVerified, false);
  assert.equal(a.snapshotOwnerSigned, false);
  for (const key of ["authoritativeCorpusInventory", "wholeCorpusVerified", "authorizesCutover", "canDeleteLegacy"])
    assert.equal(a[key], false);
  assert.notEqual(a.legacy.sqlCoverage.ephemeralFingerprint, b.legacy.sqlCoverage.ephemeralFingerprint);
  for (const forbidden of [SECRET, f.root, f.file, "token-secret", "revoked-token"])
    assert.equal(JSON.stringify(a).includes(forbidden), false);
  assert.deepEqual(fs.readFileSync(f.file), original, "scan is strictly read-only");
  const defaultView = scan(f, { sqlCoverageOptIn: false });
  assert.equal(Object.hasOwn(defaultView.legacy, "sqlCoverage"), false,
    "the new gate must be explicitly requested");
});

test("real registered migration DDL has the exact SQL source classes expected by the opt-in gate", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-legacy-migration-ddl-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const f = { file: path.join(root, "migrations.sqlite") };
  const db = new DatabaseSync(f.file);
  for (const migration of MIGRATIONS) migration.up(db);
  db.close();
  const result = scan(f);
  assert.deepEqual(result.legacy.sqlCoverage.sources.map((row) => row.kind), ALL);
  assert.equal(result.legacy.sqlCoverage.sources.every((row) => row.observedRows === 0), true);
  assert.equal(result.wholeCorpusVerified, false);
  assert.equal(result.authorizesCutover, false);
});

test("combined opt-in SQL and physical backup evidence still leaves provider custody and global closure blocked", (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-legacy-combined-"));
  t.after(() => fs.rmSync(dataDir, { recursive: true, force: true }));
  const backupDir = path.join(dataDir, "backups");
  fs.mkdirSync(backupDir);
  const f = { file: path.join(dataDir, "rootark.sqlite") };
  const db = new DatabaseSync(f.file);
  for (const migration of MIGRATIONS) migration.up(db);
  const archiveName = "rootark-backup-2026-10-23-09-00-00.zip";
  const archive = path.join(backupDir, archiveName);
  const bytes = Buffer.from("synthetic backup archive, no customer data");
  db.prepare(`INSERT INTO backup_history
    (id, filename, type, status, created_at, checksum, metadata_json)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run("backup-1", archiveName, "manual", "success", "2026-10-23T09:00:00Z",
      crypto.createHash("sha256").update(bytes).digest("hex"), "{}");
  db.close();
  fs.writeFileSync(archive, bytes);
  const report = scan(f, { backupDataDir: dataDir });
  assert.equal(report.legacy.backupEvidence.archives, 1);
  assert.equal(report.legacy.sqlCoverage.sources.find((x) => x.kind === "backups").observedRows, 1);
  assert.equal(report.legacy.sqlCoverage.providerCustodyVerified, false);
  assert.equal(report.authorizesCutover, false);
  assert.equal(report.canDeleteLegacy, false);
  fs.writeFileSync(archive, "changed after backup history was recorded");
  assert.throws(() => scan(f, { backupDataDir: dataDir }), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  assert.equal(fs.existsSync(archive), true);
});

test("unknown application table, view or trigger and missing reference table fail closed", (t) => {
  for (const ddl of [
    "CREATE TABLE surprise_legacy_files(id TEXT, plaintext TEXT)",
    "CREATE VIEW secret_legacy_refs AS SELECT file_name FROM file_versions",
    "CREATE TRIGGER suspicious_ref AFTER INSERT ON folders BEGIN SELECT 1; END",
    "ALTER TABLE file_versions ADD COLUMN hidden_legacy_copy TEXT",
    "DROP TABLE file_search_index; CREATE VIRTUAL TABLE file_search_index USING fts5(folder_id UNINDEXED, file_name, content='file_versions')",
    "DROP TABLE pending_uploads",
  ]) {
    const f = fixture(t), db = new DatabaseSync(f.file);
    db.exec(ddl); db.close();
    assert.throws(() => scan(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
    assert.equal(fs.existsSync(f.file), true);
  }
});

test("corrupt auxiliary JSON, orphan foreign key and extra over-limit rows cannot be reported as covered", (t) => {
  const f = fixture(t);
  let db = new DatabaseSync(f.file);
  db.exec("UPDATE pending_uploads SET metadata_json = '{bad'"); db.close();
  assert.throws(() => scan(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  db = new DatabaseSync(f.file);
  db.exec("UPDATE pending_uploads SET metadata_json = '{}'");
  db.exec("PRAGMA foreign_keys=OFF");
  db.prepare("INSERT INTO pending_uploads VALUES (?,?,?,?)").run("orphan", "absent-folder", "x", "{}");
  db.close();
  assert.throws(() => scan(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  const g = fixture(t);
  db = new DatabaseSync(g.file);
  const stmt = db.prepare("INSERT INTO actions_history VALUES (?,?,?,?,?)");
  db.exec("BEGIN");
  for (let i = 0; i < 5001; i++) stmt.run("overflow-" + i, "upload", "root", SECRET, "{}");
  db.exec("COMMIT"); db.close();
  assert.throws(() => scan(g), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
});

test("incomplete persistence or malformed opt-in never silently upgrades the legacy preflight", (t) => {
  const f = fixture(t);
  for (const overrides of [
    { optIn: false }, { persistence: { ...MODE, jsonReadFallback: true } },
    { sqlCoverageOptIn: "true" }, { sqlCoverageOptIn: 1 },
  ]) assert.throws(() => scan(f, overrides), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
});
