"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const Database = require("better-sqlite3");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const ROOT = path.resolve(__dirname, "..");
const NODE_MODULES = path.join(ROOT, "node_modules");
const CHILD_NODE_PATH = [NODE_MODULES, process.env.NODE_PATH].filter(Boolean).join(path.delimiter);

function isolatedRuntime(t) {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-json-migration-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-json-migration-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 5 }));
  for (const folder of ["db", "repositories", "services", "src", "config", "sync-client"]) {
    if (fs.existsSync(path.join(ROOT, folder))) {
      fs.cpSync(path.join(ROOT, folder), path.join(root, folder), { recursive: true });
    }
  }
  fs.mkdirSync(path.join(root, "data"), { recursive: true });
  const run = (code, dbEnabled) => spawnSync(process.execPath, ["-e", code], {
    cwd: root, encoding: "utf8", timeout: 45_000, windowsHide: true,
    env: { ...process.env, NODE_PATH: CHILD_NODE_PATH, DB_ENABLED: String(dbEnabled),
      BACKUP_INCLUDE_UPLOADS: "false", BACKUP_INCLUDE_TEMP: "false",
      DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
    },
  });
  return { root, run };
}

test("JSON private archived audit survives real migration, ZIP backup and fresh SQLite restore", { timeout: 90_000 }, async (t) => {
  const { root, run } = isolatedRuntime(t);
  const archived = { id: "migração-🔐-审计", eventType: "auth.login.failed",
    timestamp: "2026-11-03T12:00:00.000Z", details: { source: "signed-private-delta" } };
  const active = { id: "active-import", eventType: "file.upload.success", timestamp: "2026-11-03T12:10:00.000Z" };
  fs.writeFileSync(path.join(root, "data", "audit-logs.json"), JSON.stringify({ logs: [active] }));
  const setup = run(`require('./repositories/jsonAuditArchiveStore').appendJsonArchiveLogs([${JSON.stringify(archived)}])`, false);
  assert.equal(setup.status, 0, setup.stderr || setup.stdout);

  const migrate = run(`require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.equal(migrate.status, 0, migrate.stderr || migrate.stdout);

  const create = run(`(async()=>{const backup=await require('./services/backupService').createBackup();console.log('ARCHIVE='+backup.filename)})().catch(e=>{console.error(e);process.exitCode=1})`, true);
  assert.equal(create.status, 0, create.stderr || create.stdout);
  const filename = /ARCHIVE=(\S+)/.exec(create.stdout)?.[1];
  assert.ok(filename, create.stdout);
  const zip = await require("unzipper").Open.file(path.join(root, "data", "backups", filename));
  assert.equal(zip.files.some((entry) => entry.path.includes("archive.sqlite") || entry.path.includes("json-audit-enrollment")), false,
    "private JSON archive and enrollment must not leak in the backup");
  const sqlite = zip.files.find((entry) => entry.path === "data/rootark.sqlite");
  assert.ok(sqlite, "primary SQLite database missing from backup");
  const fresh = path.join(root, "fresh", "data", "rootark.sqlite");
  fs.mkdirSync(path.dirname(fresh), { recursive: true });
  fs.writeFileSync(fresh, await sqlite.buffer());
  const restored = new Database(fresh, { readonly: true });
  try {
    const legacy = restored.prepare("SELECT event FROM legacy_json_audit_archive WHERE id = ?").get(archived.id);
    assert.ok(legacy, "archived audit record was lost after migration and fresh restore");
    assert.deepEqual(JSON.parse(legacy.event), archived);
    assert.equal(restored.prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE id=?").get(active.id).n, 1);
  } finally { restored.close(); }
});

test("migration deduplicates an identical legacy shadow, rejects divergent replay, and reruns idempotently", { timeout: 90_000 }, (t) => {
  const { root, run } = isolatedRuntime(t);
  const record = { id: "审计-🧪-unicode", eventType: "auth.login.failed",
    timestamp: "2026-11-03T10:00:00.000Z", details: { reason: "safe" } };
  fs.writeFileSync(path.join(root, "data", "audit-logs.json"), JSON.stringify({ logs: [] }));
  const put = run(`require('./repositories/jsonAuditArchiveStore').appendJsonArchiveLogs([${JSON.stringify(record)}])`, false);
  assert.equal(put.status, 0, put.stderr || put.stdout);
  const archiveFile = path.join(root, "data", "audit-logs-archive.json");
  fs.writeFileSync(archiveFile, JSON.stringify({ logs: [{ ...record, eventType: "auth.login.success" }] }));
  const collision = run(`require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.notEqual(collision.status, 0, "divergent duplicate across legacy JSON and private SQLite delta must abort");
  assert.match(collision.stderr, /collision/i);
  const dbPath = path.join(root, "data", "rootark.sqlite");
  if (fs.existsSync(dbPath)) {
    const failed = new Database(dbPath, { readonly: true });
    try {
      assert.equal(failed.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='legacy_json_sqlite_import'").get().n, 0,
        "failed migration must not install an import marker");
      assert.equal(failed.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='legacy_json_audit_archive'").get().n, 0,
        "failed migration must roll back the whole archive table");
    } finally { failed.close(); }
  }

  fs.writeFileSync(archiveFile, JSON.stringify({ logs: [record] }));
  const success = run(`require('./db/migrate-json-to-sqlite').migrate();require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.equal(success.status, 0, success.stderr || success.stdout);
  const verify = run(`
    const assert=require('node:assert/strict'),repo=require('./repositories/auditRepository'),db=require('./db').getDb();
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM legacy_json_audit_archive').get().n,1);
    assert.equal(repo.loadAuditLogs().logs.length,0);
    assert.equal(repo.migratedJsonArchiveEvent(db, ${JSON.stringify(record.id)}).eventType,'auth.login.failed');
    assert.throws(()=>repo.saveAuditLogs({logs:[{...${JSON.stringify(record)},eventType:'auth.login.success'}]}),/collision/i);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM audit_logs').get().n,0);
  `, true);
  assert.equal(verify.status, 0, verify.stderr || verify.stdout);

  const later = run(`require('./repositories/jsonAuditArchiveStore').appendJsonArchiveLogs([{id:'after-cutover',eventType:'auth.login.failed'}])`, false);
  assert.equal(later.status, 0, later.stderr || later.stdout);
  const changed = run(`require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.notEqual(changed.status, 0);
  assert.match(changed.stderr, /JSON source changed after import/i);
});

test("SQLite whole restore retains imported archive events newer than the backup", { timeout: 95_000 }, (t) => {
  const { root, run } = isolatedRuntime(t);
  const before = { id: "before-backup", eventType: "auth.login.failed", timestamp: "2026-11-03T12:00:00Z" };
  const later = { id: "after-backup", eventType: "auth.login.failed", timestamp: "2026-11-03T13:00:00Z" };
  fs.writeFileSync(path.join(root, "data", "audit-logs.json"), JSON.stringify({ logs: [] }));
  const append = run(`require('./repositories/jsonAuditArchiveStore').appendJsonArchiveLogs([${JSON.stringify(before)}])`, false);
  assert.equal(append.status, 0, append.stderr || append.stdout);
  const migration = run(`require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.equal(migration.status, 0, migration.stderr || migration.stdout);
  const restored = run(`
    (async()=>{
      const assert=require('node:assert/strict');
      const db=require('./db').getDb();
      const backup=await require('./services/backupService').createBackup();
      db.prepare('INSERT INTO legacy_json_audit_archive(id,event) VALUES (?,?)').run(${JSON.stringify(later.id)},${JSON.stringify(JSON.stringify(later))});
      await require('./services/restoreService').restoreBackup(backup.id,{confirmation:'RESTORE',username:'archival-test'});
      const fresh=new (require('better-sqlite3'))(require('./db').getDatabasePath(),{readonly:true});
      try{
        const a=fresh.prepare('SELECT event FROM legacy_json_audit_archive WHERE id=?');
        assert.deepEqual(JSON.parse(a.get(${JSON.stringify(before.id)}).event),${JSON.stringify(before)});
        assert.deepEqual(JSON.parse(a.get(${JSON.stringify(later.id)}).event),${JSON.stringify(later)});
      }finally{fresh.close()}
    })().catch(e=>{console.error(e);process.exitCode=1});
  `, true);
  assert.equal(restored.status, 0, restored.stderr || restored.stdout);
});

test("preexisting v1 JSON-to-SQLite import marker safely upgrades archived evidence without changing account rows", { timeout: 90_000 }, (t) => {
  const { root, run } = isolatedRuntime(t);
  const event = { id: "original-🧾", eventType: "audit.retained", timestamp: "2026-11-03T10:00:00Z" };
  fs.writeFileSync(path.join(root, "data", "users.json"), JSON.stringify([{ username: "alice", password: "old" }]));
  const imported = run(`require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.equal(imported.status, 0, imported.stderr || imported.stdout);
  const v1 = run(`
    const db=require('./db').getDb();
    db.exec('DROP TABLE legacy_json_sqlite_audit_import; DROP TABLE legacy_json_audit_archive');
    db.prepare('UPDATE users SET password_hash=? WHERE username=?').run('new-hash','alice');
  `, true);
  assert.equal(v1.status, 0, v1.stderr || v1.stdout);
  const archival = run(`require('./repositories/jsonAuditArchiveStore').appendJsonArchiveLogs([${JSON.stringify(event)}])`, false);
  assert.equal(archival.status, 0, archival.stderr || archival.stdout);
  const upgraded = run(`
    const assert=require('node:assert/strict');
    const {migrate}=require('./db/migrate-json-to-sqlite');
    migrate(); migrate();
    const db=require('./db').getDb();
    assert.equal(db.prepare('SELECT password_hash FROM users WHERE username=?').get('alice').password_hash,'new-hash');
    assert.deepEqual(JSON.parse(db.prepare('SELECT event FROM legacy_json_audit_archive WHERE id=?').get(${JSON.stringify(event.id)}).event), ${JSON.stringify(event)});
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM legacy_json_audit_archive').get().n,1);
  `, true);
  assert.equal(upgraded.status, 0, upgraded.stderr || upgraded.stdout);
});

test("SQLite restore rejects a divergent archived identity without replacing live primary", { timeout: 95_000 }, (t) => {
  const { root, run } = isolatedRuntime(t);
  const prior = { id: "shared-🔐", eventType: "audit.before", timestamp: "2026-11-03T10:00:00Z" };
  fs.writeFileSync(path.join(root, "data", "audit-logs.json"), JSON.stringify({ logs: [] }));
  const archived = run(`require('./repositories/jsonAuditArchiveStore').appendJsonArchiveLogs([${JSON.stringify(prior)}])`, false);
  assert.equal(archived.status, 0, archived.stderr || archived.stdout);
  const migrated = run(`require('./db/migrate-json-to-sqlite').migrate()`, true);
  assert.equal(migrated.status, 0, migrated.stderr || migrated.stdout);
  const result = run(`
    (async()=>{
      const assert=require('node:assert/strict');
      const db=require('./db').getDb();
      const saved=await require('./services/backupService').createBackup();
      db.prepare('UPDATE legacy_json_audit_archive SET event=? WHERE id=?').run(${JSON.stringify(JSON.stringify({ ...prior, eventType: "audit.after" }))}, ${JSON.stringify(prior.id)});
      await assert.rejects(require('./services/restoreService').restoreBackup(saved.id,{confirmation:'RESTORE',username:'test'}),/collision/i);
      assert.equal(JSON.parse(db.prepare('SELECT event FROM legacy_json_audit_archive WHERE id=?').get(${JSON.stringify(prior.id)}).event).eventType,'audit.after');
    })().catch(error=>{console.error(error);process.exitCode=1});
  `, true);
  assert.equal(result.status, 0, result.stderr || result.stdout);
});
