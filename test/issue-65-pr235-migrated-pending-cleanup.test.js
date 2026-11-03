"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const root = path.resolve(__dirname, "..");

for (const scenario of ["single-v1", "capacity-4096", "divergent-v1"]) {
  test(`migrated JSON archive frees only matching pending audit evidence: ${scenario}`, { timeout: 90_000 }, (t) => {
    const fixture = process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA || os.homedir(), `rootark-migrated-pending-${crypto.randomUUID()}`)
      : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-migrated-pending-"));
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(fixture);
    t.after(() => fs.rmSync(fixture, { recursive: true, force: true, maxRetries: 5 }));
    for (const folder of ["db", "repositories", "services", "src", "sync-client", "config"]) {
      if (fs.existsSync(path.join(root, folder))) fs.cpSync(path.join(root, folder), path.join(fixture, folder), { recursive: true });
    }
    fs.mkdirSync(path.join(fixture, "data"), { recursive: true });
    fs.writeFileSync(path.join(fixture, "data", "audit-logs.json"), JSON.stringify({ logs: [] }));
    const script = `
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      const Database = require('better-sqlite3');
      const { getDb, getDatabasePath } = require('./db');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const repo = require('./repositories/auditRepository');
      const archive = require('./repositories/jsonAuditArchiveStore');
      const scenario = ${JSON.stringify(scenario)};
      const count = scenario === 'capacity-4096' ? 4096 : 1;
      const events = Array.from({length: count}, (_,n)=>({
        id: 'signed-🔐-' + n, eventType: 'auth.login.failed', timestamp:'2026-11-03T10:00:00Z',
        details:{witness:'private-json-archive'}
      }));
      migrate();
      const primary = getDb();
      // Disposable v1 SQLite installation: the original main import marker
      // exists, while the independent private-archive import did not yet exist.
      primary.exec('DROP TABLE legacy_json_sqlite_audit_import; DROP TABLE legacy_json_audit_archive');
      repo.ensurePendingAuditDatabase();
      archive.appendJsonArchiveLogs(events);
      const journal = new Database(getDatabasePath() + '.audit-private/pending.sqlite');
      try {
        journal.pragma('journal_mode = WAL');
        journal.pragma('synchronous = FULL');
        const insert = journal.prepare('INSERT INTO pending_audit(id,event) VALUES (?,?)');
        journal.transaction(()=>{for (const e of events) insert.run(e.id, JSON.stringify(e))})();
      } finally {journal.close()}
      migrate();
      primary.exec("CREATE TABLE rootark_strict_sync_audit_mode " +
        "(id INTEGER PRIMARY KEY CHECK(id=1),mode TEXT NOT NULL CHECK(mode='append_only'));" +
        "INSERT INTO rootark_strict_sync_audit_mode VALUES (1,'append_only')");
      const sidecarPath = getDatabasePath() + '.audit-private/pending.sqlite';
      const pendingCount = () => {
        const side = new Database(sidecarPath, {readonly:true, fileMustExist:true});
        try {return side.prepare('SELECT COUNT(*) AS count FROM pending_audit').get().count}
        finally {side.close()}
      };
      assert.equal(pendingCount(),count);
      assert.deepEqual(repo.loadAuditLogs().logs,[]);
      if (scenario === 'divergent-v1') {
        const side = new Database(sidecarPath);
        try {
          side.prepare('UPDATE pending_audit SET event=? WHERE id=?').run(
            JSON.stringify({...events[0],eventType:'auth.login.success'}),events[0].id);
        } finally {side.close()}
        assert.throws(()=>repo.loadAuditLogs(), e=>/collision/i.test(e.cause?.message || e.message));
        assert.throws(()=>repo.saveAuditLogs({logs:[]}), e=>/collision/i.test(e.cause?.message || e.message));
        assert.equal(pendingCount(),1,'divergent acknowledged evidence cannot be erased');
        assert.equal(repo.migratedJsonArchiveEvent(primary,events[0].id).eventType,'auth.login.failed');
        console.log('PENDING_REPLAY_REJECTED');
        return;
      }
      for (let i=0;i<3;i++) repo.saveAuditLogs(repo.loadAuditLogs());
      assert.equal(pendingCount(),0,'all acknowledged migrated duplicates must drain');
      assert.equal(primary.prepare('SELECT COUNT(*) AS n FROM legacy_json_audit_archive').get().n,count);
      repo.deferAuditLog({id:'new-after-cleanup',eventType:'auth.login.failed'});
      assert.equal(pendingCount(),1,'new audit must be admitted after cleanup');
      repo.saveAuditLogs({logs:[]});
      assert.equal(pendingCount(),1,'uncommitted pending audit without a matching authority must survive cleanup');
      console.log('MIGRATED_PENDING_DRAINED');
    `;
    const result = spawnSync(process.execPath, ["-e", `(()=>{${script}})()`], {
      cwd: fixture, encoding: "utf8", windowsHide: true, timeout: 80_000,
      env: { ...process.env, NODE_PATH: [path.join(root, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter),
        DB_ENABLED: "true", DATABASE_URL: path.join(fixture, "data", "rootark.sqlite") },
    });
    assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr}\n${result.stdout}`);
    assert.match(result.stdout, /MIGRATED_PENDING_DRAINED|PENDING_REPLAY_REJECTED/);
  });
}
