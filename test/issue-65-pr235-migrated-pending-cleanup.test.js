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

test("pending cleanup snapshots IDs only and fetches eligible event payloads by indexed ID", () => {
  const source = fs.readFileSync(path.join(root, "repositories", "auditRepository.js"), "utf8");
  const start = source.indexOf("// A crash after main commit but before sidecar removal");
  const end = source.indexOf("function saveAuditLogs(entries", start);
  assert.ok(start !== -1 && end > start, "cleanup source boundaries must be present");
  const cleanup = source.slice(start, end);
  assert.match(cleanup, /SELECT id FROM pending_audit/);
  assert.match(cleanup, /SELECT event FROM pending_audit WHERE id=\?/);
  assert.doesNotMatch(cleanup, /SELECT id\s*,\s*event FROM pending_audit/i,
    "never materialize up to 256 MiB of pending event bodies per normal save");
});

for (const scenario of ["single-v1", "capacity-4096", "divergent-v1", "large-orphans-4096"]) {
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
    // Static child program: scenario is an environment value, never JavaScript source.
    const script = `(function() {
      const assert = require('node:assert/strict');
      const fs = require('node:fs');
      const Database = require('better-sqlite3');
      const { getDb, getDatabasePath } = require('./db');
      const { migrate } = require('./db/migrate-json-to-sqlite');
      const repo = require('./repositories/auditRepository');
      const archive = require('./repositories/jsonAuditArchiveStore');
      const scenario = process.env.ROOTARK_TEST_SCENARIO;
      const largeOrphans = scenario === 'large-orphans-4096';
      const count = scenario === 'capacity-4096' || largeOrphans ? 4096 : 1;
      const events = Array.from({length: largeOrphans ? 0 : count}, (_,n)=>({
        id: 'signed-🔐-' + n, eventType: 'auth.login.failed', timestamp:'2026-11-03T10:00:00Z',
        details:{witness:'private-json-archive'}
      }));
      migrate();
      const primary = getDb();
      // Disposable v1 SQLite installation: the original main import marker
      // exists, while the independent private-archive import did not yet exist.
      primary.exec('DROP TABLE legacy_json_sqlite_audit_import; DROP TABLE legacy_json_audit_archive');
      repo.ensurePendingAuditDatabase();
      if (!largeOrphans) archive.appendJsonArchiveLogs(events);
      const journal = new Database(getDatabasePath() + '.audit-private/pending.sqlite');
      try {
        journal.pragma('journal_mode = WAL');
        journal.pragma('synchronous = FULL');
        const insert = journal.prepare('INSERT INTO pending_audit(id,event) VALUES (?,?)');
        journal.transaction(()=>{
          if (largeOrphans) {
            const payload = 'x'.repeat(63*1024);
            for (let i = 0; i < count; i++) insert.run('large-orphan-'+i,
              JSON.stringify({id:'large-orphan-'+i,eventType:'auth.login.failed',details:{payload}}));
          } else {
            for (const e of events) insert.run(e.id, JSON.stringify(e));
          }
        })();
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
      if (largeOrphans) {
        // This fixture uses ~252 MiB of sidecar event bytes. A normal empty
        // save must NOT copy the whole journal into V8 just to find matches.
        const before = process.memoryUsage().rss;
        repo.saveAuditLogs({logs:[]});
        const delta = process.memoryUsage().rss - before;
        assert.ok(delta < 100*1024*1024,
          'empty save materialized large pending evidence in RSS: '+(delta/1048576).toFixed(1)+' MiB');
        assert.equal(pendingCount(),count,'unmatched pending events must not be erased');
        console.log('LARGE_PENDING_ID_ONLY');
        return;
      }
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
    })();`;
    const result = spawnSync(process.execPath, ["-e", script], {
      cwd: fixture, encoding: "utf8", windowsHide: true, timeout: 80_000,
      env: { ...process.env, NODE_PATH: [path.join(root, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter),
        DB_ENABLED: "true", ROOTARK_TEST_SCENARIO: scenario,
        DATABASE_URL: path.join(fixture, "data", "rootark.sqlite") },
    });
    assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr}\n${result.stdout}`);
    assert.match(result.stdout, /MIGRATED_PENDING_DRAINED|PENDING_REPLAY_REJECTED|LARGE_PENDING_ID_ONLY/);
  });
}
