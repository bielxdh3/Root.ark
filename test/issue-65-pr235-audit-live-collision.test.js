"use strict";

// Strict audit collisions must fail CLOSED in normal traffic, long before a
// restore is requested. Run each scenario in a fresh process and database so
// cached strict-mode flags or SQLite handles cannot mask evidence loss.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const PROJECT = path.resolve(__dirname, "..");
const CHILD_NODE_PATH = [path.join(PROJECT, "node_modules"), process.env.NODE_PATH]
  .filter(Boolean).join(path.delimiter);
const { ensureWindowsChunkUploadRoot } = require(path.join(
  process.env.ROOTARK_LIVE_AUDIT_IMPL || PROJECT, "services", "chunkUploadWindowsAcl"));
const CASE = String.raw`
"use strict";
const assert = require("node:assert/strict");
const path = require("node:path");
const Database = require("better-sqlite3");
const project = process.env.ROOTARK_LIVE_AUDIT_TEST_PROJECT;
const { runMigrations } = require(path.join(project, "db", "migrations"));
const { getDb, closeDb } = require(path.join(project, "db"));
const { createSyncSqliteAccountWriteFence } =
  require(path.join(project, "src", "services", "syncSqliteAccountWriteFence"));
const audit = require(path.join(project, "repositories", "auditRepository"));
const pathToSidecar = process.env.DATABASE_URL + ".audit-private/pending.sqlite";
const entry = (id, type) => ({ id, timestamp: "2026-11-02T00:00:00.000Z",
  eventType: type, severity: "warning", actor: { username: "fixture" },
  action: "login", result: "failure", details: {} });
const insertMain = (id, type) => getDb().prepare(
  "INSERT INTO audit_logs (id,event_type,severity,actor_username,actor_ip,target_type,target_id,action,result,timestamp,details_json) "
  + "VALUES (?,?,?,?,?,?,?,?,?,?,?)").run(id, type, "warning", "fixture", null,
    null, null, "login", "failure", "2026-11-02T00:00:00.000Z",
    JSON.stringify({ details: {}, actorRole: null, userAgent: null, targetMetadata: null }));
const denied = (fn) => assert.throws(fn, (err) =>
  err?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE"
  || /collision|divergent/i.test(String(err?.message)),
  "divergent same-ID audit evidence MUST abort instead of getting pruned");
function rows(id) {
  const sidecar = new Database(pathToSidecar, { readonly: true, fileMustExist: true });
  try {
    const pending = sidecar.prepare("SELECT event FROM pending_audit WHERE id=?").get(id);
    const archived = sidecar.prepare("SELECT event FROM archived_audit WHERE id=?").get(id);
    return {
      pending: pending ? JSON.parse(pending.event).eventType : null,
      archived: archived ? JSON.parse(archived.event).eventType : null,
      main: getDb().prepare("SELECT event_type FROM audit_logs WHERE id=?").get(id)?.event_type || null,
    };
  } finally { sidecar.close(); }
}
try {
  runMigrations({ backup: false });
  createSyncSqliteAccountWriteFence();
  {
    const id = "pending-main";
    insertMain(id, "auth.original");
    audit.deferAuditLog(entry(id, "auth.different"));
    denied(() => audit.loadAuditLogs());
    denied(() => audit.saveAuditLogs({ logs: [entry(id, "auth.original")] }));
    assert.deepEqual(rows(id), { pending: "auth.different", archived: null, main: "auth.original" });
  }
  {
    const id = "pending-archive";
    audit.deferAuditLog(entry(id, "auth.original"));
    denied(() => audit.archiveAuditLogs([entry(id, "auth.different")]));
    assert.deepEqual(rows(id), { pending: "auth.original", archived: null, main: null });
  }
  {
    const id = "archive-pending";
    audit.archiveAuditLogs([entry(id, "auth.original")]);
    audit.deferAuditLog(entry(id, "auth.different"));
    denied(() => audit.loadAuditLogs());
    denied(() => audit.archiveAuditLogs([entry(id, "auth.different")]));
    assert.deepEqual(rows(id), { pending: "auth.different", archived: "auth.original", main: null });
  }
  {
    const id = "exact-replay";
    insertMain(id, "auth.original");
    audit.deferAuditLog(entry(id, "auth.original"));
    // The previously injected divergent IDs above remain present; query
    // exact replay using its own ID instead of hiding the divergent records.
    assert.doesNotThrow(() => audit.saveAuditLogs({ logs: [entry(id, "auth.original")] }));
    assert.deepEqual(rows(id), { pending: null, archived: null, main: "auth.original" });
    // Replaying the exact event through the archive must also be idempotent;
    // it is not grounds for a fail-closed collision.
    assert.doesNotThrow(() => audit.archiveAuditLogs([entry(id, "auth.original")]));
    assert.doesNotThrow(() => audit.archiveAuditLogs([entry(id, "auth.original")]));
    assert.deepEqual(rows(id), { pending: null, archived: "auth.original", main: null });
    assert.equal(audit.loadArchivedAuditLogs().logs.filter((value) => value.id === id).length, 1);
  }
  closeDb();
  process.stdout.write("STRICT_LIVE_COLLISION_OK\n");
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
`;

test("normal strict audit rejects divergent main/pending/archive IDs and accepts exact replay",
    { timeout: 65_000 }, (t) => {
      const root = process.platform === "win32"
        ? path.join(process.env.LOCALAPPDATA || os.homedir(),
          `rootark-audit-live-collision-${crypto.randomBytes(10).toString("hex")}`)
        : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-live-collision-"));
      if (process.platform === "win32") {
        assert.equal(fs.existsSync(root), false);
        ensureWindowsChunkUploadRoot(root);
      }
      t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 4 }));
      const result = spawnSync(process.execPath, ["-e", CASE], {
        cwd: root, encoding: "utf8", timeout: 55_000, windowsHide: true,
        env: { ...process.env, NODE_PATH: CHILD_NODE_PATH,
          ROOTARK_LIVE_AUDIT_TEST_PROJECT: process.env.ROOTARK_LIVE_AUDIT_IMPL || PROJECT,
          DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
          DB_ENABLED: "true", DB_WRITE_LEGACY_JSON: "false",
          BACKUP_ENABLED: "false" },
      });
      assert.equal(result.status, 0,
        `live audit collision tests failed: ${result.error?.message || ""}\n${result.stderr}\n${result.stdout}`);
      assert.match(result.stdout, /STRICT_LIVE_COLLISION_OK/);
    });
