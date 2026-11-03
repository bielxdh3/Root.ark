"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const PROJECT = path.resolve(__dirname, "..");
const CHILD_NODE_PATH = [path.join(PROJECT, "node_modules"), process.env.NODE_PATH]
  .filter(Boolean).join(path.delimiter);

const CASE = String.raw`
"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { performance } = require("node:perf_hooks");
const Database = require("better-sqlite3");
const project = process.env.ZK65_AUDIT_TEST_PROJECT;
const { getDb, closeDb } = require(path.join(project, "db"));
const repo = require(path.join(project, "repositories", "auditRepository"));
const snapshots = require(path.join(project, "services", "strictAuditSnapshot"));
const dbPath = process.env.DATABASE_URL;
const stage = path.join(path.dirname(dbPath), "stage");
fs.mkdirSync(stage, { recursive: true });
const source = fs.readFileSync(path.join(project, "server.js"), "utf8");
const start = source.indexOf("function archiveAuditLogs(");
const end = source.indexOf("function addActionHistory(", start);
assert.ok(start >= 0 && end > start);
const context = vm.createContext({
  crypto, Date, AUDIT_EVENTS: {}, AUDIT_RETENTION_MS: 60_000,
  MAX_AUDIT_LOGS: 100, AUDIT_LOGS_FILE: "audit.json",
  shouldUseDatabase: () => true, auditRepository: repo,
  broadcastDataChanged() {}, sanitizeAuditValue: (value) => value,
  loadAuditLogs: () => repo.loadAuditLogs(),
  saveAuditLogs: (entries) => repo.saveAuditLogs(entries),
  console: { error() {} },
});
vm.runInContext(source.slice(start, end), context, { filename: "server.js/audit" });
const auditLoginFailure = () => context.auditLog("auth.login.failed", { username: "anonymous" },
  { type: "auth", id: "login" }, "attempted", "failure", { reason: "invalid" });
const main = getDb();
main.exec("CREATE TABLE audit_logs (id TEXT PRIMARY KEY, event_type TEXT, severity TEXT,"
  + " actor_username TEXT, actor_ip TEXT, target_type TEXT, target_id TEXT, action TEXT,"
  + " result TEXT, timestamp TEXT, details_json TEXT)");
const old = { id: "aged", timestamp: "2020-01-01T00:00:00.000Z", eventType: "auth.aged",
  severity: "warning", actor: { username: "anonymous" }, action: "login", result: "failure", details: {} };
repo.saveAuditLogs({ logs: [old] });
const initialId = auditLoginFailure();
const sidecarPath = snapshots.journalPath(dbPath);
assert.ok(fs.existsSync(sidecarPath), "ordinary SQLite retention created the unmarked sidecar");
assert.equal(snapshots.inspectPrimary(dbPath), false, "strict Sync was never enrolled");
const archived = new Database(sidecarPath, { readonly: true, fileMustExist: true });
assert.equal(JSON.parse(archived.prepare("SELECT event FROM archived_audit WHERE id='aged'").get().event).eventType, "auth.aged");
archived.close();

const run = async () => {
  let deferredId;
  if (process.env.ZK65_AUDIT_SCENARIO === "backup") {
    const original = main.backup.bind(main);
    main.backup = (...args) => {
      const contender = new Database(dbPath, { timeout: 0 });
      try { assert.throws(() => contender.exec("BEGIN IMMEDIATE"), /locked|busy/i); }
      finally { contender.close(); }
      const before = performance.now();
      deferredId = auditLoginFailure();
      assert.ok(performance.now() - before < 1500, "failed login cannot stall for five seconds");
      return original(...args);
    };
    const snapshot = await snapshots.createCoordinatedSnapshots(main, dbPath, stage);
    assert.equal(snapshot.strict, false);
    const copy = new Database(snapshot.auditSnapshotPath, { readonly: true, fileMustExist: true });
    try {
      const event = JSON.parse(copy.prepare("SELECT event FROM pending_audit WHERE id=?").get(deferredId)?.event || "null");
      assert.equal(event.eventType, "auth.login.failed", "backup contains durably deferred login evidence");
      assert.equal(copy.prepare("SELECT COUNT(*) AS count FROM archived_audit WHERE id='aged'").get().count, 1);
    } finally { copy.close(); }
    assert.equal(main.prepare("SELECT id FROM audit_logs WHERE id=?").get(deferredId), undefined);
    assert.equal(repo.loadAuditLogs().logs.filter(({ id }) => id === deferredId).length, 1);
  } else {
    // Simulate a second writer acquiring the fence AFTER the initial probe.
    // The late SQLITE_BUSY must still defer the audit durably and promptly.
    const competitor = new Database(dbPath, { timeout: 0 });
    const baseLoad = context.loadAuditLogs;
    context.loadAuditLogs = (...args) => {
      const events = baseLoad(...args);
      competitor.exec("BEGIN IMMEDIATE");
      return events;
    };
    try {
      const before = performance.now();
      deferredId = auditLoginFailure();
      assert.ok(performance.now() - before < 1500, "late contention must not stall five seconds");
      assert.equal(main.prepare("SELECT id FROM audit_logs WHERE id=?").get(deferredId), undefined);
    } finally {
      if (competitor.inTransaction) competitor.exec("ROLLBACK");
      competitor.close();
    }
    assert.equal(repo.loadAuditLogs().logs.filter(({ id: found }) => found === deferredId).length, 1);
  }
  assert.equal(repo.loadAuditLogs().logs.filter(({ id }) => id === initialId).length, 1);
  // After the backup releases its lock, the next ordinary retention pass
  // can consolidate the event into main without losing or duplicating it.
  repo.saveAuditLogs(repo.loadAuditLogs());
  assert.equal(main.prepare("SELECT event_type FROM audit_logs WHERE id=?").get(deferredId)?.event_type,
    "auth.login.failed");
  const after = new Database(sidecarPath, { readonly: true, fileMustExist: true });
  try {
    assert.equal(after.prepare("SELECT COUNT(*) AS count FROM pending_audit WHERE id=?").get(deferredId).count, 0);
    assert.equal(after.prepare("SELECT COUNT(*) AS count FROM archived_audit WHERE id='aged'").get().count, 1);
  } finally { after.close(); }
  closeDb();
  process.stdout.write("NONSTRICT_AUDIT_FENCE_OK\n");
};
run().catch((error) => { console.error(error); process.exitCode = 1; closeDb(); });
`;

for (const scenario of ["backup", "late-contention"]) {
  test(`unmarked SQLite audit with retention sidecar survives ${scenario} and keeps auth evidence`,
    { timeout: 45_000 }, (t) => {
      const root = process.platform === "win32"
        ? path.join(process.env.LOCALAPPDATA || os.homedir(),
          `zk65-audit-backup-fence-${crypto.randomBytes(10).toString("hex")}`)
        : fs.mkdtempSync(path.join(os.tmpdir(), "zk65-audit-backup-fence-"));
      if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
      t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 4 }));
      const outcome = spawnSync(process.execPath, ["-e", CASE], {
        cwd: root, encoding: "utf8", windowsHide: true, timeout: 35_000,
        env: { ...process.env, NODE_PATH: CHILD_NODE_PATH,
          DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
          DB_ENABLED: "true", DB_WRITE_LEGACY_JSON: "false",
          ZK65_AUDIT_SCENARIO: scenario, ZK65_AUDIT_TEST_PROJECT: PROJECT },
      });
      assert.equal(outcome.status, 0,
        `audit ${scenario} failed: ${outcome.error?.message || ""}\n${outcome.stderr}\n${outcome.stdout}`);
      assert.match(outcome.stdout, /NONSTRICT_AUDIT_FENCE_OK/);
    });
}
