"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const vm = require("node:vm");
const { spawnSync } = require("node:child_process");

const project = path.resolve(__dirname, "..");
const implementation = process.env.ROOTARK_LIVE_AUDIT_IMPL || project;
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

test("strict audit rejects duplicate pending and archived IDs without acknowledging lost evidence", { timeout: 60_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA || os.homedir(), `zk65-final-audit-${crypto.randomBytes(12).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "zk65-final-audit-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true, maxRetries: 4 }));
  const script = String.raw`
    const assert = require("node:assert/strict");
    const path = require("node:path");
    const Database = require("better-sqlite3");
    const project = process.env.ZK65_TEST_PROJECT;
    const { runMigrations } = require(path.join(project, "db", "migrations"));
    const { closeDb } = require(path.join(project, "db"));
    const { createSyncSqliteAccountWriteFence } = require(path.join(project, "src", "services", "syncSqliteAccountWriteFence"));
    const audit = require(path.join(project, "repositories", "auditRepository"));
    const event = (id, type) => ({id, timestamp:"2026-11-02T00:00:00.000Z",
      eventType:type,severity:"warning",actor:{username:"fixture"},action:"login",result:"failure",details:{}});
    runMigrations({backup:false});
    createSyncSqliteAccountWriteFence();
    const pending = event("pending-conflict", "auth.original");
    audit.deferAuditLog(pending);
    assert.doesNotThrow(() => audit.deferAuditLog({...pending}));
    assert.throws(() => audit.deferAuditLog(event("pending-conflict","auth.changed")),
      (error) => error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE"
        && /collision|divergent/i.test(String(error?.cause?.message || error?.message)));
    audit.archiveAuditLogs([event("archived-conflict", "auth.original")]);
    assert.throws(() => audit.saveAuditLogs({logs:[event("archived-conflict","auth.changed")]}),
      (error) => /collision|divergent/i.test(String(error?.cause?.message || error?.message))
        || (error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE"
          && /collision|divergent/i.test(String(error?.cause?.cause?.message || ""))));
    const db = new Database(process.env.DATABASE_URL + ".audit-private/pending.sqlite", {readonly:true,fileMustExist:true});
    assert.equal(JSON.parse(db.prepare("SELECT event FROM pending_audit WHERE id='pending-conflict'").get().event).eventType, "auth.original");
    assert.equal(JSON.parse(db.prepare("SELECT event FROM archived_audit WHERE id='archived-conflict'").get().event).eventType, "auth.original");
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM pending_audit WHERE id='pending-conflict'").get().n, 1);
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM archived_audit WHERE id='archived-conflict'").get().n, 1);
    db.close();
    closeDb();
    process.stdout.write("ZK65_FINAL_AUDIT_NO_LOSS\n");
  `;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: root, encoding: "utf8", timeout: 55_000, windowsHide: true,
    env: { ...process.env, ZK65_TEST_PROJECT: implementation,
      DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
      DB_ENABLED: "true", DB_WRITE_LEGACY_JSON: "false" },
  });
  assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
  assert.match(result.stdout, /ZK65_FINAL_AUDIT_NO_LOSS/);
});

test("strict audit repository failures cannot be disguised as a successful empty server history", () => {
  const source = fs.readFileSync(path.join(implementation, "server.js"), "utf8");
  const start = source.indexOf("function loadAuditLogs(file = AUDIT_LOGS_FILE) {");
  const end = source.indexOf("function saveAuditLogs(", start);
  assert.ok(start >= 0 && end > start);
  const unavailable = Object.assign(new Error("Strict audit collision"), {code:"SYNC_ATOMIC_ACCOUNT_UNAVAILABLE"});
  const logs = [];
  const context = vm.createContext({
    AUDIT_LOGS_FILE: "audit.json",
    shouldUseDatabase: () => true,
    shouldReadJsonFallback: () => false,
    auditRepository: {loadAuditLogs: () => {throw unavailable;}},
    dbConfig: {isStrictSyncModeObserved: () => true},
    getDefaultAuditLogs: () => ({logs:[]}),
    console: {error: (...args) => logs.push(args)},
    fs: {existsSync: () => false},
  });
  vm.runInContext(source.slice(start, end), context, {filename:"server.js/loadAuditLogs"});
  assert.throws(() => context.loadAuditLogs(), (error) =>
    error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" && error.cause === unavailable);
  assert.equal(logs.length, 1);
  context.dbConfig.isStrictSyncModeObserved = () => false;
  context.auditRepository.loadAuditLogs = () => {throw new Error("non-strict database unavailable");};
  assert.equal(context.loadAuditLogs().logs.length, 0, "non-strict legacy fallback remains compatible");
});
