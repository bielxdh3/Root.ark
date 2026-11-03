"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const project = path.resolve(__dirname, "..");
const CASE = String.raw`
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const project = process.env.PR235_TEST_PROJECT;
const scenario = process.env.PR235_TEST_SCENARIO;
const { runMigrations } = require(path.join(project, "db", "migrations"));
const { isStrictSyncModeObserved, getDb } = require(path.join(project, "db"));
const backup = require(path.join(project, "services", "backupService"));
const restore = require(path.join(project, "services", "restoreService"));
const audit = require(path.join(project, "repositories", "auditRepository"));
const strictAudit = require(path.join(project, "services", "strictAuditSnapshot"));
const { Open } = require("unzipper");
const makeEvent = (id, eventType = "auth.login.failed") => ({
  id, timestamp: "2026-11-02T00:00:00.000Z", eventType,
  severity: "warning", actor: { username: "fixture" },
  action: "login", result: "failure", details: {},
});
(async () => {
  runMigrations({ backup: false });
  assert.equal(isStrictSyncModeObserved(), false);
  const sidecar = strictAudit.journalPath(process.env.DATABASE_URL);
  const state = path.join(process.cwd(), "data", "fixture-state.json");
  fs.writeFileSync(state, JSON.stringify({ value: "selected" }));
  if (scenario === "late-divergent") {
    audit.saveAuditLogs({ logs: [makeEvent("A-before-backup")] });
  } else if (!scenario.startsWith("late")) {
    audit.deferAuditLog(makeEvent("A-before-backup"));
  }
  const saved = await backup.createBackup({ createdBy: "fixture" });
  const zip = await Open.file(backup.getArchivePath(saved.filename));
  const included = zip.files.some((entry) => entry.path === strictAudit.ARCHIVE_ENTRY);
  assert.equal(included, !scenario.startsWith("late"), "real backup sidecar membership");
  fs.writeFileSync(state, JSON.stringify({ value: "live" }));
  if (scenario === "divergent") {
    const journal = new Database(sidecar);
    try {
      journal.prepare("UPDATE pending_audit SET event=? WHERE id=?")
        .run(JSON.stringify(makeEvent("A-before-backup", "auth.login.success")), "A-before-backup");
    } finally { journal.close(); }
  } else if (scenario === "late-divergent") {
    audit.saveAuditLogs({ logs: [makeEvent("A-before-backup", "auth.login.success")] });
  } else if (scenario === "oversized") {
    audit.saveAuditLogs({ logs: [{ ...makeEvent("B-after-backup"),
      details: { payload: "Z".repeat(70 * 1024) } }] });
  } else if (scenario === "late-main") {
    audit.saveAuditLogs({ logs: [makeEvent("B-after-backup")] });
    assert.ok(getDb().prepare("SELECT id FROM audit_logs WHERE id=?").get("B-after-backup"));
  } else {
    audit.deferAuditLog(makeEvent("B-after-backup"));
    if (scenario === "main") {
      audit.saveAuditLogs(audit.loadAuditLogs());
      assert.ok(getDb().prepare("SELECT id FROM audit_logs WHERE id=?").get("B-after-backup"));
    }
  }
  const negative = ["divergent", "late-divergent", "oversized"].includes(scenario);
  const expectedId = scenario.includes("divergent") ? "A-before-backup" : "B-after-backup";
  assert.ok(audit.loadAuditLogs().logs.some(({ id }) => id === expectedId));
  let destructive = 0;
  let result;
  try {
    result = await restore.restoreBackup(saved.id, { confirmation: "RESTORE",
      failureInjector(stage) {
        if (stage.startsWith("restore.data.")) destructive += 1;
        if (scenario === "rollback" && stage === "restore.sqlite.committed") {
          throw Error("INJECTED_POST_SQLITE_REPLACEMENT");
        }
      } });
  } catch (error) {
    if (scenario === "rollback") {
      assert.match(error.message, /INJECTED_POST_SQLITE_REPLACEMENT/);
    } else {
      if (!negative) throw error;
      assert.match(error.message, /collision|divergent|capacity/i);
    }
  }
  if (scenario === "rollback") {
    assert.equal(result, undefined);
    assert.ok(destructive > 0, "rollback case must pass the local mutation boundary");
    assert.equal(restore.getWholeRestorePhase(), "prepared");
    assert.equal(restore.assertNoPendingWholeRestore().recovered, true);
    assert.equal(JSON.parse(fs.readFileSync(state, "utf8")).value, "live");
    const evidence = audit.loadAllAuditEvidenceForRestore().map(({ log }) => log);
    for (const id of ["A-before-backup", "B-after-backup"]) {
      assert.equal(evidence.filter((entry) => entry.id === id).length, 1,
        "whole-restore rollback must recover current audit event " + id);
    }
    assert.equal(evidence.filter((entry) => entry.eventType === "backup.restore.failed").length, 1);
    assert.equal(evidence.filter((entry) => entry.eventType === "backup.restore.completed").length, 0);
  } else if (negative) {
    assert.equal(result, undefined);
    assert.equal(destructive, 0, "unsafe current evidence rejected before replacement");
    assert.equal(JSON.parse(fs.readFileSync(state, "utf8")).value, "live");
    if (scenario.includes("divergent")) {
      assert.equal(audit.loadAuditLogs().logs.find((entry) => entry.id === "A-before-backup").eventType,
        "auth.login.success");
    }
  } else {
    assert.equal(result.restartRecommended, true);
    assert.equal(JSON.parse(fs.readFileSync(state, "utf8")).value, "selected");
    // Carried history is archived on purpose, so active-only loadAuditLogs()
    // must not be used to check durability of the complete audit evidence.
    const evidence = audit.loadAllAuditEvidenceForRestore().map(({ log }) => log);
    assert.equal(evidence.filter(({ id }) => id === "B-after-backup").length, 1,
      "acknowledged event B must survive whole SQLite restore in one durable record");
    if (!scenario.startsWith("late")) {
      assert.equal(evidence.filter(({ id }) => id === "A-before-backup").length, 1,
        "restored selected evidence must not be duplicated in history");
      assert.equal(audit.loadAuditLogs().logs.filter(({ id }) => id === "A-before-backup").length, 1,
        "selected active audit evidence remains visible");
    }
    assert.equal(evidence.filter(({ eventType }) => eventType === "backup.restore.completed").length, 1,
      "exactly one successful restore outcome");
    assert.ok(fs.existsSync(sidecar), "private sidecar stores retained evidence");
  }
  console.log("NONSTRICT_SQLITE_RESTORE_AUDIT_OK", scenario);
})().catch((error) => { console.error(error.stack || error); process.exitCode = 1; });
`;

for (const scenario of ["pending", "main", "late-sidecar", "late-main", "divergent",
  "late-divergent", "oversized", "rollback"]) {
  test(`real SQLite whole restore retains non-strict audit evidence: ${scenario}`,
    { timeout: 90_000 }, (t) => {
      const runtime = process.platform === "win32"
        ? path.join(process.env.LOCALAPPDATA || os.homedir(),
          `rootark-nonstrict-restore-${crypto.randomBytes(10).toString("hex")}`)
        : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-nonstrict-restore-"));
      if (process.platform === "win32") ensureWindowsChunkUploadRoot(runtime);
      t.after(() => fs.rmSync(runtime, { recursive: true, force: true, maxRetries: 5 }));
      const result = spawnSync(process.execPath, ["-e", CASE], {
        cwd: runtime, encoding: "utf8", windowsHide: true, timeout: 80_000,
        env: { ...process.env, DATABASE_URL: path.join(runtime, "data", "rootark.sqlite"),
          DB_ENABLED: "true", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
          BACKUP_INCLUDE_TEMP: "false", BACKUP_RETENTION_COUNT: "20",
          ROOTARK_RESTORE_INSTANCE_COUNT: "1", ROOTARK_INSTANCE_ID: "nonstrict-restore-fixture",
          PR235_TEST_SCENARIO: scenario, PR235_TEST_PROJECT: project,
          UPLOAD_QUARANTINE_DIR: path.join(runtime, "quarantine"),
          NODE_PATH: [path.join(project, "node_modules"), process.env.NODE_PATH].filter(Boolean).join(path.delimiter),
        },
      });
      assert.equal(result.status, 0,
        `${scenario}: ${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
      assert.match(result.stdout, /NONSTRICT_SQLITE_RESTORE_AUDIT_OK/);
    });
}
