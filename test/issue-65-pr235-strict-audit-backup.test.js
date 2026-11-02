"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { spawnSync } = require("node:child_process");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const crypto = require("node:crypto");
const strictAudit = require("../services/strictAuditSnapshot");

function fixture(t, { strict = true, missing = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-strict-audit-backup-fixture-"));
  const primaryPath = path.join(root, "rootark.sqlite");
  const source = new Database(primaryPath);
  source.pragma("journal_mode = WAL");
  source.pragma("synchronous = FULL");
  source.exec("CREATE TABLE audit_logs (id TEXT PRIMARY KEY)");
  if (strict) source.exec("CREATE TABLE rootark_strict_sync_audit_mode (id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL CHECK(mode='append_only')); INSERT INTO rootark_strict_sync_audit_mode VALUES (1,'append_only')");
  const journalPath = strictAudit.journalPath(primaryPath);
  if (!missing) {
    fs.mkdirSync(path.dirname(journalPath), { recursive: true });
    const audit = new Database(journalPath);
    audit.pragma("journal_mode = WAL");
    audit.pragma("synchronous = FULL");
    audit.exec("CREATE TABLE pending_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL); CREATE TABLE archived_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)");
    audit.prepare("INSERT INTO pending_audit VALUES (?,?)").run("pending-1", JSON.stringify({ id: "pending-1", eventType: "auth.login.failed" }));
    audit.prepare("INSERT INTO archived_audit VALUES (?,?)").run("archived-1", JSON.stringify({ id: "archived-1", eventType: "audit.archive" }));
    audit.close();
  }
  const stageDir = path.join(root, "staged");
  fs.mkdirSync(stageDir);
  t.after(() => {
    source.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, primaryPath, source, stageDir, journalPath };
}

test("coordinated WAL/FULL online snapshot contains strict marker and pending/archived events", async (t) => {
  const sample = fixture(t);
  const snapshot = await strictAudit.createCoordinatedSnapshots(sample.source, sample.primaryPath, sample.stageDir);
  assert.equal(snapshot.strict, true);
  assert.equal(strictAudit.inspectPrimary(snapshot.snapshotPath), true);
  assert.deepEqual(strictAudit.verifyAuditDatabase(snapshot.auditSnapshotPath), { pending: 1, archived: 1 });
  assert.match(snapshot.auditSha256, /^[a-f0-9]{64}$/);
});

test("strict backup refuses missing or corrupt sidecar before publishing a complete snapshot", async (t) => {
  const sample = fixture(t, { missing: true });
  await assert.rejects(strictAudit.createCoordinatedSnapshots(sample.source, sample.primaryPath, sample.stageDir), /journal missing/);
});

test("strict backup refuses a corrupt pending audit row with mismatched signed ID", async (t) => {
  const sample = fixture(t);
  const attacker = new Database(sample.journalPath);
  try {
    attacker.prepare("UPDATE pending_audit SET event=? WHERE id=?")
      .run(JSON.stringify({ id: "changed-id", eventType: "auth.login.failed" }), "pending-1");
  } finally { attacker.close(); }
  await assert.rejects(strictAudit.createCoordinatedSnapshots(sample.source, sample.primaryPath, sample.stageDir),
    /Strict audit row mismatches its ID/);
});

test("main writer fence prevents pending audit transfer during both online snapshots", async (t) => {
  const sample = fixture(t);
  let held = false;
  const originalBackup = sample.source.backup.bind(sample.source);
  sample.source.backup = async (...args) => {
    const competing = new Database(sample.primaryPath, { timeout: 0 });
    try {
      assert.throws(() => competing.exec("BEGIN IMMEDIATE"), /locked|busy/i);
      held = true;
    } finally { competing.close(); }
    return originalBackup(...args);
  };
  const snapshot = await strictAudit.createCoordinatedSnapshots(sample.source, sample.primaryPath, sample.stageDir);
  assert.equal(held, true);
  assert.deepEqual(strictAudit.verifyAuditDatabase(snapshot.auditSnapshotPath), { pending: 1, archived: 1 });
});

test("restore writer drain waits for an already-admitted sidecar transaction", async (t) => {
  const sample = fixture(t);
  const writer = new Database(sample.journalPath, { timeout: 0 });
  writer.exec("BEGIN IMMEDIATE");
  writer.prepare("INSERT INTO pending_audit VALUES (?,?)").run("in-flight",
    JSON.stringify({ id: "in-flight", eventType: "auth.login.failed" }));
  let settled = false;
  const release = setTimeout(() => {
    writer.exec("COMMIT");
    writer.close();
    settled = true;
  }, 75);
  try {
    await strictAudit.drainAuditWriters(sample.primaryPath);
    assert.equal(settled, true, "drain must wait until pre-barrier SQLite commit finishes");
    assert.equal(strictAudit.verifyAuditDatabase(sample.journalPath).pending, 2);
  } finally {
    clearTimeout(release);
    if (!settled) { writer.exec("ROLLBACK"); writer.close(); }
  }
});

test("real backup ZIP and whole restore preserve both saved and newer strict audit evidence", { timeout: 70_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, `rootark-strict-audit-restore-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-strict-audit-real-restore-"));
  if (process.platform === "win32") {
    assert.equal(fs.existsSync(root), false);
    ensureWindowsChunkUploadRoot(root);
  }
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.resolve(__dirname, "..");
  const script = `
  const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
  const { runMigrations }=require(${JSON.stringify(path.join(project, "db", "migrations"))});
  const { createSyncSqliteAccountWriteFence }=require(${JSON.stringify(path.join(project, "src", "services", "syncSqliteAccountWriteFence"))});
  const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
  const restore=require(${JSON.stringify(path.join(project, "services", "restoreService"))});
  const audit=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
  const strict=require(${JSON.stringify(path.join(project, "services", "strictAuditSnapshot"))});
  const unzipper=require("unzipper");
  function event(id){return {id,timestamp:"2026-11-02T00:00:00.000Z",eventType:"auth.login.failed",severity:"warning",actor:{username:"fixture"},action:"login",result:"failure",details:{}};}
  (async()=>{
    console.log("phase:migrate");
    runMigrations({backup:false});
    console.log("phase:enroll");
    createSyncSqliteAccountWriteFence();
    audit.deferAuditLog(event("original-pending"));
    audit.archiveAuditLogs([event("original-archived")]);
    console.log("phase:backup");
    const saved=await backup.createBackup({createdBy:"fixture"});
    console.log("phase:backup-done");
    const zip=await unzipper.Open.file(backup.getArchivePath(saved.filename));
    const names=zip.files.map(e=>e.path);
    assert.ok(names.includes(strict.ARCHIVE_ENTRY),"archive includes private sidecar bytes");
    audit.deferAuditLog(event("current-pending"));
    audit.archiveAuditLogs([event("current-archived")]);
    console.log("phase:restore");
    const complete=await restore.restoreBackup(saved.id,{confirmation:"RESTORE"});
    console.log("phase:restore-done");
    assert.equal(complete.restartRecommended,true);
    const status=strict.verifyAuditDatabase(strict.journalPath(process.env.DATABASE_URL));
    assert.ok(status.archived>=2);
    const all=[...audit.loadAuditLogs().logs,...audit.loadArchivedAuditLogs().logs].map(x=>x.id);
    for(const id of ["original-pending","original-archived","current-pending","current-archived"])assert.ok(all.includes(id),id);
    console.log("STRICT_AUDIT_RESTORE_OK");
  })().catch(e=>{console.error(e);process.exitCode=1});`;
  const result = spawnSync(process.execPath, ["-e", script], {
    cwd: root,
    env: { ...process.env, DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
      DB_ENABLED: "true", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
      BACKUP_INCLUDE_TEMP: "false", BACKUP_RETENTION_COUNT: "20",
      ROOTARK_RESTORE_INSTANCE_COUNT: "1", ROOTARK_INSTANCE_ID: "sidecar-fixture" },
    encoding: "utf8", timeout: 50_000,
  });
  assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
  assert.match(result.stdout, /STRICT_AUDIT_RESTORE_OK/);
});

test("post-audit replacement failure restores live sidecar evidence and main DB from whole pre-images", { timeout: 70_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, `rootark-audit-rollback-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-strict-audit-rollback-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.resolve(__dirname, "..");
  const script = `
    const assert=require("node:assert/strict");
    const { runMigrations }=require(${JSON.stringify(path.join(project, "db", "migrations"))});
    const { createSyncSqliteAccountWriteFence }=require(${JSON.stringify(path.join(project, "src", "services", "syncSqliteAccountWriteFence"))});
    const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
    const restore=require(${JSON.stringify(path.join(project, "services", "restoreService"))});
    const audit=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
    const strict=require(${JSON.stringify(path.join(project, "services", "strictAuditSnapshot"))});
    function event(id){return {id,timestamp:"2026-11-02T00:00:00Z",eventType:"auth.login.failed",severity:"warning",actor:{username:"fixture"},action:"login",result:"failure",details:{}}}
    (async()=>{
      runMigrations({backup:false});createSyncSqliteAccountWriteFence();
      audit.deferAuditLog(event("old"));
      const backupEntry=await backup.createBackup({createdBy:"fixture"});
      audit.deferAuditLog(event("new"));
      await assert.rejects(restore.restoreBackup(backupEntry.id,{confirmation:"RESTORE",
        failureInjector(step){
          if(step==="restore.audit.before-replacement")
            assert.throws(()=>audit.deferAuditLog(event("late-injected")),/Strict audit writes blocked during whole restore/);
          if(step==="restore.audit.committed")throw Error("AUDIT_COMMIT_FAILURE");
        }}),/AUDIT_COMMIT_FAILURE/);
      assert.equal(restore.assertNoPendingWholeRestore().recovered,true);
      const live=audit.loadAuditLogs().logs.map(x=>x.id);
      assert.ok(live.includes("old"));assert.ok(live.includes("new"));
      assert.ok(strict.verifyAuditDatabase(strict.journalPath(process.env.DATABASE_URL)).pending>=2);
      assert.equal(restore.isWholeRestoreBlocked(),false);
      console.log("STRICT_AUDIT_ROLLBACK_OK");
    })().catch(e=>{console.error(e);process.exitCode=1});`;
  const result = spawnSync(process.execPath, ["-e", script], { cwd: root,
    env: { ...process.env, DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
      DB_ENABLED: "true", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
      BACKUP_INCLUDE_TEMP: "false", BACKUP_RETENTION_COUNT: "20",
      ROOTARK_RESTORE_INSTANCE_COUNT: "1", ROOTARK_INSTANCE_ID: "sidecar-rollback" },
    encoding: "utf8", timeout: 50_000 });
  assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
  assert.match(result.stdout, /STRICT_AUDIT_ROLLBACK_OK/);
});
