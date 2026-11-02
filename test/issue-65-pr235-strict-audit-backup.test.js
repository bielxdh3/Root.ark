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

test("strict audit capacity preserves independent legal archived+pending byte limits", () => {
  const MiB = 1024 * 1024;
  assert.doesNotThrow(() => strictAudit.assertAuditByteBudgets({
    archivedBytes: 510 * MiB, pendingBytes: 3 * MiB, fileBytes: 600 * MiB,
  }), "a legal 513 MiB combined payload must not fail the 512 MiB archive-only limit");
  assert.throws(() => strictAudit.assertAuditByteBudgets({
    archivedBytes: strictAudit.MAX_ARCHIVED_BYTES + 1, pendingBytes: 1, fileBytes: 600 * MiB,
  }), /capacity/);
  assert.throws(() => strictAudit.assertAuditByteBudgets({
    archivedBytes: 1, pendingBytes: strictAudit.MAX_PENDING_BYTES + 1, fileBytes: 600 * MiB,
  }), /capacity/);
  assert.throws(() => strictAudit.assertAuditByteBudgets({
    archivedBytes: 1, pendingBytes: 1, fileBytes: strictAudit.MAX_SIDECAR_FILE_BYTES + 1,
  }), /capacity/);
  assert.throws(() => strictAudit.assertAuditByteBudgets({
    archivedBytes: 1, pendingBytes: 1, fileBytes: 900 * MiB, walBytes: 1200 * MiB,
    shmBytes: 64 * 1024,
  }), /capacity/, "WAL/SHM physical expansion must count toward the bounded file budget");
});

test("SQLite audit byte accounting counts UTF-8 bytes, not characters", () => {
  const db = new Database(":memory:");
  try {
    db.exec("CREATE TABLE archived_audit (event TEXT NOT NULL)");
    const text = JSON.stringify({ eventType: "auth.login.failed", details: { note: "🧪".repeat(8) } });
    db.prepare("INSERT INTO archived_audit(event) VALUES(?)").run(text);
    const { bytes, chars } = db.prepare(`SELECT SUM(LENGTH(CAST(event AS BLOB))) AS bytes,
      SUM(LENGTH(event)) AS chars FROM archived_audit`).get();
    assert.equal(bytes, Buffer.byteLength(text));
    assert.ok(bytes > chars);
  } finally { db.close(); }
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

for (const origin of ["pending", "main", "current", "stored-pending", "stored-main"]) for (const replay of origin.startsWith("stored-") ? [false] : [false, true]) {
  test(`restore ${replay ? "accepts exact replay" : "rejects divergent same-ID live evidence"} vs archived ${origin} audit`, { timeout: 70_000 }, (t) => {
    const root = process.platform === "win32"
      ? path.join(process.env.LOCALAPPDATA, `rootark-audit-collision-${crypto.randomBytes(10).toString("hex")}`)
      : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-collision-"));
    if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const project = path.resolve(__dirname, "..");
    const script = `
      const assert=require("node:assert/strict"),Database=require("better-sqlite3");
      const { runMigrations }=require(${JSON.stringify(path.join(project, "db", "migrations"))});
      const { getDb }=require(${JSON.stringify(path.join(project, "db"))});
      const { createSyncSqliteAccountWriteFence }=require(${JSON.stringify(path.join(project, "src", "services", "syncSqliteAccountWriteFence"))});
      const backup=require(${JSON.stringify(path.join(project, "services", "backupService"))});
      const restore=require(${JSON.stringify(path.join(project, "services", "restoreService"))});
      const audit=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
      const strict=require(${JSON.stringify(path.join(project, "services", "strictAuditSnapshot"))});
      const mode=${JSON.stringify(origin)};
      const replay=${JSON.stringify(replay)};
      const event=(kind)=>({id:"reused",timestamp:"2026-11-02T00:00:00Z",eventType:kind,
        severity:"warning",actor:{username:"fixture"},action:"login",result:"failure",details:{}});
      (async()=>{
        runMigrations({backup:false});createSyncSqliteAccountWriteFence();
        if(mode==="stored-pending"||mode==="stored-main")audit.archiveAuditLogs([event("auth.new")]);
        if(mode==="pending"||mode==="current"||mode==="stored-pending")audit.deferAuditLog(event("auth.old"));
        else getDb().prepare("INSERT INTO audit_logs " +
          "(id,event_type,severity,actor_username,actor_ip,target_type,target_id,action,result,timestamp,details_json) " +
          "VALUES (?,?,?,?,?,?,?,?,?,?,?)").run("reused","auth.old","warning","fixture",null,null,null,"login","failure",
            "2026-11-02T00:00:00Z",JSON.stringify({details:{},actorRole:null,userAgent:null,targetMetadata:null}));
        if(mode==="current")audit.archiveAuditLogs([event("auth.old")]);
        const selected=await backup.createBackup({createdBy:"fixture"});
        if(mode==="current")audit.deferAuditLog(event("auth.old"));
        if(mode.startsWith("stored-")){
          if(mode==="stored-main")getDb().prepare("DELETE FROM audit_logs WHERE id='reused'").run();
          const db=new Database(strict.journalPath(process.env.DATABASE_URL));
          db.prepare("DELETE FROM pending_audit WHERE id='reused'").run();
          db.prepare("DELETE FROM archived_audit WHERE id='reused'").run();
          db.close();
        }else if(mode==="pending"||mode==="current"){
          const db=new Database(strict.journalPath(process.env.DATABASE_URL));
          db.prepare("UPDATE pending_audit SET event=? WHERE id='reused'").run(JSON.stringify(event(replay ? "auth.old" : "auth.new")));
          db.close();
        }else getDb().prepare("UPDATE audit_logs SET event_type=? WHERE id='reused'").run(replay ? "auth.old" : "auth.new");
        if(replay) await restore.restoreBackup(selected.id,{confirmation:"RESTORE"});
        else await assert.rejects(restore.restoreBackup(selected.id,{confirmation:"RESTORE"}),/collision|divergent/i);
        if(!replay) assert.equal(restore.assertNoPendingWholeRestore().recovered,false);
        if(mode==="current"&&!replay){
          assert.throws(()=>audit.loadAuditLogs(),e=>e?.code==="SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
            "divergent live records must remain visible as fail-closed, never silently pruned");
          const pending=new Database(strict.journalPath(process.env.DATABASE_URL),{readonly:true});
          try{assert.equal(JSON.parse(pending.prepare("SELECT event FROM pending_audit WHERE id='reused'").get().event).eventType,"auth.new");}
          finally{pending.close()}
        } else {
          const after=[...audit.loadAuditLogs().logs,...audit.loadArchivedAuditLogs().logs].find(x=>x.id==="reused");
          if(mode.startsWith("stored-")&&!replay)assert.equal(after,undefined,"live state has no conflicting ID");
          else assert.equal(after.eventType,replay ? "auth.old" : "auth.new", "restore must preserve exact replay or current evidence");
        }
        console.log("STRICT_AUDIT_COLLISION_DENIED");
      })().catch(e=>{console.error(e);process.exitCode=1});`;
    const result = spawnSync(process.execPath, ["-e", script], { cwd: root,
      env: { ...process.env, DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
        DB_ENABLED: "true", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
        BACKUP_INCLUDE_TEMP: "false", BACKUP_RETENTION_COUNT: "20",
        ROOTARK_RESTORE_INSTANCE_COUNT: "1", ROOTARK_INSTANCE_ID: `collision-${origin}` },
      encoding: "utf8", timeout: 50_000 });
    assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
    assert.match(result.stdout, /STRICT_AUDIT_COLLISION_DENIED/);
  });
}

test("live strict audit path fails closed for conflicting IDs without deleting acknowledged events", { timeout: 60_000 }, (t) => {
  const root = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, `rootark-audit-live-conflict-${crypto.randomBytes(10).toString("hex")}`)
    : fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-live-conflict-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(root);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const project = path.resolve(__dirname, "..");
  const script = `
    const assert=require("node:assert/strict"),Database=require("better-sqlite3");
    const { runMigrations }=require(${JSON.stringify(path.join(project, "db", "migrations"))});
    const { getDb }=require(${JSON.stringify(path.join(project, "db"))});
    const { createSyncSqliteAccountWriteFence }=require(${JSON.stringify(path.join(project, "src", "services", "syncSqliteAccountWriteFence"))});
    const audit=require(${JSON.stringify(path.join(project, "repositories", "auditRepository"))});
    const strict=require(${JSON.stringify(path.join(project, "services", "strictAuditSnapshot"))});
    const log=(id,type)=>({id,timestamp:"2026-11-02T00:00:00Z",eventType:type,
      severity:"warning",actor:{username:"fixture"},action:"login",result:"failure",details:{}});
    const insertMain=(id,type)=>getDb().prepare("INSERT INTO audit_logs " +
      "(id,event_type,severity,actor_username,actor_ip,target_type,target_id,action,result,timestamp,details_json) " +
      "VALUES (?,?,?,?,?,?,?,?,?,?,?)").run(id,type,"warning","fixture",null,null,null,"login","failure",
       "2026-11-02T00:00:00Z",JSON.stringify({details:{},actorRole:null,userAgent:null,targetMetadata:null}));
    const denied=(error)=>/collision|divergent/i.test(String(error?.message))
      || error?.code==="SYNC_ATOMIC_ACCOUNT_UNAVAILABLE";
    try{
      runMigrations({backup:false});createSyncSqliteAccountWriteFence();
      insertMain("main","auth.old");audit.deferAuditLog(log("main","auth.new"));
      assert.throws(()=>audit.loadAuditLogs(),denied);
      assert.throws(()=>audit.saveAuditLogs({logs:[log("main","auth.old")]}),denied);
      insertMain("main-archive","auth.old");
      assert.throws(()=>audit.archiveAuditLogs([log("main-archive","auth.new")]),denied);
      audit.deferAuditLog(log("pending","auth.new"));
      assert.throws(()=>audit.archiveAuditLogs([log("pending","auth.old")]),denied);
      audit.archiveAuditLogs([log("pending","auth.new")]);
      audit.archiveAuditLogs([log("archived","auth.old")]);
      audit.deferAuditLog(log("archived","auth.new"));
      assert.throws(()=>audit.archiveAuditLogs([log("archived","auth.new")]),denied);
      insertMain("replay","auth.old");audit.deferAuditLog(log("replay","auth.old"));
      assert.doesNotThrow(()=>audit.saveAuditLogs({logs:[log("replay","auth.old")]}));
      const sidecar=new Database(strict.journalPath(process.env.DATABASE_URL),{readonly:true});
      try{
        const get=sidecar.prepare("SELECT event FROM pending_audit WHERE id=?");
        assert.equal(JSON.parse(get.get("main").event).eventType,"auth.new");
        assert.equal(JSON.parse(get.get("archived").event).eventType,"auth.new");
        assert.equal(get.get("pending"),undefined);
        assert.equal(get.get("replay"),undefined);
        assert.equal(JSON.parse(sidecar.prepare("SELECT event FROM archived_audit WHERE id='pending'").get().event).eventType,"auth.new");
        assert.equal(sidecar.prepare("SELECT event FROM archived_audit WHERE id='main-archive'").get(),undefined,
          "failed preflight must not publish a conflicting archive entry");
      } finally {sidecar.close()}
      assert.equal(getDb().prepare("SELECT event_type FROM audit_logs WHERE id='main'").get().event_type,"auth.old");
      console.log("STRICT_LIVE_COLLISIONS_FAIL_CLOSED");
    }catch(e){console.error(e);process.exitCode=1};`;
  const result = spawnSync(process.execPath, ["-e", script], { cwd: root,
    env: { ...process.env, DATABASE_URL: path.join(root, "data", "rootark.sqlite"),
      DB_ENABLED: "true", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "false",
      BACKUP_INCLUDE_TEMP: "false" }, encoding: "utf8", timeout: 45_000 });
  assert.equal(result.status, 0, `${result.error?.message || ""}\n${result.stderr || ""}\n${result.stdout || ""}`);
  assert.match(result.stdout, /STRICT_LIVE_COLLISIONS_FAIL_CLOSED/);
});
