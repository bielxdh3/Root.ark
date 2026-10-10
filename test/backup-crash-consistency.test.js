const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const SERVICE = path.join(ROOT, "services", "backupService.js");
const REPOSITORY = path.join(ROOT, "repositories", "backupRepository.js");

function startChild(runtime, action, env = {}) {
  const child = spawn(process.execPath, ["-e", action], {
    cwd: runtime,
    env: { ...process.env, DB_ENABLED: "false", ...env },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const result = new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, result };
}

async function runChild(runtime, action, env = {}) {
  return startChild(runtime, action, env).result;
}

function newRuntime(prefix) {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  return runtime;
}

function criticalAction(servicePath, enteredPath, criticalPath) {
  return `
    const fs=require("fs");
    const service=require(${JSON.stringify(servicePath)});
    let release;
    try {
      release=service.acquireLock("backup");
      fs.appendFileSync(${JSON.stringify(enteredPath)}, process.pid + "\\n");
      const fd=fs.openSync(${JSON.stringify(criticalPath)}, "wx");
      setTimeout(() => { fs.closeSync(fd); fs.rmSync(${JSON.stringify(criticalPath)}, {force:true}); release(); process.exit(0); }, 250);
    } catch (error) {
      if (release) release();
      process.exit(error.code === "BACKUP_LOCKED" ? 10 : 11);
    }
  `;
}

async function assertOneCriticalSection(runtime, stale = false) {
  const entered = path.join(runtime, "entered.log");
  const critical = path.join(runtime, "critical");
  if (stale) {
    const lock = path.join(runtime, "data", "backups", ".backup.lock");
    fs.writeFileSync(lock, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
    fs.utimesSync(lock, new Date(0), new Date(0));
  }
  const action = criticalAction(SERVICE, entered, critical);
  const first = runChild(runtime, action);
  const second = runChild(runtime, action);
  const results = await Promise.all([first, second]);
  const owners = results.filter((item) => item.code === 0);
  const locked = results.filter((item) => item.code === 10);
  assert.equal(owners.length, 1, results.map((item) => `${item.code}:${item.stderr}`).join(" | "));
  assert.equal(locked.length, 1, results.map((item) => `${item.code}:${item.stderr}`).join(" | "));
  assert.equal(fs.readFileSync(entered, "utf8").trim().split(/\r?\n/).length, 1);
  assert.equal(fs.existsSync(path.join(runtime, "data", "backups", ".backup.lock")), false);
}

function retentionFixture({ history = true, archiveBytes = "archive", checksum = null } = {}) {
  const runtime = newRuntime("rootark-retention-crash-");
  const id = "00000000-0000-4000-8000-000000000001";
  const filename = "rootark-backup-2020-01-01-00-00-00.zip";
  const archivePath = path.join(runtime, "data", "backups", filename);
  const bytes = Buffer.from(archiveBytes);
  fs.writeFileSync(archivePath, bytes);
  const digest = checksum || crypto.createHash("sha256").update(bytes).digest("hex");
  if (history) {
    fs.writeFileSync(path.join(runtime, "data", "backup-history.json"), JSON.stringify([{ id, filename, status: "success", type: "manual", createdAt: "2020-01-01T00:00:00.000Z", checksum: digest }]));
  } else {
    fs.writeFileSync(path.join(runtime, "data", "backup-history.json"), "[]");
  }
  return { runtime, id, filename, archivePath, bytes, checksum: digest, tombstone: `${archivePath}.retention-tombstone`, transactionRoot: path.join(runtime, "data", "backups", ".retention-transactions") };
}

function cleanupAction(servicePath) {
  return `(async()=>{const service=require(${JSON.stringify(servicePath)}); await service.cleanupRetention();})().catch(error=>{console.error(error);process.exitCode=1;});`;
}

function recoveryAction(servicePath) {
  return `const service=require(${JSON.stringify(servicePath)}); service.recoverRetentionTombstones();`;
}

function transactionFor(fixture, phase = "prepared", overrides = {}) {
  const transactionId = crypto.randomUUID();
  const directory = path.join(fixture.transactionRoot, `tx-${transactionId}`);
  fs.mkdirSync(directory, { recursive: true });
  const transaction = {
    version: 1,
    transactionId,
    phase,
    backupId: fixture.id,
    filename: fixture.filename,
    archivePath: fixture.archivePath,
    tombstonePath: fixture.tombstone,
    checksum: fixture.checksum,
    createdAt: new Date().toISOString(),
    ...overrides,
  };
  fs.writeFileSync(path.join(directory, "transaction.json"), JSON.stringify(transaction));
  return { directory, transaction };
}

test("backup operation lock is exclusive across real child processes", { timeout: 30_000 }, async (t) => {
  await t.test("absent lock has one owner", async () => {
    const runtime = newRuntime("rootark-lock-race-");
    try { await assertOneCriticalSection(runtime); } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("dead stale lock has one owner", async () => {
    const runtime = newRuntime("rootark-lock-stale-race-");
    try { await assertOneCriticalSection(runtime, true); } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("a versioned lock from another runtime instance is never stolen by local PID checks", async () => {
    const runtime = newRuntime("rootark-lock-remote-instance-");
    const lock = path.join(runtime, "data", "backups", ".backup.lock");
    const remoteLock = {
      formatVersion: 1,
      token: "remote-restore-token",
      operation: "restore",
      pid: 99999999,
      processStartIdentity: null,
      instanceId: "replica-a",
      startedAt: new Date(0).toISOString(),
      runtimeRoot: runtime,
      takeoverClaimToken: null,
    };
    fs.writeFileSync(lock, JSON.stringify(remoteLock));
    fs.utimesSync(lock, new Date(0), new Date(0));
    try {
      const result = await runChild(runtime, `
        const assert=require("node:assert/strict");
        const fs=require("node:fs");
        const service=require(${JSON.stringify(SERVICE)});
        const lock=${JSON.stringify(lock)};
        const before=fs.readFileSync(lock, "utf8");
        try { const release=service.acquireLock("restore"); release(); process.exit(1); }
        catch (error) {
          if (error.code !== "BACKUP_LOCKED") process.exit(2);
          assert.equal(fs.readFileSync(lock, "utf8"), before);
          console.log(JSON.stringify({ locked: true, preserved: true }));
        }
      `, { ROOTARK_INSTANCE_ID: "replica-b" });
      assert.equal(result.code, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout.trim()), { locked: true, preserved: true });
      assert.equal(fs.readFileSync(lock, "utf8"), JSON.stringify(remoteLock));
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("a crash after stale evidence quarantine is recoverable", async () => {
    const runtime = newRuntime("rootark-lock-quarantine-");
    try {
      const action = `const fs=require("fs"); const service=require(${JSON.stringify(SERVICE)}); const original=fs.renameSync; fs.renameSync=(from,to)=>{const result=original(from,to); if(path.resolve(from)===path.resolve(service.LOCK_FILE)&&String(to).endsWith("evidence")) process.kill(process.pid,"SIGKILL"); return result;}; const path=require("path"); service.acquireLock("backup");`;
      const lock = path.join(runtime, "data", "backups", ".backup.lock");
      fs.writeFileSync(lock, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
      fs.utimesSync(lock, new Date(0), new Date(0));
      const crashed = await runChild(runtime, action);
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(runtime, criticalAction(SERVICE, path.join(runtime, "entered.log"), path.join(runtime, "critical")));
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(lock), false);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("a crash after replacement leaves a recoverable takeover authority", async () => {
    const runtime = newRuntime("rootark-lock-owner-crash-");
    try {
      const action = `const fs=require("fs"); const path=require("path"); const service=require(${JSON.stringify(SERVICE)}); const original=fs.rmSync; fs.rmSync=(target,options)=>{if(path.resolve(String(target))===path.resolve(${JSON.stringify(`${path.join(runtime, "data", "backups", ".backup.lock.takeover", "evidence")}`)})) process.kill(process.pid,"SIGKILL"); return original(target,options);}; const release=service.acquireLock("backup"); release();`;
      const lock = path.join(runtime, "data", "backups", ".backup.lock");
      fs.writeFileSync(lock, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
      fs.utimesSync(lock, new Date(0), new Date(0));
      const crashed = await runChild(runtime, action);
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(runtime, criticalAction(SERVICE, path.join(runtime, "entered.log"), path.join(runtime, "critical")));
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(lock), false);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("recent malformed evidence fails closed and old malformed evidence recovers", async () => {
    const runtime = newRuntime("rootark-lock-malformed-");
    const lock = path.join(runtime, "data", "backups", ".backup.lock");
    try {
      fs.writeFileSync(lock, "broken");
      const recent = await runChild(runtime, `const service=require(${JSON.stringify(SERVICE)}); try{service.acquireLock("backup");process.exit(1)}catch(error){process.exit(error.code==="BACKUP_LOCKED"?0:2)}`);
      assert.equal(recent.code, 0, recent.stderr);
      const old = new Date(Date.now() - 120_000);
      fs.utimesSync(lock, old, old);
      const recovered = await runChild(runtime, criticalAction(SERVICE, path.join(runtime, "entered.log"), path.join(runtime, "critical")));
      assert.equal(recovered.code, 0, recovered.stderr);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("backup, restore, and delete share one exclusion boundary", async () => {
    const runtime = newRuntime("rootark-lock-operations-");
    try {
      const result = await runChild(runtime, `const service=require(${JSON.stringify(SERVICE)}); const release=service.acquireLock("backup"); const values=[]; for(const op of ["restore","delete"]){try{service.acquireLock(op)}catch(error){values.push(error.code)}} release(); console.log(JSON.stringify(values));`);
      assert.equal(result.code, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout.trim()), ["BACKUP_LOCKED", "BACKUP_LOCKED"]);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });
});

test("retention transactions converge from real crash boundaries", { timeout: 60_000 }, async (t) => {
  await t.test("crash after archive rename restores history and bytes", async () => {
    const fixture = retentionFixture();
    try {
      const action = `const fs=require("fs"); const path=require("path"); const service=require(${JSON.stringify(SERVICE)}); const original=fs.renameSync; fs.renameSync=(from,to)=>{const result=original(from,to); if(path.resolve(from)===path.resolve(${JSON.stringify(fixture.archivePath)})&&path.resolve(to)===path.resolve(${JSON.stringify(fixture.tombstone)})) process.kill(process.pid,"SIGKILL"); return result;}; ${cleanupAction(SERVICE)}`;
      const crashed = await runChild(fixture.runtime, action, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(fixture.runtime, recoveryAction(SERVICE));
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.deepEqual(fs.readFileSync(fixture.archivePath), fixture.bytes);
      assert.equal(fs.existsSync(fixture.tombstone), false);
      assert.equal(JSON.parse(fs.readFileSync(path.join(fixture.runtime, "data", "backup-history.json"), "utf8")).length, 1);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("crash after repository deletion finalizes without an orphan", async () => {
    const fixture = retentionFixture();
    try {
      const action = `const repository=require(${JSON.stringify(REPOSITORY)}); const original=repository.deleteBackup; repository.deleteBackup=(...args)=>{const value=original(...args); process.kill(process.pid,"SIGKILL"); return value;}; ${cleanupAction(SERVICE)}`;
      const crashed = await runChild(fixture.runtime, action, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(fixture.runtime, recoveryAction(SERVICE));
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(fixture.archivePath), false);
      assert.equal(fs.existsSync(fixture.tombstone), false);
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fixture.runtime, "data", "backup-history.json"), "utf8")), []);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("crash after tombstone cleanup leaves only retryable metadata", async () => {
    const fixture = retentionFixture();
    try {
      const action = `const fs=require("fs"); const path=require("path"); const original=fs.rmSync; fs.rmSync=(target,options)=>{const result=original(target,options); if(path.resolve(target)===path.resolve(${JSON.stringify(fixture.tombstone)})) process.kill(process.pid,"SIGKILL"); return result;}; ${cleanupAction(SERVICE)}`;
      const crashed = await runChild(fixture.runtime, action, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(fixture.runtime, recoveryAction(SERVICE));
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(fixture.archivePath), false);
      assert.equal(fs.existsSync(fixture.tombstone), false);
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fixture.runtime, "data", "backup-history.json"), "utf8")), []);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("prepared metadata with untouched archive is discarded safely", async () => {
    const fixture = retentionFixture();
    try {
      const record = transactionFor(fixture, "prepared");
      const result = await runChild(fixture.runtime, recoveryAction(SERVICE));
      assert.equal(result.code, 0, result.stderr);
      assert.equal(fs.existsSync(record.directory), false);
      assert.deepEqual(fs.readFileSync(fixture.archivePath), fixture.bytes);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("history-present and history-absent tombstones choose restore or finalize", async () => {
    for (const history of [true, false]) {
      const fixture = retentionFixture({ history });
      try {
        fs.renameSync(fixture.archivePath, fixture.tombstone);
        transactionFor(fixture, "archive_moved");
        const result = await runChild(fixture.runtime, recoveryAction(SERVICE));
        assert.equal(result.code, 0, result.stderr);
        assert.equal(fs.existsSync(fixture.archivePath), history);
        assert.equal(fs.existsSync(fixture.tombstone), false);
      } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
    }
  });

  await t.test("equal duplicate bytes converge and conflicting bytes fail closed", async () => {
    const equal = retentionFixture();
    try {
      fs.copyFileSync(equal.archivePath, equal.tombstone);
      transactionFor(equal, "history_removed");
      fs.writeFileSync(path.join(equal.runtime, "data", "backup-history.json"), "[]");
      const recovered = await runChild(equal.runtime, recoveryAction(SERVICE));
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(equal.archivePath), false);
      assert.equal(fs.existsSync(equal.tombstone), false);
    } finally { fs.rmSync(equal.runtime, { recursive: true, force: true }); }

    const conflict = retentionFixture();
    try {
      fs.writeFileSync(conflict.tombstone, "different");
      transactionFor(conflict, "archive_moved");
      const failed = await runChild(conflict.runtime, recoveryAction(SERVICE));
      assert.notEqual(failed.code, 0);
      assert.equal(fs.existsSync(conflict.archivePath), true);
      assert.equal(fs.existsSync(conflict.tombstone), true);
    } finally { fs.rmSync(conflict.runtime, { recursive: true, force: true }); }
  });

  await t.test("repository, rename, and cleanup failures remain observable and retryable", async () => {
    const failure = retentionFixture();
    try {
      const result = await runChild(failure.runtime, `const repository=require(${JSON.stringify(REPOSITORY)}); repository.deleteBackup=()=>{throw Object.assign(new Error("repository"),{code:"EFAIL"})}; ${cleanupAction(SERVICE)}`, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(result.code, 0);
      assert.equal(fs.existsSync(failure.archivePath), true);
      assert.equal(fs.existsSync(failure.tombstone), false);
    } finally { fs.rmSync(failure.runtime, { recursive: true, force: true }); }

    for (const code of ["EPERM", "EBUSY"]) {
      const fixture = retentionFixture();
      try {
        const result = await runChild(fixture.runtime, `const fs=require("fs"); const path=require("path"); const original=fs.rmSync; let failed=false; fs.rmSync=(target,options)=>{if(path.resolve(target)===path.resolve(${JSON.stringify(fixture.tombstone)})&&!failed){failed=true;throw Object.assign(new Error("busy"),{code:${JSON.stringify(code)}})} return original(target,options)}; ${cleanupAction(SERVICE)}`, { BACKUP_RETENTION_DAYS: "1" });
        assert.notEqual(result.code, 0);
        assert.equal(fs.existsSync(fixture.tombstone), true);
        const retry = await runChild(fixture.runtime, recoveryAction(SERVICE));
        assert.equal(retry.code, 0, retry.stderr);
        assert.equal(fs.existsSync(fixture.tombstone), false);
      } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
    }
  });

  await t.test("duplicate transaction claims and outside-root paths fail closed", async () => {
    const fixture = retentionFixture();
    try {
      transactionFor(fixture, "prepared");
      transactionFor(fixture, "prepared", { transactionId: crypto.randomUUID() });
      const duplicate = await runChild(fixture.runtime, recoveryAction(SERVICE));
      assert.notEqual(duplicate.code, 0);
      const outside = retentionFixture();
      try {
        transactionFor(outside, "prepared", { archivePath: path.join(outside.runtime, "outside.zip") });
        const failed = await runChild(outside.runtime, recoveryAction(SERVICE));
        assert.notEqual(failed.code, 0);
      } finally { fs.rmSync(outside.runtime, { recursive: true, force: true }); }
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("recovery is idempotent across repeated restarts", async () => {
    const fixture = retentionFixture({ history: false });
    try {
      fs.renameSync(fixture.archivePath, fixture.tombstone);
      transactionFor(fixture, "history_removed");
      for (let attempt = 0; attempt < 3; attempt += 1) {
        const result = await runChild(fixture.runtime, recoveryAction(SERVICE));
        assert.equal(result.code, 0, result.stderr);
      }
      assert.equal(fs.existsSync(fixture.archivePath), false);
      assert.equal(fs.existsSync(fixture.tombstone), false);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });
});

test("normal server startup recovers backup tombstones before listening and fails closed on corrupt journals", { timeout: 45_000 }, async (t) => {
  const serverPath = path.join(ROOT, "server.js");
  const runtimeEnv = {
    NODE_ENV: "test",
    DB_ENABLED: "false",
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_RESTORE_INSTANCE_COUNT: "1",
    ROOTARK_INSTANCE_ID: "backup-recovery-startup-fixture",
    JWT_SECRET: "j".repeat(48),
    BACKUP_ENABLED: "true",
    CLOUD_STORAGE_PROVIDER: "local",
    PORT: "0",
  };
  const restartAtListener = (fixture, resultPath) => `
    const fs = require("fs");
    const net = require("net");
    const repository = require(${JSON.stringify(REPOSITORY)});
    const service = require(${JSON.stringify(SERVICE)});
    net.Server.prototype.listen = function () {
      const history = repository.getBackup(${JSON.stringify(fixture.id)});
      const result = {
        archiveExists: fs.existsSync(${JSON.stringify(fixture.archivePath)}),
        tombstoneExists: fs.existsSync(${JSON.stringify(fixture.tombstone)}),
        historyExists: Boolean(history),
        transactionRootExists: fs.existsSync(${JSON.stringify(fixture.transactionRoot)})
          && fs.readdirSync(${JSON.stringify(fixture.transactionRoot)}).length > 0,
      };
      fs.writeFileSync(${JSON.stringify(resultPath)}, JSON.stringify(result));
      const expected = ${JSON.stringify(fixture.expected)};
      process.exit(JSON.stringify(result) === JSON.stringify(expected) ? 0 : 4);
    };
    require(${JSON.stringify(serverPath)});
  `;

  for (const boundary of ["before-history-removal", "after-history-removal"]) {
    await t.test(`${boundary} crash is recovered through server entrypoint`, async () => {
      const fixture = retentionFixture();
      try {
        const action = boundary === "before-history-removal"
          ? `const fs=require("fs"); const path=require("path"); const service=require(${JSON.stringify(SERVICE)}); const original=fs.renameSync; fs.renameSync=function(from,to){const result=original.call(this,from,to); if(path.resolve(from)===path.resolve(${JSON.stringify(fixture.archivePath)})&&path.resolve(to)===path.resolve(${JSON.stringify(fixture.tombstone)})) process.kill(process.pid,"SIGKILL"); return result;}; service.deleteBackup(${JSON.stringify(fixture.id)}).catch(error=>{console.error(error);process.exitCode=1;});`
          : `const repository=require(${JSON.stringify(REPOSITORY)}); const original=repository.deleteBackup; repository.deleteBackup=(...args)=>{const result=original(...args); process.kill(process.pid,"SIGKILL"); return result;}; require(${JSON.stringify(SERVICE)}).deleteBackup(${JSON.stringify(fixture.id)}).catch(error=>{console.error(error);process.exitCode=1;});`;
        const crashed = await runChild(fixture.runtime, action);
        assert.notEqual(crashed.code, 0);
        // The operation-lock recovery path is independent; these cases isolate history/tombstone startup recovery.
        fs.rmSync(path.join(fixture.runtime, "data", "backups", ".backup.lock"), { force: true });
        fixture.expected = boundary === "before-history-removal"
          ? { archiveExists: true, tombstoneExists: false, historyExists: true, transactionRootExists: false }
          : { archiveExists: false, tombstoneExists: false, historyExists: false, transactionRootExists: false };
        const resultPath = path.join(fixture.runtime, "server-recovery-result.json");
        const restarted = await runChild(fixture.runtime, restartAtListener(fixture, resultPath), runtimeEnv);
        assert.equal(restarted.code, 0, restarted.stderr || restarted.stdout);
        assert.deepEqual(JSON.parse(fs.readFileSync(resultPath, "utf8")), fixture.expected);
      } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
    });
  }

  await t.test("corrupt transaction metadata prevents the listener from starting", async () => {
    const fixture = retentionFixture();
    try {
      const record = transactionFor(fixture, "archive_moved");
      fs.writeFileSync(path.join(record.directory, "transaction.json"), "{broken");
      const listenerMarker = path.join(fixture.runtime, "listener-started");
      const action = `const fs=require("fs"); const net=require("net"); net.Server.prototype.listen=function(){fs.writeFileSync(${JSON.stringify(listenerMarker)},"started"); process.exit(0);}; require(${JSON.stringify(serverPath)});`;
      const result = await runChild(fixture.runtime, action, runtimeEnv);
      assert.notEqual(result.code, 0, "corrupt journal state must block normal startup");
      assert.equal(fs.existsSync(listenerMarker), false, "the listener must not be opened when recovery is ambiguous");
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });
});

test("retention journal and archive transitions sync parent directories after each durable step", { timeout: 30_000 }, async (t) => {
  if (process.platform === "win32") {
    t.skip("Node.js on Windows has no supported parent-directory fsync path");
    return;
  }
  const fixture = retentionFixture();
  try {
    const script = `
      const fs=require("fs"); const path=require("path"); const service=require(${JSON.stringify(SERVICE)});
      const events=[]; const fdPaths=new Map(); const originalOpen=fs.openSync; const originalClose=fs.closeSync;
      const originalFsync=fs.fsyncSync; const originalRename=fs.renameSync; const originalRm=fs.rmSync;
      fs.openSync=function(target,...args){const fd=originalOpen.call(this,target,...args);fdPaths.set(fd,String(target));return fd;};
      fs.closeSync=function(fd){fdPaths.delete(fd);return originalClose.call(this,fd);};
      fs.fsyncSync=function(fd){const target=fdPaths.get(fd);if(target&&fs.statSync(target).isDirectory())events.push("dir-sync:"+path.resolve(target));else events.push("file-sync:"+target);return originalFsync.call(this,fd);};
      fs.renameSync=function(from,to){const result=originalRename.call(this,from,to);if(String(to).endsWith("transaction.json"))events.push("journal-rename:"+path.resolve(to));if(path.resolve(from)===path.resolve(${JSON.stringify(fixture.archivePath)})&&path.resolve(to)===path.resolve(${JSON.stringify(fixture.tombstone)}))events.push("archive-rename");return result;};
      fs.rmSync=function(target,options){const result=originalRm.call(this,target,options);const resolved=path.resolve(target);if(resolved===path.resolve(${JSON.stringify(fixture.tombstone)}))events.push("tombstone-remove");if(String(target).endsWith("transaction.json"))events.push("transaction-file-remove:"+path.dirname(resolved));if(path.dirname(resolved)===path.resolve(service.RETENTION_TRANSACTIONS_DIR))events.push("transaction-directory-remove:"+path.dirname(resolved));return result;};
      process.env.BACKUP_RETENTION_DAYS="1";process.env.BACKUP_RETENTION_COUNT="0";
      service.cleanupRetention().then(()=>console.log(JSON.stringify(events))).catch(error=>{console.error(error);process.exitCode=1;});
    `;
    const result = await runChild(fixture.runtime, script);
    assert.equal(result.code, 0, result.stderr);
    const events = JSON.parse(result.stdout.trim());
    const backupDir = path.join(fixture.runtime, "data", "backups");
    const transactionsDir = fixture.transactionRoot;
    for (const event of events.filter((value) => value.startsWith("journal-rename:"))) {
      const directory = path.dirname(event.slice("journal-rename:".length));
      const index = events.indexOf(event);
      assert.equal(events[index + 1], `dir-sync:${directory}`, "journal rename must be followed by its directory fsync");
    }
    for (const event of ["archive-rename", "tombstone-remove"]) {
      const index = events.indexOf(event);
      assert.notEqual(index, -1, `${event} must be observed`);
      assert.equal(events[index + 1], `dir-sync:${backupDir}`, `${event} must be followed by backup-directory fsync`);
    }
    for (const event of events.filter((value) => value.startsWith("transaction-file-remove:"))) {
      const directory = event.slice("transaction-file-remove:".length);
      const index = events.indexOf(event);
      assert.equal(events[index + 1], `dir-sync:${directory}`, "transaction removal must sync its containing directory");
    }
    const transactionDirectoryRemoval = events.findIndex((value) => value.startsWith("transaction-directory-remove:"));
    assert.notEqual(transactionDirectoryRemoval, -1, "the transaction directory must be removed");
    assert.equal(events[transactionDirectoryRemoval + 1], `dir-sync:${transactionsDir}`, "removing the transaction directory must sync its parent");
  } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
});

test("parent-directory fsync failure after archive rename rolls the retention move back", { timeout: 20_000 }, async (t) => {
  if (process.platform === "win32") {
    t.skip("Node.js on Windows has no supported parent-directory fsync path");
    return;
  }
  const fixture = retentionFixture();
  try {
    const script = `
      const fs=require("fs"); const path=require("path"); const service=require(${JSON.stringify(SERVICE)}); const repository=require(${JSON.stringify(REPOSITORY)});
      const originalOpen=fs.openSync; const originalFsync=fs.fsyncSync; const originalRename=fs.renameSync; const fdPaths=new Map(); let moved=false; let injected=false;
      fs.openSync=function(target,...args){const fd=originalOpen.call(this,target,...args);fdPaths.set(fd,String(target));return fd;};
      fs.fsyncSync=function(fd){const target=fdPaths.get(fd);if(moved&&!injected&&target===service.BACKUPS_DIR){injected=true;throw Object.assign(new Error("injected parent directory fsync failure"),{code:"EIO"});}return originalFsync.call(this,fd);};
      fs.renameSync=function(from,to){const result=originalRename.call(this,from,to);if(path.resolve(from)===path.resolve(${JSON.stringify(fixture.archivePath)})&&path.resolve(to)===path.resolve(${JSON.stringify(fixture.tombstone)}))moved=true;return result;};
      process.env.BACKUP_RETENTION_DAYS="1";process.env.BACKUP_RETENTION_COUNT="0";
      service.cleanupRetention().then(()=>{console.log(JSON.stringify({injected,unexpectedSuccess:true}));}).catch(error=>console.log(JSON.stringify({injected,error:error.message,archive:fs.existsSync(${JSON.stringify(fixture.archivePath)}),tombstone:fs.existsSync(${JSON.stringify(fixture.tombstone)}),history:Boolean(repository.getBackup(${JSON.stringify(fixture.id)}))})));
    `;
    const result = await runChild(fixture.runtime, script);
    assert.equal(result.code, 0, result.stderr);
    const outcome = JSON.parse(result.stdout.trim());
    assert.equal(outcome.injected, true);
    assert.match(outcome.error || "", /injected parent directory fsync failure/);
    assert.equal(outcome.archive, true);
    assert.equal(outcome.tombstone, false);
    assert.equal(outcome.history, true);
  } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
});
