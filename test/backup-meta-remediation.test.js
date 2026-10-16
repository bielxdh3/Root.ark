const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const os = require("os");
const path = require("path");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-meta-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupService = require("../services/backupService");
const backupRepository = require("../repositories/backupRepository");
const { isValidTimezone, parseBackupTime, scheduleAutomaticBackups } = require("../services/backupScheduler");

function hasVerifiableLinuxProcessIdentity() {
  if (process.platform !== "linux") return false;
  try {
    const pidNamespaceId = fs.readlinkSync("/proc/self/ns/pid");
    const selfStat = fs.readFileSync("/proc/self/stat", "utf8");
    const selfPidDelimiter = selfStat.indexOf(" (");
    if (selfPidDelimiter < 1 || Number(selfStat.slice(0, selfPidDelimiter)) !== process.pid) return false;
    if (fs.readlinkSync(`/proc/${process.pid}/ns/pid`) !== pidNamespaceId) return false;
    const status = fs.readFileSync("/proc/self/status", "utf8");
    const namespacePids = /^NSpid:\s*([0-9]+(?:\s+[0-9]+)*)\s*$/m.exec(status)?.[1];
    if (!namespacePids || Number(namespacePids.trim().split(/\s+/).at(-1)) !== process.pid) return false;
    const startIdentity = selfStat.slice(selfStat.lastIndexOf(")") + 1).trim().split(/\s+/)[19];
    return Boolean(fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim() && startIdentity);
  } catch {
    return false;
  }
}

const CAN_VERIFY_LINUX_PROCESS_IDENTITY = hasVerifiableLinuxProcessIdentity();

function findDefinitelyDeadPid() {
  const highestValidPid = 0x7fffffff;
  for (let pid = highestValidPid; pid > highestValidPid - 1024; pid -= 1) {
    try { process.kill(pid, 0); } catch (error) {
      if (error.code === "ESRCH") return pid;
      if (error.code !== "EPERM") throw error;
    }
  }
  throw new Error("could not find an unused PID for the lock-recovery fixture");
}

function reset() {
  for (const name of ["data", "uploads", "temp"]) fs.rmSync(path.join(runtime, name), { recursive: true, force: true });
  fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  for (const name of ["BACKUP_ENABLED", "BACKUP_AUTO_ENABLED", "BACKUP_RETENTION_COUNT", "BACKUP_RETENTION_DAYS", "BACKUP_LOCK_STALE_MS"]) delete process.env[name];
}

function saveHistory(entries) {
  fs.mkdirSync(path.join(runtime, "data"), { recursive: true });
  fs.writeFileSync(path.join(runtime, "data", "backup-history.json"), JSON.stringify(entries));
  for (const entry of entries) {
    if (entry.filename) {
      fs.mkdirSync(backupService.BACKUPS_DIR, { recursive: true });
      fs.writeFileSync(path.join(backupService.BACKUPS_DIR, entry.filename), entry.id || "archive");
    }
  }
}

function entry(id, filename, createdAt, extra = {}) {
  return { id, filename, status: "success", type: "manual", createdAt, ...extra };
}

function cronHarness() {
  let callback;
  let stopped = 0;
  const cron = { schedule: (_expr, fn, options) => { callback = fn; return { options, stop: () => { stopped += 1; }, destroy: () => { stopped += 1; } }; } };
  return { cron, get callback() { return callback; }, get stopped() { return stopped; } };
}

test("scheduler, lock, filename, and retention meta-remediation matrix", async (t) => {
  await t.test("backups disabled", async () => { reset(); process.env.BACKUP_ENABLED = "false"; await assert.rejects(backupService.createBackup()); });
  await t.test("automatic disabled", () => { const h = cronHarness(); assert.equal(scheduleAutomaticBackups({ env: { BACKUP_AUTO_ENABLED: "false" }, cron: h.cron, createBackup: async () => {} }), null); });
  await t.test("valid time", () => assert.deepEqual(parseBackupTime("03:00"), { hour: 3, minute: 0 }));
  await t.test("invalid hour", () => assert.equal(parseBackupTime("24:00"), null));
  await t.test("invalid minute", () => assert.equal(parseBackupTime("03:60"), null));
  await t.test("malformed time", () => assert.equal(parseBackupTime("3:00"), null));
  await t.test("valid timezone", () => assert.equal(isValidTimezone("America/Cuiaba"), true));
  await t.test("invalid timezone", () => { const h = cronHarness(); let message; assert.equal(scheduleAutomaticBackups({ env: { BACKUP_TIMEZONE: "No/Such_Zone" }, cron: h.cron, createBackup: async () => {}, onInvalid: (value) => { message = value; } }), null); assert.match(message, /TIMEZONE/); });
  await t.test("duplicate registration", () => { const h = cronHarness(); const first = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); const second = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); assert.equal(first, second); first.destroy(); });
  await t.test("automatic type", async () => { const h = cronHarness(); let received; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async (value) => { received = value; return { id: "automatic" }; } }); await h.callback(); assert.equal(received.type, "automatic"); task.destroy(); });
  await t.test("overlap", async () => { const h = cronHarness(); let resolve; const wait = new Promise((done) => { resolve = done; }); let calls = 0; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => { calls += 1; await wait; return { id: "x" }; } }); const first = h.callback(); const second = h.callback(); resolve(); await Promise.all([first, second]); assert.equal(calls, 1); task.destroy(); });
  await t.test("success audit", async () => { const h = cronHarness(); const events = []; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => ({ id: "ok", filename: "x" }), auditLog: (...args) => events.push(args) }); await h.callback(); assert.equal(events[0][0], "backup.created"); assert.equal(task.latestStatus().state, "success"); task.destroy(); });
  await t.test("failure audit", async () => { const h = cronHarness(); const events = []; const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => { throw new Error("failure"); }, auditLog: (...args) => events.push(args) }); await h.callback(); assert.equal(events[0][0], "backup.failed"); assert.equal(task.latestStatus().state, "failure"); task.destroy(); });
  await t.test("stop", () => { const h = cronHarness(); const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); task.stop(); assert.equal(h.stopped, 1); });
  await t.test("shutdown destroy", () => { const h = cronHarness(); const task = scheduleAutomaticBackups({ env: {}, cron: h.cron, createBackup: async () => {} }); task.destroy(); assert.equal(task.latestStatus().state, "stopped"); });
  await t.test("same-millisecond backups", async () => { reset(); const first = await backupService.createBackup(); const second = await backupService.createBackup(); assert.notEqual(first.filename, second.filename); });
  await t.test("existing filename is never truncated", async () => { reset(); const existing = path.join(backupService.BACKUPS_DIR, "rootark-backup-2020-01-01-00-00-00.zip"); fs.writeFileSync(existing, "keep"); await backupService.createBackup(); assert.equal(fs.readFileSync(existing, "utf8"), "keep"); });
  await t.test("create failure releases lock", async () => { reset(); const original = fs.createWriteStream; fs.createWriteStream = () => { throw new Error("create failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { fs.createWriteStream = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("archive finalize failure path releases lock", async () => { reset(); const original = fs.createWriteStream; fs.createWriteStream = () => { throw new Error("finalize failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { fs.createWriteStream = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("checksum failure path releases lock", async () => { reset(); const original = fs.createReadStream; fs.createReadStream = () => { throw new Error("checksum failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { fs.createReadStream = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("history failure path releases lock", async () => { reset(); const original = backupRepository.saveBackup; backupRepository.saveBackup = () => { throw new Error("history failure"); }; try { await assert.rejects(backupService.createBackup()); } finally { backupRepository.saveBackup = original; } const release = backupService.acquireLock("backup"); release(); });
  await t.test("backup/backup exclusion", () => { const release = backupService.acquireLock("backup"); try { assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" }); } finally { release(); } });
  await t.test("backup/restore exclusion", () => { const release = backupService.acquireLock("backup"); try { assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" }); } finally { release(); } });
  await t.test("backup/delete exclusion", () => { const release = backupService.acquireLock("backup"); try { assert.throws(() => backupService.acquireLock("delete"), { code: "BACKUP_LOCKED" }); } finally { release(); } });
  await t.test("live external lock", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ token: "external", operation: "backup", pid: process.pid, runtimeRoot: runtime })); fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0)); assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" }); fs.rmSync(backupService.LOCK_FILE, { force: true }); });
  await t.test("lock snapshot does not switch to a replacement pathname after opening", () => {
    reset();
    const replacementPath = `${backupService.LOCK_FILE}.prior`;
    const originalRelease = backupService.acquireLock("backup");
    const originalRecord = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    originalRelease();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ ...originalRecord, token: "original-live", pid: process.pid }));
    const staleRecord = { ...originalRecord, token: "replacement-stale", pid: 99999999, processInstanceId: "prior-process-instance", startedAt: new Date(0).toISOString() };
    let replaced = false;
    let lease;
    let failure;
    const originalStat = fs.statSync;
    const originalOpen = fs.openSync;
    const replaceLockPath = () => {
      if (replaced) return;
      replaced = true;
      fs.renameSync(backupService.LOCK_FILE, replacementPath);
      fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(staleRecord));
      fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    };
    fs.statSync = function (target, ...args) {
      const result = originalStat.call(this, target, ...args);
      if (target === backupService.LOCK_FILE) replaceLockPath();
      return result;
    };
    fs.openSync = function (target, ...args) {
      const fd = originalOpen.call(this, target, ...args);
      if (target === backupService.LOCK_FILE) replaceLockPath();
      return fd;
    };
    try {
      try { lease = backupService.acquireLock("backup"); } catch (error) { failure = error; }
    } finally {
      fs.statSync = originalStat;
      fs.openSync = originalOpen;
    }
    try {
      if (lease) lease();
      assert.equal(failure?.code, "BACKUP_LOCKED");
      assert.equal(replaced, true);
      assert.equal(JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8")).token, "replacement-stale");
    } finally {
      fs.rmSync(backupService.LOCK_FILE, { force: true });
      fs.rmSync(replacementPath, { force: true });
      fs.rmSync(backupService.LOCK_TAKEOVER_DIR, { recursive: true, force: true });
    }
  });
  await t.test("takeover evidence path replacement fails closed and preserves the replacement", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verifiable Linux /proc process identity" : false }, () => {
    reset();
    const evidencePath = path.join(backupService.LOCK_TAKEOVER_DIR, "evidence");
    const replacementPath = `${evidencePath}.prior`;
    const originalRelease = backupService.acquireLock("backup");
    const originalRecord = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    originalRelease();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ ...originalRecord, token: "stale", pid: 99999999, processInstanceId: "prior-process-instance", startedAt: new Date(0).toISOString() }));
    fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    let replaced = false;
    let lease;
    let failure;
    const originalRead = fs.readFileSync;
    const originalLstat = fs.lstatSync;
    const originalOpen = fs.openSync;
    let replacing = false;
    const replaceEvidence = () => {
      if (replaced || replacing) return;
      replacing = true;
      try {
        const bytes = originalRead.call(fs, evidencePath);
        fs.renameSync(evidencePath, replacementPath);
        fs.writeFileSync(evidencePath, bytes);
        replaced = true;
      } finally {
        replacing = false;
      }
    };
    fs.lstatSync = function (target, ...args) {
      const result = originalLstat.call(this, target, ...args);
      if (target === evidencePath) replaceEvidence();
      return result;
    };
    fs.openSync = function (target, ...args) {
      if (target === evidencePath) replaceEvidence();
      return originalOpen.call(this, target, ...args);
    };
    try {
      try { lease = backupService.acquireLock("backup"); } catch (error) { failure = error; }
    } finally {
      fs.readFileSync = originalRead;
      fs.lstatSync = originalLstat;
      fs.openSync = originalOpen;
      if (lease) lease();
    }
    assert.equal(replaced, true, `evidence swap hook was not reached (${failure?.code || "no error"}: ${failure?.message || ""})`);
    assert.equal(failure?.code, "BACKUP_LOCKED");
    assert.equal(fs.existsSync(evidencePath), true);
    fs.rmSync(backupService.LOCK_TAKEOVER_DIR, { recursive: true, force: true });
    fs.rmSync(backupService.LOCK_FILE, { force: true });
    fs.rmSync(replacementPath, { force: true });
  });
  await t.test("takeover authority snapshot fails closed when its pathname is replaced after opening", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verifiable Linux /proc process identity" : false }, () => {
    reset();
    const authorityPath = path.join(backupService.LOCK_TAKEOVER_DIR, "authority.json");
    const priorPath = `${authorityPath}.prior`;
    const replacementPath = path.join(backupService.BACKUPS_DIR, "authority-replacement.fixture");
    const replacementBytes = Buffer.from("replacement authority must not be followed");
    const originalRelease = backupService.acquireLock("backup");
    const originalRecord = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    originalRelease();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ ...originalRecord, token: "stale-authority-read", pid: 99999999, processInstanceId: "prior-process-instance", startedAt: new Date(0).toISOString() }));
    fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    fs.writeFileSync(replacementPath, replacementBytes, { flag: "wx", mode: 0o600 });
    let replaced = false;
    let authorityFd;
    let authorityWasRead = false;
    let lease;
    let failure;
    const originalOpen = fs.openSync;
    const originalRead = fs.readFileSync;
    const originalClose = fs.closeSync;
    const originalRename = fs.renameSync;
    fs.openSync = function (target, ...args) {
      const fd = originalOpen.call(this, target, ...args);
      if (!replaced && target === authorityPath) {
        authorityFd = fd;
        originalRename.call(fs, authorityPath, priorPath);
        originalRename.call(fs, replacementPath, authorityPath);
        replaced = true;
      }
      return fd;
    };
    fs.readFileSync = function (target, ...args) {
      if (target === authorityFd) {
        authorityWasRead = true;
        authorityFd = undefined;
      }
      return originalRead.call(this, target, ...args);
    };
    fs.closeSync = function (target, ...args) {
      if (target === authorityFd) authorityFd = undefined;
      return originalClose.call(this, target, ...args);
    };
    try {
      try { lease = backupService.acquireLock("backup"); } catch (error) { failure = error; }
    } finally {
      fs.openSync = originalOpen;
      fs.readFileSync = originalRead;
      fs.closeSync = originalClose;
      if (lease) lease();
    }
    try {
      assert.equal(replaced, true, `authority descriptor read hook was not reached (${failure?.code || "no error"})`);
      assert.equal(failure?.code, "BACKUP_LOCKED");
      assert.equal(authorityWasRead, false, "a replaced authority pathname must be rejected before consuming descriptor bytes");
      assert.deepEqual(fs.readFileSync(authorityPath), replacementBytes);
    } finally {
      fs.rmSync(backupService.LOCK_FILE, { force: true });
      fs.rmSync(backupService.LOCK_TAKEOVER_DIR, { recursive: true, force: true });
      fs.rmSync(priorPath, { force: true });
      fs.rmSync(replacementPath, { force: true });
    }
  });
  await t.test("takeover cleanup preserves a replacement installed at the removal boundary", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verifiable Linux /proc process identity" : false }, () => {
    reset();
    const evidencePath = path.join(backupService.LOCK_TAKEOVER_DIR, "evidence");
    const priorPath = `${evidencePath}.prior`;
    const replacementBytes = Buffer.from("replacement owned by another writer");
    const originalRelease = backupService.acquireLock("backup");
    const originalRecord = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    originalRelease();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ ...originalRecord, token: "stale-after-open", pid: 99999999, processInstanceId: "prior-process-instance", startedAt: new Date(0).toISOString() }));
    fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    let replaced = false;
    let replacing = false;
    let lease;
    let failure;
    const originalRename = fs.renameSync;
    const originalRemove = fs.rmSync;
    const replaceEvidence = () => {
      if (replaced || replacing) return;
      replacing = true;
      try {
        originalRename.call(fs, evidencePath, priorPath);
        fs.writeFileSync(evidencePath, replacementBytes);
        replaced = true;
      } finally {
        replacing = false;
      }
    };
    fs.renameSync = function (source, target) {
      if (source === evidencePath) replaceEvidence();
      return originalRename.call(this, source, target);
    };
    fs.rmSync = function (target, ...args) {
      if (target === evidencePath) replaceEvidence();
      return originalRemove.call(this, target, ...args);
    };
    try {
      try { lease = backupService.acquireLock("backup"); } catch (error) { failure = error; }
    } finally {
      fs.renameSync = originalRename;
      fs.rmSync = originalRemove;
      if (lease) lease();
    }
    try {
      assert.equal(replaced, true);
      assert.equal(failure?.code, "BACKUP_LOCKED");
      const preserved = fs.readdirSync(backupService.LOCK_TAKEOVER_DIR)
        .map((entry) => path.join(backupService.LOCK_TAKEOVER_DIR, entry))
        .filter((entry) => fs.statSync(entry).isFile())
        .some((entry) => fs.readFileSync(entry).equals(replacementBytes));
      assert.equal(preserved, true, "replacement evidence must remain available for recovery");
    } finally {
      fs.rmSync(backupService.LOCK_FILE, { force: true });
      fs.rmSync(priorPath, { force: true });
      fs.rmSync(backupService.LOCK_TAKEOVER_DIR, { recursive: true, force: true });
    }
  });
  await t.test("restart recovery resumes cleanup after evidence was durably staged", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verifiable Linux /proc process identity" : false }, () => {
    reset();
    const authorityPath = path.join(backupService.LOCK_TAKEOVER_DIR, "authority.json");
    const deadPid = findDefinitelyDeadPid();
    const originalRelease = backupService.acquireLock("backup");
    const originalRecord = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    originalRelease();
    const staleRecord = { ...originalRecord, token: "stale-cleanup-restart", pid: deadPid, processInstanceId: "prior-process-instance", startedAt: new Date(0).toISOString() };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(staleRecord));
    fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    const originalRemove = fs.rmSync;
    let stagedCleanupPath;
    let failure;
    fs.rmSync = function (target, ...args) {
      if (typeof target === "string" && path.basename(target).startsWith(".evidence-cleanup-")) {
        stagedCleanupPath = target;
        throw new Error("injected interruption after evidence staging");
      }
      return originalRemove.call(this, target, ...args);
    };
    try { backupService.acquireLock("backup"); } catch (error) { failure = error; } finally { fs.rmSync = originalRemove; }
    assert.ok(failure, "injected interruption should prevent the first acquisition");
    assert.ok(stagedCleanupPath && fs.existsSync(stagedCleanupPath), "staged evidence must survive interruption");
    const authority = JSON.parse(fs.readFileSync(authorityPath, "utf8"));
    const localInstanceId = String(process.env.ROOTARK_INSTANCE_ID || process.env.HOSTNAME || process.env.COMPUTERNAME || os.hostname() || "default").trim();
    fs.writeFileSync(authorityPath, JSON.stringify({ ...authority, pid: deadPid, processInstanceId: "interrupted-process", instanceId: localInstanceId, claimedAt: new Date(0).toISOString() }));
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(staleRecord));
    fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    let lease;
    let recoveryFailure;
    try { lease = backupService.acquireLock("backup"); } catch (error) { recoveryFailure = error; }
    assert.ifError(recoveryFailure);
    try {
      assert.equal(fs.existsSync(backupService.LOCK_TAKEOVER_DIR), false);
    } finally {
      lease();
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("partial lock write remains fail-closed until operator recovery", () => {
    reset();
    const originalWrite = fs.writeSync;
    let writes = 0;
    fs.writeSync = function (fd, buffer, offset = 0, length, position) {
      writes += 1;
      if (writes === 1) {
        const bytes = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
        const marker = Buffer.from('"token":"');
        const markerOffset = bytes.indexOf(marker, offset);
        const tokenEnd = bytes.indexOf(Buffer.from('"'), markerOffset + marker.length);
        assert.ok(markerOffset >= 0 && tokenEnd >= 0);
        return originalWrite.call(this, fd, buffer, offset, tokenEnd + 1 - offset, position);
      }
      throw new Error("injected partial backup lock write");
    };
    try {
      assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCK_WRITE_FAILED" });
    } finally {
      fs.writeSync = originalWrite;
    }
    const partialBytes = fs.readFileSync(backupService.LOCK_FILE);
    assert.equal(partialBytes.length, 0);
    assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" });
    assert.deepEqual(fs.readFileSync(backupService.LOCK_FILE), partialBytes);
    fs.rmSync(backupService.LOCK_FILE, { force: true });
  });
  await t.test("failed lock fsync leaves an ambiguous malformed record without unlinking", () => {
    reset();
    const originalFsync = fs.fsyncSync;
    let failOnce = true;
    fs.fsyncSync = function (fd) {
      if (failOnce) {
        failOnce = false;
        throw new Error("injected backup lock fsync failure");
      }
      return originalFsync.call(this, fd);
    };
    try {
      assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCK_WRITE_FAILED" });
    } finally {
      fs.fsyncSync = originalFsync;
    }
    const malformedBytes = fs.readFileSync(backupService.LOCK_FILE);
    assert.equal(malformedBytes.length, 0);
    assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" });
    assert.deepEqual(fs.readFileSync(backupService.LOCK_FILE), malformedBytes);
    fs.rmSync(backupService.LOCK_FILE, { force: true });
  });
  await t.test("same-process versioned lock identity remains live", () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(record));
    assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
    fs.rmSync(backupService.LOCK_FILE, { force: true });
  });
  await t.test("same PID from a distinct PID namespace remains live", () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const foreignNamespace = {
      ...record,
      processInstanceId: "prior-process-instance",
      ownerIdentity: { ...record.ownerIdentity, pidNamespaceId: "foreign-pid-namespace" },
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(foreignNamespace));
    let lease;
    try {
      assert.throws(() => { lease = backupService.acquireLock("restore"); }, { code: "BACKUP_LOCKED" });
      assert.equal(fs.readFileSync(backupService.LOCK_FILE, "utf8"), JSON.stringify(foreignNamespace));
    } finally {
      lease?.();
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("procfs PID numbering mismatch cannot reclaim a live lock", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verified Linux procfs identity" : false }, () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const mismatchedView = {
      ...record,
      processInstanceId: "prior-process-instance",
      ownerIdentity: { ...record.ownerIdentity, processStartIdentity: "different-start-time" },
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(mismatchedView));
    const originalReadFileSync = fs.readFileSync;
    const ownerStatPath = `/proc/${record.pid}/stat`;
    let lease;
    fs.readFileSync = function (target, ...args) {
      if (target === "/proc/self/stat") {
        const stat = originalReadFileSync.call(fs, target, ...args);
        const delimiter = stat.indexOf(" (");
        const mismatchedPid = process.pid + 1;
        return `${mismatchedPid}${stat.slice(delimiter)}`;
      }
      if (target === ownerStatPath) {
        const stat = originalReadFileSync.call(fs, target, ...args);
        const delimiter = stat.lastIndexOf(")") + 1;
        const fields = stat.slice(delimiter).trim().split(/\s+/);
        fields[19] = String(Number(fields[19]) + 1);
        return `${stat.slice(0, delimiter)} ${fields.join(" ")}`;
      }
      return originalReadFileSync.call(fs, target, ...args);
    };
    try {
      assert.throws(() => { lease = backupService.acquireLock("restore"); }, { code: "BACKUP_LOCKED" });
      assert.equal(fs.readFileSync(backupService.LOCK_FILE, "utf8"), JSON.stringify(mismatchedView));
    } finally {
      fs.readFileSync = originalReadFileSync;
      lease?.();
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("procfs mounted for a different PID namespace cannot reclaim a live lock", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verified Linux procfs identity" : false }, () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const mismatchedView = {
      ...record,
      processInstanceId: "prior-process-instance",
      ownerIdentity: { ...record.ownerIdentity, processStartIdentity: "different-start-time" },
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(mismatchedView));
    const originalReadFileSync = fs.readFileSync;
    const originalReadlinkSync = fs.readlinkSync;
    const ownerStatPath = `/proc/${record.pid}/stat`;
    const ownerNamespacePath = `/proc/${record.pid}/ns/pid`;
    let lease;
    fs.readFileSync = function (target, ...args) {
      if (target === ownerStatPath) {
        const stat = originalReadFileSync.call(fs, target, ...args);
        const delimiter = stat.lastIndexOf(")") + 1;
        const fields = stat.slice(delimiter).trim().split(/\s+/);
        fields[19] = String(Number(fields[19]) + 1);
        return `${stat.slice(0, delimiter)} ${fields.join(" ")}`;
      }
      return originalReadFileSync.call(fs, target, ...args);
    };
    fs.readlinkSync = function (target, ...args) {
      if (target === ownerNamespacePath) return "pid:[foreign-namespace]";
      return originalReadlinkSync.call(fs, target, ...args);
    };
    try {
      assert.throws(() => { lease = backupService.acquireLock("restore"); }, { code: "BACKUP_LOCKED" });
      assert.equal(fs.readFileSync(backupService.LOCK_FILE, "utf8"), JSON.stringify(mismatchedView));
    } finally {
      fs.readFileSync = originalReadFileSync;
      fs.readlinkSync = originalReadlinkSync;
      lease?.();
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("procfs PID translation must match the recorded namespace PID", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verified Linux procfs identity" : false }, () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const mismatchedView = {
      ...record,
      processInstanceId: "prior-process-instance",
      ownerIdentity: { ...record.ownerIdentity, processStartIdentity: "different-start-time" },
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(mismatchedView));
    const originalReadFileSync = fs.readFileSync;
    const ownerStatPath = `/proc/${record.pid}/stat`;
    const ownerStatusPath = `/proc/${record.pid}/status`;
    let lease;
    fs.readFileSync = function (target, ...args) {
      if (target === ownerStatusPath) {
        const status = originalReadFileSync.call(fs, target, ...args);
        return status.replace(/^NSpid:\s*(.*)$/m, (_match, pids) => {
          const values = pids.trim().split(/\s+/);
          values[values.length - 1] = String(record.pid + 1);
          return `NSpid:\t${values.join("\t")}`;
        });
      }
      if (target === ownerStatPath) {
        const stat = originalReadFileSync.call(fs, target, ...args);
        const delimiter = stat.lastIndexOf(")") + 1;
        const fields = stat.slice(delimiter).trim().split(/\s+/);
        fields[19] = String(Number(fields[19]) + 1);
        return `${stat.slice(0, delimiter)} ${fields.join(" ")}`;
      }
      return originalReadFileSync.call(fs, target, ...args);
    };
    try {
      assert.throws(() => { lease = backupService.acquireLock("restore"); }, { code: "BACKUP_LOCKED" });
      assert.equal(fs.readFileSync(backupService.LOCK_FILE, "utf8"), JSON.stringify(mismatchedView));
    } finally {
      fs.readFileSync = originalReadFileSync;
      lease?.();
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("PID reuse is reclaimable only with a different verified start identity", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verifiable Linux /proc process identity" : false }, () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    assert.ok(record.ownerIdentity?.processStartIdentity, "Linux lock must persist a verifiable process start identity");
    const reused = {
      ...record,
      processInstanceId: "prior-process-instance",
      ownerIdentity: { ...record.ownerIdentity, processStartIdentity: "different-start-time" },
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(reused));
    const recovered = backupService.acquireLock("restore");
    recovered();
  });
  await t.test("same host and PID with unverifiable owner identity remains live", () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const ambiguous = { ...record, processInstanceId: "prior-process-instance", ownerIdentity: null };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(ambiguous));
    try {
      assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
      assert.equal(fs.readFileSync(backupService.LOCK_FILE, "utf8"), JSON.stringify(ambiguous));
    } finally {
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("colliding host name and PID do not let a nonce mismatch prove reuse", () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const collision = {
      ...record,
      processInstanceId: "same-host-colliding-instance",
      ownerIdentity: { ...record.ownerIdentity, bootId: null, pidNamespaceId: null, processStartIdentity: null },
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(collision));
    try {
      assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
      assert.equal(fs.readFileSync(backupService.LOCK_FILE, "utf8"), JSON.stringify(collision));
    } finally {
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("legacy versioned lock without process identity remains fail-closed", () => {
    reset();
    const record = {
      formatVersion: 1,
      token: "legacy-versioned-lock",
      operation: "restore",
      pid: process.pid,
      instanceId: process.env.ROOTARK_INSTANCE_ID || os.hostname() || "default",
      startedAt: new Date().toISOString(),
      runtimeRoot: runtime,
    };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(record));
    assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
    fs.rmSync(backupService.LOCK_FILE, { force: true });
  });
  await t.test("same PID from a distinct instance remains live", () => {
    reset();
    const previousInstanceId = process.env.ROOTARK_INSTANCE_ID;
    process.env.ROOTARK_INSTANCE_ID = "rootark-lock-test-local";
    try {
      const record = {
        formatVersion: 1,
        token: "remote-instance-lock",
        operation: "restore",
        pid: process.pid,
        processInstanceId: "remote-process-instance",
        instanceId: "rootark-lock-test-remote",
        startedAt: new Date().toISOString(),
        runtimeRoot: runtime,
      };
      fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(record));
      assert.throws(() => backupService.acquireLock("restore"), { code: "BACKUP_LOCKED" });
    } finally {
      if (previousInstanceId === undefined) delete process.env.ROOTARK_INSTANCE_ID;
      else process.env.ROOTARK_INSTANCE_ID = previousInstanceId;
      fs.rmSync(backupService.LOCK_FILE, { force: true });
    }
  });
  await t.test("same-namespace dead PID is reclaimable with positive ESRCH proof", { skip: !CAN_VERIFY_LINUX_PROCESS_IDENTITY ? "requires verifiable Linux /proc process identity" : false }, () => {
    reset();
    const release = backupService.acquireLock("backup");
    const record = JSON.parse(fs.readFileSync(backupService.LOCK_FILE, "utf8"));
    release();
    const dead = { ...record, pid: findDefinitelyDeadPid(), processInstanceId: "prior-process-instance" };
    fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify(dead));
    const recovered = backupService.acquireLock("backup");
    recovered();
  });
  await t.test("malformed recent lock", () => { reset(); fs.writeFileSync(backupService.LOCK_FILE, "broken"); assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" }); fs.rmSync(backupService.LOCK_FILE, { force: true }); });
  await t.test("malformed stale lock stays byte-for-byte and fails closed", () => {
    reset();
    const bytes = Buffer.from("broken\u0000ambiguous-lock\n");
    fs.writeFileSync(backupService.LOCK_FILE, bytes);
    fs.utimesSync(backupService.LOCK_FILE, new Date(0), new Date(0));
    assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" });
    assert.deepEqual(fs.readFileSync(backupService.LOCK_FILE), bytes);
  });
  await t.test("stale malformed takeover authority directory is preserved", () => {
    reset();
    fs.mkdirSync(backupService.LOCK_TAKEOVER_DIR);
    fs.utimesSync(backupService.LOCK_TAKEOVER_DIR, new Date(0), new Date(0));
    assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCKED" });
    assert.equal(fs.existsSync(backupService.LOCK_TAKEOVER_DIR), true);
    assert.deepEqual(fs.readdirSync(backupService.LOCK_TAKEOVER_DIR), []);
    fs.rmdirSync(backupService.LOCK_TAKEOVER_DIR);
  });
  await t.test("lock-write failure", () => { reset(); const original = fs.openSync; let lockPathOpenAttempts = 0; fs.openSync = (target, ...args) => { if (target === backupService.LOCK_FILE && ++lockPathOpenAttempts === 2) throw Object.assign(new Error("denied"), { code: "EACCES" }); return original.call(fs, target, ...args); }; try { assert.throws(() => backupService.acquireLock("backup"), { code: "BACKUP_LOCK_WRITE_FAILED" }); } finally { fs.openSync = original; } });
  await t.test("release token mismatch", () => { reset(); const release = backupService.acquireLock("backup"); fs.writeFileSync(backupService.LOCK_FILE, JSON.stringify({ token: "other" })); release(); assert.equal(fs.existsSync(backupService.LOCK_FILE), true); fs.rmSync(backupService.LOCK_FILE, { force: true }); });
  await t.test("retention count", async () => { reset(); const now = new Date().toISOString(); const entries = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", now), entry("2", "rootark-backup-2020-01-01-00-00-01.zip", now)]; saveHistory(entries); process.env.BACKUP_RETENTION_COUNT = "1"; process.env.BACKUP_RETENTION_DAYS = "0"; await backupService.cleanupRetention(); assert.equal(backupRepository.getBackup("1"), null); });
  await t.test("retention age", async () => { reset(); const entries = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(entries); process.env.BACKUP_RETENTION_COUNT = "0"; process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.equal(backupRepository.getBackup("1"), null); });
  await t.test("combined retention policy", async () => { reset(); const entries = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z"), entry("2", "rootark-backup-2020-01-01-00-00-01.zip", new Date().toISOString())]; saveHistory(entries); process.env.BACKUP_RETENTION_COUNT = "1"; process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.equal(backupRepository.getBackup("1"), null); assert.ok(backupRepository.getBackup("2")); });
  await t.test("zero semantics", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); process.env.BACKUP_RETENTION_COUNT = "0"; process.env.BACKUP_RETENTION_DAYS = "0"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("negative values", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); process.env.BACKUP_RETENTION_COUNT = "-1"; process.env.BACKUP_RETENTION_DAYS = "-1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("pre-restore exclusion", async () => { reset(); const items = [entry("1", "rootark-pre-restore-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z", { type: "pre-restore" })]; saveHistory(items); process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("failed-backup exclusion", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z", { status: "failed" })]; saveHistory(items); process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("missing archive", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; fs.mkdirSync(path.join(runtime, "data"), { recursive: true }); fs.writeFileSync(path.join(runtime, "data", "backup-history.json"), JSON.stringify(items)); process.env.BACKUP_RETENTION_DAYS = "1"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("1")); });
  await t.test("tombstone failure", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); const original = backupRepository.deleteBackup; backupRepository.deleteBackup = () => { throw new Error("repository"); }; process.env.BACKUP_RETENTION_DAYS = "1"; try { await assert.rejects(backupService.cleanupRetention()); } finally { backupRepository.deleteBackup = original; } assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, items[0].filename)), true); });
  await t.test("repository failure restores archive", async () => { reset(); const items = [entry("1", "rootark-backup-2020-01-01-00-00-00.zip", "2020-01-01T00:00:00.000Z")]; saveHistory(items); const original = backupRepository.deleteBackup; backupRepository.deleteBackup = () => { throw new Error("fail"); }; process.env.BACKUP_RETENTION_DAYS = "1"; try { await assert.rejects(backupService.cleanupRetention()); } finally { backupRepository.deleteBackup = original; } assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, items[0].filename)), true); });
  await t.test("stale tombstone recovery", () => { reset(); const id = "1"; const filename = "rootark-backup-2020-01-01-00-00-00.zip"; saveHistory([entry(id, filename, new Date().toISOString(), { checksum: null })]); const original = path.join(backupService.BACKUPS_DIR, filename); const tombstone = `${original}.retention-tombstone`; fs.renameSync(original, tombstone); fs.writeFileSync(`${tombstone}.json`, JSON.stringify({ backupId: id, filename, checksum: null })); backupService.recoverRetentionTombstones(); assert.equal(fs.existsSync(original), true); });
  await t.test("repository-absent tombstone is finalized without recreating an orphan", () => { reset(); const filename = "rootark-backup-2020-01-01-00-00-00.zip"; const tombstone = path.join(backupService.BACKUPS_DIR, `${filename}.retention-tombstone`); fs.writeFileSync(tombstone, "archive"); fs.writeFileSync(`${tombstone}.json`, JSON.stringify({ backupId: "missing", filename, checksum: null })); backupService.recoverRetentionTombstones(); assert.equal(fs.existsSync(path.join(backupService.BACKUPS_DIR, filename)), false); assert.equal(fs.existsSync(tombstone), false); });
  await t.test("equal timestamp ordering", async () => { reset(); const at = new Date().toISOString(); const items = [entry("a", "rootark-backup-2020-01-01-00-00-00.zip", at), entry("b", "rootark-backup-2020-01-01-00-00-01.zip", at)]; saveHistory(items); process.env.BACKUP_RETENTION_COUNT = "1"; process.env.BACKUP_RETENTION_DAYS = "0"; await backupService.cleanupRetention(); assert.ok(backupRepository.getBackup("b")); });
  await t.test("outside-root protection", () => assert.equal(backupService.getArchivePath("../outside.zip"), null));
  await t.test("interrupted-retention restart", () => { reset(); const id = "restart"; const filename = "rootark-backup-2020-01-01-00-00-00.zip"; saveHistory([entry(id, filename, new Date().toISOString())]); const original = path.join(backupService.BACKUPS_DIR, filename); const tombstone = `${original}.retention-tombstone`; fs.renameSync(original, tombstone); fs.writeFileSync(`${tombstone}.json`, JSON.stringify({ backupId: id, filename, checksum: null })); backupService.recoverRetentionTombstones(); assert.equal(fs.readFileSync(original, "utf8"), "restart"); });
});

test.after(() => { process.chdir(originalCwd); fs.rmSync(runtime, { recursive: true, force: true }); });
