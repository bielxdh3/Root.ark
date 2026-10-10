const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-metadata-lock-"));
const repoRoot = path.resolve(__dirname, "..");
const staleRaceChild = path.join(__dirname, "helpers", "backup-metadata-lock-race-child.js");
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupRepository = require("../repositories/backupRepository");

function reset() {
  fs.rmSync(path.join(runtime, "data"), { recursive: true, force: true });
  fs.mkdirSync(path.join(runtime, "data"), { recursive: true });
}

function rootIdentity() {
  return fs.realpathSync(runtime);
}

function lockRecord(overrides = {}) {
  return {
    formatVersion: 1,
    token: "seed-token",
    pid: process.pid,
    processStartIdentity: null,
    createdAt: new Date().toISOString(),
    runtimeRootIdentity: rootIdentity(),
    operationName: "restore-sync",
    ...overrides,
  };
}

function writeLock(value) {
  fs.mkdirSync(path.dirname(backupRepository.MUTATION_LOCK_FILE), { recursive: true });
  fs.writeFileSync(backupRepository.MUTATION_LOCK_FILE, typeof value === "string" ? value : JSON.stringify(value));
}

function readLock() {
  return JSON.parse(fs.readFileSync(backupRepository.MUTATION_LOCK_FILE, "utf8"));
}

function withDifferentLockFileIdentity(callback) {
  const originalLstatSync = fs.lstatSync;
  fs.lstatSync = function (target, ...args) {
    const stat = originalLstatSync.call(this, target, ...args);
    if (path.resolve(String(target)) !== path.resolve(backupRepository.MUTATION_LOCK_FILE)) return stat;
    const altered = Object.assign(Object.create(Object.getPrototypeOf(stat)), stat);
    altered.dev += 1;
    altered.ino += 1;
    altered.birthtimeMs += 1;
    altered.ctimeMs += 1;
    return altered;
  };
  try { return callback(); }
  finally { fs.lstatSync = originalLstatSync; }
}

function childSource(action) {
  const repositoryPath = JSON.stringify(path.join(repoRoot, "repositories", "backupRepository.js"));
  return `
    const fs = require("node:fs");
    const path = require("node:path");
    const repository = require(${repositoryPath});
    ${action}
  `;
}

function startChild(action, extraEnv = {}) {
  const child = spawn(process.execPath, ["-e", childSource(action)], {
    cwd: runtime,
    env: { ...process.env, NODE_PATH: process.env.NODE_PATH || path.join(repoRoot, "node_modules"), ...extraEnv },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const result = new Promise((resolve, reject) => {
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
  });
  return { child, result };
}

function runChild(action, extraEnv = {}) {
  return startChild(action, extraEnv).result;
}

function seedMutation() {
  const id = "00000000-0000-4000-8000-000000000001";
  return backupRepository.saveBackup({
    id,
    filename: "rootark-backup-2026-08-01-00-00-01.zip",
    metadata: {
      restoreSync: {
        operationId: "operation-1",
        revision: 0,
        state: "pending",
        entries: [{ entryId: "entry-1", state: "pending", leaseToken: null, leaseUntil: null }],
        transitions: [],
      },
    },
  });
}

test("JSON metadata lock uses crash-safe bounded ownership", async (t) => {
  await t.test("normal acquisition and release persist the complete record", () => {
    reset();
    const lease = backupRepository.acquireJsonMutationLock("test-operation");
    const record = readLock();
    assert.equal(record.formatVersion, 1);
    assert.equal(record.token, lease.token);
    assert.equal(record.pid, process.pid);
    assert.equal(record.operationName, "test-operation");
    assert.equal(record.runtimeRootIdentity, rootIdentity());
    assert.ok(record.createdAt);
    lease.release();
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false);
  });

  await t.test("second live owner is denied without synchronous waiting", () => {
    reset();
    const lease = backupRepository.acquireJsonMutationLock();
    assert.throws(() => backupRepository.acquireJsonMutationLock(), { code: "BACKUP_METADATA_LOCK_BUSY" });
    lease.release();
  });

  await t.test("token mismatch does not release a replacement lock", () => {
    reset();
    const lease = backupRepository.acquireJsonMutationLock();
    writeLock(lockRecord({ token: "replacement-token" }));
    lease.release();
    assert.equal(readLock().token, "replacement-token");
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  });

  await t.test("dead PID is reclaimed", async () => {
    reset();
    const child = await runChild("process.exit(19);");
    writeLock(lockRecord({ pid: child.pid || 999999, createdAt: new Date().toISOString() }));
    const lease = backupRepository.acquireJsonMutationLock();
    lease.release();
  });

  await t.test("recent live PID remains authoritative", () => {
    reset();
    writeLock(lockRecord());
    assert.throws(() => backupRepository.acquireJsonMutationLock(), { code: "BACKUP_METADATA_LOCK_BUSY" });
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  });

  await t.test("expired lock with a live owner remains authoritative", () => {
    reset();
    writeLock(lockRecord({ createdAt: new Date(Date.now() - 31_000).toISOString() }));
    assert.throws(() => backupRepository.acquireJsonMutationLock(), (error) =>
      error.code === "BACKUP_METADATA_LOCK_BUSY" && error.reason === "live-owner-expired");
    assert.equal(readLock().token, "seed-token");
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  });

  await t.test("recent malformed lock fails closed", () => {
    reset();
    writeLock("not-json");
    assert.throws(() => backupRepository.acquireJsonMutationLock(), { code: "BACKUP_METADATA_LOCK_BUSY" });
    assert.equal(fs.readFileSync(backupRepository.MUTATION_LOCK_FILE, "utf8"), "not-json");
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  });

  await t.test("old malformed lock is recovered through an atomic claim", () => {
    reset();
    writeLock("not-json");
    const old = new Date(Date.now() - 61_000);
    fs.utimesSync(backupRepository.MUTATION_LOCK_FILE, old, old);
    const lease = backupRepository.acquireJsonMutationLock();
    assert.equal(readLock().formatVersion, 1);
    lease.release();
    assert.deepEqual(
      fs.readdirSync(path.dirname(backupRepository.MUTATION_LOCK_FILE))
        .filter((name) => name !== path.basename(backupRepository.MUTATION_COORDINATION_DB_FILE)),
      [],
    );
  });

  await t.test("record write failure removes only the owned incomplete lock", () => {
    reset();
    const originalWrite = fs.writeSync;
    fs.writeSync = () => { throw new Error("injected lock write failure"); };
    try {
      assert.throws(() => backupRepository.acquireJsonMutationLock(), /injected lock write failure/);
    } finally {
      fs.writeSync = originalWrite;
    }
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false);
  });

  await t.test("a crash immediately after creation is reclaimed by a fresh process", async () => {
    reset();
    const child = await runChild("const lease = repository.acquireJsonMutationLock('crash'); process.stdout.write(lease.token); process.exit(17);");
    assert.equal(child.code, 17, child.stderr);
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), true);
    const lease = backupRepository.acquireJsonMutationLock();
    lease.release();
  });

  await t.test("JSON restore synchronization resumes after crash-lock restart", async () => {
    reset();
    const saved = seedMutation();
    const child = await runChild("repository.acquireJsonMutationLock('crash'); process.exit(17);");
    assert.equal(child.code, 17, child.stderr);
    const current = backupRepository.getBackup(saved.id);
    const updated = backupRepository.mutateRestoreSyncEntry({
      backupId: saved.id,
      operationId: current.metadata.restoreSync.operationId,
      entryId: "entry-1",
      expectedState: "pending",
      expectedLeaseToken: null,
      expectedRevision: 0,
      mutate: (entry) => ({ entry: { ...entry, state: "completed" }, at: new Date().toISOString() }),
    });
    assert.equal(updated.metadata.restoreSync.entries[0].state, "completed");
    assert.equal(JSON.parse(fs.readFileSync(path.join(runtime, "data", "backup-history.json"), "utf8"))[0].metadata.restoreSync.entries[0].state, "completed");
  });

  await t.test("two child processes race and exactly one claim wins", async () => {
    reset();
    const raceDir = path.join(runtime, "race");
    fs.mkdirSync(raceDir);
    const startFile = path.join(raceDir, "start");
    const readyA = path.join(raceDir, "ready-a");
    const readyB = path.join(raceDir, "ready-b");
    const action = `
      const ready = process.env.READY_FILE;
      fs.writeFileSync(ready, "ready");
      const deadline = Date.now() + 5000;
      while (!fs.existsSync(process.env.START_FILE) && Date.now() < deadline) {}
      try {
        const lease = repository.acquireJsonMutationLock("race");
        console.log(JSON.stringify({ winner: true, token: lease.token }));
        setTimeout(() => { lease.release(); process.exit(0); }, 500);
      } catch (error) {
        console.log(JSON.stringify({ winner: false, code: error.code }));
        process.exit(error.code === "BACKUP_METADATA_LOCK_BUSY" ? 2 : 1);
      }
    `;
    const first = runChild(action, { READY_FILE: readyA, START_FILE: startFile });
    const second = runChild(action, { READY_FILE: readyB, START_FILE: startFile });
    const deadline = Date.now() + 3000;
    while ((!fs.existsSync(readyA) || !fs.existsSync(readyB)) && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(fs.existsSync(readyA) && fs.existsSync(readyB), true, `${fs.existsSync(readyA)} ${fs.existsSync(readyB)}`);
    fs.writeFileSync(startFile, "start");
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), true);
    const results = await Promise.all([first, second]);
    const values = results.map((result) => JSON.parse(result.stdout.trim().split(/\r?\n/).pop()));
    assert.equal(values.filter((value) => value.winner).length, 1, results.map((result) => `${result.code}:${result.stderr}:${result.stdout}`).join(" | "));
    assert.equal(values.filter((value) => value.code === "BACKUP_METADATA_LOCK_BUSY").length, 1);
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false);
  });

  await t.test("concurrent stale-lock recovery cannot steal a newly published live owner", async () => {
    reset();
    const raceDir = path.join(runtime, "stale-race");
    fs.mkdirSync(raceDir);
    const staleClassified = path.join(raceDir, "stale-classified");
    const allowFirstClaim = path.join(raceDir, "allow-first-claim");
    const firstActive = path.join(raceDir, "first-active");
    const secondActive = path.join(raceDir, "second-active");
    const releaseFirst = path.join(raceDir, "release-first");
    const releaseSecond = path.join(raceDir, "release-second");
    writeLock(lockRecord({ pid: 99999999, createdAt: "2020-01-01T00:00:00.000Z" }));
    const baseEnv = {
      NODE_PATH: process.env.NODE_PATH || path.join(repoRoot, "node_modules"),
      STALE_CLASSIFIED_FILE: staleClassified,
      ALLOW_FIRST_CLAIM_FILE: allowFirstClaim,
      FIRST_ACTIVE_FILE: firstActive,
      SECOND_ACTIVE_FILE: secondActive,
      RELEASE_FIRST_FILE: releaseFirst,
      RELEASE_SECOND_FILE: releaseSecond,
    };
    const first = spawn(process.execPath, [staleRaceChild, "paused-stale-claim"], {
      cwd: runtime,
      env: { ...process.env, ...baseEnv },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const secondHolder = { child: null, result: null };
    const collect = (child) => new Promise((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
    });
    const firstResult = collect(first);
    const waitFor = async (condition, description, timeoutMs = 5000) => {
      const deadline = Date.now() + timeoutMs;
      while (!condition() && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
      assert.ok(condition(), `timed out waiting for ${description}`);
    };
    try {
      await waitFor(() => fs.existsSync(staleClassified), "first process to classify the stale lock");
      secondHolder.child = spawn(process.execPath, [staleRaceChild, "competing-claim"], {
        cwd: runtime,
        env: { ...process.env, ...baseEnv },
        stdio: ["ignore", "pipe", "pipe"],
      });
      secondHolder.result = collect(secondHolder.child);
      await waitFor(() => fs.existsSync(secondActive) || secondHolder.child.exitCode !== null,
        "second stale-lock contender to acquire or report busy");
      fs.writeFileSync(allowFirstClaim, "continue");
      await waitFor(() => fs.existsSync(firstActive) || first.exitCode !== null,
        "first stale-lock contender to acquire or report busy");
    } finally {
      fs.writeFileSync(allowFirstClaim, "continue");
      fs.writeFileSync(releaseFirst, "release");
      fs.writeFileSync(releaseSecond, "release");
    }
    assert.ok(secondHolder.result, "the competing stale-lock process must start");
    const results = await Promise.all([firstResult, secondHolder.result]);
    assert.equal(fs.existsSync(firstActive) && fs.existsSync(secondActive), false,
      "a stale snapshot must not let one contender replace another process's live lock");
    assert.equal(results.filter((result) => result.code === 0).length, 1,
      results.map((result) => `${result.code}:${result.stderr}:${result.stdout}`).join(" | "));
    assert.equal(results.filter((result) => result.code === 2).length, 1,
      results.map((result) => `${result.code}:${result.stderr}:${result.stdout}`).join(" | "));
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false);
  });

  await t.test("lease release waits for a transient coordination lock holder", async () => {
    reset();
    const lease = backupRepository.acquireJsonMutationLock("finally-release");
    const heldFile = path.join(runtime, "coordination-held");
    const child = spawn(process.execPath, [staleRaceChild, "hold-coordination-lock"], {
      cwd: runtime,
      env: {
        ...process.env,
        NODE_PATH: process.env.NODE_PATH || path.join(repoRoot, "node_modules"),
        COORDINATION_HELD_FILE: heldFile,
        COORDINATION_HOLD_MS: "300",
      },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const result = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
    });
    await new Promise((resolve, reject) => {
      const deadline = Date.now() + 5000;
      const poll = () => {
        if (fs.existsSync(heldFile)) return resolve();
        if (child.exitCode !== null) return reject(new Error(`coordinator holder exited early: ${stderr}`));
        if (Date.now() >= deadline) return reject(new Error("coordinator holder did not acquire its transaction"));
        setTimeout(poll, 10);
      };
      poll();
    });

    assert.doesNotThrow(() => lease.release());
    const childResult = await result;
    assert.equal(childResult.code, 0, childResult.stderr);
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false,
      "the finally-path release must remove its lock after the transient namespace transaction commits");
  });

  await t.test("coordination database and sidecars are excluded from backup content", () => {
    const backupService = require("../services/backupService");
    for (const suffix of ["", "-journal", "-wal", "-shm"]) {
      assert.equal(backupService.isBackupExcludedPath(`data/.backup-metadata-coordination.sqlite${suffix}`), true);
    }
    assert.equal(backupService.isBackupExcludedPath("data/backup-history.json"), false);
  });

  await t.test("a stale releaser cannot remove a replacement owner", () => {
    reset();
    const first = backupRepository.acquireJsonMutationLock("first");
    writeLock(lockRecord({ token: "winner-token", operationName: "second" }));
    first.release();
    assert.equal(readLock().token, "winner-token");
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  });

  await t.test("runtime-root mismatch fails closed", () => {
    reset();
    writeLock(lockRecord({ runtimeRootIdentity: path.join(runtime, "other-root") }));
    assert.throws(() => backupRepository.acquireJsonMutationLock(), (error) => error.code === "BACKUP_METADATA_LOCK_BUSY" && error.reason === "runtime-root-mismatch");
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  });

  await t.test("atomic history remains valid after forced child termination and leaves no temp files", async () => {
    reset();
    const running = startChild(`
      for (let i = 0; i < 1000; i += 1) {
        repository.saveBackup({ id: String(i), filename: 'rootark-backup-2026-08-01-00-00-01.zip' });
      }
    `);
    await new Promise((resolve) => setTimeout(resolve, 5));
    running.child.kill();
    await running.result;
    const historyPath = path.join(runtime, "data", "backup-history.json");
    if (fs.existsSync(historyPath)) assert.ok(Array.isArray(JSON.parse(fs.readFileSync(historyPath, "utf8"))));
    assert.equal(fs.readdirSync(path.join(runtime, "data")).some((name) => name.includes("backup-history.json.") && name.endsWith(".tmp")), false);
  });
});

test("cross-process JSON history writes cannot overwrite a restore-sync mutation", { timeout: 20_000 }, async () => {
  reset();
  seedMutation();
  const readyFile = path.join(runtime, "restore-write-ready");
  const releaseFile = path.join(runtime, "restore-write-release");
  const historyPath = path.join(runtime, "data", "backup-history.json");
  const backupId = "00000000-0000-4000-8000-000000000001";
  const mutation = startChild(`
    const originalRenameSync = fs.renameSync;
    let paused = false;
    fs.renameSync = function (source, destination) {
      if (!paused && destination === ${JSON.stringify(historyPath)}) {
        paused = true;
        fs.writeFileSync(${JSON.stringify(readyFile)}, "ready");
        const wait = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 10000;
        while (!fs.existsSync(${JSON.stringify(releaseFile)}) && Date.now() < deadline) Atomics.wait(wait, 0, 0, 10);
        if (!fs.existsSync(${JSON.stringify(releaseFile)})) throw new Error("timed out waiting to finish restore metadata write");
      }
      return originalRenameSync.call(this, source, destination);
    };
    const updated = repository.mutateRestoreSyncEntry({
      backupId: ${JSON.stringify(backupId)}, operationId: "operation-1", entryId: "entry-1",
      expectedState: "pending", expectedLeaseToken: null, expectedRevision: 0,
      mutate: (entry) => ({ entry: { ...entry, state: "completed" }, at: "2026-10-09T00:00:00.000Z" }),
    });
    console.log(JSON.stringify({ state: updated.metadata.restoreSync.entries[0].state }));
  `);

  let ready = false;
  let ordinaryWrite = null;
  try {
    const deadline = Date.now() + 5000;
    while (!fs.existsSync(readyFile) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
    ready = fs.existsSync(readyFile);
    if (ready) {
      ordinaryWrite = await runChild(`
        try {
          repository.saveBackup({ id: "ordinary-save", filename: "ordinary-save.zip", metadata: {} });
          console.log(JSON.stringify({ saved: true }));
        } catch (error) {
          console.log(JSON.stringify({ saved: false, code: error.code }));
          process.exitCode = error.code === "BACKUP_METADATA_LOCK_BUSY" ? 2 : 1;
        }
      `);
    }
  } finally {
    fs.writeFileSync(releaseFile, "release");
  }

  const mutationResult = await mutation.result;
  assert.equal(ready, true, "restore mutation must pause after reading history while it owns the JSON mutation lock");
  assert.equal(mutationResult.code, 0, mutationResult.stderr);
  assert.equal(JSON.parse(mutationResult.stdout.trim()).state, "completed");
  assert.ok(ordinaryWrite, "the concurrent history write must run during the paused restore mutation");
  assert.ok([0, 2].includes(ordinaryWrite.code), `${ordinaryWrite.stderr} ${ordinaryWrite.stdout}`);
  if (ordinaryWrite.code === 2) {
    assert.equal(JSON.parse(ordinaryWrite.stdout.trim()).code, "BACKUP_METADATA_LOCK_BUSY");
    backupRepository.saveBackup({ id: "ordinary-save", filename: "ordinary-save.zip", metadata: {} });
  }

  const history = backupRepository.listBackups();
  assert.equal(history.find((entry) => entry.id === backupId).metadata.restoreSync.entries[0].state, "completed");
  assert.equal(history.some((entry) => entry.id === "ordinary-save"), true, "a retry after lock release must preserve both writes");
});

test("an expired live JSON lease blocks takeover and cannot mutate history", { timeout: 15_000 }, async () => {
  reset();
  const backup = seedMutation();
  const originalTtl = process.env.ROOTARK_JSON_LOCK_TTL_MS;
  process.env.ROOTARK_JSON_LOCK_TTL_MS = "1000";
  const staleLease = backupRepository.acquireJsonMutationLock("long-running-operation");
  const record = readLock();
  record.createdAt = new Date(Date.now() - 2000).toISOString();
  writeLock(record);
  const resultFile = path.join(runtime, "expired-lease-contender-result");
  const contender = startChild(`
    try {
      repository.acquireJsonMutationLock("replacement-owner");
      fs.writeFileSync(${JSON.stringify(resultFile)}, "stole-lock");
    } catch (error) {
      fs.writeFileSync(${JSON.stringify(resultFile)}, error.code === "BACKUP_METADATA_LOCK_BUSY" ? "blocked" : error.code);
      process.exitCode = error.code === "BACKUP_METADATA_LOCK_BUSY" ? 0 : 1;
    }
  `, { ROOTARK_JSON_LOCK_TTL_MS: "1000" });

  let contenderBlocked = false;
  let staleWriteError = null;
  try {
    const deadline = Date.now() + 5000;
    while (!fs.existsSync(resultFile) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 5));
    if (fs.existsSync(resultFile)) contenderBlocked = fs.readFileSync(resultFile, "utf8") === "blocked";
    try {
      backupRepository.saveBackup({ ...backup, metadata: { staleWrite: true } }, { mutationLease: staleLease });
    } catch (error) {
      staleWriteError = error.code;
    }
  } finally {
    await contender.result;
    staleLease.release();
    if (originalTtl === undefined) delete process.env.ROOTARK_JSON_LOCK_TTL_MS;
    else process.env.ROOTARK_JSON_LOCK_TTL_MS = originalTtl;
  }

  assert.equal(contenderBlocked, true, "another process must not acquire a lock whose expired owner is still live");
  assert.equal(staleWriteError, "BACKUP_METADATA_LOCK_INVALID");
  assert.equal(backupRepository.getBackup(backup.id).metadata.staleWrite, undefined,
    "a stale lease must not bypass the replacement owner's lock");
});

test("an active JSON mutation lease can renew an expired record before a long write", () => {
  reset();
  const originalTtl = process.env.ROOTARK_JSON_LOCK_TTL_MS;
  let lease;
  try {
    process.env.ROOTARK_JSON_LOCK_TTL_MS = "1000";
    lease = backupRepository.acquireJsonMutationLock("long-running-write");
    const record = readLock();
    record.createdAt = new Date(Date.now() - 2000).toISOString();
    writeLock(record);

    assert.equal(lease.renew(), true);
    assert.ok(Date.now() - Date.parse(readLock().createdAt) < 1000, "renewal must persist a fresh lease timestamp");
    assert.doesNotThrow(() => backupRepository.saveBackup({
      id: "renewed-lease-write",
      filename: "renewed-lease-write.zip",
      metadata: {},
    }, { mutationLease: lease }));
  } finally {
    lease?.release();
    if (originalTtl === undefined) delete process.env.ROOTARK_JSON_LOCK_TTL_MS;
    else process.env.ROOTARK_JSON_LOCK_TTL_MS = originalTtl;
  }
});

test("a released JSON mutation lease cannot be renewed", () => {
  reset();
  const lease = backupRepository.acquireJsonMutationLock("released-write");
  lease.release();

  assert.throws(() => lease.renew(), { code: "BACKUP_METADATA_LOCK_INVALID" });
  assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false);
});

test("a same-token JSON lock with a different file identity cannot renew the old lease", () => {
  reset();
  const originalTtl = process.env.ROOTARK_JSON_LOCK_TTL_MS;
  const originalLstatSync = fs.lstatSync;
  let lease;
  let lockStatCalls = 0;
  try {
    process.env.ROOTARK_JSON_LOCK_TTL_MS = "1000";
    lease = backupRepository.acquireJsonMutationLock("replaced-write");
    const record = readLock();
    record.createdAt = new Date(Date.now() - 2000).toISOString();
    writeLock(record);

    fs.lstatSync = function (target, ...args) {
      const stat = originalLstatSync.call(this, target, ...args);
      if (path.resolve(String(target)) !== path.resolve(backupRepository.MUTATION_LOCK_FILE)) return stat;
      lockStatCalls += 1;
      // Simulate a same-token replacement with a different inode without relying on
      // platform-specific rename semantics for an open lock descriptor.
      const altered = Object.assign(Object.create(Object.getPrototypeOf(stat)), stat);
      altered.dev += 1;
      altered.ino += 1;
      altered.birthtimeMs += 1;
      altered.ctimeMs += 1;
      return altered;
    };
    assert.throws(() => lease.renew(), { code: "BACKUP_METADATA_LOCK_INVALID" });
    assert.ok(lockStatCalls > 0, "renewal must inspect the current lock path identity");
  } finally {
    fs.lstatSync = originalLstatSync;
    lease?.release();
    if (originalTtl === undefined) delete process.env.ROOTARK_JSON_LOCK_TTL_MS;
    else process.env.ROOTARK_JSON_LOCK_TTL_MS = originalTtl;
  }
});

test("lease renewal rechecks path identity after writing through the descriptor", () => {
  reset();
  const originalTtl = process.env.ROOTARK_JSON_LOCK_TTL_MS;
  const originalLstatSync = fs.lstatSync;
  const originalFtruncateSync = fs.ftruncateSync;
  let lease;
  let writeStarted = false;
  try {
    process.env.ROOTARK_JSON_LOCK_TTL_MS = "1000";
    lease = backupRepository.acquireJsonMutationLock("renew-during-replacement");
    const record = readLock();
    record.createdAt = new Date(Date.now() - 2000).toISOString();
    writeLock(record);

    fs.ftruncateSync = function (fd, ...args) {
      const result = originalFtruncateSync.call(this, fd, ...args);
      writeStarted = true;
      return result;
    };
    fs.lstatSync = function (target, ...args) {
      const stat = originalLstatSync.call(this, target, ...args);
      if (!writeStarted || path.resolve(String(target)) !== path.resolve(backupRepository.MUTATION_LOCK_FILE)) return stat;
      // Model a replacement at the descriptor-write boundary without relying on
      // platform-specific rename semantics for an open lock file.
      const altered = Object.assign(Object.create(Object.getPrototypeOf(stat)), stat);
      altered.dev += 1;
      altered.ino += 1;
      altered.birthtimeMs += 1;
      altered.ctimeMs += 1;
      return altered;
    };

    assert.throws(() => lease.renew(), { code: "BACKUP_METADATA_LOCK_INVALID" });
    assert.equal(writeStarted, true, "the replacement must be simulated after the renewal write begins");
  } finally {
    fs.lstatSync = originalLstatSync;
    fs.ftruncateSync = originalFtruncateSync;
    lease?.release();
    if (originalTtl === undefined) delete process.env.ROOTARK_JSON_LOCK_TTL_MS;
    else process.env.ROOTARK_JSON_LOCK_TTL_MS = originalTtl;
  }
});

test("a stale JSON lease release preserves a same-token replacement file", () => {
  reset();
  const originalLstatSync = fs.lstatSync;
  let lease;
  try {
    lease = backupRepository.acquireJsonMutationLock("replacement-release");
    const replacement = readLock();
    writeLock(replacement);

    fs.lstatSync = function (target, ...args) {
      const stat = originalLstatSync.call(this, target, ...args);
      if (path.resolve(String(target)) !== path.resolve(backupRepository.MUTATION_LOCK_FILE)) return stat;
      // Model the path now naming a distinct file while its contents reuse the old token.
      const altered = Object.assign(Object.create(Object.getPrototypeOf(stat)), stat);
      altered.dev += 1;
      altered.ino += 1;
      altered.birthtimeMs += 1;
      altered.ctimeMs += 1;
      return altered;
    };

    lease.release();
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), true,
      "releasing an old descriptor must not delete a replacement path with the same token");
    assert.equal(readLock().token, lease.token);
  } finally {
    fs.lstatSync = originalLstatSync;
    lease?.release();
    fs.rmSync(backupRepository.MUTATION_LOCK_FILE, { force: true });
  }
});

test("a failed JSON lock unlink keeps the lease retryable", () => {
  reset();
  const lease = backupRepository.acquireJsonMutationLock("retryable-release");
  const originalRmSync = fs.rmSync;
  let injected = false;
  fs.rmSync = function (target, ...args) {
    if (!injected && path.resolve(String(target)) === path.resolve(backupRepository.MUTATION_LOCK_FILE)) {
      injected = true;
      throw Object.assign(new Error("injected lock unlink failure"), { code: "EACCES" });
    }
    return originalRmSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => lease.release(), { code: "EACCES" });
    assert.equal(injected, true);
    assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), true);
    assert.doesNotThrow(() => lease.renew(), "a failed unlink must leave the lease active for retry");
  } finally {
    fs.rmSync = originalRmSync;
  }
  assert.doesNotThrow(() => lease.release());
  assert.equal(fs.existsSync(backupRepository.MUTATION_LOCK_FILE), false);
});

test("JSON history save rejects an active lease whose same-token lock path identity changed", () => {
  reset();
  const original = backupRepository.saveBackup({ id: "preserved-save", filename: "preserved-save.zip", metadata: {} });
  const lease = backupRepository.acquireJsonMutationLock("save-replacement");
  try {
    assert.throws(() => withDifferentLockFileIdentity(() => backupRepository.saveBackup({
      ...original,
      metadata: { shouldNotSave: true },
    }, { mutationLease: lease })), { code: "BACKUP_METADATA_LOCK_INVALID" });
  } finally {
    lease.release();
  }
  assert.equal(backupRepository.getBackup(original.id).metadata.shouldNotSave, undefined);
});

test("JSON history delete rejects an active lease whose same-token lock path identity changed", () => {
  reset();
  const original = backupRepository.saveBackup({ id: "preserved-delete", filename: "preserved-delete.zip", metadata: {} });
  const lease = backupRepository.acquireJsonMutationLock("delete-replacement");
  try {
    assert.throws(() => withDifferentLockFileIdentity(() => backupRepository.deleteBackup(original.id, {
      mutationLease: lease,
    })), { code: "BACKUP_METADATA_LOCK_INVALID" });
  } finally {
    lease.release();
  }
  assert.equal(backupRepository.getBackup(original.id).filename, original.filename);
});

test("an expired lock held by a live writer cannot be stolen before its history rename", { timeout: 20_000 }, async () => {
  reset();
  const historyPath = path.join(runtime, "data", "backup-history.json");
  const pauseFile = path.join(runtime, "live-writer-pause");
  const resumeFile = path.join(runtime, "live-writer-resume");
  const contenderState = path.join(runtime, "contender-state");
  const attemptFile = path.join(runtime, "contender-attempt");
  const retryFile = path.join(runtime, "contender-retry");
  const writer = startChild(`
    const originalRenameSync = fs.renameSync;
    let paused = false;
    fs.renameSync = function (source, destination) {
      if (!paused && destination === ${JSON.stringify(historyPath)}) {
        paused = true;
        fs.writeFileSync(${JSON.stringify(pauseFile)}, "ready");
        const wait = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 10000;
        while (!fs.existsSync(${JSON.stringify(resumeFile)}) && Date.now() < deadline) Atomics.wait(wait, 0, 0, 10);
        if (!fs.existsSync(${JSON.stringify(resumeFile)})) throw new Error("timed out waiting to rename history");
      }
      return originalRenameSync.call(this, source, destination);
    };
    repository.saveBackup({ id: "paused-writer", filename: "paused-writer.zip", metadata: {} });
  `, { ROOTARK_JSON_LOCK_TTL_MS: "1000" });
  const contender = startChild(`
    const wait = new Int32Array(new SharedArrayBuffer(4));
    const attemptDeadline = Date.now() + 10000;
    while (!fs.existsSync(${JSON.stringify(attemptFile)}) && Date.now() < attemptDeadline) Atomics.wait(wait, 0, 0, 10);
    if (!fs.existsSync(${JSON.stringify(attemptFile)})) throw new Error("timed out waiting for expired-lock contention");
    const save = () => repository.saveBackup({ id: "contender-writer", filename: "contender-writer.zip", metadata: {} });
    try {
      save();
      fs.writeFileSync(${JSON.stringify(contenderState)}, "stole-live-lock");
    } catch (error) {
      if (error.code !== "BACKUP_METADATA_LOCK_BUSY") throw error;
      fs.writeFileSync(${JSON.stringify(contenderState)}, "blocked");
      const wait = new Int32Array(new SharedArrayBuffer(4));
      const deadline = Date.now() + 10000;
      while (!fs.existsSync(${JSON.stringify(retryFile)}) && Date.now() < deadline) Atomics.wait(wait, 0, 0, 10);
      if (!fs.existsSync(${JSON.stringify(retryFile)})) throw new Error("timed out waiting to retry after owner exit");
      save();
      fs.writeFileSync(${JSON.stringify(contenderState)}, "saved-after-retry");
    }
  `, { ROOTARK_JSON_LOCK_TTL_MS: "1000" });

  let writerReady = false;
  let contenderFirstState = null;
  try {
    const readyDeadline = Date.now() + 5000;
    while (!fs.existsSync(pauseFile) && Date.now() < readyDeadline) await new Promise((resolve) => setTimeout(resolve, 5));
    writerReady = fs.existsSync(pauseFile);
    assert.equal(writerReady, true, "writer must pause after reading history and before its rename");
    const lock = readLock();
    lock.createdAt = new Date(Date.now() - 2000).toISOString();
    writeLock(lock);
    fs.writeFileSync(attemptFile, "attempt");

    const contenderDeadline = Date.now() + 5000;
    while (!fs.existsSync(contenderState) && Date.now() < contenderDeadline) await new Promise((resolve) => setTimeout(resolve, 5));
    if (fs.existsSync(contenderState)) contenderFirstState = fs.readFileSync(contenderState, "utf8");
  } finally {
    fs.writeFileSync(resumeFile, "resume");
  }

  const writerResult = await writer.result;
  assert.equal(writerResult.code, 0, writerResult.stderr);
  fs.writeFileSync(retryFile, "retry");
  const contenderResult = await contender.result;
  assert.equal(contenderResult.code, 0, contenderResult.stderr);
  assert.equal(contenderFirstState, "blocked", "an expired lock with a live owner must not be stolen");
  assert.equal(fs.readFileSync(contenderState, "utf8"), "saved-after-retry");
  const history = backupRepository.listBackups();
  assert.equal(history.some((entry) => entry.id === "paused-writer"), true);
  assert.equal(history.some((entry) => entry.id === "contender-writer"), true,
    "the retry after the live owner finishes must preserve both writes");
});

test("JSON history deletion is serialized with restore-sync mutation", () => {
  reset();
  const backup = seedMutation();
  const lease = backupRepository.acquireJsonMutationLock("test-hold-delete");
  try {
    assert.throws(() => backupRepository.deleteBackup(backup.id), { code: "BACKUP_METADATA_LOCK_BUSY" });
    assert.ok(backupRepository.getBackup(backup.id), "a rejected delete must leave history unchanged");
  } finally {
    lease.release();
  }
  backupRepository.deleteBackup(backup.id);
  assert.equal(backupRepository.getBackup(backup.id), null);
});

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
