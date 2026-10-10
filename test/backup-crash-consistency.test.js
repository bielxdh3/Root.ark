const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const CHILD_HELPER = path.resolve(__dirname, "..", "scripts", "test-helpers", "backup-crash-child.js");

function startChild(runtime, mode, data = {}, env = {}) {
  const child = spawn(process.execPath, [CHILD_HELPER, JSON.stringify({ mode, data })], {
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

async function runChild(runtime, mode, data = {}, env = {}) {
  return startChild(runtime, mode, data, env).result;
}

function newRuntime(prefix) {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
  return runtime;
}

function criticalAction(enteredPath, criticalPath) {
  return { mode: "critical-section", data: { enteredPath, criticalPath } };
}

async function assertOneCriticalSection(runtime, stale = false) {
  const entered = path.join(runtime, "entered.log");
  const critical = path.join(runtime, "critical");
  if (stale) {
    const lock = path.join(runtime, "data", "backups", ".backup.lock");
    fs.writeFileSync(lock, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
    fs.utimesSync(lock, new Date(0), new Date(0));
  }
  const action = criticalAction(entered, critical);
  const first = runChild(runtime, action.mode, action.data);
  const second = runChild(runtime, action.mode, action.data);
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

function recoveryAction() { return { mode: "recover-retention" }; }

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

  await t.test("runtime paths containing JavaScript syntax remain plain child-process data", async () => {
    const parent = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-lock-quoted-parent-"));
    const runtime = path.join(parent, "runtime-'; process.exit(86); --");
    fs.mkdirSync(path.join(runtime, "data", "backups"), { recursive: true });
    fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
    try {
      await assertOneCriticalSection(runtime);
    } finally {
      fs.rmSync(parent, { recursive: true, force: true });
    }
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
      const result = await runChild(runtime, "remote-lock-check", { lockPath: lock }, { ROOTARK_INSTANCE_ID: "replica-b" });
      assert.equal(result.code, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout.trim()), { locked: true, preserved: true });
      assert.equal(fs.readFileSync(lock, "utf8"), JSON.stringify(remoteLock));
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("a crash after stale evidence quarantine is recoverable", async () => {
    const runtime = newRuntime("rootark-lock-quarantine-");
    try {
      const action = "crash-after-stale-evidence-quarantine";
      const lock = path.join(runtime, "data", "backups", ".backup.lock");
      fs.writeFileSync(lock, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
      fs.utimesSync(lock, new Date(0), new Date(0));
      const crashed = await runChild(runtime, action);
      assert.notEqual(crashed.code, 0);
      const recoveredAction = criticalAction(path.join(runtime, "entered.log"), path.join(runtime, "critical"));
      const recovered = await runChild(runtime, recoveredAction.mode, recoveredAction.data);
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(lock), false);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("a crash after replacement leaves a recoverable takeover authority", async () => {
    const runtime = newRuntime("rootark-lock-owner-crash-");
    try {
      const action = "crash-after-takeover-authority-removal";
      const lock = path.join(runtime, "data", "backups", ".backup.lock");
      fs.writeFileSync(lock, JSON.stringify({ token: "stale", operation: "backup", pid: 99999999 }));
      fs.utimesSync(lock, new Date(0), new Date(0));
      const crashed = await runChild(runtime, action);
      assert.notEqual(crashed.code, 0);
      const recoveredAction = criticalAction(path.join(runtime, "entered.log"), path.join(runtime, "critical"));
      const recovered = await runChild(runtime, recoveredAction.mode, recoveredAction.data);
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(lock), false);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("recent malformed evidence fails closed and old malformed evidence recovers", async () => {
    const runtime = newRuntime("rootark-lock-malformed-");
    const lock = path.join(runtime, "data", "backups", ".backup.lock");
    try {
      fs.writeFileSync(lock, "broken");
      const recent = await runChild(runtime, "expect-lock-error", { operation: "backup", expectedCode: "BACKUP_LOCKED" });
      assert.equal(recent.code, 0, recent.stderr);
      const old = new Date(Date.now() - 120_000);
      fs.utimesSync(lock, old, old);
      const recoveredAction = criticalAction(path.join(runtime, "entered.log"), path.join(runtime, "critical"));
      const recovered = await runChild(runtime, recoveredAction.mode, recoveredAction.data);
      assert.equal(recovered.code, 0, recovered.stderr);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });

  await t.test("backup, restore, and delete share one exclusion boundary", async () => {
    const runtime = newRuntime("rootark-lock-operations-");
    try {
      const result = await runChild(runtime, "operations-share-lock");
      assert.equal(result.code, 0, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout.trim()), ["BACKUP_LOCKED", "BACKUP_LOCKED"]);
    } finally { fs.rmSync(runtime, { recursive: true, force: true }); }
  });
});

test("retention transactions converge from real crash boundaries", { timeout: 60_000 }, async (t) => {
  await t.test("crash after archive rename restores history and bytes", async () => {
    const fixture = retentionFixture();
    try {
      const crashed = await runChild(fixture.runtime, "crash-after-archive-tombstone-rename", { archivePath: fixture.archivePath, tombstonePath: fixture.tombstone }, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(fixture.runtime, recoveryAction().mode);
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.deepEqual(fs.readFileSync(fixture.archivePath), fixture.bytes);
      assert.equal(fs.existsSync(fixture.tombstone), false);
      assert.equal(JSON.parse(fs.readFileSync(path.join(fixture.runtime, "data", "backup-history.json"), "utf8")).length, 1);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("crash after repository deletion finalizes without an orphan", async () => {
    const fixture = retentionFixture();
    try {
      const crashed = await runChild(fixture.runtime, "crash-after-repository-deletion", {}, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(fixture.runtime, recoveryAction().mode);
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(fixture.archivePath), false);
      assert.equal(fs.existsSync(fixture.tombstone), false);
      assert.deepEqual(JSON.parse(fs.readFileSync(path.join(fixture.runtime, "data", "backup-history.json"), "utf8")), []);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });

  await t.test("crash after tombstone cleanup leaves only retryable metadata", async () => {
    const fixture = retentionFixture();
    try {
      const crashed = await runChild(fixture.runtime, "crash-after-tombstone-removal", { tombstonePath: fixture.tombstone }, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(crashed.code, 0);
      const recovered = await runChild(fixture.runtime, recoveryAction().mode);
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
      const result = await runChild(fixture.runtime, recoveryAction().mode);
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
        const result = await runChild(fixture.runtime, recoveryAction().mode);
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
      const recovered = await runChild(equal.runtime, recoveryAction().mode);
      assert.equal(recovered.code, 0, recovered.stderr);
      assert.equal(fs.existsSync(equal.archivePath), false);
      assert.equal(fs.existsSync(equal.tombstone), false);
    } finally { fs.rmSync(equal.runtime, { recursive: true, force: true }); }

    const conflict = retentionFixture();
    try {
      fs.writeFileSync(conflict.tombstone, "different");
      transactionFor(conflict, "archive_moved");
      const failed = await runChild(conflict.runtime, recoveryAction().mode);
      assert.notEqual(failed.code, 0);
      assert.equal(fs.existsSync(conflict.archivePath), true);
      assert.equal(fs.existsSync(conflict.tombstone), true);
    } finally { fs.rmSync(conflict.runtime, { recursive: true, force: true }); }
  });

  await t.test("repository, rename, and cleanup failures remain observable and retryable", async () => {
    const failure = retentionFixture();
    try {
      const result = await runChild(failure.runtime, "fail-repository-deletion", {}, { BACKUP_RETENTION_DAYS: "1" });
      assert.notEqual(result.code, 0);
      assert.equal(fs.existsSync(failure.archivePath), true);
      assert.equal(fs.existsSync(failure.tombstone), false);
    } finally { fs.rmSync(failure.runtime, { recursive: true, force: true }); }

    for (const code of ["EPERM", "EBUSY"]) {
      const fixture = retentionFixture();
      try {
        const result = await runChild(fixture.runtime, "fail-tombstone-removal-once", { tombstonePath: fixture.tombstone, errorCode: code }, { BACKUP_RETENTION_DAYS: "1" });
        assert.notEqual(result.code, 0);
        assert.equal(fs.existsSync(fixture.tombstone), true);
        const retry = await runChild(fixture.runtime, recoveryAction().mode);
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
      const duplicate = await runChild(fixture.runtime, recoveryAction().mode);
      assert.notEqual(duplicate.code, 0);
      const outside = retentionFixture();
      try {
        transactionFor(outside, "prepared", { archivePath: path.join(outside.runtime, "outside.zip") });
        const failed = await runChild(outside.runtime, recoveryAction().mode);
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
        const result = await runChild(fixture.runtime, recoveryAction().mode);
        assert.equal(result.code, 0, result.stderr);
      }
      assert.equal(fs.existsSync(fixture.archivePath), false);
      assert.equal(fs.existsSync(fixture.tombstone), false);
    } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
  });
});

test("normal server startup recovers backup tombstones before listening and fails closed on corrupt journals", { timeout: 45_000 }, async (t) => {
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
  for (const boundary of ["before-history-removal", "after-history-removal"]) {
    await t.test(`${boundary} crash is recovered through server entrypoint`, async () => {
      const fixture = retentionFixture();
      try {
        const crashMode = boundary === "before-history-removal"
          ? "crash-delete-backup-after-archive-tombstone-rename"
          : "crash-delete-backup-after-repository-deletion";
        const crashData = boundary === "before-history-removal"
          ? { archivePath: fixture.archivePath, tombstonePath: fixture.tombstone, backupId: fixture.id }
          : { backupId: fixture.id };
        const crashed = await runChild(fixture.runtime, crashMode, crashData);
        assert.notEqual(crashed.code, 0);
        // The operation-lock recovery path is independent; these cases isolate history/tombstone startup recovery.
        fs.rmSync(path.join(fixture.runtime, "data", "backups", ".backup.lock"), { force: true });
        fixture.expected = boundary === "before-history-removal"
          ? { archiveExists: true, tombstoneExists: false, historyExists: true, transactionRootExists: false }
          : { archiveExists: false, tombstoneExists: false, historyExists: false, transactionRootExists: false };
        const resultPath = path.join(fixture.runtime, "server-recovery-result.json");
        const restarted = await runChild(fixture.runtime, "server-recovery-at-listen", {
          backupId: fixture.id,
          archivePath: fixture.archivePath,
          tombstonePath: fixture.tombstone,
          transactionRootPath: fixture.transactionRoot,
          resultPath,
          expected: fixture.expected,
        }, runtimeEnv);
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
      const result = await runChild(fixture.runtime, "corrupt-journal-blocks-listener", { listenerMarker }, runtimeEnv);
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
    const result = await runChild(fixture.runtime, "track-retention-durability", {
      archivePath: fixture.archivePath,
      tombstonePath: fixture.tombstone,
    });
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
    const result = await runChild(fixture.runtime, "fail-parent-fsync-after-rename", {
      archivePath: fixture.archivePath,
      tombstonePath: fixture.tombstone,
      backupId: fixture.id,
    });
    assert.equal(result.code, 0, result.stderr);
    const outcome = JSON.parse(result.stdout.trim());
    assert.equal(outcome.injected, true);
    assert.match(outcome.error || "", /injected parent directory fsync failure/);
    assert.equal(outcome.archive, true);
    assert.equal(outcome.tombstone, false);
    assert.equal(outcome.history, true);
  } finally { fs.rmSync(fixture.runtime, { recursive: true, force: true }); }
});
