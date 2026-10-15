const assert = require("node:assert/strict");
const Database = require("better-sqlite3");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const test = require("node:test");
const { createChunkUploadQuota, parseChunkUploadQuotaConfig } = require("../services/chunkUploadQuota");
const { ensureWindowsChunkUploadRoot, getWindowsChunkAclDescriptor } = require("../services/chunkUploadWindowsAcl");
const QUOTA_TEST_TEMP = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();

function withTempDir(callback) {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, "rootark-chunk-quota-"));
  const directory = process.platform === "win32" ? path.join(parent, ".chunks") : parent;
  try {
    if (process.platform === "win32") {
      ensureWindowsChunkUploadRoot(directory);
    }
    callback(directory);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
}

function createQuotaTestRoot(prefix) {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, prefix));
  const root = process.platform === "win32" ? path.join(parent, ".chunks") : parent;
  try {
    if (process.platform === "win32") {
      ensureWindowsChunkUploadRoot(root);
    }
  } catch (error) {
    fs.rmSync(parent, { recursive: true, force: true });
    throw error;
  }
  return { parent, root };
}

test("chunk quota configuration requires positive safe integer byte caps without defaults", () => {
  for (const env of [
    {},
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "", CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "0", CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "1.5", CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "01", CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "9007199254740992", CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "9007199254740992" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "101", CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100" },
  ]) {
    assert.equal(parseChunkUploadQuotaConfig(env).enabled, false);
  }

  assert.deepEqual(parseChunkUploadQuotaConfig({
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "80",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100",
  }), { enabled: true, perAccountBytes: 80, systemBytes: 100 });
});

test("chunk quota writes use WAL for durable local state transitions", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    let verifier;
    try {
      quota.initialize();
      verifier = new Database(path.join(directory, ".quota.sqlite"));
      assert.equal(verifier.pragma("journal_mode", { simple: true }), "wal");
      quota.reserve({ operationId: "wal-durable-operation", accountKey: "alice", reservedBytes: 1, relativePath: "incoming/wal" });
      assert.equal(quota.operations()[0].state, "reserved");
    } finally {
      verifier?.close();
      quota.close();
    }
  });
});

test("active handoff checks are scoped to the requested session and known handoff states", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      quota.reserve({ operationId: "ordinary-part", accountKey: "alice", sessionKey: "folder/ordinary", reservedBytes: 1, relativePath: "folder/ordinary/0.part" });
      assert.equal(quota.hasActiveHandoff("folder/ordinary"), false);
      quota.reserve({ operationId: "handoff", accountKey: "alice", sessionKey: "folder/target", reservedBytes: 1, relativePath: "folder/target/file.upload" });
      for (const state of ["handoff_pending", "handoff_published", "handed_off"]) {
        quota.transition({ operationId: "handoff", state, chargeBytes: state === "handed_off" ? 0 : 1 });
        assert.equal(quota.hasActiveHandoff("folder/target"), true);
        assert.equal(quota.hasActiveHandoff("folder/ordinary"), false);
      }
      quota.release("handoff");
      assert.equal(quota.hasActiveHandoff("folder/target"), false);
    } finally {
      quota.close();
    }
  });
});

test("session operation lookup returns one session through its indexed ledger key", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      quota.reserve({ operationId: "session-part-one", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 2, relativePath: "folder/upload/0.part" });
      quota.reserve({ operationId: "session-part-two", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 3, relativePath: "folder/upload/1.part" });
      quota.reserve({ operationId: "other-session-part", accountKey: "alice", sessionKey: "folder/other", reservedBytes: 1, relativePath: "folder/other/0.part" });

      assert.deepEqual(quota.operationsForSession("folder/upload").map((operation) => operation.operationId).sort(), ["session-part-one", "session-part-two"]);
      assert.deepEqual(quota.operationsForSession("folder/missing"), []);
      assert.throws(() => quota.operationsForSession(""), /Invalid chunk quota session identity/);

      const database = new Database(path.join(directory, ".quota.sqlite"), { readonly: true });
      try {
        const plan = database.prepare("EXPLAIN QUERY PLAN SELECT * FROM quota_operations WHERE session_key = ?").all("folder/upload");
        assert.ok(plan.some((entry) => entry.detail.includes("quota_operations_session_state")), "session lookup must use the existing session index");
      } finally {
        database.close();
      }
    } finally {
      quota.close();
    }
  });
});

test("ledger path lookup uses its index and rejects duplicate operation paths", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      quota.reserve({ operationId: "path-operation-one", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 2, relativePath: "folder/upload/0.part" });
      quota.reserve({ operationId: "path-operation-two", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 2, relativePath: "folder/upload/0.part" });
      assert.throws(() => quota.operationForPath("folder/upload/0.part"), /Ambiguous chunk quota path/);

      const database = new Database(path.join(directory, ".quota.sqlite"), { readonly: true });
      try {
        const plan = database.prepare("EXPLAIN QUERY PLAN SELECT * FROM quota_operations WHERE relative_path = ?").all("folder/upload/0.part");
        assert.ok(plan.some((entry) => entry.detail.includes("quota_operations_path")), "path lookup must use its ledger index");
      } finally {
        database.close();
      }
    } finally {
      quota.close();
    }
  });
});

test("schema 1 ledgers migrate usage counters without changing existing charges", () => {
  const { parent, root } = createQuotaTestRoot("rootark-chunk-quota-v1-migration-");
  const databasePath = path.join(root, ".quota.sqlite");
  const oldDatabase = new Database(databasePath);
  try {
    oldDatabase.pragma("journal_mode = DELETE");
    oldDatabase.pragma("synchronous = FULL");
    oldDatabase.exec(`
      CREATE TABLE quota_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE quota_operations (
        operation_id TEXT PRIMARY KEY, account_key TEXT NOT NULL, session_key TEXT, relative_path TEXT NOT NULL,
        state TEXT NOT NULL, charge_bytes INTEGER NOT NULL CHECK (charge_bytes >= 0),
        owner_instance_id TEXT NOT NULL, owner_pid INTEGER NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
      );
      CREATE INDEX quota_operations_account ON quota_operations(account_key);
      CREATE TABLE quota_session_locks (
        session_key TEXT PRIMARY KEY, owner_instance_id TEXT NOT NULL, owner_pid INTEGER NOT NULL, created_at INTEGER NOT NULL
      );
    `);
    oldDatabase.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?)").run("schema_version", "1");
    oldDatabase.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?)").run("ready", "1");
    oldDatabase.prepare(`
      INSERT INTO quota_operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run("existing-part", "alice", "folder/upload", "folder/upload/0.part", "part_committed", 5, "prior", 1, 1, 1);
  } finally {
    oldDatabase.close();
  }

  try {
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 12 });
    try {
      assert.deepEqual(quota.initialize(), { alreadyReady: true });
      assert.deepEqual(quota.totals(), { systemBytes: 5, accounts: { alice: 5 } });
      quota.reserve({ operationId: "new-part", accountKey: "alice", reservedBytes: 5, relativePath: "incoming/new-part" });
      assert.throws(() => quota.reserve({ operationId: "over-account", accountKey: "alice", reservedBytes: 1, relativePath: "incoming/over-account" }), { code: "CHUNK_QUOTA_EXCEEDED" });
      assert.throws(() => quota.reserve({ operationId: "over-system", accountKey: "bob", reservedBytes: 3, relativePath: "incoming/over-system" }), { code: "CHUNK_QUOTA_EXCEEDED" });
      assert.equal(quota.release("new-part"), true);
      assert.deepEqual(quota.totals(), { systemBytes: 5, accounts: { alice: 5 } });
    } finally {
      quota.close();
    }
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("inconsistent quota usage counters fail closed without changing operations", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    quota.initialize();
    quota.reserve({ operationId: "preserve-operation", accountKey: "alice", reservedBytes: 4, relativePath: "incoming/preserve" });
    quota.close();

    const database = new Database(path.join(directory, ".quota.sqlite"));
    try {
      database.prepare("UPDATE quota_usage SET charge_bytes = 3 WHERE account_key = 'alice'").run();
    } finally {
      database.close();
    }

    const reopened = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      assert.throws(() => reopened.initialize(), /account usage does not match its ledger/);
      assert.equal(reopened.operations()[0].chargeBytes, 4);
    } finally {
      reopened.close();
    }
  });
});

test("Windows creates a protected chunk staging root and verifies its DACL", { skip: process.platform !== "win32" }, () => {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, "rootark-chunk-acl-new-"));
  const root = path.join(parent, ".chunks");
  try {
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      fs.writeFileSync(path.join(root, "plaintext.part"), "disposable plaintext");
      const descriptor = getWindowsChunkAclDescriptor(root);
      assert.match(descriptor, /D:P/);
      assert.doesNotMatch(descriptor, /S-1-5-32-545|S-1-1-0/);
      assert.match(descriptor, /\(A;OICI;FA;;;SY\)/);
      assert.match(descriptor, /\(A;OICI;FA;;;BA\)/);
      assert.equal((descriptor.match(/\(A;/g) || []).length, 3);
      const children = getWindowsChunkAclDescriptor(path.join(root, "plaintext.part"));
      assert.doesNotMatch(children, /S-1-5-32-545|S-1-1-0/);
    } finally {
      quota.close();
    }
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("Windows preserves data in an existing permissive chunk root and fails closed", { skip: process.platform !== "win32" }, () => {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, "rootark-chunk-acl-permissive-"));
  const root = path.join(parent, ".chunks");
  const payloadPath = path.join(root, "existing.part");
  fs.mkdirSync(root);
  fs.writeFileSync(payloadPath, "keep this disposable fixture");
  try {
    execFileSync("icacls.exe", [root, "/grant", "*S-1-5-32-545:(OI)(CI)M"], { stdio: "ignore", windowsHide: true });
    assert.throws(() => createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 10 }));
    assert.equal(fs.readFileSync(payloadPath, "utf8"), "keep this disposable fixture");
    assert.equal(fs.existsSync(path.join(root, ".quota.sqlite")), false);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("ledger reserves exact per-account and system boundaries atomically across connections", () => {
  withTempDir((directory) => {
    const first = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 12 });
    const second = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 12 });
    try {
      first.initialize();
      second.initialize();
      first.reserve({ operationId: "operation-1", accountKey: "alice", reservedBytes: 8, relativePath: "incoming/one" });
      second.reserve({ operationId: "operation-2", accountKey: "ALICE", reservedBytes: 2, relativePath: "incoming/two" });
      second.reserve({ operationId: "operation-3", accountKey: "bob", reservedBytes: 2, relativePath: "incoming/three" });
      assert.throws(() => first.reserve({ operationId: "operation-4", accountKey: "alice", reservedBytes: 1, relativePath: "incoming/four" }), { code: "CHUNK_QUOTA_EXCEEDED" });
      assert.throws(() => first.reserve({ operationId: "operation-5", accountKey: "carol", reservedBytes: 1, relativePath: "incoming/five" }), { code: "CHUNK_QUOTA_EXCEEDED" });
      assert.deepEqual(first.totals(), { systemBytes: 12, accounts: { alice: 10, bob: 2 } });
    } finally {
      first.close();
      second.close();
    }
  });
});

test("ledger can adjust and release a charge only by its operation identity", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      quota.reserve({ operationId: "operation-1", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 8, relativePath: "incoming/one" });
      quota.transition({ operationId: "operation-1", state: "staged", chargeBytes: 5, relativePath: "incoming/one" });
      assert.deepEqual(quota.totals(), { systemBytes: 5, accounts: { alice: 5 } });
      assert.equal(quota.release("missing-operation"), false);
      assert.equal(quota.releaseSession("folder/upload"), 1);
      assert.deepEqual(quota.totals(), { systemBytes: 0, accounts: {} });
    } finally {
      quota.close();
    }
  });
});

test("zero-byte assembly markers are explicit while ordinary incoming reservations remain positive", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      assert.throws(() => quota.reserve({ operationId: "empty-incoming", accountKey: "alice", reservedBytes: 0, relativePath: "incoming/empty" }), /Invalid chunk quota reservation/);
      quota.reserve({ operationId: "empty-assembly", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/upload/assembled.upload" });
      assert.deepEqual(quota.totals(), { systemBytes: 0, accounts: { alice: 0 } });
      assert.equal(quota.operations()[0].chargeBytes, 0);
    } finally {
      quota.close();
    }
  });
});

test("first startup imports operations and publishes readiness in one idempotent transaction", () => {
  withTempDir((directory) => {
    const first = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    const second = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      assert.equal(first.isReady(), false);
      assert.throws(() => first.reserve({ operationId: "before-ready", accountKey: "alice", reservedBytes: 1, relativePath: "incoming/x" }), /not ready/);
      first.initialize([{ operationId: "legacy-part-1", accountKey: "Alice", sessionKey: "folder/upload", relativePath: "folder/upload/0.part", state: "part_committed", chargeBytes: 4 }]);
      assert.equal(first.isReady(), true);
      assert.deepEqual(second.initialize([{ operationId: "duplicate-import", accountKey: "alice", relativePath: "incoming/x", state: "reserved", chargeBytes: 1 }]), { alreadyReady: true });
      assert.deepEqual(second.totals(), { systemBytes: 4, accounts: { alice: 4 } });
    } finally {
      first.close();
      second.close();
    }
  });
});

test("concurrent processes publish only one first legacy import", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-init-race-");
  const readyDirectory = path.join(directory, "ready");
  fs.mkdirSync(readyDirectory);
  const setup = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
  setup.initialize();
  setup.close();
  const database = new Database(path.join(directory, ".quota.sqlite"));
  database.prepare("UPDATE quota_meta SET value = '0' WHERE key = 'ready'").run();
  database.close();
  const startPath = path.join(directory, "start");
  const workerPath = path.join(directory, "worker.js");
  fs.writeFileSync(workerPath, `
    const fs = require("node:fs");
    const { createChunkUploadQuota } = require(${JSON.stringify(require.resolve("../services/chunkUploadQuota"))});
    const [root, readyDir, id, startPath] = process.argv.slice(2);
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 10 });
    fs.writeFileSync(require("node:path").join(readyDir, id), "ready");
    const wait = () => new Promise((resolve) => setTimeout(resolve, 5));
    (async () => {
      while (!fs.existsSync(startPath)) await wait();
      const result = quota.initialize([{ operationId: "shared-legacy", accountKey: "alice", relativePath: "folder/upload/0.part", state: "part_committed", chargeBytes: 4 }]);
      process.stdout.write(JSON.stringify({ alreadyReady: result.alreadyReady, totals: quota.totals() }));
      quota.close();
    })().catch((error) => { console.error(error.message); process.exitCode = 1; quota.close(); });
  `);
  const children = ["one", "two"].map((id) => spawn(process.execPath, [workerPath, directory, readyDirectory, id, startPath], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }));
  try {
    const deadline = Date.now() + 5000;
    while ((!fs.existsSync(path.join(readyDirectory, "one")) || !fs.existsSync(path.join(readyDirectory, "two"))) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(fs.existsSync(path.join(readyDirectory, "one")) && fs.existsSync(path.join(readyDirectory, "two")), "both quota connections reach the initialization barrier");
    fs.writeFileSync(startPath, "go");
    const results = await Promise.all(children.map((child) => new Promise((resolve, reject) => {
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("exit", (code) => code === 0 ? resolve(JSON.parse(stdout)) : reject(new Error(`initializer exited ${code}: ${stderr}`)));
    })));
    assert.deepEqual(results.map((result) => result.alreadyReady).sort(), [false, true]);
    const verify = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      assert.deepEqual(verify.totals(), { systemBytes: 4, accounts: { alice: 4 } });
      assert.equal(verify.operations().length, 1);
    } finally {
      verify.close();
    }
  } finally {
    for (const child of children) if (child.exitCode === null) child.kill();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("failed legacy import rolls back readiness and operations so a valid retry can initialize", () => {
  withTempDir((directory) => {
    const quota = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
    try {
      assert.throws(() => quota.initialize([{ operationId: "too-large", accountKey: "alice", relativePath: "folder/upload/0.part", state: "part_committed", chargeBytes: 11 }]), /exceeds configured quota/);
      assert.equal(quota.isReady(), false);
      assert.deepEqual(quota.operations(), []);
      quota.initialize([{ operationId: "valid-retry", accountKey: "alice", relativePath: "folder/upload/0.part", state: "part_committed", chargeBytes: 4 }]);
      assert.equal(quota.isReady(), true);
      assert.deepEqual(quota.totals(), { systemBytes: 4, accounts: { alice: 4 } });
    } finally {
      quota.close();
    }
  });
});

test("ledger rejects a corrupt database instead of opening it", () => {
  withTempDir((directory) => {
    const databasePath = path.join(directory, ".quota.sqlite");
    fs.writeFileSync(databasePath, "not a sqlite database");
    assert.throws(() => createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 }));
  });
});

test("ledger rejects a symlinked database before opening its target", (t) => {
  withTempDir((directory) => {
    const targetPath = path.join(directory, "target.sqlite");
    const databasePath = path.join(directory, ".quota.sqlite");
    fs.writeFileSync(targetPath, "private target");
    try {
      fs.symlinkSync(targetPath, databasePath, "file");
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("file symlink creation is unavailable on this host");
      throw error;
    }
    assert.throws(() => createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 }));
    assert.equal(fs.readFileSync(targetPath, "utf8"), "private target");
  });
});

test("dead operation claims are compare-and-set and session locks serialize ledger clients", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-lock-");
  const stale = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "stale", processId: 2147483000 });
  const active = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "active" });
  try {
    stale.initialize([{ operationId: "dead-op", accountKey: "alice", relativePath: "incoming/dead-op", state: "reserved", chargeBytes: 4 }]);
    const row = active.operations()[0];
    assert.equal(active.claim(row), true);
    assert.equal(active.operations()[0].ownerPid, process.pid);

    let releaseFirst;
    const firstLocked = new Promise((resolve, reject) => {
      active.withSessionLock("folder/upload", async () => {
        await new Promise((resolveRelease) => { releaseFirst = resolveRelease; });
        resolve();
      }).catch(reject);
    });
    while (!releaseFirst) await new Promise((resolve) => setTimeout(resolve, 5));
    await assert.rejects(stale.withSessionLock("folder/upload", async () => {}, { waitMs: 30 }), { code: "CHUNK_SESSION_LOCK_BUSY" });
    releaseFirst();
    await firstLocked;
    await stale.withSessionLock("folder/upload", async () => {});
  } finally {
    stale.close();
    active.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("a same-PID quota session lock from a prior instance is recoverable after PID reuse", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-pid-reuse-");
  const previous = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "previous-instance", processId: process.pid });
  try {
    previous.initialize();
    previous.close();
    const database = new Database(path.join(directory, ".quota.sqlite"));
    try {
      database.prepare("INSERT INTO quota_session_locks(session_key, owner_instance_id, owner_pid, created_at) VALUES (?, ?, ?, ?)").run("handoff-folder/folder", "previous-instance", process.pid, Date.now());
    } finally {
      database.close();
    }
    const current = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "current-instance", processId: process.pid });
    try {
      let entered = false;
      await current.withSessionLock("handoff-folder/folder", async () => { entered = true; }, { waitMs: 100 });
      assert.equal(entered, true);
    } finally {
      current.close();
    }
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("a live same-PID quota instance cannot have its session lock stolen", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-same-pid-lock-");
  const owner = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "active-owner", processId: process.pid });
  const contender = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "active-contender", processId: process.pid });
  try {
    owner.initialize();
    contender.initialize();
    let releaseOwner;
    let ownerEntered;
    const ownerEnteredPromise = new Promise((resolve) => { ownerEntered = resolve; });
    const ownerTask = owner.withSessionLock("session", async () => {
      ownerEntered();
      await new Promise((resolve) => { releaseOwner = resolve; });
    });
    await ownerEnteredPromise;
    let contenderEntered = false;
    await assert.rejects(contender.withSessionLock("session", async () => { contenderEntered = true; }, { waitMs: 40 }), { code: "CHUNK_SESSION_LOCK_BUSY" });
    assert.equal(contenderEntered, false, "a second live instance in the same PID must not overlap the lock owner");
    releaseOwner();
    await ownerTask;
    await contender.withSessionLock("session", async () => { contenderEntered = true; }, { waitMs: 100 });
    assert.equal(contenderEntered, true, "the contender acquires the lock after the owner releases it");
  } finally {
    owner.close();
    contender.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("session locks serialize across separate Node processes", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-process-lock-");
  const owner = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "parent-owner" });
  try {
    owner.initialize();
    let releaseOwner;
    let ownerEntered;
    const ownerEnteredPromise = new Promise((resolve) => { ownerEntered = resolve; });
    const ownerTask = owner.withSessionLock("process-session", async () => {
      ownerEntered();
      await new Promise((resolve) => { releaseOwner = resolve; });
    });
    await ownerEnteredPromise;

    const workerSource = `
      const { createChunkUploadQuota } = require(${JSON.stringify(require.resolve("../services/chunkUploadQuota"))});
      const quota = createChunkUploadQuota({ rootDir: process.argv[1], perAccountBytes: 10, systemBytes: 10 });
      quota.initialize();
      (async () => {
        try {
          await quota.withSessionLock("process-session", async () => {}, { waitMs: Number(process.argv[2]) });
          process.stdout.write("entered");
        } catch (error) {
          process.stdout.write(error.code || error.name);
        } finally { quota.close(); }
      })();
    `;
    const runWorker = (waitMs) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["-e", workerSource, directory, String(waitMs)], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("exit", (code) => code === 0 ? resolve(stdout) : reject(new Error(`lock worker exited ${code}: ${stderr}`)));
    });
    assert.equal(await runWorker(60), "CHUNK_SESSION_LOCK_BUSY", "a live owner in another PID keeps the lock until release");
    releaseOwner();
    await ownerTask;
    assert.equal(await runWorker(500), "entered", "the other process acquires after the owner releases it");
  } finally {
    owner.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("separate Node processes cannot oversubscribe the shared system quota", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-processes-");
  const setup = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10 });
  setup.initialize();
  setup.close();
  const modulePath = path.resolve(__dirname, "../services/chunkUploadQuota.js");
  const childSource = `
    const { createChunkUploadQuota } = require(${JSON.stringify(modulePath)});
    const quota = createChunkUploadQuota({ rootDir: process.argv[1], perAccountBytes: 10, systemBytes: 10 });
    try {
      quota.initialize();
      quota.reserve({ operationId: process.argv[2], accountKey: process.argv[2], relativePath: 'incoming/' + process.argv[2], reservedBytes: 6 });
      process.stdout.write('accepted');
    } catch (error) {
      process.stdout.write(error.code === 'CHUNK_QUOTA_EXCEEDED' ? 'rejected' : 'error:' + error.message);
      if (error.code !== 'CHUNK_QUOTA_EXCEEDED') process.exitCode = 1;
    } finally { quota.close(); }
  `;
  try {
    const results = await Promise.all(["child-one", "child-two"].map((id) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["-e", childSource, directory, id], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => { stdout += chunk; });
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("exit", (code) => code === 0 ? resolve(stdout) : reject(new Error(`Quota child failed (${code}): ${stderr}`)));
    })));
    assert.deepEqual(results.sort(), ["accepted", "rejected"]);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});
