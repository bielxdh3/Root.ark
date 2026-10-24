const assert = require("node:assert/strict");
const Database = require("better-sqlite3");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync, spawn } = require("node:child_process");
const test = require("node:test");
const {
  assertSafeChunkUploadAncestors,
  assertSupportedChunkUploadFilesystem,
  classifyProcessOwner,
  createChunkUploadQuota: createChunkUploadQuotaService,
  getCurrentProcessIdentity,
  parseChunkUploadQuotaConfig,
} = require("../services/chunkUploadQuota");
const { ensureWindowsChunkUploadRoot, getWindowsChunkAclDescriptor,
  verifyWindowsChunkUploadTree } = require("../services/chunkUploadWindowsAcl");
const QUOTA_TEST_TEMP = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();
const createChunkUploadQuota = (options) => createChunkUploadQuotaService({ perAccountEntries: 5000, systemEntries: 10000, ...options });

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
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "8",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
  }), { enabled: true, perAccountBytes: 80, systemBytes: 100, perAccountEntries: 8, systemEntries: 10 });
});

test("chunk quota configuration requires positive safe integer entry caps without defaults", () => {
  const byteAndTopologyLimits = {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "80",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
  };
  for (const entries of [
    {},
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "0", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "1.5", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "01", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "9007199254740992", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "9007199254740992" },
    { CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "11", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10" },
  ]) {
    assert.equal(parseChunkUploadQuotaConfig({ ...byteAndTopologyLimits, ...entries }).enabled, false);
  }

  assert.deepEqual(parseChunkUploadQuotaConfig({
    ...byteAndTopologyLimits,
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "4",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "6",
  }), { enabled: true, perAccountBytes: 80, systemBytes: 100, perAccountEntries: 4, systemEntries: 6 });
});

test("chunk quota fails closed unless the operator attests single-host local-volume placement", () => {
  const limits = {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "80",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100",
  };
  for (const topology of [undefined, "", "multi-host", "nfs", "smb", "single-host-local-volume "]) {
    const env = { ...limits };
    if (topology !== undefined) env.CHUNK_UPLOAD_STORAGE_TOPOLOGY = topology;
    assert.equal(parseChunkUploadQuotaConfig(env).enabled, false, `topology ${String(topology)} must fail closed`);
  }
  assert.equal(parseChunkUploadQuotaConfig({
    ...limits,
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "8",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
  }).enabled, true);
});

test("chunk staging rejects a group- or world-writable non-sticky ancestor", { skip: process.platform === "win32" }, () => {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, "rootark-chunk-unsafe-parent-"));
  const untrusted = path.join(parent, "untrusted");
  const staging = path.join(untrusted, "app", "temp", ".chunks");
  try {
    fs.mkdirSync(staging, { recursive: true });
    fs.chmodSync(untrusted, 0o777);
    assert.throws(() => assertSafeChunkUploadAncestors(staging), /unsafe|writable|owner/i);
  } finally {
    fs.chmodSync(untrusted, 0o700);
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("chunk staging rejects a sticky but writable staging directory itself", { skip: process.platform === "win32" }, () => {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, "rootark-chunk-sticky-target-"));
  try {
    fs.chmodSync(parent, 0o1777);
    assert.throws(() => assertSafeChunkUploadAncestors(parent), /writable/i);
  } finally {
    fs.chmodSync(parent, 0o700);
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("quota ledger refuses a writable staging root before creating SQLite state", { skip: process.platform === "win32" }, () => {
  const parent = fs.mkdtempSync(path.join(QUOTA_TEST_TEMP, "rootark-chunk-writable-root-"));
  try {
    fs.chmodSync(parent, 0o777);
    assert.throws(() => createChunkUploadQuota({ rootDir: parent, perAccountBytes: 10, systemBytes: 10 }), /writable/i);
    assert.equal(fs.existsSync(path.join(parent, ".quota.sqlite")), false);
  } finally {
    fs.chmodSync(parent, 0o700);
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("chunk staging rejects known remote Linux filesystems even with topology attestation", () => {
  const remoteFilesystemTypes = [0x6969, 0x517b, 0xff534d42, 0xfe534d42, 0x65735546, 0x01021997, 0x00c36400, 0x5346414f, 0x6b414653, 0x564c];
  for (const type of remoteFilesystemTypes) {
    assert.throws(() => assertSupportedChunkUploadFilesystem("/disposable/chunk-root", {
      platform: "linux",
      statfs: () => ({ type }),
    }), /unsupported.*filesystem|remote.*filesystem/i);
  }
  assert.doesNotThrow(() => assertSupportedChunkUploadFilesystem("/disposable/chunk-root", {
    platform: "linux",
    statfs: () => ({ type: 0xef53 }),
  }));
  assert.throws(() => assertSupportedChunkUploadFilesystem("/disposable/chunk-root", {
    platform: "linux",
    statfs: () => { throw new Error("mount information unavailable"); },
  }), /unable to verify.*filesystem/i);
  assert.throws(() => assertSupportedChunkUploadFilesystem("/disposable/chunk-root", {
    platform: "linux",
    statfs: () => ({}),
  }), /unable to verify.*filesystem/i);
  assert.throws(() => assertSupportedChunkUploadFilesystem("\\\\fileserver\\share\\chunks", {
    platform: "win32",
  }), /unsupported network filesystem/i);
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

test("legacy ledgers preserve charges and never reclaim session locks without verified ownership", async () => {
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
    oldDatabase.prepare("INSERT INTO quota_session_locks VALUES (?, ?, ?, ?)").run("handoff-folder/folder", "prior-lock", process.pid, 1);
  } finally {
    oldDatabase.close();
  }

  try {
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 12 });
    try {
      assert.deepEqual(quota.initialize(), { alreadyReady: true, entryCapacityExceeded: false });
      assert.deepEqual(quota.totals(), { systemBytes: 5, accounts: { alice: 5 } });
      assert.deepEqual(quota.sessions().map((session) => ({ sessionKey: session.sessionKey, accountKey: session.accountKey })), [{ sessionKey: "folder/upload", accountKey: "alice" }]);
      const legacyOperation = quota.operations()[0];
      assert.equal(legacyOperation.ownerProcessIdentity, null, "legacy rows do not invent a process identity during migration");
      assert.equal(quota.ownerStatus(legacyOperation), "unknown", "legacy owners remain unrecoverable without verifiable identity");
      assert.equal(quota.claim(legacyOperation), false, "legacy operations cannot be claimed without verified death");
      let legacyLockEntered = false;
      await assert.rejects(quota.withSessionLock("handoff-folder/folder", async () => { legacyLockEntered = true; }, { waitMs: 0 }), { code: "CHUNK_SESSION_LOCK_BUSY" });
      assert.equal(legacyLockEntered, false, "an unverifiable migrated lock continues to protect its session");
      const migrated = new Database(databasePath, { readonly: true });
      try {
        assert.equal(migrated.prepare("SELECT value FROM quota_meta WHERE key = 'schema_version'").get().value, "4");
        assert.ok(migrated.pragma("table_info(quota_operations)").some((column) => column.name === "owner_process_identity"));
        assert.ok(migrated.pragma("table_info(quota_session_locks)").some((column) => column.name === "owner_process_identity"));
        assert.equal(migrated.prepare("SELECT owner_process_identity FROM quota_session_locks WHERE session_key = ?").get("handoff-folder/folder").owner_process_identity, null);
      } finally {
        migrated.close();
      }
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

test("schema v3 migration adds nullable process identities without changing existing quota state", () => {
  const { parent, root } = createQuotaTestRoot("rootark-chunk-quota-v3-migration-");
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
      CREATE TABLE quota_session_locks (
        session_key TEXT PRIMARY KEY, owner_instance_id TEXT NOT NULL, owner_pid INTEGER NOT NULL, created_at INTEGER NOT NULL
      );
      CREATE TABLE quota_usage (account_key TEXT PRIMARY KEY, charge_bytes INTEGER NOT NULL CHECK (charge_bytes >= 0));
      CREATE TABLE quota_sessions (session_key TEXT PRIMARY KEY, account_key TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
    `);
    oldDatabase.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?)").run("schema_version", "3");
    oldDatabase.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?)").run("ready", "1");
    oldDatabase.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?)").run("usage_version", "1");
    oldDatabase.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?)").run("system_charge_bytes", "5");
    oldDatabase.prepare("INSERT INTO quota_operations VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run("existing-part", "alice", "folder/upload", "folder/upload/0.part", "part_committed", 5, "prior", 4321, 1, 1);
    oldDatabase.prepare("INSERT INTO quota_usage(account_key, charge_bytes) VALUES (?, ?)").run("alice", 5);
    oldDatabase.prepare("INSERT INTO quota_sessions VALUES (?, ?, ?, ?)").run("folder/upload", "alice", 1, 1);
  } finally {
    oldDatabase.close();
  }

  try {
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 12 });
    try {
      assert.deepEqual(quota.initialize(), { alreadyReady: true, entryCapacityExceeded: false });
      assert.deepEqual(quota.totals(), { systemBytes: 5, accounts: { alice: 5 } });
      const migratedOperation = quota.operations()[0];
      assert.equal(migratedOperation.operationId, "existing-part");
      assert.equal(migratedOperation.ownerProcessIdentity, null);
      assert.equal(quota.ownerStatus(migratedOperation), "unknown");
      assert.equal(quota.claim(migratedOperation), false);
      const migrated = new Database(databasePath, { readonly: true });
      try {
        assert.equal(migrated.prepare("SELECT value FROM quota_meta WHERE key = 'schema_version'").get().value, "4");
        assert.ok(migrated.pragma("table_info(quota_operations)").some((column) => column.name === "owner_process_identity"));
        assert.ok(migrated.pragma("table_info(quota_session_locks)").some((column) => column.name === "owner_process_identity"));
      } finally {
        migrated.close();
      }
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

test("Windows ACL scan tolerates only vanished trusted transient files under concurrent child IO", {
  skip: process.platform !== "win32",
}, async () => {
  const { parent, root } = createQuotaTestRoot("rootark-chunk-acl-volatile-");
  const childSource = `
    const fs = require('node:fs');
    const path = require('node:path');
    const Database = require(${JSON.stringify(require.resolve("better-sqlite3"))});
    const root = process.argv[1];
    const marker = path.join(root, 'worker-ready');
    const dbPath = path.join(root, '.volatile.sqlite');
    const pause = new Int32Array(new SharedArrayBuffer(4));
    for (let i = 0; i < 150; i++) {
      const db = new Database(dbPath);
      try {
        db.pragma('journal_mode = WAL');
        db.exec('CREATE TABLE IF NOT EXISTS transient (value INTEGER)');
        db.prepare('INSERT INTO transient(value) VALUES(?)').run(i);
        if (i === 0) fs.writeFileSync(marker, 'ready');
      } finally { db.close(); }
      Atomics.wait(pause, 0, 0, 10);
    }
  `;
  try {
    const child = spawn(process.execPath, ["-e", childSource, root], {
      stdio: ["ignore", "ignore", "pipe"], windowsHide: true,
    });
    const exited = new Promise((resolve, reject) => {
      let stderr = "";
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.once("error", reject);
      child.once("exit", (code) => code === 0 ? resolve() : reject(new Error(
        `disposable transient writer exited ${code}: ${stderr.slice(0, 160)}`)));
    });
    try {
      const started = Date.now() + 10000;
      while (!fs.existsSync(path.join(root, "worker-ready")) && Date.now() < started) {
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.equal(fs.existsSync(path.join(root, "worker-ready")), true,
        "ACL verifier must actually overlap a separately running SQLite WAL/SHM writer");
      for (let i = 0; i < 2; i++) verifyWindowsChunkUploadTree(root);
      await exited;
      verifyWindowsChunkUploadTree(root);
      execFileSync("icacls.exe", [root, "/grant", "*S-1-5-32-545:(OI)(CI)M"], {
        stdio: "ignore", windowsHide: true,
      });
      assert.throws(() => verifyWindowsChunkUploadTree(root),
        /Windows chunk staging ACL validation failed|Untrusted principal/,
        "an untrusted ACL must remain denied even after bounded transient-file retries");
    } finally {
      if (child.exitCode === null) child.kill();
      await Promise.allSettled([exited]);
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

test("zero-byte operations and session entries share atomic account and system entry limits", () => {
  withTempDir((directory) => {
    const first = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 12, perAccountEntries: 3, systemEntries: 4 });
    const second = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 12, perAccountEntries: 3, systemEntries: 4 });
    let firstOpen = true;
    try {
      first.initialize();
      second.initialize();
      first.reserve({ operationId: "empty-part-1", accountKey: "alice", sessionKey: "folder/upload-one", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/upload-one/0.part" });
      second.reserve({ operationId: "empty-part-2", accountKey: "ALICE", sessionKey: "folder/upload-one", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/upload-one/1.part" });
      assert.deepEqual(first.entryTotals(), { systemEntries: 3, accounts: { alice: 3 } });
      assert.throws(() => second.reserve({ operationId: "empty-part-3", accountKey: "alice", reservedBytes: 0, allowZeroBytes: true, relativePath: "incoming/empty-part-3" }), { code: "CHUNK_QUOTA_EXCEEDED" });
      assert.throws(() => second.reserve({ operationId: "bob-part", accountKey: "bob", sessionKey: "folder/upload-bob", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/upload-bob/0.part" }), { code: "CHUNK_QUOTA_EXCEEDED" });
      assert.deepEqual(first.entryTotals(), { systemEntries: 3, accounts: { alice: 3 } });

      first.close();
      firstOpen = false;
      const reopened = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 12, perAccountEntries: 3, systemEntries: 4 });
      try {
        assert.equal(reopened.isReady(), true);
        assert.deepEqual(reopened.entryTotals(), { systemEntries: 3, accounts: { alice: 3 } });
        assert.equal(reopened.releaseSessionOperations("folder/upload-one"), 2);
        assert.deepEqual(reopened.entryTotals(), { systemEntries: 1, accounts: { alice: 1 } }, "expiry releases part rows but retains its tombstone session entry");
        reopened.reserve({ operationId: "after-expiry", accountKey: "alice", sessionKey: "folder/after-expiry", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/after-expiry/0.part" });
        assert.throws(() => reopened.reserve({ operationId: "system-blocked", accountKey: "bob", sessionKey: "folder/system-blocked", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/system-blocked/0.part" }), { code: "CHUNK_QUOTA_EXCEEDED" });
        assert.equal(reopened.releaseSession("folder/upload-one"), 0, "removing an expired session frees its retained entry after its tombstone expires");
        reopened.reserve({ operationId: "after-tombstone", accountKey: "bob", sessionKey: "folder/after-tombstone", reservedBytes: 0, allowZeroBytes: true, relativePath: "folder/after-tombstone/0.part" });
        assert.deepEqual(reopened.entryTotals(), { systemEntries: 4, accounts: { alice: 2, bob: 2 } });
      } finally {
        reopened.close();
      }
    } finally {
      second.close();
      if (firstOpen) first.close();
    }
  });
});

test("migration and restart detect over-cap entries while keeping cleanup available", () => {
  const scenarios = [
    {
      accountCap: 2,
      systemCap: 3,
      sessions: ["folder/upload"],
      prepare(quota) {
        quota.reserve({ operationId: "account-cap-part-1", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 1, relativePath: "folder/upload/0.part" });
        quota.reserve({ operationId: "account-cap-part-2", accountKey: "alice", sessionKey: "folder/upload", reservedBytes: 1, relativePath: "folder/upload/1.part" });
      },
      blockedAccount: "alice",
      blockedId: "account-cap-blocked",
    },
    {
      accountCap: 3,
      systemCap: 3,
      sessions: ["folder/upload-one", "folder/upload-two"],
      prepare(quota) {
        quota.reserve({ operationId: "system-cap-part-1", accountKey: "alice", sessionKey: "folder/upload-one", reservedBytes: 1, relativePath: "folder/upload-one/0.part" });
        quota.reserve({ operationId: "system-cap-part-2", accountKey: "bob", sessionKey: "folder/upload-two", reservedBytes: 1, relativePath: "folder/upload-two/0.part" });
      },
      blockedAccount: "carol",
      blockedId: "system-cap-blocked",
    },
  ];

  for (const mode of ["migration", "restart"]) {
    for (const scenario of scenarios) {
      withTempDir((directory) => {
        const original = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 20, systemBytes: 20, perAccountEntries: 5, systemEntries: 5 });
        try {
          original.initialize();
          scenario.prepare(original);
        } finally {
          original.close();
        }

        if (mode === "migration") {
          const database = new Database(path.join(directory, ".quota.sqlite"));
          try {
            database.prepare("UPDATE quota_meta SET value = '2' WHERE key = 'schema_version'").run();
            database.prepare("DELETE FROM quota_sessions").run();
          } finally {
            database.close();
          }
        }

        const reopened = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 20, systemBytes: 20, perAccountEntries: scenario.accountCap, systemEntries: scenario.systemCap });
        try {
          assert.deepEqual(reopened.initialize(), { alreadyReady: true, entryCapacityExceeded: true });
          const entriesBefore = reopened.entryTotals();
          assert.throws(() => reopened.reserve({
            operationId: scenario.blockedId,
            accountKey: scenario.blockedAccount,
            sessionKey: `folder/${scenario.blockedId}`,
            reservedBytes: 0,
            allowZeroBytes: true,
            relativePath: `folder/${scenario.blockedId}/0.part`,
          }), { code: "CHUNK_QUOTA_EXCEEDED" });
          assert.deepEqual(reopened.entryTotals(), entriesBefore, "a restart over configured entry capacity must not admit another row");

          for (const sessionKey of scenario.sessions) reopened.releaseSession(sessionKey);
          assert.deepEqual(reopened.entryTotals(), { systemEntries: 0, accounts: {} });
          reopened.reserve({ operationId: `${mode}-${scenario.blockedId}`, accountKey: scenario.blockedAccount, sessionKey: `folder/${scenario.blockedId}`, reservedBytes: 0, allowZeroBytes: true, relativePath: `folder/${scenario.blockedId}/0.part` });
          assert.equal(reopened.entryTotals().systemEntries, 2, "cleanup restores admission once the retained entries fit the configured caps");
        } finally {
          reopened.close();
        }
      });
    }
  }
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
      assert.deepEqual(second.initialize([{ operationId: "duplicate-import", accountKey: "alice", relativePath: "incoming/x", state: "reserved", chargeBytes: 1 }]), { alreadyReady: true, entryCapacityExceeded: false });
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
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000 });
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
  const stale = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "stale", processId: 2147483000, processIdentity: getCurrentProcessIdentity() });
  const active = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "active", classifyOwner: () => "dead" });
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

test("a same-namespace quota session lock is recoverable after verified PID reuse", { skip: process.platform !== "linux" }, async (t) => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-pid-reuse-");
  const currentIdentity = getCurrentProcessIdentity();
  if (!currentIdentity) {
    fs.rmSync(parent, { recursive: true, force: true });
    return t.skip("the host process identity is unavailable");
  }
  const previous = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "previous-instance", processId: process.pid });
  try {
    previous.initialize();
    previous.close();
    const database = new Database(path.join(directory, ".quota.sqlite"));
    try {
      const reusedIdentity = { ...currentIdentity, processStartTime: "0" };
      database.prepare("INSERT INTO quota_session_locks(session_key, owner_instance_id, owner_pid, owner_process_identity, created_at) VALUES (?, ?, ?, ?, ?)").run("handoff-folder/folder", "previous-instance", process.pid, JSON.stringify(reusedIdentity), Date.now());
    } finally {
      database.close();
    }
    const current = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "current-instance", processId: process.pid });
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
  const owner = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "active-owner", processId: process.pid });
  const contender = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "active-contender", processId: process.pid });
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

test("a same-numbered PID in a different namespace cannot steal a quota session lock", { skip: process.platform !== "linux" }, async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-pid-namespace-lock-");
  const ownerIdentity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: "pid:[100]", processStartTime: "10" };
  const contenderIdentity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: "pid:[200]", processStartTime: "20" };
  const owner = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "namespace-owner", processId: 4242, processIdentity: ownerIdentity });
  const contender = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "namespace-contender", processId: 4242, processIdentity: contenderIdentity });
  try {
    owner.initialize();
    contender.initialize();
    let releaseOwner;
    let ownerEntered;
    const ownerEnteredPromise = new Promise((resolve) => { ownerEntered = resolve; });
    const ownerTask = owner.withSessionLock("shared-pid-session", async () => {
      ownerEntered();
      await new Promise((resolve) => { releaseOwner = resolve; });
    });
    await ownerEnteredPromise;

    let contenderEntered = false;
    await assert.rejects(contender.withSessionLock("shared-pid-session", async () => { contenderEntered = true; }, { waitMs: 40 }), { code: "CHUNK_SESSION_LOCK_BUSY" });
    assert.equal(contenderEntered, false, "an unverifiable owner from another PID namespace keeps its lock");
    assert.equal(owner.operations().length, 0);
    releaseOwner();
    await ownerTask;
  } finally {
    owner.close();
    contender.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("operation ownership is unknown when a matching PID belongs to another namespace", { skip: process.platform !== "linux" }, () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-pid-namespace-operation-");
  const ownerIdentity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: "pid:[100]", processStartTime: "10" };
  const otherNamespaceIdentity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: "pid:[200]", processStartTime: "20" };
  const owner = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "operation-owner", processId: 4242, processIdentity: ownerIdentity });
  const contender = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, processInstanceId: "operation-contender", processId: 4242, processIdentity: otherNamespaceIdentity });
  try {
    owner.initialize([{ operationId: "preserve-foreign-owner", accountKey: "alice", relativePath: "incoming/preserve-foreign-owner", state: "reserved", chargeBytes: 4 }]);
    contender.initialize();
    const operation = contender.operations()[0];
    assert.equal(operation.ownerProcessIdentity, JSON.stringify(ownerIdentity));
    assert.equal(contender.ownerStatus(operation), "unknown", "ambiguous ownership must block startup recovery");
    assert.equal(contender.claim(operation), false, "unknown ownership cannot be claimed for recovery");
    assert.equal(contender.operations()[0].state, "reserved", "the durable reservation remains untouched");
  } finally {
    owner.close();
    contender.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("process ownership stays unknown when procfs exposes another PID namespace", () => {
  const identity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: "pid:[200]", processStartTime: "10" };
  let ownerPidRead = false;
  const status = classifyProcessOwner(4242, identity, identity, {
    platform: "linux",
    readlinkSync: (filePath) => {
      if (filePath === "/proc/self/ns/pid") return "pid:[100]";
      ownerPidRead = true;
      throw Object.assign(new Error("no such process in this procfs view"), { code: "ENOENT" });
    },
  });

  assert.equal(status, "unknown", "an out-of-namespace /proc view cannot prove that the owner PID is dead");
  assert.equal(ownerPidRead, false, "the classifier rejects the procfs view before interpreting a missing numeric PID");
});

test("inaccessible PID 1 procfs does not block recovery when self PID mapping proves the view", { skip: process.platform !== "linux" }, () => {
  const currentNamespace = fs.readlinkSync("/proc/self/ns/pid");
  const identity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: currentNamespace, processStartTime: "10" };
  const readPaths = [];
  const status = classifyProcessOwner(4242, identity, identity, {
    platform: "linux",
    readlinkSync: (filePath) => {
      readPaths.push(filePath);
      if (filePath === "/proc/self/ns/pid") return currentNamespace;
      if (filePath === "/proc/1/ns/pid") throw Object.assign(new Error("permission denied"), { code: "EACCES" });
      throw Object.assign(new Error("no such process in this procfs view"), { code: "ENOENT" });
    },
    readFileSync: (filePath) => {
      assert.equal(filePath, "/proc/self/stat");
      return `${process.pid} (rootark-quota-test) S 1 2 3`;
    },
  });

  assert.equal(status, "dead", "self namespace and self PID mapping prove that a missing owner PID is absent from this procfs view");
  assert.deepEqual(readPaths, ["/proc/self/ns/pid", "/proc/4242/ns/pid"], "classification uses the current namespace and the exact owner PID, without requiring access to PID 1");
});

test("process ownership stays unknown when procfs numeric PIDs do not map the current process", { skip: process.platform !== "linux" }, () => {
  const identity = { version: 1, platform: "linux", hostId: "a".repeat(64), bootId: "00000000-0000-0000-0000-000000000001", pidNamespace: fs.readlinkSync("/proc/self/ns/pid"), processStartTime: "10" };
  let ownerPidRead = false;
  const status = classifyProcessOwner(4242, identity, identity, {
    platform: "linux",
    readlinkSync: (filePath) => {
      if (filePath === "/proc/self/ns/pid") return identity.pidNamespace;
      ownerPidRead = true;
      throw Object.assign(new Error("owner PID must not be probed"), { code: "ENOENT" });
    },
    readFileSync: (filePath) => {
      assert.equal(filePath, "/proc/self/stat");
      return "1 (unrelated-procfs-pid) S 1 2 3";
    },
  });

  assert.equal(status, "unknown", "procfs must expose the current process using the same numeric PID recorded in the operation");
  assert.equal(ownerPidRead, false, "a mismatched procfs PID view is rejected before probing an owner");
});

test("malformed Linux owner identity is ambiguous instead of being treated as PID reuse", { skip: process.platform !== "linux" }, (t) => {
  const current = getCurrentProcessIdentity();
  if (!current) return t.skip("the host process identity is unavailable");
  const malformed = JSON.stringify({ ...current, processStartTime: "not-a-process-start-time" });
  assert.equal(classifyProcessOwner(process.pid, malformed, current, { platform: "linux" }), "unknown");
});

test("PID probing without process-start support never reclaims a present or ambiguous owner", () => {
  const identity = { version: 1, platform: "win32" };
  assert.equal(classifyProcessOwner(4242, identity, identity, { platform: "win32", kill: () => {} }), "live");
  assert.equal(classifyProcessOwner(4242, identity, identity, { platform: "win32", kill: () => { throw Object.assign(new Error("denied"), { code: "EPERM" }); } }), "unknown");
  assert.equal(classifyProcessOwner(4242, identity, identity, { platform: "win32", kill: () => { throw Object.assign(new Error("missing"), { code: "ESRCH" }); } }), "dead");
  const persistedIdentity = JSON.stringify(identity);
  assert.equal(classifyProcessOwner(4242, persistedIdentity, persistedIdentity, { platform: "win32", kill: () => { throw Object.assign(new Error("missing"), { code: "ESRCH" }); } }), "dead", "serialized current and persisted identities must support conservative absent-PID recovery");
});

test("session locks serialize across separate Node processes", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-process-lock-");
  const owner = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "parent-owner" });
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
      const quota = createChunkUploadQuota({ rootDir: process.argv[1], perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000 });
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

test("concurrent first startup reopens a database file created by another process", async () => {
  const { parent, root: directory } = createQuotaTestRoot("rootark-chunk-quota-first-startup-");
  const modulePath = path.resolve(__dirname, "../services/chunkUploadQuota.js");
  const gatePath = path.join(directory, "release-db-create");
  const workerSource = `
    const fs = require('node:fs');
    const path = require('node:path');
    const root = process.argv[1];
    const readyPath = path.join(root, 'lstat-ready-' + process.argv[2]);
    const gatePath = path.join(root, 'release-db-create');
    const databasePath = path.join(root, '.quota.sqlite');
    const originalLstat = fs.lstatSync;
    fs.lstatSync = function(target, ...args) {
      if (path.resolve(target) === path.resolve(databasePath)) {
        try { return originalLstat.call(this, target, ...args); }
        catch (error) {
          if (error.code !== 'ENOENT') throw error;
          fs.writeFileSync(readyPath, 'ready');
          while (!fs.existsSync(gatePath)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
          throw error;
        }
      }
      return originalLstat.call(this, target, ...args);
    };
    const { createChunkUploadQuota } = require(${JSON.stringify(modulePath)});
    const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 20, systemBytes: 20, perAccountEntries: 4, systemEntries: 8 });
    try { quota.initialize(); process.stdout.write('ready'); }
    catch (error) { process.stderr.write(error.code || error.message); process.exitCode = 1; }
    finally { quota.close(); }
  `;
  const children = [];
  const workers = [];
  try {
    for (let index = 0; index < 4; index += 1) {
      const child = spawn(process.execPath, ["-e", workerSource, directory, String(index)], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      children.push(child);
      workers.push(new Promise((resolve, reject) => {
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (chunk) => { stdout += chunk; });
        child.stderr.on("data", (chunk) => { stderr += chunk; });
        child.once("error", reject);
        child.once("exit", (code) => code === 0 ? resolve(stdout) : reject(new Error(`startup worker exited ${code}: ${stderr}`)));
      }));
    }

    const barrierDeadline = Date.now() + 10000;
    while (fs.readdirSync(directory).filter((name) => name.startsWith("lstat-ready-")).length < children.length && Date.now() < barrierDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(fs.readdirSync(directory).filter((name) => name.startsWith("lstat-ready-")).length, children.length, "all processes observe the fresh database as missing before any process creates it");
    fs.writeFileSync(gatePath, "go");
    assert.deepEqual(await Promise.all(workers), Array(children.length).fill("ready"));

    const verify = createChunkUploadQuota({ rootDir: directory, perAccountBytes: 20, systemBytes: 20, perAccountEntries: 4, systemEntries: 8 });
    try {
      assert.deepEqual(verify.initialize(), { alreadyReady: true, entryCapacityExceeded: false });
      assert.equal(verify.isReady(), true);
    } finally {
      verify.close();
    }
  } finally {
    fs.writeFileSync(gatePath, "go");
    for (const child of children) if (child.exitCode === null) child.kill();
    await Promise.allSettled(workers);
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
    const quota = createChunkUploadQuota({ rootDir: process.argv[1], perAccountBytes: 10, systemBytes: 10, perAccountEntries: 5000, systemEntries: 10000 });
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

test("chunk quota fails closed in cluster workers and non-primary PM2 instances", () => {
  const env = {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "80",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100",
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "8",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
  };
  assert.deepEqual(parseChunkUploadQuotaConfig(env, { isWorker: true }), { enabled: false, reason: "multi_process_runtime" });
  assert.deepEqual(parseChunkUploadQuotaConfig({ ...env, NODE_APP_INSTANCE: "1" }, { isWorker: false }), { enabled: false, reason: "multi_process_runtime" });
  assert.equal(parseChunkUploadQuotaConfig({ ...env, NODE_APP_INSTANCE: "0" }, { isWorker: false }).enabled, true);
  assert.equal(parseChunkUploadQuotaConfig(env, { isWorker: false }).enabled, true);
});

test("chunk quota stays enabled in multi-process runtimes only when the host-shared SQLite rate store is selected", () => {
  const env = {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "80",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "100",
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "8",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
    UPLOAD_CHUNK_RATE_LIMIT_STORE: "sqlite",
  };
  assert.equal(parseChunkUploadQuotaConfig(env, { isWorker: true }).enabled, true);
  assert.equal(parseChunkUploadQuotaConfig({ ...env, NODE_APP_INSTANCE: "1" }, { isWorker: false }).enabled, true);
  assert.equal(parseChunkUploadQuotaConfig({ ...env, UPLOAD_CHUNK_RATE_LIMIT_STORE: "memory" }, { isWorker: true }).reason, "multi_process_runtime");
});
