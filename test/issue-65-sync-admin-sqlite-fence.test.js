"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { execFile, spawn } = require("node:child_process");
const { promisify } = require("node:util");
const { performance } = require("node:perf_hooks");
const vm = require("node:vm");
const test = require("node:test");
const express = require("express");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { runMigrations } = require("../db/migrations");
const { closeDb } = require("../db");
const users = require("../repositories/usersRepository");
const auditRepository = require("../repositories/auditRepository");
const analyticsRepository = require("../repositories/analyticsRepository");
const actionHistoryRepository = require("../repositories/actionHistoryRepository");
const foldersRepository = require("../repositories/foldersRepository");
const pendingUploadsRepository = require("../repositories/pendingUploadsRepository");
const publicLinksRepository = require("../repositories/publicLinksRepository");
const fileSearchIndexRepository = require("../repositories/fileSearchIndexRepository");
const { ensureRootFolder } = require("../repositories/repositoryUtils");
const { getDb } = require("../db");

const execFileAsync = promisify(execFile);

function isolatedDirectory() {
  if (process.platform !== "win32") return fs.mkdtempSync(path.join(os.tmpdir(), "zk65-sync-admin-"));
  const directory = path.join(process.env.LOCALAPPDATA, "zk65-sync-admin-" + crypto.randomBytes(8).toString("hex"));
  ensureWindowsChunkUploadRoot(directory);
  return directory;
}

function post(port, operation) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(operation));
    const req = http.request({ host: "127.0.0.1", port, path: "/sync/v1/objects", method: "POST",
      headers: { "content-type": "application/json", "content-length": payload.length } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

async function fixture(t, { holdAdmission = null } = {}) {
  const dir = isolatedDirectory();
  const oldEnv = { DATABASE_URL: process.env.DATABASE_URL, DB_ENABLED: process.env.DB_ENABLED,
    DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON };
  process.env.DATABASE_URL = path.join(dir, "accounts.sqlite");
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  t.after(() => {
    closeDb();
    for (const [name, value] of Object.entries(oldEnv)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  runMigrations({ backup: false });
  users.saveUsers([{ username: "alice", password: "fixture-only", role: "user",
    permissions: { upload: true, delete: true }, sessionVersion: 4 }]);
  const storagePath = path.join(dir, "objects.json");
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const route = registerSyncRoutes({ app, storagePath, atomicDeviceRegistry: true,
    requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", sessionVersion: 4, role: "user",
        permissions: { upload: true, delete: true } };
      next();
    },
    requirePermission: (permission) => (req, _res, next) => {
      if (permission === "upload" && req.method === "POST" && holdAdmission) {
        holdAdmission().then(next, next);
      } else next();
    } });
  await route.ready;
  await route.store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey, expectedEpoch: 0 });
  const listener = await new Promise((resolve) => {
    const server = app.listen(0, "127.0.0.1", () => resolve(server));
  });
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const signedOperation = async (name) => {
    const operation = createOperation({
      operation: "create", objectId: name, fileId: name + "-file",
      versionId: name + "-version", operationId: name + "-op", deviceId: "device-a",
      keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: name + ".txt" }, plaintext: Buffer.from("fixture"),
      fileKey: crypto.randomBytes(32),
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", publicKey, privateKey: keys.privateKey,
      expiresAt: Date.now() + 120000,
    });
    return operation;
  };
  const updateAccount = async (sql) => {
    const program = `const Database=require(process.argv[1]);const db=new Database(process.argv[2]);db.pragma('busy_timeout = 10000');db.exec('BEGIN IMMEDIATE');db.prepare(process.argv[3]).run();db.exec('COMMIT');db.close();`;
    await execFileAsync(process.execPath, ["-e", program, require.resolve("better-sqlite3"),
      process.env.DATABASE_URL, sql], { timeout: 15000 });
  };
  return { dir, route, listener, storagePath, signedOperation, updateAccount };
}

test("strict Sync HTTP fails closed after cross-process account permission revocation before commit", async (t) => {
  let reachedAdmission;
  const reached = new Promise((resolve) => { reachedAdmission = resolve; });
  let releaseAdmission;
  const released = new Promise((resolve) => { releaseAdmission = resolve; });
  const ctx = await fixture(t, { holdAdmission: () => { reachedAdmission(); return released; } });
  const operation = await ctx.signedOperation("revoked-before");
  const pending = post(ctx.listener.address().port, operation);
  await reached;
  try {
    await ctx.updateAccount("UPDATE users SET permissions_json='{\"upload\":false,\"delete\":false}',storage_revision=storage_revision+1 WHERE username='alice'");
  } finally { releaseAdmission(); }
  assert.equal(await pending, 403);
  assert.deepEqual((await new SyncObjectStore(ctx.storagePath, { atomicDeviceRegistry: true }).open()).list("alice"), []);
});

test("a second process cannot commit SQLite revocation while signed Sync JSON commit is in flight", async (t) => {
  const ctx = await fixture(t);
  let reachedRename;
  const reached = new Promise((resolve) => { reachedRename = resolve; });
  let releaseRename;
  const released = new Promise((resolve) => { releaseRename = resolve; });
  const originalRename = fsp.rename;
  fsp.rename = async function (...args) {
    if (args[1] === ctx.storagePath) {
      reachedRename();
      await released;
    }
    return originalRename.apply(this, args);
  };
  t.after(() => { releaseRename(); fsp.rename = originalRename; });
  const first = await ctx.signedOperation("first-commit");
  const pending = post(ctx.listener.address().port, first);
  await reached;

  const program = `const Database=require(process.argv[1]);const db=new Database(process.argv[2],{timeout:15000});db.pragma('busy_timeout=15000');process.stdout.write('TRY\\n');db.exec('BEGIN IMMEDIATE');db.prepare("UPDATE users SET permissions_json='{\\\"upload\\\":false,\\\"delete\\\":false}',storage_revision=storage_revision+1 WHERE username='alice'").run();db.exec('COMMIT');db.close();process.stdout.write('COMMITTED\\n');`;
  const child = spawn(process.execPath, ["-e", program, require.resolve("better-sqlite3"),
    process.env.DATABASE_URL], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let output = "";
  child.stdout.on("data", (data) => { output += data.toString(); });
  await new Promise((resolve, reject) => {
    if (output.includes("TRY")) return resolve();
    child.stdout.on("data", function onData(data) {
      if (data.toString().includes("TRY") || output.includes("TRY")) {
        child.stdout.off("data", onData);
        resolve();
      }
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (!output.includes("TRY")) reject(new Error(`Revocation child exited before SQLite write: ${code}`));
    });
  });
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(output.includes("COMMITTED"), false,
    "SQLite admin writer must be blocked until the Sync ciphertext rename/fsync completes");
  releaseRename();
  assert.equal(await pending, 201);
  const childExit = await new Promise((resolve) => {
    if (child.exitCode !== null) resolve(child.exitCode);
    else child.once("exit", resolve);
  });
  assert.equal(childExit, 0);
  assert.match(output, /COMMITTED/);

  const restarted = await new SyncObjectStore(ctx.storagePath, { atomicDeviceRegistry: true }).open();
  assert.deepEqual(restarted.list("alice").map((record) => record.objectId), ["first-commit"]);
  assert.equal(await post(ctx.listener.address().port, await ctx.signedOperation("after-revoke")), 403);
  assert.deepEqual(restarted.list("alice").map((record) => record.objectId), ["first-commit"]);
});

test("two concurrent strict HTTP POSTs on one Node process keep event-loop timers alive", async (t) => {
  const ctx = await fixture(t);
  const originalRename = fsp.rename;
  let hitFirstRename;
  const firstRenameReached = new Promise((resolve) => { hitFirstRename = resolve; });
  let releaseFirstRename;
  const firstRenameReleased = new Promise((resolve) => { releaseFirstRename = resolve; });
  let calls = 0;
  fsp.rename = async (...args) => {
    if (args[1] === ctx.storagePath && ++calls === 1) {
      hitFirstRename();
      await firstRenameReleased;
    }
    return originalRename(...args);
  };
  t.after(() => { releaseFirstRename(); fsp.rename = originalRename; });

  const op1 = await ctx.signedOperation("same-process-one");
  const op2 = await ctx.signedOperation("same-process-two");
  const firstRequest = post(ctx.listener.address().port, op1);
  await firstRenameReached;
  let heartbeat = 0;
  const interval = setInterval(() => { heartbeat++; }, 40);
  t.after(() => clearInterval(interval));
  const started = performance.now();
  let timerDelay = Infinity;
  const releaseTimer = setTimeout(() => {
    timerDelay = performance.now() - started;
    releaseFirstRename();
  }, 200);
  t.after(() => clearTimeout(releaseTimer));
  const secondRequest = post(ctx.listener.address().port, op2);
  const statuses = await Promise.all([firstRequest, secondRequest]);
  assert.deepEqual(statuses, [201, 201], "both unique signed devices operations should serialize");
  assert.ok(timerDelay < 5000,
    `the first pending JSON fsync must not be starved by a second synchronous SQLite BEGIN IMMEDIATE (timer delay ${timerDelay}ms)`);
  assert.ok(heartbeat > 0, "same-process request contention must yield to the event loop");
  const reopened = await new SyncObjectStore(ctx.storagePath, { atomicDeviceRegistry: true }).open();
  assert.deepEqual(reopened.list("alice").map((record) => record.objectId).sort(),
    ["same-process-one", "same-process-two"]);
});

test("independent SQLite admin writer wins before admission without blocking the HTTP event loop", async (t) => {
  const ctx = await fixture(t);
  const program = `const Database=require(process.argv[1]);const db=new Database(process.argv[2],{timeout:0});db.exec('BEGIN IMMEDIATE');process.stdout.write('LOCKED\\n');setTimeout(()=>{db.prepare("UPDATE users SET permissions_json='{\\\"upload\\\":false,\\\"delete\\\":false}',storage_revision=storage_revision+1 WHERE username='alice'").run();db.exec('COMMIT');db.close();process.stdout.write('REVOKED\\n')},600);`;
  const child = spawn(process.execPath, ["-e", program, require.resolve("better-sqlite3"),
    process.env.DATABASE_URL], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let output = "";
  child.stdout.on("data", (data) => { output += data.toString(); });
  await new Promise((resolve, reject) => {
    child.stdout.on("data", function onData() {
      if (!output.includes("LOCKED")) return;
      child.stdout.off("data", onData);
      resolve();
    });
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`SQLite admin lock child terminated: ${code}`)));
  });
  const operation = await ctx.signedOperation("external-admin-wins");
  let ticks = 0;
  const ticker = setInterval(() => { ticks++; }, 40);
  t.after(() => clearInterval(ticker));
  let pingDelay = Infinity;
  const started = performance.now();
  const ping = setTimeout(() => { pingDelay = performance.now() - started; }, 100);
  t.after(() => clearTimeout(ping));
  assert.equal(await post(ctx.listener.address().port, operation), 403);
  assert.ok(ticks > 0 && pingDelay < 5000,
    `SQLite busy retries should yield to timers (${pingDelay}ms)`);
  const restarted = await new SyncObjectStore(ctx.storagePath, { atomicDeviceRegistry: true }).open();
  assert.deepEqual(restarted.list("alice"), []);
  assert.match(output, /REVOKED/);
});

test("same-process admin account update fails fast during protected Sync without stalling timers", async (t) => {
  const ctx = await fixture(t);
  const originalRename = fsp.rename;
  let reachedRename;
  const reached = new Promise((resolve) => { reachedRename = resolve; });
  let releaseRename;
  const released = new Promise((resolve) => { releaseRename = resolve; });
  fsp.rename = async (...args) => {
    if (args[1] === ctx.storagePath) { reachedRename(); await released; }
    return originalRename(...args);
  };
  t.after(() => { releaseRename(); fsp.rename = originalRename; });
  const pending = post(ctx.listener.address().port, await ctx.signedOperation("admin-stall"));
  await reached;
  const previous = users.loadUsers()[0];
  let tickDelay = Infinity;
  const began = performance.now();
  const timer = setTimeout(() => { tickDelay = performance.now() - began; }, 20);
  t.after(() => clearTimeout(timer));
  try {
    assert.throws(() => users.saveUsers([{ ...previous, permissions: { upload: false } }]),
      { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    assert.throws(() => users.commitSyncResumeProof({ username: "alice" }),
      { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    const blockedMs = performance.now() - began;
    assert.ok(blockedMs < 200,
      `admin retryable fail-fast must not block the Node event loop (${blockedMs}ms)`);
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(tickDelay < 200, `heartbeat missed its bounded window (${tickDelay}ms)`);
  } finally {
    releaseRename();
  }
  assert.equal(await pending, 201);
  users.saveUsers([{ ...users.loadUsers()[0], permissions: { upload: false } }]);
  assert.equal(await post(ctx.listener.address().port, await ctx.signedOperation("admin-after")), 403);
});

test("audit and analytics SQLite writes during strict Sync do not stall the event loop; audit survives reopen", async (t) => {
  const ctx = await fixture(t);
  const originalRename = fsp.rename;
  let reachRename;
  let releaseRename;
  const reached = new Promise((resolve) => { reachRename = resolve; });
  const released = new Promise((resolve) => { releaseRename = resolve; });
  fsp.rename = async (...args) => {
    if (args[1] === ctx.storagePath) { reachRename(); await released; }
    return originalRename(...args);
  };
  t.after(() => { releaseRename(); fsp.rename = originalRename; });
  const pending = post(ctx.listener.address().port, await ctx.signedOperation("audit-analytics-stall"));
  await reached;
  const auditEvent = { id: crypto.randomUUID(), eventType: "file.access.denied",
    timestamp: new Date().toISOString(), actor: { username: "alice" },
    action: "read", result: "failure", details: { reason: "missing_viewAuditLogs" } };
  const began = performance.now();
  let timerDelay = Infinity;
  const timer = setTimeout(() => { timerDelay = performance.now() - began; }, 20);
  t.after(() => clearTimeout(timer));
  try {
    // Direct legacy whole-table writers must NOT enter the blocking 5s SQLite
    // busy wait. Server auditLog uses a durable sidecar for this one call.
    assert.throws(() => auditRepository.saveAuditLogs({ logs: [auditEvent] }),
      { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    assert.throws(() => analyticsRepository.saveAnalytics({ uploads: [{ id: "a1" }] }),
      { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    assert.equal(auditRepository.deferIfStrictSyncWriter(auditEvent), true,
      "the same fallback used by server appendAuditLog must persist a denied access");
    assert.ok(performance.now() - began < 200, "all three operations must return in less than 200 ms");
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(timerDelay < 200, "audit/analytics must not starve the event loop");
    assert.equal(auditRepository.loadAuditLogs().logs.filter((x) => x.id === auditEvent.id).length, 1,
      "durably deferred audit should remain readable during Sync");
  } finally {
    releaseRename();
  }
  assert.equal(await pending, 201);
  const once = auditRepository.loadAuditLogs().logs.filter((x) => x.id === auditEvent.id);
  assert.equal(once.length, 1);
  const readFromRestartedProcess = async () => {
    const script = "const rows=require(process.argv[1]).loadAuditLogs().logs;process.stdout.write(JSON.stringify(rows.filter(x=>x.id===process.argv[2])))";
    const { stdout } = await execFileAsync(process.execPath, ["-e", script,
      require.resolve("../repositories/auditRepository"), auditEvent.id],
    { timeout: 15000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
    return JSON.parse(stdout);
  };
  assert.equal((await readFromRestartedProcess()).length, 1,
    "a separate Node process can recover the durable pending audit after exit/restart");
  auditRepository.saveAuditLogs({ logs: once });
  assert.equal(auditRepository.loadAuditLogs().logs.filter((x) => x.id === auditEvent.id).length, 1,
    "audit must migrate to primary SQLite once without duplication");
  assert.equal((await readFromRestartedProcess()).length, 1,
    "consolidated audit remains durably visible exactly once across processes");
  assert.equal(auditRepository.deferIfStrictSyncWriter({ ...auditEvent, id: crypto.randomUUID() }), false,
    "noncontended and legacy audit paths must still use the original primary writer");
  assert.deepEqual(analyticsRepository.loadAnalytics().uploads, [],
    "a failed analytics replace must not mutate the analytics ledger");
  analyticsRepository.saveAnalytics({ uploads: [{ id: "event-after-fence", timestamp: new Date().toISOString() }] });
  assert.equal(analyticsRepository.loadAnalytics().uploads.length, 1,
    "analytics writes resume normally after protected Sync finishes");
});

test("other synchronous repository writers fail immediately under strict Sync rather than freeze event loop", async (t) => {
  const ctx = await fixture(t);
  const originalRename = fsp.rename;
  let reachedRename;
  const reached = new Promise((resolve) => { reachedRename = resolve; });
  let releaseRename;
  const released = new Promise((resolve) => { releaseRename = resolve; });
  fsp.rename = async (...args) => {
    if (args[1] === ctx.storagePath) { reachedRename(); await released; }
    return originalRename(...args);
  };
  t.after(() => { releaseRename(); fsp.rename = originalRename; });
  const pending = post(ctx.listener.address().port, await ctx.signedOperation("global-writers"));
  await reached;
  const writers = [
    ["actionHistory", () => actionHistoryRepository.saveActionHistory([])],
    ["folders", () => foldersRepository.saveFolders([])],
    ["pendingUploads", () => pendingUploadsRepository.savePendingUploads({})],
    ["publicLinks", () => publicLinksRepository.savePublicLinks({})],
    ["searchIndex", () => fileSearchIndexRepository.upsert("root", "test.txt")],
    ["ensureRootFolder", () => ensureRootFolder(getDb())],
  ];
  let tickDelay = Infinity;
  const before = performance.now();
  const timer = setTimeout(() => { tickDelay = performance.now() - before; }, 20);
  t.after(() => clearTimeout(timer));
  try {
    for (const [name, operation] of writers) {
      const start = performance.now();
      assert.throws(operation, { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" }, `${name} must fail-fast`);
      assert.ok(performance.now() - start < 200, `${name} blocked event loop`);
    }
    await new Promise((resolve) => setTimeout(resolve, 30));
    assert.ok(tickDelay < 200, `heartbeat delayed ${tickDelay}ms`);
  } finally { releaseRename(); }
  assert.equal(await pending, 201);
});

test("stale cross-process audit snapshot cannot delete already consolidated sidecar event", async (t) => {
  const ctx = await fixture(t);
  const stale = auditRepository.loadAuditLogs();
  const event = { id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    eventType: "user.deleted", action: "deleted", result: "success",
    actor: { username: "admin" }, details: { operation: "durable" } };
  const child = `const audit=require(process.argv[1]);const entry=JSON.parse(process.argv[2]);audit.deferAuditLog(entry);audit.saveAuditLogs(audit.loadAuditLogs());`;
  await execFileAsync(process.execPath, ["-e", child, require.resolve("../repositories/auditRepository"),
    JSON.stringify(event)], { timeout: 20000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
  assert.equal(auditRepository.loadAuditLogs().logs.filter((log) => log.id === event.id).length, 1);
  auditRepository.saveAuditLogs(stale);
  assert.equal(auditRepository.loadAuditLogs().logs.filter((log) => log.id === event.id).length, 1,
    "obsolete snapshot from another Node process must never erase an acknowledged audit event");
  auditRepository.archiveAuditLogs([event]);
  assert.equal(auditRepository.loadArchivedAuditLogs().logs.filter((log) => log.id === event.id).length, 1);
  assert.equal(auditRepository.loadAuditLogs().logs.filter((log) => log.id === event.id).length, 0,
    "archived IDs must never reappear in the active audit view");
  auditRepository.saveAuditLogs({ logs: [event] });
  auditRepository.archiveAuditLogs([event]);
  assert.equal(auditRepository.loadAuditLogs().logs.filter((log) => log.id === event.id).length, 0);
  assert.equal(auditRepository.loadArchivedAuditLogs().logs.filter((log) => log.id === event.id).length, 1,
    "archive must remain idempotent after stale writers and duplicate requests");
  const staleChild = `const a=require(process.argv[1]);a.saveAuditLogs({logs:[JSON.parse(process.argv[2])]})`;
  await execFileAsync(process.execPath, ["-e", staleChild, require.resolve("../repositories/auditRepository"),
    JSON.stringify(event)], { timeout: 20000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
  assert.equal(auditRepository.loadAuditLogs().logs.filter((log) => log.id === event.id).length, 0,
    "a second process must not resurrect a durably archived event");
});

test("abrupt process exit after durable audit sidecar commit still recovers exactly once", async (t) => {
  await fixture(t);
  const event = { id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    eventType: "user.updated", actor: { username: "admin" },
    action: "updated", result: "success" };
  const script = `const a=require(process.argv[1]);a.deferAuditLog(JSON.parse(process.argv[2]));process.exit(23)`;
  await assert.rejects(execFileAsync(process.execPath, ["-e", script,
    require.resolve("../repositories/auditRepository"), JSON.stringify(event)], {
    timeout: 15000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH },
  }), { code: 23 });
  assert.equal(auditRepository.loadAuditLogs().logs.filter(({ id }) => id === event.id).length, 1);
  auditRepository.saveAuditLogs(auditRepository.loadAuditLogs());
  assert.equal(auditRepository.loadAuditLogs().logs.filter(({ id }) => id === event.id).length, 1);
});

test("independent process cannot erase strict audit with absent or renamed sidecar", async (t) => {
  await fixture(t);
  const entry = { id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    eventType: "user.updated", actor: { username: "admin" },
    action: "updated", result: "success" };
  auditRepository.saveAuditLogs({ logs: [entry] });
  const sidecar = process.env.DATABASE_URL + ".audit-private";
  // Strict route registration must materialize the FULL durable journal
  // BEFORE enrolling the permanent main SQLite marker.
  assert.equal(fs.existsSync(path.join(sidecar, "pending.sqlite")), true);
  // A second process must NOT infer legacy mode from a removed/renamed file.
  const script = `const audit=require(process.argv[1]);audit.saveAuditLogs({logs:[]});`;
  const runPeer = async () => execFileAsync(process.execPath,
    ["-e", script, require.resolve("../repositories/auditRepository")],
    { timeout: 15000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
  await runPeer();
  assert.equal(auditRepository.loadAuditLogs().logs.filter(({ id }) => id === entry.id).length, 1,
    "another process cannot DELETE confirmed audit without a sidecar file");
  if (fs.existsSync(sidecar)) {
    const old = sidecar + "-renamed";
    fs.renameSync(sidecar, old);
    t.after(() => { if (fs.existsSync(old)) fs.renameSync(old, sidecar); });
    await assert.rejects(runPeer(), /Strict audit|missing|unavailable/);
    assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE id=?").get(entry.id).n, 1,
      "a missing enrolled sidecar must fail closed without erasing confirmed primary rows");
    assert.throws(() => auditRepository.loadAuditLogs(), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
  }
});

test("strict marker bounds an independent Node process's SQLite busy wait while another writer holds the lock", async (t) => {
  await fixture(t);
  const db = getDb();
  assert.equal(db.pragma("busy_timeout", { simple: true }), 25);
  db.exec("BEGIN IMMEDIATE");
  const script = `const t=require("node:perf_hooks").performance;const started=t.now();let code="OK";try{require(process.argv[1]).saveAnalytics({uploads:[{id:"crossprocess"}]})}catch(e){code=e.code||"UNKNOWN"}process.stdout.write(JSON.stringify({code,elapsed:t.now()-started}));`;
  let outcome;
  try {
    const { stdout } = await execFileAsync(process.execPath, ["-e", script,
      require.resolve("../repositories/analyticsRepository")],
    { timeout: 7000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
    outcome = JSON.parse(stdout);
  } finally { db.exec("ROLLBACK"); }
  assert.equal(outcome.code, "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE");
  assert.ok(outcome.elapsed < 500, `remote Node writer must not pause its event loop 5s (${outcome.elapsed}ms)`);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM analytics_events").get().n, 0);
});

test("strict restart in a second process rejects vanished pending audit journal without recreating it", async (t) => {
  const ctx = await fixture(t);
  const pending = { id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    eventType: "file.access.denied", action: "denied", result: "failure",
    actor: { username: "auditor" } };
  auditRepository.deferAuditLog(pending);
  const sidecarDir = process.env.DATABASE_URL + ".audit-private";
  const sidecarDb = path.join(sidecarDir, "pending.sqlite");
  assert.equal(fs.existsSync(sidecarDb), true);
  const moved = path.join(ctx.dir, "audit-sidecar-disconnected");
  fs.renameSync(sidecarDir, moved);
  assert.equal(fs.existsSync(sidecarDir), false);

  // This is a NEW Node process with an empty in-memory enrollment flag.
  // Before the fix, it silently CREATED a new empty sidecar and accepted
  // strict Sync even though the acknowledged pending audit event was missing.
  const restart = `const f=require(process.argv[1]);let accepted=false,code=null;
try{f.createSyncSqliteAccountWriteFence();accepted=true;}
catch(error){code=error.code||error.message;}
process.stdout.write(JSON.stringify({accepted,code}));`;
  const { stdout } = await execFileAsync(process.execPath, ["-e", restart,
    require.resolve("../src/services/syncSqliteAccountWriteFence")],
  { timeout: 15000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
  const outcome = JSON.parse(stdout);
  assert.equal(outcome.accepted, false, "a new process must not accept strict Sync when its existing audit journal vanished");
  assert.equal(outcome.code, "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE");
  assert.equal(fs.existsSync(sidecarDir), false,
    "strict restart must not create any replacement sidecar directory");
  assert.equal(getDb().prepare("SELECT mode FROM rootark_strict_sync_audit_mode WHERE id=1").get().mode,
    "append_only", "the main durable marker stays enrolled");
  const Database = require("better-sqlite3");
  const archive = new Database(path.join(moved, "pending.sqlite"), { fileMustExist: true, readonly: true });
  try {
    assert.equal(archive.prepare("SELECT COUNT(*) AS n FROM pending_audit WHERE id=?").get(pending.id).n, 1,
      "the original acknowledged audit event must survive in the disconnected journal");
  } finally { archive.close(); }
  // A second form of removal (only pending.sqlite, original directory still
  // present) must fail identically and leave no replacement DB.
  fs.renameSync(moved, sidecarDir);
  const orphan = path.join(ctx.dir, "original-pending-disconnected.sqlite");
  fs.renameSync(sidecarDb, orphan);
  const { stdout: secondOutput } = await execFileAsync(process.execPath, ["-e", restart,
    require.resolve("../src/services/syncSqliteAccountWriteFence")],
  { timeout: 15000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
  const second = JSON.parse(secondOutput);
  assert.equal(second.accepted, false, "missing pending.sqlite must not be replaced on restart");
  assert.equal(second.code, "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE");
  assert.equal(fs.existsSync(sidecarDb), false);
  // Restore the ORIGINAL acknowledged journal. A genuine restart must then
  // succeed, and the staged audit event must be visible exactly once.
  fs.renameSync(orphan, sidecarDb);
  const validRestart = `const f=require(process.argv[1]);const audit=require(process.argv[2]);
f.createSyncSqliteAccountWriteFence();
process.stdout.write(JSON.stringify(audit.loadAuditLogs().logs.filter(x=>x.id===process.argv[3]).length));`;
  const { stdout: recovered } = await execFileAsync(process.execPath, ["-e", validRestart,
    require.resolve("../src/services/syncSqliteAccountWriteFence"),
    require.resolve("../repositories/auditRepository"), pending.id],
  { timeout: 15000, env: { ...process.env, NODE_PATH: process.env.NODE_PATH } });
  assert.equal(JSON.parse(recovered), 1, "recovering original FULL journal must restore pending audit exactly once");
});

test("busy sidecar cleanup after main commit remains retryable without failing a committed audit event", async (t) => {
  await fixture(t);
  const event = { id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    eventType: "file.access.denied", action: "denied", result: "failure" };
  auditRepository.deferAuditLog(event);
  const sidecar = path.join(process.env.DATABASE_URL + ".audit-private", "pending.sqlite");
  const program = `const D=require(process.argv[1]);const db=new D(process.argv[2]);db.exec("BEGIN IMMEDIATE");process.stdout.write("LOCKED\\n");setTimeout(()=>{db.exec("ROLLBACK");db.close()},700)`;
  const child = spawn(process.execPath, ["-e", program, require.resolve("better-sqlite3"), sidecar],
    { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  const childEnded = new Promise((resolve) => child.once("exit", resolve));
  t.after(() => { if (child.exitCode === null) child.kill(); });
  await new Promise((resolve, reject) => {
    child.stdout.once("data", (data) => data.toString().includes("LOCKED") ? resolve() : reject(new Error("No sidecar lock")));
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`sidecar writer exited early ${code}`)));
  });
  // The main DB commits successfully; cleanup gets SQLITE_BUSY from another
  // process. It must retain the pending duplicate, not claim HTTP500.
  assert.doesNotThrow(() => auditRepository.saveAuditLogs({ logs: [event] }));
  assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE id=?").get(event.id).n, 1);
  await childEnded;
  assert.equal(auditRepository.loadAuditLogs().logs.filter(({ id }) => id === event.id).length, 1);
  auditRepository.saveAuditLogs({ logs: [event] });
  assert.equal(auditRepository.loadAuditLogs().logs.filter(({ id }) => id === event.id).length, 1);
});

test("strict archive physically prunes primary rows while preserving one durable archive and rejecting stale resurrection", async (t) => {
  await fixture(t);
  const event = { id: crypto.randomUUID(), timestamp: new Date().toISOString(),
    eventType: "file.deleted", action: "deleted", result: "success" };
  auditRepository.saveAuditLogs({ logs: [event] });
  assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE id=?").get(event.id).n, 1);
  auditRepository.archiveAuditLogs([event]);
  assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE id=?").get(event.id).n, 0,
    "archive must release primary SQLite rows after FULL-durable sidecar commit");
  auditRepository.saveAuditLogs({ logs: [event] });
  assert.equal(getDb().prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE id=?").get(event.id).n, 0);
  assert.equal(auditRepository.loadArchivedAuditLogs().logs.filter(({ id }) => id === event.id).length, 1);
});

test("unmarked SQLite preserves legacy whole-table audit replacement and 5000ms busy timeout", (t) => {
  const dir = isolatedDirectory();
  const old = Object.fromEntries(["DATABASE_URL", "DB_ENABLED", "DB_WRITE_LEGACY_JSON"]
    .map((key) => [key, process.env[key]]));
  closeDb();
  process.env.DATABASE_URL = path.join(dir, "legacy.sqlite");
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  t.after(() => {
    closeDb();
    for (const [key, value] of Object.entries(old)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  runMigrations({ backup: false });
  assert.equal(getDb().pragma("busy_timeout", { simple: true }), 5000);
  const entry = { id: crypto.randomUUID(), eventType: "file.access.denied" };
  auditRepository.saveAuditLogs({ logs: [entry] });
  auditRepository.saveAuditLogs({ logs: [] });
  assert.equal(auditRepository.loadAuditLogs().logs.length, 0);
});

test("once strict SQLite marker is observed, malformed or missing marker cannot restore legacy semantics", async (t) => {
  await fixture(t);
  const db = getDb();
  assert.equal(db.pragma("busy_timeout", { simple: true }), 25);
  db.exec("DROP TABLE rootark_strict_sync_audit_mode");
  assert.throws(() => getDb(), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
  closeDb();
  assert.throws(() => getDb(), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
});

test("strict audit sidecar rejects an existing Windows directory with an untrusted DACL", async (t) => {
  if (process.platform !== "win32") return t.skip("Windows ACL-specific security gate");
  const root = isolatedDirectory();
  const oldPath = process.env.DATABASE_URL;
  t.after(() => {
    closeDb();
    if (oldPath === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = oldPath;
    fs.rmSync(root, { recursive: true, force: true });
  });
  closeDb();
  const dbPath = path.join(root, "untrusted-accounts.sqlite");
  process.env.DATABASE_URL = dbPath;
  getDb(); // No strict marker exists in this unrelated disposable database.
  const unsafeDir = dbPath + ".audit-private";
  fs.mkdirSync(unsafeDir);
  await execFileAsync("icacls.exe", [unsafeDir, "/grant", "*S-1-5-32-545:(OI)(CI)M"]);
  assert.throws(() => auditRepository.preparePendingAuditJournal(),
    /Windows chunk staging ACL validation failed|Untrusted principal|Unsafe/);
  assert.equal(fs.existsSync(path.join(unsafeDir, "pending.sqlite")), false);

  // A directory can be restricted while an existing SQLite WAL/SHM or DB
  // file carries an unsafe explicit ACE. Verify its descendants as well.
  const nextDb = path.join(root, "unsafe-wal.sqlite");
  closeDb();
  process.env.DATABASE_URL = nextDb;
  getDb(); // Ensure process-local marker state follows this separate authority.
  const safeDir = nextDb + ".audit-private";
  ensureWindowsChunkUploadRoot(safeDir);
  const unsafeWal = path.join(safeDir, "pending.sqlite-wal");
  fs.writeFileSync(unsafeWal, "");
  await execFileAsync("icacls.exe", [unsafeWal, "/grant", "*S-1-5-32-545:M"]);
  assert.throws(() => auditRepository.preparePendingAuditJournal(),
    /Windows chunk staging ACL validation failed|Untrusted principal|Unsafe/);
});

test("busy external audit sidecar writer fails promptly without corrupting earlier accepted records", async (t) => {
  const ctx = await fixture(t);
  const id = crypto.randomUUID();
  const log = { id, eventType: "file.access.denied", timestamp: new Date().toISOString() };
  auditRepository.deferAuditLog(log);
  const sidecar = path.join(process.env.DATABASE_URL + ".audit-private", "pending.sqlite");
  const program = `const D=require(process.argv[1]);const db=new D(process.argv[2]);db.exec('BEGIN IMMEDIATE');process.stdout.write('HELD\\n');setTimeout(()=>{db.exec('ROLLBACK');db.close()},800);`;
  const child = spawn(process.execPath, ["-e", program, require.resolve("better-sqlite3"), sidecar],
    { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  await new Promise((resolve, reject) => {
    child.stdout.once("data", (data) => data.toString().includes("HELD") ? resolve() : reject(new Error("No writer lock")));
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`writer ended early: ${code}`)));
  });
  const start = performance.now();
  let actualError;
  try { auditRepository.deferAuditLog({ ...log, id: crypto.randomUUID() }); }
  catch (error) { actualError = error; }
  const delay = performance.now() - start;
  assert.equal(actualError?.code, "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    `busy journal writer should map to unavailable; observed ${actualError?.code}`);
  assert.ok(delay < 1500, `sidecar SQLite writer retry must have a strict short bound (${delay} ms)`);
  await new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    child.once("exit", resolve);
  });
  assert.equal(auditRepository.loadAuditLogs().logs.filter((entry) => entry.id === id).length, 1);
});

test("strict malformed archived_audit fails closed through actual server audit loader instead of empty fallback", async (t) => {
  await fixture(t);
  const pending = { id: crypto.randomUUID(), eventType: "file.access.denied",
    timestamp: new Date().toISOString(), action: "denied", result: "failure" };
  auditRepository.deferAuditLog(pending);
  const sidecar = path.join(process.env.DATABASE_URL + ".audit-private", "pending.sqlite");
  const sqlite = new (require("better-sqlite3"))(sidecar);
  try {
    sqlite.exec("DROP TABLE archived_audit; CREATE TABLE archived_audit (wrong_column TEXT NOT NULL)");
  } finally { sqlite.close(); }

  assert.throws(() => auditRepository.loadAuditLogs(),
    { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" },
    "valid pending evidence cannot be ignored when archive schema is corrupt");
  assert.throws(() => auditRepository.loadArchivedAuditLogs(),
    { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });

  // Execute the real server.js loadAuditLogs function without starting its
  // singleton server/background maintenance; it must propagate 503-class
  // errors instead of returning getDefaultAuditLogs/JSON fallbacks.
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  const start = source.indexOf("function loadAuditLogs(file = AUDIT_LOGS_FILE) {");
  const end = source.indexOf("\nfunction saveAuditLogs(", start);
  assert.ok(start > 0 && end > start, "server audit loader must be located");
  const auditLogsFile = path.join(process.env.DATABASE_URL + ".legacy-audit.json");
  fs.writeFileSync(auditLogsFile, JSON.stringify({ logs: [{ id: "FABRICATED_JSON_FALLBACK" }] }));
  const load = vm.runInNewContext(source.slice(start, end) + "\nloadAuditLogs;", {
    AUDIT_LOGS_FILE: auditLogsFile,
    AUDIT_ARCHIVE_FILE: auditLogsFile + ".archive",
    dbConfig: require("../db"),
    auditRepository, fs,
    shouldUseDatabase: () => true,
    shouldReadJsonFallback: () => true,
    getDefaultAuditLogs: () => ({ logs: [{ id: "FABRICATED_EMPTY_FALLBACK" }] }),
    console,
  });
  assert.throws(() => load(), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" },
    "server loader must not invent audit contents or return legacy JSON on strict integrity failure");

  // Exercise actual audit router + production error middleware over HTTP.
  // Authentication is supplied by this isolated disposable fixture; no
  // production session or server.js timers are started.
  const api = express();
  require("../src/routes/audit")(api, {
    authenticate: (_req, _res, next) => next(),
    requireAuditAccess: (_req, _res, next) => next(),
    getFilteredAuditLogs: () => load().logs,
  });
  const errorStart = source.lastIndexOf("app.use((error, _req, res, next) => {");
  const errorEnd = source.indexOf("\n});", errorStart);
  assert.ok(errorStart > 0 && errorEnd > errorStart, "production HTTP 503 middleware must exist");
  vm.runInNewContext(source.slice(errorStart, errorEnd + 4), { app: api });
  const listener = await new Promise((resolve) => {
    const server = api.listen(0, "127.0.0.1", () => resolve(server));
  });
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const response = await new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port: listener.address().port, path: "/audit/logs" }, (res) => {
      let body = "";
      res.on("data", (part) => { body += part; });
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    }).on("error", reject);
  });
  assert.equal(response.status, 503, "broken audit journal must return HTTP 503 instead of fabricated 200");
  assert.equal(JSON.parse(response.body).code, "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE");
  assert.equal(response.headers["retry-after"], "1");
});

test("strict main audit SQL schema faults fail closed on read and write; legacy stays unmarked", async (t) => {
  await fixture(t);
  const db = getDb();
  db.exec("ALTER TABLE audit_logs RENAME TO audit_logs_damaged");
  assert.throws(() => auditRepository.loadAuditLogs(), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
  assert.throws(() => auditRepository.saveAuditLogs({ logs: [] }),
    { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
  assert.equal(db.prepare("SELECT mode FROM rootark_strict_sync_audit_mode WHERE id=1").get().mode,
    "append_only", "a failed audit SQL operation cannot downgrade the enrolled strict marker");
});

test("strict empty audit view never substitutes stale JSON when JSON fallback is configured", async (t) => {
  await fixture(t);
  const auditFile = path.join(process.env.DATABASE_URL + ".legacy-audit.json");
  fs.writeFileSync(auditFile, JSON.stringify({ logs: [
    { id: "FABRICATED_STALE_JSON_AUDIT", eventType: "auth.login.failed" },
  ] }));
  const source = fs.readFileSync(path.join(__dirname, "..", "server.js"), "utf8");
  const start = source.indexOf("function loadAuditLogs(file = AUDIT_LOGS_FILE) {");
  const end = source.indexOf("\nfunction saveAuditLogs(", start);
  const load = vm.runInNewContext(source.slice(start, end) + "\nloadAuditLogs;", {
    AUDIT_LOGS_FILE: auditFile, AUDIT_ARCHIVE_FILE: auditFile + ".archive",
    auditRepository, dbConfig: require("../db"), fs, console,
    shouldUseDatabase: () => true, shouldReadJsonFallback: () => true,
    getDefaultAuditLogs: () => ({ logs: [] }),
  });
  assert.deepEqual(Array.from(load().logs), [],
    "durably enrolled strict audit must not accept a fabricated legacy JSON log when active table is empty");
});

test("strict sidecar SQLite BUSY during load maps to explicit retryable 503-class unavailable", async (t) => {
  await fixture(t);
  const pending = { id: crypto.randomUUID(), eventType: "file.access.denied",
    timestamp: new Date().toISOString(), action: "denied", result: "failure" };
  auditRepository.deferAuditLog(pending);
  const sidecar = path.join(process.env.DATABASE_URL + ".audit-private", "pending.sqlite");
  const program = `const D=require(process.argv[1]);const db=new D(process.argv[2]);db.pragma("locking_mode = EXCLUSIVE");db.exec("BEGIN EXCLUSIVE");process.stdout.write("HELD\\n");setTimeout(()=>{db.exec("ROLLBACK");db.close()},1200)`;
  const child = spawn(process.execPath, ["-e", program, require.resolve("better-sqlite3"), sidecar],
    { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  const childEnded = new Promise((resolve) => child.once("exit", resolve));
  await new Promise((resolve, reject) => {
    child.stdout.once("data", (data) => data.toString().includes("HELD") ? resolve() : reject(new Error("Writer lock not held")));
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`Writer lock ended early ${code}`)));
  });
  try {
    const began = performance.now();
    assert.throws(() => auditRepository.loadAuditLogs(), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    assert.ok(performance.now() - began < 1000, "read must not synchronously stall for 5 seconds");
  } finally {
    await childEnded;
  }
  assert.equal(auditRepository.loadAuditLogs().logs.filter(({ id }) => id === pending.id).length, 1);
});

test("strict REST rejects a missing SQLite authority or concurrent legacy JSON account writes at setup", (t) => {
  const previousDb = process.env.DB_ENABLED;
  const previousLegacy = process.env.DB_WRITE_LEGACY_JSON;
  t.after(() => {
    if (previousDb === undefined) delete process.env.DB_ENABLED;
    else process.env.DB_ENABLED = previousDb;
    if (previousLegacy === undefined) delete process.env.DB_WRITE_LEGACY_JSON;
    else process.env.DB_WRITE_LEGACY_JSON = previousLegacy;
  });
  const options = {
    app: express(), atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (_req, _res, next) => next(),
    requirePermission: () => (_req, _res, next) => next(),
  };
  process.env.DB_ENABLED = "false";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  assert.throws(() => registerSyncRoutes(options), { code: "SYNC_ATOMIC_DEVICE_CONFIGURATION" });
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "true";
  assert.throws(() => registerSyncRoutes(options), { code: "SYNC_ATOMIC_DEVICE_CONFIGURATION" });
});
