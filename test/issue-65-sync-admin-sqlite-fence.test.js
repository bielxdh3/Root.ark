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
