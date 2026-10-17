"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { DEFAULT_MAX_DESTRUCTIVE, DEFAULT_WINDOW_MS, createSyncBurstGuard } = require("../src/services/syncBurstGuard");

// ---- unit tests of the metadata-only guard ----

test("issue 67 guard: defaults and env overrides", () => {
  const defaults = createSyncBurstGuard({ env: {} });
  assert.equal(defaults.config.maxDestructive, 200);
  assert.equal(defaults.config.windowMs, 600000);
  assert.equal(DEFAULT_MAX_DESTRUCTIVE, 200);
  assert.equal(DEFAULT_WINDOW_MS, 600000);
  const fromEnv = createSyncBurstGuard({ env: { SYNC_BURST_MAX_DESTRUCTIVE: "5", SYNC_BURST_WINDOW_MS: "1000" } });
  assert.equal(fromEnv.config.maxDestructive, 5);
  assert.equal(fromEnv.config.windowMs, 1000);
  const invalid = createSyncBurstGuard({ env: { SYNC_BURST_MAX_DESTRUCTIVE: "-3", SYNC_BURST_WINDOW_MS: "abc" } });
  assert.equal(invalid.config.maxDestructive, 200);
  assert.equal(invalid.config.windowMs, 600000);
});

test("issue 67 guard: trips on the operation after the limit inside the window", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 3, windowMs: 1000, env: {} });
  assert.equal(guard.recordDestructive("alice", "dev", 0).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", 1).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", 2).exceeded, false);
  const tripped = guard.recordDestructive("alice", "dev", 3);
  assert.equal(tripped.exceeded, true);
  assert.equal(tripped.limit, 3);
});

test("issue 67 guard: old entries leave the sliding window", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 2, windowMs: 100, env: {} });
  guard.recordDestructive("alice", "dev", 0);
  guard.recordDestructive("alice", "dev", 10);
  // At t=200 the first two entries are outside (100, 200], so a new burst starts fresh.
  assert.equal(guard.recordDestructive("alice", "dev", 200).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", 201).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", 202).exceeded, true);
});

test("issue 67 guard: counters are isolated per user and per device", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 1, windowMs: 1000, env: {} });
  guard.recordDestructive("alice", "dev-a", 0);
  assert.equal(guard.recordDestructive("alice", "dev-b", 1).exceeded, false);
  assert.equal(guard.recordDestructive("bob", "dev-a", 2).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev-a", 3).exceeded, true);
});

test("issue 67 guard: reset clears a device counter and memory stays bounded", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 2, windowMs: 1000, maxKeys: 4, env: {} });
  for (let i = 0; i < 50; i += 1) guard.recordDestructive("alice", "dev", i);
  assert.equal(guard.recordDestructive("alice", "dev", 50).exceeded, true);
  guard.reset("alice", "dev");
  assert.equal(guard.recordDestructive("alice", "dev", 51).exceeded, false);
  for (let i = 0; i < 100; i += 1) guard.recordDestructive(`user-${i}`, "dev", 60);
  assert.ok(guard.trackedKeys() <= 4);
});

// ---- route-level tests through the real sync router ----

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve({ status: res.statusCode, body: text ? JSON.parse(text) : null });
      });
    });
    req.once("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function jsonRequest(port, requestPath, method, value) {
  const body = value === undefined ? undefined : Buffer.from(JSON.stringify(value));
  const headers = { "content-type": "application/json" };
  if (body) headers["content-length"] = body.length;
  return request(port, requestPath, { method, headers, body });
}

const PASSWORD = "correct-horse-battery";
const bcrypt = require("bcryptjs");
const ALICE_HASH = bcrypt.hashSync(PASSWORD, 4);

function resumeRequest(port, body = { password: PASSWORD }) {
  return jsonRequest(port, "/sync/v1/devices/device-a/resume", "POST", body);
}

async function startServer(t, { storagePath, burstGuard, auditEvents = [], bcryptImpl = bcrypt }) {
  const app = express();
  app.use("/sync/v1", express.json({ limit: "9mb" }));
  const authenticate = (req, _res, next) => { req.user = { username: "alice", role: "user" }; next(); };
  const requirePermission = () => (_req, _res, next) => next();
  const auditLog = (eventType, actor, target, action, result, details) => auditEvents.push({ eventType, actor, target, action, result, details });
  const loadUsers = () => [{ username: "alice", password: ALICE_HASH }];
  const route = registerSyncRoutes({ app, authenticate, requirePermission, storagePath, burstGuard, auditLog, bcrypt: bcryptImpl, loadUsers });
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); });
  await route.ready;
  return { port: server.address().port, route };
}

function createFor(index, fileKey) {
  return protocol.createOperation({
    operation: "create", objectId: `object-${index}`, fileId: `file-${index}`, versionId: `version-${index}-1`,
    operationId: `create-${index}`, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: `f${index}.txt`, name: `f${index}.txt`, size: 4 },
    plaintext: Buffer.from("data"), fileKey,
  });
}

function deleteFor(index, created, fileKey, deviceId = "device-a") {
  return protocol.createOperation({
    operation: "delete", objectId: `object-${index}`, fileId: `file-${index}`, versionId: `version-${index}-2`,
    operationId: `delete-${index}-${deviceId}`, deviceId, keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: created.revision, metadata: { path: `f${index}.txt` }, fileKey,
  });
}

test("issue 67 route: destructive burst pauses the device with 423 while reads and creates keep working", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-route-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const storagePath = path.join(dir, "objects.json");
  const auditEvents = [];
  const burstGuard = createSyncBurstGuard({ maxDestructive: 2, windowMs: 600000, env: {} });
  const { port } = await startServer(t, { storagePath, burstGuard, auditEvents });
  const key = crypto.randomBytes(32);

  const created = [1, 2, 3, 4, 5].map((index) => createFor(index, key));
  for (const operation of created) assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", operation)).status, 201);

  // Two destructive operations are inside the limit.
  for (const index of [1, 2]) {
    const deleted = await jsonRequest(port, `/sync/v1/objects/object-${index}`, "DELETE", deleteFor(index, created[index - 1], key));
    assert.equal(deleted.status, 200);
  }
  // The third destructive operation trips the pause and is not applied.
  const tripped = await jsonRequest(port, "/sync/v1/objects/object-3", "DELETE", deleteFor(3, created[2], key));
  assert.equal(tripped.status, 423);
  assert.equal(tripped.body.error, "sync_burst_paused");
  assert.equal(tripped.body.code, "sync_burst_paused");
  assert.equal(auditEvents.length, 1);
  assert.equal(auditEvents[0].eventType, "sync.burst.paused");
  assert.equal(auditEvents[0].target.id, "device-a");
  assert.equal(JSON.stringify(auditEvents[0]).includes("data"), false);

  // Further destructive operations from the paused device are rejected.
  assert.equal((await jsonRequest(port, "/sync/v1/objects/object-4", "DELETE", deleteFor(4, created[3], key))).status, 423);
  // Reads and non-destructive writes still work.
  assert.equal((await request(port, "/sync/v1/objects/object-4", { method: "GET" })).status, 200);
  assert.equal((await request(port, "/sync/v1/objects", { method: "GET" })).status, 200);
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", createFor(6, key))).status, 201);
  // Object-3 was not deleted by the rejected operation.
  assert.equal((await request(port, "/sync/v1/objects/object-3", { method: "GET" })).status, 200);

  // Another device of the same user is not paused.
  assert.equal((await jsonRequest(port, "/sync/v1/objects/object-4", "DELETE", deleteFor(4, created[3], key, "device-b"))).status, 200);
});

test("issue 67 route: pause survives restart and resume lifts it without touching data", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-resume-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const storagePath = path.join(dir, "objects.json");
  const key = crypto.randomBytes(32);
  const auditEvents = [];
  const created = [1, 2, 3].map((index) => createFor(index, key));
  {
    const { port } = await startServer(t, { storagePath, burstGuard: createSyncBurstGuard({ maxDestructive: 1, windowMs: 600000, env: {} }), auditEvents });
    for (const operation of created) assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", operation)).status, 201);
    assert.equal((await jsonRequest(port, "/sync/v1/objects/object-1", "DELETE", deleteFor(1, created[0], key))).status, 200);
    assert.equal((await jsonRequest(port, "/sync/v1/objects/object-2", "DELETE", deleteFor(2, created[1], key))).status, 423);
  }
  // Restart with a fresh in-memory guard: the persisted pause must still block.
  const restarted = await startServer(t, { storagePath, burstGuard: createSyncBurstGuard({ maxDestructive: 100, windowMs: 600000, env: {} }), auditEvents });
  assert.equal((await jsonRequest(restarted.port, "/sync/v1/objects/object-3", "DELETE", deleteFor(3, created[2], key))).status, 423);
  assert.equal((await request(restarted.port, "/sync/v1/objects/object-2", { method: "GET" })).status, 200);

  // Resume needs re-authentication and leaves current data untouched.
  const resumed = await resumeRequest(restarted.port);
  assert.equal(resumed.status, 200);
  assert.equal(resumed.body.paused, false);
  assert.equal(resumed.body.wasPaused, true);
  assert.equal(auditEvents.some((event) => event.eventType === "sync.device.resumed"), true);
  assert.equal((await request(restarted.port, "/sync/v1/objects/object-2", { method: "GET" })).status, 200);
  // Resume is idempotent.
  assert.equal((await resumeRequest(restarted.port)).body.wasPaused, false);
  // After resume the device can perform destructive operations again.
  assert.equal((await jsonRequest(restarted.port, "/sync/v1/objects/object-3", "DELETE", deleteFor(3, created[2], key))).status, 200);
});

test("issue 67 resume: re-authentication is required and the paused device cannot resume itself", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-reauth-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const storagePath = path.join(dir, "objects.json");
  const key = crypto.randomBytes(32);
  const auditEvents = [];
  const created = [1, 2].map((index) => createFor(index, key));
  const { port } = await startServer(t, { storagePath, burstGuard: createSyncBurstGuard({ maxDestructive: 1, windowMs: 600000, env: {} }), auditEvents });
  for (const operation of created) assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", operation)).status, 201);
  assert.equal((await jsonRequest(port, "/sync/v1/objects/object-1", "DELETE", deleteFor(1, created[0], key))).status, 200);
  assert.equal((await jsonRequest(port, "/sync/v1/objects/object-2", "DELETE", deleteFor(2, created[1], key))).status, 423);

  // Missing password is a client error and does not change the pause.
  assert.equal((await resumeRequest(port, {})).status, 400);
  // Wrong password is rejected.
  const wrong = await resumeRequest(port, { password: "not-the-password" });
  assert.equal(wrong.status, 401);
  // The paused device cannot resume itself, even with the correct password.
  const self = await resumeRequest(port, { password: PASSWORD, deviceId: "device-a" });
  assert.equal(self.status, 403);
  assert.equal((await jsonRequest(port, "/sync/v1/objects/object-2", "DELETE", deleteFor(2, created[1], key))).status, 423);
  // Correct password from another context (a different device identifies itself) succeeds.
  const other = await resumeRequest(port, { password: PASSWORD, deviceId: "device-b" });
  assert.equal(other.status, 200);
  assert.equal(other.body.wasPaused, true);
  assert.equal((await jsonRequest(port, "/sync/v1/objects/object-2", "DELETE", deleteFor(2, created[1], key))).status, 200);
  assert.ok(auditEvents.some((event) => event.eventType === "sync.device.resume.failed"));
});

test("issue 67 resume: five wrong passwords in 15 minutes lock resume for the user", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-limit-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const { port } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ env: {} }) });
  for (let i = 0; i < 5; i += 1) assert.equal((await resumeRequest(port, { password: "wrong" })).status, 401);
  const limited = await resumeRequest(port, { password: PASSWORD });
  assert.equal(limited.status, 429);
});

test("issue 67 resume: parallel wrong passwords start at most five password checks", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-race-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  let checks = 0;
  const countingBcrypt = { compare: async (...args) => { checks += 1; return bcrypt.compare(...args); } };
  const { port } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ env: {} }), bcryptImpl: countingBcrypt });
  const responses = await Promise.all(Array.from({ length: 20 }, () => resumeRequest(port, { password: "wrong" })));
  const statuses = responses.map((response) => response.status);
  assert.equal(statuses.filter((status) => status === 401).length, 5);
  assert.equal(statuses.filter((status) => status === 429).length, 15);
  assert.equal(checks, 5);
  // The lockout also holds for the correct password after the burst.
  assert.equal((await resumeRequest(port, { password: PASSWORD })).status, 429);
});

test("issue 67 store: a paused device is blocked at the store boundary and history is not trimmed by rejected operations", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-store-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const storagePath = path.join(dir, "objects.json");
  const store = await new SyncObjectStore(storagePath, { burstGuard: createSyncBurstGuard({ maxDestructive: 1, windowMs: 600000, env: {} }) }).open();
  const key = crypto.randomBytes(32);
  const created = createFor(1, key);
  assert.equal((await store.put("alice", created)).kind, "stored");
  const update = protocol.createOperation({
    operation: "update", objectId: "object-1", fileId: "file-1", versionId: "version-1-2", operationId: "update-1",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 2, deviceId: "device-a" },
    baseRevision: created.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from("more"), fileKey: key,
  });
  assert.equal((await store.put("alice", update)).kind, "stored");
  const historyBefore = store.history("alice", "object-1").length;
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: "object-1", fileId: "file-1", versionId: "version-1-4", operationId: "delete-1",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 3, deviceId: "device-a" },
    baseRevision: update.revision, metadata: { path: "f1.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "paused");
  assert.equal(store.isDevicePaused("alice", "device-a"), true);
  const rejected = protocol.createOperation({
    operation: "update", objectId: "object-1", fileId: "file-1", versionId: "version-1-3", operationId: "update-2",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 3, deviceId: "device-a" },
    baseRevision: update.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from("x"), fileKey: key,
  });
  assert.equal((await store.put("alice", rejected)).kind, "paused");
  assert.equal(store.history("alice", "object-1").length, historyBefore);
});
