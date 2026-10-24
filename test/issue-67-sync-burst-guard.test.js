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
  assert.equal(guard.recordDestructive("alice", "dev", null, 0).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", null, 1).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", null, 2).exceeded, false);
  const tripped = guard.recordDestructive("alice", "dev", null, 3);
  assert.equal(tripped.exceeded, true);
  assert.equal(tripped.limit, 3);
});

test("issue 67 guard: old entries leave the sliding window", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 2, windowMs: 100, env: {} });
  guard.recordDestructive("alice", "dev", null, 0);
  guard.recordDestructive("alice", "dev", null, 10);
  // At t=200 the first two entries are outside (100, 200], so a new burst starts fresh.
  assert.equal(guard.recordDestructive("alice", "dev", null, 200).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", null, 201).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev", null, 202).exceeded, true);
});

test("issue 67 guard: counters are isolated per user and per device", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 1, windowMs: 1000, env: {} });
  guard.recordDestructive("alice", "dev-a", null, 0);
  assert.equal(guard.recordDestructive("alice", "dev-b", null, 1).exceeded, false);
  assert.equal(guard.recordDestructive("bob", "dev-a", null, 2).exceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev-a", null, 3).exceeded, true);
});

test("issue 67 guard: reset clears a device counter and memory stays bounded", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 2, windowMs: 1000, maxKeys: 4, env: {} });
  for (let i = 0; i < 50; i += 1) guard.recordDestructive("alice", "dev", null, i);
  assert.equal(guard.recordDestructive("alice", "dev", null, 50).exceeded, true);
  guard.reset("alice", "dev");
  assert.equal(guard.recordDestructive("alice", "dev", null, 51).exceeded, false);
  for (let i = 0; i < 100; i += 1) guard.recordDestructive(`user-${i}`, "dev", null, 60);
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
const { encryptSecret, generateRecoveryCodes, generateSecret, hotp } = require("../src/services/totp");
const ALICE_HASH = bcrypt.hashSync(PASSWORD, 4);

function resumeRequest(port, body = { password: PASSWORD }) {
  return jsonRequest(port, "/sync/v1/devices/device-a/resume", "POST", body);
}

// Builds a 2FA account: encrypted seed plus two single-use recovery codes.
function twoFactorAccount() {
  const secret = generateSecret();
  const recovery = generateRecoveryCodes(2);
  const user = {
    username: "alice", password: ALICE_HASH, totpEnabled: true, sessionVersion: 0,
    totpSecret: encryptSecret(secret, TEST_TOTP_KEY, "Root.ark/TOTP/alice"),
    totpRecoveryHashes: recovery.hashes, totpLastUsedStep: null,
  };
  return { users: [user], secret, recoveryCodes: recovery.codes };
}

function codeAt(secret, stepOffset = 0) {
  return hotp(secret, Math.floor(Date.now() / 1000 / 30) + stepOffset);
}

// Pauses device-a: with a per-device limit of 1, the second delete of a fresh pair trips the pause.
async function pauseDeviceA(port, key, first, second) {
  const a = createFor(first, key);
  const b = createFor(second, key);
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", a)).status, 201);
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", b)).status, 201);
  assert.equal((await jsonRequest(port, `/sync/v1/objects/object-${first}`, "DELETE", deleteFor(first, a, key))).status, 200);
  assert.equal((await jsonRequest(port, `/sync/v1/objects/object-${second}`, "DELETE", deleteFor(second, b, key))).status, 423);
}

const TEST_TOTP_KEY = crypto.randomBytes(32);

// Account state persists through load/save like the users file does, so replay state and consumed
// recovery codes are real. Each load returns a fresh copy.
async function startServer(t, { storagePath, burstGuard, auditEvents = [], bcryptImpl = bcrypt, accountUsers = null, totpKey = TEST_TOTP_KEY }) {
  const accountState = { users: accountUsers || [{ username: "alice", password: ALICE_HASH }] };
  const app = express();
  app.use("/sync/v1", express.json({ limit: "9mb" }));
  const authenticate = (req, _res, next) => { req.user = { username: "alice", role: "user" }; next(); };
  const requirePermission = () => (_req, _res, next) => next();
  const auditLog = (eventType, actor, target, action, result, details) => auditEvents.push({ eventType, actor, target, action, result, details });
  const loadUsers = () => JSON.parse(JSON.stringify(accountState.users));
  const saveUsers = (users) => { accountState.users = JSON.parse(JSON.stringify(users)); };
  const getTotpKey = () => totpKey;
  const route = registerSyncRoutes({ app, authenticate, requirePermission, storagePath, burstGuard, auditLog, bcrypt: bcryptImpl, loadUsers, saveUsers, getTotpKey });
  route.accountState = accountState;
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

test("issue 67 guard: repeated overwrites of one object trip the per-object limit before the device total", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 200, maxPerObject: 16, windowMs: 600000, env: {} });
  let last = null;
  for (let i = 0; i < 16; i += 1) last = guard.recordDestructive("alice", "dev", "object-1", i);
  assert.equal(last.objectExceeded, false);
  last = guard.recordDestructive("alice", "dev", "object-1", 16);
  assert.equal(last.exceeded, true);
  assert.equal(last.objectExceeded, true);
  assert.equal(last.deviceExceeded, false);
});

test("issue 67 guard: reset clears per-object counters for that device only", () => {
  const guard = createSyncBurstGuard({ maxDestructive: 200, maxPerObject: 2, windowMs: 600000, env: {} });
  for (let i = 0; i < 3; i += 1) guard.recordDestructive("alice", "dev-a", "object-1", i);
  for (let i = 0; i < 2; i += 1) guard.recordDestructive("alice", "dev-b", "object-1", i);
  guard.reset("alice", "dev-a");
  assert.equal(guard.recordDestructive("alice", "dev-a", "object-1", 10).objectExceeded, false);
  assert.equal(guard.recordDestructive("alice", "dev-b", "object-1", 10).objectExceeded, true);
});

test("issue 67 route: after a per-object pause and password resume the next overwrite of that object succeeds", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-object-resume-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const { port } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ env: {} }) });
  const key = crypto.randomBytes(32);
  const created = createFor(1, key);
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", created)).status, 201);
  let previous = created;
  const update = (counter) => protocol.createOperation({
    operation: "update", objectId: "object-1", fileId: "file-1", versionId: `version-1-${counter}`, operationId: `update-${counter}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-a" },
    baseRevision: previous.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from(`v${counter}`), fileKey: key,
  });
  for (let counter = 2; counter <= 17; counter += 1) {
    const operation = update(counter);
    assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", operation)).status, 201);
    previous = operation;
  }
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", update(18))).status, 423);
  assert.equal((await resumeRequest(port)).status, 200);
  // The next normal overwrite of the same object is not refused by the pre-resume per-object counter.
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", update(18))).status, 201);
});

test("issue 67 store: 40 edits within the retention window keep the first version and history at the cap", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-anchor-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const clock = 1700000000000;
  const store = await new SyncObjectStore(path.join(dir, "objects.json"), {
    burstGuard: createSyncBurstGuard({ maxDestructive: 100000, maxPerObject: 100000, env: {} }),
    retentionMs: 24 * 60 * 60 * 1000,
    now: () => clock,
  }).open();
  const key = crypto.randomBytes(32);
  const created = createFor(1, key);
  assert.equal((await store.put("alice", created)).kind, "stored");
  let previous = created;
  for (let counter = 2; counter <= 41; counter += 1) {
    const update = protocol.createOperation({
      operation: "update", objectId: "object-1", fileId: "file-1", versionId: `version-1-${counter}`, operationId: `update-${counter}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-a" },
      baseRevision: previous.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from(`v${counter}`), fileKey: key,
    });
    assert.equal((await store.put("alice", update)).kind, "stored");
    previous = update;
  }
  const history = store.history("alice", "object-1");
  assert.equal(history.length, 32);
  assert.equal(history[0].versionId, created.versionId);
  assert.equal(history[history.length - 1].versionId, previous.versionId);
});

test("issue 67 route: rapid overwrites of one object pause the device before the pre-attack version is pruned", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-object-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const { port, route } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ env: {} }) });
  const key = crypto.randomBytes(32);
  const created = createFor(1, key);
  assert.equal((await jsonRequest(port, "/sync/v1/objects", "POST", created)).status, 201);
  let previous = created;
  const statuses = [];
  for (let counter = 2; counter <= 101; counter += 1) {
    const update = protocol.createOperation({
      operation: "update", objectId: "object-1", fileId: "file-1", versionId: `version-1-${counter}`, operationId: `update-${counter}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-a" },
      baseRevision: previous.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from(`v${counter}`), fileKey: key,
    });
    const response = await jsonRequest(port, "/sync/v1/objects", "POST", update);
    statuses.push(response.status);
    if (response.status === 201) previous = update;
  }
  // 16 overwrites are accepted; the 17th trips the per-object pause and every later attempt is refused.
  assert.equal(statuses.filter((status) => status === 201).length, 16);
  assert.equal(statuses[16], 423);
  assert.ok(statuses.slice(16).every((status) => status === 423));
  // The pre-attack version is still retained with its ciphertext and crypto metadata; history stays within cap + 1.
  const history = route.store.history("alice", "object-1");
  assert.ok(history.length <= 33);
  assert.equal(history[0].versionId, created.versionId);
  assert.equal(history[0].ciphertext, created.ciphertext);
  assert.equal(history[0].nonce, created.nonce);
  assert.equal(history[0].tag, created.tag);
});

test("issue 67 store: pre-window checkpoint survives pruning and history stays bounded", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-checkpoint-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  let clock = 1700000000000;
  const store = await new SyncObjectStore(path.join(dir, "objects.json"), {
    burstGuard: createSyncBurstGuard({ maxDestructive: 100000, maxPerObject: 100000, env: {} }),
    retentionMs: 24 * 60 * 60 * 1000,
    now: () => clock,
  }).open();
  const key = crypto.randomBytes(32);
  const created = createFor(1, key);
  assert.equal((await store.put("alice", created)).kind, "stored");
  clock += 25 * 60 * 60 * 1000;
  let previous = created;
  for (let counter = 2; counter <= 80; counter += 1) {
    const update = protocol.createOperation({
      operation: "update", objectId: "object-1", fileId: "file-1", versionId: `version-1-${counter}`, operationId: `update-${counter}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-a" },
      baseRevision: previous.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from(`v${counter}`), fileKey: key,
    });
    assert.equal((await store.put("alice", update)).kind, "stored");
    previous = update;
  }
  const history = store.history("alice", "object-1");
  assert.equal(history.length, 32);
  assert.equal(history[0].versionId, created.versionId);
  assert.equal(history[history.length - 1].versionId, previous.versionId);
});

test("issue 67 store: versions created by a paused device are not pruned while it stays paused", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-paused-prune-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const store = await new SyncObjectStore(path.join(dir, "objects.json"), {
    burstGuard: createSyncBurstGuard({ maxDestructive: 100000, maxPerObject: 100000, env: {} }),
    now: () => 1700000000000,
  }).open();
  const key = crypto.randomBytes(32);
  const created = createFor(1, key);
  assert.equal((await store.put("alice", created)).kind, "stored");
  let previous = created;
  for (let counter = 2; counter <= 3; counter += 1) {
    const update = protocol.createOperation({
      operation: "update", objectId: "object-1", fileId: "file-1", versionId: `version-1-${counter}`, operationId: `update-${counter}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-a" },
      baseRevision: previous.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from(`v${counter}`), fileKey: key,
    });
    assert.equal((await store.put("alice", update)).kind, "stored");
    previous = update;
  }
  // Pause device-a directly (the same persisted pause record the guard writes).
  await store.transact((next) => {
    const user = store.user(next, "alice");
    user.pausedDevices = { "d:device-a": { pausedAt: new Date().toISOString(), reason: "test", limit: 1, windowMs: 1 } };
  });
  // Device-b keeps overwriting the object far past the history cap.
  let prior = previous;
  for (let counter = 4; counter <= 60; counter += 1) {
    const update = protocol.createOperation({
      operation: "update", objectId: "object-1", fileId: "file-1", versionId: `version-1-${counter}`, operationId: `update-b-${counter}`,
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-b" },
      baseRevision: prior.revision, metadata: { path: "f1.txt", name: "f1.txt", size: 4 }, plaintext: Buffer.from(`b${counter}`), fileKey: key,
    });
    assert.equal((await store.put("alice", update)).kind, "stored");
    prior = update;
  }
  const versionIds = store.history("alice", "object-1").map((entry) => entry.versionId);
  assert.ok(versionIds.includes("version-1-1"));
  assert.ok(versionIds.includes("version-1-2"));
  assert.ok(versionIds.includes("version-1-3"));
});

test("issue 67 resume 2FA: password alone is refused, a wrong TOTP is refused, the correct TOTP resumes", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-2fa-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const { port, route } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ maxDestructive: 1, env: {} }), accountUsers: account.users });
  const key = crypto.randomBytes(32);
  await pauseDeviceA(port, key, 1, 2);
  assert.equal((await resumeRequest(port)).status, 401);
  assert.equal((await resumeRequest(port, { password: PASSWORD, code: "000000" })).status, 401);
  assert.equal((await resumeRequest(port, { password: PASSWORD, code: codeAt(account.secret, 10) })).status, 401);
  const ok = await resumeRequest(port, { password: PASSWORD, code: codeAt(account.secret) });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.wasPaused, true);
  // The accepted TOTP step is persisted for replay protection.
  assert.equal(typeof route.accountState.users[0].totpLastUsedStep, "number");
});

test("issue 67 resume 2FA: the same TOTP code cannot be replayed to resume again", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-2fa-replay-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const { port } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ maxDestructive: 1, env: {} }), accountUsers: account.users });
  const key = crypto.randomBytes(32);
  await pauseDeviceA(port, key, 1, 2);
  const code = codeAt(account.secret);
  assert.equal((await resumeRequest(port, { password: PASSWORD, code })).status, 200);
  await pauseDeviceA(port, key, 3, 4);
  assert.equal((await resumeRequest(port, { password: PASSWORD, code })).status, 401);
});

test("issue 67 resume 2FA: a recovery code works once", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-2fa-recovery-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const { port, route } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ maxDestructive: 1, env: {} }), accountUsers: account.users });
  const key = crypto.randomBytes(32);
  await pauseDeviceA(port, key, 1, 2);
  const recovery = account.recoveryCodes[0];
  assert.equal((await resumeRequest(port, { password: PASSWORD, code: recovery })).status, 200);
  // Persisted removal: exactly one recovery hash remains.
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 1);
  await pauseDeviceA(port, key, 3, 4);
  assert.equal((await resumeRequest(port, { password: PASSWORD, code: recovery })).status, 401);
});

test("issue 65 resume: indeterminate sync persistence rejects re-auth before spending a recovery code", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue65-resume-indeterminate-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const storagePath = path.join(dir, "objects.json");
  const { port, route } = await startServer(t, {
    storagePath, accountUsers: account.users,
  });
  const recovery = account.recoveryCodes[0];
  route.store.commitIndeterminate = true;

  const missingPassword = await resumeRequest(port, {});
  assert.equal(missingPassword.status, 503);
  assert.equal(missingPassword.body.code, "SYNC_COMMIT_INDETERMINATE");
  const rejected = await resumeRequest(port, { password: PASSWORD, code: recovery });
  assert.equal(rejected.status, 503);
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 2);

  // A newly opened store reads the persisted JSON rather than bypassing the quarantine flag.
  const reopened = await startServer(t, { storagePath, accountUsers: route.accountState.users });
  assert.equal((await resumeRequest(reopened.port, { password: PASSWORD, code: recovery })).status, 200);
  assert.equal(reopened.route.accountState.users[0].totpRecoveryHashes.length, 1);
});

test("issue 65 resume: an already locked sync store cannot consume a recovery code", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue65-resume-locked-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const { port, route } = await startServer(t, {
    storagePath: path.join(dir, "objects.json"), accountUsers: account.users,
  });
  const recovery = account.recoveryCodes[0];
  const originalTransact = route.store.transact.bind(route.store);
  route.store.transact = async () => {
    throw Object.assign(new Error("storage busy"), { code: "EACCES" });
  };
  const locked = await resumeRequest(port, { password: PASSWORD, code: recovery });
  assert.equal(locked.status, 503);
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 2,
    "no recovery factor may be spent when the sync storage cannot persist");
  route.store.transact = originalTransact;
  assert.equal((await resumeRequest(port, { password: PASSWORD, code: recovery })).status, 200,
    "the same code works after storage becomes writable");
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 1);
});

test("issue 65 resume: a store becoming indeterminate during bcrypt fails before second-factor consumption", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue65-resume-race-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const storagePath = path.join(dir, "objects.json");
  let route;
  let quarantineNext = true;
  const bcryptImpl = {
    compare: async (...args) => {
      const result = await bcrypt.compare(...args);
      if (quarantineNext) {
        route.store.commitIndeterminate = true;
        quarantineNext = false;
      }
      return result;
    },
  };
  const opened = await startServer(t, {
    storagePath, accountUsers: account.users, bcryptImpl,
  });
  route = opened.route;
  const recovery = account.recoveryCodes[0];

  const rejected = await resumeRequest(opened.port, { password: PASSWORD, code: "000000" });
  assert.equal(rejected.status, 503);
  assert.equal(rejected.body.code, "SYNC_COMMIT_INDETERMINATE");
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 2);

  const reopened = await startServer(t, { storagePath, accountUsers: route.accountState.users });
  assert.equal((await resumeRequest(reopened.port, { password: PASSWORD, code: recovery })).status, 200);
  assert.equal(reopened.route.accountState.users[0].totpRecoveryHashes.length, 1);
});

test("issue 203 sync resume: recovery verification does not call synchronous scrypt", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue203-sync-recovery-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const { port, route } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ maxDestructive: 1, env: {} }), accountUsers: account.users });
  const key = crypto.randomBytes(32);
  await pauseDeviceA(port, key, 1, 2);
  const recovery = account.recoveryCodes[0];
  const originalScryptSync = crypto.scryptSync;
  crypto.scryptSync = () => { throw new Error("synchronous recovery-code scrypt is forbidden on the request path"); };
  let response;
  try {
    response = await resumeRequest(port, { password: PASSWORD, code: recovery });
  } finally {
    crypto.scryptSync = originalScryptSync;
  }
  assert.equal(response.status, 200);
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 1);
});

test("issue 67 resume 2FA: without the TOTP key the resume fails closed with 503", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-2fa-nokey-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const { port } = await startServer(t, { storagePath: path.join(dir, "objects.json"), burstGuard: createSyncBurstGuard({ maxDestructive: 1, env: {} }), accountUsers: account.users, totpKey: null });
  const key = crypto.randomBytes(32);
  await pauseDeviceA(port, key, 1, 2);
  assert.equal((await resumeRequest(port, { password: PASSWORD, code: codeAt(account.secret) })).status, 503);
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

async function raceTwoDeviceResumes(t, codeForAccount) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-issue67-concurrent-resume-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const account = twoFactorAccount();
  const pending = [];
  // Release both password checks together to exercise the stale-snapshot boundary.
  const bcryptImpl = {
    compare: () => new Promise((resolve) => {
      pending.push(resolve);
      if (pending.length === 2) pending.forEach((release) => release(true));
    }),
  };
  const { port, route } = await startServer(t, {
    storagePath: path.join(dir, "objects.json"),
    bcryptImpl,
    accountUsers: account.users,
  });
  await route.store.transact((next) => {
    const user = route.store.user(next, "alice");
    user.pausedDevices = {
      "d:device-a": { pausedAt: new Date().toISOString(), reason: "test" },
      "d:device-b": { pausedAt: new Date().toISOString(), reason: "test" },
    };
  });
  const code = codeForAccount(account);
  const body = { password: PASSWORD, code };
  const results = await Promise.all([
    resumeRequest(port, body),
    jsonRequest(port, "/sync/v1/devices/device-b/resume", "POST", body),
  ]);
  assert.deepEqual(results.map((result) => result.status).sort((a, b) => a - b), [200, 401]);
  assert.equal(["device-a", "device-b"].filter((device) => route.store.isDevicePaused("alice", device)).length, 1);
  return { route, account };
}

test("issue 67 resume 2FA: concurrent requests cannot reuse the same TOTP step", { timeout: 30_000 }, async (t) => {
  const { route } = await raceTwoDeviceResumes(t, (account) => codeAt(account.secret));
  assert.equal(typeof route.accountState.users[0].totpLastUsedStep, "number");
});

test("issue 67 resume 2FA: concurrent requests cannot reuse the same recovery code", { timeout: 30_000 }, async (t) => {
  const { route } = await raceTwoDeviceResumes(t, (account) => account.recoveryCodes[0]);
  assert.equal(route.accountState.users[0].totpRecoveryHashes.length, 1);
});
