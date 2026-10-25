"use strict";

const assert = require("node:assert/strict");
const { execFile } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { promisify } = require("node:util");
const express = require("express");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const execFileAsync = promisify(execFile);

async function isolatedRegistryDirectory(prefix) {
  if (process.platform !== "win32") return fs.mkdtemp(path.join(os.tmpdir(), prefix));
  // The Windows test machine's %TEMP% inherits broad Modify rights. Strict
  // atomic mode intentionally refuses it; provision ONLY a disposable child
  // below the separately protected per-user LocalAppData ancestry instead.
  const directory = path.join(process.env.LOCALAPPDATA, `${prefix}${crypto.randomBytes(8).toString("hex")}`);
  ensureWindowsChunkUploadRoot(directory);
  return directory;
}

function post(port, body) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const req = http.request({ host: "127.0.0.1", port, path: "/sync/v1/objects", method: "POST",
      headers: { "content-type": "application/json", "content-length": payload.length } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

test("revocation committed before sync put must fence operation across authorization gap", async (t) => {
  const directory = await isolatedRegistryDirectory("rootark-sync-revoke-race-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const storagePath = path.join(directory, "objects.json");
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");

  let reachedPut;
  const reached = new Promise((resolve) => { reachedPut = resolve; });
  let releasePut;
  const released = new Promise((resolve) => { releasePut = resolve; });
  const originalPut = SyncObjectStore.prototype.put;
  SyncObjectStore.prototype.put = async function (...args) {
    reachedPut();
    await released;
    return originalPut.apply(this, args);
  };
  t.after(() => { SyncObjectStore.prototype.put = originalPut; releasePut(); });

  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const route = registerSyncRoutes({ app, storagePath,
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => { req.user = { username: "alice" }; next(); },
    requirePermission: () => (_req, _res, next) => next() });
  await route.ready;
  assert.deepEqual(await route.store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey,
    expectedEpoch: 0 }), { epoch: 1 });
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const operation = createOperation({ operation: "create", objectId: "object-a", fileId: "file-a",
    versionId: "version-a", operationId: "op-a", deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "a.txt" }, plaintext: Buffer.from("fixture"), fileKey: crypto.randomBytes(32) });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", publicKey, privateKey: keys.privateKey, expiresAt: Date.now() + 60_000 });

  const pending = post(server.address().port, operation);
  await reached; // Request reached put, but has not taken the cross-process write lock.
  assert.deepEqual(await route.store.revokeDevice({ username: "alice", deviceId: "device-a", expectedEpoch: 1 }), { epoch: 2 });
  releasePut();

  const status = await pending;
  assert.equal(status, 403, "revocation committed before put must reject the request");
  assert.deepEqual(route.store.list("alice"), [], "revoked device must not durably write ciphertext");
  const restarted = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(restarted.atomicRegistryEpoch(), 2);
  assert.deepEqual(restarted.list("alice"), []);
  await assert.rejects(restarted.enrollDevice({ username: "alice", deviceId: "device-a", publicKey,
    expectedEpoch: 2 }), { code: "SYNC_ATOMIC_DEVICE_AUTH_REJECTED" }, "revoked ID must not silently re-enroll");
});

test("strict co-located mode rejects an external registry or callback and refuses unmigrated stores", async (t) => {
  const directory = await isolatedRegistryDirectory("rootark-sync-registry-strict-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const storagePath = path.join(directory, "objects.json");
  const app = express();
  const base = { app, storagePath, atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (_req, _res, next) => next(), requirePermission: () => (_req, _res, next) => next() };
  assert.throws(() => registerSyncRoutes({ ...base, deviceRegistryPath: path.join(directory, "external.json") }),
    { code: "SYNC_ATOMIC_DEVICE_CONFIGURATION" });
  assert.throws(() => registerSyncRoutes({ ...base, deviceAuthorization: async () => true }),
    { code: "SYNC_ATOMIC_DEVICE_CONFIGURATION" });
  assert.throws(() => registerSyncRoutes({ ...base, requireDeviceAuthorization: false }),
    { code: "SYNC_ATOMIC_DEVICE_CONFIGURATION" });
  assert.throws(() => registerSyncRoutes({ ...base, atomicDeviceRegistry: "true" }),
    { code: "SYNC_ATOMIC_DEVICE_CONFIGURATION" });
  await new SyncObjectStore(storagePath).open();
  await assert.rejects(new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open(),
    { code: "SYNC_ATOMIC_DEVICE_REGISTRY_INVALID" });
});

test("global epoch CAS is serialized across store instances and restart", async (t) => {
  const directory = await isolatedRegistryDirectory("rootark-sync-registry-cas-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const storagePath = path.join(directory, "objects.json");
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const a = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  const b = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  const enroll = (deviceId) => ({ username: "alice", deviceId, publicKey, expectedEpoch: 0 });
  const settled = await Promise.allSettled([a.enrollDevice(enroll("first")), b.enrollDevice(enroll("second"))]);
  assert.equal(settled.filter((entry) => entry.status === "fulfilled").length, 1);
  assert.equal(settled.filter((entry) => entry.status === "rejected"
    && entry.reason.code === "SYNC_ATOMIC_DEVICE_EPOCH_CONFLICT").length, 1);
  assert.equal(a.atomicRegistryEpoch(), 1);
  const restarted = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(restarted.atomicRegistryEpoch(), 1);
  const first = settled[0].status === "fulfilled" ? "first" : "second";
  assert.deepEqual(await restarted.revokeDevice({ username: "alice", deviceId: first, expectedEpoch: 1 }), { epoch: 2 });
  await assert.rejects(b.revokeDevice({ username: "alice", deviceId: first, expectedEpoch: 1 }),
    { code: "SYNC_ATOMIC_DEVICE_EPOCH_CONFLICT" });
});

test("registered signer can commit; wrong signer, revoked signer, and legacy process cannot", async (t) => {
  const directory = await isolatedRegistryDirectory("rootark-sync-signature-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const storagePath = path.join(directory, "objects.json");
  const store = await new SyncObjectStore(storagePath, { atomicDeviceRegistry: true }).open();
  const owner = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const publicKey = owner.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const attackerKey = attacker.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  assert.deepEqual(await store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey,
    expectedEpoch: 0 }), { epoch: 1 });
  const make = (id) => createOperation({ operation: "create", objectId: `object-${id}`,
    fileId: `file-${id}`, versionId: `version-${id}`, operationId: `operation-${id}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: `${id}.txt` },
    plaintext: Buffer.from("fixture"), fileKey: crypto.randomBytes(32) });
  const signed = async (id, pair = owner, key = publicKey) => {
    const operation = make(id);
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: pair.privateKey, publicKey: key });
    return operation;
  };
  const valid = await signed("good");
  assert.equal((await store.put("alice", valid)).kind, "stored");
  await assert.rejects(store.put("alice", await signed("forged", attacker, attackerKey)),
    { code: "SYNC_ATOMIC_DEVICE_AUTH_REJECTED" });
  assert.deepEqual(await store.revokeDevice({ username: "alice", deviceId: "device-a", expectedEpoch: 1 }), { epoch: 2 });
  const revoked = await signed("revoked");
  await assert.rejects(store.put("alice", revoked), { code: "SYNC_ATOMIC_DEVICE_AUTH_REJECTED" });
  const legacy = await new SyncObjectStore(storagePath).open();
  await assert.rejects(legacy.put("alice", revoked), { code: "SYNC_PROTECTED_ATOMIC_REQUIRED" },
    "a legacy process cannot commit a signed protected write without an atomic registry");
  assert.deepEqual(store.list("alice").map((record) => record.objectId), ["object-good"]);
});

test("atomic device authorization expires during Ed25519 verification before durable commit", async (t) => {
  const directory = await isolatedRegistryDirectory("rootark-sync-expiry-race-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const store = await new SyncObjectStore(path.join(directory, "objects.json"),
    { atomicDeviceRegistry: true }).open();
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  await store.enrollDevice({ username: "alice", deviceId: "device-expiry", publicKey,
    expectedEpoch: 0 });
  const operation = createOperation({ operation: "create", objectId: "expired-object",
    fileId: "expired-file", versionId: "expired-version", operationId: "expired-operation",
    deviceId: "device-expiry", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-expiry" },
    metadata: { path: "expired.txt" }, plaintext: Buffer.from("ciphertext fixture"),
    fileKey: crypto.randomBytes(32) });
  const nativeNow = Date.now;
  const nativeVerify = crypto.verify;
  const expiresAt = nativeNow() + 60_000;
  operation.authorization = await createAuthorizationProof(operation,
    { username: "alice", publicKey, privateKey: signer.privateKey, expiresAt });
  let verifiedRealSignature = false;
  try {
    Date.now = () => verifiedRealSignature ? expiresAt + 1 : nativeNow();
    crypto.verify = function (...args) {
      const result = nativeVerify.apply(this, args);
      if (result === true) verifiedRealSignature = true;
      return result;
    };
    await assert.rejects(store.put("alice", operation),
      { code: "SYNC_ATOMIC_DEVICE_AUTH_REJECTED" },
      "real signed proof must be rejected if its clock expires before persistence");
  } finally {
    crypto.verify = nativeVerify;
    Date.now = nativeNow;
  }
  assert.equal(verifiedRealSignature, true, "native Ed25519 signature must actually verify");
  assert.deepEqual(store.list("alice"), [], "expired proof cannot durably write ciphertext");
  const restarted = await new SyncObjectStore(path.join(directory, "objects.json"),
    { atomicDeviceRegistry: true }).open();
  assert.deepEqual(restarted.list("alice"), [], "expired proof cannot survive restart");
});

test("a separate Node process revokes durably before a queued HTTP object commit", async (t) => {
  const directory = await isolatedRegistryDirectory("rootark-sync-revoke-process-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const storagePath = path.join(directory, "objects.json");
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  let reachedPut;
  const reached = new Promise((resolve) => { reachedPut = resolve; });
  let releasePut;
  const released = new Promise((resolve) => { releasePut = resolve; });
  const originalPut = SyncObjectStore.prototype.put;
  SyncObjectStore.prototype.put = async function (...args) {
    reachedPut();
    await released;
    return originalPut.apply(this, args);
  };
  t.after(() => { SyncObjectStore.prototype.put = originalPut; releasePut(); });
  const app = express();
  app.use(express.json());
  const route = registerSyncRoutes({ app, storagePath, atomicDeviceRegistry: true,
    requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => { req.user = { username: "alice" }; next(); },
    requirePermission: () => (_req, _res, next) => next() });
  await route.ready;
  await route.store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey, expectedEpoch: 0 });
  const server = await new Promise((resolve) => {
    const listening = app.listen(0, "127.0.0.1", () => resolve(listening));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));

  const operation = createOperation({ operation: "create", objectId: "process-object",
    fileId: "process-file", versionId: "process-version", operationId: "process-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "child.txt" },
    plaintext: Buffer.from("fixture"), fileKey: crypto.randomBytes(32) });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", publicKey, privateKey: keys.privateKey });
  const pending = post(server.address().port, operation);
  await reached;
  const childScript = `const {SyncObjectStore}=require(process.argv[1]);\n` +
    `(async()=>{const store=await new SyncObjectStore(process.argv[2],{atomicDeviceRegistry:true}).open();\n` +
    `const result=await store.revokeDevice({username:'alice',deviceId:'device-a',expectedEpoch:1});\n` +
    `process.stdout.write(JSON.stringify(result))})().catch(error=>{console.error(error.code||error.message);process.exitCode=1});`;
  const { stdout } = await execFileAsync(process.execPath, ["-e", childScript, require.resolve("../src/routes/sync"), storagePath],
    { timeout: 15000 });
  assert.deepEqual(JSON.parse(stdout), { epoch: 2 });
  releasePut();
  assert.equal(await pending, 403);
  assert.deepEqual(route.store.list("alice"), []);
});
