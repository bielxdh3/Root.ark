"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { runMigrations } = require("../db/migrations");
const { closeDb } = require("../db");

async function strictSqliteAuthority(t) {
  // The strict route also requires an independent, durable SQLite account
  // authority. Supply it in these negative *object-store* tests so they reach
  // the intended legacy-migration / unsafe-ACL guard instead of failing early
  // because DB_ENABLED defaults to false in a standalone test process.
  const original = {
    DB_ENABLED: process.env.DB_ENABLED,
    DATABASE_URL: process.env.DATABASE_URL,
    DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON,
  };
  const directory = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA,
      "zk65-strict-sqlite-test-" + crypto.randomBytes(8).toString("hex"))
    : await fs.mkdtemp(path.join(os.tmpdir(), "zk65-strict-sqlite-test-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(directory);
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  process.env.DATABASE_URL = path.join(directory, "accounts.sqlite");
  t.after(async () => {
    closeDb();
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fs.rm(directory, { recursive: true, force: true });
  });
  runMigrations({ backup: false });
}

function request(port, method, object) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(object));
    const req = http.request({ host: "127.0.0.1", port,
      method, path: "/sync/v1/objects/" + object.objectId,
      headers: { "content-type": "application/json", "content-length": payload.length } },
    (res) => {
      const parts = [];
      res.on("data", (chunk) => parts.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode,
        body: JSON.parse(Buffer.concat(parts).toString("utf8")) }));
    });
    req.on("error", reject);
    req.end(payload);
  });
}

function operation(suffix) {
  return createOperation({ operation: "create", objectId: "object-" + suffix,
    fileId: "file-" + suffix, versionId: "version-" + suffix,
    operationId: "operation-" + suffix, deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: suffix + ".txt" },
    plaintext: Buffer.from("local secret must never reach server"),
    fileKey: crypto.randomBytes(32) });
}

async function harness(t, opts = {}) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "zk65-atomic-ingress-"));
  const storagePath = path.join(directory, "objects.json");
  const registryPath = path.join(directory, "legacy-registry.json");
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const setRevoked = (revoked) => fs.writeFile(registryPath, JSON.stringify({ devices: {
    "device-a": { username: "alice", publicKey, revoked, active: !revoked },
  } }));
  await setRevoked(false);
  const app = express();
  app.use(express.json());
  const routes = registerSyncRoutes({ app, storagePath,
    deviceRegistryPath: opts.deviceRegistryPath === false ? "" : registryPath,
    requireDeviceAuthorization: opts.requireDeviceAuthorization !== false,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", permissions: { delete: true } };
      next();
    },
    requirePermission: () => (_req, _res, next) => next(),
  });
  await routes.ready;
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(directory, { recursive: true, force: true });
  });
  const signed = async (name) => {
    const envelope = operation(name);
    envelope.authorization = await createAuthorizationProof(envelope, {
      username: "alice", privateKey: pair.privateKey, publicKey,
      expiresAt: Date.now() + 60_000,
    });
    return envelope;
  };
  return { routes, storagePath, setRevoked, signed,
    send: (method, envelope) => request(server.address().port, method, envelope) };
}

test("signed protected HTTP PUT cannot commit after legacy registry revokes in-flight", async (t) => {
  const f = await harness(t);
  const originalPut = SyncObjectStore.prototype.put;
  let enteredPut;
  const entered = new Promise((resolve) => { enteredPut = resolve; });
  let releasePut;
  const released = new Promise((resolve) => { releasePut = resolve; });
  SyncObjectStore.prototype.put = async function (...args) {
    enteredPut();
    await released;
    return originalPut.apply(this, args);
  };
  t.after(() => { SyncObjectStore.prototype.put = originalPut; releasePut(); });
  const pending = f.send("PUT", await f.signed("inflight"));
  // The insecure implementation passes the legacy preflight and waits here.
  // The fixed implementation returns 503 *before* entering the unsafe store.
  let timeout;
  let first;
  try {
    first = await Promise.race([entered.then(() => "entered"),
      pending.then(() => "denied"),
      new Promise((_, reject) => {
        timeout = setTimeout(() => reject(new Error("PUT stalled")), 5000);
      })]);
  } finally { clearTimeout(timeout); }
  if (first === "entered") {
    await f.setRevoked(true); // Real on-disk registry revocation before persistence.
    releasePut();
  }
  const reply = await pending;
  assert.equal(reply.status, 503, "no legacy external-registry check can authorize a protected PUT");
  assert.equal(reply.body.code, "SYNC_PROTECTED_ATOMIC_REQUIRED");
  assert.deepEqual(f.routes.store.list("alice"), []);
  const restart = await new SyncObjectStore(f.storagePath).open();
  assert.deepEqual(restart.list("alice"), [], "a restart must not expose revoked ciphertext");
});

test("signed PUT without registry and direct signed store.put fail closed; unsigned legacy unaffected", async (t) => {
  const f = await harness(t, { requireDeviceAuthorization: false, deviceRegistryPath: false });
  const signed = await f.signed("no-registry");
  const denied = await f.send("PUT", signed);
  assert.equal(denied.status, 503);
  assert.equal(denied.body.code, "SYNC_PROTECTED_ATOMIC_REQUIRED");
  await assert.rejects(f.routes.store.put("alice", signed),
    { code: "SYNC_PROTECTED_ATOMIC_REQUIRED" });
  const unsigned = operation("legacy-unsigned");
  const permitted = await f.send("PUT", unsigned);
  assert.equal(permitted.status, 200);
  assert.equal(f.routes.store.list("alice").length, 1);
});

test("required signed device mode with missing proof returns explicit 503, not legacy 403", async (t) => {
  const f = await harness(t);
  const denied = await f.send("PUT", operation("missing-proof"));
  assert.equal(denied.status, 503);
  assert.equal(denied.body.code, "SYNC_PROTECTED_ATOMIC_REQUIRED");
  assert.deepEqual(f.routes.store.list("alice"), []);
});

test("strict registry refuses legacy store across restart without migrating unsigned data", async (t) => {
  await strictSqliteAuthority(t);
  const directory = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, "zk65-atomic-no-silent-migration-"
      + crypto.randomBytes(8).toString("hex"))
    : await fs.mkdtemp(path.join(os.tmpdir(), "zk65-atomic-no-migration-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(directory);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const storagePath = path.join(directory, "objects.json");
  const legacy = await new SyncObjectStore(storagePath).open();
  assert.equal((await legacy.put("alice", operation("existing-legacy"))).kind, "stored");
  const legacyDisk = await fs.readFile(storagePath);
  const app = express();
  app.use(express.json());
  const strict = registerSyncRoutes({ app, storagePath,
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => { req.user = { username: "alice" }; next(); },
    requirePermission: () => (_req, _res, next) => next() });
  await assert.rejects(strict.ready, { code: "SYNC_ATOMIC_DEVICE_REGISTRY_INVALID" });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await request(server.address().port, "PUT", operation("refused-migration"));
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "SYNC_ATOMIC_REGISTRY_UNAVAILABLE");
  assert.deepEqual(await fs.readFile(storagePath), legacyDisk, "no silent upgrade/overwrite");
  await assert.rejects(new SyncObjectStore(storagePath,
    { atomicDeviceRegistry: true }).open(), { code: "SYNC_ATOMIC_DEVICE_REGISTRY_INVALID" });
  const restartedLegacy = await new SyncObjectStore(storagePath).open();
  assert.deepEqual(restartedLegacy.list("alice").map((item) => item.objectId),
    ["object-existing-legacy"], "legacy unsigned persisted data remains recoverable");
});

test("private ACL required: unsafe atomic registry fails closed with HTTP 503 and no new store", async (t) => {
  await strictSqliteAuthority(t);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "zk65-atomic-unsafe-perms-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  if (process.platform !== "win32") await fs.chmod(directory, 0o755);
  const storagePath = path.join(directory, "objects.json");
  const app = express();
  app.use(express.json());
  const strict = registerSyncRoutes({ app, storagePath,
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
    authenticate: (req, _res, next) => { req.user = { username: "alice" }; next(); },
    requirePermission: () => (_req, _res, next) => next() });
  await assert.rejects(strict.ready, { code: "SYNC_ATOMIC_REGISTRY_STORAGE_UNSAFE" });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const response = await request(server.address().port, "PUT", operation("unsafe-dir"));
  assert.equal(response.status, 503);
  assert.equal(response.body.code, "SYNC_ATOMIC_REGISTRY_UNAVAILABLE");
  await assert.rejects(fs.stat(storagePath), { code: "ENOENT" },
    "unsafe ACL must not initialize a trusted atomic registry");
});
