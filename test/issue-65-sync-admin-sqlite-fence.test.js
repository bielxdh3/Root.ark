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
const test = require("node:test");
const express = require("express");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { runMigrations } = require("../db/migrations");
const { closeDb } = require("../db");
const users = require("../repositories/usersRepository");

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
