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

const REQUIRES_ATOMIC = { code: "SYNC_PROTECTED_ATOMIC_REQUIRED" };

function make(kind, revision, objectId = "protected-a", suffix = kind) {
  return createOperation({
    operation: kind, objectId, fileId: "file-a",
    versionId: "version-" + suffix, operationId: "operation-" + suffix,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: revision, deviceId: "device-a" },
    baseRevision: revision === 1 ? null : { counter: revision - 1, deviceId: "device-a" },
    metadata: { path: "secret.txt" },
    plaintext: Buffer.from("only ciphertext is persisted"),
    fileKey: crypto.randomBytes(32),
  });
}

async function signedCreate() {
  const op = make("create", 1);
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  op.authorization = await createAuthorizationProof(op, {
    username: "alice", privateKey: keys.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  return op;
}

async function setup(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "zk65-protected-old-history-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "objects.json");
  const store = await new SyncObjectStore(file).open();
  const signed = await signedCreate();
  // Faithfully model a persisted signed Sync v2 object written by the old
  // legacy route, before the atomic ingress gate was introduced. Never use
  // store.put(signed): the patched ingress must prohibit precisely that.
  const seed = async (current, history) => store.transact((next) => {
    const record = JSON.parse(JSON.stringify(current));
    next.users.alice = {
      objects: { [signed.objectId]: record },
      versions: { [signed.objectId]: history.map((x) => JSON.parse(JSON.stringify(x))) },
      revisions: { [signed.objectId]: current.revision },
      versionTimes: { [signed.objectId]: history.map(() => Date.now()) },
      seen: { [signed.operationId]: true },
    };
  });
  return { store, file, signed, seed };
}

async function send(port, op, method = "DELETE") {
  const body = Buffer.from(JSON.stringify(op));
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, method,
      path: "/sync/v1/objects/" + op.objectId,
      headers: { "content-type": "application/json", "content-length": body.length } }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: JSON.parse(text) }));
    });
    req.on("error", reject);
    req.end(body);
  });
}

async function listen(t, file) {
  const app = express();
  app.use(express.json());
  const route = registerSyncRoutes({ app, storagePath: file,
    requireDeviceAuthorization: false,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", permissions: { delete: true } };
      next();
    },
    requirePermission: () => (_req, _res, next) => next(),
  });
  await route.ready;
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return { route, port: server.address().port };
}

test("restart of legacy signed object refuses unsigned update, delete, create and replay", async (t) => {
  const f = await setup(t);
  await f.seed(f.signed, [f.signed]);
  const originalBytes = await fs.readFile(f.file);
  const reopened = await new SyncObjectStore(f.file).open();
  for (const attempt of [
    make("update", 2, f.signed.objectId, "update"),
    make("delete", 2, f.signed.objectId, "delete"),
    make("create", 3, f.signed.objectId, "recreate"),
    { ...make("delete", 2, f.signed.objectId, "replay"),
      operationId: f.signed.operationId },
  ]) await assert.rejects(reopened.put("alice", attempt), REQUIRES_ATOMIC);
  assert.deepEqual(await fs.readFile(f.file), originalBytes,
    "no unauthorized write or tombstone may replace the signed object");
});

test("even historical signed version fences unsigned current and HTTP delete", async (t) => {
  const f = await setup(t);
  const unsignedCurrent = make("update", 2, f.signed.objectId, "old-unsafe-current");
  await f.seed(unsignedCurrent, [f.signed, unsignedCurrent]);
  const previous = await fs.readFile(f.file);
  const { route, port } = await listen(t, f.file);
  const attempt = make("delete", 3, f.signed.objectId, "unsigned-tombstone");
  const response = await send(port, attempt);
  assert.equal(response.status, 503);
  assert.equal(response.body.code, REQUIRES_ATOMIC.code);
  assert.equal(route.store.list("alice")[0].tombstone, false);
  assert.deepEqual(await fs.readFile(f.file), previous);
});

test("foreign writer signs old object after HTTP preflight; final transaction must deny", async (t) => {
  const f = await setup(t);
  const initial = make("create", 1, f.signed.objectId, "initial-unsigned");
  assert.equal((await f.store.put("alice", initial)).kind, "stored");
  const { route, port } = await listen(t, f.file);
  const originalPut = SyncObjectStore.prototype.put;
  let entered, release;
  const reached = new Promise((resolve) => { entered = resolve; });
  const suspended = new Promise((resolve) => { release = resolve; });
  SyncObjectStore.prototype.put = async function (...args) {
    entered();
    await suspended;
    return originalPut.apply(this, args);
  };
  t.after(() => { SyncObjectStore.prototype.put = originalPut; release(); });
  const attempt = make("delete", 2, f.signed.objectId, "late-delete");
  const pending = send(port, attempt);
  await reached;
  // A separately opened store creates a historically signed version DURABLY
  // while HTTP has already parsed the unsigned request.
  await f.seed(f.signed, [f.signed]);
  const immutable = await fs.readFile(f.file);
  release();
  const response = await pending;
  assert.equal(response.status, 503);
  assert.equal(response.body.code, REQUIRES_ATOMIC.code);
  assert.deepEqual(await fs.readFile(f.file), immutable);
  assert.equal(route.store.list("alice")[0].tombstone, false);
});

test("unsigned-only legacy operations and restart remain compatible", async (t) => {
  const f = await setup(t);
  const initial = make("create", 1, f.signed.objectId, "plain");
  assert.equal((await f.store.put("alice", initial)).kind, "stored");
  const { port } = await listen(t, f.file);
  const deletion = make("delete", 2, f.signed.objectId, "plain-delete");
  const response = await send(port, deletion);
  assert.equal(response.status, 200);
  const restarted = await new SyncObjectStore(f.file).open();
  assert.equal(restarted.list("alice")[0].tombstone, true);
});
