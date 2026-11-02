"use strict";

// Exclusive DEV test. Real HTTP, real private JSON disk, signed Ed25519 and
// authoritative disposable SQLite account; NO production data or server.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { createSyncBurstGuard } = require("../src/services/syncBurstGuard");
const { runMigrations } = require("../db/migrations");
const { closeDb } = require("../db");
const usersRepository = require("../repositories/usersRepository");

async function privateDirectory(prefix) {
  if (process.platform !== "win32") return fs.mkdtemp(path.join(os.tmpdir(), prefix));
  const directory = path.join(process.env.LOCALAPPDATA,
    prefix + crypto.randomBytes(8).toString("hex"));
  ensureWindowsChunkUploadRoot(directory);
  return directory;
}

function request(port, url, body) {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(JSON.stringify(body));
    const req = http.request({ host: "127.0.0.1", port, method: "POST", path: url,
      headers: { "content-type": "application/json", "content-length": payload.length } }, (res) => {
      const parts = [];
      res.on("data", (chunk) => parts.push(chunk));
      res.on("end", () => {
        const bytes = Buffer.concat(parts).toString("utf8");
        let parsed = null;
        try { parsed = bytes ? JSON.parse(bytes) : null; } catch {
          // express.json's 413 parser error is HTML, before the route starts.
        }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on("error", reject);
    req.end(payload);
  });
}

async function fixture(t, options = {}) {
  const directory = await privateDirectory("zk65-cos-batch-");
  const accountsDirectory = await privateDirectory("zk65-cos-batch-accounts-");
  const original = { DB_ENABLED: process.env.DB_ENABLED,
    DATABASE_URL: process.env.DATABASE_URL,
    DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON };
  t.after(async () => {
    closeDb();
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fs.rm(directory, { recursive: true, force: true });
    await fs.rm(accountsDirectory, { recursive: true, force: true });
  });
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  process.env.DATABASE_URL = path.join(accountsDirectory, "accounts.sqlite");
  runMigrations({ backup: false });
  usersRepository.saveUsers([{ username: "alice", role: "user", password: "fixture",
    sessionVersion: 0, permissions: { upload: true, delete: true } }]);
  const storagePath = path.join(directory, "objects.json");
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" })
    .toString("base64url");
  const fileKeys = { a: crypto.randomBytes(32), b: crypto.randomBytes(32) };
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const routes = registerSyncRoutes({ app, storagePath, atomicDeviceRegistry: true,
    requireDeviceAuthorization: true,
    burstGuard: options.burstGuard,
    auditLog: options.auditLog,
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", sessionVersion: 0,
        permissions: { upload: true, delete: options.canDelete !== false } };
      next();
    }, requirePermission: () => (_req, _res, next) => next() });
  await routes.ready;
  await routes.store.enrollDevice({ username: "alice", deviceId: "device-a",
    publicKey, expectedEpoch: 0 });
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const sign = async (operation) => {
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", publicKey, privateKey: signer.privateKey,
      expiresAt: Date.now() + 60_000,
    });
    return operation;
  };
  const make = async (kind, id, counter, suffix, {
    targetPath = "a.txt", keyEpoch = "epoch-1", plaintext = null,
  } = {}) => sign(createOperation({
    operation: kind, objectId: "object-" + id, fileId: "file-" + id,
    versionId: "version-" + id + "-" + counter,
    operationId: kind + "-" + id + "-" + counter + "-" + suffix,
    deviceId: "device-a", keyEpoch, compartmentId: "private",
    revision: { counter, deviceId: "device-a" },
    baseRevision: counter > 1 ? { counter: counter - 1, deviceId: "device-a" } : null,
    metadata: kind === "move" ? { path: targetPath, sourcePath: id + ".txt" }
      : { path: id + ".txt" },
    plaintext: plaintext || Buffer.from("disposable ciphertext " + id),
    fileKey: fileKeys[id],
  }));
  const send = (route, body) => request(server.address().port, route, body);
  assert.equal((await send("/sync/v1/objects", await make("create", "a", 1, "seed"))).status, 201);
  assert.equal((await send("/sync/v1/objects", await make("create", "b", 1, "seed"))).status, 201);
  return { routes, storagePath, make, send, publicKey,
    batch: async (deleteOp, moveOp) => send("/sync/v1/objects/batch",
      { operations: [deleteOp, moveOp] }),
    onDisk: () => fs.readFile(storagePath, "utf8") };
}

test("real HTTP signed DELETE+MOVE commits atomically under one durable disk state", async (t) => {
  const f = await fixture(t);
  const deleted = await f.make("delete", "a", 2, "ok");
  const moved = await f.make("move", "b", 2, "ok");
  const reply = await f.batch(deleted, moved);
  assert.equal(reply.status, 200);
  assert.deepEqual(reply.body.objects.map((o) => o.operation), ["delete", "move"]);
  const disk = JSON.parse(await f.onDisk());
  assert.equal(disk.users.alice.objects["object-a"].tombstone, true);
  assert.equal(disk.users.alice.objects["object-b"].operation, "move");
  assert.equal(disk.users.alice.objects["object-b"].metadata.path,
    disk.users.alice.objects["object-a"].metadata.path,
    "MOVE must land at the exact deleted destination");
  assert.equal(disk.users.alice.seen[deleted.operationId], true);
  assert.equal(disk.users.alice.seen[moved.operationId], true);
  const reopened = await new SyncObjectStore(f.storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal(reopened.list("alice").find((o) => o.objectId === "object-b").operation, "move");
});

test("replay of an actually committed signed batch returns 409 without another disk write", async (t) => {
  const f = await fixture(t);
  const deleted = await f.make("delete", "a", 2, "replay");
  const moved = await f.make("move", "b", 2, "replay");
  assert.equal((await f.batch(deleted, moved)).status, 200);
  const committed = await f.onDisk();
  assert.equal((await f.batch(deleted, moved)).status, 409);
  assert.equal(await f.onDisk(), committed, "replayed DELETE and MOVE never persist again");
  await assert.rejects(f.routes.store.putSignedBatch("alice", [deleted, moved]),
    { code: "SYNC_SIGNED_BATCH_REJECTED", kind: "replay" });
  assert.equal(await f.onDisk(), committed);
});

test("both individually signed operations must remain in the exact same key epoch", async (t) => {
  const f = await fixture(t);
  const deleted = await f.make("delete", "a", 2, "epoch-1");
  const moved = await f.make("move", "b", 2, "epoch-2", { keyEpoch: "epoch-2" });
  const before = await f.onDisk();
  const trustedDevicePublicKeys = { "device-a": f.publicKey };
  assert.equal(await verifyAuthorizationProof(deleted.authorization, deleted,
    { username: "alice", trustedDevicePublicKeys, revokedDeviceIds: [] }), true);
  assert.equal(await verifyAuthorizationProof(moved.authorization, moved,
    { username: "alice", trustedDevicePublicKeys, revokedDeviceIds: [] }), true);
  assert.equal((await f.batch(deleted, moved)).status, 400);
  assert.equal(await f.onDisk(), before);
  await assert.rejects(f.routes.store.putSignedBatch("alice", [deleted, moved]),
    { code: "SYNC_SIGNED_BATCH_REJECTED", kind: "invalid" });
});

test("proof expiry after staging fsync but before rename cancels the entire signed batch", async (t) => {
  const f = await fixture(t);
  const deleted = await f.make("delete", "a", 2, "fsync-expiry");
  const moved = await f.make("move", "b", 2, "fsync-expiry");
  const before = await f.onDisk();
  const originalOpen = fs.open;
  const originalRename = fs.rename;
  const originalNow = Date.now;
  const expiredAt = Math.max(deleted.authorization.expiresAt,
    moved.authorization.expiresAt) + 1;
  let expiredDuringSync = false;
  let calledRename = false;
  try {
    fs.open = async function (...args) {
      const handle = await originalOpen.apply(this, args);
      if (typeof args[0] === "string" && args[0].startsWith(f.storagePath + ".tmp-")) {
        const sync = handle.sync.bind(handle);
        handle.sync = async () => {
          await sync();
          expiredDuringSync = true;
        };
      }
      return handle;
    };
    fs.rename = async function (...args) {
      if (args[1] === f.storagePath) calledRename = true;
      return originalRename.apply(this, args);
    };
    Date.now = () => expiredDuringSync ? expiredAt : originalNow();
    const denied = await f.batch(deleted, moved);
    assert.equal(denied.status, 403);
  } finally {
    Date.now = originalNow;
    fs.open = originalOpen;
    fs.rename = originalRename;
  }
  assert.equal(expiredDuringSync, true, "the staged JSON file was synced before expiry");
  assert.equal(calledRename, false, "the expired approval cannot reach physical rename");
  assert.equal(await f.onDisk(), before, "no partial or total destructive batch commit");
});

test("single protected DELETE expiring during fsync must not pass the final rename fence", async (t) => {
  const f = await fixture(t);
  const operation = await f.make("delete", "a", 2, "single-fsync-expiry");
  const before = await f.onDisk();
  const originalOpen = fs.open;
  const originalRename = fs.rename;
  const originalNow = Date.now;
  let afterSync = false;
  let renamed = false;
  try {
    fs.open = async function (...args) {
      const handle = await originalOpen.apply(this, args);
      if (typeof args[0] === "string" && args[0].startsWith(f.storagePath + ".tmp-")) {
        const sync = handle.sync.bind(handle);
        handle.sync = async () => { await sync(); afterSync = true; };
      }
      return handle;
    };
    fs.rename = async function (...args) {
      if (args[1] === f.storagePath) renamed = true;
      return originalRename.apply(this, args);
    };
    Date.now = () => afterSync ? operation.authorization.expiresAt + 1 : originalNow();
    const reply = await f.send("/sync/v1/objects", operation);
    assert.equal(reply.status, 403);
  } finally {
    Date.now = originalNow;
    fs.open = originalOpen;
    fs.rename = originalRename;
  }
  assert.equal(afterSync, true, "the uncommitted temporary store file reached fsync");
  assert.equal(renamed, false, "expired single-device grant cannot rename protected data");
  assert.equal(await f.onDisk(), before, "expired single DELETE cannot persist or become seen");
});

test("9 MiB aggregate request cap rejects two individually bounded signed ciphertexts", async (t) => {
  const f = await fixture(t);
  const bytes = Buffer.alloc(4 * 1024 * 1024, 0x6b);
  const deleted = await f.make("delete", "a", 2, "large", { plaintext: bytes });
  const moved = await f.make("move", "b", 2, "large", { plaintext: bytes });
  const payload = { operations: [deleted, moved] };
  assert.ok(Buffer.byteLength(JSON.stringify(payload)) > 9 * 1024 * 1024);
  assert.ok(Buffer.from(deleted.ciphertext, "base64url").length < 8 * 1024 * 1024);
  assert.ok(Buffer.from(moved.ciphertext, "base64url").length < 8 * 1024 * 1024);
  const prior = await f.onDisk();
  const result = await f.send("/sync/v1/objects/batch", payload);
  assert.equal(result.status, 413);
  assert.equal(await f.onDisk(), prior);
});

test("independently valid signed DELETE A + MOVE B to unrelated C must not mutate disk", async (t) => {
  const f = await fixture(t);
  const deleted = await f.make("delete", "a", 2, "target-a");
  const unrelated = await f.make("move", "b", 2, "target-c", { targetPath: "c.txt" });
  const trustedDevicePublicKeys = { "device-a": f.publicKey };
  assert.equal(await verifyAuthorizationProof(deleted.authorization, deleted,
    { username: "alice", trustedDevicePublicKeys, revokedDeviceIds: [] }), true);
  assert.equal(await verifyAuthorizationProof(unrelated.authorization, unrelated,
    { username: "alice", trustedDevicePublicKeys, revokedDeviceIds: [] }), true);
  assert.equal(deleted.metadata.path, "a.txt");
  assert.equal(unrelated.metadata.path, "c.txt");
  const before = await f.onDisk();
  const rejected = await f.batch(deleted, unrelated);
  assert.ok([400, 409].includes(rejected.status), "unrelated destinations must be denied");
  assert.equal(await f.onDisk(), before,
    "both signed envelopes are valid, but neither may commit an unrelated destination");
  await assert.rejects(f.routes.store.putSignedBatch("alice", [deleted, unrelated]),
    { code: "SYNC_SIGNED_BATCH_REJECTED", kind: "invalid" },
    "direct store callers must not bypass the shared destination binding");
  assert.equal(await f.onDisk(), before);
});

test("second MOVE conflict or replay returns 409 without partially committing DELETE", async (t) => {
  const f = await fixture(t);
  const before = await f.onDisk();
  const deleted = await f.make("delete", "a", 2, "no-partial");
  const staleMove = await f.make("move", "b", 3, "bad-base");
  const reply = await f.batch(deleted, staleMove);
  assert.equal(reply.status, 409);
  assert.equal(await f.onDisk(), before, "no DELETE, seen flag, burst or version persisted");
  const duplicate = await f.batch(deleted, deleted);
  assert.equal(duplicate.status, 400, "duplicate signed operation/object ids forbidden");
  assert.equal(await f.onDisk(), before);
});

test("invalid second Ed25519 proof rejects whole batch without durable DELETE", async (t) => {
  const f = await fixture(t);
  const deleted = await f.make("delete", "a", 2, "signed");
  const moved = await f.make("move", "b", 2, "forged");
  const prior = await f.onDisk();
  const signature = moved.authorization.signature;
  moved.authorization.signature = (signature[0] === "A" ? "B" : "A") + signature.slice(1);
  const denied = await f.batch(deleted, moved);
  assert.equal(denied.status, 403);
  assert.equal(await f.onDisk(), prior, "first valid DELETE must roll back on second forged proof");
});

test("real registry revocation beats delayed batch arrival; neither operation commits", async (t) => {
  const f = await fixture(t);
  const original = SyncObjectStore.prototype.putSignedBatch;
  let entered;
  const atBoundary = new Promise((resolve) => { entered = resolve; });
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  SyncObjectStore.prototype.putSignedBatch = async function (...args) {
    entered();
    await barrier;
    return original.apply(this, args);
  };
  t.after(() => { SyncObjectStore.prototype.putSignedBatch = original; release(); });
  const deleted = await f.make("delete", "a", 2, "revoked");
  const moved = await f.make("move", "b", 2, "revoked");
  const before = await f.onDisk();
  const pending = f.batch(deleted, moved);
  await atBoundary;
  assert.deepEqual(await f.routes.store.revokeDevice({
    username: "alice", deviceId: "device-a", expectedEpoch: 1 }), { epoch: 2 });
  release();
  const reply = await pending;
  assert.equal(reply.status, 403);
  const disk = JSON.parse(await f.onDisk());
  const snapshot = JSON.parse(before);
  assert.deepEqual(disk.users, snapshot.users, "device revocation cannot produce partial object updates");
  assert.equal(disk.deviceRegistry.epoch, 2);
  assert.equal(disk.users.alice.seen[deleted.operationId], undefined);
});

test("fresh disk state wins a competing writer race before batch acquires its writer lock", async (t) => {
  const f = await fixture(t);
  const original = SyncObjectStore.prototype.putSignedBatch;
  let entered;
  const atBoundary = new Promise((resolve) => { entered = resolve; });
  let release;
  const barrier = new Promise((resolve) => { release = resolve; });
  SyncObjectStore.prototype.putSignedBatch = async function (...args) {
    entered();
    await barrier;
    return original.apply(this, args);
  };
  t.after(() => { SyncObjectStore.prototype.putSignedBatch = original; release(); });
  const deleted = await f.make("delete", "a", 2, "racing-delete");
  const moved = await f.make("move", "b", 2, "racing-move");
  const pending = f.batch(deleted, moved);
  await atBoundary;
  const competing = await f.make("move", "b", 2, "independent-writer");
  const sibling = await new SyncObjectStore(f.storagePath, { atomicDeviceRegistry: true }).open();
  assert.equal((await sibling.put("alice", competing)).kind, "stored");
  release();
  const result = await pending;
  assert.equal(result.status, 409, "batch must reload second object's new revision under writer lock");
  const persisted = JSON.parse(await f.onDisk());
  assert.equal(persisted.users.alice.objects["object-a"].operation, "create",
    "first DELETE must not survive second-op conflict after an external writer");
  assert.equal(persisted.users.alice.objects["object-b"].operation, "move");
  assert.equal(persisted.users.alice.seen[deleted.operationId], undefined);
});

test("batch burst persists a sticky audited pause across restart without committing either mutation", async (t) => {
  const auditEvents = [];
  const burstGuard = createSyncBurstGuard({
    maxDestructive: 1, maxPerObject: 20, windowMs: 10, env: {},
  });
  const f = await fixture(t, {
    burstGuard,
    auditLog: (eventType) => auditEvents.push(eventType),
  });
  const before = JSON.parse(await f.onDisk());
  const deleted = await f.make("delete", "a", 2, "burst");
  const moved = await f.make("move", "b", 2, "burst");
  const reply = await f.batch(deleted, moved);
  assert.equal(reply.status, 423);
  assert.equal(reply.body.code, "sync_burst_paused");
  const after = JSON.parse(await f.onDisk());
  for (const key of ["objects", "versions", "versionTimes", "revisions", "seen"]) {
    assert.deepEqual(after.users.alice[key], before.users.alice[key],
      `burst must not persist first DELETE or second MOVE ${key}`);
  }
  const pause = after.users.alice.pausedDevices["d:device-a"];
  assert.equal(typeof pause.pauseNonce, "string");
  assert.equal(pause.reason, "destructive_burst");
  assert.equal(after.users.alice.burstCounters["d:device-a"].events.length, 2,
    "both attempted destructive operations must count");
  assert.deepEqual(auditEvents, ["sync.burst.paused"]);

  // Reopen the physical store rather than relying on its in-memory state.
  const reopened = await new SyncObjectStore(f.storagePath,
    { atomicDeviceRegistry: true, burstGuard }).open();
  assert.equal(reopened.isDevicePaused("alice", "device-a"), true);
  assert.equal(reopened.pauseFence("alice", "device-a"), pause.pauseNonce);
  await new Promise((resolve) => setTimeout(resolve, 30));
  const retry = await f.batch(
    await f.make("delete", "a", 2, "after-window"),
    await f.make("move", "b", 2, "after-window"));
  assert.equal(retry.status, 423, "expired burst window must not lift the durable pause");
  const persisted = JSON.parse(await f.onDisk());
  assert.deepEqual(persisted.users.alice.objects, before.users.alice.objects);
  assert.deepEqual(persisted.users.alice.seen, before.users.alice.seen);
  assert.equal(persisted.users.alice.pausedDevices["d:device-a"].pauseNonce, pause.pauseNonce,
    "rejected retry must not rotate the pause fence");
  assert.deepEqual(auditEvents, ["sync.burst.paused"], "retries must not repeat the new-pause audit");
});

test("batch refuses a signed MOVE whose current source was already tombstoned", async (t) => {
  const f = await fixture(t);
  const removedSource = await f.make("delete", "b", 2, "tombstone-source");
  assert.equal((await f.send("/sync/v1/objects", removedSource)).status, 201);
  const before = await f.onDisk();
  const deleted = await f.make("delete", "a", 2, "replacement-target");
  const moved = await f.make("move", "b", 3, "removed-source");
  const denied = await f.batch(deleted, moved);
  assert.equal(denied.status, 409);
  assert.equal(await f.onDisk(), before, "no target DELETE, MOVE or seen flags may commit");
});

test("atomic registry refuses unsigned or expired batch admission before changing either object", async (t) => {
  const f = await fixture(t);
  const before = await f.onDisk();
  const deleted = await f.make("delete", "a", 2, "unsigned-target");
  const moved = await f.make("move", "b", 2, "unsigned-source");
  delete deleted.authorization;
  const unsigned = await f.batch(deleted, moved);
  assert.ok([400, 403].includes(unsigned.status), "unsigned DELETE must be rejected");
  assert.equal(await f.onDisk(), before, "unsigned first member must not mutate either object");

  const freshDelete = await f.make("delete", "a", 2, "expired-target");
  const expiredMove = await f.make("move", "b", 2, "expired-source");
  expiredMove.authorization.expiresAt = Date.now() - 1;
  const expired = await f.batch(freshDelete, expiredMove);
  assert.ok([400, 403].includes(expired.status), "expired MOVE must be rejected");
  assert.equal(await f.onDisk(), before, "invalid second member cannot commit DELETE");
});

test("HTTP denied on missing atomic mode, upload-only permission or malformed order", async (t) => {
  const f = await fixture(t, { canDelete: false });
  const deleted = await f.make("delete", "a", 2, "permissions");
  const moved = await f.make("move", "b", 2, "permissions");
  const before = await f.onDisk();
  assert.equal((await f.batch(deleted, moved)).status, 403);
  assert.equal((await f.batch(moved, deleted)).status, 400);
  assert.equal(await f.onDisk(), before);
});

test("legacy object store never exposes the atomic batch path as two independent writes", async (t) => {
  const directory = await privateDirectory("zk65-cos-batch-legacy-");
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const routes = registerSyncRoutes({ app, storagePath: path.join(directory, "objects.json"),
    authenticate: (req, _res, next) => {
      req.user = { username: "alice", permissions: { upload: true, delete: true } };
      next();
    }, requirePermission: () => (_req, _res, next) => next() });
  await routes.ready;
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const denied = await request(server.address().port, "/sync/v1/objects/batch",
    { operations: [{ operation: "delete" }, { operation: "move" }] });
  assert.equal(denied.status, 503);
  assert.equal(denied.body.code, "SYNC_PROTECTED_ATOMIC_REQUIRED");
  assert.deepEqual(routes.store.list("alice"), []);
});
