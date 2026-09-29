"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");

async function adapterFor(store, username, state) {
  return {
    async push(operation) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      const result = await store.put(username, operation);
      if (result.kind === "conflict" || result.kind === "stale") return { status: 409, currentRevision: result.current?.revision || null, current: result.current };
      if (result.kind === "replay") return { status: 409 };
      return { status: 201, record: result.record };
    },
    async list() { return store.list(username); },
  };
}

async function engine(rootDir, adapter, key, options = {}) {
  return new SyncEngine({
    rootDir, adapter, deviceId: options.deviceId || "device-a", keyEpoch: options.keyEpoch || "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, authorize: options.authorize,
  }).open();
}

test("Phase 16 engine reconciles, encrypts, pulls, restarts, and stays ciphertext-only", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-"));
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const state = { offline: false };
  const key = crypto.randomBytes(32);
  const adapter = await adapterFor(store, "alice", state);
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));

  await fsp.mkdir(rootA, { recursive: true });
  await fsp.writeFile(path.join(rootA, "hello.txt"), "secret-body");
  const first = await (await engine(rootA, adapter, key)).syncOnce();
  assert.equal(first.pushed, 1);
  const pulled = await (await engine(rootB, adapter, key, { deviceId: "device-b" })).syncOnce();
  assert.equal(pulled.pulled, 1);
  assert.equal(await fsp.readFile(path.join(rootB, "hello.txt"), "utf8"), "secret-body");
  const persisted = JSON.stringify(store.state);
  assert.equal(persisted.includes("secret-body"), false);
  assert.equal(persisted.includes("fileKey"), false);

  state.offline = true;
  await fsp.writeFile(path.join(rootA, "offline.txt"), "reconnect");
  assert.equal((await (await engine(rootA, adapter, key)).syncOnce()).offline, true);
  state.offline = false;
  assert.equal((await (await engine(rootA, adapter, key)).syncOnce()).pushed >= 1, true);
  assert.equal((await (await engine(rootB, adapter, key, { deviceId: "device-b" })).syncOnce()).pulled >= 1, true);
  assert.equal(await fsp.readFile(path.join(rootB, "offline.txt"), "utf8"), "reconnect");
});

test("Phase 16 engine applies authenticated move/delete and rejects wrong epoch or key", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-ops-"));
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const state = { offline: false };
  const key = crypto.randomBytes(32);
  const adapter = await adapterFor(store, "alice", state);
  const source = path.join(dir, "source");
  const target = path.join(dir, "target");
  await fsp.mkdir(source, { recursive: true });
  await fsp.mkdir(target, { recursive: true });
  await fsp.writeFile(path.join(source, "name.txt"), "payload");
  const a = await engine(source, adapter, key);
  await a.syncOnce();
  const b = await engine(target, adapter, key, { deviceId: "device-b" });
  await b.syncOnce();
  const remote = store.list("alice")[0];
  await fsp.rename(path.join(source, "name.txt"), path.join(source, "renamed.txt"));
  await a.enqueueChange({
    operation: "move", objectId: remote.objectId, fileId: remote.fileId, versionId: "move-v1", baseRevision: remote.revision,
    revision: { counter: 2, deviceId: "device-a" }, metadata: { path: "renamed.txt", sourcePath: "name.txt" }, fileKey: key,
  });
  await a.pushPending({ pushed: 0, conflicts: [] });
  assert.equal((await a.syncOnce()).pushed, 0);
  assert.equal((await b.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(target, "renamed.txt"), "utf8"), "payload");
  const rootC = path.join(dir, "fresh-device");
  const c = await engine(rootC, adapter, key, { deviceId: "device-c" });
  assert.equal((await c.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(rootC, "renamed.txt"), "utf8"), "payload");
  assert.equal((await c.syncOnce()).pushed, 0);
  const moved = store.list("alice")[0];
  await a.enqueueChange({ operation: "delete", objectId: moved.objectId, fileId: moved.fileId, versionId: "delete-v1", baseRevision: moved.revision, revision: { counter: 3, deviceId: "device-a" }, metadata: { path: "renamed.txt" }, fileKey: key });
  await a.pushPending({ pushed: 0, conflicts: [] });
  await b.syncOnce();
  assert.equal(await fsp.stat(path.join(target, "renamed.txt")).then(() => true, () => false), false);
  assert.equal((await fsp.readdir(path.join(target, ".rootark-trash"))).length > 0, true);

  const wrong = await engine(path.join(dir, "wrong"), adapter, crypto.randomBytes(32), { keyEpoch: "epoch-1", deviceId: "revoked" });
  await assert.rejects(() => wrong.syncOnce());
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});

test("Phase 16 engine rejects legacy moves safely and preserves raw payloads when the source exists", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-legacy-move-"));
  const root = path.join(dir, "device");
  const key = crypto.randomBytes(32);
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "renamed.txt"), "keep-local-file");
  const rawLegacyPayload = Buffer.from("ROOTARK-SYNC-MOVE\0v1\0legacy file bytes with an invalid frame");
  assert.equal(protocol.decodeMovePayload(rawLegacyPayload, key), null);
  const operation = protocol.createOperation({
    operation: "move", objectId: "legacy-object", fileId: "legacy-file", versionId: "legacy-version",
    operationId: "legacy-move", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "nested/renamed.txt", sourcePath: "original.txt" }, plaintext: rawLegacyPayload, fileKey: key,
  });
  const sync = await engine(root, { async push() { return { status: 201 }; }, async list() { return []; } }, key);
  await assert.rejects(() => sync.apply(operation), { code: "move_source_missing" });
  assert.equal(await fsp.readFile(path.join(root, "renamed.txt"), "utf8"), "keep-local-file");
  assert.equal(await fsp.stat(path.join(root, "nested")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(root, ".rootark-trash")).then(() => true, () => false), false);

  await fsp.writeFile(path.join(root, "original.txt"), rawLegacyPayload);
  const legacyWithSource = protocol.createOperation({
    operation: "move", objectId: "legacy-object", fileId: "legacy-file", versionId: "legacy-version-2",
    operationId: "legacy-move-with-source", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 3, deviceId: "device-a" }, baseRevision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "nested/renamed.txt", sourcePath: "original.txt" }, plaintext: rawLegacyPayload, fileKey: key,
  });
  await sync.apply(legacyWithSource);
  assert.deepEqual(await fsp.readFile(path.join(root, "nested", "renamed.txt")), rawLegacyPayload);
  const framed = protocol.createOperation({
    operation: "move", objectId: "framed-object", fileId: "framed-file", versionId: "framed-version",
    operationId: "framed-move", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    metadata: { path: "nested/framed.txt", sourcePath: "missing-framed-source.txt" },
    plaintext: protocol.encodeMovePayload(rawLegacyPayload, key), fileKey: key,
  });
  await sync.apply(framed);
  assert.deepEqual(await fsp.readFile(path.join(root, "nested", "framed.txt")), rawLegacyPayload);
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});

test("Phase 16 engine type transitions replace stale snapshot directory state", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-type-transition-"));
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = await adapterFor(store, "alice", { offline: false });
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true });
  const a = await engine(rootA, adapter, key);
  await fsp.mkdir(path.join(rootA, "transition"));
  assert.equal((await a.syncOnce()).pushed, 1);
  const b = await engine(rootB, adapter, key, { deviceId: "device-b" });
  await b.syncOnce();

  await fsp.rmdir(path.join(rootA, "transition"));
  await fsp.writeFile(path.join(rootA, "transition"), "now a file");
  assert.equal((await a.syncOnce()).pushed, 1);
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "transition"), "utf8"), "now a file");
  assert.equal((await a.syncOnce()).pushed, 0);
  assert.equal((await b.syncOnce()).pushed, 0);

  await fsp.rm(path.join(rootA, "transition"));
  await fsp.mkdir(path.join(rootA, "transition"));
  assert.equal((await a.syncOnce()).pushed, 1);
  await b.syncOnce();
  assert.equal((await fsp.stat(path.join(rootB, "transition"))).isDirectory(), true);

  await fsp.rmdir(path.join(rootA, "transition"));
  await fsp.writeFile(path.join(rootA, "transition"), "recreated after tombstone");
  assert.equal((await a.syncOnce()).pushed, 1);
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "transition"), "utf8"), "recreated after tombstone");
  assert.equal((await a.syncOnce()).pushed, 0);
  assert.equal((await b.syncOnce()).pushed, 0);

  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});

test("Phase 16 peers prune implicit empty parents after remote move and delete", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-prune-parents-"));
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = await adapterFor(store, "alice", { offline: false });
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(path.join(rootA, "implicit"), { recursive: true });
  await fsp.writeFile(path.join(rootA, "implicit", "move.txt"), "move me");
  await fsp.writeFile(path.join(rootA, "implicit", "delete.txt"), "delete me");
  const a = await engine(rootA, adapter, key);
  await a.syncOnce();
  const b = await engine(rootB, adapter, key, { deviceId: "device-b" });
  await b.syncOnce();

  const records = store.list("alice");
  const moveRecord = records.find((record) => record.metadata.path === "implicit/move.txt");
  const deleteRecord = records.find((record) => record.metadata.path === "implicit/delete.txt");
  const moved = protocol.createOperation({
    operation: "move", objectId: moveRecord.objectId, fileId: moveRecord.fileId,
    versionId: "implicit-move-v2", operationId: "implicit-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moveRecord.revision, revision: { counter: moveRecord.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "moved/move.txt", sourcePath: "implicit/move.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("move me"), key), fileKey: key,
  });
  const deleted = protocol.createOperation({
    operation: "delete", objectId: deleteRecord.objectId, fileId: deleteRecord.fileId,
    versionId: "implicit-delete-v2", operationId: "implicit-delete-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: deleteRecord.revision, revision: { counter: deleteRecord.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "implicit/delete.txt" }, plaintext: Buffer.alloc(0), fileKey: key,
  });
  await store.put("alice", moved);
  await store.put("alice", deleted);
  await b.syncOnce();
  assert.equal(await fsp.stat(path.join(rootB, "implicit")).then(() => true, () => false), false);
  assert.equal(await fsp.readFile(path.join(rootB, "moved", "move.txt"), "utf8"), "move me");
  assert.equal((await b.syncOnce()).pushed, 0);

  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});

test("Phase 16 engine rejects malicious metadata before local apply", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-input-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "safe.txt"), "safe");
  const key = crypto.randomBytes(32);
  const valid = protocol.createOperation({ operation: "create", objectId: "object-safe", fileId: "file-safe", versionId: "version-safe", operationId: "operation-safe", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "safe.txt" }, plaintext: Buffer.from("changed"), fileKey: key });
  const malicious = { ...valid, metadata: { ...valid.metadata, path: "../escape.txt" } };
  const adapter = { async push() { return { status: 201 }; }, async list() { return [malicious]; } };
  const sync = await engine(root, adapter, key);
  await assert.rejects(() => sync.syncOnce());
  assert.equal(await fsp.readFile(path.join(root, "safe.txt"), "utf8"), "safe");
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});
