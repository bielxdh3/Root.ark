"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

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
    async list(objectId = "") {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      if (objectId && state.missingObjectId === objectId) return [];
      return store.list(username, objectId || null);
    },
  };
}

async function engine(rootDir, adapter, key, options = {}) {
  return new SyncEngine({
    rootDir, adapter, deviceId: options.deviceId || "device-a", keyEpoch: options.keyEpoch || "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, authorize: options.authorize, selectedPaths: options.selectedPaths,
  }).open();
}

test("sync path validation reserves active and initializing process lock files", () => {
  const reservedPaths = [
    ".rootark-sync.lock",
    ".rootark-sync-lock-init-123-token",
    "nested/.rootark-sync.lock",
  ];
  for (const reservedPath of reservedPaths) {
    assert.throws(() => protocol.safeRelativePath(reservedPath, "path"), { code: "invalid_operation" });
  }

  const browserContext = { atob: globalThis.atob, btoa: globalThis.btoa, TextDecoder: globalThis.TextDecoder };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, "../public/client/rootark-sync-adapter.js"), "utf8"), browserContext);
  const operation = protocol.createOperation({
    operation: "create", objectId: "reserved-path-test", deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "safe.txt" },
    fileKey: Buffer.alloc(32, 1),
  });
  for (const reservedPath of reservedPaths) {
    assert.throws(() => browserContext.RootarkSyncAdapter.assertOpaqueEnvelope({
      ...operation,
      metadata: { ...operation.metadata, path: reservedPath },
    }));
  }
});

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

test("selective sync materializes only selected remote paths on each device", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-selective-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const state = { offline: false };
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", state);
  const source = path.join(dir, "source");
  await fsp.mkdir(path.join(source, "selected"), { recursive: true });
  await fsp.mkdir(path.join(source, "excluded"), { recursive: true });
  await fsp.writeFile(path.join(source, "selected", "chosen.txt"), "selected payload");
  await fsp.writeFile(path.join(source, "excluded", "deferred.txt"), "deferred payload");
  await (await engine(source, adapter, key)).syncOnce();
  const remote = store.list("alice");
  const deferred = remote.find((record) => record.metadata.path === "excluded/deferred.txt");

  const rootA = path.join(dir, "device-a");
  assert.equal((await (await engine(rootA, adapter, key)).syncOnce()).pulled, 2);
  await fsp.unlink(path.join(rootA, "excluded", "deferred.txt"));
  const deviceA = await engine(rootA, adapter, key, { selectedPaths: ["selected"] });
  assert.equal((await deviceA.syncOnce()).pushed, 0);
  assert.equal(await fsp.readFile(path.join(rootA, "selected", "chosen.txt"), "utf8"), "selected payload");
  assert.equal(await fsp.stat(path.join(rootA, "excluded", "deferred.txt")).then(() => true, () => false), false);
  assert.equal(deviceA.snapshot.remoteOnly[deferred.objectId].reason, "excluded");
  assert.equal(store.list("alice").find((record) => record.objectId === deferred.objectId).tombstone, false);

  const rootB = path.join(dir, "device-b");
  const deviceB = await engine(rootB, adapter, key, { deviceId: "device-b", selectedPaths: ["selected"] });
  assert.equal((await deviceB.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(rootB, "selected", "chosen.txt"), "utf8"), "selected payload");
  assert.equal(await fsp.stat(path.join(rootB, "excluded", "deferred.txt")).then(() => true, () => false), false);
  assert.equal(deviceB.snapshot.remoteOnly[deferred.objectId].reason, "excluded");

  const rootC = path.join(dir, "device-c");
  const deviceC = await engine(rootC, adapter, key, { deviceId: "device-c", selectedPaths: ["excluded"] });
  assert.equal((await deviceC.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(rootC, "excluded", "deferred.txt"), "utf8"), "deferred payload");
});

test("selective sync hydrates a remote move when its destination is selected", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-selective-move-in-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const source = path.join(dir, "source");
  await fsp.mkdir(path.join(source, "excluded"), { recursive: true });
  await fsp.writeFile(path.join(source, "excluded", "chosen.txt"), "selected after move");
  const owner = await engine(source, adapter, key);
  await owner.syncOnce();
  const prior = store.list("alice")[0];

  const device = await engine(path.join(dir, "device"), adapter, key, { selectedPaths: ["selected"] });
  await device.syncOnce();
  assert.equal(device.snapshot.remoteOnly[prior.objectId].reason, "excluded");

  const move = protocol.createOperation({
    operation: "move", objectId: prior.objectId, fileId: prior.fileId, versionId: "selective-move-v2",
    operationId: "selective-move-v2-op", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision, revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "selected/chosen.txt", sourcePath: "excluded/chosen.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("selected after move"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");

  assert.equal((await device.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(dir, "device", "selected", "chosen.txt"), "utf8"), "selected after move");
  assert.equal(device.snapshot.remoteOnly[prior.objectId], undefined);
});

test("conflict recovery does not materialize the remote version outside selected scope", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-selective-conflict-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const root = path.join(dir, "device");
  await fsp.mkdir(path.join(root, "selected"), { recursive: true });
  await fsp.writeFile(path.join(root, "selected", "file.txt"), "local version");
  const remote = protocol.createOperation({
    operation: "move", objectId: "conflict-object", fileId: "conflict-file", versionId: "remote-v2",
    operationId: "remote-move-out-of-scope", deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: { counter: 1, deviceId: "device-a" }, revision: { counter: 2, deviceId: "device-b" },
    metadata: { path: "excluded/file.txt", sourcePath: "selected/file.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("remote version"), key), fileKey: key,
  });
  const adapter = {
    async push() { throw Object.assign(new Error("conflict"), { code: "sync_conflict", status: 409, current: remote }); },
    async list() { return []; },
  };
  const sync = await engine(root, adapter, key, { selectedPaths: ["selected"] });
  sync.snapshot.files["selected/file.txt"] = {
    objectId: "conflict-object", fileId: "conflict-file", versionId: "local-v1",
    revision: { counter: 1, deviceId: "device-a" }, hash: crypto.createHash("sha256").update("local version").digest("hex"),
    deleted: false, directory: false,
  };
  await sync.enqueueChange({
    operation: "update", objectId: "conflict-object", fileId: "conflict-file", versionId: "local-v2",
    baseRevision: { counter: 1, deviceId: "device-a" }, revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "selected/file.txt" }, fileKey: key,
  });

  const summary = await sync.syncOnce();
  assert.equal(summary.conflicts.length, 1);
  assert.equal(await fsp.readFile(path.join(root, "selected", "file.txt"), "utf8"), "local version");
  assert.equal(await fsp.stat(path.join(root, "excluded", "file.txt")).then(() => true, () => false), false);
  assert.equal(sync.snapshot.remoteOnly["conflict-object"].path, "excluded/file.txt");
});

test("cache eviction serializes against reconciliation so its intent cannot be cleared", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-eviction-race-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const source = path.join(dir, "source");
  await fsp.mkdir(source, { recursive: true });
  await fsp.writeFile(path.join(source, "cached.txt"), "verified remote bytes");
  await (await engine(source, adapter, key)).syncOnce();
  const root = path.join(dir, "device");
  const sync = await engine(root, adapter, key);
  await sync.syncOnce();
  const concurrentEngine = await engine(root, adapter, key);

  let enterStage;
  let releaseStage;
  const stageStarted = new Promise((resolve) => { enterStage = resolve; });
  const stageBlocked = new Promise((resolve) => { releaseStage = resolve; });
  const stageExisting = sync.stageExisting.bind(sync);
  sync.stageExisting = async (...args) => {
    enterStage();
    await stageBlocked;
    return stageExisting(...args);
  };
  const eviction = sync.evictLocal("cached.txt");
  await stageStarted;
  const busyWriterScript = "const { SyncEngine } = require(process.argv[1]); const engine = new SyncEngine({ rootDir: process.argv[2], adapter: { async push() { return { status: 201 }; }, async list() { return []; } }, deviceId: 'other-device', keyEpoch: 'epoch-1', compartmentId: 'private', fileKey: Buffer.alloc(32) }); engine.syncOnce().then(() => process.exit(4), (error) => process.exit(error.code === 'sync_root_busy' ? 0 : 5));";
  execFileSync(process.execPath, ["-e", busyWriterScript, require.resolve("../sync-client/rootark-sync-engine"), root], {
    cwd: path.resolve(__dirname, ".."), stdio: "pipe",
  });
  const concurrentSync = concurrentEngine.syncOnce();
  const current = store.list("alice")[0];
  const queuedUpdate = sync.enqueueChange({
    operation: "update", objectId: current.objectId, fileId: current.fileId, versionId: "after-eviction-update",
    baseRevision: current.revision, revision: { counter: current.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "cached.txt" }, plaintext: Buffer.from("must not race eviction"), fileKey: key,
  });
  releaseStage();
  await eviction;
  await concurrentSync;
  await assert.rejects(queuedUpdate, { code: "remote_only_object" });
  sync.stageExisting = stageExisting;

  assert.equal(sync.snapshot.remoteOnly[store.list("alice")[0].objectId].reason, "evicted");
  assert.equal(concurrentEngine.snapshot.remoteOnly[store.list("alice")[0].objectId].reason, "evicted");
  assert.equal((await sync.syncOnce()).pushed, 0);
  assert.equal(store.list("alice")[0].tombstone, false);
});

test("abandoned process-lock initialization files neither block sync nor enter the remote index", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-sync-lock-init-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const root = path.join(dir, "device");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, ".rootark-sync-lock-init-crashed-writer"), "partial owner record");

  const sync = await engine(root, adapter, key);
  assert.equal((await sync.syncOnce()).pushed, 0);
  assert.equal(sync.snapshot.files[".rootark-sync-lock-init-crashed-writer"], undefined);
  assert.equal(store.list("alice").length, 0);
});

test("an abandoned process lock directory fails closed and is left for explicit recovery", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-sync-lock-stale-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const root = path.join(dir, "device");
  await fsp.mkdir(root, { recursive: true });
  const lockPath = path.join(root, ".rootark-sync.lock");
  await fsp.mkdir(lockPath, { mode: 0o700 });

  await assert.rejects(engine(root, adapter, key), { code: "sync_root_busy" });
  assert.equal((await fsp.lstat(lockPath)).isDirectory(), true);
  assert.deepEqual(await fsp.readdir(lockPath), []);

  await fsp.rmdir(lockPath);
  const legacyLock = "legacy lock record\n";
  const legacyHandle = await fsp.open(lockPath, "wx+", 0o600);
  try {
    await legacyHandle.writeFile(legacyLock);
    await assert.rejects(engine(root, adapter, key), { code: "sync_root_busy" });
    const contents = Buffer.alloc(Buffer.byteLength(legacyLock));
    const { bytesRead } = await legacyHandle.read(contents, 0, contents.length, 0);
    assert.equal(contents.subarray(0, bytesRead).toString("utf8"), legacyLock);
    assert.equal(store.list("alice").length, 0);
  } finally {
    await legacyHandle.close();
  }
});

test("Windows reconciliation protects pending paths across filename casing", { skip: process.platform !== "win32" }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-pending-case-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const root = path.join(dir, "device");
  await fsp.mkdir(path.join(root, "Folder"), { recursive: true });
  await fsp.writeFile(path.join(root, "Folder", "pending.txt"), "pending operation payload");
  const sync = await engine(root, adapter, key, { selectedPaths: ["folder"] });
  const pending = protocol.createOperation({
    operation: "create", objectId: "pending-object", fileId: "pending-file", versionId: "pending-v1",
    operationId: "pending-case-operation", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "folder/pending.txt", name: "pending.txt", size: Buffer.byteLength("pending operation payload") },
    plaintext: Buffer.from("pending operation payload"), fileKey: key,
  });
  await sync.journal.enqueue(pending);

  await sync.reconcileLocal();

  assert.deepEqual((await sync.journal.recover()).map((operation) => operation.operationId), [pending.operationId]);
});

test("selected path matching follows Windows case-insensitive paths", { skip: process.platform !== "win32" }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-selective-windows-case-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", { offline: false });
  const source = path.join(dir, "source");
  await fsp.mkdir(path.join(source, "folder"), { recursive: true });
  await fsp.writeFile(path.join(source, "folder", "file.txt"), "case-insensitive match");
  await (await engine(source, adapter, key)).syncOnce();

  const root = path.join(dir, "device");
  const selected = await engine(root, adapter, key, { selectedPaths: ["Folder"] });
  assert.equal((await selected.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(root, "Folder", "file.txt"), "utf8"), "case-insensitive match");
});

test("cache eviction preserves the remote object and explicit materialization verifies its payload", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-cache-eviction-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const state = { offline: false };
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", state);
  const source = path.join(dir, "source");
  await fsp.mkdir(source, { recursive: true });
  await fsp.writeFile(path.join(source, "cached.txt"), "remote cache payload");
  await (await engine(source, adapter, key)).syncOnce();
  const before = store.list("alice")[0];
  const root = path.join(dir, "device");
  const sync = await engine(root, adapter, key);
  await sync.syncOnce();

  assert.equal(await sync.evictLocal("cached.txt"), true);
  assert.equal(await fsp.stat(path.join(root, "cached.txt")).then(() => true, () => false), false);
  assert.equal((await sync.syncOnce()).pushed, 0);
  const after = store.list("alice")[0];
  assert.equal(after.operationId, before.operationId);
  assert.equal(after.tombstone, false);
  assert.equal(sync.snapshot.remoteOnly[before.objectId].reason, "evicted");

  assert.equal(await sync.materializeRemote("cached.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "cached.txt"), "utf8"), "remote cache payload");
  assert.equal(sync.snapshot.remoteOnly[before.objectId], undefined);
});

test("cache eviction fails closed when the remote object is missing, deleted, or offline", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-cache-preflight-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const state = { offline: false };
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", state);
  const source = path.join(dir, "source");
  await fsp.mkdir(source, { recursive: true });
  await fsp.writeFile(path.join(source, "cached.txt"), "remote cache payload");
  await (await engine(source, adapter, key)).syncOnce();
  const current = store.list("alice")[0];
  const root = path.join(dir, "device");
  const sync = await engine(root, adapter, key);
  await sync.syncOnce();
  const localPath = path.join(root, "cached.txt");

  state.missingObjectId = current.objectId;
  await assert.rejects(() => sync.evictLocal("cached.txt"), { code: "remote_object_missing" });
  assert.equal(await fsp.readFile(localPath, "utf8"), "remote cache payload");
  state.missingObjectId = null;

  const deletion = protocol.createOperation({
    operation: "delete", objectId: current.objectId, fileId: current.fileId, versionId: "cache-delete-v2",
    operationId: "cache-delete-op", deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: current.revision, revision: { counter: current.revision.counter + 1, deviceId: "device-b" },
    metadata: { path: "cached.txt" }, plaintext: Buffer.alloc(0), fileKey: key,
  });
  assert.equal((await store.put("alice", deletion)).kind, "stored");
  await assert.rejects(() => sync.evictLocal("cached.txt"), { code: "remote_object_deleted" });
  assert.equal(await fsp.readFile(localPath, "utf8"), "remote cache payload");

  state.offline = true;
  await assert.rejects(() => sync.evictLocal("cached.txt"), { code: "offline" });
  assert.equal(await fsp.readFile(localPath, "utf8"), "remote cache payload");
  assert.equal(sync.snapshot.remoteOnly[current.objectId], undefined);
});

test("selective remote-only state survives restart and reconnect with a changed scope", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-selective-restart-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const state = { offline: false };
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const adapter = await adapterFor(store, "alice", state);
  const source = path.join(dir, "source");
  await fsp.mkdir(path.join(source, "selected"), { recursive: true });
  await fsp.mkdir(path.join(source, "other"), { recursive: true });
  await fsp.writeFile(path.join(source, "selected", "one.txt"), "one");
  await fsp.writeFile(path.join(source, "other", "two.txt"), "two");
  await (await engine(source, adapter, key)).syncOnce();

  const root = path.join(dir, "device");
  const first = await engine(root, adapter, key, { selectedPaths: ["selected"] });
  await first.syncOnce();
  const other = store.list("alice").find((record) => record.metadata.path === "other/two.txt");
  const selected = store.list("alice").find((record) => record.metadata.path === "selected/one.txt");
  assert.equal(first.snapshot.remoteOnly[other.objectId].reason, "excluded");

  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const interrupted = JSON.parse(await fsp.readFile(snapshotPath, "utf8"));
  interrupted.remoteOnly[selected.objectId] = {
    objectId: selected.objectId, fileId: selected.fileId, versionId: selected.versionId,
    revision: selected.revision, path: selected.metadata.path, directory: false,
    deleted: false, reason: "evicted", hash: first.snapshot.files[selected.metadata.path].hash,
  };
  await fsp.writeFile(snapshotPath, JSON.stringify(interrupted));

  state.offline = true;
  const restarted = await engine(root, adapter, key, { selectedPaths: ["selected"] });
  assert.equal((await restarted.syncOnce()).offline, true);
  assert.equal(restarted.snapshot.remoteOnly[other.objectId].path, "other/two.txt");
  assert.equal(restarted.snapshot.remoteOnly[selected.objectId], undefined);

  state.offline = false;
  const reconnected = await engine(root, adapter, key, { selectedPaths: ["other"] });
  assert.equal((await reconnected.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(root, "other", "two.txt"), "utf8"), "two");
  assert.equal(reconnected.snapshot.remoteOnly[other.objectId], undefined);
});

test("successful sync commits the payload hash captured before push", { timeout: 30_000 }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-push-snapshot-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);

  async function exercise(root, prepare) {
    await fsp.mkdir(root, { recursive: true });
    const accepted = [];
    let enterPush;
    let releasePush;
    const entered = new Promise((resolve) => { enterPush = resolve; });
    const blocked = new Promise((resolve) => { releasePush = resolve; });
    let blockFirstPush = true;
    const adapter = {
      async push(operation) {
        const decrypted = protocol.decryptPayload(operation, key);
        const plaintext = operation.operation === "move"
          ? protocol.decodeMovePayload(decrypted, key) || decrypted
          : decrypted;
        accepted.push({ operation, plaintext: Buffer.from(plaintext) });
        if (blockFirstPush) {
          blockFirstPush = false;
          enterPush();
          await blocked;
        }
        return { status: 201 };
      },
      async list() { return []; },
    };
    const sync = await engine(root, adapter, key);
    await prepare(sync, root);
    const firstSync = sync.syncOnce();
    await entered;
    await fsp.writeFile(path.join(root, "target.txt"), "D2 after push began");
    releasePush();
    await firstSync;
    assert.equal(accepted[0].plaintext.toString("utf8"), "D1 captured before push");

    const next = await sync.syncOnce();
    assert.equal(next.pushed, 1);
    assert.equal(accepted[1].plaintext.toString("utf8"), "D2 after push began");
    return accepted;
  }

  await t.test("create/update payload", async () => {
    const root = path.join(dir, "ordinary");
    await fsp.mkdir(root, { recursive: true });
    await fsp.writeFile(path.join(root, "target.txt"), "D1 captured before push");
    const accepted = await exercise(root, async () => {});
    assert.equal(accepted[0].operation.operation, "create");
    assert.equal(accepted[1].operation.operation, "update");
  });

  await t.test("MOVE payload", async () => {
    const root = path.join(dir, "move");
    const target = path.join(root, "target.txt");
    await fsp.mkdir(root, { recursive: true });
    await fsp.writeFile(target, "D1 captured before push");
    const accepted = await exercise(root, async (sync) => {
      sync.snapshot.files["source.txt"] = {
        objectId: "move-object", fileId: "move-file", versionId: "move-v1",
        revision: { counter: 1, deviceId: "device-a" }, hash: crypto.createHash("sha256").update("D1 captured before push").digest("hex"),
        deleted: false, directory: false,
      };
      await sync.enqueueChange({
        operation: "move", objectId: "move-object", fileId: "move-file", versionId: "move-v2",
        baseRevision: { counter: 1, deviceId: "device-a" }, revision: { counter: 2, deviceId: "device-a" },
        metadata: { path: "target.txt", sourcePath: "source.txt" },
      });
    });
    assert.equal(accepted[0].operation.operation, "move");
    assert.equal(accepted[1].operation.operation, "update");
  });
});

test("sync does not block when a checked file is replaced by a FIFO", { skip: process.platform === "win32", timeout: 30_000 }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-sync-fifo-"));
  const root = path.join(dir, "root");
  const target = path.join(root, "document.txt");
  const fifo = path.join(root, "replacement.fifo");
  const key = crypto.randomBytes(32);
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(target, "checked regular file");
  execFileSync("mkfifo", [fifo]);
  const sync = await engine(root, { async push() { return { status: 201 }; }, async list() { return []; } }, key);
  const originalOpen = fsp.open;
  let swapped = false;
  fsp.open = async (filePath, flags, ...args) => {
    if (!swapped && path.resolve(String(filePath)) === target) {
      swapped = true;
      await fsp.rename(target, `${target}.original`);
      await fsp.rename(fifo, target);
    }
    return originalOpen(filePath, flags, ...args);
  };
  try {
    let completed = false;
    const read = sync.reconcileLocal().then((value) => { completed = true; return value; }, (error) => { completed = true; throw error; });
    const settledEarly = await Promise.race([
      read.then(() => true, () => true),
      new Promise((resolve) => setTimeout(() => resolve(false), 250)),
    ]);
    if (!settledEarly) {
      const unblock = await originalOpen(target, fs.constants.O_WRONLY);
      await unblock.close();
    }
    await assert.rejects(read, { code: "unsafe_path" });
    assert.equal(swapped, true);
    assert.equal(completed, true);
    assert.equal(settledEarly, true, "opening a raced FIFO must return without waiting for a writer");
  } finally {
    fsp.open = originalOpen;
    await fsp.rm(dir, { recursive: true, force: true });
  }
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
  sync.snapshot.files["original.txt"] = {
    objectId: "legacy-object", fileId: "legacy-file", versionId: "legacy-version",
    revision: { counter: 2, deviceId: "device-a" }, deleted: false, directory: false,
  };
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

test("Phase 16 MOVE never renames an unrelated local source when the recovery payload is authoritative", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-move-identity-"));
  const root = path.join(dir, "device");
  const key = crypto.randomBytes(32);
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "source.txt"), "unrelated local bytes");
  const sync = await engine(root, { async push() { return { status: 201 }; }, async list() { return []; } }, key);
  sync.snapshot.files["source.txt"] = {
    objectId: "unrelated-object", fileId: "unrelated-file", versionId: "unrelated-version",
    revision: { counter: 1, deviceId: "device-local" }, hash: crypto.createHash("sha256").update("unrelated local bytes").digest("hex"),
    deleted: false, directory: false,
  };

  const operation = protocol.createOperation({
    operation: "move", objectId: "remote-object", fileId: "remote-file", versionId: "remote-version",
    operationId: "remote-move-with-payload", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "destination.txt", sourcePath: "source.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("authenticated remote bytes"), key), fileKey: key,
  });
  await sync.apply(operation);

  assert.equal(await fsp.readFile(path.join(root, "source.txt"), "utf8"), "unrelated local bytes");
  assert.equal(sync.snapshot.files["source.txt"].objectId, "unrelated-object");
  assert.equal(await fsp.readFile(path.join(root, "destination.txt"), "utf8"), "authenticated remote bytes");
  assert.equal(sync.snapshot.files["destination.txt"].objectId, "remote-object");

  const legacyWithoutIdentity = protocol.createOperation({
    operation: "move", objectId: "legacy-untracked-object", fileId: "legacy-untracked-file", versionId: "legacy-version",
    operationId: "legacy-move-without-identity", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    metadata: { path: "legacy-destination.txt", sourcePath: "source.txt" },
    plaintext: Buffer.from("legacy move has no payload frame"), fileKey: key,
  });
  await assert.rejects(() => sync.apply(legacyWithoutIdentity), { code: "move_source_missing" });
  assert.equal(await fsp.readFile(path.join(root, "source.txt"), "utf8"), "unrelated local bytes");
  assert.equal(await fsp.stat(path.join(root, "legacy-destination.txt")).then(() => true, () => false), false);

  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});

test("Phase 16 DELETE ignores a reused path when no local identity matches the tombstone", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-delete-identity-"));
  const root = path.join(dir, "device");
  const key = crypto.randomBytes(32);
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "reused.txt"), "unrelated current bytes");
  const sync = await engine(root, { async push() { return { status: 201 }; }, async list() { return []; } }, key);
  sync.snapshot.files["reused.txt"] = {
    objectId: "current-object", fileId: "current-file", versionId: "current-version",
    revision: { counter: 1, deviceId: "device-local" },
    hash: crypto.createHash("sha256").update("unrelated current bytes").digest("hex"),
    deleted: false, directory: false,
  };
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: "deleted-object", fileId: "deleted-file", versionId: "deleted-version",
    operationId: "stale-delete-reused-path", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "reused.txt" }, plaintext: Buffer.alloc(0), fileKey: key,
  });

  await sync.apply(tombstone);

  assert.equal(await fsp.readFile(path.join(root, "reused.txt"), "utf8"), "unrelated current bytes");
  assert.equal(sync.snapshot.files["reused.txt"].objectId, "current-object");
  assert.equal(sync.snapshot.files["reused.txt"].deleted, false);
  assert.equal(await fsp.stat(path.join(root, ".rootark-trash")).then(() => true, () => false), false);
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

test("Phase 16 filesystem recreation after a synced delete uses a fresh identity", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-engine-recreate-identity-"));
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = await adapterFor(store, "alice", { offline: false });
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true });
  await fsp.writeFile(path.join(rootA, "recreated.txt"), "first incarnation");
  const a = await engine(rootA, adapter, key);
  assert.equal((await a.syncOnce()).pushed, 1);
  const originalIdentity = { ...a.snapshot.files["recreated.txt"] };
  const b = await engine(rootB, adapter, key, { deviceId: "device-b" });
  await b.syncOnce();

  await fsp.rm(path.join(rootA, "recreated.txt"));
  assert.equal((await a.syncOnce()).pushed, 1);
  await b.syncOnce();
  assert.equal(await fsp.stat(path.join(rootB, "recreated.txt")).then(() => true, () => false), false);

  await fsp.writeFile(path.join(rootA, "recreated.txt"), "second incarnation");
  assert.equal((await a.syncOnce()).pushed, 1);
  const recreatedIdentity = a.snapshot.files["recreated.txt"];
  assert.notEqual(recreatedIdentity.objectId, originalIdentity.objectId);
  assert.notEqual(recreatedIdentity.fileId, originalIdentity.fileId);
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "recreated.txt"), "utf8"), "second incarnation");
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

test("Phase 16 move reads stay bound to the checked file identity", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-file-race-"));
  const root = path.join(dir, "root");
  const raced = path.join(root, "raced.txt");
  const replacement = path.join(root, "replacement.txt");
  const ordinary = path.join(root, "ordinary.txt");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(raced, "inside payload");
  await fsp.writeFile(replacement, "replacement payload");
  await fsp.writeFile(ordinary, "ordinary payload");
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));

  const key = crypto.randomBytes(32);
  const sync = await engine(root, { async push() { return { status: 201 }; }, async list() { return []; } }, key);
  const fspOpen = fsp.open;
  fsp.open = async (filePath, ...args) => {
    if (path.resolve(String(filePath)) === path.resolve(raced)) {
      await fsp.unlink(raced);
      await fsp.rename(replacement, raced);
    }
    return fspOpen.call(fsp, filePath, ...args);
  };
  const base = {
    operation: "move", objectId: "object-race", fileId: "file-race", versionId: "version-race",
    operationId: "operation-race", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, fileKey: key,
  };
  try {
    await assert.rejects(() => sync.buildOperation({ ...base, metadata: { path: "raced.txt", sourcePath: "previous.txt" } }), { code: "unsafe_path" });
    const ordinaryMove = await sync.buildOperation({ ...base, operationId: "ordinary-move", metadata: { path: "ordinary.txt", sourcePath: "old.txt" } });
    const payload = protocol.decodeMovePayload(protocol.decryptPayload(ordinaryMove, key), key);
    assert.deepEqual(payload, Buffer.from("ordinary payload"));
  } finally {
    fsp.open = fspOpen;
  }
});
