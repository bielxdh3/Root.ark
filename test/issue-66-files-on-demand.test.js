"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");

async function setup(t, files) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-on-demand-"));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  const store = await new SyncObjectStore(path.join(directory, "objects.json")).open();
  const state = { offline: false, fullReads: [], inventoryReads: 0, pushes: 0 };
  const adapter = {
    async push(operation) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.pushes++;
      const result = await store.put("alice", operation);
      return { status: 201, record: result.record };
    },
    async list(objectId = "") {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.fullReads.push(objectId || "ALL");
      return store.list("alice", objectId || null);
    },
    async listInventory({ limit = 64, cursor = null } = {}) {
      if (state.offline) throw Object.assign(new Error("offline"), { code: "offline" });
      state.inventoryReads++;
      const inventory = store.list("alice")
        .sort((a, b) => a.objectId.localeCompare(b.objectId))
        .map(({ ciphertext, nonce, tag, aad, authorization, ...record }) => record);
      const start = cursor === null ? 0 : Number(cursor);
      return { protocolVersion: 2, view: "metadata", objects: inventory.slice(start, start + limit),
        nextCursor: start + limit < inventory.length ? String(start + limit) : null };
    },
  };
  const source = path.join(directory, "source");
  for (const [relative, body] of Object.entries(files)) {
    await fsp.mkdir(path.dirname(path.join(source, relative)), { recursive: true });
    await fsp.writeFile(path.join(source, relative), body);
  }
  const writer = await new SyncEngine({
    rootDir: source, adapter, deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
  }).open();
  await writer.syncOnce();
  state.fullReads.length = 0;
  state.inventoryReads = 0;
  state.pushes = 0;
  const root = path.join(directory, "consumer");
  const open = (selectedPaths = ["docs"]) => new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, selectedPaths,
    filesOnDemand: true,
  }).open();
  return { root, source, writer, open, adapter, state, store, key };
}

async function exists(filePath) {
  return fsp.stat(filePath).then(() => true, () => false);
}

async function seedRemote(store, key, relative, objectId = `external-${crypto.randomUUID()}`) {
  const operation = protocol.createOperation({
    operation: "create", objectId, fileId: `file-${crypto.randomUUID()}`,
    versionId: `version-${crypto.randomUUID()}`, operationId: `operation-${crypto.randomUUID()}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: relative, name: path.posix.basename(relative), size: 15 },
    plaintext: Buffer.from("remote original"), fileKey: key,
  });
  assert.equal((await store.put("alice", operation)).kind, "stored");
  return operation;
}

test("issue 66 P2: a fresh local CREATE cannot duplicate an existing remote opaque path", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  const remote = await seedRemote(store, key, "docs/collision.txt");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "collision.txt"), "different local content");
  const client = await open();
  await assert.rejects(client.syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0, "no CREATE may be sent before remote-path preflight");
  assert.equal(state.fullReads.length, 0, "preflight must not fetch the full ciphertext inventory");
  assert.equal(store.list("alice").length, 1);
  assert.equal(store.list("alice")[0].operationId, remote.operationId);
  assert.equal(await fsp.readFile(path.join(root, "docs", "collision.txt"), "utf8"), "different local content");
  await assert.rejects(client.materializeRemote("docs/collision.txt"), { code: "local_changes_pending" });
  const resumed = await open();
  await assert.rejects(resumed.syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
});

test("issue 66 P2: tombstoned remote path does not block a new Files On-Demand CREATE", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  const original = await seedRemote(store, key, "docs/reused.txt");
  const removed = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: original.revision,
    metadata: { path: "docs/reused.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", removed)).kind, "stored");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "reused.txt"), "new independent local file");
  const client = await open();
  const summary = await client.syncOnce();
  assert.equal(summary.pushed, 1);
  assert.equal(state.pushes, 1);
  assert.equal((await client.journal.recover()).length, 0);
  const versions = store.list("alice");
  assert.equal(versions.filter((record) => !record.tombstone && record.metadata.path === "docs/reused.txt").length, 1);
  assert.equal(versions.filter((record) => record.tombstone).length, 1);
});

test("issue 66 P2: an offline CREATE stays queued; reconnect rechecks remote identity before push", async (t) => {
  const { root, open, store, state, key } = await setup(t, {});
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "collision.txt"), "local offline version");
  state.offline = true;
  const offline = await open();
  assert.equal((await offline.syncOnce()).offline, true);
  assert.equal(state.pushes, 0);
  assert.equal((await offline.journal.recover()).length, 1);
  await seedRemote(store, key, "docs/collision.txt");
  state.offline = false;
  const restarted = await open();
  await assert.rejects(restarted.syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
  assert.equal((await restarted.journal.recover()).length, 1);
});

test("issue 66 P2: stale or invalid paged inventory fails closed before CREATE, then retries", async (t) => {
  const { root, open, adapter, store, key, state } = await setup(t, {});
  await seedRemote(store, key, "docs/other.txt");
  await seedRemote(store, key, "docs/collision.txt");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "collision.txt"), "local same path");
  const listInventory = adapter.listInventory;
  adapter.listInventory = async (params) => {
    const page = await listInventory({ ...params, limit: 1 });
    if (params.cursor !== null) throw Object.assign(new Error("stale inventory cursor"), { status: 409 });
    return page;
  };
  const client = await open();
  await assert.rejects(client.syncOnce(), { code: "inventory_changed" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 2);
  assert.equal((await client.journal.recover()).length, 1,
    "stale inventory must not consume or mark the queued CREATE seen");
  adapter.listInventory = listInventory;
  await assert.rejects((await open()).syncOnce(), { code: "remote_path_collision" });
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 2);
});

test("issue 66 P2: unrelated local CREATE still publishes after a clean metadata preflight", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  await seedRemote(store, key, "docs/existing.txt");
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "new.txt"), "brand new");
  const client = await open();
  const summary = await client.syncOnce();
  assert.equal(summary.pushed, 1);
  assert.equal(state.pushes, 1);
  assert.equal(state.fullReads.length, 0);
  assert.deepEqual(store.list("alice").map((r) => r.metadata.path).sort(),
    ["docs/existing.txt", "docs/new.txt"]);
});

test("issue 66: lazy sync pages metadata and hydrates only the selected signed object", async (t) => {
  const { root, open, state, store } = await setup(t, {
    "docs/a.txt": "first payload", "docs/b.txt": "second payload", "private/secret.txt": "private",
  });
  const client = await open();
  const summary = await client.syncOnce();
  assert.equal(summary.pulled, 0);
  assert.equal(summary.available, 2);
  assert.ok(state.inventoryReads >= 1);
  assert.deepEqual(state.fullReads, []);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  const listing = await client.browseRemoteInventory({ limit: 2 });
  assert.equal(listing.objects.length, 2);
  assert.equal(listing.objects.every((record) =>
    record.selectedOnDevice === record.metadata.path.startsWith("docs/")), true);
  assert.equal(Object.keys(client.snapshot.remoteOnly).length, 0, "unsigned inventory cannot create durable pins");

  assert.equal(await client.materializeRemote("docs/b.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"), "second payload");
  const objectId = store.list("alice").find((item) => item.metadata.path === "docs/b.txt").objectId;
  assert.deepEqual(state.fullReads, [objectId]);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  await assert.rejects(client.materializeRemote("private/secret.txt"), { code: "path_not_selected" });

  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"), "second payload");
  assert.equal(store.list("alice").every((item) => item.tombstone === false), true);
});

test("issue 66: forged inventory, races, and preexisting local data fail closed", async (t) => {
  const { root, open, adapter, state } = await setup(t, { "docs/a.txt": "authentic" });
  const client = await open();
  const listInventory = adapter.listInventory;
  adapter.listInventory = async (request) => {
    const result = await listInventory(request);
    return { ...result, objects: result.objects.map((item) => ({
      ...item, versionId: "forged-version",
    })) };
  };
  await assert.rejects(client.materializeRemote("docs/a.txt"), { code: "inventory_changed" });
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  adapter.listInventory = listInventory;

  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "a.txt"), "unsynced local data");
  await assert.rejects(client.materializeRemote("docs/a.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "a.txt"), "utf8"), "unsynced local data");
  await fsp.unlink(path.join(root, "docs", "a.txt"));

  const originalList = adapter.list;
  adapter.list = async (id) => (await originalList(id)).map((operation) => ({
    ...operation, ciphertext: Buffer.from("corrupt encrypted bytes").toString("base64url"),
  }));
  await assert.rejects(client.materializeRemote("docs/a.txt"));
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(Object.keys(client.snapshot.files).length, 0);
  assert.ok(state.fullReads.length > 0);
});

test("issue 66: duplicate inventory paths refuse ambiguous hydration", async (t) => {
  const { root, open, adapter, state } = await setup(t, {
    "docs/a.txt": "one", "docs/b.txt": "two",
  });
  const listInventory = adapter.listInventory;
  adapter.listInventory = async (request) => {
    const page = await listInventory(request);
    return { ...page, objects: page.objects.map((entry) => ({
      ...entry, metadata: { ...entry.metadata, path: "docs/a.txt" },
    })) };
  };
  const client = await open();
  await assert.rejects(client.materializeRemote("docs/a.txt"), { code: "remote_object_ambiguous" });
  assert.deepEqual(state.fullReads, []);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
});

test("issue 66: hydration finds a file on later inventory pages without downloading siblings", async (t) => {
  const { root, open, adapter, state } = await setup(t, {
    "docs/a.txt": "one", "docs/b.txt": "two", "docs/c.txt": "three",
  });
  const listInventory = adapter.listInventory;
  adapter.listInventory = (request) => listInventory({ ...request, limit: 1 });
  const client = await open();
  assert.equal((await client.syncOnce()).available, 3);
  assert.equal(await client.materializeRemote("docs/c.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "c.txt"), "utf8"), "three");
  assert.equal(state.fullReads.length, 1);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
});

test("issue 66: Files On-Demand refuses destructive cache eviction without native root custody", async (t) => {
  const { root, open, store, state } = await setup(t, { "docs/cache.txt": "cache me" });
  const client = await open();
  await client.materializeRemote("docs/cache.txt");
  const before = store.list("alice")[0];
  const beforeSnapshot = JSON.stringify(client.snapshot);
  const beforeFullReads = state.fullReads.length;
  await assert.rejects(client.evictLocal("docs/cache.txt"),
    { code: "root_session_native_unavailable" });
  // A direct internal call, including the batchDurable variant, must never
  // turn an unavailable native authority into pathname-based deletion.
  await assert.rejects(client._evictLocal("docs/cache.txt", null, null, true),
    { code: "root_session_native_unavailable" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
  assert.equal(JSON.stringify(client.snapshot), beforeSnapshot,
    "rejected eviction cannot alter tracked or remote-only durable intent");
  assert.equal(state.fullReads.length, beforeFullReads,
    "rejected eviction must not query remote state before rejecting unsafe I/O");
  assert.equal((await fsp.readdir(root)).includes(".rootark-trash"), false);
  assert.equal((await fsp.readdir(root)).includes(".rootark-sync-evictions"), false);
  assert.equal(store.list("alice")[0].operationId, before.operationId);
  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
  assert.equal(store.list("alice")[0].operationId, before.operationId);
  state.offline = false;
  const restarted = await open();
  assert.equal(restarted.snapshot.remoteOnly[before.objectId], undefined);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
});

test("issue 66: automatic excluded cache migration refuses legacy eviction before snapshot mutation", async (t) => {
  const { root, open, adapter, store, state, key } = await setup(t,
    { "docs/cache.txt": "retain exact Unicode café-中-😀 bytes" });
  const original = await open();
  await original.materializeRemote("docs/cache.txt");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshotPath);
  const oldFile = await fsp.readFile(path.join(root, "docs", "cache.txt"));
  const oldRecords = JSON.stringify(store.list("alice"));
  const oldState = { pushes: state.pushes, fullReads: state.fullReads.length,
    inventoryReads: state.inventoryReads };
  const excluded = new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], excludedPaths: ["docs/cache.txt"],
    filesOnDemand: true, fileKeyResolver: () => key,
  });
  await excluded.open();
  await assert.rejects(excluded.syncOnce(), { code: "root_session_native_unavailable" },
    "automatic exclusion must never turn an unsafe native denial into persisted failure or remote-only state");
  assert.deepEqual(await fsp.readFile(snapshotPath), oldSnapshot);
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "cache.txt")), oldFile);
  assert.equal(JSON.stringify(store.list("alice")), oldRecords);
  assert.equal(state.pushes, oldState.pushes);
  assert.equal(state.fullReads.length, oldState.fullReads);
  assert.equal(state.inventoryReads, oldState.inventoryReads);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
  assert.equal(await exists(path.join(root, ".rootark-sync-evictions")), false);
});

test("issue 66: Files On-Demand cannot sign remote DELETE merely because a cached pathname vanishes", async (t) => {
  const { root, open, store, state } = await setup(t, { "docs/café-中-😀.txt": "trusted cached bytes" });
  const client = await open();
  await client.materializeRemote("docs/café-中-😀.txt");
  const original = await fsp.readFile(path.join(root, "docs", "café-中-😀.txt"));
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const originalRemote = JSON.stringify(store.list("alice"));
  const originalPushes = state.pushes;
  await fsp.rename(path.join(root, "docs", "café-中-😀.txt"),
    path.join(root, "docs", "temporarily-missing.txt"));

  await assert.rejects(client.syncOnce(), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "temporarily-missing.txt")), original);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), originalRemote);
  assert.equal(state.pushes, originalPushes);
  assert.equal((await client.journal.recover()).length, 0, "no signed DELETE or CREATE was queued");
});

test("issue 66: Files On-Demand WebDAV translation never signs pathname-derived DELETE", async (t) => {
  const { root, open, store, state } = await setup(t, { "docs/item.txt": "trusted cached bytes" });
  const client = await open();
  await client.materializeRemote("docs/item.txt");
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const originalRemote = JSON.stringify(store.list("alice"));
  await fsp.unlink(path.join(root, "docs", "item.txt"));

  await assert.rejects(client.translateWebDavMutation({
    kind: "delete", operationId: crypto.randomUUID(), source: "/docs/item.txt",
  }), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), originalRemote);
  assert.equal(state.pushes, 0);
  assert.equal((await client.journal.recover()).length, 0);
});

test("issue 66: direct Files On-Demand outbox cannot enqueue a signed DELETE", async (t) => {
  const { open, store, key, state } = await setup(t, { "docs/remote.txt": "signed original" });
  const client = await open();
  const remote = store.list("alice")[0];
  const originalRemote = JSON.stringify(store.list("alice"));
  await assert.rejects(client.enqueueChange({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), baseRevision: remote.revision,
    revision: { counter: 2, deviceId: "device-b" },
    metadata: { path: "docs/remote.txt" }, fileKey: key,
  }), { code: "root_session_native_unavailable" });
  assert.equal((await client.journal.recover()).length, 0);
  assert.equal(JSON.stringify(store.list("alice")), originalRemote);
  assert.equal(state.pushes, 0);
});

test("issue 66: a previous non-FOD signed DELETE in a durable journal cannot be pushed by FOD", async (t) => {
  const { root, open, store, adapter, key, state } = await setup(t,
    { "docs/retained.txt": "retain remote and local" });
  // A genuine pre-FOD outbox must precede the first FOD open. Opening a
  // non-FOD writer after FOD activation is now deliberately forbidden.
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  await legacy.syncOnce();
  const remote = store.list("alice")[0];
  await legacy.enqueueChange({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), baseRevision: remote.revision,
    revision: { counter: 2, deviceId: "device-b" },
    metadata: { path: "docs/retained.txt" }, fileKey: key,
  });
  const pendingBefore = (await legacy.journal.recover()).map((item) => item.operationId);
  const remoteBefore = JSON.stringify(store.list("alice"));
  const reopened = await open();
  const snapshotBefore = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-index.json")));
  await assert.rejects(reopened.syncOnce(), { code: "root_session_native_unavailable" });
  assert.deepEqual((await reopened.journal.recover()).map((item) => item.operationId), pendingBefore);
  const snapshotAfter = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-index.json")));
  assert.deepEqual(snapshotAfter.files, snapshotBefore.files);
  assert.deepEqual(snapshotAfter.remoteOnly, snapshotBefore.remoteOnly);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  assert.equal(await fsp.readFile(path.join(root, "docs", "retained.txt"), "utf8"), "retain remote and local");
});

test("issue 66: FOD public staging denies before probing an outside-root path", async (t) => {
  const { root, open } = await setup(t, {});
  const client = await open();
  const outside = path.join(path.dirname(root), "independent-outside-witness.txt");
  const bytes = Buffer.from("outside source must remain unchanged");
  await fsp.writeFile(outside, bytes);

  await assert.rejects(client.stageExisting(outside), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(outside), bytes);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: public staging cannot relocate an in-root cached FOD file without native custody", async (t) => {
  const { root, open, store } = await setup(t, { "docs/retained.txt": "protected FOD cache" });
  const client = await open();
  await client.materializeRemote("docs/retained.txt");
  const target = path.join(root, "docs", "retained.txt");
  const bytesBefore = await fsp.readFile(target);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  await assert.rejects(client.stageExisting(target), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(target), bytesBefore);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: direct incoming DELETE must not stage materialized FOD bytes without native custody", async (t) => {
  const { root, open, store, key } = await setup(t,
    { "docs/retained.txt": "verified cached owner bytes" });
  const client = await open();
  await client.materializeRemote("docs/retained.txt");
  const original = store.list("alice")[0];
  const originalBytes = await fsp.readFile(path.join(root, "docs", "retained.txt"));
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteDelete = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "docs/retained.txt" }, fileKey: key,
  });

  await assert.rejects(client.apply(remoteDelete), { code: "root_session_native_unavailable" });
  await assert.rejects(client._apply(remoteDelete), { code: "sync_root_busy" },
    "private direct apply must not bypass the physical mutation lock");
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "retained.txt")), originalBytes);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: Files On-Demand WebDAV MOVE translation denies before any local scan", async (t) => {
  const { root, open, store, state } = await setup(t, { "docs/a.txt": "retained signed bytes" });
  const client = await open();
  await client.materializeRemote("docs/a.txt");
  const originalBytes = await fsp.readFile(path.join(root, "docs", "a.txt"));
  const originalSnapshot = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const readsBefore = state.fullReads.length;

  await assert.rejects(client.translateWebDavMutation({
    kind: "move", operationId: crypto.randomUUID(),
    source: "/docs/a.txt", destination: "/docs/b.txt",
  }), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "a.txt")), originalBytes);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), originalSnapshot);
  assert.equal(await exists(path.join(root, "docs", "b.txt")), false);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.fullReads.length, readsBefore);
});

test("issue 66: out-of-scope remote DELETE cannot stage an in-scope FOD cache origin", async (t) => {
  const { root, open, store, key } = await setup(t,
    { "docs/retained.txt": "same cache origin must remain" });
  const client = await open();
  await client.materializeRemote("docs/retained.txt");
  const original = store.list("alice")[0];
  const bytesBefore = await fsp.readFile(path.join(root, "docs", "retained.txt"));
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "outside/retained.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "stored");

  await assert.rejects(client.pullRemote({ conflicts: [] }), { code: "root_session_native_unavailable" });
  await assert.rejects(client.reconcileOutOfScopeMove(tombstone, { conflicts: [] }),
    { code: "root_session_native_unavailable" }, "direct reconcile must not bypass the pull fence");
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "retained.txt")), bytesBefore);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: out-of-scope remote MOVE cannot rename a tracked FOD origin without native custody", async (t) => {
  const { root, open, store, key } = await setup(t,
    { "docs/café-中-😀.txt": "origin must survive MOVE outside selected scope" });
  const client = await open();
  await client.materializeRemote("docs/café-中-😀.txt");
  const original = store.list("alice")[0];
  const filePath = path.join(root, "docs", "café-中-😀.txt");
  const bytesBefore = await fsp.readFile(filePath);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision,
    metadata: { path: "outside/café-中-😀.txt", sourcePath: "docs/café-中-😀.txt" },
    plaintext: protocol.encodeMovePayload(bytesBefore, key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");

  await assert.rejects(client.pullRemote({ conflicts: [] }), { code: "root_session_native_unavailable" });
  await assert.rejects(client.reconcileOutOfScopeMove(moved, { conflicts: [] }),
    { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(filePath), bytesBefore);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: replacing public preflight cannot bypass direct out-of-scope FOD DELETE denial", async (t) => {
  const { root, open, store, key } = await setup(t,
    { "docs/retained.txt": "must never be staged by a shadowed method" });
  const client = await open();
  await client.materializeRemote("docs/retained.txt");
  const remote = store.list("alice")[0];
  const cachePath = path.join(root, "docs", "retained.txt");
  const originalBytes = await fsp.readFile(cachePath);
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const originalSnapshot = await fsp.readFile(snapshotPath);
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: remote.revision.counter + 1, deviceId: "device-a" },
    baseRevision: remote.revision, metadata: { path: "outside/retained.txt" }, fileKey: key,
  });
  let hijacked = 0;
  client.preflightOutOfScopeMove = () => {
    hijacked += 1;
    return { sourcePath: "docs/retained.txt", prior: client.snapshot.files["docs/retained.txt"],
      tombstone: true, directoryRecord: false };
  };

  await assert.rejects(client.reconcileOutOfScopeMove(tombstone, { conflicts: [] }),
    { code: "root_session_native_unavailable" });
  assert.equal(hijacked, 0, "a replaced public preflight must never supply destructive authority");
  assert.deepEqual(await fsp.readFile(cachePath), originalBytes);
  assert.deepEqual(await fsp.readFile(snapshotPath), originalSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: Proxy preflight interception cannot bypass FOD remote pull denial", async (t) => {
  const { root, open, store, key } = await setup(t,
    { "docs/café-中-😀.txt": "proxy must not stage owner bytes" });
  const client = await open();
  await client.materializeRemote("docs/café-中-😀.txt");
  const remote = store.list("alice")[0];
  const cachePath = path.join(root, "docs", "café-中-😀.txt");
  const originalBytes = await fsp.readFile(cachePath);
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const originalSnapshot = await fsp.readFile(snapshotPath);
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: remote.objectId, fileId: remote.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: remote.revision.counter + 1, deviceId: "device-a" },
    baseRevision: remote.revision, metadata: { path: "outside/café-中-😀.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "stored");
  let hijacked = 0;
  const proxied = new Proxy(client, {
    get(target, property, receiver) {
      if (property === "preflightOutOfScopeMove") {
        return () => {
          hijacked += 1;
          return { sourcePath: "docs/café-中-😀.txt",
            prior: target.snapshot.files["docs/café-中-😀.txt"],
            tombstone: true, directoryRecord: false };
        };
      }
      return Reflect.get(target, property, receiver);
    },
  });

  await assert.rejects(proxied.pullRemote({ conflicts: [] }),
    { code: "root_session_native_unavailable" });
  assert.equal(hijacked, 0, "Proxy method interception must not direct path staging");
  assert.deepEqual(await fsp.readFile(cachePath), originalBytes);
  assert.deepEqual(await fsp.readFile(snapshotPath), originalSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: a FOD root retains its mode across non-FOD restart and custom snapshot paths", async (t) => {
  const { root, open, adapter, store, key, state } = await setup(t,
    { "docs/cache.txt": "mode must remain bound to this physical root" });
  const client = await open();
  await client.materializeRemote("docs/cache.txt");
  const cachedPath = path.join(root, "docs", "cache.txt");
  const original = await fsp.readFile(cachedPath);
  const originalStore = JSON.stringify(store.list("alice"));
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const markerPath = path.join(root, ".rootark-sync-ever-fod");
  // Preserve the explicit regular-file assertion without reopening a mutable
  // pathname after the check (the old stat(path) -> readFile(path) was racy).
  const markerHandle = await fsp.open(markerPath, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const before = await markerHandle.stat({ bigint: true });
    assert.equal(before.isFile(), true, "FOD must create a regular-file root marker");
    assert.equal(before.nlink, 1n, "a marker hardlink cannot be root-mode authority");
    const expectedMarker = Buffer.from("rootark-sync-ever-fod-v1\n");
    const bounded = Buffer.alloc(expectedMarker.length + 1);
    let bytesRead = 0;
    while (bytesRead < bounded.length) {
      const result = await markerHandle.read(bounded, bytesRead,
        bounded.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    assert.equal(bytesRead, expectedMarker.length, "marker must match exact bounded bytes");
    assert.deepEqual(bounded.subarray(0, bytesRead), expectedMarker);
    const after = await markerHandle.stat({ bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
  } finally { await markerHandle.close(); }
  const nonFod = new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => key,
  });
  await assert.rejects(nonFod.open(), { code: "root_mode_fod_required" });
  await assert.rejects(nonFod.evictLocal("docs/cache.txt"), { code: "root_mode_fod_required" });
  assert.deepEqual(await fsp.readFile(cachedPath), original);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), originalStore);
  assert.equal(state.pushes, 0);

  const alternateSnapshot = path.join(path.dirname(root), "alternate-fod-index.json");
  const otherRoot = path.join(path.dirname(root), "custom-snapshot-root");
  const customFod = await new SyncEngine({ rootDir: otherRoot, snapshotPath: alternateSnapshot,
    adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private",
    filesOnDemand: true, fileKeyResolver: () => key,
  }).open();
  assert.equal(customFod.filesOnDemand, true);
  assert.equal((await fsp.stat(path.join(otherRoot, ".rootark-sync-ever-fod"))).isFile(), true);
  assert.equal(Object.hasOwn(await customFod.scanFiles(), ".rootark-sync-ever-fod"), false,
    "the mode marker must never be synchronized as an ordinary file");
  assert.equal(await exists(path.join(otherRoot, ".rootark-sync-index.json")), false);
  const differentSnapshot = path.join(path.dirname(root), "other-new-index.json");
  await assert.rejects(new SyncEngine({ rootDir: otherRoot, snapshotPath: differentSnapshot,
    adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open(), { code: "root_mode_fod_required" });
  assert.equal(await exists(differentSnapshot), false,
    "mode denial must precede creating an alternate snapshot");
});

test("issue 66: an already-open non-FOD engine cannot evict after another instance marks FOD", async (t) => {
  const { root, open, adapter, store, key, state } = await setup(t,
    { "docs/retained.txt": "bytes of owner must never be evicted" });
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => key,
  }).open();
  assert.equal(await exists(path.join(root, ".rootark-sync-ever-fod")), false,
    "ordinary non-FOD operations must not set the marker");
  const fod = await open();
  await fod.materializeRemote("docs/retained.txt");
  const cachedPath = path.join(root, "docs", "retained.txt");
  const original = await fsp.readFile(cachedPath);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  await assert.rejects(legacy.evictLocal("docs/retained.txt"),
    { code: "root_mode_fod_required" });
  await assert.rejects(legacy.syncOnce(), { code: "root_mode_fod_required" });
  await assert.rejects(legacy.stageExisting(cachedPath), { code: "root_mode_fod_required" },
    "a direct stage helper must also honor the durable root-mode marker");
  await assert.rejects(legacy._reconcileLocal(), { code: "root_mode_fod_required" });
  await assert.rejects(legacy._pushPending({ pushed: 0, conflicts: [], offline: false }),
    { code: "root_mode_fod_required" });
  await assert.rejects(legacy._apply({ operation: "delete" }), { code: "root_mode_fod_required" });
  await assert.rejects(legacy.persistSnapshot(), { code: "root_mode_fod_required" });
  assert.deepEqual(await fsp.readFile(cachedPath), original);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: direct recoverConflict cannot write after another engine marks FOD", async (t) => {
  const { root, open, adapter, store, key } = await setup(t,
    { "docs/retained.txt": "protected content" });
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  const fod = await open();
  await fod.materializeRemote("docs/retained.txt");
  const original = store.list("alice")[0];
  const cachedPath = path.join(root, "docs", "retained.txt");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const bytesBefore = await fsp.readFile(cachedPath);
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const conflict = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    baseRevision: original.revision, metadata: { path: "docs/retained.txt" },
    plaintext: Buffer.from("should not create a recovery file"), fileKey: key,
  });
  const summary = { conflicts: [], conflictRecovery: 0 };
  await assert.rejects(legacy.recoverConflict(conflict, summary), { code: "root_mode_fod_required" });
  assert.deepEqual(await fsp.readFile(cachedPath), bytesBefore);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(summary.conflictRecovery, 0);
  assert.equal(await exists(path.join(root, ".rootark-conflicts")), false);
});

test("issue 66: direct prune cannot remove empty tracked-root ancestors after FOD activation", async (t) => {
  const { root, open, adapter, key } = await setup(t, {});
  const legacy = await new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  const empty = path.join(root, "untracked", "nested");
  await fsp.mkdir(empty, { recursive: true });
  const fod = await open();
  const marker = await fsp.readFile(path.join(root, ".rootark-sync-ever-fod"));
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  await assert.rejects(legacy.pruneEmptyUntrackedParents(empty), { code: "root_mode_fod_required" });
  assert.equal((await fsp.stat(empty)).isDirectory(), true);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-ever-fod")), marker);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(fod.filesOnDemand, true);
});

test("issue 66: shared protocol and WebDAV reject ever-FOD marker metadata", async (t) => {
  const { root, open, store, key, state } = await setup(t, {});
  const client = await open();
  const markerPath = path.join(root, ".rootark-sync-ever-fod");
  const originalMarker = await fsp.readFile(markerPath);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const readsBefore = state.fullReads.length;
  for (const name of [".rootark-sync-ever-fod", ".ROOTARK-SYNC-EVER-FOD",
    "docs/.rootark-sync-ever-fod"]) {
    assert.throws(() => protocol.safeRelativePath(name, "path"), { code: "invalid_operation" });
    assert.throws(() => protocol.createOperation({ operation: "create",
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-b" }, metadata: { path: name },
      plaintext: Buffer.from("not allowed"), fileKey: key,
    }), { code: "invalid_operation" });
  }
  await assert.rejects(client.translateWebDavMutation({
    kind: "put", operationId: crypto.randomUUID(), path: "/.rootark-sync-ever-fod",
  }), { code: "invalid_operation" });
  assert.deepEqual(await fsp.readFile(markerPath), originalMarker);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.fullReads.length, readsBefore);
});

test("issue 66: malformed ever-FOD root marker fails closed without writing a snapshot", async (t) => {
  const { root, adapter, key } = await setup(t, {});
  await fsp.mkdir(root, { recursive: true });
  const markerPath = path.join(root, ".rootark-sync-ever-fod");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  for (const malformed of ["{", "{}", '{"version":999}']) {
    await fsp.writeFile(markerPath, malformed, "utf8");
    for (const filesOnDemand of [false, true]) {
      const engine = new SyncEngine({ rootDir: root, adapter,
        deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
        fileKeyResolver: () => key, filesOnDemand,
      });
      await assert.rejects(engine.open(), { code: "root_mode_marker_invalid" });
      assert.equal(await exists(snapshotPath), false);
    }
  }
});

test("issue 66: a multiply-linked ever-FOD marker cannot authorize a root mode", async (t) => {
  const { root, open, adapter, key } = await setup(t, {});
  await open();
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const alias = path.join(root, "marker-hardlink-outside-sync");
  await fsp.link(marker, alias);
  const original = await fsp.readFile(marker);
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  await assert.rejects(new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open(), { code: "root_mode_marker_invalid" });
  assert.deepEqual(await fsp.readFile(marker), original);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
});

test("issue 66: a physically rebound FOD marker never authorizes a foreign inode", async (t) => {
  const { root, open, adapter, key, state, store } = await setup(t, {
    "docs/keep.txt": "protected remote content",
  });
  await open();
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const parked = path.join(root, "parked-original-marker-for-adversarial-test");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const expectedMarker = "rootark-sync-ever-fod-v1\n";
  const markerBefore = await fsp.open(marker, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let before;
  try { before = await markerBefore.stat({ bigint: true }); }
  finally { await markerBefore.close(); }
  const snapshotBefore = await fsp.readFile(snapshot);
  const storeBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const originalLstat = fsp.lstat;
  const originalRename = fsp.rename;
  let swapped = false;
  // The old implementation used lstat(marker), then a fresh readFile(marker).
  // Physically rebind that same name immediately after the successful lstat.
  // A pathname second read would wrongly accept identical foreign bytes.
  fsp.lstat = async (requested, ...args) => {
    const result = await originalLstat(requested, ...args);
    if (!swapped && path.resolve(String(requested)) === path.resolve(marker)) {
      swapped = true;
      await originalRename(marker, parked);
      await fsp.writeFile(marker, expectedMarker, { flag: "wx" });
    }
    return result;
  };
  try {
    await assert.rejects(new SyncEngine({ rootDir: root, adapter,
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
      fileKeyResolver: () => key, filesOnDemand: true,
    }).open(), { code: "root_mode_marker_invalid" });
  } finally { fsp.lstat = originalLstat; }
  assert.equal(swapped, true, "the physical inode replacement must have happened");
  // Read each inode from its own held descriptor, not via another pathname
  // lookup following a lstat. The proof must not recreate the CodeQL race.
  const heldEvidence = async (entry) => {
    const handle = await fsp.open(entry, fs.constants.O_RDONLY
      | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
    try {
      const stats = await handle.stat({ bigint: true });
      const bytes = await handle.readFile("utf8");
      return { stats, bytes };
    } finally { await handle.close(); }
  };
  const foreign = await heldEvidence(marker);
  const parkedOriginal = await heldEvidence(parked);
  assert.equal(parkedOriginal.stats.ino, before.ino, "original opened inode is retained");
  assert.notEqual(foreign.stats.ino, before.ino, "foreign equal-byte inode must remain distinct");
  assert.equal(foreign.bytes, expectedMarker);
  assert.equal(parkedOriginal.bytes, expectedMarker);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "a failed root-mode admission must not push a signed operation");
});

test("issue 66: ambiguous FOD publish retains foreign temporary and quarantines the root", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "authenticated recovery payload",
  });
  const client = await open();
  // Keep the parent pre-existing: even then, a failed publication attempt
  // cannot prove the target was never mutated. Retain the root lock; an
  // untrusted cold opener cannot authorize a retry from mutable pathnames.
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  const target = path.join(root, "docs", "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const storeBefore = JSON.stringify(store.list("alice"));
  const pushesBefore = state.pushes;
  const foreignBytes = "foreign temporary must never be removed";
  const parked = path.join(path.dirname(root), "parked-original-inbound-for-adversarial-test");
  const originalRename = fsp.rename;
  const originalRm = fsp.rm;
  let planted = false;
  let attemptedForeignRemoval = false;
  let temporary = null;
  let sameVolumeParent = false;
  fsp.rename = async (source, destination, ...rest) => {
    if (!planted && path.resolve(String(destination)) === path.resolve(target)
      && String(source).includes(".tmp-")) {
      sameVolumeParent = path.dirname(path.resolve(String(source))) === path.dirname(path.resolve(target));
      await originalRename(source, parked);
      await fsp.writeFile(source, foreignBytes, { flag: "wx" });
      planted = true;
      temporary = String(source);
      throw Object.assign(new Error("physical inbound publish EIO after temp replacement"), { code: "EIO" });
    }
    return originalRename(source, destination, ...rest);
  };
  fsp.rm = async (candidate, options) => {
    if (planted && path.resolve(String(candidate)) === path.resolve(temporary)) {
      attemptedForeignRemoval = true;
      // Trap only the destructive syscall, retaining the physical foreign
      // inode for assertions; the rest of the transaction is real NTFS/ext4.
      return;
    }
    return originalRm(candidate, options);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
    fsp.rm = originalRm;
  }
  assert.equal(planted, true, "real inbound temp must be moved and physically replaced");
  assert.equal(sameVolumeParent, true,
    "an incoming temp must share its destination directory for nested mount support");
  assert.equal(attemptedForeignRemoval, false,
    "failed publish must not issue pathname rm against a substituted foreign inode");
  assert.equal(await fsp.readFile(temporary, "utf8"), foreignBytes);
  assert.equal(await fsp.readFile(parked, "utf8"), "authenticated recovery payload");
  assert.equal(await exists(target), false, "failed incoming hydration must not claim a local cache");
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "inbound failure may not publish a signed operation");
  assert.equal(path.basename(temporary).startsWith(".rootark-sync-index.json.tmp-inbound-"), true,
    "a failed inbound write must leave inert reserved debris, never a user-path temp name");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "ambiguous attempted publish must hold custody even with a pre-existing parent");
  await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(await exists(target), false,
    "do not manufacture an authorized target or claim an unsafe cold retry");
  assert.equal(await fsp.readFile(temporary, "utf8"), foreignBytes);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "blocked cold retry may not sign a foreign temp or delete");
});

test("issue 66: new FOD parent remains locked when inbound payload rename fails", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "inbound payload denied before final rename",
  });
  const client = await open();
  const parent = path.join(root, "docs");
  const target = path.join(parent, "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const beforeStore = JSON.stringify(store.list("alice"));
  const originalRename = fsp.rename;
  let intercepted = false;
  fsp.rename = async (source, dest, ...args) => {
    if (!intercepted && path.resolve(String(dest)) === path.resolve(target)
      && String(source).includes(".tmp-inbound-")) {
      intercepted = true;
      throw Object.assign(new Error("injected pre-rename EIO"), { code: "EIO" });
    }
    return originalRename(source, dest, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(intercepted, true, "the parent must be created before final payload rename");
  assert.equal((await fsp.lstat(parent)).isDirectory(), true);
  assert.equal(await exists(target), false);
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot);
  await assert.rejects(client.pruneEmptyUntrackedParents(parent),
    { code: "sync_inbound_indeterminate" });
  assert.equal((await fsp.lstat(parent)).isDirectory(), true,
    "a direct cleanup caller must not remove the quarantined ancestor");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "new uncheckpointed parent must retain the cross-process root lock");
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
});

test("issue 66: recursive FOD parent mkdir partial EIO cannot free cold lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/sub/restore.txt": "remote bytes after a partial ancestor mkdir",
  });
  const client = await open();
  const firstAncestor = path.join(root, "docs");
  const requestedParent = path.join(firstAncestor, "sub");
  const target = path.join(requestedParent, "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const oldStore = JSON.stringify(store.list("alice"));
  const originalMkdir = fsp.mkdir;
  let createdRealAncestor = false;
  let injectedPartialError = false;
  fsp.mkdir = async (candidate, options, ...extra) => {
    if (!injectedPartialError && path.resolve(String(candidate)) === path.resolve(requestedParent)
      && options?.recursive === true) {
      // Real OS mkdir for the first component; the recursive call then
      // fails at the next segment instead of returning its created path.
      await originalMkdir(firstAncestor, { recursive: false });
      createdRealAncestor = true;
      injectedPartialError = true;
      throw Object.assign(new Error("physical first ancestor followed by EIO"), { code: "EIO" });
    }
    return originalMkdir(candidate, options, ...extra);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/sub/restore.txt"), { code: "EIO" });
  } finally {
    fsp.mkdir = originalMkdir;
  }
  assert.equal(createdRealAncestor, true, "real ancestor must be created before the recursive EIO");
  assert.equal(injectedPartialError, true);
  assert.equal((await fsp.lstat(firstAncestor)).isDirectory(), true);
  assert.equal(await exists(requestedParent), false);
  assert.equal(await exists(target), false);
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "partial recursive mkdir must quarantine the root, not authorize a cold local CREATE");
  await assert.rejects(open(), { code: "sync_root_busy" });
  const diskJournal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.deepEqual(diskJournal.pending, []);
  assert.equal(state.pushes, 0, "no outbound push is asserted or fabricated by this fixture");
  assert.equal(JSON.stringify(store.list("alice")), oldStore);
});

test("issue 66: physical post-publish FOD crash retains lock and stops cold outbound reconcile", async (t) => {
  const { root, open, store, state, key } = await setup(t, {
    "docs/restore.txt": "remote fixture bytes after abrupt exit",
  });
  await open();
  const target = path.join(root, "docs", "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  const beforeStore = JSON.stringify(store.list("alice"));
  const childProgram = [
    '"use strict";',
    'const fs=require("node:fs");',
    'const fsp=require("node:fs/promises");',
    'const path=require("node:path");',
    '(async()=>{',
    'const input=JSON.parse(process.env.ROOTARK_ISSUE66_CRASH_TEST);',
    'const {SyncEngine}=require(input.engine);',
    'const {SyncObjectStore}=require(input.storeModule);',
    'const store=await new SyncObjectStore(input.storeFile).open();',
    'const adapter={list:async(id="")=>store.list("alice",id||null),',
    'listInventory:async()=>({protocolVersion:2,view:"metadata",objects:[],nextCursor:null}),',
    'push:async()=>{throw Error("unexpected outbound during inbound child")}};',
    'const client=await new SyncEngine({rootDir:input.root,adapter,deviceId:"device-b",',
    'keyEpoch:"epoch-1",compartmentId:"private",fileKeyResolver:()=>Buffer.from(input.key,"hex"),',
    'selectedPaths:["docs"],filesOnDemand:true}).open();',
    'const operation=store.list("alice").find(x=>x.metadata?.path==="docs/restore.txt");',
    'if(!operation)throw Error("remote fixture record missing");',
    'const originalRename=fsp.rename;',
    'fsp.rename=async(source,destination,...args)=>{',
    'const result=await originalRename(source,destination,...args);',
    'if(String(source).includes(".tmp-inbound-") &&',
    'path.resolve(String(destination))===path.resolve(input.target)){',
    'fs.writeSync(1,"POST_PUBLISH_PHYSICAL_RENAME\\n");',
    'process.kill(process.pid,"SIGKILL");',
    'throw Error("native immediate termination unexpectedly returned");',
    '}',
    'return result;',
    '};',
    'await client.apply(operation);',
    'process.exit(67);',
    '})().catch(e=>{fs.writeSync(2,String(e.stack||e));process.exit(68)});',
  ].join("\n");
  const child = spawnSync(process.execPath, ["-e", childProgram], {
    timeout: 15000, encoding: "utf8", maxBuffer: 8192,
    env: {
      ...process.env,
      ROOTARK_ISSUE66_CRASH_TEST: JSON.stringify({
        engine: path.join(__dirname, "..", "sync-client", "rootark-sync-engine.js"),
        storeModule: path.join(__dirname, "..", "src", "routes", "sync.js"),
        storeFile: path.join(path.dirname(root), "objects.json"),
        root, target, key: key.toString("hex"),
      }),
    },
  });
  assert.match(child.stdout, /POST_PUBLISH_PHYSICAL_RENAME/,
    `must reach physical rename before crash, stderr=${child.stderr}`);
  assert.equal(child.error, undefined, "subprocess must not time out or fail to spawn");
  assert.equal(child.stderr, "", "failure/exception path must never pass as a crash");
  if (process.platform === "win32") {
    assert.equal(Number.isInteger(child.status), true);
    assert.equal([0, 67, 68].includes(child.status), false,
      "Windows must terminate by SIGKILL, not the child normal/failure exits");
  } else {
    assert.equal(child.signal, "SIGKILL", "POSIX must observe a real SIGKILL termination");
  }
  assert.equal(await fsp.readFile(target, "utf8"), "remote fixture bytes after abrupt exit");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot,
    "the original snapshot is physically older than published payload");
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
  // A real abnormal process termination leaves the preexisting root lock.
  // Cold open MUST stop here; never simulate a custodian or unlink this
  // security lock from a same-UID/SID writable path to force a fake replay.
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "cold lock prevents an untracked outbound CREATE");
  const diskJournal = JSON.parse(await fsp.readFile(
    path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.equal(diskJournal.pending.length, 0,
    "failed cold admission cannot enqueue any new outbound CREATE");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
});

test("issue 66: FOD post-publish snapshot EIO retains root lock before any outbound reconcile", async (t) => {
  const { root, open, store, state, adapter } = await setup(t, {
    "docs/recover.txt": "remote file published before a failed checkpoint",
  });
  const client = await open();
  const target = path.join(root, "docs", "recover.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  const beforeStore = JSON.stringify(store.list("alice"));
  const originalRename = fsp.rename;
  let published = false;
  let injected = false;
  fsp.rename = async (source, destination, ...args) => {
    const dest = path.resolve(String(destination));
    if (dest === path.resolve(target) && String(source).includes(".tmp-inbound-")) {
      const result = await originalRename(source, destination, ...args);
      published = true; // the kernel really renamed the payload inode
      return result;
    }
    if (published && !injected && dest === path.resolve(snapshot)
      && String(source).includes(".tmp-")) {
      injected = true;
      throw Object.assign(new Error("durable snapshot publish injected EIO"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/recover.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(published, true, "the inbound file must have been physically published");
  assert.equal(injected, true, "EIO must land in the later snapshot rename, not the payload");
  assert.equal(await fsp.readFile(target, "utf8"),
    "remote file published before a failed checkpoint");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot,
    "the cache content and durable snapshot must disagree at this test boundary");
  // Public locking is not the only entry point. The module-private negative
  // latch must also reject direct internal method calls before scanning or
  // attempting outbound signed mutation, even if a caller overwrites fields.
  client.inboundPublicationIndeterminate = false;
  await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client._pushPending({ pushed: 0 }), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client.translateWebDavMutation({
    kind: "put", path: "/docs/recover.txt", operationId: "post-publish-eio-webdav",
  }), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client._enqueueChange({ operation: "create" }),
    { code: "sync_inbound_indeterminate" });
  await assert.rejects(client._open(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client.recoverConflict(store.list("alice")[0], {}),
    { code: "sync_inbound_indeterminate" });
  const originalPush = adapter.push;
  let unsafeDispatchAttempted = false;
  adapter.push = async () => {
    unsafeDispatchAttempted = true;
    throw Object.assign(new Error("unexpected outbound after EIO"), { code: "unsafe_dispatch" });
  };
  try {
    await assert.rejects(client.retryPush(store.list("alice")[0]),
      { code: "sync_inbound_indeterminate" });
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(unsafeDispatchAttempted, false,
    "direct retryPush may not reach HTTP after the root became indeterminate");
  await assert.rejects(client.syncOnce(), { code: "sync_root_busy" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "no uncertain cache may be enqueued or dispatched as outbound CREATE");
  const diskJournal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.equal(diskJournal.pending.length, 0);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
});

test("issue 66: inbound FOD rename completion followed by EIO retains lock before cold reconcile", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "remote authenticated content after a late native error",
  });
  const client = await open();
  const parent = path.join(root, "docs");
  await fsp.mkdir(parent, { recursive: true });
  const target = path.join(parent, "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const oldStore = JSON.stringify(store.list("alice"));
  const originalRename = fsp.rename;
  let published = false;
  fsp.rename = async (source, destination, ...args) => {
    if (!published && path.resolve(String(destination)) === path.resolve(target)
      && String(source).includes(".tmp-inbound-")) {
      await originalRename(source, destination, ...args);
      published = true; // Kernel has physically completed the target rename.
      throw Object.assign(new Error("injected EIO after real inbound publish"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"), { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
  }
  assert.equal(published, true, "must reach a real successful OS rename before injected EIO");
  assert.equal(await fsp.readFile(target, "utf8"),
    "remote authenticated content after a late native error");
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot,
    "the durable checkpoint must remain older than the physical payload");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "the publisher's uncertain completion must never release the process lock");
  await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
  await assert.rejects(client.syncOnce(), { code: "sync_root_busy" });
  await assert.rejects(open(), { code: "sync_root_busy" });
  const journal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.deepEqual(journal.pending, []);
  assert.equal(state.pushes, 0, "there is no evidence of an outbound signed CREATE");
  assert.equal(JSON.stringify(store.list("alice")), oldStore);
});

test("issue 66: native-required direct inbound _apply cannot bypass an occupied physical root lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "signed remote cache bytes",
  });
  const client = await open();
  const op = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(op, "fixture must contain a real signed remote operation");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  const beforeRemote = JSON.stringify(store.list("alice"));
  const lock = path.join(root, ".rootark-sync.lock");
  // A different process's exclusive mkdir is represented by the actual
  // kernel directory. This test never unlinks someone else's lock.
  await fsp.mkdir(lock, { mode: 0o700 });
  await assert.rejects(client._apply(op), { code: "sync_root_busy" });
  await assert.rejects(client.apply(op), { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false,
    "no target may be created by bypassing the owner of the physical lock");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(state.pushes, 0);
  assert.equal(JSON.stringify(store.list("alice")), beforeRemote);
});

test("issue 66: native-required private hydration and reconcile require the physical mutation context", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "signed remote cache bytes",
  });
  const client = await open();
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._materializeOnDemand("docs/restore.txt"),
    { code: "sync_root_busy" });
  await assert.rejects(client._reconcileLocal(), { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false);
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
});

test("issue 66: an escaped stale AsyncLocalStorage callback cannot reuse a released native-required lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "remote bytes protected by physical lock",
  });
  const client = await open();
  const operation = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(operation);
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const beforeSnapshot = await fsp.readFile(snapshot);
  let releaseCallback;
  const trigger = new Promise((resolve) => { releaseCallback = resolve; });
  let escaped;
  await client.withMutationLock(async () => {
    // Registration happens INSIDE the AsyncLocalStorage context, but the
    // operation will execute after withMutationLock has already released
    // the physical lock. An equality-only context guard is a false authority.
    escaped = trigger.then(() => client._apply(operation));
  });
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  releaseCallback();
  await assert.rejects(escaped, { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false);
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(state.pushes, 0);
});

test("issue 66: direct native-required outbound retry and conflict recovery cannot bypass a physical lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "authenticated remote bytes",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const remoteBefore = JSON.stringify(store.list("alice"));
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client.retryPush(operation), { code: "sync_root_busy" });
  await assert.rejects(client.recoverConflict(operation, { conflicts: [] }),
    { code: "sync_root_busy" });
  assert.equal(await exists(path.join(root, ".rootark-conflicts")), false);
  assert.equal(state.pushes, 0, "no outbound signed PUT may bypass the lock owner");
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
});

test("issue 66: a started but unawaited native-required _apply keeps the physical lock through all awaited I/O", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "remote content behind deferred key resolver",
  });
  const client = await open();
  const operation = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(operation);
  const physicalLock = path.join(root, ".rootark-sync.lock");
  const originalKeyFor = client.keyFor.bind(client);
  let releaseKey;
  let enteredKey;
  const deferredKey = new Promise((resolve) => { releaseKey = resolve; });
  const keyStarted = new Promise((resolve) => { enteredKey = resolve; });
  client.keyFor = async (...args) => {
    enteredKey();
    await deferredKey;
    return originalKeyFor(...args);
  };
  let pendingApply;
  let outerSettled = false;
  const owner = client.withMutationLock(async () => {
    pendingApply = client._apply(operation);
    await keyStarted;
    // Deliberately return without awaiting the started _apply.
  }).then(() => { outerSettled = true; });
  await keyStarted;
  // Give the original owner's async finally a complete event-loop turn. The
  // lock must be retained even when the callback has already returned.
  await new Promise((resolve) => setImmediate(resolve));
  const stillHeld = await exists(physicalLock);
  const prematurelySettled = outerSettled;
  releaseKey();
  await Promise.all([owner, pendingApply]);
  assert.equal(stillHeld, true,
    "a live native-required mutation must retain the real process lock across deferred key I/O");
  assert.equal(prematurelySettled, false,
    "withMutationLock may not settle before an in-flight private mutation");
  assert.equal(await exists(physicalLock), false,
    "the physical lock may be retired only AFTER the complete inbound transaction");
  assert.equal(await fsp.readFile(path.join(root, "docs", "restore.txt"), "utf8"),
    "remote content behind deferred key resolver");
  assert.equal(state.pushes, 0);
});

test("issue 66: a started unawaited native-required outbound retry holds its lock until adapter I/O finishes", async (t) => {
  const { root, open, store, adapter, state } = await setup(t, {
    "docs/restore.txt": "remote outbound test fixture",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const rootLock = path.join(root, ".rootark-sync.lock");
  let releaseDispatch;
  let dispatchStarted;
  let dispatchCalls = 0;
  const dispatchGate = new Promise((resolve) => { releaseDispatch = resolve; });
  const entered = new Promise((resolve) => { dispatchStarted = resolve; });
  const originalPush = adapter.push;
  adapter.push = async () => {
    dispatchCalls += 1;
    dispatchStarted();
    await dispatchGate;
    return { status: 201 };
  };
  let pendingRetry;
  let ownerSettled = false;
  try {
    const owner = client.withMutationLock(async () => {
      pendingRetry = client.retryPush(operation);
      await entered;
      // Intentionally return before the private outbound request completes.
    }).then(() => { ownerSettled = true; });
    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    const heldWhileDispatchPending = await exists(rootLock);
    const prematureOwnerCompletion = ownerSettled;
    releaseDispatch();
    await Promise.all([owner, pendingRetry]);
    assert.equal(heldWhileDispatchPending, true,
      "cross-process root exclusion must cover a started outbound request");
    assert.equal(prematureOwnerCompletion, false);
    assert.equal(await exists(rootLock), false);
    assert.equal(dispatchCalls, 1);
    assert.equal(state.pushes, 0, "fixture's real remote writer must never run");
  } finally {
    releaseDispatch();
    adapter.push = originalPush;
  }
});

test("issue 66: direct native-required cold open and snapshot persistence cannot bypass the physical root lock", async (t) => {
  const { root, open, state, store } = await setup(t, {
    "docs/restore.txt": "cache fixture never admitted without the physical lock",
  });
  const client = await open();
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const remoteBefore = JSON.stringify(store.list("alice"));
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._open(), { code: "sync_root_busy" });
  await assert.rejects(client.persistSnapshot(), { code: "sync_root_busy" });
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(await exists(path.join(root, "docs", "restore.txt")), false);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
});

test("issue 66: direct cold private _materializeRemote cannot create a root marker before acquiring the physical lock", async (t) => {
  const { root, adapter, key, state } = await setup(t, {
    "docs/restore.txt": "remote cold inventory fixture",
  });
  const client = new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true,
  });
  await fsp.mkdir(root, { recursive: true });
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._materializeRemote("docs/restore.txt"),
    { code: "sync_root_busy" });
  for (const leaf of [".rootark-sync-ever-fod", ".rootark-sync-index.json",
    ".rootark-sync-journal.json", "docs"]) {
    assert.equal(await exists(path.join(root, leaf)), false,
      `private cold path must not create ${leaf} under an unowned lock`);
  }
  assert.equal(state.pushes, 0);
  assert.equal(state.inventoryReads, 0, "deny before contacting remote inventory");
});

test("issue 66: an unawaited inbound publish that physically renames then fails cannot make its lock owner succeed", async (t) => {
  const payload = "published physical bytes before injected EIO";
  const { root, open, store, state } = await setup(t, { "docs/restore.txt": payload });
  const client = await open();
  const operation = store.list("alice").find((entry) => entry.metadata?.path === "docs/restore.txt");
  assert.ok(operation);
  const target = path.join(root, "docs", "restore.txt");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const originalKeyFor = client.keyFor.bind(client);
  const originalRename = fsp.rename;
  let keyEntered;
  let releaseKey;
  const entered = new Promise((resolve) => { keyEntered = resolve; });
  const gate = new Promise((resolve) => { releaseKey = resolve; });
  client.keyFor = async (...args) => {
    keyEntered();
    await gate;
    return originalKeyFor(...args);
  };
  let physicallyPublished = false;
  fsp.rename = async (source, destination, ...args) => {
    if (!physicallyPublished && String(source).includes(".tmp-inbound-")
      && path.resolve(String(destination)) === path.resolve(target)) {
      await originalRename(source, destination, ...args);
      physicallyPublished = true;
      throw Object.assign(new Error("physical inbound rename completed then EIO"), { code: "EIO" });
    }
    return originalRename(source, destination, ...args);
  };
  let detached;
  try {
    const owner = client.withMutationLock(async () => {
      detached = client._apply(operation);
      await entered;
      // Return without awaiting the started private physical publication.
    });
    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
    releaseKey();
    await assert.rejects(owner, { code: "EIO" },
      "outer lock owner must not report SUCCESS after detached publisher EIO");
    // Attach the caller observer only AFTER the owner has observed the error:
    // the trusted internal observer must prevent an unhandled Node rejection.
    await assert.rejects(detached, { code: "EIO" });
  } finally {
    releaseKey();
    fsp.rename = originalRename;
  }
  assert.equal(physicallyPublished, true);
  assert.equal(await fsp.readFile(target, "utf8"), payload);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "ambiguous physical completion must quarantine the real process lock");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: an unawaited outbound adapter failure cannot make the physical lock owner succeed", async (t) => {
  const { root, open, store, state, adapter } = await setup(t, {
    "docs/restore.txt": "remote owned bytes",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const originalPush = adapter.push;
  let dispatchEntered;
  let releaseDispatch;
  const entered = new Promise((resolve) => { dispatchEntered = resolve; });
  const gate = new Promise((resolve) => { releaseDispatch = resolve; });
  adapter.push = async () => {
    dispatchEntered();
    await gate;
    throw Object.assign(new Error("injected unresolved remote acknowledgement"),
      { code: "authorization_rejected" });
  };
  let detached;
  try {
    const owner = client.withMutationLock(async () => {
      detached = client.retryPush(operation);
      await entered;
    });
    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
    releaseDispatch();
    await assert.rejects(owner, { code: "authorization_rejected" });
    await assert.rejects(detached, { code: "authorization_rejected" });
  } finally {
    releaseDispatch();
    adapter.push = originalPush;
  }
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "detached ambiguous outgoing I/O must not retire its owner's physical lock");
  assert.equal(state.pushes, 0, "the fixture's real remote writer must not execute");
});

test("issue 66: an already-settled unawaited private retry failure still blocks the owner's success", async (t) => {
  const { root, open, store, state, adapter } = await setup(t, {
    "docs/restore.txt": "signed remote retry failure",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const lock = path.join(root, ".rootark-sync.lock");
  const originalPush = adapter.push;
  let entered;
  const pushEntered = new Promise((resolve) => { entered = resolve; });
  adapter.push = async () => {
    entered();
    throw Object.assign(new Error("remote commit has unknown outcome"), { code: "EIO" });
  };
  let unawaited;
  try {
    const owner = client.withMutationLock(async () => {
      unawaited = client.retryPush(operation);
      await pushEntered;
      // The rejected private promise FINISHES before the owner callback
      // returns. Its ticket is no longer in the active inFlight set.
      await new Promise((resolve) => setImmediate(resolve));
    });
    await assert.rejects(owner, { code: "EIO" },
      "a failed private operation must not vanish when its ticket settled early");
    await assert.rejects(unawaited, { code: "EIO" });
  } finally {
    adapter.push = originalPush;
  }
  assert.equal(await exists(lock), true,
    "a detached failed remote request must keep the real physical lock");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: an owner that throws cannot release the lock after a different detached error has settled", async (t) => {
  const { root, open, store, adapter, state } = await setup(t, {
    "docs/restore.txt": "signed remote operation",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const oldPush = adapter.push;
  let entered;
  const dispatched = new Promise((resolve) => { entered = resolve; });
  adapter.push = async () => {
    entered();
    throw Object.assign(new Error("ambiguous detached remote I/O"), { code: "EIO" });
  };
  let child;
  try {
    const owner = client.withMutationLock(async () => {
      child = client.retryPush(operation);
      await dispatched;
      // The detached EIO finishes before the owner's independent rejection.
      await new Promise((resolve) => setImmediate(resolve));
      throw Object.assign(new Error("independent owner failure"), { code: "owner_abort" });
    });
    await assert.rejects(owner, { code: "owner_abort" },
      "the primary owner error must remain intact");
    await assert.rejects(child, { code: "EIO" });
  } finally {
    adapter.push = oldPush;
  }
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "an independently failed owner must still quarantine earlier detached I/O");
  assert.equal(state.pushes, 0);
  await assert.rejects(open(), { code: "sync_root_busy" });
});

test("issue 66: an awaited transient outbound failure handled as offline must not falsely quarantine a native-required root", async (t) => {
  const { root, open, adapter, store, state } = await setup(t, {});
  await fsp.mkdir(path.join(root, "docs"), { recursive: true });
  await fsp.writeFile(path.join(root, "docs", "new.txt"), "local queued bytes");
  const originalPush = adapter.push;
  adapter.push = async () => {
    throw Object.assign(new Error("transient offline before server write"), { code: "offline" });
  };
  const client = await open();
  try {
    const offline = await client.syncOnce();
    assert.equal(offline.offline, true);
    assert.equal(state.pushes, 0);
    assert.equal((await client.journal.recover()).length, 1);
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false,
      "a caught no-write offline event may release the process lock");
  } finally {
    adapter.push = originalPush;
  }
  const resumed = await open();
  const report = await resumed.syncOnce();
  assert.equal(report.pushed, 1);
  assert.equal(state.pushes, 1);
  assert.equal(store.list("alice").length, 1);
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), false);
});

test("issue 66: direct private signed batch and out-of-scope reconciliation must not bypass a foreign lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "private/excluded.txt": "signed remote bytes",
  });
  const client = await open();
  const operation = store.list("alice")[0];
  assert.ok(operation);
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const remoteBefore = JSON.stringify(store.list("alice"));
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client.reconcileOutOfScopeMove(operation, { conflicts: [] }),
    { code: "sync_root_busy" });
  await assert.rejects(client.pushAtomicSignedOverwritePair([operation, operation],
    { pushed: 0 }), { code: "sync_root_busy" });
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, "private", "excluded.txt")), false);
});

test("issue 66: direct private eviction, staging and ledger replay cannot probe past a foreign lock", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/cache.txt": "signed remote cache bytes",
  });
  const client = await open();
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client.stageExisting(path.join(root, "docs", "cache.txt")),
    { code: "root_session_native_unavailable" });
  await assert.rejects(client._evictLocal("docs/cache.txt"),
    { code: "root_session_native_unavailable" });
  await assert.rejects(client.replayEvictionLedger(), { code: "sync_root_busy" });
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
});

test("issue 66: native-required private pull, push, enqueue and prune deny before reading or mutating", async (t) => {
  const { root, open, state, store } = await setup(t, {
    "docs/restore.txt": "authenticated remote bytes",
  });
  const client = await open();
  const empty = path.join(root, "docs", "nested-empty");
  await fsp.mkdir(empty, { recursive: true });
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshot);
  const readsBefore = state.fullReads.length;
  await fsp.mkdir(path.join(root, ".rootark-sync.lock"), { mode: 0o700 });
  await assert.rejects(client._pullRemote({ pulled: 0, offline: false }),
    { code: "sync_root_busy" });
  await assert.rejects(client._pushPending({ pushed: 0 }),
    { code: "sync_root_busy" });
  await assert.rejects(client._enqueueChange({ operation: "create" }),
    { code: "sync_root_busy" });
  await assert.rejects(client.pruneEmptyUntrackedParents(empty),
    { code: "sync_root_busy" });
  assert.equal(await exists(empty), true, "a foreign lock must prevent rmdir of an untracked parent");
  assert.equal(state.fullReads.length, readsBefore,
    "direct pull must refuse before network inventory or full-content fetch");
  assert.equal(state.pushes, 0);
  assert.equal(store.list("alice").length, 1);
  assert.deepEqual(await fsp.readFile(snapshot), snapshotBefore);
});

test("issue 66: equal-byte foreign inbound stage cannot authorize a successful FOD publish", async (t) => {
  const payload = "remote source payload with identical foreign bytes";
  const { root, open, store, state } = await setup(t, { "docs/restore.txt": payload });
  const client = await open();
  const parent = path.join(root, "docs");
  await fsp.mkdir(parent, { recursive: true });
  const target = path.join(parent, "restore.txt");
  const parked = path.join(path.dirname(root), "original-inbound-stage-parked");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const storeBefore = JSON.stringify(store.list("alice"));
  const originalOpen = fsp.open;
  const originalRename = fsp.rename;
  const heldFlags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0);
  const observeOpened = async (handle) => {
    const before = await handle.stat({ bigint: true });
    assert.equal(before.isFile(), true);
    assert.ok(before.ino > 0n && before.size <= BigInt(Buffer.byteLength(payload)));
    const bytes = Buffer.alloc(Buffer.byteLength(payload) + 1);
    let count = 0;
    while (count < bytes.length) {
      const { bytesRead } = await handle.read(bytes, count, bytes.length - count, count);
      if (!bytesRead) break;
      count += bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    assert.equal(after.dev, before.dev);
    assert.equal(after.ino, before.ino);
    assert.equal(after.size, before.size);
    assert.equal(after.mtimeNs, before.mtimeNs);
    assert.equal(BigInt(count), before.size);
    return { stat: before, bytes: bytes.subarray(0, count).toString("utf8") };
  };
  let publisherHandle;
  let foreignHandle;
  let parkedHandle;
  let publishedHandle;
  let originalInode;
  let foreignInode;
  let physicallyPublished = false;
  fsp.open = async (file, flags, ...args) => {
    const handle = await originalOpen(file, flags, ...args);
    if (!publisherHandle && typeof flags === "number" && (flags & fs.constants.O_EXCL)
      && String(file).includes(".tmp-inbound-")) publisherHandle = handle;
    return handle;
  };
  fsp.rename = async (source, destination, ...args) => {
    if (!physicallyPublished && path.resolve(String(destination)) === path.resolve(target)
      && String(source).includes(".tmp-inbound-")) {
      assert.ok(publisherHandle, "the producer must retain its exact opened stage handle");
      originalInode = await publisherHandle.stat({ bigint: true });
      assert.equal(originalInode.isFile(), true);
      await originalRename(source, parked);
      foreignHandle = await fsp.open(source, fs.constants.O_RDWR | fs.constants.O_CREAT
        | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
      await foreignHandle.writeFile(payload);
      await foreignHandle.sync();
      foreignInode = (await observeOpened(foreignHandle)).stat;
      assert.equal(originalInode.dev === foreignInode.dev
        && originalInode.ino === foreignInode.ino, false,
        "physical replacement must be a different inode despite byte equality");
      await originalRename(source, destination, ...args);
      physicallyPublished = true;
      const stillHeld = await publisherHandle.stat({ bigint: true });
      assert.equal(stillHeld.dev, originalInode.dev);
      assert.equal(stillHeld.ino, originalInode.ino,
        "the same original publisher inode must remain opened after foreign publication");
      return;
    }
    return originalRename(source, destination, ...args);
  };
  try {
    await assert.rejects(client.materializeRemote("docs/restore.txt"),
      { code: "invalid_snapshot" });
    assert.equal(physicallyPublished, true,
      "test must cause a REAL kernel rename of foreign source bytes into the target");
    parkedHandle = await fsp.open(parked, heldFlags);
    publishedHandle = await fsp.open(target, heldFlags);
    const parkedProof = await observeOpened(parkedHandle);
    const publishedProof = await observeOpened(publishedHandle);
    assert.equal(parkedProof.stat.dev, originalInode.dev);
    assert.equal(parkedProof.stat.ino, originalInode.ino,
      "parked name must bind to the original opened stage inode");
    assert.equal(publishedProof.stat.dev, foreignInode.dev);
    assert.equal(publishedProof.stat.ino, foreignInode.ino,
      "published name must bind to the actual opened foreign inode");
    assert.equal(publishedProof.bytes, payload,
      "the same opened foreign inode must contain the byte-identical payload");
    assert.equal(parkedProof.bytes, payload);
    assert.equal((await observeOpened(foreignHandle)).bytes, payload);
    assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot,
      "the untrusted replacement must not become durably authenticated metadata");
    assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true);
    await assert.rejects(client._reconcileLocal(), { code: "sync_inbound_indeterminate" });
    await assert.rejects(open(), { code: "sync_root_busy" });
    assert.equal(state.pushes, 0);
    assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  } finally {
    fsp.rename = originalRename;
    fsp.open = originalOpen;
    if (publishedHandle) await publishedHandle.close();
    if (parkedHandle) await parkedHandle.close();
    if (foreignHandle) await foreignHandle.close();
  }
});

test("issue 66: signed FOD directory CREATE followed by snapshot EIO keeps cold root locked", async (t) => {
  const { root, adapter, store, state, key } = await setup(t, {});
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const engineOptions = {
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (op) => verifyAuthorizationProof(op.authorization, op, trusted),
  };
  const client = await new SyncEngine(engineOptions).open();
  const directory = path.join(root, "docs");
  const snapshot = path.join(root, ".rootark-sync-index.json");
  const oldSnapshot = await fsp.readFile(snapshot);
  const operation = protocol.createOperation({
    operation: "create", objectId: `object-${crypto.randomUUID()}`,
    fileId: `file-${crypto.randomUUID()}`, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    baseRevision: null, metadata: { path: "docs", name: "docs", size: 0,
      contentType: "inode/directory" }, plaintext: Buffer.alloc(0), fileKey: key,
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", privateKey: signer.privateKey, publicKey,
    expiresAt: Date.now() + 60_000,
  });
  const oldStore = JSON.stringify(store.list("alice"));
  const originalMkdir = fsp.mkdir;
  const originalRename = fsp.rename;
  let physicallyCreated = false;
  let snapshotEio = false;
  fsp.mkdir = async (candidate, ...args) => {
    const result = await originalMkdir(candidate, ...args);
    if (path.resolve(String(candidate)) === path.resolve(directory)) physicallyCreated = true;
    return result;
  };
  fsp.rename = async (source, target, ...args) => {
    if (physicallyCreated && !snapshotEio && path.resolve(String(target)) === path.resolve(snapshot)
      && String(source).includes(".tmp-")) {
      snapshotEio = true;
      throw Object.assign(new Error("injected snapshot publish EIO after mkdir"), { code: "EIO" });
    }
    return originalRename(source, target, ...args);
  };
  try {
    await assert.rejects(client.apply(operation), { code: "EIO" });
  } finally {
    fsp.mkdir = originalMkdir;
    fsp.rename = originalRename;
  }
  assert.equal(physicallyCreated, true, "the physical signed directory CREATE must actually execute");
  assert.equal(snapshotEio, true, "EIO must happen at the later snapshot, not before mkdir");
  assert.equal((await fsp.lstat(directory)).isDirectory(), true);
  assert.deepEqual(await fsp.readFile(snapshot), oldSnapshot,
    "the durable snapshot must not claim the newly created directory");
  assert.equal(await exists(path.join(root, ".rootark-sync.lock")), true,
    "indeterminate physical directory CREATE must retain the process lock");
  await assert.rejects(new SyncEngine(engineOptions).open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "no outbound push is observed; this does not prove an upload attempt");
  const journal = JSON.parse(await fsp.readFile(path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.deepEqual(journal.pending, [], "a fresh local CREATE must not have been enqueued");
  assert.equal(JSON.stringify(store.list("alice")), oldStore);
});

test("issue 66: a dangling ever-FOD symlink is invalid, never an absent root marker", async (t) => {
  const { root, adapter, key } = await setup(t, {});
  await fsp.mkdir(root, { recursive: true });
  const marker = path.join(root, ".rootark-sync-ever-fod");
  try { await fsp.symlink("nonexistent-target", marker, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) { t.skip("symlink creation unavailable"); return; }
    throw error;
  }
  await assert.rejects(new SyncEngine({ rootDir: root, adapter,
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key,
  }).open(), { code: "root_mode_marker_invalid" });
  assert.equal(await exists(path.join(root, ".rootark-sync-index.json")), false);
});

test("issue 66: held marker inspection uses bounded FD reads under physical concurrent growth", async (t) => {
  const { root, open, adapter, key } = await setup(t, {});
  await open();
  if (process.platform === "linux" && process.env.ROOTARK_ISSUE66_FIFO_REQUIRE_EXT4 === "1") {
    assert.match(process.version, /^v22\./);
    assert.equal((await fsp.statfs(root)).type, 0xef53,
      "explicit marker growth race must be exercised on physical ext4");
  }
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const snapshotPath = path.join(root, ".rootark-sync-index.json");
  const snapshotBefore = await fsp.readFile(snapshotPath);
  const originalSize = (await fsp.stat(marker)).size;
  const originalOpen = fsp.open;
  let unboundedRead = false;
  let mutated = false;
  let reads = 0;
  let maxRequested = 0;
  let totalReturned = 0;
  fsp.open = async (...args) => {
    const handle = await originalOpen(...args);
    if (args[0] === marker) {
      const actualRead = handle.read.bind(handle);
      handle.readFile = async () => {
        unboundedRead = true;
        throw new Error("UNBOUNDED_MARKER_READ_FORBIDDEN");
      };
      handle.read = async (buffer, offset, length, position) => {
        reads++;
        maxRequested = Math.max(maxRequested, length);
        if (!mutated) {
          mutated = true;
          await fsp.appendFile(marker, Buffer.alloc(256 * 1024, 0x41));
        }
        const result = await actualRead(buffer, offset, length, position);
        totalReturned += result.bytesRead;
        return result;
      };
    }
    return handle;
  };
  try {
    await assert.rejects(new SyncEngine({ rootDir: root, adapter,
      deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
      fileKeyResolver: () => key,
    }).open(), { code: "root_mode_marker_invalid" });
  } finally { fsp.open = originalOpen; }
  assert.equal(unboundedRead, false, "marker admission may not call FileHandle.readFile");
  assert.equal(mutated, true, "the race must modify the physical marker during FD read");
  assert.ok(reads > 0 && maxRequested <= originalSize + 1,
    `untrusted marker read must be capped to expected bytes + 1; observed ${maxRequested}`);
  assert.ok(totalReturned <= originalSize + 1,
    `aggregate marker bytes read must be bounded; observed ${totalReturned}`);
  assert.equal((await fsp.stat(marker)).size, originalSize + 256 * 1024);
  assert.deepEqual(await fsp.readFile(snapshotPath), snapshotBefore);
});

test("issue 66: FIFO root marker fails closed in bounded cold subprocess opens and later legitimate recovery", { skip: process.platform !== "linux" }, async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-ever-fod-fifo-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  // CI may use overlayfs/tmpfs: require *physical* ext4 and Node22 only for
  // an explicit physical-custody run, without making ordinary hosted CI fail.
  if (process.env.ROOTARK_ISSUE66_FIFO_REQUIRE_EXT4 === "1") {
    assert.match(process.version, /^v22\./);
    assert.equal((await fsp.statfs(root)).type, 0xef53,
      "explicit FIFO physical run must actually use Linux ext4");
  }
  const marker = path.join(root, ".rootark-sync-ever-fod");
  const made = spawnSync("/usr/bin/mkfifo", [marker], { timeout: 1500, encoding: "utf8" });
  assert.equal(made.status, 0, made.stderr);
  const childSource = [
    "const { SyncEngine } = require(process.argv[1]);",
    "const rootDir = process.argv[2];",
    "const filesOnDemand = process.argv[3] === 'fod';",
    "new SyncEngine({ rootDir, deviceId: 'fifo-test-device', keyEpoch: 'epoch-1',",
    "compartmentId: 'private', filesOnDemand, fileKeyResolver: () => Buffer.alloc(32),",
    "adapter: { list: async () => [], listInventory: async () => ({protocolVersion:2, view:'metadata', objects:[], nextCursor:null}), push: async () => ({status: 201}) } }).open()",
    ".then(() => { process.stdout.write('OPEN_OK\\n'); process.exit(0); })",
    ".catch((error) => { process.stdout.write('DENIED:' + error.code + '\\n'); process.exit(2); });",
  ].join("\n");
  const reopen = (mode) => spawnSync(process.execPath,
    ["-e", childSource, require.resolve("../sync-client/rootark-sync-engine"), root, mode],
    { timeout: 8000, encoding: "utf8" });
  for (const mode of ["legacy", "fod"]) {
    const denied = reopen(mode);
    assert.equal(denied.error?.code, undefined, `FIFO marker must not hang ${mode} cold open`);
    assert.equal(denied.status, 2, denied.stderr);
    assert.match(denied.stdout, /DENIED:root_mode_marker_invalid/);
  }
  assert.equal(await fsp.stat(marker).then((s) => s.isFIFO()), true);
  assert.equal(await fsp.stat(path.join(root, ".rootark-sync-index.json")).then(() => true, () => false), false);
  await fsp.unlink(marker);
  const recovered = reopen("fod");
  assert.equal(recovered.error?.code, undefined);
  assert.equal(recovered.status, 0, recovered.stderr);
  assert.match(recovered.stdout, /OPEN_OK/);
  const coldReopen = reopen("fod");
  assert.equal(coldReopen.status, 0, coldReopen.stderr);
  assert.match(coldReopen.stdout, /OPEN_OK/);
  const downgrade = reopen("legacy");
  assert.equal(downgrade.status, 2, downgrade.stderr);
  assert.match(downgrade.stdout, /DENIED:root_mode_fod_required/);
});

test("issue 66: refuses unsafe cached refresh and preserves dirty cached bytes", async (t) => {
  const { root, source, writer, open } = await setup(t, { "docs/version.txt": "version one" });
  const client = await open();
  await client.materializeRemote("docs/version.txt");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version two");
  await writer.syncOnce();
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  await assert.rejects(client.materializeRemote("docs/version.txt"), { code: "root_session_native_unavailable" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "version one");
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);

  await fsp.writeFile(path.join(root, "docs", "version.txt"), "offline local changes");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version three");
  await writer.syncOnce();
  await assert.rejects(client.materializeRemote("docs/version.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "offline local changes");
});

test("issue 66: local changes during remote fetch cannot be overwritten", async (t) => {
  const { root, source, writer, open, adapter } = await setup(t, { "docs/race.txt": "clean cached" });
  const client = await open();
  await client.materializeRemote("docs/race.txt");
  await fsp.writeFile(path.join(source, "docs", "race.txt"), "new remote version");
  await writer.syncOnce();
  const oldList = adapter.list;
  adapter.list = async (objectId) => {
    const response = await oldList(objectId);
    await fsp.writeFile(path.join(root, "docs", "race.txt"), "edited during network request");
    return response;
  };
  await assert.rejects(client.materializeRemote("docs/race.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "race.txt"), "utf8"), "edited during network request");
});

test("issue 66: a remote MOVE must not relocate unsynced local source bytes", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/original.txt": "original verified bytes" });
  const client = await open();
  await client.materializeRemote("docs/original.txt");
  const before = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-move-v2", operationId: "on-demand-move-v2-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("original verified bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  await fsp.writeFile(path.join(root, "docs", "original.txt"), "unsynced edits");
  await assert.rejects(client.materializeRemote("docs/renamed.txt"), { code: "local_changes_pending" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "original.txt"), "utf8"), "unsynced edits");
  assert.equal(await exists(path.join(root, "docs", "renamed.txt")), false);
});

test("issue 66: even a clean cached source cannot be renamed by legacy FOD MOVE without native custody", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/original.txt": "signed move bytes" });
  const client = await open();
  await client.materializeRemote("docs/original.txt");
  const before = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-good-move", operationId: "on-demand-good-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("signed move bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  const originalBytes = await fsp.readFile(path.join(root, "docs", "original.txt"));
  const snapshotBefore = await fsp.readFile(path.join(root, ".rootark-sync-index.json"));
  const remoteBefore = JSON.stringify(store.list("alice"));
  const pendingBefore = (await client.journal.recover()).map((item) => item.operationId);
  await assert.rejects(client.apply(move), { code: "root_session_native_unavailable" });
  await assert.rejects(client.materializeRemote("docs/renamed.txt"), { code: "root_session_native_unavailable" });
  assert.deepEqual(await fsp.readFile(path.join(root, "docs", "original.txt")), originalBytes);
  assert.deepEqual(await fsp.readFile(path.join(root, ".rootark-sync-index.json")), snapshotBefore);
  assert.equal(await exists(path.join(root, "docs", "renamed.txt")), false);
  assert.equal(await exists(path.join(root, ".rootark-trash")), false);
  assert.deepEqual((await client.journal.recover()).map((item) => item.operationId), pendingBefore);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
});

test("issue 66: first hydration of authorized signed MOVE with no local source or destination stays available", async (t) => {
  const { root, adapter, store, key, state } = await setup(t, { "docs/original.txt": "verified first hydration" });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trusted = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  let verified = 0;
  const client = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => {
      verified++;
      return verifyAuthorizationProof(op.authorization, op, trusted);
    },
  }).open();
  const original = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: "first-hydration-move", operationId: "first-hydration-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("verified first hydration"), key), fileKey: key,
  });
  move.authorization = await createAuthorizationProof(move, {
    username: "alice", privateKey: pair.privateKey, publicKey, expiresAt: Date.now() + 60_000,
  });
  // Store the ciphertext in the fixture's non-protected object store; supply
  // the signed envelope through the inbound adapter so strict verification
  // is exercised without forging a protected atomic device-registry write.
  const unsigned = { ...move };
  delete unsigned.authorization;
  assert.equal((await store.put("alice", unsigned)).kind, "stored");
  const listFromStore = adapter.list;
  adapter.list = async (objectId) => (await listFromStore(objectId))
    .map((record) => record.operationId === move.operationId ? move : record);
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false);
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  const remoteBefore = JSON.stringify(store.list("alice"));
  assert.equal(await client.materializeRemote("docs/new.txt"), true);
  assert.ok(verified > 0, "real Ed25519 pinned-key verifier must run");
  assert.equal(client.journal.hasSeen(move.operationId), true);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(await fsp.readFile(path.join(root, "docs", "new.txt"), "utf8"), "verified first hydration");
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false);
  assert.equal(JSON.stringify(store.list("alice")), remoteBefore);
  assert.equal(state.pushes, 0);
  const reopened = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b",
    keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => verifyAuthorizationProof(op.authorization, op, trusted),
  }).open();
  assert.equal(reopened.snapshot.files["docs/new.txt"].objectId, move.objectId);
  assert.equal(reopened.snapshot.files["docs/new.txt"].versionId, move.versionId);
  assert.equal(reopened.journal.hasSeen(move.operationId), true);
});
