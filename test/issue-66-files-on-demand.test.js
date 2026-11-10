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
  await assert.rejects(client._apply(remoteDelete), { code: "root_session_native_unavailable" },
    "private direct apply must not bypass the public method fence");
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

test("issue 66: failed FOD hydration cannot delete a physically substituted inbound temporary", async (t) => {
  const { root, open, store, state } = await setup(t, {
    "docs/restore.txt": "authenticated recovery payload",
  });
  const client = await open();
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
  const cold = await open();
  const physical = await cold.scanFiles();
  assert.equal(Object.keys(physical).some((name) => name.endsWith("/" + path.basename(temporary))), false,
    "a cold FOD scan must not upload an uncertain payload temporary as a user file");
  assert.equal(await cold.materializeRemote("docs/restore.txt"), true,
    "legitimate cold hydration must remain available after a failed publish");
  assert.equal(await fsp.readFile(target, "utf8"), "authenticated recovery payload");
  assert.equal(await fsp.readFile(temporary, "utf8"), foreignBytes);
  assert.equal(JSON.stringify(store.list("alice")), storeBefore);
  assert.equal(state.pushes, pushesBefore, "cold recovery may not sign a foreign temp or delete");
});

test("issue 66: physical post-publish FOD crash retains cold lock and forbids unsigned outbound reconcile", async (t) => {
  const { root, open, store, state, key } = await setup(t, {
    "docs/restore.txt": "trusted signed-source recovery bytes",
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
    'if(!operation)throw Error("signed-source record missing");',
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
  assert.ok(child.status !== 0 || child.signal,
    "crash boundary must terminate the separate process without returning");
  assert.equal(await fsp.readFile(target, "utf8"), "trusted signed-source recovery bytes");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot,
    "the original snapshot is physically older than published payload");
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
  // A real abnormal process termination leaves the preexisting root lock.
  // Cold open MUST stop here; never simulate a custodian or unlink this
  // security lock from a same-UID/SID writable path to force a fake replay.
  await assert.rejects(open(), { code: "sync_root_busy" });
  assert.equal(state.pushes, 0, "cold replay cannot sign an untracked inbound file as a new CREATE");
  const diskJournal = JSON.parse(await fsp.readFile(
    path.join(root, ".rootark-sync-journal.json"), "utf8"));
  assert.equal(diskJournal.pending.length, 0,
    "failed cold admission cannot enqueue a fresh signed outbound CREATE");
  assert.deepEqual(await fsp.readFile(snapshot), beforeSnapshot);
  assert.equal(JSON.stringify(store.list("alice")), beforeStore);
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
