"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncObjectStore } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

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

test("issue 66: verified cache eviction survives offline and hydrates again after reconnect", async (t) => {
  const { root, open, store, state } = await setup(t, { "docs/cache.txt": "cache me" });
  const client = await open();
  await client.materializeRemote("docs/cache.txt");
  const before = store.list("alice")[0];
  assert.equal(await client.evictLocal("docs/cache.txt"), true);
  assert.equal(await exists(path.join(root, "docs", "cache.txt")), false);
  state.offline = true;
  assert.equal((await client.syncOnce()).offline, true);
  await assert.rejects(client.materializeRemote("docs/cache.txt"), { code: "offline" });
  assert.equal(client.snapshot.remoteOnly[before.objectId].reason, "evicted");
  assert.equal(store.list("alice")[0].operationId, before.operationId);
  state.offline = false;
  const restarted = await open();
  assert.equal(await restarted.materializeRemote("docs/cache.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "cache.txt"), "utf8"), "cache me");
  assert.equal(restarted.snapshot.remoteOnly[before.objectId], undefined);
});

test("issue 66 P2: verified evicted A can hydrate a later remote MOVE at B", async (t) => {
  const { root, open, store, key, adapter } = await setup(t,
    { "docs/a.txt": "original verified bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/a.txt"), true);
  const earlier = store.list("alice")[0];
  assert.equal(await client.evictLocal("docs/a.txt"), true);
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  const moved = protocol.createOperation({
    operation: "move", objectId: earlier.objectId, fileId: earlier.fileId,
    versionId: `moved-${crypto.randomUUID()}`, operationId: `moved-${crypto.randomUUID()}`,
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: earlier.revision,
    revision: { counter: earlier.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/b.txt", sourcePath: "docs/a.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("original verified bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const inventory = await client.syncOnce();
  assert.equal(inventory.available, 1);
  assert.equal(store.list("alice").find((item) => item.objectId === earlier.objectId).operationId,
    moved.operationId, "local reconciliation may publish a directory, never replace the remote moved file");
  const originalInventory = adapter.listInventory;
  adapter.listInventory = async (options) => {
    const page = await originalInventory(options);
    return { ...page, objects: page.objects.map((row) => row.objectId === earlier.objectId
      ? { ...row, fileId: "unrelated-file" } : row) };
  };
  await assert.rejects(client.materializeRemote("docs/b.txt"),
    { code: "remote_object_changed" },
    "an advisory MOVE that changes the evicted file identity cannot rebind the cache");
  adapter.listInventory = originalInventory;
  await fsp.writeFile(path.join(root, "docs", "b.txt"), "offline independent local bytes");
  await assert.rejects(client.materializeRemote("docs/b.txt"),
    { code: "local_changes_pending" },
    "hydrating a verified remote MOVE must never overwrite an untracked destination");
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"),
    "offline independent local bytes");
  await fsp.unlink(path.join(root, "docs", "b.txt"));
  assert.equal(await client.materializeRemote("docs/b.txt"), true,
    "new destination must recover from the AEAD MOVE payload after A was evicted");
  assert.equal(await fsp.readFile(path.join(root, "docs", "b.txt"), "utf8"),
    "original verified bytes");
  assert.equal(await exists(path.join(root, "docs", "a.txt")), false);
  assert.equal(client.snapshot.files["docs/b.txt"].objectId, earlier.objectId);
  assert.equal(client.snapshot.remoteOnly[earlier.objectId], undefined);
  assert.equal((await client.journal.recover()).length, 0);
});

test("issue 66: refreshes clean cached bytes, preserves dirty cached bytes", async (t) => {
  const { root, source, writer, open } = await setup(t, { "docs/version.txt": "version one" });
  const client = await open();
  await client.materializeRemote("docs/version.txt");
  await fsp.writeFile(path.join(source, "docs", "version.txt"), "version two");
  await writer.syncOnce();
  assert.equal(await client.materializeRemote("docs/version.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "version.txt"), "utf8"), "version two");

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

test("issue 66 P2 signed MOVE: fileId rotation cannot erase an unsynced local deletion", async (t) => {
  const dir = process.platform === "win32"
    ? path.join(process.env.LOCALAPPDATA, "rootark-signed-move-rotation-" + crypto.randomBytes(8).toString("hex"))
    : await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-signed-move-rotation-"));
  if (process.platform === "win32") ensureWindowsChunkUploadRoot(dir);
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const root = path.join(dir, "client");
  const store = await new SyncObjectStore(path.join(dir, "objects.json"),
    { atomicDeviceRegistry: true }).open();
  const key = crypto.randomBytes(32);
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  await store.enrollDevice({ username: "alice", deviceId: "device-a", publicKey, expectedEpoch: 0 });
  const sign = async (op) => {
    const signed = { ...op, authorization: await createAuthorizationProof(op, {
      username: "alice", publicKey, privateKey: signer.privateKey,
      expiresAt: Date.now() + 60_000,
    }) };
    assert.equal(await verifyAuthorizationProof(signed.authorization, signed, trust), true);
    return signed;
  };
  const objectId = "obj-" + crypto.randomUUID();
  const fileId = "file-old-" + crypto.randomUUID();
  const create = await sign(protocol.createOperation({
    operation: "create", objectId, fileId, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "docs/source.txt" }, plaintext: Buffer.from("cached A"),
    fileKey: key,
  }));
  assert.equal((await store.put("alice", create)).kind, "stored");
  const adapter = {
    async push(operation) { return (await store.put("alice", operation)).record; },
    async list(objectId = "") { return store.list("alice", objectId || null); },
    async listInventory() {
      const objects = store.list("alice").map(
        ({ ciphertext, nonce, tag, aad, authorization, ...record }) => record);
      return { protocolVersion: 2, view: "metadata", objects, nextCursor: null };
    },
  };
  let verified = 0;
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => {
      const accepted = await verifyAuthorizationProof(op.authorization, op, trust);
      if (accepted) verified += 1;
      return accepted;
    },
  }).open();
  assert.equal(await client.materializeRemote("docs/source.txt"), true);
  assert.ok(verified >= 1, "real signed CREATE must pass through strict verification");
  await fsp.unlink(path.join(root, "docs", "source.txt"));
  assert.equal(client.snapshot.files["docs/source.txt"].fileId, fileId);

  const nextFileId = "file-new-" + crypto.randomUUID();
  const update = await sign(protocol.createOperation({
    operation: "update", objectId, fileId: nextFileId, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", baseRevision: create.revision,
    revision: { counter: 2, deviceId: "device-a" },
    metadata: { path: "docs/source.txt" }, plaintext: Buffer.from("remote B"),
    fileKey: key,
  }));
  assert.equal((await store.put("alice", update)).kind, "stored",
    "real atomic device registry must accept the signed fileId rotation");
  const move = await sign(protocol.createOperation({
    operation: "move", objectId, fileId: nextFileId, versionId: crypto.randomUUID(),
    operationId: crypto.randomUUID(), deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", baseRevision: update.revision,
    revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "docs/moved.txt", sourcePath: "docs/source.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("remote B"), key), fileKey: key,
  }));
  assert.equal((await store.put("alice", move)).kind, "stored",
    "MOVE must be signed and admitted after signed UPDATE under real atomic registry");
  await assert.rejects(client.materializeRemote("docs/moved.txt"),
    { code: "local_changes_pending" },
    "a stale tracked objectId may not lose an unsynced deletion via fileId rotation");
  assert.equal(await exists(path.join(root, "docs", "moved.txt")), false);
  assert.equal(client.snapshot.files["docs/source.txt"].fileId, fileId);
  assert.equal(client.snapshot.files["docs/moved.txt"], undefined);
  assert.deepEqual(await client.journal.recover(), []);
  assert.equal(store.list("alice", objectId)[0].operationId, move.operationId);
});

for (const explicitlyEvicted of [false, true]) {
test("issue 66 P2 signed MOVE: " + (explicitlyEvicted ? "explicit eviction can move" : "missing tracked source preserves local deletion"), async (t) => {
  const content = Buffer.from("genuine Ed25519 signed MOVE payload");
  const { root, adapter, store, key } = await setup(t, { "docs/source.txt": content });
  const signer = crypto.generateKeyPairSync("ed25519");
  const publicKey = signer.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const signed = new Map();
  const sign = async (op) => {
    if (!signed.has(op.operationId)) {
      signed.set(op.operationId, { ...op, authorization: await createAuthorizationProof(op,
        { username: "alice", publicKey, privateKey: signer.privateKey, expiresAt: Date.now() + 60000 }) });
    }
    return signed.get(op.operationId);
  };
  const strictAdapter = { ...adapter,
    list: async (objectId) => Promise.all((await adapter.list(objectId)).map(sign)) };
  let verified = 0;
  const client = await new SyncEngine({
    rootDir: root, adapter: strictAdapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: async (op) => {
      const result = await verifyAuthorizationProof(op.authorization, op, trust);
      if (result) verified++;
      return result;
    },
  }).open();
  assert.equal(await client.materializeRemote("docs/source.txt"), true);
  const prior = store.list("alice")[0];
  if (explicitlyEvicted) {
    assert.equal(await client.evictLocal("docs/source.txt"), true);
    assert.equal(client.snapshot.remoteOnly[prior.objectId].reason, "evicted");
  } else {
    await fsp.unlink(path.join(root, "docs", "source.txt"));
    assert.equal(client.snapshot.files["docs/source.txt"].objectId, prior.objectId);
  }
  const moved = protocol.createOperation({
    operation: "move", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/moved.txt", sourcePath: "docs/source.txt" },
    plaintext: protocol.encodeMovePayload(content, key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  assert.equal(await verifyAuthorizationProof((await sign(moved)).authorization,
    await sign(moved), trust), true, "genuine owner-signed MOVE proof");
  if (explicitlyEvicted) {
    assert.equal(await client.materializeRemote("docs/moved.txt"), true);
    assert.deepEqual(await fsp.readFile(path.join(root, "docs", "moved.txt")), content);
  } else {
    await assert.rejects(client.materializeRemote("docs/moved.txt"),
      { code: "local_changes_pending" });
    assert.equal(await exists(path.join(root, "docs", "moved.txt")), false);
    assert.equal(client.snapshot.files["docs/source.txt"].objectId, prior.objectId);
    assert.equal(client.snapshot.files["docs/moved.txt"], undefined);
    assert.deepEqual(await client.journal.recover(), []);
  }
  assert.ok(verified >= (explicitlyEvicted ? 2 : 1), "strict Ed25519 verifier must authenticate every operation reaching admission");
});
}

test("issue 66: a clean cached source can be hydrated through a verified remote MOVE", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/original.txt": "signed move bytes" });
  const client = await open();
  await client.materializeRemote("docs/original.txt");
  const before = store.list("alice")[0];
  assert.equal((await store.put("alice", protocol.createOperation({
    operation: "move", objectId: before.objectId, fileId: before.fileId,
    versionId: "on-demand-good-move", operationId: "on-demand-good-move-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: before.revision, revision: { counter: before.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/renamed.txt", sourcePath: "docs/original.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("signed move bytes"), key), fileKey: key,
  }))).kind, "stored");
  assert.equal(await client.materializeRemote("docs/renamed.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "renamed.txt"), "utf8"), "signed move bytes");
  assert.equal(await exists(path.join(root, "docs", "original.txt")), false);
});

for (const changedFileId of [false, true]) {
test(`issue 66 #263 P2: signed old inventory cannot roll back newer object with ${changedFileId ? "changed" : "stable"} fileId`, async (t) => {
  const { root, source, writer, store, key, adapter } = await setup(t,
    { "docs/replay.txt": "authentic revision A" });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey },
    revokedDeviceIds: [] };
  const expiry = Date.now() + 60_000;
  const signed = new Map();
  const sign = async (operation) => {
    if (!signed.has(operation.operationId)) {
      signed.set(operation.operationId, {
        ...operation, authorization: await createAuthorizationProof(operation,
          { username: "alice", publicKey, privateKey: pair.privateKey, expiresAt: expiry }),
      });
    }
    return signed.get(operation.operationId);
  };
  const liveList = adapter.list.bind(adapter);
  const strictAdapter = { ...adapter,
    list: async (objectId) => Promise.all((await liveList(objectId)).map(sign)),
  };
  const client = await new SyncEngine({
    rootDir: root, adapter: strictAdapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key,
    selectedPaths: ["docs"], filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (operation) => verifyAuthorizationProof(
      operation.authorization, operation, trust),
  }).open();
  assert.equal(await client.materializeRemote("docs/replay.txt"), true);
  const revisionA = await sign(store.list("alice")[0]);
  assert.equal(await verifyAuthorizationProof(revisionA.authorization, revisionA, trust), true);
  const firstSnapshot = client.snapshot.files["docs/replay.txt"];

  if (changedFileId) {
    assert.equal(await client.evictLocal("docs/replay.txt"), true,
      "evict authentic A before the signed successor replaces its file identity");
    const next = protocol.createOperation({
      operation: "update", objectId: revisionA.objectId,
      fileId: `new-file-${crypto.randomUUID()}`,
      versionId: `new-version-${crypto.randomUUID()}`,
      operationId: `new-operation-${crypto.randomUUID()}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      baseRevision: revisionA.revision,
      revision: { counter: revisionA.revision.counter + 1, deviceId: "device-a" },
      metadata: { path: "docs/replay.txt" },
      plaintext: Buffer.from("authentic revision B"), fileKey: key,
    });
    assert.equal((await store.put("alice", next)).kind, "stored",
      "real legacy fixture store preserves a newer revision with changed fileId");
    assert.equal(await verifyAuthorizationProof((await sign(next)).authorization,
      await sign(next), trust), true,
    "client admission later receives genuine Ed25519-signed B, not a forged metadata claim");
  } else {
    await fsp.writeFile(path.join(source, "docs", "replay.txt"), "authentic revision B");
    await writer.syncOnce();
  }
  const revisionB = await sign(store.list("alice")[0]);
  assert.equal(await verifyAuthorizationProof(revisionB.authorization, revisionB, trust), true);
  assert.equal(revisionB.objectId, revisionA.objectId);
  assert.equal(revisionB.fileId === revisionA.fileId, !changedFileId);
  assert.ok(protocol.compareRevisions(revisionB.revision, revisionA.revision) > 0);
  assert.equal(await client.materializeRemote("docs/replay.txt"), true);
  const before = client.snapshot.files["docs/replay.txt"];
  assert.ok(protocol.compareRevisions(before.revision, firstSnapshot.revision) > 0);
  assert.equal(await fsp.readFile(path.join(root, "docs", "replay.txt"), "utf8"),
    "authentic revision B");

  // Replaying A involves a GENUINE owner-enrolled Ed25519 signature over the
  // old full ciphertext, together with internally consistent old inventory.
  // It is not a tampered AAD/invalid-signature canary.
  const { ciphertext, nonce, tag, aad, authorization, ...oldInventory } = revisionA;
  const liveSignedList = strictAdapter.list;
  const liveInventory = strictAdapter.listInventory;
  assert.equal(await client.evictLocal("docs/replay.txt"), true,
    "positive setup: current B is durably evicted with a pinned revision floor");
  const evictedB = { ...client.snapshot.remoteOnly[revisionB.objectId] };
  assert.equal(protocol.compareRevisions(evictedB.revision, revisionB.revision), 0);
  strictAdapter.listInventory = async () => ({ protocolVersion: 2, view: "metadata",
    objects: [oldInventory], nextCursor: null });
  strictAdapter.list = async () => [revisionA];
  await assert.rejects(client.materializeRemote("docs/replay.txt"),
    { code: "remote_rollback_detected" },
    "same genuinely signed replay A must also be rejected against an evicted B marker");
  assert.deepEqual(client.snapshot.remoteOnly[revisionB.objectId], evictedB);
  assert.equal(await exists(path.join(root, "docs", "replay.txt")), false);

  strictAdapter.listInventory = liveInventory;
  strictAdapter.list = liveSignedList;
  assert.equal(await client.materializeRemote("docs/replay.txt"), true,
    "positive control: rehydration of exactly the same signed B revision after eviction succeeds");
  assert.equal(client.snapshot.remoteOnly[revisionB.objectId], undefined);
  strictAdapter.listInventory = async () => ({ protocolVersion: 2, view: "metadata",
    objects: [oldInventory], nextCursor: null });
  strictAdapter.list = async () => [revisionA];
  await assert.rejects(client.materializeRemote("docs/replay.txt"),
    { code: changedFileId ? "local_changes_pending" : "remote_rollback_detected" },
    "historically valid Ed25519 A must not replace B, even if A's fileId changed");
  assert.equal(await fsp.readFile(path.join(root, "docs", "replay.txt"), "utf8"),
    "authentic revision B");
  assert.deepEqual(client.snapshot.files["docs/replay.txt"], before,
    "replayed old inventory cannot lower the durable local revision");
});
}

test("issue 66 #263 P2: UPDATE after remote MOVE retires the old clean cached path", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "initial bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/old.txt"), true);
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("initial bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" },
    plaintext: Buffer.from("new bytes"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  assert.equal(await client.materializeRemote("docs/new.txt"), true);
  assert.equal(await fsp.readFile(path.join(root, "docs", "new.txt"), "utf8"), "new bytes");
  assert.equal(await exists(path.join(root, "docs", "old.txt")), false);
  assert.equal(client.snapshot.files["docs/old.txt"], undefined);
  assert.equal(client.snapshot.files["docs/new.txt"].objectId, original.objectId);
  assert.deepEqual(await client.journal.recover(), []);
});

for (const localChange of ["dirty", "missing"]) {
test(`issue 66 #263 P2: relocated UPDATE preserves ${localChange} source`, async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "initial bytes" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("initial bytes"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" },
    plaintext: Buffer.from("new bytes"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  if (localChange === "dirty") await fsp.writeFile(path.join(root, "docs", "old.txt"), "local edit");
  else await fsp.unlink(path.join(root, "docs", "old.txt"));
  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "local_changes_pending" });
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, original.objectId);
  assert.equal(await exists(path.join(root, "docs", "old.txt")), localChange === "dirty");
  if (localChange === "dirty") assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "local edit");
});
}

test("issue 66 #263 P2: verified remote tombstone invalidates a clean hydrated cache", async (t) => {
  const { root, open, store, key, state } = await setup(t, { "docs/gone.txt": "cached bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/gone.txt"), true);
  const prior = store.list("alice")[0];
  const deleted = protocol.createOperation({
    operation: "delete", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/gone.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  const summary = await client.syncOnce();
  assert.equal(summary.available, 0);
  assert.equal(state.pushes, 0);
  assert.equal(await exists(path.join(root, "docs", "gone.txt")), false);
  assert.equal(client.snapshot.files["docs/gone.txt"]?.deleted, true);
  assert.deepEqual(await client.journal.recover(), []);
});

for (const localChange of ["dirty", "missing"]) {
test(`issue 66 #263 P2: ${localChange} cache refuses remote tombstone even on explicit refresh`, async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/gone.txt": "cached bytes" });
  const client = await open();
  await client.materializeRemote("docs/gone.txt");
  const prior = store.list("alice")[0];
  const deleted = protocol.createOperation({
    operation: "delete", objectId: prior.objectId, fileId: prior.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: prior.revision,
    revision: { counter: prior.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/gone.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  if (localChange === "dirty") await fsp.writeFile(path.join(root, "docs", "gone.txt"), "unsynced local edit");
  else await fsp.unlink(path.join(root, "docs", "gone.txt"));
  await assert.rejects(client.materializeRemote("docs/gone.txt"), { code: "local_changes_pending" });
  assert.equal(await exists(path.join(root, "docs", "gone.txt")), localChange === "dirty");
  if (localChange === "dirty") assert.equal(await fsp.readFile(path.join(root, "docs", "gone.txt"), "utf8"), "unsynced local edit");
  assert.equal(client.snapshot.files["docs/gone.txt"].objectId, prior.objectId);
});
}

test("issue 66 #263 P2: forged tombstone inventory cannot evict an authentic cached object", async (t) => {
  const { root, open, store, adapter } = await setup(t, { "docs/preserved.txt": "live authenticated ciphertext" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/preserved.txt"), true);
  const prior = store.list("alice")[0];
  const actualInventory = adapter.listInventory;
  adapter.listInventory = async (options) => {
    const page = await actualInventory(options);
    return { ...page, objects: page.objects.map((entry) => entry.objectId === prior.objectId
      ? { ...entry, tombstone: true, operation: "delete" } : entry) };
  };
  await assert.rejects(client.syncOnce(), { code: "inventory_changed" });
  assert.equal(await fsp.readFile(path.join(root, "docs", "preserved.txt"), "utf8"), "live authenticated ciphertext");
  assert.equal(client.snapshot.files["docs/preserved.txt"].deleted, false);
});

for (const mutation of ["dirty", "missing"]) {
test(`issue 66 #263 reviewer P2 A: UPDATE relocation source becomes ${mutation} during staging`, async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "cached pre-move" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const first = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision, revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached pre-move"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const updated = protocol.createOperation({
    operation: "update", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision, revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" }, plaintext: Buffer.from("remote update"), fileKey: key,
  });
  assert.equal((await store.put("alice", updated)).kind, "stored");
  const sourcePath = path.join(root, "docs", "old.txt");
  const destinationPath = path.join(root, "docs", "new.txt");
  const actualStage = client.stageExisting.bind(client);
  let destinationPresentWhenSourceStaged = null;
  client.stageExisting = async (target) => {
    if (target === sourcePath) {
      destinationPresentWhenSourceStaged = await exists(destinationPath);
      if (mutation === "dirty") await fsp.writeFile(sourcePath, "local racing edit");
      else await fsp.unlink(sourcePath);
    }
    return actualStage(target);
  };
  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "local_changes_pending" });
  assert.equal(destinationPresentWhenSourceStaged, false, "source must be staged before publishing destination");
  assert.equal(await exists(destinationPath), false, "failed reconciliation cannot leave orphan destination");
  assert.equal(await exists(sourcePath), mutation === "dirty");
  if (mutation === "dirty") {
    assert.equal(await fsp.readFile(sourcePath, "utf8"), "local racing edit",
      "concurrent local changes must be restored from trash");
  }
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, first.objectId);
  assert.equal(client.snapshot.files["docs/new.txt"], undefined);
  assert.equal((await client.journal.recover()).length, 0);
});
}

test("issue 66 #263 reviewer P2 B: authenticated rotated-fileId tombstone retires cache by object identity", async (t) => {
  const { root, adapter, store, key } = await setup(t, { "docs/rotated.txt": "original cache" });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const trust = { username: "alice", trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [] };
  const originalList = adapter.list;
  const authorizationExpiresAt = Date.now() + 60_000;
  adapter.list = async (objectId) => Promise.all((await originalList(objectId)).map(async (record) => ({
    ...record,
    authorization: await createAuthorizationProof(record, {
      username: "alice", publicKey, privateKey: pair.privateKey,
      expiresAt: authorizationExpiresAt,
    }),
  })));
  const client = await new SyncEngine({
    rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1",
    compartmentId: "private", fileKeyResolver: () => key, selectedPaths: ["docs"],
    filesOnDemand: true, requireAuthorization: true,
    verifyIncoming: (operation) => verifyAuthorizationProof(operation.authorization, operation, trust),
  }).open();
  await client.materializeRemote("docs/rotated.txt");
  const first = store.list("alice")[0];
  const changedFileId = `file-rotated-${crypto.randomUUID()}`;
  const deleted = protocol.createOperation({
    operation: "delete", objectId: first.objectId, fileId: changedFileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision, revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/rotated.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  assert.equal((await client.syncOnce()).available, 0);
  assert.equal(await exists(path.join(root, "docs", "rotated.txt")), false);
  assert.equal(client.snapshot.files["docs/rotated.txt"].deleted, true);
  assert.equal(client.snapshot.files["docs/rotated.txt"].fileId, changedFileId);
  assert.equal(client.journal.hasSeen(deleted.operationId), true);
});

test("issue 66 #263 reviewer P2 C: tombstone stage-time edit restores dirty cache and keeps snapshot active", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/race-delete.txt": "cached for deletion" });
  const client = await open();
  await client.materializeRemote("docs/race-delete.txt");
  const first = store.list("alice")[0];
  const deleted = protocol.createOperation({
    operation: "delete", objectId: first.objectId, fileId: first.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: first.revision, revision: { counter: first.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/race-delete.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  const sourcePath = path.join(root, "docs", "race-delete.txt");
  const actualStage = client.stageExisting.bind(client);
  let staged = false;
  client.stageExisting = async (target) => {
    if (target === sourcePath) {
      staged = true;
      await fsp.writeFile(sourcePath, "changed between clean hash and stage");
    }
    return actualStage(target);
  };
  await assert.rejects(client.materializeRemote("docs/race-delete.txt"), { code: "local_changes_pending" });
  assert.equal(staged, true, "test must race the real staging call, not just the precheck");
  assert.equal(await fsp.readFile(sourcePath, "utf8"), "changed between clean hash and stage");
  assert.equal(client.snapshot.files["docs/race-delete.txt"].deleted, false);
  assert.equal(client.journal.hasSeen(deleted.operationId), false);
});

test("#263 P2: authenticated tombstone and new live identity at one path allow clean rehydration", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/reused.txt": "previous local bytes" });
  const client = await open();
  assert.equal(await client.materializeRemote("docs/reused.txt"), true);
  const original = store.list("alice")[0];
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/reused.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", tombstone)).kind, "stored");
  const replacement = await seedRemote(store, key, "docs/reused.txt");
  assert.notEqual(replacement.objectId, original.objectId);

  assert.equal(await client.materializeRemote("docs/reused.txt"), true,
    "verified old tombstone must retire the old cache before the new live identity is hydrated");
  assert.equal(await fsp.readFile(path.join(root, "docs", "reused.txt"), "utf8"), "remote original");
  assert.equal(client.snapshot.files["docs/reused.txt"].objectId, replacement.objectId);
  assert.equal(client.journal.hasSeen(tombstone.operationId), true);
});

test("#263 P2: one dirty tombstone cache does not suppress reconciliation of another clean cache", async (t) => {
  const { root, open, store, key } = await setup(t, {
    "docs/a-dirty.txt": "first local cache", "docs/z-clean.txt": "second local cache",
  });
  const client = await open();
  await client.materializeRemote("docs/a-dirty.txt");
  await client.materializeRemote("docs/z-clean.txt");
  const before = store.list("alice");
  for (const record of before) {
    const tombstone = protocol.createOperation({
      operation: "delete", objectId: record.objectId, fileId: record.fileId,
      versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      baseRevision: record.revision,
      revision: { counter: record.revision.counter + 1, deviceId: "device-a" },
      metadata: { path: record.metadata.path }, fileKey: key,
    });
    assert.equal((await store.put("alice", tombstone)).kind, "stored");
  }
  await fsp.writeFile(path.join(root, "docs", "a-dirty.txt"), "unsynced local change");
  // Isolate the background tombstone sweep from its earlier local-change
  // enqueue: the real signed reconciliation and disk writes still execute.
  client._reconcileLocal = async () => {};
  const result = await client.syncOnce();
  assert.equal(result.pulled, 1);
  assert.equal(await fsp.readFile(path.join(root, "docs", "a-dirty.txt"), "utf8"), "unsynced local change");
  assert.equal(client.snapshot.files["docs/a-dirty.txt"].deleted, false);
  assert.equal(await exists(path.join(root, "docs", "z-clean.txt")), false);
  assert.equal(client.snapshot.files["docs/z-clean.txt"].deleted, true);
});

test("#263 P2: moved then deleted out-of-scope object only retires its selected cached path", async (t) => {
  const { root, open, store, key } = await setup(t, { "docs/old.txt": "cached tracked identity" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const move = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "private/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached tracked identity"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", move)).kind, "stored");
  const deleted = protocol.createOperation({
    operation: "delete", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: move.revision,
    revision: { counter: move.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "private/new.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", deleted)).kind, "stored");

  assert.equal((await client.syncOnce()).pulled, 1);
  assert.equal(await exists(path.join(root, "docs", "old.txt")), false);
  assert.equal(client.snapshot.files["docs/old.txt"].deleted, true);
  assert.equal(client.snapshot.files["private/new.txt"], undefined,
    "no unselected destination can gain a durable local tombstone from a relocated delete");
});

test("#263 P2: pending operation on relocated source discovered after inventory fetch blocks UPDATE", async (t) => {
  const { root, open, store, key, adapter } = await setup(t,
    { "docs/old.txt": "cached source" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached source"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const update = protocol.createOperation({
    operation: "update", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: moved.revision,
    revision: { counter: moved.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt" }, plaintext: Buffer.from("remote updated"), fileKey: key,
  });
  assert.equal((await store.put("alice", update)).kind, "stored");
  let injected = false;
  const realList = adapter.list;
  adapter.list = async (objectId) => {
    const records = await realList(objectId);
    if (!injected && objectId === original.objectId) {
      injected = true;
      await client.journal.enqueue(protocol.createOperation({
        operation: "move", objectId: `other-${crypto.randomUUID()}`,
        fileId: `other-${crypto.randomUUID()}`,
        versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
        deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
        revision: { counter: 1, deviceId: "device-b" },
        metadata: { path: "docs/elsewhere.txt",
          sourcePath: process.platform === "win32" ? "DOCS/OLD.TXT" : "docs/old.txt" },
        plaintext: protocol.encodeMovePayload(Buffer.from("other bytes"), key), fileKey: key,
      }));
    }
    return records;
  };

  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "sync_operation_pending" });
  assert.equal(injected, true, "pending source operation must be inserted after initial preflight");
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "cached source");
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, original.objectId);
});

test("#263 P2: remote MOVE cannot relocate cached source with a newly pending local operation", async (t) => {
  const { root, open, store, key, adapter } = await setup(t,
    { "docs/old.txt": "cached source for MOVE" });
  const client = await open();
  await client.materializeRemote("docs/old.txt");
  const original = store.list("alice")[0];
  const moved = protocol.createOperation({
    operation: "move", objectId: original.objectId, fileId: original.fileId,
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    baseRevision: original.revision,
    revision: { counter: original.revision.counter + 1, deviceId: "device-a" },
    metadata: { path: "docs/new.txt", sourcePath: "docs/old.txt" },
    plaintext: protocol.encodeMovePayload(Buffer.from("cached source for MOVE"), key), fileKey: key,
  });
  assert.equal((await store.put("alice", moved)).kind, "stored");
  const realList = adapter.list;
  let injected = false;
  adapter.list = async (objectId) => {
    const records = await realList(objectId);
    if (objectId === original.objectId && !injected) {
      injected = true;
      await client.journal.enqueue(protocol.createOperation({
        operation: "move", objectId: `other-${crypto.randomUUID()}`,
        fileId: `other-${crypto.randomUUID()}`,
        versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
        deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
        revision: { counter: 1, deviceId: "device-b" },
        metadata: { path: "docs/elsewhere.txt",
          sourcePath: process.platform === "win32" ? "DOCS/OLD.TXT" : "docs/old.txt" },
        plaintext: protocol.encodeMovePayload(Buffer.from("other bytes"), key), fileKey: key,
      }));
    }
    return records;
  };

  await assert.rejects(client.materializeRemote("docs/new.txt"), { code: "sync_operation_pending" });
  assert.equal(injected, true, "injection must happen after initial pending preflight");
  assert.equal(await exists(path.join(root, "docs", "new.txt")), false);
  assert.equal(await fsp.readFile(path.join(root, "docs", "old.txt"), "utf8"), "cached source for MOVE");
  assert.equal(client.snapshot.files["docs/old.txt"].objectId, original.objectId);
});
