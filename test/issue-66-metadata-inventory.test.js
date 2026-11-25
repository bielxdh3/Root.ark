"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { registerSyncRoutes, SyncObjectStore } = require("../src/routes/sync");

async function fixture(t) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-inventory-"));
  const app = express();
  app.use("/sync/v1", express.json({ limit: "9mb" }));
  const authenticate = (req, res, next) => {
    if (!req.headers["x-test-user"]) return res.status(401).json({ error: "unauthorized" });
    req.user = { username: String(req.headers["x-test-user"]) };
    next();
  };
  const requirePermission = (name) => (req, res, next) => req.headers["x-test-permission"] === name
    ? next() : res.status(403).json({ error: "forbidden" });
  const { store, ready } = registerSyncRoutes({
    app, authenticate, requirePermission, storagePath: path.join(dir, "objects.json"),
  });
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    await fsp.rm(dir, { recursive: true, force: true });
  });
  await ready;
  const url = `http://127.0.0.1:${server.address().port}`;
  const get = async (route, username = "alice", permission = "listFiles") => {
    const headers = {};
    if (username) headers["x-test-user"] = username;
    if (permission) headers["x-test-permission"] = permission;
    const response = await fetch(url + route, { headers, redirect: "error" });
    const body = await response.json();
    return { status: response.status, body, bytes: Buffer.byteLength(JSON.stringify(body)) };
  };
  const key = crypto.randomBytes(32);
  const seed = async (username, objectId, content = Buffer.alloc(100 * 1024, 0x41),
    extraMetadata = {}, targetStore = store) => {
    const operation = createOperation({
      operation: "create", objectId, fileId: `file-${objectId}`,
      versionId: `version-${objectId}`, operationId: `operation-${objectId}`,
      deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-a" },
      metadata: { path: `docs/${objectId}.txt`, name: `${objectId}.txt`, size: content.length,
        ...extraMetadata },
      plaintext: content, fileKey: key,
    });
    assert.equal((await targetStore.put(username, operation)).kind, "stored");
    return operation;
  };
  return { url, get, seed, storagePath: path.join(dir, "objects.json"), store };
}

test("issue 66 inventory: authenticated, tenant-only, deterministic pages without ciphertext; legacy GET unchanged", async (t) => {
  const { get, seed } = await fixture(t);
  for (const id of ["object-d", "object-a", "object-c", "object-b", "object-e"]) await seed("alice", id);
  await seed("bob", "object-private");
  const old = await get("/sync/v1/objects");
  assert.equal(old.status, 200);
  assert.equal(old.body.objects.length, 5);
  assert.equal(typeof old.body.objects[0].ciphertext, "string");
  assert.equal((await get("/sync/v1/objects/object-a")).body.objectId, "object-a");
  const first = await get("/sync/v1/objects?view=metadata&limit=2");
  assert.equal(first.status, 200);
  assert.equal(first.body.view, "metadata");
  assert.deepEqual(first.body.objects.map((x) => x.objectId), ["object-a", "object-b"]);
  assert.equal(first.body.objects.every((x) => !Object.hasOwn(x, "ciphertext")
    && !Object.hasOwn(x, "nonce") && !Object.hasOwn(x, "tag") && !Object.hasOwn(x, "aad")), true);
  assert.ok(first.bytes < 8192, `too much inventory: ${first.bytes}`);
  assert.ok(old.bytes > 500000);
  const ids = [...first.body.objects.map((x) => x.objectId)];
  let cursor = first.body.nextCursor;
  while (cursor) {
    const page = await get(`/sync/v1/objects?view=metadata&limit=2&cursor=${encodeURIComponent(cursor)}`);
    assert.equal(page.status, 200);
    ids.push(...page.body.objects.map((x) => x.objectId));
    cursor = page.body.nextCursor;
  }
  assert.deepEqual(ids, ["object-a", "object-b", "object-c", "object-d", "object-e"]);
  assert.equal((await get("/sync/v1/objects?view=metadata&limit=2", null)).status, 401);
  assert.equal((await get("/sync/v1/objects?view=metadata&limit=2", "alice", null)).status, 403);
  assert.deepEqual((await get("/sync/v1/objects?view=metadata&limit=2", "bob")).body.objects.map((x) => x.objectId), ["object-private"]);
  assert.equal((await get(`/sync/v1/objects?view=metadata&limit=2&cursor=${encodeURIComponent(first.body.nextCursor)}`, "bob")).status, 409);
});

test("issue 66 inventory: rejects malformed/oversized cursors and detects concurrent inventory change", async (t) => {
  const { get, seed } = await fixture(t);
  for (const id of ["object-a", "object-b", "object-c"]) await seed("alice", id);
  for (const suffix of ["limit=0", "limit=65", "limit=NaN", "limit=2.5",
    "limit=2&cursor=%%%25", "limit=2&cursor=" + "A".repeat(2000), "limit=2&cursor=e30"]) {
    assert.equal((await get(`/sync/v1/objects?view=metadata&${suffix}`)).status, 400, suffix);
  }
  assert.equal((await get("/sync/v1/objects?view=unknown")).status, 400);
  const first = await get("/sync/v1/objects?view=metadata&limit=1");
  await seed("alice", "object-new");
  assert.equal((await get(`/sync/v1/objects?view=metadata&limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`)).status, 409);
});

test("issue 66 inventory: adapter browses pages and fetches full ciphertext for only the selected object", async (t) => {
  const { url, seed } = await fixture(t);
  for (const id of ["object-a", "object-b", "object-c"]) await seed("alice", id);
  const requests = [];
  const adapter = createOpaqueSyncAdapter({ baseUrl: url, fetchImpl: async (target, options) => {
    requests.push(target);
    return fetch(target, { ...options, headers: {
      ...options.headers, "x-test-user": "alice", "x-test-permission": "listFiles",
    } });
  } });
  const first = await adapter.listInventory({ limit: 2 });
  assert.deepEqual(first.objects.map((x) => x.objectId), ["object-a", "object-b"]);
  const engine = new SyncEngine({
    rootDir: path.join(os.tmpdir(), `rootark-browser-${crypto.randomUUID()}`),
    adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs/object-b.txt"], fileKeyResolver: () => crypto.randomBytes(32),
  });
  const browsed = await engine.browseRemoteInventory({ limit: 2 });
  assert.deepEqual(browsed.objects.map((entry) => entry.selectedOnDevice), [false, true]);
  assert.equal(browsed.advisory, true);
  assert.equal(requests.every((target) => target.includes("?view=metadata")), true);
  const second = await adapter.listInventory({ limit: 2, cursor: first.nextCursor });
  assert.deepEqual(second.objects.map((x) => x.objectId), ["object-c"]);
  assert.equal(second.nextCursor, null);
  const selected = first.objects.filter((x) => x.metadata.path.startsWith("docs/object-b"));
  const full = await adapter.list(selected[0].objectId);
  assert.equal(full.objectId, "object-b");
  assert.equal(typeof full.ciphertext, "string");
  assert.equal(requests.filter((u) => /\/sync\/v1\/objects\/object-/.test(u)).length, 1);
  assert.equal(requests.some((u) => /\/sync\/v1\/objects\?$/.test(u)), false);
});

test("issue 66 P2: advisory browse rejects full envelopes and unexpected page or metadata fields from custom adapters", async () => {
  const item = {
    protocolVersion: 2, operationId: "operation-a", objectId: "object-a",
    fileId: "file-a", versionId: "version-a", operation: "create",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-a",
    metadata: { path: "docs/a.txt", name: "a.txt", size: 1 }, tombstone: false,
  };
  const page = { protocolVersion: 2, view: "metadata", objects: [item], nextCursor: null };
  let response = page;
  let inventoryReads = 0;
  const adapter = {
    listInventory: async () => { inventoryReads += 1; return response; },
    list: async () => { throw new Error("Unexpected full ciphertext read during browse"); },
    push: async () => { throw new Error("Unexpected remote write during browse"); },
  };
  // Construct but do not open a root: browsing must never touch a journal or
  // create on-disk state, nor require the operational Files On-Demand backend.
  const engine = new SyncEngine({
    rootDir: path.join(os.tmpdir(), `rootark-advisory-only-${crypto.randomUUID()}`),
    adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => { throw new Error("Unexpected key read"); },
  });
  const good = await engine.browseRemoteInventory({ limit: 2 });
  assert.deepEqual(good, { ...page, advisory: true,
    objects: [{ ...item, selectedOnDevice: true }] });
  for (const malformed of [
    { ...page, objects: [{ ...item, ciphertext: "NOT_ADVISORY", nonce: "nonce", tag: "tag", aad: "aad" }] },
    { ...page, objects: [{ ...item, authorization: { synthetic: "NOT_ADVISORY" } }] },
    { ...page, objects: [{ ...item, metadata: { ...item.metadata, protectedPlaintext: "NOT_ADVISORY" } }] },
    { ...page, privateAccountState: "NOT_ADVISORY" },
  ]) {
    response = malformed;
    await assert.rejects(engine.browseRemoteInventory({ limit: 2 }), { code: "invalid_inventory" });
  }
  assert.equal(inventoryReads, 5, "all rejected pages must come only from the metadata adapter");
});

test("issue 66 P2: advisory browse cannot publish a changing cursor, getters or Proxy records", async () => {
  const item = {
    protocolVersion: 2, operationId: "operation-a", objectId: "object-a",
    fileId: "file-a", versionId: "version-a", operation: "create",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-a",
    metadata: { path: "docs/a.txt" }, tombstone: false,
  };
  const page = { protocolVersion: 2, view: "metadata", objects: [item], nextCursor: null };
  let response = page;
  const engine = new SyncEngine({
    rootDir: path.join(os.tmpdir(), `rootark-advisory-getters-${crypto.randomUUID()}`),
    adapter: {
      listInventory: async () => response,
      list: async () => { throw new Error("Unexpected full read"); },
      push: async () => { throw new Error("Unexpected push"); },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => { throw new Error("Unexpected key read"); },
  });
  let cursorReads = 0;
  const changingCursor = { ...page };
  Object.defineProperty(changingCursor, "nextCursor", { enumerable: true,
    get() { return ++cursorReads === 1 ? null : "NOT_ADVISORY"; } });
  response = changingCursor;
  await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });

  const getterRecord = { ...item };
  Object.defineProperty(getterRecord, "metadata", { enumerable: true,
    get() { return { path: "docs/a.txt" }; } });
  for (const malicious of [
    { ...page, objects: [getterRecord] },
    { ...page, objects: [new Proxy(item, {})] },
    new Proxy(page, {}),
  ]) {
    response = malicious;
    await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });
  }
});

test("issue 66 P2: advisory DTO rejects non-JSON values and nested coercion without invoking callbacks", async () => {
  const item = {
    protocolVersion: 2, operationId: "operation-a", objectId: "object-a",
    fileId: "file-a", versionId: "version-a", operation: "create",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-a",
    metadata: { path: "docs/a.txt", name: "a.txt", size: 1 }, tombstone: false,
  };
  let response;
  let callbackCalls = 0;
  const engine = new SyncEngine({
    rootDir: path.join(os.tmpdir(), `rootark-advisory-callbacks-${crypto.randomUUID()}`),
    adapter: {
      listInventory: async () => response,
      list: async () => { throw new Error("Unexpected full ciphertext fetch"); },
      push: async () => { throw new Error("Unexpected remote write"); },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => { throw new Error("Unexpected key read"); },
  });
  const suspicious = [
    { ...item, objectId: { toString() { callbackCalls++; return "object-a"; } } },
    { ...item, metadata: { ...item.metadata, path: {
      toString() { callbackCalls++; return "docs/a.txt"; },
    } } },
    { ...item, metadata: { ...item.metadata, name: {
      toString() { callbackCalls++; return "a.txt"; },
    } } },
    { ...item, objectId: () => "object-a" },
    { ...item, objectId: Symbol("object-a") },
    { ...item, objectId: 42n },
    { ...item, metadata: { ...item.metadata, size: NaN } },
    { ...item, metadata: { ...item.metadata, size: Infinity } },
    { ...item, metadata: { ...item.metadata, path: new Date() } },
    { ...item, objectId: 123 },
    { ...item, metadata: { ...item.metadata, path: 123 } },
    { ...item, metadata: { ...item.metadata, name: 123 } },
    { ...item, revision: { counter: 1, deviceId: 123 } },
  ];
  for (const record of suspicious) {
    response = { protocolVersion: 2, view: "metadata", objects: [record], nextCursor: null };
    await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });
    assert.equal(callbackCalls, 0, "advisory parsing must not call attacker-provided coercion");
  }
  for (const pageSecret of [Symbol("secret"), 32n, () => "secret"]) {
    response = { protocolVersion: 2, view: "metadata", objects: [item], nextCursor: pageSecret };
    await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });
  }
  const hidden = { ...item };
  Object.defineProperty(hidden, "hiddenExecutable", {
    enumerable: false,
    get() { callbackCalls++; throw new Error("Advisory browse executed a hidden callback"); },
  });
  response = { protocolVersion: 2, view: "metadata", objects: [hidden], nextCursor: null };
  const sanitized = await engine.browseRemoteInventory();
  assert.equal(callbackCalls, 0);
  assert.equal(Object.hasOwn(sanitized.objects[0], "hiddenExecutable"), false);

  // JSON decoding and custom adapters may legitimately use null prototypes.
  const plainNullProto = (source) => Object.assign(Object.create(null), source);
  response = plainNullProto({ protocolVersion: 2, view: "metadata",
    objects: [plainNullProto({ ...item,
      revision: plainNullProto(item.revision),
      metadata: plainNullProto(item.metadata),
    })], nextCursor: null });
  const accepted = await engine.browseRemoteInventory();
  assert.equal(accepted.objects[0].selectedOnDevice, true);
  assert.equal(accepted.objects[0].metadata.path, "docs/a.txt");
  assert.equal(callbackCalls, 0);
});

test("issue 66 P2: advisory DTO enforces aggregate page and key budgets without callbacks", async () => {
  const item = {
    protocolVersion: 2, operationId: "operation-a", objectId: "object-a",
    fileId: "file-a", versionId: "version-a", operation: "create",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-a",
    metadata: { path: "docs/a.txt", name: "a.txt", size: 1 }, tombstone: false,
  };
  let response;
  const engine = new SyncEngine({
    rootDir: path.join(os.tmpdir(), `rootark-advisory-budget-${crypto.randomUUID()}`),
    adapter: {
      listInventory: async () => response,
      list: async () => { throw new Error("Unexpected full ciphertext fetch"); },
      push: async () => { throw new Error("Unexpected remote write"); },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => { throw new Error("Unexpected key read"); },
  });
  response = { protocolVersion: 2, view: "metadata", objects: [
    { ...item, metadata: { path: `docs/${"x".repeat(140000)}` } },
  ], nextCursor: null };
  await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });

  const excess = { ...item };
  for (let i = 0; i < 2048; i++) excess[`unrecognized${i}`] = "x";
  response = { protocolVersion: 2, view: "metadata", objects: [excess], nextCursor: null };
  await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });

  // Every individual record is schema-valid; only their aggregate serialized
  // metadata exceeds the 128 KiB page budget. This is not a path-length RED.
  response = { protocolVersion: 2, view: "metadata", objects: Array.from({ length: 64 }, (_, i) => ({
    ...item, objectId: `object-${i}`, metadata: {
      path: `docs/${"x".repeat(440)}/${i}`, name: "n".repeat(500),
      contentType: "t".repeat(500), parentId: "p".repeat(160),
      fileId: "f".repeat(160), versionId: "v".repeat(160),
      keyEpoch: "e".repeat(160), compartmentId: "c".repeat(160),
      deviceId: "d".repeat(160), size: 1,
    },
  })), nextCursor: null };
  await assert.rejects(engine.browseRemoteInventory(), { code: "invalid_inventory" });
});

test("issue 66 P2: advisory browse bounds custom adapter pages, cursor and request inputs before returning UI data", async () => {
  const item = {
    protocolVersion: 2, operationId: "operation-a", objectId: "object-a",
    fileId: "file-a", versionId: "version-a", operation: "create",
    revision: { counter: 1, deviceId: "device-a" }, baseRevision: null,
    keyEpoch: "epoch-1", compartmentId: "private", deviceId: "device-a",
    metadata: { path: "docs/a.txt" }, tombstone: false,
  };
  let response = { protocolVersion: 2, view: "metadata", objects: [item], nextCursor: null };
  let inventoryReads = 0;
  const engine = new SyncEngine({
    rootDir: path.join(os.tmpdir(), `rootark-advisory-bounds-${crypto.randomUUID()}`),
    adapter: {
      listInventory: async () => { inventoryReads += 1; return response; },
      list: async () => { throw new Error("Unexpected full read"); },
      push: async () => { throw new Error("Unexpected push"); },
    },
    deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    selectedPaths: ["docs"], fileKeyResolver: () => { throw new Error("Unexpected key read"); },
  });
  for (const malformed of [
    { ...response, objects: [item, item, item] },
    { ...response, nextCursor: "x".repeat(1025) },
    { ...response, objects: [], nextCursor: "next" },
    { ...response, view: "full" },
    { ...response, protocolVersion: 1 },
  ]) {
    response = malformed;
    await assert.rejects(engine.browseRemoteInventory({ limit: 2 }), { code: "invalid_inventory" });
  }
  const readsBeforeInvalidArgs = inventoryReads;
  for (const options of [{ limit: 0 }, { limit: 65 }, { limit: 1, cursor: "" },
    { limit: 1, cursor: "x".repeat(1025) }]) {
    await assert.rejects(engine.browseRemoteInventory(options), { code: "invalid_inventory" });
  }
  assert.equal(inventoryReads, readsBeforeInvalidArgs,
    "invalid requests must be denied before invoking a custom adapter");
});

test("issue 66 inventory: metadata-heavy library is fully paged within 128 KiB HTTP bodies", async (t) => {
  const { get, seed } = await fixture(t);
  const heavyMetadata = {
    path: `docs/${Array.from({ length: 5 }, () => "p".repeat(94)).join("/")}/file.txt`,
    name: "n".repeat(500),
    contentType: "t".repeat(500),
    parentId: "p".repeat(160),
    fileId: "f".repeat(160),
    versionId: "v".repeat(160),
    keyEpoch: "e".repeat(160),
    compartmentId: "c".repeat(160),
    deviceId: "d".repeat(160),
  };
  for (let index = 0; index < 70; index += 1) {
    await seed("alice", `object-${String(index).padStart(3, "0")}`, Buffer.from("x"), heavyMetadata);
  }
  const names = [];
  let cursor = null;
  do {
    const query = `/sync/v1/objects?view=metadata&limit=64${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
    const page = await get(query);
    assert.equal(page.status, 200);
    assert.ok(page.bytes <= 128 * 1024, `page exceeds bound: ${page.bytes}`);
    assert.ok(page.body.objects.length > 0 && page.body.objects.length <= 64);
    names.push(...page.body.objects.map((entry) => entry.objectId));
    cursor = page.body.nextCursor;
  } while (cursor);
  assert.equal(names.length, 70);
  assert.equal(new Set(names).size, 70);
});

test("issue 66 inventory: cached pages revalidate external writer commits and refuse orphaned writer locks", async (t) => {
  const { get, seed, storagePath, store } = await fixture(t);
  for (const id of ["object-a", "object-b", "object-c"]) await seed("alice", id);
  const first = await get("/sync/v1/objects?view=metadata&limit=1");
  assert.equal(first.status, 200);
  assert.equal(first.body.objects[0].objectId, "object-a");
  assert.equal(store.inventoryCache.get("alice")?.username, "alice");
  const sibling = await new SyncObjectStore(storagePath).open();
  await seed("alice", "object-aa", Buffer.from("fresh"), {}, sibling);
  const stale = await get(`/sync/v1/objects?view=metadata&limit=1&cursor=${encodeURIComponent(first.body.nextCursor)}`);
  assert.equal(stale.status, 409, "external commit must invalidate cached cursor");
  assert.deepEqual((await get("/sync/v1/objects?view=metadata&limit=4")).body.objects
    .map((record) => record.objectId), ["object-a", "object-aa", "object-b", "object-c"]);

  const lockPath = storagePath + ".writer-lock";
  await fsp.writeFile(lockPath, "external writer is running");
  t.after(() => fsp.rm(lockPath, { force: true }));
  assert.equal((await get("/sync/v1/objects?view=metadata&limit=1")).status, 503,
    "a cached metadata index cannot bypass a writer lock");
  await fsp.rm(lockPath);
  assert.equal((await get("/sync/v1/objects?view=metadata&limit=1")).status, 200);
});

test("issue 66 inventory: two active tenants reuse positive pages without rereading the entire store", async (t) => {
  const { get, seed, store, storagePath } = await fixture(t);
  for (const id of ["a-1", "a-2", "a-3"]) await seed("alice", id);
  for (const id of ["b-1", "b-2", "b-3"]) await seed("bob", id);
  const originalReadSnapshot = store.readSnapshot.bind(store);
  let reads = 0;
  store.readSnapshot = () => { reads += 1; return originalReadSnapshot(); };
  const route = "/sync/v1/objects?view=metadata&limit=1";
  const aFirst = await get(route);
  const bFirst = await get(route, "bob");
  assert.equal(aFirst.status, 200);
  assert.equal(bFirst.status, 200);
  assert.equal(reads, 2, "each tenant needs one initial verified snapshot");
  const aSecond = await get(`${route}&cursor=${encodeURIComponent(aFirst.body.nextCursor)}`);
  const bSecond = await get(`${route}&cursor=${encodeURIComponent(bFirst.body.nextCursor)}`, "bob");
  assert.equal(aSecond.status, 200);
  assert.equal(bSecond.status, 200);
  assert.deepEqual(aSecond.body.objects.map((entry) => entry.objectId), ["a-2"]);
  assert.deepEqual(bSecond.body.objects.map((entry) => entry.objectId), ["b-2"]);
  assert.equal(reads, 2, "A/B/A/B cursor paging must not re-read unchanged shared JSON");
  assert.deepEqual([...store.inventoryCache.keys()], ["alice", "bob"]);
  assert.equal(store.inventoryCache.size, 2);
  assert.ok(store.inventoryCacheBytes <= 64 * 1024 * 1024);

  const sibling = await new SyncObjectStore(storagePath).open();
  await seed("alice", "a-extra", Buffer.from("fresh"), {}, sibling);
  const stale = await get(`${route}&cursor=${encodeURIComponent(aSecond.body.nextCursor)}`);
  assert.equal(stale.status, 409, "Alice's metadata change invalidates her old cursor");
  assert.equal(reads, 3, "fresh generation requires exactly one recheck");
  const continuedBob = await get(`${route}&cursor=${encodeURIComponent(bSecond.body.nextCursor)}`, "bob");
  assert.equal(continuedBob.status, 200, "Bob's unchanged metadata keeps his tenant-scoped cursor valid");
  assert.equal(reads, 4, "cross-process generation still invalidates Bob's cached state");
});

test("issue 66 inventory: positive cache evicts least recently used tenant after two entries", async (t) => {
  const { get, seed, store } = await fixture(t);
  for (const username of ["alice", "bob", "carol"]) await seed(username, `object-${username}`, Buffer.from("x"));
  const originalReadSnapshot = store.readSnapshot.bind(store);
  let reads = 0;
  store.readSnapshot = () => { reads += 1; return originalReadSnapshot(); };
  const route = "/sync/v1/objects?view=metadata&limit=1";
  for (const username of ["alice", "bob", "alice", "carol"]) {
    assert.equal((await get(route, username)).status, 200);
  }
  assert.equal(reads, 3, "an A hit refreshes LRU before C evicts B");
  assert.deepEqual([...store.inventoryCache.keys()], ["alice", "carol"]);
  assert.ok(store.inventoryCacheBytes <= 64 * 1024 * 1024);
  assert.equal((await get(route, "alice")).status, 200);
  assert.equal(reads, 3, "cached A still reuses its snapshot");
  assert.equal((await get(route, "bob")).status, 200);
  assert.equal(reads, 4, "evicted third tenant needs one fresh read");
  assert.equal(store.inventoryCache.size, 2);
});

test("issue 66 inventory: bounded metadata index fails closed and never re-reads an oversized snapshot per page", async (t) => {
  const { get, seed, store, storagePath } = await fixture(t);
  for (let n = 0; n < 8; n += 1) {
    await seed("alice", `heavy-${n}`, Buffer.from("x"), {
      name: "n".repeat(500), contentType: "t".repeat(500),
      path: `docs/${"p".repeat(470)}/file-${n}.txt`, parentId: "p".repeat(160),
    });
  }
  await seed("bob", "small", Buffer.from("x"));
  // Force a small cap in the isolated fixture instead of generating a
  // multi-gigabyte repo test. Production always uses the default bound.
  store.inventoryCacheMaxBytes = 1024;
  const readSnapshot = store.readSnapshot.bind(store);
  let reads = 0;
  store.readSnapshot = () => { reads += 1; return readSnapshot(); };
  const route = "/sync/v1/objects?view=metadata&limit=1";
  const first = await get(route);
  assert.equal(first.status, 507);
  assert.equal(first.body.code, "metadata_index_too_large");
  assert.equal(reads, 1, "oversized inventory should incur at most one initial parse");
  for (let n = 0; n < 4; n += 1) {
    const retry = await get(route);
    assert.equal(retry.status, 507);
    assert.equal(retry.body.code, "metadata_index_too_large");
  }
  assert.equal(reads, 1, "a cached overflow marker must prevent repeated JSON parses");
  assert.equal((await get(route, "bob")).status, 200, "smaller authenticated tenant must remain usable");
  const afterOtherTenant = await get(route);
  assert.equal(afterOtherTenant.status, 507, "A must still fail closed after B populates the positive cache");
  assert.equal(afterOtherTenant.body.code, "metadata_index_too_large");
  assert.equal(reads, 2, "B must cause only its own first full read; A must reuse its overflow marker");
  assert.equal(store.inventoryOverflowMarkers.get("alice")?.maxBytes, 1024);
  assert.ok(store.inventoryOverflowMarkers.size <= 32, "negative tenant markers must remain bounded");

  // Independent process/instance commits must invalidate the overflow
  // marker, even if new inventory still exceeds the configured bound.
  const sibling = await new SyncObjectStore(storagePath).open();
  await seed("alice", "heavy-new", Buffer.from("x"), {}, sibling);
  reads = 0;
  assert.equal((await get(route)).status, 507);
  assert.equal(reads, 1, "new durable file identity forces revalidation");
  assert.equal((await get(route)).status, 507);
  assert.equal(reads, 1);
});
