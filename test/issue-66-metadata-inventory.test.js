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
  assert.equal(store.inventoryCache.username, "alice");
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
