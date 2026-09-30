"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const vm = require("node:vm");
const test = require("node:test");

const clientCrypto = require("../public/client/rootark-client-crypto");
const protectedIndex = require("../public/client/rootark-protected-index");
const protectedPreview = require("../public/client/rootark-protected-preview");
const protectedSession = require("../public/client/rootark-protected-session");
const syncAdapter = require("../public/client/rootark-sync-adapter");
const offlineQueue = require("../public/client/rootark-offline-queue");
const protocol = require("../sync-client/rootark-sync-protocol");
const { GroupKeySharing } = require("../src/services/groupKeySharing");
const { AtomicGroupsStore, isGroupMember, MAX_MEMBERS, registerGroupRoutes } = require("../src/routes/groups");

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.once("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function json(value) {
  return Buffer.from(JSON.stringify(value));
}

test("protected client index canonicalizes metadata and rejects tamper/wrong keys", async () => {
  const key = crypto.randomBytes(32);
  const wrongKey = crypto.randomBytes(32);
  const first = await protectedIndex.createEntry({ id: "file-1", versionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", metadata: { name: "secret.txt", size: 4, nested: { b: 2, a: 1 } } }, key);
  const second = await protectedIndex.createEntry({ id: "file-2", versionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", metadata: { name: "public.txt", size: 6 } }, key);
  assert.equal(JSON.stringify(first).includes("secret.txt"), false);
  assert.deepEqual((await protectedIndex.search([first, second], "secret", key)).map((item) => item.id), ["file-1"]);
  await assert.rejects(protectedIndex.decryptEntry(first, wrongKey));
  await assert.rejects(protectedIndex.decryptEntry({ ...first, envelope: { ...first.envelope, ciphertext: `${first.envelope.ciphertext}x` } }, key));
  assert.equal(clientCrypto.canonicalJson({ b: 2, a: 1 }), clientCrypto.canonicalJson({ a: 1, b: 2 }));
});

test("protected preview never exposes body in its envelope and decrypts locally", async () => {
  const key = crypto.randomBytes(32);
  const preview = await protectedPreview.seal({ fileId: "file-1", sourceVersionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", contentType: "text/plain", body: "private preview" }, key);
  assert.equal(JSON.stringify(preview).includes("private preview"), false);
  assert.deepEqual(await protectedPreview.open(preview, key), { fileId: "file-1", sourceVersionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", previewFormat: "rootark-protected-preview-v2", contentType: "text/plain", body: "private preview" });
  await assert.rejects(protectedPreview.open(preview, crypto.randomBytes(32)));
  await assert.rejects(protectedPreview.seal({ fileId: "file-1", sourceVersionId: "version-1", keyEpoch: "epoch-1", compartmentId: "private", contentType: "text/plain; charset=utf-8", body: "x" }, key));
  await assert.rejects(protectedPreview.open({ ...preview, fileId: "file-2" }, key));
  const jsonPreview = await protectedPreview.seal({ fileId: "file-1", sourceVersionId: "version-2", keyEpoch: "epoch-2", compartmentId: "private", contentType: "application/json", body: "{}" }, key);
  assert.equal(protectedPreview.invalidateOnEpoch([preview, jsonPreview], "file-1", "epoch-2").length, 1);
  assert.equal(protectedPreview.invalidateOnVersion([preview, jsonPreview], "file-1", "version-2").length, 1);
});

test("protected browser session keeps keys in memory and wires queue/sync/logout hooks", async () => {
  let queued = null;
  let cleared = 0;
  const store = {
    enqueue: async (operation, key) => { queued = { operation, key }; return true; },
    clear: async () => { cleared += 1; return true; },
  };
  const key = new Uint8Array(32);
  protectedSession.attachStore(store);
  protectedSession.configure({ getKey: () => key, syncOnce: () => "synced" });
  assert.equal(await protectedSession.enqueue({ operationId: "session-op" }), true);
  assert.equal(queued.key, key);
  assert.equal(protectedSession.syncOnce(), "synced");
  assert.equal(await protectedSession.logout(), true);
  assert.equal(cleared, 1);
  await assert.rejects(protectedSession.getKey());
});

test("offline queue and sync adapter reject plaintext, keys, and search terms", () => {
  const store = new Map();
  const local = { getItem: (key) => store.get(key) || null, setItem: (key, value) => store.set(key, value), removeItem: (key) => store.delete(key) };
  const queue = offlineQueue.createOfflineQueue(local);
  assert.throws(() => queue.enqueue({ ciphertext: "opaque", plaintext: "secret" }));
  const valid = protocol.createOperation({ operation: "create", objectId: "object-queue", fileId: "file-queue", versionId: "version-queue", operationId: "operation-queue", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "queue.txt" }, plaintext: Buffer.from("opaque"), fileKey: crypto.randomBytes(32) });
  assert.equal(queue.enqueue(valid), 1);
  const normalized = syncAdapter.assertOpaqueEnvelope(valid);
  assert.notEqual(normalized, valid);
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ...valid, nested: { plaintext: "secret" } }));
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ...valid, metadata: { ...valid.metadata, preview: "secret" } }));
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ...valid, metadata: { ...valid.metadata, path: "../escape" } }));
  store.set("rootark.offline.encrypted.v2", "not-json");
  assert.equal(queue.size(), 0);
  assert.equal(queue.clear(), true);
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ plaintext: "secret" }));
  assert.throws(() => syncAdapter.assertOpaqueEnvelope({ ciphertext: "x", fileKey: "key" }));
});

test("service worker caches only the public shell and bypasses protected paths", async () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "public", "service-worker.js"), "utf8");
  const handlers = {};
  const cached = [];
  const context = {
    URL,
    Promise,
    self: {
      location: { origin: "https://rootark.test" },
      addEventListener: (name, handler) => { handlers[name] = handler; },
      skipWaiting: () => Promise.resolve(),
      clients: { claim: () => Promise.resolve() },
    },
    caches: {
      open: async () => ({
        addAll: async (assets) => cached.push(...assets),
        put: async () => {},
      }),
      match: async () => null,
      keys: async () => [],
      delete: async () => true,
    },
    fetch: async () => ({ ok: true, clone: () => ({}) }),
  };
  vm.runInNewContext(source, context);
  let installWait;
  handlers.install({ waitUntil: (promise) => { installWait = promise; } });
  await installWait;
  assert.ok(cached.includes("/index.html"));
  assert.ok(cached.includes("/styles/app.css"));
  assert.ok(cached.includes("/client/rootark-api.js"));
  assert.ok(cached.includes("/client/rootark-workspace.js"));
  assert.ok(cached.includes("/client/rootark-bootstrap.js"));
  assert.ok(cached.includes("/client/rootark-protected-index.js"));
  assert.ok(cached.includes("/client/rootark-offline-queue.js"));
  assert.ok(cached.includes("/client/rootark-protected-session.js"));
  assert.equal(cached.some((asset) => /^\/(?:auth|api|files|preview|sync|encrypted|groups|folders)(?:\/|$)/i.test(new URL(asset, "https://rootark.test").pathname)), false);
  let fetchWait;
  handlers.fetch({ request: { method: "GET", url: "https://rootark.test/files/private.txt" }, respondWith: (promise) => { fetchWait = promise; } });
  assert.equal(fetchWait, undefined);
  for (const pathname of ["/auth/me", "/preview/file/public/private.txt", "/encrypted/private.txt/metadata", "/sync/operations", "/share/private-token", "/open-file/private-token/private.txt"]) {
    let intercepted = false;
    handlers.fetch({ request: { method: "GET", url: "https://rootark.test" + pathname }, respondWith: () => { intercepted = true; } });
    assert.equal(intercepted, false, pathname + " must bypass the public shell cache");
  }
  handlers.fetch({ request: { method: "GET", url: "https://rootark.test/" }, respondWith: (promise) => { fetchWait = promise; } });
  assert.ok(fetchWait);
  await fetchWait;
});

test("groups require manageUsers, persist atomically, and add folder membership access", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase13-groups-"));
  const events = [];
  const users = [{ username: "admin", role: "admin" }, { username: "alice", role: "user" }, { username: "bob", role: "user" }];
  const folders = [{ id: "folder-1", createdBy: "owner", users: { bob: { read: true } }, groupIds: [] }];
  const app = express();
  app.use(express.json());
  const authenticate = (req, _res, next) => { req.user = users.find((user) => user.username === req.headers["x-user"]) || users[1]; next(); };
  const requirePermission = (permission) => (req, res, next) => req.user.role === "admin" || req.user.permissions?.[permission] ? next() : res.status(403).json({ error: `Permissao negada: ${permission}` });
  const route = registerGroupRoutes({ app, authenticate, requirePermission, loadUsers: () => users, loadFolders: () => folders, saveFolders: (next) => folders.splice(0, folders.length, ...next), auditLog: (...args) => events.push(args), getAuditActor: () => ({ username: "admin" }), storagePath: path.join(dir, "groups.json") });
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = server.address().port;
  const denied = await request(port, "/groups", { headers: { "x-user": "alice" } });
  assert.equal(denied.status, 403);
  const createdBody = json({ name: "docs", members: ["alice"] });
  const created = await request(port, "/groups", { method: "POST", headers: { "x-user": "admin", "content-type": "application/json", "content-length": createdBody.length }, body: createdBody });
  assert.equal(created.status, 201);
  const group = JSON.parse(created.body).group;
  assert.equal(JSON.stringify(created.body).includes("password"), false);
  assert.equal(route.store.isMember("alice", [group.id]), true);
  assert.equal(isGroupMember(route.store, "alice", [group.id]), true);
  folders[0].groupIds = [group.id];
  assert.equal(route.store.isMember("alice", folders[0].groupIds), true);
  const persisted = new AtomicGroupsStore(path.join(dir, "groups.json"));
  assert.equal(persisted.get(group.id).name, "docs");
  const sharing = new GroupKeySharing({ groupId: group.id, members: ["alice"] });
  const cek = crypto.randomBytes(32);
  const cer = crypto.randomBytes(32);
  const wrap = await sharing.wrapFor({ compartmentId: "private", epoch: 1, objectId: "object-1", versionId: "version-1", keyRef: "file-1", recipientId: "alice", deviceId: "device-a", cek, cer });
  const manifestBody = json({ groupId: group.id, epoch: 1, wraps: [wrap] });
  const manifest = await request(port, `/groups/${group.id}/key-manifest`, { method: "POST", headers: { "x-user": "admin", "content-type": "application/json", "content-length": manifestBody.length }, body: manifestBody });
  assert.equal(manifest.status, 201);
  assert.equal(JSON.stringify(await fsp.readFile(path.join(dir, "groups.json"), "utf8")).includes(cek.toString("base64")), false);
  const changedMembers = json({ members: ["alice", "bob"] });
  assert.equal((await request(port, `/groups/${group.id}/members`, { method: "PUT", headers: { "x-user": "admin", "content-type": "application/json", "content-length": changedMembers.length }, body: changedMembers })).status, 200);
  assert.equal(JSON.parse((await request(port, `/groups/${group.id}/key-manifest`, { headers: { "x-user": "admin" } })).body).wraps.length, 0);
  assert.ok(events.some((entry) => entry[0] === "group.created"));
  route.store.state.groups[group.id].members = Array.from({ length: MAX_MEMBERS }, () => "alice");
  const overLimitBody = json({ username: "bob" });
  const overLimit = await request(port, `/groups/${group.id}/members`, { method: "POST", headers: { "x-user": "admin", "content-type": "application/json", "content-length": overLimitBody.length }, body: overLimitBody });
  assert.equal(overLimit.status, 400);
});
