"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");

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

function appFor(storagePath, options = {}) {
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const route = registerSyncRoutes({
    app, authenticate: (req, _res, next) => { req.user = { username: "alice" }; next(); },
    requirePermission: () => (_req, _res, next) => next(), storagePath, ...options,
  });
  return { app, route };
}

test("HTTP 409 adapter contract recovers local content and applies remote-wins", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-conflict-"));
  const storePath = path.join(dir, "objects.json");
  const { app, route } = appFor(storePath);
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await fsp.rm(dir, { recursive: true, force: true }); });
  const adapter = createOpaqueSyncAdapter({ baseUrl: `http://127.0.0.1:${server.address().port}` });
  await route.ready;
  const key = crypto.randomBytes(32);
  const remote = protocol.createOperation({ operation: "create", objectId: "object-conflict", fileId: "file-conflict", versionId: "version-1", operationId: "remote-create", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "note.txt" }, plaintext: Buffer.from("remote"), fileKey: key });
  assert.equal((await adapter.push(remote)).operationId, remote.operationId);
  const root = path.join(dir, "local");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "note.txt"), "local");
  const engine = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await engine.enqueueChange({ operation: "update", objectId: remote.objectId, fileId: remote.fileId, versionId: "local-version", operationId: "local-update", revision: { counter: 2, deviceId: "device-b" }, metadata: { path: "note.txt" }, plaintext: Buffer.from("local"), fileKey: key });
  const summary = { pushed: 0, conflicts: [] };
  await engine.pushPending(summary);
  assert.equal(summary.conflicts.length, 1);
  assert.equal(summary.conflictRecovery, 1);
  assert.equal(await fsp.readFile(path.join(root, "note.txt"), "utf8"), "remote");
  assert.equal((await fsp.readdir(path.join(root, ".rootark-conflicts"))).length, 1);
  assert.deepEqual(await engine.journal.recover(), []);
});

test("device authorization is exact, signed, expiry-bound, and revocable", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-authz-"));
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const registryPath = path.join(dir, "devices.json");
  await fsp.writeFile(registryPath, JSON.stringify({ devices: { "device-a": { username: "alice", publicKey, active: true } } }));
  const { app, route } = appFor(path.join(dir, "objects.json"), { requireDeviceAuthorization: true, deviceRegistryPath: registryPath });
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await fsp.rm(dir, { recursive: true, force: true }); });
  await route.ready;
  const key = crypto.randomBytes(32);
  const operation = protocol.createOperation({ operation: "create", objectId: "auth-object", fileId: "auth-file", versionId: "auth-version", operationId: "auth-operation", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "auth.txt" }, plaintext: Buffer.from("ciphertext-only"), fileKey: key });
  operation.authorization = await createAuthorizationProof(operation, { username: "alice", privateKey: keys.privateKey, publicKey, expiresAt: Date.now() + 60_000 });
  const body = Buffer.from(JSON.stringify(operation));
  const first = await request(server.address().port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json", "content-length": body.length }, body });
  assert.equal(first.status, 201);
  assert.equal((await request(server.address().port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json", "content-length": body.length }, body })).status, 409);
  const expired = { ...operation, operationId: "expired-operation", authorization: { ...operation.authorization, expiresAt: Date.now() - 1 } };
  const expiredBody = Buffer.from(JSON.stringify(expired));
  assert.equal((await request(server.address().port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json", "content-length": expiredBody.length }, body: expiredBody })).status, 403);
  await fsp.writeFile(registryPath, JSON.stringify({ devices: { "device-a": { username: "alice", publicKey, active: false } } }));
  const revoked = { ...operation, operationId: "revoked-operation" };
  const revokedBody = Buffer.from(JSON.stringify(revoked));
  assert.equal((await request(server.address().port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json", "content-length": revokedBody.length }, body: revokedBody })).status, 403);
});

test("two authorized devices separate local send authorization from remote apply verification", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-two-device-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const key = crypto.randomBytes(32);
  let revoked = false;
  const deviceA = crypto.generateKeyPairSync("ed25519");
  const deviceB = crypto.generateKeyPairSync("ed25519");
  const publicDer = (pair) => pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const records = new Map();
  const adapter = {
    async push(operation) { records.set(operation.objectId, operation); return { status: 201, operationId: operation.operationId }; },
    async list() { return [...records.values()]; },
  };
  const authorizeIncoming = async (operation) => verifyAuthorizationProof(operation.authorization, operation, { username: "alice" });
  const engineA = await new SyncEngine({
    rootDir: path.join(dir, "a"), adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, authorize: async () => true,
    authorizeOutgoing: async (operation) => !revoked && operation.deviceId === "device-a",
    authorizationFactory: (operation) => createAuthorizationProof(operation, { username: "alice", privateKey: deviceA.privateKey, publicKey: publicDer(deviceA) }),
  }).open();
  await assert.rejects(engineA.enqueueChange({ operation: "create", objectId: "wrong-device", fileId: "wrong-file", versionId: "wrong-version", operationId: "wrong-device-op", deviceId: "device-b", revision: { counter: 1, deviceId: "device-b" }, metadata: { path: "blocked.txt" }, plaintext: Buffer.from("blocked"), fileKey: key }), { code: "authorization_rejected" });
  await engineA.enqueueChange({ operation: "create", objectId: "shared-object", fileId: "shared-file", versionId: "shared-version", operationId: "device-a-op", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "shared.txt" }, plaintext: Buffer.from("two-device-secret"), fileKey: key });
  await engineA.syncOnce();
  assert.equal(JSON.stringify([...records.values()]).includes("two-device-secret"), false);
  revoked = true;
  await assert.rejects(engineA.enqueueChange({ operation: "update", objectId: "shared-object", fileId: "shared-file", versionId: "revoked-version", operationId: "revoked-local-op", revision: { counter: 2, deviceId: "device-a" }, metadata: { path: "shared.txt" }, plaintext: Buffer.from("revoked"), fileKey: key }), { code: "authorization_rejected" });
  const engineB = await new SyncEngine({
    rootDir: path.join(dir, "b"), adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    fileKeyResolver: () => key, authorize: async () => true, authorizeOutgoing: async (operation) => operation.deviceId === "device-b",
    verifyIncoming: authorizeIncoming,
  }).open();
  const summary = await engineB.syncOnce();
  assert.equal(summary.pulled, 1);
  assert.equal(await fsp.readFile(path.join(dir, "b", "shared.txt"), "utf8"), "two-device-secret");
});

test("sync object history retains encrypted versions and tombstones across restart", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-history-"));
  const filePath = path.join(dir, "objects.json");
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const store = await new SyncObjectStore(filePath).open();
  const key = crypto.randomBytes(32);
  const make = (operation, versionId, operationId, counter, baseRevision, plaintext = "x") => protocol.createOperation({ operation, objectId: "history-object", fileId: "history-file", versionId, operationId, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter, deviceId: "device-a" }, baseRevision, metadata: { path: "history.txt" }, plaintext: Buffer.from(plaintext), fileKey: key });
  const first = make("create", "history-v1", "history-op-1", 1, null, "one");
  const second = make("update", "history-v2", "history-op-2", 2, first.revision, "two");
  const tombstone = make("delete", "history-v3", "history-op-3", 3, second.revision, "");
  await store.put("alice", first); await store.put("alice", second); await store.put("alice", tombstone);
  assert.equal(store.history("alice", "history-object").length, 3);
  assert.equal(store.list("alice")[0].tombstone, true);
  const reopened = await new SyncObjectStore(filePath).open();
  assert.equal(reopened.history("alice", "history-object").length, 3);
  await reopened.transact((next) => { delete next.users.alice.seen["history-op-1"]; });
  assert.ok(["stale", "conflict"].includes((await reopened.put("alice", first)).kind));
});

test("WebDAV mutation journal translates into v2 move and reaches a second client", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-sync-"));
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true }); await fsp.mkdir(rootB, { recursive: true });
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = { async push(operation) { const result = await store.put("alice", operation); return result.kind === "stored" ? { status: 201 } : { status: 409, current: result.current, currentRevision: result.current?.revision || null }; }, async list() { return store.list("alice"); } };
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const a = await new SyncEngine({ rootDir: rootA, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: rootA, token: "webdav-sync-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => a.translateWebDavMutation(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const headers = { authorization: "Bearer webdav-sync-token" };
  const sourceName = "résumé file.txt";
  const encodedSource = "/r%C3%A9sum%C3%A9%20file.txt";
  await request(bridge.address().port, encodedSource, { method: "PUT", headers, body: Buffer.from("payload") });
  await a.syncOnce();
  const b = await new SyncEngine({ rootDir: rootB, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await b.syncOnce();
  await request(bridge.address().port, "/folder", { method: "MKCOL", headers });
  await request(bridge.address().port, encodedSource, { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${bridge.address().port}/folder/renamed%20space.txt` } });
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "folder", "renamed space.txt"), "utf8"), "payload");
  assert.equal(await fsp.stat(path.join(rootB, sourceName)).then(() => true, () => false), false);
  const rootC = path.join(dir, "c");
  await fsp.mkdir(rootC, { recursive: true });
  const c = await new SyncEngine({ rootDir: rootC, adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  assert.equal((await c.syncOnce()).pulled, 1);
  assert.equal(await fsp.readFile(path.join(rootC, "folder", "renamed space.txt"), "utf8"), "payload");
  const followUp = await a.syncOnce();
  assert.equal(followUp.pushed, 0);
  assert.equal(followUp.conflicts.length, 0);

  const directory = path.join(rootA, "folder to move");
  const nestedEmptyDirectory = path.join(directory, "empty nested");
  await fsp.mkdir(nestedEmptyDirectory, { recursive: true });
  await fsp.writeFile(path.join(directory, "child file.txt"), "nested payload");
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "folder to move", "child file.txt"), "utf8"), "nested payload");
  assert.equal(await fsp.stat(path.join(rootB, "folder to move", "empty nested")).then((stats) => stats.isDirectory(), () => false), true);
  const overwrittenDirectory = path.join(rootA, "folder moved");
  await fsp.mkdir(overwrittenDirectory, { recursive: true });
  await fsp.writeFile(path.join(overwrittenDirectory, "child file.txt"), "old destination payload");
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "folder moved", "child file.txt"), "utf8"), "old destination payload");

  const directoryMove = await request(bridge.address().port, "/folder%20to%20move", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${bridge.address().port}/folder%20moved` } });
  assert.equal(directoryMove.status, 204);
  assert.equal(await fsp.stat(path.join(rootA, "folder moved")).then((stats) => stats.isDirectory(), () => false), true);
  assert.equal(await fsp.stat(directory).then(() => true, () => false), false);
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "folder moved", "child file.txt"), "utf8"), "nested payload");
  assert.equal(await fsp.stat(path.join(rootB, "folder moved", "empty nested")).then((stats) => stats.isDirectory(), () => false), true);
  assert.equal(await fsp.stat(path.join(rootB, "folder to move", "child file.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "folder to move", "empty nested")).then(() => true, () => false), false);

  const rootD = path.join(dir, "d");
  await fsp.mkdir(rootD, { recursive: true });
  const d = await new SyncEngine({ rootDir: rootD, adapter, deviceId: "device-d", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await d.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootD, "folder", "renamed space.txt"), "utf8"), "payload");
  assert.equal(await fsp.readFile(path.join(rootD, "folder moved", "child file.txt"), "utf8"), "nested payload");
  assert.equal(await fsp.stat(path.join(rootD, "folder moved", "empty nested")).then((stats) => stats.isDirectory(), () => false), true);
  const directoryFollowUp = await a.syncOnce();
  assert.equal(directoryFollowUp.pushed, 0);
  assert.equal(directoryFollowUp.conflicts.length, 0);

  const burstPort = bridge.address().port;
  await request(burstPort, "/burst-start.txt", { method: "PUT", headers, body: Buffer.from("created then moved") });
  assert.equal((await request(burstPort, "/burst-start.txt", { method: "MOVE", headers: { ...headers, destination: "http://127.0.0.1:" + burstPort + "/burst-middle.txt" } })).status, 201);
  assert.equal((await request(burstPort, "/burst-middle.txt", { method: "MOVE", headers: { ...headers, destination: "http://127.0.0.1:" + burstPort + "/burst-final.txt" } })).status, 201);
  await request(burstPort, "/repeated-put.txt", { method: "PUT", headers, body: Buffer.from("first version") });
  await request(burstPort, "/repeated-put.txt", { method: "PUT", headers, body: Buffer.from("second version") });
  await request(burstPort, "/repeated-put.txt", { method: "PUT", headers, body: Buffer.from("final version") });
  const burstSummary = await a.syncOnce();
  assert.equal(burstSummary.conflicts.length, 0);
  await b.syncOnce();
  await c.syncOnce();
  const pathExists = async (rootPath, relative) => fsp.stat(path.join(rootPath, relative)).then(() => true, () => false);
  for (const peerRoot of [rootB, rootC]) {
    assert.equal(await fsp.readFile(path.join(peerRoot, "burst-final.txt"), "utf8"), "created then moved");
    assert.equal(await pathExists(peerRoot, "burst-start.txt"), false);
    assert.equal(await pathExists(peerRoot, "burst-middle.txt"), false);
    assert.equal(await fsp.readFile(path.join(peerRoot, "repeated-put.txt"), "utf8"), "final version");
  }
  const burstFollowUp = await a.syncOnce();
  assert.equal(burstFollowUp.pushed, 0);
  assert.equal(burstFollowUp.conflicts.length, 0);

  await request(burstPort, "/empty-growth", { method: "MKCOL", headers });
  await a.syncOnce();
  await b.syncOnce();
  await request(burstPort, "/empty-growth/child.txt", { method: "PUT", headers, body: Buffer.from("grew from empty") });
  const growthSync = await a.syncOnce();
  assert.equal(growthSync.conflicts.length, 0);
  await b.syncOnce();
  await c.syncOnce();
  for (const peerRoot of [rootB, rootC]) {
    assert.equal(await fsp.readFile(path.join(peerRoot, "empty-growth", "child.txt"), "utf8"), "grew from empty");
    assert.equal(await (await fsp.stat(path.join(peerRoot, "empty-growth"))).isDirectory(), true);
  }
  const growthFollowUp = await a.syncOnce();
  assert.equal(growthFollowUp.pushed, 0);

  const fileSource = path.join(rootA, "file-source.txt");
  const directoryDestination = path.join(rootA, "directory-destination");
  await fsp.writeFile(fileSource, "preserve source file");
  await fsp.mkdir(directoryDestination, { recursive: true });
  await fsp.writeFile(path.join(directoryDestination, "existing.txt"), "preserve destination folder");
  assert.equal((await request(burstPort, "/file-source.txt", { method: "MOVE", headers: { ...headers, destination: "http://127.0.0.1:" + burstPort + "/directory-destination" } })).status, 409);
  assert.equal(await fsp.readFile(fileSource, "utf8"), "preserve source file");
  assert.equal(await fsp.readFile(path.join(directoryDestination, "existing.txt"), "utf8"), "preserve destination folder");

  const directorySource = path.join(rootA, "directory-source");
  const fileDestination = path.join(rootA, "file-destination.txt");
  await fsp.mkdir(directorySource, { recursive: true });
  await fsp.writeFile(path.join(directorySource, "child.txt"), "preserve source folder");
  await fsp.writeFile(fileDestination, "preserve destination file");
  assert.equal((await request(burstPort, "/directory-source", { method: "MOVE", headers: { ...headers, destination: "http://127.0.0.1:" + burstPort + "/file-destination.txt" } })).status, 409);
  assert.equal(await fsp.readFile(path.join(directorySource, "child.txt"), "utf8"), "preserve source folder");
  assert.equal(await fsp.readFile(fileDestination, "utf8"), "preserve destination file");
});

test("WebDAV directory MOVE overwrite and DELETE reconcile complete subtrees", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-subtree-"));
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true });
  await fsp.mkdir(rootB, { recursive: true });
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = { async push(operation) { const result = await store.put("alice", operation); return result.kind === "stored" ? { status: 201 } : { status: 409, current: result.current, currentRevision: result.current?.revision || null }; }, async list() { return store.list("alice"); } };
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const a = await new SyncEngine({ rootDir: rootA, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: rootA, token: "webdav-subtree-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => a.translateWebDavMutation(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  const headers = { authorization: "Bearer webdav-subtree-token" };
  const req = (url, method, extra = {}) => request(port, url, { method, headers: { ...headers, ...(extra.headers || {}) }, body: extra.body });

  await req("/source", "MKCOL");
  await a.syncOnce();
  const sourceDirectoryIdentity = { objectId: a.snapshot.files.source.objectId, fileId: a.snapshot.files.source.fileId };
  await req("/source/empty", "MKCOL");
  await a.syncOnce();
  const sourceNestedDirectoryIdentity = { objectId: a.snapshot.files["source/empty"].objectId, fileId: a.snapshot.files["source/empty"].fileId };
  await req("/source/shared.txt", "PUT", { body: Buffer.from("source payload") });
  await req("/source/empty/nested.txt", "PUT", { body: Buffer.from("source nested payload") });
  await a.syncOnce();
  await req("/destination", "MKCOL");
  await a.syncOnce();
  await req("/destination/empty", "MKCOL");
  await a.syncOnce();
  await req("/destination/shared.txt", "PUT", { body: Buffer.from("old destination payload") });
  await req("/destination/empty/stale-nested.txt", "PUT", { body: Buffer.from("destination-only nested payload") });
  await req("/destination/stale.txt", "PUT", { body: Buffer.from("destination-only payload") });
  await req("/destination/stale-empty", "MKCOL");
  await a.syncOnce();
  const destinationNestedIdentity = { objectId: a.snapshot.files["destination/empty"].objectId, fileId: a.snapshot.files["destination/empty"].fileId };
  const b = await new SyncEngine({ rootDir: rootB, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await b.syncOnce();

  assert.equal((await req("/source", "MOVE", { headers: { destination: `http://127.0.0.1:${port}/destination` } })).status, 204);
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "destination", "shared.txt"), "utf8"), "source payload");
  assert.equal(await fsp.readFile(path.join(rootB, "destination", "empty", "nested.txt"), "utf8"), "source nested payload");
  assert.equal(b.snapshot.files.destination.objectId, sourceDirectoryIdentity.objectId);
  assert.equal(b.snapshot.files.destination.fileId, sourceDirectoryIdentity.fileId);
  assert.equal(b.snapshot.files["destination/empty"].objectId, sourceNestedDirectoryIdentity.objectId);
  assert.equal(b.snapshot.files["destination/empty"].fileId, sourceNestedDirectoryIdentity.fileId);
  assert.notEqual(destinationNestedIdentity.objectId, sourceNestedDirectoryIdentity.objectId);
  assert.equal(await fsp.stat(path.join(rootB, "destination", "empty", "stale-nested.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "destination", "stale.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "destination", "stale-empty")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "source")).then(() => true, () => false), false);

  const rootC = path.join(dir, "c");
  const c = await new SyncEngine({ rootDir: rootC, adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await c.syncOnce();
  assert.equal(c.snapshot.files.destination.objectId, sourceDirectoryIdentity.objectId);
  assert.equal(c.snapshot.files["destination/empty"].objectId, sourceNestedDirectoryIdentity.objectId);
  assert.equal(await fsp.readFile(path.join(rootC, "destination", "empty", "nested.txt"), "utf8"), "source nested payload");
  assert.equal(await fsp.stat(path.join(rootC, "destination", "empty", "stale-nested.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootC, "destination", "stale.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootC, "destination", "stale-empty")).then(() => true, () => false), false);

  assert.equal((await req("/destination", "DELETE")).status, 204);
  await a.syncOnce();
  await b.syncOnce();
  await c.syncOnce();
  for (const root of [rootB, rootC]) {
    assert.equal(await fsp.stat(path.join(root, "destination")).then(() => true, () => false), false);
  }
  assert.equal((await b.syncOnce()).pushed, 0);
  assert.equal((await c.syncOnce()).pushed, 0);
});

test("WebDAV move preserves an explicit source directory when the destination has no snapshot record", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-new-directory-destination-"));
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true });
  await fsp.mkdir(rootB, { recursive: true });
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = { async push(operation) { const result = await store.put("alice", operation); return result.kind === "stored" ? { status: 201 } : { status: 409, current: result.current, currentRevision: result.current?.revision || null }; }, async list() { return store.list("alice"); } };
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const a = await new SyncEngine({ rootDir: rootA, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: rootA, token: "webdav-new-directory-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => a.translateWebDavMutation(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  const headers = { authorization: "Bearer webdav-new-directory-token" };
  await request(port, "/source-folder", { method: "MKCOL", headers });
  await a.syncOnce();
  assert.equal(a.snapshot.files["source-folder"].directory, true);
  const sourceDirectoryIdentity = { objectId: a.snapshot.files["source-folder"].objectId, fileId: a.snapshot.files["source-folder"].fileId };
  const b = await new SyncEngine({ rootDir: rootB, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await b.syncOnce();
  assert.equal(b.snapshot.files["source-folder"].directory, true);

  await request(port, "/source-folder/child.txt", { method: "PUT", headers, body: Buffer.from("directory identity payload") });
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "source-folder", "child.txt"), "utf8"), "directory identity payload");

  const moved = await request(port, "/source-folder", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${port}/new-folder` } });
  assert.equal(moved.status, 201);
  await a.syncOnce();
  await b.syncOnce();
  assert.equal(await fsp.readFile(path.join(rootB, "new-folder", "child.txt"), "utf8"), "directory identity payload");
  assert.equal(b.snapshot.files["new-folder"].directory, true);
  assert.equal(b.snapshot.files["new-folder"].objectId, sourceDirectoryIdentity.objectId);
  assert.equal(b.snapshot.files["new-folder"].fileId, sourceDirectoryIdentity.fileId);
  assert.equal(await fsp.stat(path.join(rootB, "source-folder")).then(() => true, () => false), false);
  assert.equal((await a.syncOnce()).pushed, 0);
  assert.equal((await b.syncOnce()).pushed, 0);
});

test("WebDAV MOVE preserves explicit directory identities when Windows source casing differs", { skip: process.platform !== "win32" }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-source-case-"));
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true });
  await fsp.mkdir(rootB, { recursive: true });
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = { async push(operation) { const result = await store.put("alice", operation); return result.kind === "stored" ? { status: 201 } : { status: 409, current: result.current, currentRevision: result.current?.revision || null }; }, async list() { return store.list("alice"); } };
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const a = await new SyncEngine({ rootDir: rootA, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: rootA, token: "webdav-source-case-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => a.translateWebDavMutation(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  const headers = { authorization: "Bearer webdav-source-case-token" };
  await request(port, "/source", { method: "MKCOL", headers });
  await a.syncOnce();
  const sourceDirectoryIdentity = { objectId: a.snapshot.files.source.objectId, fileId: a.snapshot.files.source.fileId };
  await request(port, "/source/nested", { method: "MKCOL", headers });
  await a.syncOnce();
  const sourceNestedIdentity = { objectId: a.snapshot.files["source/nested"].objectId, fileId: a.snapshot.files["source/nested"].fileId };
  await request(port, "/source/nested/child.txt", { method: "PUT", headers, body: Buffer.from("nested source content") });
  await a.syncOnce();
  const b = await new SyncEngine({ rootDir: rootB, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await b.syncOnce();

  const moved = await request(port, "/SOURCE", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${port}/destination` } });
  assert.equal(moved.status, 201);
  await a.syncOnce();
  await b.syncOnce();

  for (const engine of [a, b]) {
    assert.equal(engine.snapshot.files.destination.objectId, sourceDirectoryIdentity.objectId);
    assert.equal(engine.snapshot.files.destination.fileId, sourceDirectoryIdentity.fileId);
    assert.equal(engine.snapshot.files["destination/nested"].objectId, sourceNestedIdentity.objectId);
    assert.equal(engine.snapshot.files["destination/nested"].fileId, sourceNestedIdentity.fileId);
    assert.equal(await fsp.readFile(path.join(engine.rootDir, "destination", "nested", "child.txt"), "utf8"), "nested source content");
    assert.equal(await fsp.stat(path.join(engine.rootDir, "source")).then(() => true, () => false), false);
  }

  const rootC = path.join(dir, "c");
  const c = await new SyncEngine({ rootDir: rootC, adapter, deviceId: "device-c", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await c.syncOnce();
  assert.equal(c.snapshot.files.destination.objectId, sourceDirectoryIdentity.objectId);
  assert.equal(c.snapshot.files.destination.fileId, sourceDirectoryIdentity.fileId);
  assert.equal(c.snapshot.files["destination/nested"].objectId, sourceNestedIdentity.objectId);
  assert.equal(c.snapshot.files["destination/nested"].fileId, sourceNestedIdentity.fileId);
  assert.equal(await fsp.readFile(path.join(rootC, "destination", "nested", "child.txt"), "utf8"), "nested source content");
  assert.equal(await fsp.stat(path.join(rootC, "source")).then(() => true, () => false), false);

  for (const engine of [a, b, c]) {
    const followUp = await engine.syncOnce();
    assert.equal(followUp.pushed, 0);
    assert.equal(followUp.conflicts.length, 0);
  }
});

test("WebDAV MOVE rejects a Windows case-only rename before changing the source", { skip: process.platform !== "win32" }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-case-only-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "source.txt"), "case-only source");
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "webdav-case-only-token", journal: transactionJournal, protocolJournal, toProtocolOperation: async () => [] });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });

  const moved = await request(bridge.address().port, "/source.txt", {
    method: "MOVE",
    headers: { authorization: "Bearer webdav-case-only-token", destination: `http://127.0.0.1:${bridge.address().port}/SOURCE.txt` },
  });
  assert.equal(moved.status, 400);
  assert.equal(await fsp.readFile(path.join(root, "source.txt"), "utf8"), "case-only source");
  assert.deepEqual(await fsp.readdir(path.join(root, ".rootark-trash")), []);
  assert.deepEqual((await fsp.readdir(root)).filter((name) => name !== ".rootark-trash"), ["source.txt"]);
  assert.deepEqual(await transactionJournal.recover(), []);
  assert.deepEqual(await protocolJournal.recover(), []);
});

test("remote case-only MOVE updates Windows filename casing without staging the source", { skip: process.platform !== "win32" }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-remote-case-only-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "Source.txt"), "case-only remote source");
  const key = crypto.randomBytes(32);
  const adapter = { async push() { return { status: 201 }; }, async list() { return []; } };
  const engine = await new SyncEngine({ rootDir: root, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  engine.snapshot.files["Source.txt"] = { objectId: "case-only-object", fileId: "case-only-file", revision: { counter: 1, deviceId: "device-a" }, hash: crypto.createHash("sha256").update("case-only remote source").digest("hex"), deleted: false, directory: false };
  const operation = protocol.createOperation({
    operation: "move", objectId: "case-only-object", fileId: "case-only-file", versionId: "case-only-v2", operationId: "case-only-move",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", baseRevision: { counter: 1, deviceId: "device-a" },
    revision: { counter: 2, deviceId: "device-a" }, metadata: { path: "source.txt", sourcePath: "Source.txt" },
    plaintext: Buffer.from("case-only remote source"), fileKey: key,
  });
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));

  await engine.apply(operation);

  assert.deepEqual((await fsp.readdir(root)).filter((name) => !name.startsWith(".rootark-sync-")), ["source.txt"]);
  assert.equal(await fsp.readFile(path.join(root, "source.txt"), "utf8"), "case-only remote source");
  assert.equal(await fsp.stat(path.join(root, ".rootark-trash")).then(() => true, () => false), false);
  assert.equal(engine.snapshot.files["Source.txt"], undefined);
  assert.equal(engine.snapshot.files["source.txt"].deleted, false);
});

test("offline peers apply the latest move and delete by file identity after intermediate moves", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-offline-latest-path-"));
  const rootA = path.join(dir, "a");
  const rootB = path.join(dir, "b");
  await fsp.mkdir(rootA, { recursive: true });
  await fsp.mkdir(rootB, { recursive: true });
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = { async push(operation) { const result = await store.put("alice", operation); return result.kind === "stored" ? { status: 201 } : { status: 409, current: result.current, currentRevision: result.current?.revision || null }; }, async list() { return store.list("alice"); } };
  const a = await new SyncEngine({ rootDir: rootA, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await fsp.writeFile(path.join(rootA, "move-a.txt"), "move through two paths");
  await fsp.writeFile(path.join(rootA, "delete-a.txt"), "move then delete");
  await a.syncOnce();
  const b = await new SyncEngine({ rootDir: rootB, adapter, deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  await b.syncOnce();

  const moveAt = async (sourcePath, destinationPath, versionId) => {
    const prior = a.snapshot.files[sourcePath];
    const content = await fsp.readFile(path.join(rootA, ...sourcePath.split("/")));
    await fsp.rename(path.join(rootA, ...sourcePath.split("/")), path.join(rootA, ...destinationPath.split("/")));
    await a.enqueueChange({ operation: "move", objectId: prior.objectId, fileId: prior.fileId, versionId, baseRevision: prior.revision, revision: { counter: prior.revision.counter + 1, deviceId: "device-a" }, metadata: { path: destinationPath, sourcePath }, plaintext: content, fileKey: key });
    await a.syncOnce();
  };
  await moveAt("move-a.txt", "move-b.txt", "move-v2");
  await moveAt("move-b.txt", "move-c.txt", "move-v3");
  await moveAt("delete-a.txt", "delete-b.txt", "delete-move-v2");
  const deletePrior = a.snapshot.files["delete-b.txt"];
  await fsp.rm(path.join(rootA, "delete-b.txt"));
  await a.enqueueChange({ operation: "delete", objectId: deletePrior.objectId, fileId: deletePrior.fileId, versionId: "delete-v3", baseRevision: deletePrior.revision, revision: { counter: deletePrior.revision.counter + 1, deviceId: "device-a" }, metadata: { path: "delete-b.txt" }, plaintext: Buffer.alloc(0), fileKey: key });
  await a.syncOnce();

  const latest = await adapter.list();
  assert.equal(latest.length, 2);
  assert.equal(latest.find((operation) => operation.metadata.path === "move-c.txt")?.operation, "move");
  assert.equal(latest.find((operation) => operation.objectId === deletePrior.objectId)?.operation, "delete");
  await b.syncOnce();

  assert.equal(await fsp.readFile(path.join(rootB, "move-c.txt"), "utf8"), "move through two paths");
  assert.equal(await fsp.stat(path.join(rootB, "move-a.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "move-b.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "delete-a.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.stat(path.join(rootB, "delete-b.txt")).then(() => true, () => false), false);
  assert.equal(b.snapshot.files["move-a.txt"], undefined);
  assert.equal(b.snapshot.files["move-b.txt"], undefined);
  assert.equal(b.snapshot.files["delete-a.txt"], undefined);
  assert.equal(b.snapshot.files["move-c.txt"].deleted, false);
  assert.equal(b.snapshot.files["delete-b.txt"].deleted, true);

  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
});

test("WebDAV directory MOVE rejects nested file/collection collisions without changing either tree", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-nested-types-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  const store = await new SyncObjectStore(path.join(dir, "objects.json")).open();
  const key = crypto.randomBytes(32);
  const adapter = { async push(operation) { const result = await store.put("alice", operation); return result.kind === "stored" ? { status: 201 } : { status: 409, current: result.current }; }, async list() { return store.list("alice"); } };
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const engine = await new SyncEngine({ rootDir: root, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "webdav-nested-types-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => engine.translateWebDavMutation(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  const headers = { authorization: "Bearer webdav-nested-types-token" };
  const mkcol = (url) => request(port, url, { method: "MKCOL", headers });
  const put = (url, body) => request(port, url, { method: "PUT", headers, body: Buffer.from(body) });

  await mkcol("/file-source");
  await put("/file-source/item", "source-file");
  await mkcol("/file-destination");
  await mkcol("/file-destination/item");
  await put("/file-destination/item/old.txt", "destination-directory-child");
  await engine.syncOnce();
  const beforeFileToDirectory = protocolJournal.pending().length;
  const fileToDirectory = await request(port, "/file-source", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${port}/file-destination` } });
  assert.equal(fileToDirectory.status, 409);
  assert.equal(await fsp.readFile(path.join(root, "file-source", "item"), "utf8"), "source-file");
  assert.equal(await fsp.readFile(path.join(root, "file-destination", "item", "old.txt"), "utf8"), "destination-directory-child");
  assert.equal(protocolJournal.pending().length, beforeFileToDirectory);

  await mkcol("/directory-source");
  await mkcol("/directory-source/item");
  await put("/directory-source/item/child.txt", "source-directory-child");
  await mkcol("/directory-destination");
  await put("/directory-destination/item", "destination-file");
  await engine.syncOnce();
  const beforeDirectoryToFile = protocolJournal.pending().length;
  const directoryToFile = await request(port, "/directory-source", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${port}/directory-destination` } });
  assert.equal(directoryToFile.status, 409);
  assert.equal(await fsp.readFile(path.join(root, "directory-source", "item", "child.txt"), "utf8"), "source-directory-child");
  assert.equal(await fsp.readFile(path.join(root, "directory-destination", "item"), "utf8"), "destination-file");
  assert.equal(protocolJournal.pending().length, beforeDirectoryToFile);
});

test("WebDAV keeps a queued move committed when transaction completion marking fails", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-outbox-mark-failure-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "source.txt"), "durable move payload");
  const key = crypto.randomBytes(32);
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const markSeen = transactionJournal.markSeen.bind(transactionJournal);
  let failNextMark = true;
  transactionJournal.markSeen = async (operationId) => {
    if (failNextMark) {
      failNextMark = false;
      throw new Error("injected transaction journal mark failure");
    }
    return markSeen(operationId);
  };
  const operation = protocol.createOperation({
    operation: "move", objectId: "mark-failure-object", fileId: "mark-failure-file",
    versionId: "mark-failure-version", operationId: "mark-failure-protocol-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "destination.txt", sourcePath: "source.txt" },
    plaintext: Buffer.from("durable move payload"), fileKey: key,
  });
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: "phase16-outbox-mark-token", journal: transactionJournal, protocolJournal,
    toProtocolOperation: async () => operation,
  });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  const response = await request(port, "/source.txt", {
    method: "MOVE",
    headers: { authorization: "Bearer phase16-outbox-mark-token", destination: "http://127.0.0.1:" + port + "/destination.txt" },
  });
  assert.equal(response.status, 201);
  assert.equal(await fsp.stat(path.join(root, "source.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.readFile(path.join(root, "destination.txt"), "utf8"), "durable move payload");
  assert.deepEqual(protocolJournal.pending().map((item) => item.operationId), ["mark-failure-protocol-op"]);
  assert.equal(transactionJournal.pending()[0].phase, "protocol-queued");

  await bridge.stop();
  await bridge.start();
  assert.deepEqual(await transactionJournal.recover(), []);
  assert.deepEqual(protocolJournal.pending().map((item) => item.operationId), ["mark-failure-protocol-op"]);
});

test("WebDAV does not roll back a move when protocol journal directory sync fails after rename", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-journal-sync-failure-"));
  const root = path.join(dir, "root");
  const protocolDirectory = path.join(dir, "protocol");
  const protocolPath = path.join(protocolDirectory, "journal.json");
  const transactionPath = path.join(dir, "webdav-journal.json");
  await fsp.mkdir(root, { recursive: true });
  await fsp.mkdir(protocolDirectory, { recursive: true });
  await fsp.writeFile(path.join(root, "source.txt"), "committed despite fsync error");
  const key = crypto.randomBytes(32);
  const protocolJournal = await new SyncJournal(protocolPath).open();
  const transactionJournal = await new SyncJournal(transactionPath).open();
  const operation = protocol.createOperation({
    operation: "move", objectId: "fsync-object", fileId: "fsync-file",
    versionId: "fsync-version", operationId: "fsync-protocol-op",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, baseRevision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "destination.txt", sourcePath: "source.txt" },
    plaintext: Buffer.from("committed despite fsync error"), fileKey: key,
  });
  const update = transactionJournal.update.bind(transactionJournal);
  let failQueuedPhase = true;
  transactionJournal.update = async (operationId, patch) => {
    if (failQueuedPhase && patch.phase === "protocol-queued") {
      failQueuedPhase = false;
      const error = new Error("injected protocol queued phase failure");
      error.code = "EIO";
      throw error;
    }
    return update(operationId, patch);
  };
  const bridge = new LocalSyncWebDavBridge({
    rootDir: root, token: "webdav-journal-sync-token", journal: transactionJournal, protocolJournal,
    toProtocolOperation: async () => operation,
  });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });

  const originalOpen = fsp.open;
  let injectDirectorySyncFailure = true;
  let observedRenamedOperation = false;
  fsp.open = async (filePath, ...args) => {
    const handle = await originalOpen(filePath, ...args);
    if (!injectDirectorySyncFailure || path.resolve(String(filePath)) !== protocolDirectory) return handle;
    injectDirectorySyncFailure = false;
    return {
      async sync() {
        const persisted = JSON.parse(await fsp.readFile(protocolPath, "utf8"));
        observedRenamedOperation = persisted.pending.some((entry) => entry.operationId === "fsync-protocol-op");
        const error = new Error("injected directory fsync failure after rename");
        error.code = "EIO";
        throw error;
      },
      close: () => handle.close(),
    };
  };
  let response;
  try {
    const port = bridge.address().port;
    response = await request(port, "/source.txt", {
      method: "MOVE",
      headers: { authorization: "Bearer webdav-journal-sync-token", destination: `http://127.0.0.1:${port}/destination.txt` },
    });
  } finally {
    fsp.open = originalOpen;
  }

  assert.equal(observedRenamedOperation, true);
  assert.equal(response.status, 201);
  assert.equal(await fsp.stat(path.join(root, "source.txt")).then(() => true, () => false), false);
  assert.equal(await fsp.readFile(path.join(root, "destination.txt"), "utf8"), "committed despite fsync error");
  assert.deepEqual(protocolJournal.pending().map((item) => item.operationId), ["fsync-protocol-op"]);
  assert.equal(transactionJournal.pending()[0].phase, "source-moved");
  const reopenedProtocolJournal = await new SyncJournal(protocolPath).open();
  assert.deepEqual(reopenedProtocolJournal.pending().map((item) => item.operationId), ["fsync-protocol-op"]);

  await bridge.stop();
  const recoveredTransactionJournal = await new SyncJournal(transactionPath).open();
  const recoveredBridge = new LocalSyncWebDavBridge({
    rootDir: root, token: "webdav-journal-sync-token", journal: recoveredTransactionJournal,
    protocolJournal: reopenedProtocolJournal, toProtocolOperation: async () => operation,
  });
  await recoveredBridge.start();
  t.after(async () => { await recoveredBridge.stop(); });
  assert.deepEqual(await recoveredTransactionJournal.recover(), []);
  assert.deepEqual(reopenedProtocolJournal.pending().map((item) => item.operationId), ["fsync-protocol-op"]);
});

test("WebDAV recovery translates a source-moved transaction after a crash before enqueue", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-recover-before-enqueue-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "destination.txt"), "crash-recovered payload");
  const key = crypto.randomBytes(32);
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  await transactionJournal.enqueue({
    operationId: "crash-recovery-move", kind: "move", journalType: "webdav-mutation",
    source: "/source.txt", destination: "/destination.txt", trash: null, phase: "source-moved",
  });
  const adapter = { async push() { return { status: 201 }; }, async list() { return []; } };
  const engine = await new SyncEngine({ rootDir: root, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  engine.snapshot.files["source.txt"] = { objectId: "crash-object", fileId: "crash-file", revision: { counter: 1, deviceId: "device-a" }, hash: crypto.createHash("sha256").update("crash-recovered payload").digest("hex"), deleted: false, directory: false };
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "webdav-recovery-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => engine.translateWebDavMutation(event) });
  await bridge.start();
  assert.deepEqual(await transactionJournal.recover(), []);
  const pending = protocolJournal.pending();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].operation, "move");
  assert.equal(pending[0].metadata.sourcePath, "source.txt");
  assert.equal(pending[0].metadata.path, "destination.txt");
  await bridge.stop();
  await bridge.start();
  assert.deepEqual(protocolJournal.pending().map((item) => item.operationId), pending.map((item) => item.operationId));
  await bridge.stop();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
});

test("WebDAV recovery deduplicates a batch after the protocol-queued phase write fails", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-recover-queued-phase-"));
  const root = path.join(dir, "root");
  await fsp.mkdir(root, { recursive: true });
  await fsp.writeFile(path.join(root, "source.txt"), "queued phase payload");
  const key = crypto.randomBytes(32);
  const protocolJournal = await new SyncJournal(path.join(dir, "protocol-journal.json")).open();
  const transactionJournal = await new SyncJournal(path.join(dir, "webdav-journal.json")).open();
  const update = transactionJournal.update.bind(transactionJournal);
  let failQueuedPhase = true;
  transactionJournal.update = async (operationId, patch) => {
    if (failQueuedPhase && patch.phase === "protocol-queued") {
      failQueuedPhase = false;
      throw new Error("injected protocol-queued phase write failure");
    }
    return update(operationId, patch);
  };
  const adapter = { async push() { return { status: 201 }; }, async list() { return []; } };
  const engine = await new SyncEngine({ rootDir: root, journal: protocolJournal, adapter, deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", fileKeyResolver: () => key }).open();
  engine.snapshot.files["source.txt"] = { objectId: "queued-object", fileId: "queued-file", revision: { counter: 1, deviceId: "device-a" }, hash: crypto.createHash("sha256").update("queued phase payload").digest("hex"), deleted: false, directory: false };
  const bridge = new LocalSyncWebDavBridge({ rootDir: root, token: "webdav-phase-retry-token", journal: transactionJournal, protocolJournal, toProtocolOperation: (event) => engine.translateWebDavMutation(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  const response = await request(port, "/source.txt", {
    method: "MOVE",
    headers: { authorization: "Bearer webdav-phase-retry-token", destination: `http://127.0.0.1:${port}/destination.txt` },
  });
  assert.equal(response.status, 201);
  const operationIds = protocolJournal.pending().map((item) => item.operationId);
  assert.equal(operationIds.length, 1);
  assert.equal(transactionJournal.pending()[0].phase, "source-moved");

  await bridge.stop();
  await bridge.start();
  assert.deepEqual(protocolJournal.pending().map((item) => item.operationId), operationIds);
  assert.deepEqual(await transactionJournal.recover(), []);
});

test("sync reconciliation protects URL-encoded pending WebDAV paths", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-encoded-webdav-reconcile-"));
  const key = crypto.randomBytes(32);
  const filename = "résumé report.txt";
  await fsp.writeFile(path.join(dir, filename), "renamed bytes");
  const journal = await new SyncJournal(path.join(dir, ".rootark-sync-journal.json")).open();
  await journal.enqueue({
    operationId: "pending-webdav-move",
    journalType: "webdav-mutation",
    kind: "move",
    source: "/old%20name.txt",
    destination: "/r%C3%A9sum%C3%A9%20report.txt",
  });
  const engine = await new SyncEngine({
    rootDir: dir,
    journal,
    adapter: { async push() { return { status: 201 }; }, async list() { return []; } },
    deviceId: "device-a",
    keyEpoch: "epoch-1",
    compartmentId: "private",
    fileKeyResolver: () => key,
  }).open();
  engine.snapshot.files["old name.txt"] = { objectId: "old-object", fileId: "old-file", revision: { counter: 1, deviceId: "device-a" }, hash: "old-hash" };
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));

  await engine.reconcileLocal();

  assert.deepEqual(journal.pending().map((operation) => operation.operationId), ["pending-webdav-move"]);
  assert.ok(engine.snapshot.files["old name.txt"]);
});
