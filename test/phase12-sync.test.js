"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const express = require("express");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const protocol = require("../sync-client/rootark-sync-protocol");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { LocalSyncWebDavBridge } = require("../sync-client/rootark-sync-webdav");
const { MAX_REQUEST_BYTES, SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.once("error", reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

function jsonBody(value) { return Buffer.from(JSON.stringify(value)); }

test("Phase 12 protocol encrypts with bound metadata and rejects tampering", () => {
  const key = crypto.randomBytes(32);
  const operation = protocol.createOperation({
    operation: "create", objectId: "object-1", fileId: "file-1", versionId: "version-1",
    operationId: "operation-1", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "folder/file.txt", name: "file.txt", size: 6 },
    plaintext: Buffer.from("secret"), fileKey: key,
  });
  assert.equal(protocol.decryptPayload(operation, key).toString(), "secret");
  assert.throws(() => protocol.decryptPayload({ ...operation, objectId: "object-2" }, key));
  assert.equal(protocol.compareRevisions({ counter: 2, deviceId: "z" }, { counter: 1, deviceId: "z" }) > 0, true);
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: operation.objectId, fileId: operation.fileId, versionId: "version-2",
    operationId: "operation-delete", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 2, deviceId: "device-a" }, metadata: { path: "folder/file.txt" }, fileKey: key,
  });
  assert.equal(tombstone.tombstone, true);
  const metadataMove = protocol.createOperation({
    operation: "move", objectId: "object-1", fileId: "file-1", versionId: "version-3", operationId: "operation-move",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 3, deviceId: "device-a" },
    metadata: { path: "new.txt", sourcePath: "folder/file.txt" }, plaintext: Buffer.alloc(0), fileKey: key,
  });
  assert.equal(metadataMove.ciphertext, "");
  assert.equal(protocol.decryptPayload(protocol.validateOperation(JSON.parse(JSON.stringify(metadataMove))), key).length, 0);
  assert.throws(() => protocol.validateOperation({ ...metadataMove, metadata: { ...metadataMove.metadata, path: "other.txt" } }));
  assert.throws(() => protocol.validateOperation({ ...metadataMove, extra: "smuggled" }));
  assert.throws(() => protocol.createOperation({ ...metadataMove, operation: "delete", metadata: { ...metadataMove.metadata, search: "secret" }, fileKey: key }));
  for (const unsafe of ["../escape.txt", ".rootark-trash/hidden.txt", "folder/%2e%2e/escape.txt", "C:/escape.txt"]) {
    assert.throws(() => protocol.createOperation({ ...metadataMove, operation: "move", metadata: { path: unsafe, sourcePath: "safe.txt" }, fileKey: key }));
  }
});

test("Phase 12 journal is durable and recovers pending operations", async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase12-journal-"));
  try {
    const filePath = path.join(dir, "journal.json");
    const journal = await new SyncJournal(filePath).open();
    await journal.enqueue({ operationId: "move-1", kind: "move", source: "/a", destination: "/b" });
    await journal.enqueue({ operationId: "delete-1", kind: "delete", source: "/b" });
    await journal.markSeen("move-1");
    const recovered = await new SyncJournal(filePath).open();
    assert.deepEqual((await recovered.recover()).map((item) => item.operationId), ["delete-1"]);
    assert.equal(recovered.hasSeen("move-1"), true);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test("sync journal commits move batches atomically and remains usable after capacity rejection", async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase12-journal-batch-"));
  try {
    const filePath = path.join(dir, "journal.json");
    const journal = await new SyncJournal(filePath).open();
    journal.state.pending = Array.from({ length: 9999 }, (_, index) => ({ operationId: `queued-${index}` }));
    await assert.rejects(journal.enqueueMany([{ operationId: "batch-a" }, { operationId: "batch-b" }]), /capacity/);
    assert.equal(journal.pending().length, 9999);

    journal.state.pending = [];
    await journal.enqueueMany([{ operationId: "batch-a" }, { operationId: "batch-b" }]);
    const recovered = await new SyncJournal(filePath).open();
    assert.deepEqual(recovered.pending().map((operation) => operation.operationId), ["batch-a", "batch-b"]);
  } finally {
    await fsp.rm(dir, { recursive: true, force: true });
  }
});

test("Phase 12 local bridge is loopback bearer protected, contained, and trash-backed", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase12-bridge-"));
  const events = [];
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, token: "bridge-test-token", onOperation: async (event) => events.push(event) });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const port = bridge.address().port;
  assert.equal((await request(port, "/", { method: "PROPFIND" })).status, 401);
  const headers = { authorization: "Bearer bridge-test-token" };
  assert.equal((await request(port, "/%2e%2e/outside", { method: "GET", headers })).status, 400);
  assert.equal((await request(port, "/a.txt", { method: "PUT", headers, body: Buffer.from("hello") })).status, 201);
  assert.equal((await request(port, "/a.txt", { method: "GET", headers })).body.toString(), "hello");
  assert.equal((await request(port, "/a.txt", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${port}/b.txt` } })).status, 201);
  assert.equal((await request(port, "/b.txt", { method: "DELETE", headers })).status, 204);
  assert.equal(fs.existsSync(path.join(dir, "b.txt")), false);
  assert.equal(events.map((event) => event.kind).join(","), "put,move,delete");
  assert.equal(fs.readdirSync(path.join(dir, ".rootark-trash")).length, 1);
});

test("Phase 16 WebDAV overwrite is recoverable, journaled, and protects configured trash", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-webdav-"));
  const trashDir = path.join(dir, "private-trash");
  const journal = await new SyncJournal(path.join(dir, "journal.json")).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, trashDir, token: "phase16-token", journal });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const headers = { authorization: "Bearer phase16-token" };
  const port = bridge.address().port;
  await request(port, "/source.txt", { method: "PUT", headers, body: Buffer.from("source") });
  await request(port, "/destination.txt", { method: "PUT", headers, body: Buffer.from("prior") });
  assert.equal((await request(port, "/source.txt", { method: "MOVE", headers: { ...headers, overwrite: "F", destination: `http://127.0.0.1:${port}/destination.txt` } })).status, 412);
  assert.equal((await request(port, "/destination.txt", { method: "GET", headers })).body.toString(), "prior");
  assert.equal((await request(port, "/source.txt", { method: "MOVE", headers: { ...headers, overwrite: "T", destination: `http://127.0.0.1:${port}/destination.txt` } })).status, 204);
  assert.equal((await request(port, "/destination.txt", { method: "GET", headers })).body.toString(), "source");
  assert.equal(fs.readdirSync(trashDir).length, 1);
  assert.equal((await request(port, "/private-trash", { method: "PROPFIND", headers })).status, 400);

  await fsp.mkdir(path.join(dir, "source-dir"));
  await fsp.writeFile(path.join(dir, "source-dir", "new.txt"), "new");
  await fsp.mkdir(path.join(dir, "destination-dir"));
  await fsp.writeFile(path.join(dir, "destination-dir", "old.txt"), "old");
  assert.equal((await request(port, "/source-dir", { method: "MOVE", headers: { ...headers, overwrite: "T", destination: `http://127.0.0.1:${port}/destination-dir` } })).status, 204);
  assert.equal(fs.existsSync(path.join(dir, "destination-dir", "new.txt")), true);
  assert.equal(fs.existsSync(path.join(dir, "destination-dir", "old.txt")), false);
});

test("Phase 16 WebDAV rename and journal failures leave both paths unchanged", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-rollback-"));
  const journal = await new SyncJournal(path.join(dir, "journal.json")).open();
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, token: "phase16-token", journal });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  const headers = { authorization: "Bearer phase16-token" };
  const port = bridge.address().port;
  await request(port, "/source.txt", { method: "PUT", headers, body: Buffer.from("source") });
  await request(port, "/destination.txt", { method: "PUT", headers, body: Buffer.from("destination") });
  const originalRename = fsp.rename;
  fsp.rename = async (from, to) => { if (from === path.join(dir, "source.txt")) throw new Error("induced rename failure"); return originalRename(from, to); };
  try {
    assert.equal((await request(port, "/source.txt", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${port}/destination.txt` } })).status, 500);
  } finally { fsp.rename = originalRename; }
  assert.equal((await request(port, "/source.txt", { method: "GET", headers })).body.toString(), "source");
  assert.equal((await request(port, "/destination.txt", { method: "GET", headers })).body.toString(), "destination");

  const journalFailure = new LocalSyncWebDavBridge({ rootDir: dir, token: "phase16-token", journal, onOperation: async () => { throw new Error("journal failure"); } });
  await journalFailure.start();
  const secondSource = path.join(dir, "second-source.txt");
  const secondDestination = path.join(dir, "second-destination.txt");
  await fsp.writeFile(secondSource, "second-source");
  await fsp.writeFile(secondDestination, "second-destination");
  const secondPort = journalFailure.address().port;
  assert.equal((await request(secondPort, "/second-source.txt", { method: "MOVE", headers: { ...headers, destination: `http://127.0.0.1:${secondPort}/second-destination.txt` } })).status, 500);
  await journalFailure.stop();
  assert.equal(await fsp.readFile(secondSource, "utf8"), "second-source");
  assert.equal(await fsp.readFile(secondDestination, "utf8"), "second-destination");
});

test("Phase 16 WebDAV journal recovery resolves a staged completed move", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase16-recovery-"));
  const trashDir = path.join(dir, "configured-trash");
  const journal = await new SyncJournal(path.join(dir, "journal.json")).open();
  const backup = path.join(trashDir, "staged-recovery.txt");
  await fsp.mkdir(trashDir, { recursive: true });
  await fsp.writeFile(backup, "recover");
  await journal.enqueue({ operationId: "recover-1", kind: "move", source: "/source.txt", destination: "/restored.txt", trash: path.relative(dir, backup), phase: "staged" });
  const bridge = new LocalSyncWebDavBridge({ rootDir: dir, trashDir, token: "phase16-token", journal });
  await bridge.start();
  t.after(async () => { await bridge.stop(); await fsp.rm(dir, { recursive: true, force: true }); });
  assert.equal((await fsp.readFile(path.join(dir, "restored.txt"), "utf8")), "recover");
  assert.deepEqual(await journal.recover(), []);

  const unresolvedBackup = path.join(trashDir, "unresolved.txt");
  await fsp.writeFile(unresolvedBackup, "backup");
  const unresolvedSource = path.join(dir, "unresolved-source.txt");
  await fsp.writeFile(unresolvedSource, "source");
  await fsp.rename(unresolvedSource, path.join(dir, "unresolved.txt"));
  await journal.enqueue({ operationId: "recover-2", kind: "move", source: "/unresolved-source.txt", destination: "/unresolved.txt", trash: path.relative(dir, unresolvedBackup), phase: "staged" });
  await bridge.recoverPending();
  assert.deepEqual(await journal.recover(), []);
  assert.equal(await fsp.readFile(path.join(dir, "unresolved.txt"), "utf8"), "source");
  assert.equal(await fsp.readFile(unresolvedBackup, "utf8"), "backup");
});

test("Phase 12 server route stores opaque records and rejects conflict/replay", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase12-route-"));
  const app = express();
  app.use((req, res, next) => req.path.startsWith("/sync/v1/") ? next() : express.json()(req, res, next));
  app.use("/sync/v1", express.json({ limit: "9mb" }));
  const authenticate = (req, _res, next) => { req.user = { username: "alice" }; next(); };
  const requirePermission = () => (_req, _res, next) => next();
  const route = registerSyncRoutes({ app, authenticate, requirePermission, storagePath: path.join(dir, "objects.json") });
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await fsp.rm(dir, { recursive: true, force: true }); });
  await route.ready;
  const key = crypto.randomBytes(32);
  const create = protocol.createOperation({ operation: "create", objectId: "object-1", fileId: "file-1", versionId: "version-1", operationId: "operation-1", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "file.txt", name: "file.txt", size: 6 }, plaintext: Buffer.from("secret"), fileKey: key });
  const port = server.address().port;
  const first = await request(port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json", "content-length": jsonBody(create).length }, body: jsonBody(create) });
  assert.equal(first.status, 201);
  assert.equal(first.body.toString().includes("secret"), false);
  assert.equal((await request(port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json" }, body: jsonBody(create) })).status, 409);
  const update = protocol.createOperation({ operation: "update", objectId: "object-1", fileId: "file-1", versionId: "version-2", operationId: "operation-2", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 2, deviceId: "device-a" }, baseRevision: create.revision, metadata: { path: "file.txt", name: "file.txt", size: 7 }, plaintext: Buffer.from("updated"), fileKey: key });
  assert.equal((await request(port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json" }, body: jsonBody(update) })).status, 201);
  const stale = protocol.createOperation({
    operation: "update", objectId: "object-1", fileId: "file-1", versionId: "version-2",
    operationId: "operation-3", deviceId: "device-b", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-b" }, baseRevision: create.revision,
    metadata: { path: "file.txt", name: "file.txt", size: 7 }, plaintext: Buffer.from("updated"), fileKey: key,
  });
  assert.equal((await request(port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json" }, body: jsonBody(stale) })).status, 409);
  const tombstone = protocol.createOperation({
    operation: "delete", objectId: "object-1", fileId: "file-1", versionId: "version-3", operationId: "operation-delete",
    deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 3, deviceId: "device-a" },
    baseRevision: update.revision, metadata: { path: "file.txt" }, fileKey: key,
  });
  const tombstoneBody = jsonBody(tombstone);
  const deleted = await request(port, "/sync/v1/objects/object-1", { method: "DELETE", headers: { "content-type": "application/json", "content-length": tombstoneBody.length }, body: tombstoneBody });
  assert.equal(deleted.status, 200);
  assert.equal(JSON.parse(deleted.body).tombstone, true);
  assert.equal((await request(port, "/sync/v1/objects/object-1", { method: "DELETE", headers: { "content-type": "application/json", "content-length": tombstoneBody.length }, body: tombstoneBody })).status, 409);
  assert.equal((await request(port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json" }, body: Buffer.alloc(MAX_REQUEST_BYTES + 1, "x") })).status, 413);
  assert.equal((await request(port, "/sync/v1/objects/object-1", { method: "GET" })).status, 200);
  const persisted = JSON.parse(await fsp.readFile(path.join(dir, "objects.json"), "utf8"));
  assert.equal(Object.hasOwn(persisted.users.alice.objects["object-1"], "fileKey"), false);
});

test("sync ingress rejects malformed encrypted envelopes without poisoning store reopen", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-phase12-ingress-"));
  const storagePath = path.join(dir, "objects.json");
  const app = express();
  app.use("/sync/v1", express.json({ limit: "9mb" }));
  const authenticate = (req, _res, next) => { req.user = { username: "alice" }; next(); };
  const requirePermission = () => (_req, _res, next) => next();
  const route = registerSyncRoutes({ app, authenticate, requirePermission, storagePath });
  const server = await new Promise((resolve) => { const value = app.listen(0, "127.0.0.1", () => resolve(value)); });
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await fsp.rm(dir, { recursive: true, force: true }); });
  await route.ready;
  const operation = protocol.createOperation({
    operation: "create", objectId: "poison-object", fileId: "poison-file", versionId: "poison-version",
    operationId: "poison-operation", deviceId: "device-a", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" }, metadata: { path: "file.txt", name: "file.txt", size: 6 },
    plaintext: Buffer.from("secret"), fileKey: crypto.randomBytes(32),
  });
  const invalid = [
    { ciphertext: "%%%%" },
    { nonce: "AAAA" },
    { tag: "AAAA" },
    { aad: Buffer.from("wrong-aad").toString("base64url") },
  ];
  const port = server.address().port;
  for (const [index, change] of invalid.entries()) {
    const body = jsonBody({ ...operation, operationId: `poison-operation-${index}`, ...change });
    const response = await request(port, "/sync/v1/objects", { method: "POST", headers: { "content-type": "application/json", "content-length": body.length }, body });
    assert.equal(response.status, 400);
  }
  const reopened = await new SyncObjectStore(storagePath).open();
  assert.deepEqual(reopened.list("alice"), []);
});
