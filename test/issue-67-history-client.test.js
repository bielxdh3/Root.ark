"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const express = require("express");

const protocol = require("../sync-client/rootark-sync-protocol");
const { createOpaqueSyncAdapter } = require("../public/client/rootark-sync-adapter");
const { SyncObjectStore, registerSyncRoutes } = require("../src/routes/sync");
const { writePrivateSyncConfig } = require("../sync-client/rootark-sync-private-config");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync-v2.js");

function invokeHistoryCli(configPath, objectId) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "history", "--config", configPath, "--object-id", objectId], {
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => child.kill(), 10000);
    child.stdout.on("data", (data) => { stdout += data.toString(); });
    child.stderr.on("data", (data) => { stderr += data.toString(); });
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (status) => {
      clearTimeout(timeout);
      resolve({ status, stdout, stderr });
    });
  });
}

async function fixture(t) {
  const root = createPrivateAuthorityFixture("rootark-67-history-client-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const store = await new SyncObjectStore(path.join(root, "objects.json")).open();
  const app = express();
  app.use("/sync/v1", express.json());
  let username = "alice";
  let permission = true;
  const authenticate = (req, res, next) => {
    if (req.get("authorization") !== "Bearer only-for-test") return res.status(401).json({ error: "Denied" });
    req.user = { username, permissions: { listFiles: permission } };
    next();
  };
  const requirePermission = (name) => (req, res, next) => req.user.permissions[name]
    ? next() : res.status(403).json({ error: "Denied" });
  const route = registerSyncRoutes({ app, storagePath: store.filePath, authenticate, requirePermission });
  await route.ready;
  const server = await new Promise((resolve) => {
    const instance = app.listen(0, "127.0.0.1", () => resolve(instance));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  const configPath = path.join(root, "private-sync.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: baseUrl, username: "alice", token: "only-for-test",
  }));
  const key = crypto.randomBytes(32);
  const create = protocol.createOperation({
    operation: "create", objectId: "file-1", fileId: "file-1", versionId: "first",
    operationId: "first-op", deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "document.txt" }, plaintext: Buffer.from("private original"), fileKey: key,
  });
  const deleted = protocol.createOperation({
    operation: "delete", objectId: "file-1", fileId: "file-1", versionId: "deleted",
    operationId: "delete-op", deviceId: "device-a", keyEpoch: "epoch-1",
    compartmentId: "private", revision: { counter: 2, deviceId: "device-a" },
    baseRevision: create.revision, metadata: { path: "document.txt" }, fileKey: key,
  });
  assert.equal((await store.put("alice", create)).kind, "stored");
  assert.equal((await store.put("alice", deleted)).kind, "stored");
  return { root, store, baseUrl, configPath, create, deleted,
    changeUser: (value) => { username = value; },
    changePermission: (value) => { permission = value; } };
}

test("#67: owner browses retained ciphertext history after delete without revealing keys or modifying store", async (t) => {
  const f = await fixture(t);
  const before = await fsp.readFile(f.store.filePath);
  const result = await invokeHistoryCli(f.configPath, "file-1");
  assert.equal(result.status, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.objectId, "file-1");
  assert.deepEqual(parsed.versions.map((version) => version.versionId), ["first", "deleted"]);
  assert.deepEqual(parsed.versions.map((version) => version.deviceId), ["device-a", "device-a"]);
  assert.deepEqual(parsed.versions.map((version) => version.revision.counter), [1, 2]);
  assert.equal(parsed.versions[1].tombstone, true);
  assert.equal(parsed.signatureVerified, false);
  assert.doesNotMatch(result.stdout, /private original|only-for-test|ciphertext|nonce|tag|fileKey/);
  assert.deepEqual(await fsp.readFile(f.store.filePath), before);
});

test("#67: no client history disclosure across permission and tenant boundaries", async (t) => {
  const f = await fixture(t);
  const adapter = createOpaqueSyncAdapter({ baseUrl: f.baseUrl,
    fetchImpl: (url, opts) => fetch(url, { ...opts, headers: { ...opts.headers, Authorization: "Bearer only-for-test" } }),
  });
  assert.equal((await adapter.history("file-1")).versions.length, 2);
  f.changeUser("bob");
  await assert.rejects(adapter.history("file-1"), (error) => error.status === 404);
  f.changeUser("alice");
  f.changePermission(false);
  await assert.rejects(adapter.history("file-1"), (error) => error.status === 403);
  await assert.rejects(createOpaqueSyncAdapter({ baseUrl: f.baseUrl }).history("file-1"),
    (error) => error.status === 401);
});

test("#67: read-only adapter rejects cross-object and malformed history without any write", async () => {
  const source = protocol.createOperation({
    operation: "create", objectId: "different-object", deviceId: "device-a",
    keyEpoch: "epoch-1", compartmentId: "private", revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: "safe.txt" }, fileKey: Buffer.alloc(32, 1),
  });
  const requests = [];
  const adapter = createOpaqueSyncAdapter({ baseUrl: "https://example.invalid",
    fetchImpl: async (url, options) => {
      requests.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ protocolVersion: 2, versions: [source] }) };
    },
  });
  await assert.rejects(adapter.history("requested-object"), /history|object/i);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].options.redirect, "error");
  assert.equal(requests[0].options.method, undefined);
  assert.equal(requests[0].options.body, undefined);
  await assert.rejects(adapter.history("../escape"), /Invalid sync id/);
  assert.equal(requests.length, 1, "unsafe history identifiers cannot contact the server");
});
