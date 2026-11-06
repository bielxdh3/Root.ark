"use strict";

// Run against the pinned #255 server worktree, never a mock pagination endpoint:
// ROOTARK_PAGED_SERVER_ROOT=<checkout-of-3ccf9558> node --test this-file
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const fs = require("node:fs/promises");
const crypto = require("node:crypto");
const express = require("express");
const serverRoot = process.env.ROOTARK_PAGED_SERVER_ROOT;

test("real #255 signed >128-object paginated HTTP, 401, 403, tenant isolation and changed snapshot", {
  skip: !serverRoot && "Requires pinned PR #255 server source",
  timeout: 240000,
}, async (t) => {
  const { registerSyncRoutes } = require(path.join(serverRoot, "src/routes/sync.js"));
  const { createOperation } = require(path.join(serverRoot, "sync-client/rootark-sync-protocol.js"));
  const { createAuthorizationProof } = require(path.join(serverRoot, "sync-client/rootark-sync-authorization.js"));
  const { createPrivateAuthorityFixture } = require(path.join(serverRoot, "test/support/issue-65-private-authority-fixture.js"));
  const { runMigrations } = require(path.join(serverRoot, "db/migrations.js"));
  const { closeDb } = require(path.join(serverRoot, "db/index.js"));
  const usersRepository = require(path.join(serverRoot, "repositories/usersRepository.js"));
  const dir = createPrivateAuthorityFixture("rootark-android-paged-http-");
  const oldEnv = { DB_ENABLED: process.env.DB_ENABLED, DATABASE_URL: process.env.DATABASE_URL,
    DB_WRITE_LEGACY_JSON: process.env.DB_WRITE_LEGACY_JSON };
  process.env.DB_ENABLED = "true";
  process.env.DB_WRITE_LEGACY_JSON = "false";
  process.env.DATABASE_URL = path.join(dir, "accounts.sqlite");
  t.after(async () => {
    closeDb();
    for (const [key, value] of Object.entries(oldEnv)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    await fs.rm(dir, { recursive: true, force: true });
  });
  runMigrations({ backup: false });
  usersRepository.saveUsers(["alice", "bob"].map((username) => ({
    username, password: "fixture-only-hash", role: "user", sessionVersion: 0,
    permissions: { listFiles: true, upload: true },
  })));

  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const authenticate = (req, res, next) => {
    const bearer = req.headers.authorization;
    if (bearer !== "Bearer alice-fixture" && bearer !== "Bearer bob-fixture")
      return res.status(401).json({ error: "Unauthorized" });
    req.user = { username: bearer === "Bearer alice-fixture" ? "alice" : "bob", role: "user" };
    next();
  };
  const requirePermission = (name) => (req, res, next) =>
    req.headers["x-fixture-permission"] === name ? next() : res.status(403).json({ error: "Forbidden" });
  const route = registerSyncRoutes({
    app, authenticate, requirePermission, storagePath: path.join(dir, "objects.json"),
    atomicDeviceRegistry: true, requireDeviceAuthorization: true,
  });
  await route.ready;
  const listener = await new Promise((resolve) => {
    const running = app.listen(0, "127.0.0.1", () => resolve(running));
  });
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const base = `http://127.0.0.1:${listener.address().port}`;

  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const deviceId = "android-paged-fixture-device";
  for (const [expectedEpoch, username] of ["alice", "bob"].entries())
    await route.store.enrollDevice({ username, deviceId, publicKey, expectedEpoch });
  const fileKey = crypto.randomBytes(32);
  async function seed(username, number, bulk = false) {
    const objectId = `${username}-file-${String(number).padStart(3, "0")}`;
    const operation = createOperation({
      objectId, fileId: `file-${objectId}`, versionId: `version-${objectId}`,
      operationId: `create-${objectId}`, deviceId, keyEpoch: "epoch-1",
      compartmentId: "private", operation: "create", revision: { counter: 1, deviceId },
      metadata: { path: `docs/${objectId}.txt`, name: `${objectId}.txt`, size: 3 },
      plaintext: Buffer.from("abc"), fileKey,
    });
    operation.authorization = await createAuthorizationProof(operation, {
      username, privateKey: keys.privateKey, publicKey, expiresAt: Date.now() + 180000,
      idempotencyKey: crypto.createHash("sha256").update(operation.operationId).digest("base64url"),
    });
    if (!bulk) assert.equal((await route.store.put(username, operation)).kind, "stored");
    return operation;
  }
  // One record must pass the actual Ed25519 store admission path. The other
  // 129 canonical signed records are staged in ONE disposable fixture write;
  // serial fsync for every synthetic record adds minutes without covering
  // any additional read-path behavior.
  await seed("alice", 0);
  const bulk = [];
  for (let index = 1; index < 130; index++) bulk.push(await seed("alice", index, true));
  await route.store.transact((next) => {
    const user = route.store.user(next, "alice");
    for (const operation of bulk) {
      user.objects[operation.objectId] = operation;
      user.revisions[operation.objectId] = operation.revision;
      user.seen[operation.operationId] = true;
    }
  });
  await seed("bob", 0);

  async function get(query, bearer = "alice-fixture", permission = "listFiles") {
    const headers = {};
    if (bearer) headers.authorization = `Bearer ${bearer}`;
    if (permission) headers["x-fixture-permission"] = permission;
    const response = await fetch(base + query, { headers, redirect: "error" });
    const raw = await response.text();
    return { status: response.status, bytes: Buffer.byteLength(raw), body: JSON.parse(raw) };
  }
  const endpoint = "/sync/v1/objects?view=metadata&limit=64";
  assert.equal((await get(endpoint, null)).status, 401);
  assert.equal((await get(endpoint, "alice-fixture", null)).status, 403);
  const first = await get(endpoint);
  assert.equal(first.status, 200);
  assert.equal(first.body.view, "metadata");
  assert.equal(first.body.objects.length, 64);
  assert.ok(first.body.nextCursor);
  const ids = [];
  let cursor = null;
  do {
    const page = await get(endpoint + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""));
    assert.equal(page.status, 200);
    assert.ok(page.bytes <= 128 * 1024);
    assert.ok(page.body.objects.length > 0 && page.body.objects.length <= 64);
    for (const item of page.body.objects) {
      assert.equal(item.objectId.startsWith("alice-file-"), true);
      for (const secret of ["ciphertext", "nonce", "tag", "aad", "authorization"])
        assert.equal(Object.hasOwn(item, secret), false);
      ids.push(item.objectId);
    }
    cursor = page.body.nextCursor;
  } while (cursor);
  assert.equal(ids.length, 130);
  assert.equal(new Set(ids).size, 130);
  assert.deepEqual((await get(endpoint, "bob-fixture")).body.objects.map((o) => o.objectId), ["bob-file-000"]);
  assert.equal((await get(endpoint + `&cursor=${encodeURIComponent(first.body.nextCursor)}`, "bob-fixture")).status, 409);
  await seed("alice", 130);
  assert.equal((await get(endpoint + `&cursor=${encodeURIComponent(first.body.nextCursor)}`)).status, 409);
});
