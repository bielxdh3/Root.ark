"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const express = require("express");
const { registerOpaqueDevVaultRoutes } = require("../src/routes/zkOpaqueDevVault");
const KEY_ID = crypto.randomBytes(32).toString("base64url");

function envelope() {
  return { format: "rootark-dev-file-v1", algorithm: "AES-256-GCM",
    iv: crypto.randomBytes(12).toString("base64url"),
    ciphertext: crypto.randomBytes(60).toString("base64url") };
}

test("authenticated HTTP upload/list/get/update/delete preserve ciphertext, isolate users and CAS", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-http-"));
  const app = express();
  app.use(express.json({ limit: "9mb" }));
  const authenticate = (req, res, next) => {
    if (req.headers.authorization !== "Bearer synthetic-session") {
      return res.status(401).json({ error: "unauthorized" });
    }
    req.user = { username: req.headers["x-test-owner"] || "alice",
      permissions: { upload: true, listFiles: true, delete: req.headers["x-test-deny-delete"] !== "true" } };
    next();
  };
  const requirePermission = (permission) => (req, res, next) => {
    if (req.user.permissions[permission]) next();
    else res.status(403).json({ error: "denied" });
  };
  const routes = registerOpaqueDevVaultRoutes({ app, authenticate, requirePermission,
    dbPath: path.join(dir, "vault.sqlite") });
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    routes.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const root = "http://127.0.0.1:" + server.address().port + "/zk-dev/v1";
  for (const asset of [
    "/zk-dev/vendor/libsodium-sumo.js",
    "/zk-dev/vendor/libsodium-wrappers.js",
  ]) {
    const response = await fetch("http://127.0.0.1:" + server.address().port + asset);
    assert.equal(response.status, 200, asset + " must load from this app, never an external CDN");
    assert.match(response.headers.get("content-type") || "", /javascript/i);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.ok((await response.arrayBuffer()).byteLength > 100_000);
  }
  const request = async (url, options = {}, owner = "alice") => {
    const headers = { "content-type": "application/json", authorization: "Bearer synthetic-session",
      "x-test-owner": owner, ...(options.headers || {}) };
    const response = await fetch(root + url, { ...options, headers });
    return { status: response.status, body: await response.json(), headers: response.headers };
  };
  const id = crypto.randomBytes(16).toString("base64url");
  const obj = { account: "alice", id, envelope: envelope(), keyId: KEY_ID };
  assert.equal((await request("/objects", { method: "POST", body: JSON.stringify(obj),
    headers: { authorization: "none" } })).status, 401);
  const created = await request("/objects", { method: "POST", body: JSON.stringify(obj) });
  assert.equal(created.status, 201);
  assert.equal(created.body.revision, 1);
  assert.equal((await request("/session")).body.activeKeyId, KEY_ID);
  assert.equal((await request("/objects", { method: "POST", body: JSON.stringify({
    ...obj, id: crypto.randomBytes(16).toString("base64url"),
    keyId: crypto.randomBytes(32).toString("base64url"),
  }) })).status, 409, "different content key cannot silently enter the same collection");
  assert.equal((await request("/objects", { method: "POST",
    body: JSON.stringify({ ...obj, id: crypto.randomBytes(16).toString("base64url") }),
  }, "bob")).status, 409, "backend must refuse a stale browser account during upload");
  assert.equal(created.headers.get("cache-control"), "no-store");
  const listed = await request("/objects");
  assert.deepEqual(listed.body.objects, [{ id, revision: 1 }]);
  assert.equal(JSON.stringify(listed.body).includes("ciphertext"), false);
  assert.deepEqual((await request("/objects/" + id)).body.envelope, obj.envelope);
  assert.equal((await request("/objects/" + id, {}, "bob")).status, 404);
  assert.deepEqual((await request("/objects", {}, "bob")).body.objects, []);
  assert.equal((await request("/objects", { method: "POST", body: JSON.stringify(obj) })).status, 409);
  const updatedEnvelope = envelope();
  assert.equal((await request("/objects/" + id, { method: "PUT",
    body: JSON.stringify({ account: "alice", expectedRevision: 1, envelope: updatedEnvelope, keyId: KEY_ID }) })).status, 200);
  assert.equal((await request("/objects/" + id, { method: "PUT",
    body: JSON.stringify({ account: "alice", expectedRevision: 1, envelope: obj.envelope, keyId: KEY_ID }) })).status, 409);
  assert.equal((await request("/objects/" + id, { method: "DELETE",
    body: JSON.stringify({ account: "alice", expectedRevision: 2 }),
    headers: { "x-test-deny-delete": "true" } })).status, 403,
  "Upload permission alone must not authorize deletion");
  assert.equal((await request("/objects/" + id, { method: "DELETE",
    body: JSON.stringify({ account: "alice", expectedRevision: 2 }) })).status, 200);
  assert.equal((await request("/objects/" + id)).status, 404);
  assert.equal((await request("/objects", { method: "POST", body: JSON.stringify(obj) })).status, 409);
});
