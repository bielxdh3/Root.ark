"use strict";

// ZK10 characterization at the published PR236 head, NOT a strict-mode
// acceptance test. No signed account-wide cutover authority exists here.
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const express = require("express");
const fs = require("node:fs/promises");
const http = require("node:http");
const jwt = require("jsonwebtoken");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const registerAuthRoutes = require("../src/routes/auth");
const { createAuthenticate } = require("../src/middlewares/auth");
const { registerSyncRoutes } = require("../src/routes/sync");
const { createOperation } = require("../sync-client/rootark-sync-protocol");

const REQUEST_TIMEOUT_MS = 10_000;

function httpRequest(port, url, method = "GET", body, authorization) {
  const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
  const headers = {
    ...(bytes ? { "content-type": "application/json", "content-length": bytes.length } : {}),
    ...(authorization ? { authorization: `Bearer ${authorization}` } : {}),
  };
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, path: url, method, headers,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        let parsed;
        try { parsed = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
        catch { return reject(new Error("HTTP characterization received invalid JSON")); }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });
    req.once("error", reject);
    req.end(bytes);
  });
}

test("real /auth/login JWT can read legacy Sync metadata for an ordinary account",
  { timeout: 60_000 }, async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "zk65-w101-legacy-jwt-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const user = {
    username: "alice", password: bcrypt.hashSync("local-test-only", 4),
    role: "user", permissions: { listFiles: true, upload: true, delete: true },
    sessionVersion: 0, totpEnabled: false,
  };
  const otherUser = {
    username: "bob", password: bcrypt.hashSync("other-local-test-only", 4),
    role: "user", permissions: { listFiles: true, upload: true, delete: true },
    sessionVersion: 0, totpEnabled: false,
  };
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const loadUsers = () => [user, otherUser];
  const normalizeUserPermissions = (entry) => entry.permissions;
  const authenticate = createAuthenticate({
    jwt, jwtSecret, loadUser: (name) => loadUsers().find((entry) => entry.username === name),
    normalizeUserPermissions,
  });
  const requirePermission = (permission) => (req, res, next) => {
    if (req.user?.permissions?.[permission] !== true) {
      return res.status(403).json({ error: "permission denied" });
    }
    next();
  };
  const app = express();
  app.use(express.json());
  registerAuthRoutes(app, {
    authenticate, auditLog: () => {}, bcrypt, checkAnomalies: () => {},
    getAuditActor: (_req, username) => ({ username, ip: "127.0.0.1", role: "user" }),
    jwt, jwtSecret, loadUsers, saveUsers: () => {}, getTotpKey: () => Buffer.alloc(32, 1),
    logAnalyticsEvent: () => {}, normalizeUserPermissions, qrcode: {},
    requirePermission, sessionCookieOptions: { httpOnly: true, sameSite: "lax" },
  });
  const registered = registerSyncRoutes({
    app, authenticate, requirePermission, storagePath: path.join(dir, "objects.json"),
  });
  await registered.ready;
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;

  const login = await httpRequest(port, "/auth/login", "POST", {
    username: "alice", password: "local-test-only",
  });
  assert.equal(login.status, 200);
  // Token comes from the actual auth route, not test-generated jwt.sign().
  const cookie = login.headers["set-cookie"].find((line) => line.startsWith("rootark_session="));
  assert.ok(cookie);
  const token = cookie.split(";")[0].slice("rootark_session=".length);
  assert.equal(jwt.verify(token, jwtSecret, { algorithms: ["HS256"] }).username, "alice");
  assert.equal((await httpRequest(port, "/sync/v1/objects")).status, 401);

  const object = createOperation({
    operation: "create", objectId: "legacy-object", fileId: "file-a",
    versionId: "version-1", operationId: "operation-1", deviceId: "device-a",
    keyEpoch: "legacy-epoch", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { name: "server-readable-name.txt", path: "personal/server-readable-name.txt" },
    plaintext: Buffer.from("encrypted payload but readable metadata"), fileKey: crypto.randomBytes(32),
  });
  const create = await httpRequest(port, "/sync/v1/objects", "POST", object, token);
  assert.equal(create.status, 201);
  const listing = await httpRequest(port, "/sync/v1/objects", "GET", undefined, token);
  const read = await httpRequest(port, "/sync/v1/objects/legacy-object", "GET", undefined, token);
  assert.equal(listing.status, 200);
  assert.equal(read.status, 200);
  assert.equal(listing.body.objects[0].metadata.name, "server-readable-name.txt");
  assert.equal(read.body.metadata.path, "personal/server-readable-name.txt");
  assert.equal((await httpRequest(port, "/sync/v1/objects/legacy-object", "GET", undefined, token + "tampered")).status, 401);
  const bobLogin = await httpRequest(port, "/auth/login", "POST", {
    username: "bob", password: "other-local-test-only",
  });
  assert.equal(bobLogin.status, 200);
  const bobCookie = bobLogin.headers["set-cookie"].find((line) => line.startsWith("rootark_session="));
  assert.ok(bobCookie);
  const bobToken = bobCookie.split(";")[0].slice("rootark_session=".length);
  const bobList = await httpRequest(port, "/sync/v1/objects", "GET", undefined, bobToken);
  assert.equal(bobList.status, 200);
  assert.deepEqual(bobList.body.objects, []);
  assert.equal((await httpRequest(port, "/sync/v1/objects/legacy-object", "GET", undefined, bobToken)).status, 404);
  user.sessionVersion += 1;
  assert.equal((await httpRequest(port, "/sync/v1/objects", "GET", undefined, token)).status, 401);
});
