"use strict";

// Route-boundary RED/GREEN only: no signed account-wide authority exists in
// this fixture. Never interpret an HTTP mock as a verified cutover grant.
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

function request(port, route, method = "GET", token, body) {
  const data = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1", port, path: route, method,
      headers: {
        ...(token ? { authorization: "Bearer " + token } : {}),
        ...(data ? { "content-type": "application/json", "content-length": data.length } : {}),
      },
      signal: AbortSignal.timeout(10_000),
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) }); }
        catch { reject(new Error("Invalid HTTP JSON response")); }
      });
    });
    req.once("error", reject);
    req.end(data);
  });
}

async function fixture(t, cutover = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "zk65-w101-cutover-http-"));
  t.after(() => fs.rm(dir, { force: true, recursive: true }));
  const user = {
    username: "alice", password: bcrypt.hashSync("test-only", 4),
    role: "user", permissions: { listFiles: true, upload: true, delete: true },
    sessionVersion: 0, totpEnabled: false,
  };
  const secret = crypto.randomBytes(48).toString("base64url");
  const loadUsers = () => [user];
  const normalizeUserPermissions = (entry) => entry.permissions;
  const authenticate = createAuthenticate({ jwt, jwtSecret: secret,
    loadUser: (username) => loadUsers().find((entry) => entry.username === username),
    normalizeUserPermissions });
  const requirePermission = (permission) => (req, res, next) => req.user.permissions[permission]
    ? next() : res.status(403).json({ error: "permission denied" });
  const app = express();
  app.use(express.json());
  registerAuthRoutes(app, {
    authenticate, auditLog: () => {}, bcrypt, checkAnomalies: () => {},
    getAuditActor: (_req, username) => ({ username, ip: "127.0.0.1", role: "user" }),
    jwt, jwtSecret: secret, loadUsers, saveUsers: () => {},
    getTotpKey: () => Buffer.alloc(32, 1), logAnalyticsEvent: () => {},
    normalizeUserPermissions, qrcode: {}, requirePermission,
    sessionCookieOptions: { httpOnly: true, sameSite: "lax" },
  });
  const storagePath = path.join(dir, "sync.json");
  const { ready } = registerSyncRoutes({
    app, authenticate, requirePermission, storagePath,
    bcrypt, loadUsers,
    ...cutover,
  });
  await ready;
  const server = await new Promise((resolve) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port;
  const login = await new Promise((resolve, reject) => {
    const data = Buffer.from(JSON.stringify({ username: "alice", password: "test-only" }));
    const req = http.request({ host: "127.0.0.1", port, path: "/auth/login",
      method: "POST", headers: { "content-type": "application/json", "content-length": data.length },
      signal: AbortSignal.timeout(10_000) }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, cookies: res.headers["set-cookie"] }));
    });
    req.once("error", reject);
    req.end(data);
  });
  assert.equal(login.status, 200);
  const cookie = login.cookies.find((value) => value.startsWith("rootark_session="));
  assert.ok(cookie, "auth route must issue session JWT");
  const token = cookie.split(";")[0].slice("rootark_session=".length);
  assert.equal(jwt.verify(token, secret, { algorithms: ["HS256"] }).username, "alice");
  return { port, token, storagePath };
}

const endpoints = [
  ["GET", "/sync/v1/objects"],
  ["GET", "/sync/v1/objects/sample"],
  ["POST", "/sync/v1/objects"],
  ["PUT", "/sync/v1/objects/sample"],
  ["DELETE", "/sync/v1/objects/sample"],
  ["POST", "/sync/v1/devices/device-a/resume"],
];

function endpointBody(method, route) {
  if (method === "GET") return undefined;
  return route.endsWith("/resume") ? { password: "test-only" } : {};
}

test("legacy Sync mode is off by default for a real login JWT", { timeout: 30_000 }, async (t) => {
  const f = await fixture(t);
  assert.equal((await request(f.port, "/sync/v1/objects", "GET", f.token)).status, 200);
  assert.equal((await request(f.port, "/sync/v1/objects/sample", "GET", f.token)).status, 404);
  const resume = await request(f.port, "/sync/v1/devices/device-a/resume", "POST",
    f.token, { password: "test-only" });
  assert.equal(resume.status, 200, "legacy password-authenticated resume remains functional");
  assert.equal(resume.body.wasPaused, false);
});

test("strict Sync with no external attestor fails closed on all six legacy entry points",
  { timeout: 30_000 }, async (t) => {
    const f = await fixture(t, { legacyCutoverStrict: true });
    const before = await fs.readFile(f.storagePath);
    for (const [method, route] of endpoints) {
      const result = await request(f.port, route, method, f.token, endpointBody(method, route));
      assert.equal(result.status, 503, method + " " + route);
      assert.equal(result.body.code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
    }
    assert.deepEqual(await fs.readFile(f.storagePath), before,
      "strict refusal must not write even an unpaused resume transaction");
    assert.equal((await request(f.port, "/sync/v1/objects")).status, 401);
    assert.equal((await request(f.port, "/sync/v1/objects", "GET", f.token + "tampered")).status, 401);
  });

test("strict Sync ignores injected untrusted cutover adapters instead of trusting arbitrary functions",
  { timeout: 30_000 }, async (t) => {
    const log = [];
    const f = await fixture(t, {
      legacyCutoverStrict: true,
      legacyCutoverFence: {
        async withCurrentAccountLegacyPolicy(context, execute) {
          log.push(context);
          return execute();
        },
      },
    });
    for (const [method, route] of endpoints) {
      const result = await request(f.port, route, method, f.token, endpointBody(method, route));
      assert.equal(result.status, 503, method + " " + route);
      assert.equal(result.body.code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
    }
    assert.equal(log.length, 0, "no unbranded capability may invoke a legacy handler");
  });
