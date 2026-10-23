"use strict";

const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const jwt = require("jsonwebtoken");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const MAX_STARTUP_MS = process.platform === "linux" && ROOT.startsWith("/mnt/") ? 60_000 : 20_000;

async function freePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await new Promise((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function request(port, pathname, method = "GET", body, headers = {}, declaredLength) {
  const bytes = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request({ hostname: "127.0.0.1", port, path: pathname, method,
      headers: { ...(bytes ? { "content-type": "application/json",
        "content-length": declaredLength ?? bytes.length } : {}), ...headers } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        let json;
        try { json = JSON.parse(Buffer.concat(chunks).toString()); } catch { json = null; }
        resolve({ status: res.statusCode, json, headers: res.headers });
      });
    });
    req.on("error", reject);
    // Send an actual oversized HTTP body so the request framing is valid.
    // The content-length still lets a premature parser reject before auth.
    if (declaredLength !== undefined) {
      req.end(Buffer.alloc(declaredLength, 0x20));
    } else {
      req.end(bytes || undefined);
    }
  });
}

async function start(t, enabled) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk-dev-parser-"));
  for (const name of ["data", "temp", "uploads"]) fs.mkdirSync(path.join(dir, name));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const password = crypto.randomBytes(20).toString("base64url");
  fs.writeFileSync(path.join(dir, "data", "users.local.json"), JSON.stringify([
    { username: "allowed", password: bcrypt.hashSync(password, 10), role: "user",
      permissions: { upload: true, listFiles: true, delete: true }, sessionVersion: 0 },
    { username: "reader", password: bcrypt.hashSync(password, 10), role: "user",
      permissions: { upload: false, listFiles: true, delete: false }, sessionVersion: 0 },
  ]));
  const port = await freePort();
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const env = { ...process.env, NODE_ENV: "test", PORT: String(port), DB_ENABLED: "false",
    JWT_SECRET: jwtSecret,
    ROOTARK_ZK_DEV_VAULT_DB: path.join(dir, "data", "dev.sqlite"),
    CLOUD_STORAGE_PROVIDER: "local" };
  if (enabled) env.ROOTARK_ZK_DEV_VAULT_ENABLED = "true";
  else delete env.ROOTARK_ZK_DEV_VAULT_ENABLED;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_ZK1_CONTENT_CONFIG;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: dir, env, stdio: ["ignore", "ignore", "pipe"], windowsHide: true,
  });
  let startupError = "";
  child.stderr.on("data", (chunk) => { startupError = (startupError + chunk).slice(-2000); });
  t.after(async () => {
    if (child.exitCode === null) {
      const done = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await Promise.race([done, new Promise((resolve) => setTimeout(resolve, 3_000))]);
      if (child.exitCode === null) { child.kill("SIGKILL"); await done; }
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 12, retryDelay: 100 });
  });
  const deadline = Date.now() + MAX_STARTUP_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("server exited on startup: " + startupError);
    try { if ((await request(port, "/login.html")).status === 200) break; }
    catch { /* server is booting */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.ok(Date.now() < deadline, "server ready");
  async function login(username) {
    const result = await request(port, "/auth/login", "POST", { username, password });
    assert.equal(result.status, 200, JSON.stringify(result.json));
    const cookies = result.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
    return { cookie: cookies.join("; "), origin: `http://127.0.0.1:${port}`,
      csrf: cookies.find((entry) => entry.startsWith("rootark_csrf=")).slice(13) };
  }
  return { port, login, jwtSecret };
}

function sessionHeaders(s, origin = s.origin) {
  return { cookie: s.cookie, origin, "x-csrf-token": s.csrf };
}

test("zk-dev disabled paths never parse oversized object or history JSON", { timeout: 60_000 }, async (t) => {
  const { port } = await start(t, false);
  for (const pathname of ["/zk-dev/v1/objects", "/ZK-DEV/V1/OBJECTS/",
    "/zk-dev/v1/objects/record", "/ZK-DEV/V1/ZK1-HISTORY/"]) {
    const r = await request(port, pathname, "POST", {}, {}, 12 * 1024 * 1024);
    assert.equal(r.status, 404, pathname);
  }
});

test("zk-dev enabled oversized JSON is gated by authentication, CSRF and permission first", {
  timeout: 60_000,
}, async (t) => {
  const { port, login, jwtSecret } = await start(t, true);
  const allowed = await login("allowed");
  const reader = await login("reader");
  const expired = jwt.sign({ username: "allowed", sessionVersion: 0, exp: 1 }, jwtSecret);
  for (const pathname of ["/zk-dev/v1/objects", "/ZK-DEV/V1/OBJECTS/",
    "/zk-dev/v1/objects/record", "/ZK-DEV/V1/ZK1-HISTORY/"]) {
    const method = pathname.toLowerCase().includes("/objects/record") ? "PUT" : "POST";
    const oversized = (headers = {}) => request(port, pathname, method, {}, headers, 12 * 1024 * 1024);
    assert.equal((await oversized()).status, 401, pathname + " no token");
    assert.equal((await oversized({ authorization: "Bearer " + expired })).status, 401,
      pathname + " expired token");
    assert.equal((await oversized(sessionHeaders(allowed, "https://evil.example"))).status, 403,
      pathname + " cross-origin");
    assert.equal((await oversized({ cookie: allowed.cookie })).status, 403,
      pathname + " missing CSRF");
    assert.equal((await oversized(sessionHeaders(reader))).status, 403, pathname + " missing upload");
    assert.equal((await oversized(sessionHeaders(allowed))).status, 413, pathname + " oversized");
  }
  for (const pathname of ["/ZK-DEV/V1/OBJECTS/record/", "/zk-dev/v1/objects/%2Fbad"]) {
    assert.equal((await request(port, pathname, "GET", {}, {}, 12 * 1024 * 1024)).status, 401,
      pathname + " GET must authenticate before considering its body");
  }
  assert.equal((await request(port, "/ZK-DEV/V1/OBJECTS/record/", "DELETE", {},
    sessionHeaders(reader), 12 * 1024 * 1024)).status, 403,
  "DELETE must check delete permission before parsing");
  assert.equal((await request(port, "/ZK-DEV/V1/OBJECTS/record/", "DELETE", {},
    sessionHeaders(allowed), 12 * 1024 * 1024)).status, 413,
  "authorized DELETE must retain bounded JSON parsing");
  const longInvalid = "A".repeat(150_000);
  assert.equal((await request(port, "/ZK-DEV/V1/OBJECTS/", "POST", {
    account: "allowed", id: "nope", envelope: longInvalid, keyId: "nope",
  }, sessionHeaders(allowed))).status, 400,
  "authorized requests larger than default 100kb must reach object validation");
  assert.equal((await request(port, "/ZK-DEV/V1/ZK1-HISTORY/", "POST", {
    account: "allowed", manifestBase64: longInvalid,
    expectedRevision: 0, expectedDigest: null,
  }, sessionHeaders(allowed))).status, 400,
  "signed-history canonical aliases must reach its authenticated 11mb parser");
});
