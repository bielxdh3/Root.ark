"use strict";

// Route-only security regression. Local JWTs, creator metadata and public
// tokens cannot serve as ZK10 independent owner/object authorization.
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const FILE_NAME = "owner-secret.txt";
const CONTENT = "owner-B-private-ciphertext-fixture";

function freePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const port = listener.address().port;
      listener.close(() => resolve(port));
    });
  });
}

function request(port, url, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: url, method, headers,
      signal: AbortSignal.timeout(10_000) }, (res) => {
      const parts = [];
      res.on("data", (part) => parts.push(part));
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode,
        body: Buffer.concat(parts).toString(), headers: res.headers }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function fixture(t, strict) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-zk10-anon-"));
  const data = path.join(sandbox, "data");
  fs.mkdirSync(data);
  fs.mkdirSync(path.join(sandbox, "uploads"));
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", FILE_NAME), CONTENT);
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify([
    { username: "alice", password: bcrypt.hashSync(password, 4), role: "admin",
      permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(data, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "alice", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(data, "file-permissions.json"), JSON.stringify({
    [`root/${FILE_NAME}`]: { public: true, owner: "bob", users: {} },
  }));
  const shareToken = crypto.randomBytes(24).toString("hex");
  fs.writeFileSync(path.join(data, "public-links.json"), JSON.stringify({
    [shareToken]: { folderId: "root", fileName: FILE_NAME, createdBy: "alice",
      createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(),
      views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, activeViewers: {} },
  }));
  const port = await freePort();
  const env = { ...process.env, NODE_ENV: "test", PORT: String(port),
    DB_ENABLED: "false", CLOUD_STORAGE_PROVIDER: "local",
    ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict ? "1" : "0",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  for (const key of Object.keys(env)) if (/^(AWS_|GOOGLE_DRIVE_)/.test(key)) delete env[key];
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")],
    { cwd: sandbox, env, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
  let startupError = "";
  child.stderr.on("data", (part) => { startupError = (startupError + part.toString()).slice(-1800); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
    }
    fs.rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const deadline = Date.now() + 15_000;
  let ready;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`server exited: ${child.exitCode}\n${startupError}`);
    try { ready = await request(port, "/login.html"); break; }
    catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.equal(ready?.status, 200, "disposable real server started");
  const loginBody = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", { method: "POST", body: loginBody,
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) } });
  assert.equal(login.status, 200, "real JWT login");
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  return { port, shareToken, cookies: cookies.join("; "),
    csrf: cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1] };
}

async function exercise(t, strict) {
  const f = await fixture(t, strict);
  const origin = `http://127.0.0.1:${f.port}`;
  const body = JSON.stringify({ name: FILE_NAME, folderId: "root" });
  const jwtHeaders = { cookie: f.cookies, origin, "x-csrf-token": f.csrf,
    "content-type": "application/json", "content-length": Buffer.byteLength(body) };
  const makeOpen = await request(f.port, "/file-open-token", { method: "POST", body, headers: jwtHeaders });
  const openUrl = makeOpen.status === 200 ? JSON.parse(makeOpen.body).url
    : `/open-file/${crypto.randomBytes(24).toString("hex")}/${FILE_NAME}`;
  const openFile = await request(f.port, openUrl);
  const sharePage = await request(f.port, `/share/${f.shareToken}`);
  const shareView = await request(f.port, `/share/${f.shareToken}/view`,
    { method: "POST", headers: { origin } });
  const shareFile = await request(f.port, `/share/${f.shareToken}/file`,
    { method: "POST", headers: { origin } });
  if (strict) {
    for (const [label, result] of Object.entries({ makeOpen, openFile, sharePage, shareView, shareFile })) {
      assert.equal(result.status, 503, label + " requires independent ZK10 owner/object authority");
      assert.doesNotMatch(result.body, /owner-B-private-ciphertext-fixture/, label);
    }
    const newShareBody = JSON.stringify({
      name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
    });
    const shareNew = await request(f.port, "/share", { method: "POST", body: newShareBody,
      headers: { ...jwtHeaders, "content-length": Buffer.byteLength(newShareBody) } });
    assert.equal(shareNew.status, 503, "strict must refuse issuance as well as redemption");
    assert.equal(JSON.parse(shareNew.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
    const versionToken = await request(f.port, "/version-open-token", { method: "POST", body,
      headers: jwtHeaders });
    assert.equal(versionToken.status, 503, "version token issuance must also be denied");
    for (const [route, method] of [
      ["status", "POST"], ["password", "POST"], ["download", "POST"],
      ["preview", "GET"], ["preview", "POST"], ["qr", "GET"],
    ]) {
      const response = await request(f.port, `/share/${f.shareToken}/${route}`,
        { method, headers: { origin } });
      assert.equal(response.status, 503, `${route}/${method} must not bypass strict mode`);
      assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
    }
  } else {
    assert.equal(makeOpen.status, 200, "default-off legacy issuance");
    assert.equal(openFile.status, 200, "default-off legacy redemption");
    assert.equal(openFile.body, CONTENT);
    assert.equal(sharePage.status, 200, "default-off public page");
    assert.equal(shareView.status, 200, "default-off public share view");
    assert.equal(shareFile.status, 200, "default-off public share read");
    assert.equal(shareFile.body, CONTENT);
  }
}

test("legacy anonymous URLs stay usable with ZK10 default OFF", { timeout: 40_000 }, (t) => exercise(t, false));
test("strict ZK10 refuses anonymous share and open-file without external owner/object identity",
  { timeout: 40_000 }, (t) => exercise(t, true));
