"use strict";

// Real server child, real /auth/login JWT and WebDAV Basic request. No owner
// authority is bootstrapped here: strict mode must fail closed, not infer an
// owner-signed negative-membership proof from the legacy users table.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const bcrypt = require("bcryptjs");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const root = path.resolve(__dirname, "..");
const request = (port, route, method = "GET", headers = {}, body, deadlineMs = 15000) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: route, method,
    headers, signal: AbortSignal.timeout(deadlineMs) }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("error", reject);
    res.on("end", () => resolve({ status: res.statusCode,
      headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
  });
  req.on("error", reject);
  req.end(body);
});
const availablePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer();
  probe.once("error", reject);
  probe.listen(0, "127.0.0.1", () => {
    const port = probe.address().port;
    probe.close(() => resolve(port));
  });
});

test("W145 strict signed Sync cutover cannot be bypassed through authenticated WebDAV MKCOL", {
  timeout: 60000,
}, async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w145-real-webdav-"));
  fs.mkdirSync(path.join(tmp, "data"));
  fs.writeFileSync(path.join(tmp, "data", "users.json"), JSON.stringify([{
    username: "alice", password: bcrypt.hashSync("alice-dev-password", 10),
    role: "user", sessionVersion: 0,
    permissions: { listFiles: true, upload: true, createFolders: true },
  }]));
  fs.symlinkSync(path.join(root, "public"), path.join(tmp, "public"), "junction");
  const port = await availablePort();
  const child = spawn(process.execPath, [path.join(root, "server.js")], {
    cwd: tmp, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
    env: { ...process.env, NODE_ENV: "test", PORT: String(port), DB_ENABLED: "false",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", UPLOAD_SCAN_ENABLED: "false",
      WEBDAV_ENABLED: "true", ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
  });
  let stderr = "";
  child.stderr.on("data", (chunk) => { stderr += String(chunk).slice(0, 1200); });
  child.stdout.on("data", (chunk) => { stderr += String(chunk).slice(0, 1200); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null)
      await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  let started = false;
  for (let attempt = 0; attempt < 240; attempt++) {
    try { await request(port, "/login.html", "GET", {}, undefined, 700); started = true; break; }
    catch { if (child.exitCode !== null) break;
      await new Promise((resolve) => setTimeout(resolve, 75)); }
  }
  assert.ok(started, "real server failed to boot: " + stderr.slice(-1800));
  const body = JSON.stringify({ username: "alice", password: "alice-dev-password" });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(body),
  }, body);
  assert.equal(login.status, 200, "real JWT login must succeed");
  const cookie = login.headers["set-cookie"].find((v) => v.startsWith("rootark_session="));
  assert.ok(cookie);
  const strictSync = await request(port, "/sync/v1/objects", "GET",
    { cookie: cookie.split(";")[0] });
  assert.equal(strictSync.status, 503, strictSync.text);
  assert.equal(JSON.parse(strictSync.text).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");

  const folder = "protected-downgrade-" + crypto.randomBytes(5).toString("hex");
  const webdav = await request(port, "/dav/" + folder, "MKCOL", {
    authorization: "Basic " + Buffer.from("alice:alice-dev-password").toString("base64"),
  });
  assert.equal(webdav.status, 503, "legacy WebDAV bypassed strict signed cutover: " + webdav.text);
  const basic = "Basic " + Buffer.from("alice:alice-dev-password").toString("base64");
  for (const method of ["GET", "HEAD", "PROPFIND", "PUT", "MOVE"]) {
    const response = await request(port, "/dav/" + folder, method,
      { authorization: basic });
    assert.equal(response.status, 503, `${method} WebDAV must fail closed in strict mode`);
  }
  const status = await request(port,
    "/webdav/moves/00000000-0000-4000-8000-000000000000/status", "GET",
    { cookie: cookie.split(";")[0] });
  assert.equal(status.status, 503, "JWT WebDAV move status also requires signed cutover authority");
  const foldersPath = path.join(tmp, "data", "folders.json");
  if (fs.existsSync(foldersPath))
    assert.ok(!fs.readFileSync(foldersPath, "utf8").includes(folder),
      "denied WebDAV request must not create a folder");
});
