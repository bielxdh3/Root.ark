"use strict";
const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");
const unzipper = require("unzipper");

const ROOT = path.resolve(__dirname, "..");
const CHILD = path.join(__dirname, "support", "w147-strict-backup-child.cjs");
function request(port, route, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: route, method, headers,
      signal: AbortSignal.timeout(12000) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks) }));
    });
    req.once("error", reject);
    req.end(body);
  });
}
async function unusedPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}
async function running(port, child) {
  const until = Date.now() + 12000;
  while (Date.now() < until && child.exitCode === null) {
    try {
      const answer = await request(port, "/health");
      if (answer.status === 200) return;
    } catch { /* cold-start probe */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("isolated server failed to start: " + child.diagnostics.slice(-1000));
}
async function start(root, port, password, strict) {
  const env = { ...process.env, DB_ENABLED: "false", PORT: String(port),
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict, CLOUD_STORAGE_PROVIDER: "local",
    BACKUP_ENABLED: "true", BACKUP_AUTO_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", JWT_SECRET: password.repeat(3).slice(0, 72) };
  const child = spawn(process.execPath, [path.join(__dirname, "../lab/issue-65-test-processes", "w147-strict-backup-http-server.cjs")], {
    cwd: root, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  child.diagnostics = "";
  child.stdout.on("data", (chunk) => { child.diagnostics = (child.diagnostics + chunk).slice(-1500); });
  child.stderr.on("data", (chunk) => { child.diagnostics = (child.diagnostics + chunk).slice(-1500); });
  try { await running(port, child); }
  catch (error) { child.kill(); throw error; }
  return child;
}
async function login(port, password) {
  const body = Buffer.from(JSON.stringify({ username: "manager", password }));
  const answer = await request(port, "/auth/login", { method: "POST",
    headers: { "content-type": "application/json", "content-length": body.length }, body });
  assert.equal(answer.status, 200, answer.body.toString());
  const cookies = answer.headers["set-cookie"].map((c) => c.split(";", 1)[0]);
  return { cookies: cookies.join("; "), csrf: cookies.find((c) => c.startsWith("rootark_csrf=")).split("=", 2)[1] };
}
function auth(port, session) {
  return { cookie: session.cookies, "x-csrf-token": session.csrf, origin: "http://127.0.0.1:" + port };
}
async function stop(child) {
  if (child.exitCode !== null) return;
  child.kill();
  await Promise.race([
    new Promise((resolve) => child.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 8000)),
  ]);
}
test("JWT manager cannot create, restore or download another account's legacy backup in STRICT; OFF remains legacy", { timeout: 110000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-http-"));
  const password = crypto.randomBytes(24).toString("base64url");
  const uploadDir = path.join(root, "uploads", "root");
  fs.mkdirSync(uploadDir, { recursive: true });
  fs.mkdirSync(path.join(root, "data"), { recursive: true });
  fs.writeFileSync(path.join(uploadDir, "victim.txt"), "W147_OTHER_ACCOUNT_PLAINTEXT_TEST_ONLY");
  fs.writeFileSync(path.join(root, "data", "users.json"), JSON.stringify([
    { username: "manager", password: bcrypt.hashSync(password, 10), role: "user", permissions: { manageBackups: true }, sessionVersion: 0 },
    { username: "victim", password: bcrypt.hashSync(password, 10), role: "user", permissions: {}, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(root, "data", "folders.json"), "[]");
  let server;
  t.after(async () => { if (server) await stop(server); fs.rmSync(root, { recursive: true, force: true }); });
  const initial = spawnSync(process.execPath, [CHILD, "create"], {
    cwd: root, encoding: "utf8", timeout: 30000, windowsHide: true,
    env: { ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true",
      BACKUP_INCLUDE_UPLOADS: "true", ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "0" },
  });
  assert.equal(initial.status, 0, initial.stderr || initial.stdout);
  const backup = JSON.parse(initial.stdout.trim().split(/\r?\n/).at(-1));
  assert.equal(backup.allowed, true, initial.stdout);
  const archive = await unzipper.Open.file(path.join(root, "data", "backups", backup.filename));
  assert.equal((await archive.files.find((file) => file.path === "uploads/root/victim.txt").buffer()).toString(),
    "W147_OTHER_ACCOUNT_PLAINTEXT_TEST_ONLY");
  const port = await unusedPort();
  server = await start(root, port, password, "1");
  const session = await login(port, password);
  const body = Buffer.from("{}");
  for (const [method, route] of [
    ["POST", "/backups"], ["POST", "/backups/" + backup.id + "/restore"],
    ["GET", "/backups/" + backup.id + "/download"], ["HEAD", "/backups/" + backup.id + "/download"],
    ["DELETE", "/backups/" + backup.id],
  ]) {
    const response = await request(port, route, { method, headers: { ...auth(port, session),
      ...(method === "POST" ? { "content-type": "application/json", "content-length": body.length } : {}) },
      ...(method === "POST" ? { body } : {}) });
    assert.equal(response.status, 503, method + " " + route + ": " + response.body.toString().slice(0, 200));
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(response.body.includes(Buffer.from("W147_OTHER_ACCOUNT_PLAINTEXT_TEST_ONLY")), false);
  }
  assert.equal(fs.readdirSync(path.join(root, "data", "backups")).filter((name) => name.endsWith(".zip")).length,
    1, "strict attempts cannot create another ZIP");

  await stop(server);
  server = await start(root, port, password, "0");
  const legacySession = await login(port, password);
  const legacy = await request(port, "/backups/" + backup.id + "/download", {
    headers: auth(port, legacySession),
  });
  assert.equal(legacy.status, 200, "OFF after restart still permits old plaintext ZIP; this is a documented downgrade");
  assert.deepEqual(legacy.body, fs.readFileSync(path.join(root, "data", "backups", backup.filename)));
});
