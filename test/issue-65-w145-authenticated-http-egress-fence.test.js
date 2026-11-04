"use strict";

// RED: real authenticated Alice/Bob legacy HTTP bytes and metadata escape
// strict Sync cutover. GREEN: every scoped GET/HEAD fails closed, not merely
// the eventual stream or a conditional 304. Neither case proves owner custody.
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

const root = path.resolve(__dirname, "..");
const SENTINEL = "ALICE_PRIVATE_ZK65_HTTP_EGRESS_SENTINEL";
const NAME = "zk65-private-egress.txt";
const request = (port, route, method = "GET", headers = {}, body) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: route, method,
    headers, signal: AbortSignal.timeout(12000) }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("error", reject);
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
      body: Buffer.concat(chunks).toString("utf8") }));
  });
  req.on("error", reject);
  req.end(body);
});
const freePort = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    server.close(() => resolve(port));
  });
});

async function fixture(t, strict) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w145-auth-egress-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.symlinkSync(path.join(root, "public"), path.join(dir, "public"), "junction");
  const secrets = { alice: crypto.randomBytes(12).toString("base64url"),
    bob: crypto.randomBytes(12).toString("base64url") };
  fs.writeFileSync(path.join(dir, "data", "users.local.json"), JSON.stringify(
    Object.entries(secrets).map(([username, password]) => ({
      username, password: bcrypt.hashSync(password, 4), role: "user",
      permissions: { listFiles: true, upload: true }, sessionVersion: 0,
    }))));
  fs.writeFileSync(path.join(dir, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "sistema", isRoot: true },
  ]));
  fs.writeFileSync(path.join(dir, "data", "file-permissions.json"), JSON.stringify({
    [`root/${NAME}`]: { folderId: "root", fileName: NAME, owner: "alice", public: false, users: {} },
  }));
  fs.writeFileSync(path.join(dir, "uploads", NAME), SENTINEL);
  const port = await freePort();
  const env = { ...process.env, PORT: String(port), NODE_ENV: "test", DB_ENABLED: "false",
    CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "false",
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict ? "true" : "off",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(root, "server.js")], {
    cwd: dir, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  let diagnostic = "";
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => { diagnostic = (diagnostic + chunk.toString()).slice(-2200); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const done = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await done;
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  let ready = false;
  for (let i = 0; i < 240 && child.exitCode === null; i++) {
    try { ready = (await request(port, "/login.html")).status === 200; } catch {}
    if (ready) break;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  assert.ok(ready, "disposable child did not start: " + diagnostic);
  const cookies = {};
  for (const [username, password] of Object.entries(secrets)) {
    const body = JSON.stringify({ username, password });
    const login = await request(port, "/auth/login", "POST", {
      "content-type": "application/json", "content-length": Buffer.byteLength(body),
    }, body);
    assert.equal(login.status, 200, `${username} JWT login: ${login.body}`);
    cookies[username] = login.headers["set-cookie"].map((c) => c.split(";")[0]).join("; ");
    assert.match(cookies[username], /rootark_session=/);
  }
  return { port, cookies };
}

const scoped = [
  "/files/search?q=zk65-private-egress", `/files/${NAME}?folderId=root`,
  "/list?folderId=root", `/versions/${NAME}?folderId=root`,
  `/download/${NAME}/v/1?folderId=root`, "/history",
  `/preview/file/public/${NAME}?folderId=root`,
  `/preview/text/public/${NAME}?folderId=root`,
];

test("strict authenticated legacy HTTP egress denies Alice/Bob JSON, bytes, HEAD, range and conditional reads", {
  timeout: 90_000,
}, async (t) => {
  const { port, cookies } = await fixture(t, true);
  const anonymous = await request(port, "/list?folderId=root");
  assert.equal(anonymous.status, 401, "strict fence must not bypass JWT authentication");
  const directLeak = await request(port, "/list?folderId=root", "GET", { cookie: cookies.alice });
  assert.equal(directLeak.status, 503,
    "strict legacy metadata leak: list must never enumerate Alice's private file: " + directLeak.body.slice(0, 150));
  for (const [username, cookie] of Object.entries(cookies)) {
    for (const pathname of scoped) {
      for (const method of ["GET", "HEAD"]) {
        const response = await request(port, pathname, method, {
          cookie, origin: `http://127.0.0.1:${port}`,
          range: "bytes=0-8",
          "if-none-match": "*", "if-modified-since": new Date(Date.now() + 86400000).toUTCString(),
        });
        assert.equal(response.status, 503, `${username} ${method} ${pathname}: ${response.status} ${response.body.slice(0, 120)}`);
        assert.equal(response.headers["cache-control"], "no-store");
        assert.ok(!response.body.includes(SENTINEL), "private content must not escape");
        if (method === "GET")
          assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
        else assert.equal(response.body, "", "HEAD must not stream body");
      }
    }
  }
});

test("default OFF retains genuine authenticated Alice GET/HEAD and ordinary Bob ACL", {
  timeout: 60_000,
}, async (t) => {
  const { port, cookies } = await fixture(t, false);
  const aliceHeaders = { cookie: cookies.alice, origin: `http://127.0.0.1:${port}` };
  const list = await request(port, "/list?folderId=root", "GET", aliceHeaders);
  assert.equal(list.status, 200, list.body);
  assert.ok(list.body.includes(NAME), "normal list must return existing file");
  const search = await request(port, "/files/search?q=zk65-private-egress", "GET", aliceHeaders);
  assert.equal(search.status, 200, search.body);
  assert.ok(search.body.includes(NAME));
  const file = await request(port, `/files/${NAME}?folderId=root`, "GET", aliceHeaders);
  assert.equal(file.status, 200, file.body);
  assert.equal(file.body, SENTINEL);
  const head = await request(port, `/files/${NAME}?folderId=root`, "HEAD", aliceHeaders);
  assert.equal(head.status, 200);
  assert.equal(head.body, "");
  for (const pathname of ["/history", `/versions/${NAME}?folderId=root`,
    `/preview/text/public/${NAME}?folderId=root`]) {
    const response = await request(port, pathname, "GET", aliceHeaders);
    assert.equal(response.status, 200, `default OFF ${pathname}: ${response.body}`);
  }
  const denied = await request(port, `/files/${NAME}?folderId=root`, "GET",
    { cookie: cookies.bob, origin: `http://127.0.0.1:${port}` });
  assert.equal(denied.status, 403, "ordinary ACL must still protect Bob");
  const auth = await request(port, "/auth/me", "GET", { cookie: cookies.alice });
  assert.equal(auth.status, 200, "unrelated authenticated routes remain reachable");
});
