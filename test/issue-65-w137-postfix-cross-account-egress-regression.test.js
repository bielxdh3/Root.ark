"use strict";

// Security regression for the shared global WebSocket invalidation payload.
// Run unchanged against vulnerable 1cd1a565 for RED, then fixed be8df727
// for GREEN. Does not assert account-wide ZK cutover or immutable ownership.
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
const WebSocket = require("ws");

const root = process.env.ROOTARK_W137_BASELINE_ROOT
  ? path.resolve(process.env.ROOTARK_W137_BASELINE_ROOT)
  : path.resolve(__dirname, "..");
const request = (port, url, options = {}) => new Promise((resolve, reject) => {
  const req = http.request({ host: "127.0.0.1", port, path: url,
    method: options.method || "GET", headers: options.headers || {},
    signal: AbortSignal.timeout(10_000) }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
      body: Buffer.concat(chunks).toString("utf8") }));
  });
  req.once("error", reject);
  req.end(options.body);
});

async function randomPort() {
  const probe = net.createServer();
  await new Promise((resolve) => probe.listen(0, "127.0.0.1", resolve));
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

test("cross-account JWT/WS invalidations hide private DELETE and WebDAV mutation metadata",
  { timeout: 45_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w137-legacy-egress-"));
  const data = path.join(dir, "data");
  fs.mkdirSync(data);
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.symlinkSync(path.join(root, "public"), path.join(dir, "public"), "junction");
  const alicePassword = crypto.randomBytes(16).toString("base64url");
  const bobPassword = crypto.randomBytes(16).toString("base64url");
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify([
    { username: "alice", password: bcrypt.hashSync(alicePassword, 4), role: "user",
      permissions: { listFiles: true, delete: true, upload: true, createFolders: true }, sessionVersion: 0 },
    { username: "bob", password: bcrypt.hashSync(bobPassword, 4), role: "user",
      permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(data, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "sistema", isRoot: true },
  ]));
  const aclPath = path.join(data, "file-permissions.json");
  const acl = {
    "root/only-alice.txt": { folderId: "root", fileName: "only-alice.txt", owner: "alice", public: false, users: {} },
    "root/alice-activity.txt": { folderId: "root", fileName: "alice-activity.txt", owner: "alice", public: false, users: {} },
  };
  fs.writeFileSync(aclPath, JSON.stringify(acl));
  fs.writeFileSync(path.join(dir, "uploads", "only-alice.txt"), "private-test-byte-sequence");
  fs.writeFileSync(path.join(dir, "uploads", "alice-activity.txt"), "private-event-marker");

  const port = await randomPort();
  const env = { ...process.env, PORT: String(port), NODE_ENV: "test", DB_ENABLED: "false",
    CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "true",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(root, "server.js")],
    { cwd: dir, env, stdio: "ignore", windowsHide: true });
  let socket;
  t.after(async () => {
    if (socket) socket.terminate();
    if (child.exitCode === null) {
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await exited;
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  const readyDeadline = Date.now() + 15_000;
  let ready = false;
  while (Date.now() < readyDeadline && child.exitCode === null) {
    try { ready = (await request(port, "/login.html")).status === 200; }
    catch { await new Promise((resolve) => setTimeout(resolve, 60)); }
    if (ready) break;
  }
  assert.ok(ready, "disposable server did not start");

  async function login(username, password) {
    const body = JSON.stringify({ username, password });
    const response = await request(port, "/auth/login", { method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
    assert.equal(response.status, 200, response.body);
    const entries = response.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
    return { cookie: entries.join("; "), csrf: entries.find((value) => value.startsWith("rootark_csrf=")).split("=")[1] };
  }
  const alice = await login("alice", alicePassword);
  const bob = await login("bob", bobPassword);
  const bobRead = () => request(port, "/files/only-alice.txt?folderId=root",
    { headers: { cookie: bob.cookie, origin: `http://127.0.0.1:${port}` } });
  assert.equal((await bobRead()).status, 403, "ordinary ACL initially isolates Alice's file");

  socket = new WebSocket(`ws://127.0.0.1:${port}/ws`, {
    headers: { cookie: bob.cookie }, origin: `http://127.0.0.1:${port}` });
  const receivedChanges = [];
  socket.on("message", (raw) => {
    try {
      const message = JSON.parse(raw.toString());
      if (message.event === "data:changed") receivedChanges.push(message);
    } catch { /* malformed messages are not events */ }
  });
  function waitForInvalidation(source) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.off("message", onMessage);
        reject(new Error(`missing ${source} broadcast invalidation`));
      }, 6_000);
      function onMessage(raw) {
      let message;
      try { message = JSON.parse(raw.toString()); } catch { return; }
      if (message.event === "data:changed" && message.payload?.source === source) {
        clearTimeout(timer);
        socket.off("message", onMessage);
        resolve(message);
      }
      }
      socket.on("message", onMessage);
    });
  }
  await new Promise((resolve, reject) => {
    socket.once("open", resolve);
    socket.once("error", reject);
  });
  const activity = waitForInvalidation("trash");
  assert.equal((await request(port, "/files/alice-activity.txt?folderId=root",
    { headers: { cookie: bob.cookie, origin: `http://127.0.0.1:${port}` } })).status, 403);
  const deleteResult = await request(port, "/delete/alice-activity.txt?folderId=root", {
    method: "POST", headers: { cookie: alice.cookie, origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": alice.csrf, "content-type": "application/json", "content-length": "2" }, body: "{}",
  });
  assert.equal(deleteResult.status, 200, deleteResult.body);
  const trashMessage = await activity;

  const privateFolder = `alice-private-${crypto.randomBytes(5).toString("hex")}`;
  const privateWebDavFile = `alice-webdav-${crypto.randomBytes(5).toString("hex")}.txt`;
  const basicAlice = `Basic ${Buffer.from(`alice:${alicePassword}`).toString("base64")}`;
  const folderEvent = waitForInvalidation("folders");
  const mkcol = await request(port, `/dav/${privateFolder}`, {
    method: "MKCOL", headers: { authorization: basicAlice },
  });
  assert.equal(mkcol.status, 201, mkcol.body);
  const folderMessage = await folderEvent;
  const putEvent = waitForInvalidation("pending");
  const putBody = "private-webdav-data";
  const upload = await request(port, `/dav/${privateFolder}/${privateWebDavFile}`, {
    method: "PUT", headers: { authorization: basicAlice, "content-length": Buffer.byteLength(putBody) },
    body: putBody,
  });
  assert.equal(upload.status, 201, upload.body);
  const pendingMessage = await putEvent;
  const bobWebDav = await request(port, `/dav/${privateFolder}`, {
    method: "PROPFIND",
    headers: { authorization: `Basic ${Buffer.from(`bob:${bobPassword}`).toString("base64")}` },
  });
  assert.notEqual(bobWebDav.status, 207, "Bob must not enumerate Alice private WebDAV folder");

  assert.deepEqual(
    [trashMessage.payload, folderMessage.payload, pendingMessage.payload],
    [{ source: "trash" }, { source: "folders" }, { source: "pending" }],
    "HTTP DELETE and WebDAV MKCOL/PUT must produce only redacted WS categories for Bob",
  );
  for (const message of receivedChanges) {
    assert.deepEqual(message.payload, { source: message.payload.source },
      `Every global ${message.payload.source} WS invalidation must exclude private metadata`);
    assert.ok(!JSON.stringify(message).includes(privateFolder));
    assert.ok(!JSON.stringify(message).includes(privateWebDavFile));
    assert.ok(!JSON.stringify(message).includes("alice-activity.txt"));
  }
  assert.equal((await bobRead()).status, 403,
    "Bob stays unauthorized to Alice unrelated private file after deletion");
});
