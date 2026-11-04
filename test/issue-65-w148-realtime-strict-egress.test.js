"use strict";

// Adversarial HTTP + JWT cookie + WebSocket test: an authenticated account
// must not learn even the category/timing of another account's mutation when
// ZK10 strict cutover lacks independently verified account/owner authority.
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

const root = path.resolve(__dirname, "..");
function openPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const result = server.address().port;
      server.close(() => resolve(result));
    });
  });
}
function request(port, url, method = "GET", headers = {}, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: url, method, headers,
      signal: AbortSignal.timeout(12_000) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.once("error", reject);
    req.end(body);
  });
}
function observe(socket) {
  const transcript = [];
  const waiters = [];
  socket.on("message", (raw) => {
    const packet = JSON.parse(raw.toString());
    transcript.push(packet);
    for (let i = 0; i < waiters.length; i++) {
      if (packet.event !== waiters[i].event) continue;
      const waiter = waiters.splice(i, 1)[0];
      clearTimeout(waiter.timer);
      waiter.resolve(packet);
      break;
    }
  });
  return {
    transcript,
    next(event) {
      const existing = transcript.find((packet) => packet.event === event);
      if (existing) return Promise.resolve(existing);
      return new Promise((resolve, reject) => {
        const waiter = { event, resolve };
        waiter.timer = setTimeout(() => {
          const i = waiters.indexOf(waiter);
          if (i >= 0) waiters.splice(i, 1);
          reject(new Error("Missing WebSocket event: " + event));
        }, 5000);
        waiters.push(waiter);
      });
    },
  };
}

test("strict ZK10 mutes all account-ambiguous mutation notifications even with real A/B JWT sockets", { timeout: 60000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w148-strict-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "alice", password: bcrypt.hashSync("alice-local", 10), role: "user",
      sessionVersion: 0, permissions: { createFolders: true, listFiles: true } },
    { username: "bob", password: bcrypt.hashSync("bob-local", 10), role: "user",
      sessionVersion: 0, permissions: { listFiles: true } },
  ]));
  fs.symlinkSync(path.join(root, "public"), path.join(dir, "public"), "junction");
  const number = await openPort();
  const child = spawn(process.execPath, [path.join(root, "server.js")], {
    cwd: dir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, NODE_ENV: "test", PORT: String(number), DB_ENABLED: "false",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", UPLOAD_SCAN_ENABLED: "false",
      ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
  });
  let logs = "";
  child.stdout.on("data", (chunk) => { logs += String(chunk).slice(0, 300); });
  child.stderr.on("data", (chunk) => { logs += String(chunk).slice(0, 300); });
  const sockets = [];
  t.after(async () => {
    for (const socket of sockets) socket.terminate();
    if (child.exitCode === null && child.signalCode === null) {
      const exited = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await exited;
    }
    fs.rmSync(dir, { recursive: true, force: true });
  });
  let ready = false;
  for (let i = 0; i < 240; i++) {
    try { await request(number, "/login.html"); ready = true; break; }
    catch { if (child.exitCode !== null) break; await new Promise((resolve) => setTimeout(resolve, 75)); }
  }
  assert.ok(ready, "server bootstrap failed: " + logs);
  const origin = `http://127.0.0.1:${number}`;
  async function login(username, password) {
    const body = JSON.stringify({ username, password });
    const response = await request(number, "/auth/login", "POST", {
      "content-type": "application/json", "content-length": Buffer.byteLength(body),
    }, body);
    assert.equal(response.status, 200, username + ": " + response.body);
    const cookies = response.headers["set-cookie"].map((item) => item.split(";")[0]);
    return { cookie: cookies.join("; "), csrf: cookies.find((item) => item.startsWith("rootark_csrf=")).slice(13) };
  }
  const alice = await login("alice", "alice-local");
  const bob = await login("bob", "bob-local");
  async function connect(session) {
    const socket = new WebSocket(`ws://127.0.0.1:${number}/ws`, { origin,
      headers: { cookie: session.cookie } });
    sockets.push(socket);
    const observer = observe(socket);
    await observer.next("connected");
    return { socket, observer };
  }
  const a = await connect(alice);
  const b = await connect(bob);
  const privateName = "alice-only-" + crypto.randomBytes(6).toString("hex");
  const body = JSON.stringify({ name: privateName, users: {} });
  const created = await request(number, "/folders", "POST", {
    cookie: alice.cookie, origin, "x-csrf-token": alice.csrf,
    "content-type": "application/json", "content-length": Buffer.byteLength(body),
  }, body);
  assert.equal(created.status, 201, "real Alice folder mutation must succeed: " + created.body);
  assert.equal(JSON.parse(created.body).name, privateName);

  // An HTTP response comes after the synchronous mutation broadcast; a pong
  // on each ordered socket is a barrier proving earlier packets arrived.
  for (const peer of [a, b]) {
    peer.socket.send(JSON.stringify({ event: "ping" }));
    await peer.observer.next("pong");
    assert.deepEqual(peer.observer.transcript.map((packet) => packet.event), ["connected", "pong"],
      "strict mode must not leak category, presence or timing across any socket");
  }
});
