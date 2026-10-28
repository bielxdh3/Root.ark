"use strict";

// Executable RED/GREEN, two independent REAL /auth/login cookie sessions and
// the actual /ws socket + WebDAV mutation path. The live legacy UI consumes
// data:changed.payload.source to invalidate; private filenames/folder IDs
// must never be pushed to a different account over that shared channel.
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
const port = () => new Promise((resolve, reject) => {
  const server = net.createServer();
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const number = server.address().port;
    server.close(() => resolve(number));
  });
});
function request(number, url, method = "GET", headers = {}, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: number, path: url,
      method, headers, signal: AbortSignal.timeout(12000) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end(body);
  });
}
function observe(socket) {
  const messages = [];
  const transcript = [];
  const waiters = [];
  socket.on("message", (raw) => {
    const message = JSON.parse(raw.toString("utf8"));
    transcript.push(message);
    const index = waiters.findIndex((waiter) => waiter.event === message.event
      && (!waiter.source || waiter.source === message.payload?.source)
      && (!waiter.action || waiter.action === message.payload?.action));
    if (index < 0) return messages.push(message);
    const waiter = waiters.splice(index, 1)[0];
    clearTimeout(waiter.timer);
    waiter.resolve(message);
  });
  function next(event, source, action) {
    const index = messages.findIndex((message) => message.event === event
      && (!source || source === message.payload?.source)
      && (!action || action === message.payload?.action));
    if (index >= 0) return Promise.resolve(messages.splice(index, 1)[0]);
    return new Promise((resolve, reject) => {
      const waiter = { event, source, action, resolve };
      waiter.timer = setTimeout(() => {
        const at = waiters.indexOf(waiter);
        if (at >= 0) waiters.splice(at, 1);
        reject(new Error("Timed out waiting for websocket " + event + " " + source));
      }, 5000);
      waiters.push(waiter);
    });
  }
  next.transcript = transcript;
  return next;
}

test("ZK10 real authenticated A/B websocket does not disclose private WebDAV folderId/filename and rejects revoked sessions",
  { timeout: 60000 }, async (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-ws-egress-"));
    fs.mkdirSync(path.join(dir, "data"));
    const secret = "file-private-" + crypto.randomBytes(6).toString("hex") + ".txt";
    const privateFolder = "personal-" + crypto.randomBytes(6).toString("hex");
    fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
      { username: "alice", password: bcrypt.hashSync("alice-local", 10),
        role: "user", sessionVersion: 0,
        permissions: { upload: true, createFolders: true, listFiles: true } },
      { username: "bob", password: bcrypt.hashSync("bob-local", 10),
        role: "user", sessionVersion: 0,
        permissions: { listFiles: true } },
    ]));
    fs.symlinkSync(path.join(root, "public"), path.join(dir, "public"), "junction");
    const number = await port();
    const child = spawn(process.execPath, [path.join(root, "server.js")], {
      cwd: dir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NODE_ENV: "test", PORT: String(number),
        DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
        UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "true",
        JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    });
    let logs = "";
    child.stderr.on("data", (chunk) => { logs += String(chunk).slice(0, 1000); });
    child.stdout.on("data", (chunk) => { logs += String(chunk).slice(0, 1000); });
    const sockets = [];
    t.after(async () => {
      for (const socket of sockets) socket.terminate();
      if (child.exitCode === null && child.signalCode === null)
        await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
      fs.rmSync(dir, { recursive: true, force: true });
    });
    let started = false;
    for (let i = 0; i < 240; i++) {
      try { await request(number, "/login.html"); started = true; break; }
      catch { if (child.exitCode !== null) break;
        await new Promise((resolve) => setTimeout(resolve, 75)); }
    }
    assert.ok(started, "server bootstrap failed: " + logs);
    const origin = "http://127.0.0.1:" + number;
    async function login(user, password) {
      const body = JSON.stringify({ username: user, password });
      const response = await request(number, "/auth/login", "POST",
        { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body);
      assert.equal(response.status, 200, "real auth/login for " + user);
      const cookies = response.headers["set-cookie"].map((item) => item.split(";")[0]);
      return { cookie: cookies.join("; "), csrf: cookies.find((item) =>
        item.startsWith("rootark_csrf=")).slice("rootark_csrf=".length) };
    }
    const alice = await login("alice", "alice-local");
    const bob = await login("bob", "bob-local");
    function connect(session) {
      const socket = new WebSocket("ws://127.0.0.1:" + number + "/ws",
        { origin, headers: { cookie: session.cookie } });
      sockets.push(socket);
      return { socket, next: observe(socket) };
    }
    const a = connect(alice);
    const b = connect(bob);
    assert.equal((await a.next("connected")).payload.username, "alice");
    assert.equal((await b.next("connected")).payload.username, "bob");

    const basic = "Basic " + Buffer.from("alice:alice-local").toString("base64");
    const mkdirA = a.next("data:changed", "folders");
    const mkdirB = b.next("data:changed", "folders");
    const mkdir = await request(number, "/dav/" + privateFolder, "MKCOL",
      { authorization: basic });
    assert.equal(mkdir.status, 201, mkdir.body + " " + logs);
    const folderId = JSON.parse(fs.readFileSync(path.join(dir, "data", "folders.json")))
      .find((entry) => entry.name === privateFolder).id;
    const [createdA, createdB] = await Promise.all([mkdirA, mkdirB]);
    assert.equal(createdA.payload.source, "folders");
    assert.equal(createdB.payload.source, "folders", "legacy refresh remains functional");
    assert.deepEqual(createdB.payload, { source: "folders" },
      "global invalidation packet must carry no user metadata or mutation details");
    assert.ok(!JSON.stringify(createdB).includes(folderId),
      "cross-account authenticated WS must never expose private folderId");

    const putA = a.next("data:changed", "pending");
    const putB = b.next("data:changed", "pending");
    const put = await request(number, "/dav/" + privateFolder + "/" + secret,
      "PUT", { authorization: basic, "content-length": "4" }, "test");
    assert.equal(put.status, 201, put.body + " " + logs);
    const [pendingA, pendingB] = await Promise.all([putA, putB]);
    assert.equal(pendingA.payload.source, "pending");
    assert.equal(pendingB.payload.source, "pending");
    assert.deepEqual(pendingB.payload, { source: "pending" });
    await new Promise((resolve) => setTimeout(resolve, 60));
    for (const packet of b.next.transcript) {
      if (packet.event !== "data:changed") continue;
      assert.deepEqual(Object.keys(packet.payload), ["source"],
        "all broadcast invalidations must omit untrusted metadata");
    }
    for (const packet of [pendingA, pendingB]) {
      assert.ok(!JSON.stringify(packet).includes(folderId), "event leaked folderId");
      assert.ok(!JSON.stringify(packet).includes(secret), "event leaked fileName");
    }
    const unrelatedList = await request(number, "/dav/" + privateFolder,
      "PROPFIND", { authorization: "Basic " + Buffer.from("bob:bob-local").toString("base64") });
    assert.notEqual(unrelatedList.status, 207, "Bob must not have read access to Alice's folder");

    const closed = new Promise((resolve) => b.socket.once("close", (code) => resolve(code)));
    const logout = await request(number, "/auth/logout", "POST",
      { cookie: bob.cookie, origin, "x-csrf-token": bob.csrf });
    assert.equal(logout.status, 204);
    b.socket.send(JSON.stringify({ event: "ping" }));
    assert.equal(await closed, 1008, "realtime invalidation must close revoked sessions");
    assert.equal((await request(number, "/auth/me", "GET",
      { cookie: bob.cookie })).status, 401);
    const stillActive = a.next("data:changed", "folders");
    assert.equal((await request(number, "/dav/" + privateFolder + "-next",
      "MKCOL", { authorization: basic })).status, 201);
    assert.equal((await stillActive).payload.source, "folders");
  });
