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
const proxyaddr = require("proxy-addr");
const { parseTrustedProxies } = require("../src/middlewares/trustedProxies");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");

function getUnusedPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function request(port, requestPath, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited");
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

function waitForWebSocketEvent(socket, event, timeout = 3_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for WebSocket ${event}`)), timeout);
    socket.on("message", (rawMessage) => {
      let message;
      try { message = JSON.parse(rawMessage.toString()); } catch { return; }
      if (message.event !== event) return;
      clearTimeout(timer);
      resolve(message);
    });
    socket.once("error", (error) => { clearTimeout(timer); reject(error); });
    socket.once("close", (code, reason) => {
      clearTimeout(timer);
      reject(new Error(`WebSocket closed before ${event}: ${code} ${reason}`));
    });
  });
}

test("trusted proxy configuration accepts explicit IP ranges and rejects malformed or empty entries", () => {
  assert.equal(parseTrustedProxies(undefined), false);
  assert.equal(parseTrustedProxies("  "), false);
  assert.deepEqual(parseTrustedProxies("127.0.0.1, 10.0.0.0/8, 2001:db8::/32, ::ffff:10.0.0.0/104"), ["127.0.0.1", "10.0.0.0/8", "2001:db8::/32", "::ffff:10.0.0.0/104"]);
  for (const invalid of ["true", "*", "localhost", "127.0.0.1,", "0.0.0.0/0", "0.0.0.0/7", "::/0", "::/1", "::ffff:10.0.0.0/8", "::ffff:0.0.0.0/96", "::ffff:0.0.0.0/096", "::ffff:10.0.0.0/103", "::ffff:0:0/96", "::ffff:0:0/0103", "0:0:0:0:0:ffff:0:0/96", "fe80::1%eth0", "fe80::1%eth0/128", "192.0.2.1/33", "2001:db8::/129"]) {
    assert.throws(() => parseTrustedProxies(invalid), /explicit IP addresses or CIDR ranges/);
  }
});

test("proxy-addr does not match IPv4-mapped peers against broad IPv6 prefixes", () => {
  const trust = proxyaddr.compile(["::/1"]);
  assert.equal(trust("::ffff:127.0.0.1", 0), false);
  assert.equal(trust("::ffff:198.51.100.19", 0), false);
  const mappedV4Slash8 = proxyaddr.compile(parseTrustedProxies("::ffff:10.0.0.0/104"));
  assert.equal(mappedV4Slash8("::ffff:10.1.2.3", 0), true);
  assert.equal(mappedV4Slash8("::ffff:11.1.2.3", 0), false);
});

test("server refuses an overbroad IPv6 trust range before accepting requests", { timeout: 15_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-proxy-broad-v6-"));
  fs.mkdirSync(path.join(directory, "data"), { recursive: true });
  fs.writeFileSync(path.join(directory, "data", "users.local.json"), JSON.stringify([
    { username: "fixture", password: bcrypt.hashSync("disposable-password", 10), role: "user", permissions: {}, sessionVersion: 0 },
  ]));
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"), TRUSTED_PROXIES: "::/1" },
    stdio: ["ignore", "ignore", "pipe"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill();
      await new Promise((resolve) => child.once("exit", resolve));
    }
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  const exitCode = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), 5_000);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
  assert.notEqual(exitCode, null, "server must reject the broad trust range rather than listening");
  assert.notEqual(exitCode, 0, stderr);
  assert.match(stderr, /TRUSTED_PROXIES/);
});

test("login audit IP ignores untrusted forwarding headers and honors configured proxy hops", { timeout: 60_000 }, async (t) => {
  const sandboxes = [];
  const servers = [];
  t.after(async () => {
    for (const child of servers) {
      if (child.exitCode === null) {
        child.kill();
        await new Promise((resolve) => child.once("exit", resolve));
      }
    }
    for (const directory of sandboxes) fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  for (const scenario of [
    { name: "direct-untrusted", headers: { "x-forwarded-for": "198.51.100.10", "cf-connecting-ip": "198.51.100.11", "x-real-ip": "198.51.100.12" }, expected: "127.0.0.1" },
    { name: "trusted-proxy", trusted: "127.0.0.1/32", headers: { "x-forwarded-for": "198.51.100.20" }, expected: "198.51.100.20" },
    { name: "trusted-multiple-hops", trusted: "127.0.0.1/32,10.0.0.0/8", headers: { "x-forwarded-for": "203.0.113.30, 10.0.0.7" }, expected: "203.0.113.30" },
  ]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), `rootark-proxy-${scenario.name}-`));
    sandboxes.push(directory);
    fs.mkdirSync(path.join(directory, "data"), { recursive: true });
    fs.writeFileSync(path.join(directory, "data", "users.local.json"), JSON.stringify([
      { username: "fixture", password: bcrypt.hashSync(crypto.randomBytes(24).toString("base64url"), 10), role: "user", permissions: {}, sessionVersion: 0 },
    ]));
    fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");
    const port = await getUnusedPort();
    const env = { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
    delete env.TRUSTED_PROXIES;
    if (scenario.trusted) env.TRUSTED_PROXIES = scenario.trusted;
    const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
    servers.push(child);
    assert.equal((await waitForServer(port, child)).status, 200, scenario.name);

    const body = JSON.stringify({ username: "missing-user", password: "disposable" });
    await request(port, "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body), ...scenario.headers },
      body,
    });

    const logs = JSON.parse(fs.readFileSync(path.join(directory, "data", "audit-logs.json"), "utf8")).logs;
    const failedLogin = logs.find((entry) => entry.eventType === "auth.login.failed");
    assert.equal(failedLogin?.actor.ip, scenario.expected, scenario.name);
  }
});

test("WebSocket origin uses the configured proxy protocol for trusted TLS termination", { timeout: 45_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-proxy-websocket-"));
  fs.mkdirSync(path.join(directory, "data"), { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(directory, "data", "users.local.json"), JSON.stringify([
    { username: "fixture", password: bcrypt.hashSync(password, 10), role: "user", permissions: {}, sessionVersion: 0 },
  ]));
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"), TRUSTED_PROXIES: "127.0.0.1/32" },
    stdio: "ignore",
    windowsHide: true,
  });
  let socket;
  t.after(async () => {
    socket?.terminate();
    if (child.exitCode === null) {
      await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
    }
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  assert.equal((await waitForServer(port, child)).status, 200);
  const body = JSON.stringify({ username: "fixture", password });
  const login = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.equal(login.status, 200, login.body);
  const cookie = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]).join("; ");
  socket = new WebSocket(`ws://127.0.0.1:${port}/ws`, {
    headers: { cookie, host: "rootark.example", "x-forwarded-proto": "https" },
    origin: "https://rootark.example",
  });
  const connected = await waitForWebSocketEvent(socket, "connected");
  assert.equal(connected.payload.username, "fixture");
});
