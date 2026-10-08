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
const { EventEmitter } = require("node:events");

const ROOT = path.resolve(__dirname, "..");
function port() { return new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const value = server.address().port; server.close(() => resolve(value)); }); }); }
function stopChild(child) { if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve(); const exited = new Promise((resolve) => child.once("exit", resolve)); child.kill(); return exited; }
function request(portNumber, requestPath, options = {}) { return new Promise((resolve, reject) => { const req = http.request({ host: "127.0.0.1", port: portNumber, path: requestPath, ...options }, (res) => { let body = ""; res.on("data", (chunk) => { body += chunk; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body })); }); req.once("error", reject); req.end(options.body); }); }
async function ready(portNumber) { for (let index = 0; index < 100; index += 1) { try { await request(portNumber, "/login.html"); return; } catch { await new Promise((resolve) => setTimeout(resolve, 50)); } } throw new Error("server did not start"); }
const websocketMessageStates = new WeakMap();
function observeWebSocketMessages(socket) {
  const state = { messages: [], waiters: [] };
  websocketMessageStates.set(socket, state);
  socket.on("message", (raw) => {
    let message;
    try { message = JSON.parse(raw); } catch { return; }
    const index = state.waiters.findIndex((waiter) => waiter.name === message.event);
    if (index < 0) {
      state.messages.push(message);
      return;
    }
    const waiter = state.waiters.splice(index, 1)[0];
    clearTimeout(waiter.timer);
    socket.off("error", waiter.onError);
    waiter.resolve(message);
  });
  return socket;
}
function event(socket, name) {
  const state = websocketMessageStates.get(socket);
  if (!state) return Promise.reject(new Error("WebSocket message observer was not installed"));
  const index = state.messages.findIndex((message) => message.event === name);
  if (index >= 0) return Promise.resolve(state.messages.splice(index, 1)[0]);
  return new Promise((resolve, reject) => {
    const waiter = { name, resolve, timer: null, onError: null };
    waiter.timer = setTimeout(() => {
      const waiterIndex = state.waiters.indexOf(waiter);
      if (waiterIndex >= 0) state.waiters.splice(waiterIndex, 1);
      socket.off("error", waiter.onError);
      reject(new Error(`missing ${name}`));
    }, 2000);
    waiter.onError = (error) => {
      const waiterIndex = state.waiters.indexOf(waiter);
      if (waiterIndex >= 0) state.waiters.splice(waiterIndex, 1);
      clearTimeout(waiter.timer);
      reject(error);
    };
    state.waiters.push(waiter);
    socket.once("error", waiter.onError);
  });
}

test("WebSocket test harness buffers a greeting received before the assertion waits", async () => {
  const socket = new EventEmitter();
  observeWebSocketMessages(socket);
  socket.emit("message", Buffer.from(JSON.stringify({ event: "connected" })));
  assert.deepEqual(await event(socket, "connected"), { event: "connected" });
});
function close(socket) { return new Promise((resolve) => socket.once("close", (code) => resolve(code))); }
function websocketUpgrade(portNumber, cookie, origin, requestHeaders = {}) {
  const socket = observeWebSocketMessages(new WebSocket(`ws://127.0.0.1:${portNumber}/ws`, { headers: { ...(cookie ? { cookie } : {}), ...requestHeaders }, origin }));
  return new Promise((resolve, reject) => {
    socket.once("open", () => resolve({ status: 101, socket }));
    socket.once("unexpected-response", (_request, response) => { response.resume(); resolve({ status: response.statusCode, socket }); });
    socket.once("error", (error) => {
      if (socket.readyState === WebSocket.CLOSED) return;
      reject(error);
    });
  });
}

test("realtime transport declares bounded payload, compression, binary, and burst handling", () => {
  const contents = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");
  assert.match(contents, /maxPayload: REALTIME_MAX_PAYLOAD_BYTES/);
  assert.match(contents, /perMessageDeflate: false/);
  assert.match(contents, /if \(isBinary\) return socket\.close\(1003/);
  assert.match(contents, /REALTIME_MAX_MESSAGES_PER_WINDOW/);
  assert.match(contents, /REALTIME_MAX_BUFFERED_BYTES/);
  assert.match(contents, /socket\.bufferedAmount > REALTIME_MAX_BUFFERED_BYTES/);
  assert.match(contents, /Limite de mensagens excedido/);
  assert.match(contents, /REALTIME_HEARTBEAT_MS/);
  assert.match(contents, /socket\.ping\(\)/);
  assert.match(contents, /socket\.terminate\(\)/);
  assert.match(contents, /server\.once\("close", \(\) => clearInterval\(realtimeHeartbeat\)\)/);
});

test("WebSocket HTTP upgrade enforces cookie, Origin, message, and binary boundaries", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-realtime-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: {}, sessionVersion: 0 }]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const body = JSON.stringify({ username: "agent", password: "password" });
  const login = await request(portNumber, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  const cookie = login.headers["set-cookie"].map((item) => item.split(";", 1)[0]).join("; ");
  const origin = `http://127.0.0.1:${portNumber}`;
  const connect = (headers = {}, requestedOrigin = origin) => observeWebSocketMessages(new WebSocket(`ws://127.0.0.1:${portNumber}/ws`, { headers, origin: requestedOrigin }));
  const allowed = connect({ cookie }); t.after(() => allowed.terminate()); await event(allowed, "connected"); allowed.send("not-json"); allowed.send(JSON.stringify({ event: "ping" })); await event(allowed, "pong");
  const missing = await websocketUpgrade(portNumber, "", origin); assert.equal(missing.status, 401);
  const malformed = await websocketUpgrade(portNumber, "rootark_session=not-a-token", origin); assert.equal(malformed.status, 401);
  const wrongOrigin = await websocketUpgrade(portNumber, cookie, "https://evil.test"); assert.equal(wrongOrigin.status, 403);
  const binary = connect({ cookie }); await event(binary, "connected"); const binaryClose = close(binary); binary.send(Buffer.from([1])); assert.equal(await binaryClose, 1003);
  const oversized = connect({ cookie }); await event(oversized, "connected"); const oversizedClose = close(oversized); oversized.send("x".repeat(17 * 1024)); assert.equal(await oversizedClose, 1009);
  const burst = connect({ cookie }); await event(burst, "connected"); const burstClose = close(burst); for (let index = 0; index < 31; index += 1) burst.send(JSON.stringify({ event: "ping" })); assert.equal(await burstClose, 1008);
});

test("WebSocket rejects unauthorized upgrades before 101 and caps concurrent peer connections", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-realtime-upgrade-guard-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: {}, sessionVersion: 0 }]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: {
    ...process.env,
    PORT: String(portNumber),
    DB_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    REALTIME_UPGRADE_MAX_PER_WINDOW: "6",
    REALTIME_MAX_CONNECTIONS_PER_PEER: "1",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
  }, stdio: "ignore", windowsHide: true });
  const sockets = [];
  t.after(async () => { for (const socket of sockets) socket.terminate(); await stopChild(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const loginBody = JSON.stringify({ username: "agent", password: "password" });
  const login = await request(portNumber, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
  const cookie = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]).join("; ");
  const origin = `http://127.0.0.1:${portNumber}`;
  const missing = await websocketUpgrade(portNumber, "", origin); sockets.push(missing.socket); assert.equal(missing.status, 401);
  const wrongOrigin = await websocketUpgrade(portNumber, cookie, "https://evil.test"); sockets.push(wrongOrigin.socket); assert.equal(wrongOrigin.status, 403);
  const active = await websocketUpgrade(portNumber, cookie, origin); sockets.push(active.socket); assert.equal(active.status, 101); await event(active.socket, "connected");
  const overCap = await websocketUpgrade(portNumber, cookie, origin); sockets.push(overCap.socket); assert.equal(overCap.status, 429);
  active.socket.close(); await new Promise((resolve) => active.socket.once("close", resolve));
  const afterRelease = await websocketUpgrade(portNumber, cookie, origin); sockets.push(afterRelease.socket); assert.equal(afterRelease.status, 101); await event(afterRelease.socket, "connected");
  const invalid = await websocketUpgrade(portNumber, "rootark_session=invalid", origin); sockets.push(invalid.socket); assert.equal(invalid.status, 401);
  const invalidAgain = await websocketUpgrade(portNumber, "rootark_session=invalid", origin); sockets.push(invalidAgain.socket); assert.equal(invalidAgain.status, 429);
});

test("WebSocket upgrade throttling uses the first untrusted client address across multiple configured proxy hops", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-realtime-upgrade-proxy-peer-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: {}, sessionVersion: 0 }]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: {
    ...process.env,
    PORT: String(portNumber),
    DB_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    REALTIME_UPGRADE_MAX_PER_WINDOW: "1",
    TRUSTED_PROXIES: "127.0.0.1,10.0.0.0/8",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
  }, stdio: "ignore", windowsHide: true });
  const sockets = [];
  t.after(async () => { for (const socket of sockets) socket.terminate(); await stopChild(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const origin = `http://127.0.0.1:${portNumber}`;
  const first = await websocketUpgrade(portNumber, "", origin, { "x-forwarded-for": "203.0.113.77, 198.51.100.10, 10.1.2.3" }); sockets.push(first.socket); assert.equal(first.status, 401);
  const second = await websocketUpgrade(portNumber, "", origin, { "x-forwarded-for": "203.0.113.77, 203.0.113.20, 10.2.3.4" }); sockets.push(second.socket); assert.equal(second.status, 401, "a different untrusted client address behind the same trusted proxy chain has a distinct budget");
  const firstAgain = await websocketUpgrade(portNumber, "", origin, { "x-forwarded-for": "192.0.2.90, 198.51.100.10, 10.1.2.3" }); sockets.push(firstAgain.socket);
  assert.equal(firstAgain.status, 429, "the client budget uses the nearest untrusted address and ignores untrusted prefixes to the left");
});

test("WebSocket upgrade throttling ignores spoofed forwarded IPs on direct origin requests", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-realtime-upgrade-direct-peer-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: {}, sessionVersion: 0 }]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: {
    ...process.env,
    PORT: String(portNumber),
    DB_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    REALTIME_UPGRADE_MAX_PER_WINDOW: "1",
    TRUSTED_PROXIES: "",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
  }, stdio: "ignore", windowsHide: true });
  const sockets = [];
  t.after(async () => { for (const socket of sockets) socket.terminate(); await stopChild(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const origin = `http://127.0.0.1:${portNumber}`;
  const first = await websocketUpgrade(portNumber, "", origin, { "x-forwarded-for": "198.51.100.10" }); sockets.push(first.socket); assert.equal(first.status, 401);
  const second = await websocketUpgrade(portNumber, "", origin, { "x-forwarded-for": "203.0.113.20" }); sockets.push(second.socket);
  assert.equal(second.status, 429, "untrusted forwarded headers cannot repartition the direct TCP peer budget");
});

test("WebDAV HTTP boundary rejects unauthenticated, hostile, traversing, and infinite-depth requests", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", UPLOAD_SCAN_ENABLED: "false", TOTP_POLICY: "optional", LOGIN_RATE_LIMIT_MAX: "20", LOGIN_DELAY_BASE: "0", LOGIN_BLOCK_THRESHOLD: "50", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { await stopChild(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const basic = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  assert.equal((await request(portNumber, "/dav", { method: "PROPFIND" })).status, 401);
  assert.equal((await request(portNumber, "/dav/%252e%252e/secret", { method: "PROPFIND", headers: { authorization: basic } })).status, 400);
  assert.equal((await request(portNumber, "/dav/%5Csecret", { method: "PROPFIND", headers: { authorization: basic } })).status, 400);
  assert.equal((await request(portNumber, "/dav//secret", { method: "PROPFIND", headers: { authorization: basic } })).status, 404);
  assert.equal((await request(portNumber, "/dav/../secret", { method: "PROPFIND", headers: { authorization: basic } })).status, 404);
  assert.equal((await request(portNumber, "/dav", { method: "PROPFIND", headers: { authorization: basic, depth: "infinity" } })).status, 400);
  assert.equal((await request(portNumber, "/dav", { method: "PROPFIND", headers: { authorization: basic, origin: "https://evil.test" } })).status, 403);
  assert.equal((await request(portNumber, "/dav", { method: "PROPFIND", headers: { authorization: basic, depth: "0" } })).status, 207);
  assert.equal((await request(portNumber, "/dav", { method: "PROPFIND", headers: { authorization: basic, depth: "1" } })).status, 207);
  assert.equal((await request(portNumber, "/dav", { method: "PROPFIND", headers: { authorization: basic, "content-type": "application/xml" }, body: "<broken" })).status, 400);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "GET", headers: { authorization: basic } })).status, 200);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "HEAD", headers: { authorization: basic } })).status, 200);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "LOCK", headers: { authorization: basic } })).status, 501);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "UNLOCK", headers: { authorization: basic } })).status, 501);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "PUT", headers: { authorization: basic, "content-length": String(9 * 1024 * 1024) }, body: Buffer.alloc(9 * 1024 * 1024) })).status, 413);
  assert.equal((await request(portNumber, "/dav/upload.bin", { method: "PUT", headers: { authorization: basic, "content-length": "3" }, body: Buffer.from([0, 1, 2]) })).status, 201);
  assert.equal((await request(portNumber, "/dav/upload.bin", { method: "PUT", headers: { "content-length": "3" }, body: "bad" })).status, 401);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "DELETE", headers: { authorization: basic } })).status, 405);
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "MOVE", headers: { authorization: basic, destination: "/dav/target.txt" } })).status, 405);
  assert.equal(fs.existsSync(path.join(dir, "temp", "source.txt")), false);
});

test("WebDAV rejects disabled accounts for Basic-auth mutations", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-disabled-user-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "disabled", password: bcrypt.hashSync("password", 10), role: "admin", disabled: true, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", TOTP_POLICY: "optional", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const basic = `Basic ${Buffer.from("disabled:password").toString("base64")}`;
  const createFolder = await request(portNumber, "/dav/should-not-exist", { method: "MKCOL", headers: { authorization: basic } });
  assert.equal(createFolder.status, 401);
  assert.equal(fs.existsSync(path.join(dir, "uploads", "should-not-exist")), false);
});

test("WebDAV Basic failures share normal login IP and username throttles", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-login-throttle-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "agent", password: bcrypt.hashSync("correct-password", 10), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: {
    ...process.env,
    PORT: String(portNumber),
    DB_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    WEBDAV_ENABLED: "true",
    TOTP_POLICY: "optional",
    TRUSTED_PROXIES: "127.0.0.1",
    LOGIN_RATE_LIMIT_MAX: "20",
    LOGIN_DELAY_BASE: "10",
    LOGIN_BLOCK_THRESHOLD: "50",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
  }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const wrong = `Basic ${Buffer.from("agent:wrong-password").toString("base64")}`;
  assert.equal((await request(portNumber, "/dav/source.txt", { headers: { authorization: wrong, "x-forwarded-for": "198.51.100.10" } })).status, 401);
  assert.equal((await request(portNumber, "/dav/source.txt", { headers: { authorization: wrong, "x-forwarded-for": "198.51.100.10" } })).status, 429);
  const loginBody = JSON.stringify({ username: "agent", password: "correct-password" });
  const login = await request(portNumber, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody), "x-forwarded-for": "198.51.100.11" }, body: loginBody });
  assert.equal(login.status, 429, "a different trusted client IP cannot bypass the shared per-username progressive delay");
  assert.ok(Number(login.headers["retry-after"]) >= 1);
});

test("successful login and WebDAV requests preserve the shared IP failure limit", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-password-spray-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "agent", password: bcrypt.hashSync("correct-password", 10), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: {
    ...process.env,
    NODE_ENV: "test",
    PORT: String(portNumber),
    DB_ENABLED: "false",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    WEBDAV_ENABLED: "true",
    UPLOAD_SCAN_ENABLED: "false",
    TOTP_POLICY: "optional",
    LOGIN_RATE_LIMIT_MAX: "5",
    LOGIN_DELAY_BASE: "0",
    LOGIN_BLOCK_THRESHOLD: "50",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
  }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);

  async function failedLogin(username) {
    const body = JSON.stringify({ username, password: "wrong-password" });
    return request(portNumber, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  }
  const validBasic = `Basic ${Buffer.from("agent:correct-password").toString("base64")}`;
  const webDavSuccess = () => request(portNumber, "/dav", { method: "PROPFIND", headers: { authorization: validBasic } });
  const validLogin = () => {
    const body = JSON.stringify({ username: "agent", password: "correct-password" });
    return request(portNumber, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  };

  for (let i = 0; i < 6; i += 1) assert.equal((await webDavSuccess()).status, 207, "successful WebDAV traffic must not consume the failed-login limit");
  assert.equal((await failedLogin("spray-one")).status, 401);
  assert.equal((await failedLogin("spray-two")).status, 401);
  assert.equal((await failedLogin("spray-three")).status, 401);
  assert.equal((await webDavSuccess()).status, 207);
  assert.equal((await failedLogin("spray-four")).status, 401);
  assert.equal((await validLogin()).status, 200);
  assert.equal((await failedLogin("spray-five")).status, 401);
  assert.equal((await failedLogin("spray-six")).status, 429, "successful auth for another account must not erase the shared per-IP failure window");
});
test("WebDAV Basic auth cannot bypass a required TOTP policy", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-totp-policy-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "admin", password: bcrypt.hashSync("admin-password", 10), role: "admin", permissions: {}, sessionVersion: 0 },
    { username: "user", password: bcrypt.hashSync("user-password", 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", TOTP_POLICY: "role-required", TOTP_REQUIRED_ROLES: "admin", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const adminBasic = `Basic ${Buffer.from("admin:admin-password").toString("base64")}`;
  const userBasic = `Basic ${Buffer.from("user:user-password").toString("base64")}`;
  assert.equal((await request(portNumber, "/dav/source.txt", { headers: { authorization: adminBasic } })).status, 401);
  assert.equal((await request(portNumber, "/dav/source.txt", { headers: { authorization: userBasic } })).status, 200);
});

test("WebDAV Basic auth rejects enrolled TOTP users under optional policy", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-enrolled-totp-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "enrolled", password: bcrypt.hashSync("enrolled-password", 10), role: "user", totpEnabled: true, permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "unenrolled", password: bcrypt.hashSync("unenrolled-password", 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", TOTP_POLICY: "optional", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const enrolledBasic = `Basic ${Buffer.from("enrolled:enrolled-password").toString("base64")}`;
  const unenrolledBasic = `Basic ${Buffer.from("unenrolled:unenrolled-password").toString("base64")}`;
  assert.equal((await request(portNumber, "/dav/source.txt", { headers: { authorization: enrolledBasic } })).status, 401);
  assert.equal((await request(portNumber, "/dav/source.txt", { headers: { authorization: unenrolledBasic } })).status, 200);
});

test("WebDAV stops dispatch when the TOTP policy becomes invalid after startup", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-invalid-totp-policy-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const childBootstrap = [
    `require(${JSON.stringify(path.join(ROOT, "server.js"))});`,
    'process.on("message", (message) => { if (message === "invalidate-totp-policy") { process.env.TOTP_POLICY = "invalid"; process.send("policy-invalidated"); } });',
  ].join("\n");
  const child = spawn(process.execPath, ["-e", childBootstrap], {
    cwd: dir,
    env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", TOTP_POLICY: "optional", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "ignore", "pipe", "ipc"],
    windowsHide: true,
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const policyChanged = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("child did not acknowledge the policy change")), 2_000);
    child.once("message", (message) => { clearTimeout(timer); resolve(message); });
    child.send("invalidate-totp-policy");
  });
  assert.equal(await policyChanged, "policy-invalidated");

  const basic = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  const denied = await request(portNumber, "/dav/source.txt", { method: "DELETE", headers: { authorization: basic } });
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(denied.status, 503);
  assert.equal(denied.body, "Authentication policy unavailable");
  assert.equal(fs.readFileSync(path.join(dir, "uploads", "source.txt"), "utf8"), "source");
  const auditLogs = JSON.parse(fs.readFileSync(path.join(dir, "data", "audit-logs.json"), "utf8")).logs;
  assert.ok(auditLogs.some((entry) => entry.eventType === "webdav.login.failed" && entry.details?.reason === "totp_policy_unavailable"), "the policy failure is audited");
  assert.equal(auditLogs.some((entry) => entry.eventType === "webdav.delete"), false, "the rejected request does not continue into the WebDAV method handler");
  assert.doesNotMatch(stderr, /ERR_HTTP_HEADERS_SENT|Cannot set headers after they are sent/i);
});

test("WebDAV enabled MOVE preserves same-folder files and fails closed for hostile destinations", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-move-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
  fs.writeFileSync(path.join(dir, "uploads", "replace.txt"), "replacement");
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", WEBDAV_ALLOW_MOVE: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(portNumber);
  const basic = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  assert.equal((await request(portNumber, "/dav/source.txt", { method: "MOVE", headers: { authorization: basic, destination: "/dav/target.txt" } })).status, 201);
  assert.equal(fs.readFileSync(path.join(dir, "uploads", "target.txt"), "utf8"), "source");
  assert.equal((await request(portNumber, "/dav/target.txt", { method: "MOVE", headers: { authorization: basic, destination: "/dav/target.txt" } })).status, 403);
  assert.equal((await request(portNumber, "/dav/replace.txt", { method: "MOVE", headers: { authorization: basic, destination: "/dav/target.txt" } })).status, 412);
  assert.equal((await request(portNumber, "/dav/replace.txt", { method: "MOVE", headers: { authorization: basic, destination: "/dav/target.txt", overwrite: "T" } })).status, 204);
  assert.equal(fs.readFileSync(path.join(dir, "uploads", "target.txt"), "utf8"), "replacement");
  assert.equal((await request(portNumber, "/dav/target.txt", { method: "MOVE", headers: { authorization: basic, destination: "https://evil.test/dav/x" } })).status, 409);
  assert.equal((await request(portNumber, "/dav/target.txt", { method: "MOVE", headers: { authorization: basic, destination: "/dav/private/x" } })).status, 409);
});
