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

const ROOT = path.resolve(__dirname, "..");
function port() { return new Promise((resolve, reject) => { const server = net.createServer(); server.once("error", reject); server.listen(0, "127.0.0.1", () => { const value = server.address().port; server.close(() => resolve(value)); }); }); }
function request(portNumber, requestPath, options = {}) { return new Promise((resolve, reject) => { const req = http.request({ host: "127.0.0.1", port: portNumber, path: requestPath, ...options }, (res) => { let body = ""; res.on("data", (chunk) => { body += chunk; }); res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body })); }); req.once("error", reject); req.end(options.body); }); }
async function ready(portNumber) { for (let index = 0; index < 100; index += 1) { try { await request(portNumber, "/login.html"); return; } catch { await new Promise((resolve) => setTimeout(resolve, 50)); } } throw new Error("server did not start"); }
function event(socket, name) { return new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error(`missing ${name}`)), 2000); socket.on("message", (raw) => { const message = JSON.parse(raw); if (message.event === name) { clearTimeout(timer); resolve(message); } }); socket.once("error", reject); }); }
function close(socket) { return new Promise((resolve) => socket.once("close", (code) => resolve(code))); }

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
  const connect = (headers = {}, requestedOrigin = origin) => new WebSocket(`ws://127.0.0.1:${portNumber}/ws`, { headers, origin: requestedOrigin });
  const allowed = connect({ cookie }); t.after(() => allowed.terminate()); await event(allowed, "connected"); allowed.send("not-json"); allowed.send(JSON.stringify({ event: "ping" })); await event(allowed, "pong");
  const missing = connect(); assert.equal(await close(missing), 1008);
  const malformed = connect({ cookie: "rootark_session=not-a-token" }); assert.equal(await close(malformed), 1008);
  const wrongOrigin = connect({ cookie }, "https://evil.test"); assert.equal(await close(wrongOrigin), 1008);
  const binary = connect({ cookie }); await event(binary, "connected"); const binaryClose = close(binary); binary.send(Buffer.from([1])); assert.equal(await binaryClose, 1003);
  const oversized = connect({ cookie }); await event(oversized, "connected"); const oversizedClose = close(oversized); oversized.send("x".repeat(17 * 1024)); assert.equal(await oversizedClose, 1009);
  const burst = connect({ cookie }); await event(burst, "connected"); const burstClose = close(burst); for (let index = 0; index < 31; index += 1) burst.send(JSON.stringify({ event: "ping" })); assert.equal(await burstClose, 1008);
});

test("WebDAV HTTP boundary rejects unauthenticated, hostile, traversing, and infinite-depth requests", { timeout: 20_000 }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-webdav-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "uploads", "source.txt"), "source");
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const portNumber = await port();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: { ...process.env, PORT: String(portNumber), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", UPLOAD_SCAN_ENABLED: "false", TOTP_POLICY: "optional", JWT_SECRET: crypto.randomBytes(48).toString("base64url") }, stdio: "ignore", windowsHide: true });
  t.after(async () => { if (child.exitCode === null) { child.kill(); await new Promise((resolve) => child.once("exit", resolve)); } fs.rmSync(dir, { recursive: true, force: true }); });
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
