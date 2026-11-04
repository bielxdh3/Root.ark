"use strict";

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
const fileName = "owner-legacy-before-cutover.txt";
const marker = "W161_DISPOSABLE_PRE_CUTOVER_OWNER_BYTES";

const request = (port, route, method = "GET", headers = {}, body) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: route, method,
    headers, signal: AbortSignal.timeout(10000) }, (res) => {
    const parts = [];
    res.on("data", (part) => parts.push(part));
    res.on("error", reject);
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
      body: Buffer.concat(parts).toString("utf8") }));
  });
  req.on("error", reject);
  req.end(body);
});

async function availablePort() {
  const socket = net.createServer();
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.listen(0, "127.0.0.1", resolve);
  });
  const port = socket.address().port;
  await new Promise((resolve) => socket.close(resolve));
  return port;
}

async function boot(directory, port, strict, preload = null) {
  const env = { ...process.env, PORT: String(port), NODE_ENV: "test", DB_ENABLED: "false",
    CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "false",
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict ? "1" : "off",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    NODE_OPTIONS: [process.env.NODE_OPTIONS, preload ? `--require=${preload}` : null]
      .filter(Boolean).join(" ") };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(root, "server.js")], {
    cwd: directory, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
  });
  let diagnostics = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (data) => { diagnostics = (diagnostics + data.toString()).slice(-1000); });
  }
  for (let attempt = 0; attempt < 200 && child.exitCode === null; attempt++) {
    try { if ((await request(port, "/login.html")).status === 200) return child; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  if (child.exitCode === null) child.kill();
  throw new Error("disposable server did not start: " + diagnostics);
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
}

test("strict restart refuses pending plaintext approval before any legacy version promotion", {
  timeout: 90_000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w161-strict-approval-"));
  const data = path.join(dir, "data");
  const temp = path.join(dir, "temp", fileName);
  const approved = path.join(dir, "uploads", fileName);
  fs.mkdirSync(data);
  fs.mkdirSync(path.join(dir, "temp"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.symlinkSync(path.join(root, "public"), path.join(dir, "public"),
    process.platform === "win32" ? "junction" : "dir");
  const password = crypto.randomBytes(18).toString("base64url");
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify([{
    username: "alice", password: bcrypt.hashSync(password, 4), role: "admin",
    permissions: {}, sessionVersion: 0,
  }]));
  fs.writeFileSync(path.join(data, "pending-uploads.json"), JSON.stringify({
    [`root/${fileName}`]: { fileName, folderId: "root", uploadedBy: "alice" },
  }));
  fs.writeFileSync(temp, marker);
  const port = await availablePort();
  let child;
  t.after(async () => {
    await stop(child);
    fs.rmSync(dir, { force: true, recursive: true, maxRetries: 10, retryDelay: 100 });
  });

  // An existing pending plaintext file survives a normal OFF -> STRICT process restart.
  child = await boot(dir, port, false);
  assert.equal(fs.readFileSync(temp, "utf8"), marker);
  assert.equal(fs.existsSync(approved), false);
  await stop(child);
  child = await boot(dir, port, true);

  const credentials = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(credentials),
  }, credentials);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((cookie) => cookie.split(";")[0]);
  const headers = { cookie: cookies.join("; "),
    "x-csrf-token": cookies.find((cookie) => cookie.startsWith("rootark_csrf="))?.split("=")[1],
    origin: `http://127.0.0.1:${port}` };
  const refused = await request(port, `/approve/${fileName}?folderId=root`, "POST", headers);
  assert.equal(refused.status, 503, `strict approval promoted plaintext: ${refused.body}`);
  assert.equal(refused.headers["cache-control"], "no-store");
  assert.equal(JSON.parse(refused.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  assert.equal(fs.readFileSync(temp, "utf8"), marker);
  assert.equal(fs.existsSync(approved), false);
  assert.ok(Object.hasOwn(JSON.parse(fs.readFileSync(path.join(data, "pending-uploads.json"), "utf8")),
    `root/${fileName}`), "rejected strict approval must preserve recoverable pending entry");

  await stop(child);
  child = await boot(dir, port, false);
  const again = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(credentials),
  }, credentials);
  assert.equal(again.status, 200, again.body);
  const otherCookies = again.headers["set-cookie"].map((cookie) => cookie.split(";")[0]);
  const restored = await request(port, `/approve/${fileName}?folderId=root`, "POST", {
    cookie: otherCookies.join("; "),
    "x-csrf-token": otherCookies.find((cookie) => cookie.startsWith("rootark_csrf="))?.split("=")[1],
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(restored.status, 200, `explicit OFF should preserve legacy semantics: ${restored.body}`);
  assert.equal(fs.readFileSync(approved, "utf8"), marker);
});

test("late STRICT flip while resolving pending file refuses approval at physical promotion", {
  timeout: 60_000,
}, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w161-approval-late-"));
  const data = path.join(dir, "data");
  const temp = path.join(dir, "temp", fileName);
  const approved = path.join(dir, "uploads", fileName);
  const arm = path.join(dir, "arm-flip");
  const tripped = path.join(dir, "flip-observed");
  fs.mkdirSync(data);
  fs.mkdirSync(path.join(dir, "temp"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.symlinkSync(path.join(root, "public"), path.join(dir, "public"),
    process.platform === "win32" ? "junction" : "dir");
  const password = crypto.randomBytes(18).toString("base64url");
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify([{
    username: "alice", password: bcrypt.hashSync(password, 4), role: "admin",
    permissions: {}, sessionVersion: 0,
  }]));
  fs.writeFileSync(path.join(data, "pending-uploads.json"), JSON.stringify({
    [`root/${fileName}`]: { fileName, folderId: "root", uploadedBy: "alice" },
  }));
  fs.writeFileSync(temp, marker);
  const preload = path.join(dir, "flip-after-authorized-lookup.cjs");
  fs.writeFileSync(preload, [
    '"use strict";',
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const target = ${JSON.stringify(temp)};`,
    `const arm = ${JSON.stringify(arm)};`,
    `const tripped = ${JSON.stringify(tripped)};`,
    'const original = fs.statSync;',
    'fs.statSync = function (file, ...options) {',
    '  const stat = original.call(this, file, ...options);',
    '  if (typeof file === "string" && path.resolve(file) === path.resolve(target)',
    '    && fs.existsSync(arm) && process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT === "off") {',
    '    process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";',
    '    fs.writeFileSync(tripped, "STRICT_AFTER_FIRST_ROUTE_CHECK");',
    '  }',
    '  return stat;',
    '};',
  ].join("\n"));
  const port = await availablePort();
  let child;
  t.after(async () => {
    await stop(child);
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  child = await boot(dir, port, false, preload);
  const credentials = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(credentials),
  }, credentials);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((cookie) => cookie.split(";")[0]);
  fs.writeFileSync(arm, "ready");
  const response = await request(port, `/approve/${fileName}?folderId=root`, "POST", {
    cookie: cookies.join("; "),
    "x-csrf-token": cookies.find((cookie) => cookie.startsWith("rootark_csrf="))?.split("=")[1],
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(fs.readFileSync(tripped, "utf8"), "STRICT_AFTER_FIRST_ROUTE_CHECK",
    "late mode flip must happen inside pending source lookup, after request admission");
  assert.equal(response.status, 503, `late STRICT still promoted pending plaintext: ${response.body}`);
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
  assert.equal(fs.readFileSync(temp, "utf8"), marker);
  assert.equal(fs.existsSync(approved), false);
});
