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

function freePort() {
  return new Promise((resolve, reject) => {
    const listener = net.createServer();
    listener.once("error", reject);
    listener.listen(0, "127.0.0.1", () => {
      const value = listener.address().port;
      listener.close(() => resolve(value));
    });
  });
}

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.once("error", reject);
    req.end(options.body);
  });
}

async function ready(port) {
  for (let index = 0; index < 120; index += 1) {
    try { await request(port, "/login.html"); return; } catch { await new Promise((resolve) => setTimeout(resolve, 40)); }
  }
  throw new Error("server did not start");
}

function stop(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve(child.exitCode);
    child.once("exit", (code) => resolve(code));
    child.kill();
  });
}

function createWebDavFixture(prefix) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([{ username: "agent", password: bcrypt.hashSync("password", 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 }]));
  try { fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction"); } catch {}
  return dir;
}

function serverEnv(port, extra = {}) {
  return { ...process.env, PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", WEBDAV_ENABLED: "true", UPLOAD_SCAN_ENABLED: "false", JWT_SECRET: crypto.randomBytes(48).toString("base64url"), ...extra };
}

test("PROPFIND rejects malformed and unsupported non-empty bodies while empty requests succeed", { timeout: 20_000 }, async (t) => {
  const dir = createWebDavFixture("rootark-propfind-body-");
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port), stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(port);
  const authorization = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  assert.equal((await request(port, "/dav", { method: "PROPFIND", headers: { authorization, "content-type": "application/xml" }, body: "<broken" })).status, 400);
  assert.equal((await request(port, "/dav", { method: "PROPFIND", headers: { authorization, "content-type": "application/json" }, body: "{}" })).status, 400);
  assert.equal((await request(port, "/dav", { method: "PROPFIND", headers: { authorization, depth: "0" } })).status, 207);
});

test("chunked PUT over the byte limit removes its staging artifact", { timeout: 30_000 }, async (t) => {
  const dir = createWebDavFixture("rootark-put-limit-");
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port), stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(port);
  const authorization = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  const result = await request(port, "/dav/too-large.bin", { method: "PUT", headers: { authorization }, body: Buffer.alloc(8 * 1024 * 1024 + 1) });
  assert.equal(result.status, 413);
  const incoming = path.join(dir, "temp", ".incoming");
  const leftovers = fs.existsSync(incoming) ? fs.readdirSync(incoming).filter((name) => name.endsWith(".webdav")) : [];
  assert.deepEqual(leftovers, []);
});

test("aborted PUT removes its incoming staging file", { timeout: 20_000 }, async (t) => {
  const dir = createWebDavFixture("rootark-put-abort-");
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port), stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(port);
  const authorization = `Basic ${Buffer.from("agent:password").toString("base64")}`;
  await new Promise((resolve) => {
    const req = http.request({ host: "127.0.0.1", port, path: "/dav/aborted.bin", method: "PUT", headers: { authorization, "transfer-encoding": "chunked" } });
    req.once("error", () => resolve());
    req.write(Buffer.alloc(1024));
    req.destroy();
  });
  await new Promise((resolve) => setTimeout(resolve, 250));
  const incoming = path.join(dir, "temp", ".incoming");
  const leftovers = fs.existsSync(incoming) ? fs.readdirSync(incoming).filter((name) => name.endsWith(".webdav")) : [];
  assert.deepEqual(leftovers, []);
});

test("restart recovery restores a source staged by MOVE from the durable journal", { timeout: 20_000 }, async (t) => {
  const dir = createWebDavFixture("rootark-move-recovery-");
  const id = crypto.randomUUID();
  const incoming = path.join(dir, "temp", ".incoming");
  const metadataDirectory = path.join(incoming, `rootark-webdav-move-${id}`, "metadata");
  fs.mkdirSync(metadataDirectory, { recursive: true });
  const sourcePath = path.join(dir, "uploads", "source.txt");
  const stagePath = path.join(dir, "uploads", `.rootark-move-${id}.source`);
  const destinationPath = path.join(dir, "uploads", "target.txt");
  const destinationBackupPath = path.join(dir, "uploads", `.rootark-move-${id}.destination`);
  fs.writeFileSync(stagePath, "source");
  fs.writeFileSync(destinationPath, "target");
  const metadataFiles = {};
  for (const [index, file] of ["public-links.json", "file-permissions.json", "file-expirations.json", "file-versions.json", "encrypted-files.json"].entries()) {
    metadataFiles[`./data/${file}`] = { present: false, path: path.join(metadataDirectory, `${index}-${file}.snapshot`), checksum: null };
  }
  const journalPath = path.join(incoming, `rootark-webdav-move-${id}.json`);
  fs.writeFileSync(journalPath, JSON.stringify({ version: 1, transactionId: id, phase: "source_staged", journalPath, sourcePath, destinationPath, stagePath, destinationBackupPath, destinationExisted: false, replacementInstalled: false, completedOperations: ["source.stage"], metadata: { directory: metadataDirectory, files: metadataFiles } }));
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port), stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(port);
  assert.equal(fs.readFileSync(sourcePath, "utf8"), "source");
  assert.equal(fs.readFileSync(destinationPath, "utf8"), "target");
  assert.equal(fs.existsSync(journalPath), false);
  assert.equal(fs.existsSync(stagePath), false);
});

test("metadata checksum mismatch fails closed during MOVE journal recovery", { timeout: 10_000 }, async () => {
  const dir = createWebDavFixture("rootark-move-checksum-");
  const id = crypto.randomUUID();
  const incoming = path.join(dir, "temp", ".incoming");
  const metadataDirectory = path.join(incoming, `rootark-webdav-move-${id}`, "metadata");
  fs.mkdirSync(metadataDirectory, { recursive: true });
  const snapshotPath = path.join(metadataDirectory, "0-public-links.json.snapshot");
  fs.writeFileSync(snapshotPath, "safe");
  const sourcePath = path.join(dir, "uploads", "source.txt");
  const stagePath = path.join(dir, "uploads", `.rootark-move-${id}.source`);
  fs.writeFileSync(stagePath, "source");
  const journalPath = path.join(incoming, `rootark-webdav-move-${id}.json`);
  const files = {};
  for (const [index, file] of ["public-links.json", "file-permissions.json", "file-expirations.json", "file-versions.json", "encrypted-files.json"].entries()) {
    files[`./data/${file}`] = index === 0 ? { present: true, path: snapshotPath, checksum: "00".repeat(32) } : { present: false, path: path.join(metadataDirectory, `${index}-${file}.snapshot`), checksum: null };
  }
  fs.writeFileSync(journalPath, JSON.stringify({ version: 1, transactionId: id, phase: "source_staged", journalPath, sourcePath, destinationPath: path.join(dir, "uploads", "target.txt"), stagePath, destinationBackupPath: path.join(dir, "uploads", `.rootark-move-${id}.destination`), replacementInstalled: false, metadata: { directory: metadataDirectory, files } }));
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port), stdio: "ignore", windowsHide: true });
  const code = await new Promise((resolve) => { const timer = setTimeout(() => { child.kill(); resolve(0); }, 5000); child.once("exit", (value) => { clearTimeout(timer); resolve(value); }); });
  fs.rmSync(dir, { recursive: true, force: true });
  assert.notEqual(code, 0);
});

test("configured WebSocket rate boundary is enforced at runtime", { timeout: 20_000 }, async (t) => {
  const dir = createWebDavFixture("rootark-ws-config-");
  const port = await freePort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], { cwd: dir, env: serverEnv(port, { WEBDAV_ENABLED: "false", REALTIME_MAX_MESSAGES_PER_WINDOW: "2", REALTIME_RATE_WINDOW_MS: "1000" }), stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(dir, { recursive: true, force: true }); });
  await ready(port);
  const body = JSON.stringify({ username: "agent", password: "password" });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  const cookie = login.headers["set-cookie"].map((item) => item.split(";", 1)[0]).join("; ");
  const socket = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { cookie }, origin: `http://127.0.0.1:${port}` });
  t.after(() => socket.terminate());
  await new Promise((resolve, reject) => { socket.once("open", resolve); socket.once("error", reject); });
  await new Promise((resolve) => setTimeout(resolve, 30));
  const closed = new Promise((resolve) => socket.once("close", (code) => resolve(code)));
  socket.send(JSON.stringify({ event: "ping" }));
  socket.send(JSON.stringify({ event: "ping" }));
  socket.send(JSON.stringify({ event: "ping" }));
  assert.equal(await closed, 1008);
});
