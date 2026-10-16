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

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");

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

function request(port, requestPath, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited");
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

async function waitForFile(file) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (fs.existsSync(file)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail("timed out waiting for disposable lock marker");
}

function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("move rechecks destination folder access after waiting for its lifecycle lock", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-folder-move-lock-"));
  const dataDir = path.join(directory, "data");
  const uploadsDir = path.join(directory, "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, "source"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "mover", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true, delete: true }, sessionVersion: 0 },
  ]));
  const sourceFolderId = "source";
  const hashFolderLock = (folderId) => crypto.createHash("sha256").update("folder:" + folderId).digest("hex");
  let destinationFolderId = "destination";
  while (hashFolderLock(sourceFolderId) >= hashFolderLock(destinationFolderId)) destinationFolderId += "-next";
  fs.mkdirSync(path.join(uploadsDir, destinationFolderId), { recursive: true });
  fs.writeFileSync(path.join(uploadsDir, sourceFolderId, "moving.txt"), "disposable move fixture");
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    { id: sourceFolderId, name: "Source", createdBy: "mover", allowedUsers: [], isRoot: false },
    { id: destinationFolderId, name: "Destination", createdBy: "owner", allowedUsers: ["mover"], isRoot: false },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    [sourceFolderId + "/moving.txt"]: { public: false, owner: "mover", users: {} },
  }));

  const serverPort = await getUnusedPort();
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const env = { ...process.env, PORT: String(serverPort), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: jwtSecret, TOTP_POLICY: "optional", TRASH_ENABLED: "true" };
  for (const key of Object.keys(env)) {
    if (/^(AWS_|GOOGLE_DRIVE_)/.test(key)) delete env[key];
  }
  delete env.CLOUD_STORAGE_PROVIDER;
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  let server;
  let lockHolder;
  const marker = path.join(directory, "destination-lock-held.txt");
  const release = path.join(directory, "release-destination-lock.txt");
  t.after(async () => {
    fs.writeFileSync(release, "release");
    await stop(lockHolder);
    await stop(server);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  server = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  assert.equal((await waitForServer(serverPort, server)).status, 200);
  const loginBody = JSON.stringify({ username: "mover", password });
  const login = await request(serverPort, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const moveBody = JSON.stringify({ name: "moving.txt", fromFolderId: sourceFolderId, toFolderId: destinationFolderId });

  const lockScript = path.join(directory, "hold-folder-lock.cjs");
  fs.writeFileSync(lockScript, [
    'const fs = require("node:fs");',
    "const { createFileLifecycleLock } = require(" + JSON.stringify(path.join(ROOT, "services", "fileLifecycleLock.js")) + ");",
    "const marker = " + JSON.stringify(marker) + ";",
    "const release = " + JSON.stringify(release) + ";",
    "const lock = createFileLifecycleLock({ directory: " + JSON.stringify(path.join(dataDir, ".rootark-cloud-file-locks")) + ", timeoutMs: 10000, pollMs: 5 });",
    "lock.runFolder(" + JSON.stringify(destinationFolderId) + ", async () => { fs.writeFileSync(marker, 'held'); while (!fs.existsSync(release)) await new Promise((resolve) => setTimeout(resolve, 5)); }).catch((error) => { console.error(error.message); process.exitCode = 1; });",
  ].join("\n"));
  lockHolder = spawn(process.execPath, [lockScript], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  await waitForFile(marker);

  const sourceLock = path.join(dataDir, ".rootark-cloud-file-locks", hashFolderLock(sourceFolderId) + ".lock");
  const move = request(serverPort, "/move", {
    method: "PUT",
    headers: { cookie, origin: "http://127.0.0.1:" + serverPort, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(moveBody) },
    body: moveBody,
  });
  await waitForFile(sourceLock);
  const folders = JSON.parse(fs.readFileSync(path.join(dataDir, "folders.json"), "utf8"));
  const destination = folders.find((folder) => folder.id === destinationFolderId);
  destination.allowedUsers = [];
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify(folders));
  fs.writeFileSync(release, "release");

  const response = await move;
  await stop(lockHolder);
  assert.equal(response.status, 403, response.body);
  assert.equal(fs.readFileSync(path.join(uploadsDir, sourceFolderId, "moving.txt"), "utf8"), "disposable move fixture");
  assert.equal(fs.existsSync(path.join(uploadsDir, destinationFolderId, "moving.txt")), false);
});
