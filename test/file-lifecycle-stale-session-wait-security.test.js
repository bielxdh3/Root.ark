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
const SERVER = process.env.ROOTARK_TEST_SERVER || path.join(ROOT, "server.js");

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

function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("rename and move reject sessions revoked while waiting for a file lifecycle lock", { timeout: 45_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-stale-lifecycle-session-"));
  const dataDir = path.join(directory, "data");
  const uploadsDir = path.join(directory, "uploads");
  const tempDir = path.join(directory, "temp");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.mkdirSync(tempDir, { recursive: true });
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  const adminPassword = crypto.randomBytes(24).toString("base64url");
  const usersPath = path.join(dataDir, "users.local.json");
  fs.writeFileSync(usersPath, JSON.stringify([
    { username: "editor", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true, delete: true }, sessionVersion: 0 },
    { username: "owner", password: bcrypt.hashSync(adminPassword, 10), role: "admin", permissions: { upload: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    { id: "folder-a", name: "Folder A", createdBy: "editor", allowedUsers: [] },
    { id: "folder-b", name: "Folder B", createdBy: "editor", allowedUsers: [] },
    { id: "folder-c", name: "Folder C", createdBy: "editor", allowedUsers: [] },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    "root/rename-source.txt": { public: false, owner: "editor", users: {} },
    "folder-a/move-source.txt": { public: false, owner: "editor", users: {} },
  }));
  fs.writeFileSync(path.join(uploadsDir, "rename-source.txt"), "rename source");
  fs.mkdirSync(path.join(uploadsDir, "folder-a"), { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, "folder-b"), { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, "folder-c"), { recursive: true });
  fs.writeFileSync(path.join(uploadsDir, "folder-a", "move-source.txt"), "move source");

  const gateConfigPath = path.join(directory, "rename-gate.json");
  const gateStartedPath = path.join(directory, "rename-gate-started");
  const gateReleasePath = path.join(directory, "rename-gate-release");
  const preloadPath = path.join(directory, "lifecycle-rename-gate.cjs");
  fs.writeFileSync(preloadPath, [
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const configPath = ${JSON.stringify(gateConfigPath)};`,
    `const startedPath = ${JSON.stringify(gateStartedPath)};`,
    `const releasePath = ${JSON.stringify(gateReleasePath)};`,
    'const originalRename = fs.promises.rename.bind(fs.promises);',
    'fs.promises.rename = async function (source, destination) {',
    '  if (fs.existsSync(configPath) && !fs.existsSync(startedPath)) {',
    '    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));',
    '    if (path.resolve(source) === path.resolve(config.source)) {',
    '      fs.writeFileSync(startedPath, "started");',
    '      while (!fs.existsSync(releasePath)) await new Promise((resolve) => setTimeout(resolve, 10));',
    '    }',
    '  }',
    '  return originalRename(source, destination);',
    '};',
  ].join("\n"));

  let markScanStarted;
  let releaseScan;
  let scanHasStarted = false;
  const scanStarted = new Promise((resolve) => { markScanStarted = resolve; });
  const scanGate = new Promise((resolve) => { releaseScan = resolve; });
  const scanner = net.createServer((socket) => {
    socket.on("data", () => {
      if (scanHasStarted) return;
      scanHasStarted = true;
      markScanStarted();
      scanGate.then(() => socket.end("stream: OK\n"));
    });
  });
  await new Promise((resolve, reject) => {
    scanner.once("error", reject);
    scanner.listen(0, "127.0.0.1", resolve);
  });
  const port = await getUnusedPort();
  const env = {
    ...process.env,
    PORT: String(port), NODE_ENV: "test", DB_ENABLED: "false", JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    TOTP_POLICY: "optional", ROUTE_RATE_LIMIT_MAX: "1000", WEBDAV_ENABLED: "true", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "clamav",
    CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.address().port), NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadPath}`].filter(Boolean).join(" "),
  };
  delete env.CLOUD_STORAGE_PROVIDER;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  t.after(async () => {
    fs.writeFileSync(gateReleasePath, "release");
    releaseScan();
    await stop(child);
    await new Promise((resolve) => scanner.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  assert.equal((await waitForServer(port, child)).status, 200);

  async function login() {
    const body = JSON.stringify({ username: "editor", password });
    const response = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
    assert.equal(response.status, 200, response.body);
    const cookies = response.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
    const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
    return { cookie: cookies.join("; "), csrf };
  }
  const mutate = (session, requestPath, bodyValue) => {
    const body = JSON.stringify(bodyValue);
    return request(port, requestPath, {
      method: "PUT",
      headers: { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };
  async function runRevokedWait(name, source, firstPath, firstBody, stalePath, staleBody, existsAfterFirst, existsAfterStale) {
    const session = await login();
    fs.rmSync(gateStartedPath, { force: true });
    fs.rmSync(gateReleasePath, { force: true });
    fs.writeFileSync(gateConfigPath, JSON.stringify({ source }));
    const first = mutate(session, firstPath, firstBody);
    const gateDeadline = Date.now() + 5000;
    while (!fs.existsSync(gateStartedPath) && Date.now() < gateDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(fs.existsSync(gateStartedPath), true, `${name} reaches the deterministic in-lock rename boundary`);
    let staleSettled = false;
    const stale = mutate(session, stalePath, staleBody).then((response) => { staleSettled = true; return response; });
    await new Promise((resolve) => setTimeout(resolve, 100));
    assert.equal(staleSettled, false, `${name} waits behind the active lifecycle lock`);
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    users[0].sessionVersion += 1;
    fs.writeFileSync(usersPath, JSON.stringify(users));
    fs.writeFileSync(gateReleasePath, "release");
    const [firstResult, staleResult] = await Promise.all([first, stale]);
    assert.equal(firstResult.status, 200, firstResult.body);
    assert.equal(staleResult.status, 401, staleResult.body);
    assert.equal(fs.existsSync(existsAfterFirst), true, `${name} preserves the operation that already held the lock`);
    assert.equal(fs.existsSync(existsAfterStale), false, `${name} performs no mutation after the stale waiter acquires the lock`);
    fs.rmSync(gateConfigPath, { force: true });
  }

  await runRevokedWait("rename", path.join(uploadsDir, "rename-source.txt"), "/rename", { oldName: "rename-source.txt", newName: "rename-first.txt", folderId: "root" }, "/rename", { oldName: "rename-source.txt", newName: "rename-stale.txt", folderId: "root" }, path.join(uploadsDir, "rename-first.txt"), path.join(uploadsDir, "rename-stale.txt"));
  await runRevokedWait("move", path.join(uploadsDir, "folder-a", "move-source.txt"), "/move", { name: "move-source.txt", fromFolderId: "folder-a", toFolderId: "folder-b" }, "/move", { name: "move-source.txt", fromFolderId: "folder-a", toFolderId: "folder-c" }, path.join(uploadsDir, "folder-b", "move-source.txt"), path.join(uploadsDir, "folder-c", "move-source.txt"));

  const webDavAuth = `Basic ${Buffer.from(`editor:${password}`).toString("base64")}`;
  const webDavAdminAuth = `Basic ${Buffer.from(`owner:${adminPassword}`).toString("base64")}`;
  const webDavPut = (name, bytes) => request(port, `/dav/${name}`, {
    method: "PUT",
    headers: { authorization: webDavAuth, "content-length": Buffer.byteLength(bytes) },
    body: bytes,
  });
  const firstWebDavPut = request(port, "/dav/webdav-first.txt", {
    method: "PUT",
    headers: { authorization: webDavAdminAuth, "content-length": Buffer.byteLength("first webdav put") },
    body: "first webdav put",
  });
  await scanStarted;
  let staleWebDavSettled = false;
  const staleWebDavPut = webDavPut("webdav-stale.txt", "stale webdav put").then((response) => { staleWebDavSettled = true; return response; });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(staleWebDavSettled, false, "WebDAV PUT waits behind the active folder lifecycle lock");
  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  users[0].permissions.upload = false;
  fs.writeFileSync(usersPath, JSON.stringify(users));
  releaseScan();
  const [firstPutResult, stalePutResult] = await Promise.all([firstWebDavPut, staleWebDavPut]);
  assert.equal(firstPutResult.status, 201, firstPutResult.body);
  assert.equal(stalePutResult.status, 403, stalePutResult.body);
  const pendingUploads = JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8"));
  assert.equal(Boolean(pendingUploads["root/webdav-first.txt"]), true);
  assert.equal(Boolean(pendingUploads["root/webdav-stale.txt"]), false, "permission revoked during the wait prevents WebDAV upload registration");

  const folderLockDirectory = path.join(dataDir, ".rootark-cloud-file-locks");
  const holdFolderLock = async (folderId) => {
    const marker = path.join(directory, folderId + "-folder-lock-held");
    const release = path.join(directory, folderId + "-folder-lock-release");
    const lockScript = path.join(directory, folderId + "-hold-folder-lock.cjs");
    fs.rmSync(marker, { force: true });
    fs.rmSync(release, { force: true });
    fs.writeFileSync(lockScript, [
      'const fs = require("node:fs");',
      "const { createFileLifecycleLock } = require(" + JSON.stringify(path.join(ROOT, "services", "fileLifecycleLock.js")) + ");",
      "const lock = createFileLifecycleLock({ directory: " + JSON.stringify(folderLockDirectory) + ", timeoutMs: 10000, pollMs: 5 });",
      "lock.runFolder(" + JSON.stringify(folderId) + ", async () => { fs.writeFileSync(" + JSON.stringify(marker) + ", 'held'); while (!fs.existsSync(" + JSON.stringify(release) + ")) await new Promise((resolve) => setTimeout(resolve, 5)); }).catch((error) => { console.error(error.message); process.exitCode = 1; });",
    ].join("\n"));
    const lockHolder = spawn(process.execPath, [lockScript], { cwd: directory, env, stdio: "ignore", windowsHide: true });
    const lockDigest = crypto.createHash("sha256").update("folder:" + folderId).digest("hex");
    try {
      await waitForServerFile(marker);
      return {
        lockHolder,
        release() { fs.writeFileSync(release, "release"); },
        lockPath: path.join(folderLockDirectory, lockDigest + ".lock"),
      };
    } catch (error) {
      fs.writeFileSync(release, "release");
      await stop(lockHolder);
      throw error;
    }
  };

  async function waitForServerFile(file) {
    const deadline = Date.now() + 5000;
    while (!fs.existsSync(file) && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(fs.existsSync(file), true, "timed out waiting for " + path.basename(file));
  }

  async function loginCookie() {
    const body = JSON.stringify({ username: "editor", password });
    const response = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
    assert.equal(response.status, 200, response.body);
    const cookies = response.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
    return { cookie: cookies.join("; "), csrf: cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1] };
  }

  async function runFolderMutationWhileLocked(folderId, requestPath, { method, bodyValue }, changeState, expectedStatus, assertUnchanged) {
    const session = await loginCookie();
    const holder = await holdFolderLock(folderId);
    let settled = false;
    const body = bodyValue === undefined ? "" : JSON.stringify(bodyValue);
    const mutation = request(port, requestPath, {
      method,
      headers: {
        cookie: session.cookie,
        origin: "http://127.0.0.1:" + port,
        "x-csrf-token": session.csrf,
        ...(body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {}),
      },
      body,
    }).then((response) => { settled = true; return response; });
    try {
      await waitForServerFile(holder.lockPath);
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(settled, false, requestPath + " waits behind the folder lifecycle lock");
      changeState();
      holder.release();
      const response = await mutation;
      await stop(holder.lockHolder);
      assert.equal(response.status, expectedStatus, response.body);
      assertUnchanged();
    } finally {
      holder.release();
      await stop(holder.lockHolder);
    }
  }

  await runFolderMutationWhileLocked("folder-c", "/folders/folder-c/temporary", {
    method: "PUT",
    bodyValue: { expiresAt: new Date(Date.now() + 60_000).toISOString() },
  }, () => {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    users.find((user) => user.username === "editor").sessionVersion += 1;
    fs.writeFileSync(usersPath, JSON.stringify(users));
  }, 401, () => {
    const folders = JSON.parse(fs.readFileSync(path.join(dataDir, "folders.json"), "utf8"));
    assert.equal(folders.find((folder) => folder.id === "folder-c").expiresAt, undefined);
  });

  await runFolderMutationWhileLocked("folder-b", "/folders/folder-b", { method: "DELETE" }, () => {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    users.find((user) => user.username === "editor").permissions.delete = false;
    fs.writeFileSync(usersPath, JSON.stringify(users));
  }, 403, () => {
    const folders = JSON.parse(fs.readFileSync(path.join(dataDir, "folders.json"), "utf8"));
    assert.equal(folders.some((folder) => folder.id === "folder-b"), true);
    assert.equal(fs.existsSync(path.join(uploadsDir, "folder-b")), true);
  });
});
