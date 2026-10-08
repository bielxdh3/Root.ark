const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");
const Database = require("better-sqlite3");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const MIGRATIONS = path.join(ROOT, "db", "migrations");
const USERS_REPOSITORY = path.join(ROOT, "repositories", "usersRepository");
const FOLDERS_REPOSITORY = path.join(ROOT, "repositories", "foldersRepository");
const PENDING_REPOSITORY = path.join(ROOT, "repositories", "pendingUploadsRepository");

function unusedPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const port = probe.address().port;
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
    if (child.exitCode !== null) throw new Error("disposable server exited before listening");
    try {
      const response = await request(port, "/login.html");
      if (response.status === 200) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  throw new Error("disposable server did not listen");
}

function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

async function startHarness(t, { mirror = false } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-approval-sqlite-"));
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), process.platform === "win32" ? "junction" : "dir");

  const password = crypto.randomBytes(24).toString("base64url");
  const users = [{ username: "admin", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {}, sessionVersion: 0 }];
  const folders = [{ id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true }];
  const databasePath = path.join(dataDir, "rootark.sqlite");
  const prepareDatabase = [
    `process.chdir(${JSON.stringify(directory)});`,
    "process.env.DB_ENABLED = 'true';",
    `process.env.DATABASE_URL = ${JSON.stringify(databasePath)};`,
    `require(${JSON.stringify(MIGRATIONS)}).runMigrations({ backup: false });`,
    `require(${JSON.stringify(USERS_REPOSITORY)}).saveUsers(${JSON.stringify(users)});`,
    `require(${JSON.stringify(FOLDERS_REPOSITORY)}).saveFolders(${JSON.stringify(folders)});`,
    `require(${JSON.stringify(PENDING_REPOSITORY)}).savePendingUploads({"root/legacy-current-no-history.txt": { folderId: "root", fileName: "legacy-current-no-history.txt", uploadedBy: "admin" }, "root/new-file-mirror-failure.txt": { folderId: "root", fileName: "new-file-mirror-failure.txt", uploadedBy: "admin" }});`,
  ].join(" ");
  const prepared = spawnSync(process.execPath, ["-e", prepareDatabase], { encoding: "utf8" });
  assert.equal(prepared.status, 0, prepared.stderr);

  const existingName = "legacy-current-no-history.txt";
  const initialName = "new-file-mirror-failure.txt";
  fs.writeFileSync(path.join(directory, "uploads", existingName), "existing disposable current bytes");
  fs.writeFileSync(path.join(directory, "temp", existingName), "replacement disposable pending bytes");
  fs.writeFileSync(path.join(directory, "temp", initialName), "initial disposable pending bytes");
  const pendingPath = path.join(dataDir, "pending-uploads.json");
  fs.writeFileSync(pendingPath, JSON.stringify({
    [`root/${existingName}`]: { folderId: "root", fileName: existingName, uploadedBy: "admin" },
    [`root/${initialName}`]: { folderId: "root", fileName: initialName, uploadedBy: "admin" },
  }));
  const mirrorPath = path.join(dataDir, "file-versions.json");
  fs.writeFileSync(mirrorPath, "{}");

  const failArchive = path.join(directory, "fail-archive-once");
  const failMirror = path.join(directory, "fail-mirror-once");
  const failSnapshot = path.join(directory, "fail-snapshot-read-once");
  const preloadPath = path.join(directory, "approval-failure-preload.cjs");
  fs.writeFileSync(preloadPath, [
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const failArchive = ${JSON.stringify(failArchive)};`,
    `const failMirror = ${JSON.stringify(failMirror)};`,
    `const failSnapshot = ${JSON.stringify(failSnapshot)};`,
    `const currentPath = ${JSON.stringify(path.join(directory, "uploads", existingName))};`,
    `const mirrorPath = ${JSON.stringify(mirrorPath)};`,
    'const originalRename = fs.renameSync;',
    'fs.renameSync = function (source, destination, ...args) { if (fs.existsSync(failArchive) && path.resolve(String(source)) === path.resolve(currentPath) && String(destination).endsWith(".v1")) { fs.unlinkSync(failArchive); const error = new Error("injected archive failure"); error.code = "EIO"; throw error; } return originalRename.call(this, source, destination, ...args); };',
    'const originalWrite = fs.writeFileSync;',
    'fs.writeFileSync = function (file, ...args) { if (fs.existsSync(failMirror) && typeof file === "string" && path.resolve(file) === path.resolve(mirrorPath)) { fs.unlinkSync(failMirror); const error = new Error("injected legacy mirror failure"); error.code = "EIO"; throw error; } return originalWrite.call(this, file, ...args); };',
    'const originalRead = fs.readFileSync;',
    'fs.readFileSync = function (file, ...args) { if (fs.existsSync(failSnapshot) && typeof file === "string" && path.resolve(file) === path.resolve(mirrorPath)) { fs.unlinkSync(failSnapshot); const error = new Error("injected legacy snapshot read failure"); error.code = "EIO"; throw error; } return originalRead.call(this, file, ...args); };',
  ].join("\n"));

  const port = await unusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    windowsHide: true,
    stdio: "ignore",
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "true",
      DATABASE_URL: databasePath,
      DB_READ_FALLBACK_JSON: "false",
      DB_WRITE_LEGACY_JSON: String(mirror),
      NODE_ENV: "test",
      TOTP_POLICY: "optional",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      CLOUD_STORAGE_PROVIDER: "local",
      NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadPath}`].filter(Boolean).join(" "),
    },
  });
  t.after(async () => {
    await stop(child);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await waitForServer(port, child);

  const loginBody = JSON.stringify({ username: "admin", password });
  const login = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) },
    body: loginBody,
  });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const approve = (fileName) => request(port, `/approve/${encodeURIComponent(fileName)}?folderId=root`, {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf },
  });
  const readVersionRow = (fileName) => {
    const db = new Database(databasePath, { readonly: true });
    try { return db.prepare("SELECT versions_json FROM file_versions WHERE folder_id = ? AND file_name = ?").get("root", fileName); }
    finally { db.close(); }
  };
  const readPendingRow = (fileName) => {
    const db = new Database(databasePath, { readonly: true });
    try { return db.prepare("SELECT id FROM pending_uploads WHERE id = ?").get(`root/${fileName}`); }
    finally { db.close(); }
  };
  return { directory, dataDir, port, existingName, initialName, pendingPath, mirrorPath, failArchive, failMirror, failSnapshot, approve, readVersionRow, readPendingRow };
}

test("failed approval with an existing file but no history does not leave a committed SQLite history row", { timeout: 45_000 }, async (t) => {
  const harness = await startHarness(t);
  fs.writeFileSync(harness.failArchive, "fail once");

  const response = await harness.approve(harness.existingName);

  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(path.join(harness.directory, "uploads", harness.existingName), "utf8"), "existing disposable current bytes");
  assert.equal(fs.readFileSync(path.join(harness.directory, "temp", harness.existingName), "utf8"), "replacement disposable pending bytes");
  assert.ok(JSON.parse(fs.readFileSync(harness.pendingPath, "utf8"))[`root/${harness.existingName}`]);
  assert.equal(harness.readVersionRow(harness.existingName), undefined, "a rolled-back approval must not commit version metadata for a file that was not approved");
});

test("initial approval keeps SQLite authoritative when the legacy JSON mirror write fails", { timeout: 45_000 }, async (t) => {
  const harness = await startHarness(t, { mirror: true });

  const replacement = await harness.approve(harness.existingName);

  assert.equal(replacement.status, 200, replacement.body);
  assert.equal(fs.readFileSync(path.join(harness.directory, "uploads", harness.existingName), "utf8"), "replacement disposable pending bytes");
  assert.equal(fs.readFileSync(path.join(harness.directory, "uploads", `${harness.existingName}.v1`), "utf8"), "existing disposable current bytes");
  assert.equal(fs.existsSync(path.join(harness.directory, "temp", harness.existingName)), false);
  const replacementHistory = JSON.parse(harness.readVersionRow(harness.existingName).versions_json);
  assert.equal(replacementHistory.currentVersion, 2);
  assert.deepEqual(replacementHistory.versions.map(({ version, storedAs }) => ({ version, storedAs })), [
    { version: 1, storedAs: `${harness.existingName}.v1` },
    { version: 2, storedAs: harness.existingName },
  ]);
  assert.deepEqual(JSON.parse(fs.readFileSync(harness.mirrorPath, "utf8"))[`root/${harness.existingName}`], replacementHistory);

  fs.writeFileSync(harness.failMirror, "fail once");

  const response = await harness.approve(harness.initialName);

  assert.equal(response.status, 200, response.body);
  assert.equal(fs.readFileSync(path.join(harness.directory, "uploads", harness.initialName), "utf8"), "initial disposable pending bytes");
  assert.equal(fs.existsSync(path.join(harness.directory, "temp", harness.initialName)), false);
  assert.equal(harness.readPendingRow(harness.initialName), undefined);
  const storedHistory = JSON.parse(harness.readVersionRow(harness.initialName).versions_json);
  assert.equal(storedHistory.currentVersion, 1);
  assert.equal(storedHistory.versions.length, 1);
  assert.equal(storedHistory.versions[0].storedAs, harness.initialName);
  assert.equal(storedHistory.versions[0].uploadedBy, "admin");
  assert.equal(storedHistory.versions[0].size, Buffer.byteLength("initial disposable pending bytes"));
  assert.equal(storedHistory.versions[0].comment, "Versao inicial");
  assert.ok(Number.isFinite(Date.parse(storedHistory.versions[0].uploadedAt)));
  const mirrorAfterFailure = JSON.parse(fs.readFileSync(harness.mirrorPath, "utf8"));
  assert.equal(Object.hasOwn(mirrorAfterFailure, `root/${harness.initialName}`), false, "failed legacy mirror remains stale while SQLite stays authoritative");
  assert.equal(mirrorAfterFailure[`root/${harness.existingName}`].currentVersion, 2);
});

test("SQLite-only approval does not require reading the disabled legacy JSON snapshot", { timeout: 45_000 }, async (t) => {
  const harness = await startHarness(t);
  fs.writeFileSync(harness.failSnapshot, "fail once");

  const response = await harness.approve(harness.initialName);

  assert.equal(response.status, 200, response.body);
  assert.equal(fs.readFileSync(path.join(harness.directory, "uploads", harness.initialName), "utf8"), "initial disposable pending bytes");
  assert.equal(fs.existsSync(path.join(harness.directory, "temp", harness.initialName)), false);
  assert.equal(harness.readPendingRow(harness.initialName), undefined);
  const storedHistory = JSON.parse(harness.readVersionRow(harness.initialName).versions_json);
  assert.equal(storedHistory.currentVersion, 1);
  assert.equal(storedHistory.versions[0].storedAs, harness.initialName);
  assert.equal(fs.existsSync(harness.failSnapshot), true, "unused legacy snapshot failure remains unconsumed");
});
