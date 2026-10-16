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
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited before becoming ready");
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("version restore keeps SQLite and filesystem committed when the legacy mirror fails", { timeout: 20_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-version-db-mirror-"));
  const dataDir = path.join(directory, "data");
  const uploadsDir = path.join(directory, "uploads");
  const databasePath = path.join(dataDir, "rootark.sqlite");
  const versionHistoryPath = path.join(dataDir, "file-versions.json");
  const failMirror = path.join(directory, "fail-version-mirror-once");
  const filename = "db-mirror-restore.txt";
  const key = `root/${filename}`;
  const password = crypto.randomBytes(24).toString("base64url");
  const history = {
    currentVersion: 3,
    versions: [
      { version: 1, storedAs: `${filename}.v1`, size: Buffer.byteLength("version one") },
      { version: 2, storedAs: `${filename}.v2`, size: Buffer.byteLength("version two") },
      { version: 3, storedAs: filename, size: Buffer.byteLength("current version") },
    ],
  };
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");
  fs.writeFileSync(path.join(uploadsDir, filename), "current version");
  fs.writeFileSync(path.join(uploadsDir, `${filename}.v1`), "version one");
  fs.writeFileSync(path.join(uploadsDir, `${filename}.v2`), "version two");
  fs.writeFileSync(versionHistoryPath, JSON.stringify({ [key]: history }));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({ [key]: { public: false, owner: "restore-admin", users: {} } }));

  const migrationsPath = path.join(ROOT, "db", "migrations");
  const usersRepositoryPath = path.join(ROOT, "repositories", "usersRepository");
  const foldersRepositoryPath = path.join(ROOT, "repositories", "foldersRepository");
  const permissionsRepositoryPath = path.join(ROOT, "repositories", "filePermissionsRepository");
  const versionsRepositoryPath = path.join(ROOT, "repositories", "fileVersionsRepository");
  const prepareDatabase = [
    `process.env.DB_ENABLED = "true"; process.env.DATABASE_URL = ${JSON.stringify(databasePath)};`,
    `require(${JSON.stringify(migrationsPath)}).runMigrations({ backup: false });`,
    `require(${JSON.stringify(usersRepositoryPath)}).saveUsers(${JSON.stringify([
      { username: "restore-admin", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true, edit: true, delete: true }, sessionVersion: 0 },
    ])});`,
    `require(${JSON.stringify(foldersRepositoryPath)}).saveFolders(${JSON.stringify([
      { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    ])});`,
    `require(${JSON.stringify(permissionsRepositoryPath)}).saveFilePermissions(${JSON.stringify({ [key]: { public: false, owner: "restore-admin", users: {} } })});`,
    `require(${JSON.stringify(versionsRepositoryPath)}).saveFileVersions(${JSON.stringify({ [key]: history })});`,
    `process.stdout.write(JSON.stringify({ databasePath: require(${JSON.stringify(path.join(ROOT, "db"))}).getDatabasePath(), entries: require(${JSON.stringify(versionsRepositoryPath)}).loadFileVersions() }));`,
  ].join(" ");
  const prepared = spawnSync(process.execPath, ["-e", prepareDatabase], { cwd: ROOT, encoding: "utf8" });
  assert.equal(prepared.status, 0, prepared.stderr);
  const preparedState = JSON.parse(prepared.stdout.trim().split(/\r?\n/).at(-1));
  assert.ok(preparedState.entries[key], `database seed missing ${key}: ${prepared.stdout}`);

  const preloadPath = path.join(directory, "version-mirror-failure-preload.cjs");
  fs.writeFileSync(preloadPath, [
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const failMirror = ${JSON.stringify(failMirror)};`,
    `const versionHistoryPath = ${JSON.stringify(versionHistoryPath)};`,
    'const originalWriteFileSync = fs.writeFileSync;',
    'fs.writeFileSync = function (file, ...args) { if (fs.existsSync(failMirror) && typeof file === "string" && path.resolve(file) === path.resolve(versionHistoryPath)) { fs.unlinkSync(failMirror); const error = new Error("injected legacy version mirror failure"); error.code = "EIO"; throw error; } return originalWriteFileSync.call(this, file, ...args); };',
  ].join("\n"));

  const port = await getUnusedPort();
  const env = {
    ...process.env,
    PORT: String(port),
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    DB_READ_FALLBACK_JSON: "true",
    DB_WRITE_LEGACY_JSON: "true",
    NODE_ENV: "test",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    TOTP_POLICY: "optional",
    CLOUD_STORAGE_PROVIDER: "local",
    NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadPath}`].filter(Boolean).join(" "),
  };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
  let childErrors = "";
  child.stderr?.on("data", (chunk) => { childErrors += chunk.toString(); });
  t.after(async () => {
    await stop(child);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  await waitForServer(port, child).catch((error) => { throw new Error(`${error.message}: ${childErrors.slice(-500)}`); });

  const loginBody = JSON.stringify({ username: "restore-admin", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];

  fs.writeFileSync(failMirror, "fail once");
  const response = await request(port, `/restore/${filename}/v/1?folderId=root`, {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": 2 },
    body: "{}",
  });
  assert.equal(response.status, 200, `${response.body}\n${childErrors}`);
  const dbRead = [
    `process.env.DB_ENABLED = "true"; process.env.DATABASE_URL = ${JSON.stringify(databasePath)};`,
    `process.stdout.write(JSON.stringify({ databasePath: require(${JSON.stringify(path.join(ROOT, "db"))}).getDatabasePath(), entries: require(${JSON.stringify(versionsRepositoryPath)}).loadFileVersions() }));`,
  ].join(" ");
  const persisted = spawnSync(process.execPath, ["-e", dbRead], { cwd: ROOT, encoding: "utf8" });
  assert.equal(persisted.status, 0, persisted.stderr);
  const persistedState = JSON.parse(persisted.stdout);
  const persistedEntries = persistedState.entries;
  assert.ok(persistedEntries[key], `missing persisted key ${key}; state: ${persisted.stdout}; expected DB ${databasePath}`);
  const persistedHistory = persistedEntries[key];
  const currentPath = path.join(uploadsDir, filename);
  assert.deepEqual({ status: response.status, currentBytes: fs.readFileSync(currentPath, "utf8"), currentVersion: persistedHistory.currentVersion }, {
    status: 200,
    currentBytes: "version one",
    currentVersion: 4,
  }, response.body);
  assert.equal(fs.existsSync(failMirror), false, "the injected legacy mirror failure was reached");
});
