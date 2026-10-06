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

function request(port, requestPath, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
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

test("resetting a file ACL preserves its owner and owner-based edit access", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-owner-acl-"));
  const dataDir = path.join(directory, "data");
  const uploadsDir = path.join(directory, "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "owner", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: "owner-space", name: "Pasta do proprietario", createdBy: "owner", allowedUsers: [], isRoot: false },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    "root/owned.txt": { folderId: "root", fileName: "owned.txt", owner: "owner", public: false, users: {} },
  }));
  fs.writeFileSync(path.join(uploadsDir, "owned.txt"), "disposable owner fixture\n");

  const port = await getUnusedPort();
  const env = { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"), CLOUD_STORAGE_PROVIDER: "local" };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const startChild = () => spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  let child = startChild();
  t.after(async () => {
    await stop(child);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  assert.equal((await waitForServer(port, child)).status, 200);

  const loginBody = JSON.stringify({ username: "owner", password });
  const login = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) },
    body: loginBody,
  });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const sessionCookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const mutate = (requestPath, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method: "PUT",
      headers: {
        cookie: sessionCookie,
        origin: `http://127.0.0.1:${port}`,
        "x-csrf-token": csrf,
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
      },
      body,
    });
  };

  const initialAccess = await request(port, "/file-access?name=owned.txt&folderId=root", { headers: { cookie: sessionCookie } });
  assert.equal(initialAccess.status, 200, initialAccess.body);
  assert.equal(JSON.parse(initialAccess.body).owner, "owner");

  const reset = await mutate("/file-access", { name: "owned.txt", folderId: "root", public: true, users: {} });
  assert.equal(reset.status, 200, reset.body);
  assert.equal(JSON.parse(reset.body).owner, "owner", "resetting the ACL must not transfer ownership to the system account");
  assert.equal(JSON.parse(reset.body).inherited, true);

  const listing = await request(port, "/list?folderId=root", { headers: { cookie: sessionCookie } });
  assert.equal(listing.status, 200, listing.body);
  assert.equal(JSON.parse(listing.body).find((file) => file.name === "owned.txt").owner, "owner");

  const renameBody = JSON.stringify({ oldName: "owned.txt", newName: "owned-renamed.txt", folderId: "root" });
  const rename = await request(port, "/rename", {
    method: "PUT",
    headers: {
      cookie: sessionCookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(renameBody),
    },
    body: renameBody,
  });
  assert.equal(rename.status, 200, rename.body);

  const renamedAccess = await request(port, "/file-access?name=owned-renamed.txt&folderId=root", { headers: { cookie: sessionCookie } });
  assert.equal(renamedAccess.status, 200, renamedAccess.body);
  assert.equal(JSON.parse(renamedAccess.body).owner, "owner");
  assert.equal(JSON.parse(renamedAccess.body).inherited, true);

  const moveBody = JSON.stringify({ name: "owned-renamed.txt", fromFolderId: "root", toFolderId: "owner-space" });
  const move = await request(port, "/move", {
    method: "PUT",
    headers: {
      cookie: sessionCookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(moveBody),
    },
    body: moveBody,
  });
  assert.equal(move.status, 200, move.body);
  const movedAccess = await request(port, "/file-access?name=owned-renamed.txt&folderId=owner-space", { headers: { cookie: sessionCookie } });
  assert.equal(movedAccess.status, 200, movedAccess.body);
  assert.equal(JSON.parse(movedAccess.body).owner, "owner");
  assert.equal(JSON.parse(movedAccess.body).inherited, true);

  await stop(child);
  child = startChild();
  assert.equal((await waitForServer(port, child)).status, 200);
  const restartedLogin = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) },
    body: loginBody,
  });
  assert.equal(restartedLogin.status, 200, restartedLogin.body);
  const restartedCookie = restartedLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]).join("; ");
  const afterRestart = await request(port, "/file-access?name=owned-renamed.txt&folderId=owner-space", { headers: { cookie: restartedCookie } });
  assert.equal(afterRestart.status, 200, afterRestart.body);
  assert.equal(JSON.parse(afterRestart.body).owner, "owner");
  assert.equal(JSON.parse(afterRestart.body).inherited, true);
});

test("reset file ACL owner survives SQLite route persistence and a cross-folder move", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-file-owner-sqlite-"));
  const dataDir = path.join(directory, "data");
  const uploadsDir = path.join(directory, "uploads");
  const databasePath = path.join(dataDir, "rootark.sqlite");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  const outsiderPassword = crypto.randomBytes(24).toString("base64url");
  const users = [
    { username: "owner", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "outsider", password: bcrypt.hashSync(outsiderPassword, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ];
  const folders = [
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: "owner-space", name: "Pasta do proprietario", createdBy: "owner", allowedUsers: ["outsider"], isRoot: false },
  ];
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    "root/owned.txt": { folderId: "root", fileName: "owned.txt", owner: "owner", public: false, users: {} },
  }));
  fs.writeFileSync(path.join(uploadsDir, "owned.txt"), "disposable SQLite owner fixture\n");

  const migrationsPath = path.join(ROOT, "db", "migrations");
  const usersRepositoryPath = path.join(ROOT, "repositories", "usersRepository");
  const foldersRepositoryPath = path.join(ROOT, "repositories", "foldersRepository");
  const prepareDatabase = [
    `process.chdir(${JSON.stringify(directory)});`,
    'process.env.DB_ENABLED = "true";',
    `process.env.DATABASE_URL = ${JSON.stringify(databasePath)};`,
    `require(${JSON.stringify(migrationsPath)}).runMigrations({ backup: false });`,
    `require(${JSON.stringify(usersRepositoryPath)}).saveUsers(${JSON.stringify(users)});`,
    `require(${JSON.stringify(foldersRepositoryPath)}).saveFolders(${JSON.stringify(folders)});`,
  ].join(" ");
  const prepared = spawnSync(process.execPath, ["-e", prepareDatabase], { encoding: "utf8" });
  assert.equal(prepared.status, 0, prepared.stderr);

  const port = await getUnusedPort();
  const env = {
    ...process.env,
    PORT: String(port),
    DB_ENABLED: "true",
    DATABASE_URL: databasePath,
    DB_READ_FALLBACK_JSON: "true",
    DB_WRITE_LEGACY_JSON: "false",
    NODE_ENV: "test",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    CLOUD_STORAGE_PROVIDER: "local",
  };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const startChild = () => spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  let child = startChild();
  t.after(async () => {
    await stop(child);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  assert.equal((await waitForServer(port, child)).status, 200);

  async function login(username, userPassword) {
    const body = JSON.stringify({ username, password: userPassword });
    const response = await request(port, "/auth/login", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
    assert.equal(response.status, 200, response.body);
    const cookies = response.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
    return {
      cookie: cookies.join("; "),
      csrf: cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1],
    };
  }

  const owner = await login("owner", password);
  const initial = await request(port, "/file-access?name=owned.txt&folderId=root", { headers: { cookie: owner.cookie } });
  assert.equal(initial.status, 200, initial.body);
  assert.equal(JSON.parse(initial.body).owner, "owner");

  const resetBody = JSON.stringify({ name: "owned.txt", folderId: "root", public: true, users: {} });
  const reset = await request(port, "/file-access", {
    method: "PUT",
    headers: {
      cookie: owner.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": owner.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(resetBody),
    },
    body: resetBody,
  });
  assert.equal(reset.status, 200, reset.body);
  assert.equal(JSON.parse(reset.body).owner, "owner");
  assert.equal(JSON.parse(reset.body).inherited, true);

  const moveBody = JSON.stringify({ name: "owned.txt", fromFolderId: "root", toFolderId: "owner-space" });
  const move = await request(port, "/move", {
    method: "PUT",
    headers: {
      cookie: owner.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": owner.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(moveBody),
    },
    body: moveBody,
  });
  assert.equal(move.status, 200, move.body);

  const outsider = await login("outsider", outsiderPassword);
  const inheritedListing = await request(port, "/list?folderId=owner-space", { headers: { cookie: outsider.cookie } });
  assert.equal(inheritedListing.status, 200, inheritedListing.body);
  assert.ok(JSON.parse(inheritedListing.body).some((file) => file.name === "owned.txt"));

  const deniedBody = JSON.stringify({ name: "owned.txt", folderId: "owner-space", public: true, users: {} });
  const denied = await request(port, "/file-access", {
    method: "PUT",
    headers: {
      cookie: outsider.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": outsider.csrf,
      "content-type": "application/json",
      "content-length": Buffer.byteLength(deniedBody),
    },
    body: deniedBody,
  });
  assert.equal(denied.status, 403, denied.body);

  await stop(child);
  child = startChild();
  assert.equal((await waitForServer(port, child)).status, 200);
  const restartedOwner = await login("owner", password);
  const afterRestart = await request(port, "/file-access?name=owned.txt&folderId=owner-space", { headers: { cookie: restartedOwner.cookie } });
  assert.equal(afterRestart.status, 200, afterRestart.body);
  assert.equal(JSON.parse(afterRestart.body).owner, "owner");
  assert.equal(JSON.parse(afterRestart.body).inherited, true);
});
