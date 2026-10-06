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
  const afterRestart = await request(port, "/file-access?name=owned-renamed.txt&folderId=root", { headers: { cookie: restartedCookie } });
  assert.equal(afterRestart.status, 200, afterRestart.body);
  assert.equal(JSON.parse(afterRestart.body).owner, "owner");
  assert.equal(JSON.parse(afterRestart.body).inherited, true);
});
