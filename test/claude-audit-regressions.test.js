const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const test = require("node:test");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");

const protectedIndex = require("../public/client/rootark-protected-index");

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

function request(port, requestPath, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
    });
    req.once("error", reject);
    if (body) req.end(body);
    else req.end();
  });
}

async function waitForServer(port) {
  const deadline = Date.now() + 10_000;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await request(port, "/login.html");
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw lastError;
}

async function login(port, username, password) {
  const body = JSON.stringify({ username, password });
  const response = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.equal(response.status, 200);
  const cookies = response.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  return {
    cookie: cookies.join("; "),
    csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1],
  };
}

// Writes a sandbox with seed users, optional folders and action history, then starts server.js.
async function startServer(t, { users, folders, history }) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-regressions-"));
  fs.mkdirSync(path.join(cwd, "data"));
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify(users));
  if (folders) fs.writeFileSync(path.join(cwd, "data", "folders.json"), JSON.stringify(folders));
  if (history) fs.writeFileSync(path.join(cwd, "data", "actions-history.json"), JSON.stringify(history));
  fs.symlinkSync(PUBLIC, path.join(cwd, "public"), "junction");

  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env: { ...process.env, PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        child.once("exit", resolve);
        child.kill();
      });
    }
    fs.rmSync(cwd, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  return { port, origin: `http://127.0.0.1:${port}` };
}

function mutatingHeaders(session, origin, body) {
  const headers = { cookie: session.cookie, origin, "x-csrf-token": session.csrf };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    headers["content-length"] = Buffer.byteLength(body);
  }
  return headers;
}

function userFixtures(password) {
  const hash = bcrypt.hashSync(password, 10);
  return [
    {
      username: "admin",
      password: hash,
      role: "admin",
      permissions: {},
      sessionVersion: 0,
      totpSecret: "TOTPSECRETVALUE",
      totpPendingSecret: "TOTPPENDINGVALUE",
      totpRecoveryHashes: ["RECOVERYHASHVALUE"],
      totpLastUsedStep: 123456,
    },
    { username: "delegate", password: hash, role: "user", permissions: { manageUsers: true }, sessionVersion: 0 },
    { username: "plain", password: hash, role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ];
}

// ---------- Item 1: delegated user managers cannot touch admin accounts ----------

test("manageUsers delegate cannot create, edit or delete admin accounts", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const { port, origin } = await startServer(t, { users: userFixtures(password) });
  const delegate = await login(port, "delegate", password);

  const createBody = JSON.stringify({ username: "newadmin", password: crypto.randomBytes(24).toString("base64url"), role: "admin", permissions: {} });
  const create = await request(port, "/users", { method: "POST", headers: mutatingHeaders(delegate, origin, createBody), body: createBody });
  assert.equal(create.status, 403);

  const editBody = JSON.stringify({ password: crypto.randomBytes(24).toString("base64url") });
  const edit = await request(port, "/users/admin", { method: "PUT", headers: mutatingHeaders(delegate, origin, editBody), body: editBody });
  assert.equal(edit.status, 403);

  const remove = await request(port, "/users/admin", { method: "DELETE", headers: mutatingHeaders(delegate, origin) });
  assert.equal(remove.status, 403);
});

test("real admin can still create, edit and delete accounts including admins", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const { port, origin } = await startServer(t, { users: userFixtures(password) });
  const admin = await login(port, "admin", password);

  const createBody = JSON.stringify({ username: "newadmin", password: crypto.randomBytes(24).toString("base64url"), role: "admin", permissions: {} });
  const create = await request(port, "/users", { method: "POST", headers: mutatingHeaders(admin, origin, createBody), body: createBody });
  assert.equal(create.status, 201);

  const editBody = JSON.stringify({ password: crypto.randomBytes(24).toString("base64url") });
  const edit = await request(port, "/users/newadmin", { method: "PUT", headers: mutatingHeaders(admin, origin, editBody), body: editBody });
  assert.equal(edit.status, 200);

  const remove = await request(port, "/users/newadmin", { method: "DELETE", headers: mutatingHeaders(admin, origin) });
  assert.equal(remove.status, 200);
});

// ---------- Item 2: access listings never expose TOTP or password material ----------

test("folder access listing omits password and TOTP secret fields for eligible users", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const folders = [{ id: "f1", name: "Shared", createdBy: "admin", createdAt: new Date().toISOString(), users: {}, groupIds: [] }];
  const { port } = await startServer(t, { users: userFixtures(password), folders });
  const admin = await login(port, "admin", password);

  const response = await request(port, "/folders/f1/access", { headers: { cookie: admin.cookie } });
  assert.equal(response.status, 200);
  const payload = JSON.parse(response.body);
  assert.ok(Array.isArray(payload.eligibleUsers));
  assert.ok(payload.eligibleUsers.some((user) => user.username === "plain"));
  for (const user of payload.eligibleUsers) {
    for (const field of ["password", "totpSecret", "totpPendingSecret", "totpRecoveryHashes", "totpLastUsedStep"]) {
      assert.equal(Object.hasOwn(user, field), false, `${user.username} leaked ${field}`);
    }
  }
  assert.equal(response.body.includes("TOTPSECRETVALUE"), false);
  assert.equal(response.body.includes("RECOVERYHASHVALUE"), false);
});

// ---------- Item 3: action history is filtered for non-managers ----------

test("history hides other users' entries and folders the viewer cannot access", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const folders = [{ id: "f1", name: "Private", createdBy: "admin", createdAt: new Date().toISOString(), users: {}, groupIds: [] }];
  const history = [
    { id: "h1", actor: "admin", action: "upload", details: {}, createdAt: new Date().toISOString() },
    { id: "h2", actor: "plain", action: "upload", details: {}, createdAt: new Date().toISOString() },
    { id: "h3", actor: "admin", action: "move", details: { folderId: "f1" }, createdAt: new Date().toISOString() },
  ];
  const { port } = await startServer(t, { users: userFixtures(password), folders, history });

  const plain = await login(port, "plain", password);
  const plainView = await request(port, "/history", { headers: { cookie: plain.cookie } });
  assert.equal(plainView.status, 200);
  assert.deepEqual(JSON.parse(plainView.body).items.map((entry) => entry.id), ["h2"]);

  const admin = await login(port, "admin", password);
  const adminView = await request(port, "/history", { headers: { cookie: admin.cookie } });
  assert.equal(adminView.status, 200);
  assert.deepEqual(JSON.parse(adminView.body).items.map((entry) => entry.id).sort(), ["h1", "h2", "h3"]);
});

// ---------- Item 4: client search matches metadata values only ----------

test("client search matches metadata values, not JSON syntax or key names", async () => {
  const key = crypto.randomBytes(32);
  const entry = await protectedIndex.createEntry({
    id: "file-report",
    versionId: "version-1",
    keyEpoch: "epoch-1",
    compartmentId: "private",
    metadata: { title: "Report" },
  }, key);

  for (const term of [":", "{", "\"", "title"]) {
    assert.deepEqual((await protectedIndex.search([entry], term, key)).map((item) => item.id), [], `term ${JSON.stringify(term)} must not match`);
  }
  assert.deepEqual((await protectedIndex.search([entry], "report", key)).map((item) => item.id), ["file-report"]);
});

// Item 5 (restoreService assertSafeZipPath NUL/":" rejection) is not covered:
// assertSafeZipPath is not exported from services/restoreService.js.
