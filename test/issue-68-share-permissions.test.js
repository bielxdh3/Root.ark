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
const FILE_NAME = "permission-fixture.txt";
const FILE_CONTENT = "disposable share permission fixture\n";
const DENIED = "Operacao nao permitida por este link.";
const ALL_OPERATIONS = ["view", "preview", "download"];

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

async function startFixture(t, mode) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), `rootark-share-permissions-${mode}-`));
  const dataDir = path.join(sandbox, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", FILE_NAME), FILE_CONTENT);

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "tester", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    [`root/${FILE_NAME}`]: { public: true, owner: "tester", users: {} },
  }));

  // A legacy link created before the permissions capability existed: no permissions field at all.
  const legacyToken = crypto.randomBytes(24).toString("hex");
  const now = Date.now();
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [legacyToken]: {
      folderId: "root",
      fileName: FILE_NAME,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60 * 60 * 1000).toISOString(),
      createdBy: "tester",
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 0,
      activeViewers: {},
    },
  }));

  const dbEnv = mode === "sqlite"
    ? {
      DB_ENABLED: "true",
      DATABASE_URL: path.join(dataDir, "rootark.sqlite"),
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "false",
      DB_AUTO_BACKUP_ON_START: "false",
    }
    : { DB_ENABLED: "false" };
  const env = { ...process.env, ...dbEnv, NODE_ENV: "test", CLOUD_STORAGE_PROVIDER: "local", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  for (const key of Object.keys(env)) if (/^(AWS_|GOOGLE_DRIVE_)/.test(key)) delete env[key];
  delete env.TRUSTED_PROXIES;
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], { cwd: sandbox, env: { ...env, PORT: String(port) }, stdio: "ignore", windowsHide: true });

  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
    }
    fs.rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const deadline = Date.now() + 15_000;
  let ready = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`disposable server exited (${child.exitCode})`);
    try { ready = await request(port, "/login.html"); break; } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.equal(ready?.status, 200, "disposable server is ready");

  // SQLite mode stores users in the database, so it uses the non-production bootstrap admin (NODE_ENV=test).
  const credentials = mode === "sqlite" ? { username: "admin", password: "admin123" } : { username: "tester", password };
  const body = JSON.stringify(credentials);
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const origin = `http://127.0.0.1:${port}`;

  const authed = (url, value) => {
    const payload = JSON.stringify(value);
    return request(port, url, {
      method: "POST",
      headers: { cookie, origin, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
      body: payload,
    });
  };
  const publicPost = (token, operationPath, viewerCookie = "") => request(port, `/share/${token}/${operationPath}`, {
    method: "POST",
    headers: viewerCookie ? { origin, cookie: viewerCookie } : { origin },
  });

  return { port, origin, authed, publicPost, legacyToken };
}

function viewerCookieFrom(response) {
  return (response.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]).join("; ");
}

for (const mode of ["json", "sqlite"]) {
  test(`share link permissions are enforced per operation (${mode} storage)`, { timeout: 60_000 }, async (t) => {
    const { port, origin, authed, publicPost, legacyToken } = await startFixture(t, mode);

    await t.test("invalid permissions and expiry are rejected with 400 before any link is created", async () => {
      const base = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60 };
      const invalid = [
        { permissions: [] },
        { permissions: "view" },
        { permissions: ["admin"] },
        { permissions: ["view", "view"] },
        { permissions: ["view", 1] },
        { permissions: ["view", "download", "list"] },
      ];
      for (const extra of invalid) {
        const response = await authed("/share", { ...base, ...extra });
        assert.equal(response.status, 400, JSON.stringify(extra));
      }
      const noExpiry = await authed("/share", { name: FILE_NAME, folderId: "root", permissions: ["view"] });
      assert.equal(noExpiry.status, 400, "a share without expiry is rejected explicitly");
    });

    await t.test("default links without a permissions field keep all operations", async () => {
      const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60 });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      assert.deepEqual(JSON.parse(created.body).permissions, ALL_OPERATIONS);

      const view = await publicPost(token, "view");
      assert.equal(view.status, 200, view.body);
      const viewerCookie = viewerCookieFrom(view);
      const download = await publicPost(token, "download", viewerCookie);
      assert.equal(download.status, 200, "default link can still download");
      assert.equal(download.body, FILE_CONTENT);
      const preview = await publicPost(token, "preview", viewerCookie);
      assert.notEqual(preview.status, 403, "default link can still preview");
    });

    await t.test("legacy stored links without permissions behave as all operations", async () => {
      const view = await publicPost(legacyToken, "view");
      assert.equal(view.status, 200, view.body);
      assert.deepEqual(JSON.parse(view.body).permissions, ALL_OPERATIONS);
      const download = await publicPost(legacyToken, "download", viewerCookieFrom(view));
      assert.equal(download.status, 200, "legacy link keeps download behaviour");
      assert.equal(download.body, FILE_CONTENT);
    });

    await t.test("view-only link: view works while download, preview and file are denied", async () => {
      const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["view"] });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      assert.deepEqual(JSON.parse(created.body).permissions, ["view"]);

      const view = await publicPost(token, "view");
      assert.equal(view.status, 200, view.body);
      assert.deepEqual(JSON.parse(view.body).permissions, ["view"]);
      const viewerCookie = viewerCookieFrom(view);

      for (const operationPath of ["download", "file", "preview"]) {
        const denied = await publicPost(token, operationPath, viewerCookie);
        assert.equal(denied.status, 403, `${operationPath} must be denied`);
        assert.ok(denied.body.includes(DENIED), `${operationPath} returns the generic denial`);
        assert.equal(denied.body.includes(FILE_CONTENT), false, `${operationPath} does not leak content`);
      }
      const getPreview = await request(port, `/share/${token}/preview`, {
        headers: { origin, cookie: viewerCookie, "sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "iframe" },
      });
      assert.equal(getPreview.status, 403, "GET preview is denied for a view-only link");
      assert.ok(getPreview.body.includes(DENIED));
      assert.equal(getPreview.body.includes(FILE_CONTENT), false);
    });

    await t.test("download-only link denies view without leaking the file", async () => {
      const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"] });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const denied = await publicPost(token, "view");
      assert.equal(denied.status, 403);
      assert.ok(denied.body.includes(DENIED));
    });
  });
}
