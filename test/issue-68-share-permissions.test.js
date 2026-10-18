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
const PNG_NAME = "permission-fixture.png";
const PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLytQAAAABJRU5ErkJggg==";
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

async function startFixture(t, mode, extraEnv = {}) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), `rootark-share-permissions-${mode}-`));
  const dataDir = path.join(sandbox, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", FILE_NAME), FILE_CONTENT);
  fs.writeFileSync(path.join(sandbox, "uploads", PNG_NAME), Buffer.from(PNG_BASE64, "base64"));

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "tester", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    [`root/${FILE_NAME}`]: { public: true, owner: "tester", users: {} },
    [`root/${PNG_NAME}`]: { public: true, owner: "tester", users: {} },
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
  const env = { ...process.env, ...dbEnv, ...extraEnv, NODE_ENV: "test", CLOUD_STORAGE_PROVIDER: "local", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
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

  return { port, origin, authed, publicPost, legacyToken, dataDir };
}

function viewerCookieFrom(response) {
  return (response.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]).join("; ");
}

// Changes stored permissions directly, simulating an admin edit that lands while a request is in flight.
function setLinkPermissions(mode, dataDir, token, permissions) {
  if (mode === "sqlite") {
    const Database = require("better-sqlite3");
    const db = new Database(path.join(dataDir, "rootark.sqlite"));
    try {
      db.prepare("UPDATE public_links SET permissions_json = ? WHERE token = ?").run(JSON.stringify(permissions), token);
    } finally {
      db.close();
    }
    return;
  }
  const file = path.join(dataDir, "public-links.json");
  const links = JSON.parse(fs.readFileSync(file, "utf8"));
  links[token].permissions = permissions;
  fs.writeFileSync(file, JSON.stringify(links, null, 2));
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function passwordPost(port, origin, token, password) {
  const payload = JSON.stringify({ password });
  return request(port, `/share/${token}/password`, {
    method: "POST",
    headers: { origin, "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
    body: payload,
  });
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

    await t.test("password-protected download-only link unlocks via /password, allows download and denies view", async () => {
      const sharePassword = "unlock-pass-68";
      const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"], password: sharePassword });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      assert.deepEqual(JSON.parse(created.body).permissions, ["download"]);

      const locked = await publicPost(token, "view");
      assert.equal(locked.status, 401, "password is required before any operation is revealed");
      assert.equal(locked.body.includes(DENIED), false);

      const wrong = await passwordPost(port, origin, token, "wrong-pass-68");
      assert.equal(wrong.status, 401, "wrong password on a download-only link returns 401, not 403");
      assert.equal(wrong.body.includes(DENIED), false);

      const unlock = await passwordPost(port, origin, token, sharePassword);
      assert.equal(unlock.status, 200, unlock.body);
      const unlocked = JSON.parse(unlock.body);
      assert.deepEqual(unlocked.permissions, ["download"]);
      assert.equal(unlocked.passwordAccepted, true);
      assert.equal("fileName" in unlocked, false, "minimal payload omits the file name");
      assert.equal("size" in unlocked, false, "minimal payload omits the file size");
      const sessionCookie = viewerCookieFrom(unlock);
      assert.ok(sessionCookie.length > 0, "unlock issues a share session");

      const download = await publicPost(token, "download", sessionCookie);
      assert.equal(download.status, 200, download.body);
      assert.equal(download.body, FILE_CONTENT);
      const viewAfterUnlock = await publicPost(token, "view", sessionCookie);
      assert.equal(viewAfterUnlock.status, 200, "view endpoint still establishes a session for a download-only link");
      assert.equal("fileName" in JSON.parse(viewAfterUnlock.body), false);
    });

    await t.test("download-only link with maxViews=1 works through the session flow without consuming a view", async () => {
      const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"], maxViews: 1 });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);

      const session = await publicPost(token, "view");
      assert.equal(session.status, 200, session.body);
      assert.deepEqual(JSON.parse(session.body).permissions, ["download"]);
      assert.equal("fileName" in JSON.parse(session.body), false);
      const download = await publicPost(token, "download", viewerCookieFrom(session));
      assert.equal(download.status, 200, download.body);
      assert.equal(download.body, FILE_CONTENT);

      const sessionAgain = await publicPost(token, "view");
      assert.equal(sessionAgain.status, 200, "a second session is not blocked by maxViews of a non-view link");
    });

    await t.test("preview-only link with maxDownloads=1 works through the session flow and denies download", async () => {
      const created = await authed("/share", { name: PNG_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["preview"], maxDownloads: 1 });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);

      const session = await publicPost(token, "view");
      assert.equal(session.status, 200, session.body);
      const viewerCookie = viewerCookieFrom(session);
      const preview = await publicPost(token, "preview", viewerCookie);
      assert.equal(preview.status, 200, preview.body);
      assert.equal(preview.headers["content-type"], "image/png");

      const download = await publicPost(token, "download", viewerCookie);
      assert.equal(download.status, 403, "download is denied for a preview-only link");
      assert.ok(download.body.includes(DENIED));
    });

    await t.test("download-only link without a session cookie is not usable for download", async () => {
      const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"], maxViews: 1 });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const download = await publicPost(token, "download");
      assert.notEqual(download.status, 200, "download needs a session");
      assert.equal(download.body.includes(FILE_CONTENT), false);
    });
  });
}

for (const mode of ["json", "sqlite"]) {
  test(`an in-flight download is re-authorized after the file check reloads the link (${mode} storage)`, { timeout: 60_000 }, async (t) => {
    const { authed, publicPost, dataDir } = await startFixture(t, mode, { ROOTARK_TEST_SHARE_PAUSE_POINT: "reload", ROOTARK_TEST_SHARE_PAUSE_MS: "1500" });
    const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"] });
    assert.equal(created.status, 201, created.body);
    const { token } = JSON.parse(created.body);

    const pending = publicPost(token, "download");
    await sleep(500);
    setLinkPermissions(mode, dataDir, token, ["view"]);
    const result = await pending;
    assert.equal(result.status, 403, result.body);
    assert.ok(result.body.includes(DENIED));
    assert.equal(result.body.includes(FILE_CONTENT), false, "no content is served after the permission change");
  });
}

test("an in-flight download is re-authorized inside the quota transaction (sqlite storage)", { timeout: 60_000 }, async (t) => {
  const { authed, publicPost, dataDir } = await startFixture(t, "sqlite", { ROOTARK_TEST_SHARE_PAUSE_POINT: "reserve", ROOTARK_TEST_SHARE_PAUSE_MS: "1500" });
  const created = await authed("/share", { name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"] });
  assert.equal(created.status, 201, created.body);
  const { token } = JSON.parse(created.body);

  const pending = publicPost(token, "download");
  await sleep(500);
  setLinkPermissions("sqlite", dataDir, token, ["view"]);
  const result = await pending;
  assert.equal(result.status, 403, result.body);
  assert.ok(result.body.includes(DENIED));
  assert.equal(result.body.includes(FILE_CONTENT), false);
});

test("permissions null and malformed stored values fail closed, legacy absence stays all operations", { timeout: 60_000 }, async (t) => {
  const { publicPost, dataDir, legacyToken } = await startFixture(t, "json");
  const nullToken = crypto.randomBytes(24).toString("hex");
  const badToken = crypto.randomBytes(24).toString("hex");
  const links = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"));
  const base = { folderId: "root", fileName: FILE_NAME, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3_600_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, activeViewers: {} };
  links[nullToken] = { ...base, permissions: null };
  links[badToken] = { ...base, permissions: "download" };
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify(links, null, 2));

  for (const token of [nullToken, badToken]) {
    const view = await publicPost(token, "view");
    assert.equal(view.status, 403, `${token.slice(0, 6)} with malformed permissions grants nothing`);
    assert.ok(view.body.includes(DENIED));
  }
  const legacy = await publicPost(legacyToken, "view");
  assert.equal(legacy.status, 200, "legacy link without permissions field still works");
});

for (const mode of ["json", "sqlite"]) {
  test(`explicit null permissions is rejected while an absent field stores the full explicit allowlist (${mode} storage)`, { timeout: 60_000 }, async (t) => {
    const { authed, dataDir } = await startFixture(t, mode);
    const base = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60 };

    const nullCreate = await authed("/share", { ...base, permissions: null });
    assert.equal(nullCreate.status, 400, "explicit null is invalid, not a default");
    assert.equal(nullCreate.body.includes("token"), false, "no link is created for null");

    const absent = await authed("/share", base);
    assert.equal(absent.status, 201, absent.body);
    const { token } = JSON.parse(absent.body);
    assert.deepEqual(JSON.parse(absent.body).permissions, ALL_OPERATIONS);
    if (mode === "json") {
      const stored = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))[token];
      assert.deepEqual(stored.permissions, ALL_OPERATIONS, "absent field stores an explicit full allowlist");
    }
  });
}
