const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

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
  const sandbox = createPrivateAuthorityFixture(`rootark-share-permissions-${mode}-`);
  const dataDir = path.join(sandbox, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", FILE_NAME), FILE_CONTENT);
  fs.writeFileSync(path.join(sandbox, "uploads", PNG_NAME), Buffer.from(PNG_BASE64, "base64"));

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "other", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
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
  const swapAfterOpen = extraEnv.ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN === "1";
  const swapFile = path.join(sandbox, "uploads", FILE_NAME);
  const child = spawn(process.execPath, [
    ...(swapAfterOpen ? ["--require", path.join(ROOT, "test", "support", "issue-68-share-after-open-swap.js")] : []),
    SERVER,
  ], {
    cwd: sandbox,
    env: {
      ...env,
      PORT: String(port),
      ...(swapAfterOpen ? {
        ROOTARK_TEST_SHARE_SWAP_FILE: swapFile,
        ROOTARK_TEST_SHARE_SWAP_SAVED_FILE: `${swapFile}.granted`,
        ROOTARK_TEST_SHARE_SWAP_MARKER: path.join(sandbox, "swap-after-open.marker"),
      } : {}),
    },
    stdio: "ignore",
    windowsHide: true,
  });

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
    try {
      ready = await request(port, "/login.html");
      if (ready.status === 200) break;
    } catch { /* A port probe may precede the actual child listener. */ }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(ready?.status, 200,
    `disposable server must serve its public login page (last status: ${ready?.status ?? "none"})`);

  // SQLite mode stores users in the database, so it uses the non-production bootstrap admin (NODE_ENV=test).
  const credentials = mode === "sqlite" ? { username: "admin", password: "admin123" } : { username: "tester", password };
  const body = JSON.stringify(credentials);
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const origin = `http://127.0.0.1:${port}`;

  const authed = (url, value, method = "POST") => {
    const payload = JSON.stringify(value);
    return request(port, url, {
      method,
      headers: { cookie, origin, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
      body: payload,
    });
  };
  const publicPost = (token, operationPath, viewerCookie = "") => request(port, `/share/${token}/${operationPath}`, {
    method: "POST",
    headers: viewerCookie ? { origin, cookie: viewerCookie } : { origin },
  });

  return { port, origin, authed, publicPost, legacyToken, dataDir, password };
}

function viewerCookieFrom(response) {
  return (response.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]).join("; ");
}

for (const mode of ["json", "sqlite"]) {
  test(`download checks the actual opened descriptor before stream (${mode})`, { timeout: 60_000 }, async (t) => {
    const { authed, publicPost, dataDir } = await startFixture(t, mode, {
      ROOTARK_TEST_SHARE_PAUSE_POINT: "reserve",
      ROOTARK_TEST_SHARE_PAUSE_MS: "1800",
      ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN: "1",
    });

    const created = await authed("/share/capabilities", {
      name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
      permissions: ["download"], maxDownloads: 1,
    });
    assert.equal(created.status, 201, created.body);
    const { token } = JSON.parse(created.body);
    const viewer = await publicPost(token, "view");
    assert.equal(viewer.status, 200, viewer.body);

    const pending = publicPost(token, "download", viewerCookieFrom(viewer));
    await new Promise((resolve) => setTimeout(resolve, 400));

    const originalPath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
    const grantedPath = `${originalPath}.granted`;
    fs.renameSync(originalPath, grantedPath);
    fs.writeFileSync(originalPath, "FORBIDDEN_AFTER_OPEN_BYTES\n");
    const marker = path.join(path.dirname(dataDir), "swap-after-open.marker");
    fs.writeFileSync(marker, "swap once after verified open");

    const response = await pending;
    assert.equal(fs.existsSync(marker), false, "hook must have restored the pathname after fd open");
    assert.equal(fs.readFileSync(originalPath, "utf8"), FILE_CONTENT,
      "the path is authorized again while the open descriptor remains foreign");
    assert.equal(fs.readFileSync(`${originalPath}.untrusted-opened`, "utf8"), "FORBIDDEN_AFTER_OPEN_BYTES\n",
      "the foreign file is retained only by the outgoing descriptor");
    assert.equal(response.status, 404, "never stream bytes from a descriptor outside the capability generation");
    assert.equal(response.body.includes("FORBIDDEN_AFTER_OPEN_BYTES"), false);
    const authorizedRetry = await publicPost(token, "download", viewerCookieFrom(viewer));
    assert.equal(authorizedRetry.status, 200, "rejected foreign descriptor must not spend the download quota");
    assert.equal(authorizedRetry.body, FILE_CONTENT);
  });
}

for (const mode of ["json", "sqlite"]) {
  test(`scoped capability: authorized creation, per-operation limits and durable revocation (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, port, origin, publicPost, dataDir, password } = await startFixture(t, mode);
      const input = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 1 };

      const unauthenticated = await request(port, "/share/capabilities", {
        method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(input),
      });
      assert.notEqual(unauthenticated.status, 201, "bearer possession cannot create a grant");

      for (const invalid of [
        { ...input, permissions: undefined },
        { ...input, permissions: ["upload"] },
        { ...input, maxDownloads: -1 },
        { ...input, expiresInMinutes: 0 },
        { ...input, recipient: "someone@example.test" },
      ]) {
        const denied = await authed("/share/capabilities", invalid);
        assert.equal(denied.status, 400, JSON.stringify(invalid));
      }
      const alias = await authed("/share/CaPaBiLiTiEs/", { ...input, permissions: undefined });
      assert.equal(alias.status, 400, "case-insensitive and trailing-slash routes must retain strict capability admission");

      const created = await authed("/share/capabilities", input);
      assert.equal(created.status, 201, created.body);
      const capability = JSON.parse(created.body);
      assert.equal(capability.capability, true);
      assert.deepEqual(capability.permissions, ["download"]);
      assert.equal(capability.scope?.folderId, "root");
      assert.equal(capability.scope?.fileName, FILE_NAME);
      assert.match(capability.token, /^C[a-f0-9]{47}$/);
      assert.ok(capability.url.endsWith(`/share/${capability.token}`));

      const view = await publicPost(capability.token, "view");
      assert.equal(view.status, 200, view.body);
      assert.equal("fileName" in JSON.parse(view.body), false, "download-only is metadata-blind");
      const cookie = viewerCookieFrom(view);
      const deniedPreview = await publicPost(capability.token, "preview", cookie);
      assert.equal(deniedPreview.status, 403, "download token cannot preview");
      const anotherViewer = await publicPost(capability.token, "view");
      assert.equal(anotherViewer.status, 200, anotherViewer.body);
      const results = await Promise.all([
        publicPost(capability.token, "download", cookie),
        publicPost(capability.token, "download", viewerCookieFrom(anotherViewer)),
      ]);
      assert.deepEqual(results.map((response) => response.status).sort(), [200, 410],
        "competing independent viewers must consume exactly one allowed download");
      const first = results.find((response) => response.status === 200);
      const exhausted = results.find((response) => response.status === 410);
      assert.equal(first.body, FILE_CONTENT);
      assert.equal(exhausted.body.includes(FILE_CONTENT), false);

      const unauthorizedRevoke = await request(port, `/share/capabilities/${capability.token}`, {
        method: "DELETE", headers: { origin },
      });
      assert.notEqual(unauthorizedRevoke.status, 204, "anonymous client cannot revoke");
      if (mode === "json") {
        const loginBody = JSON.stringify({ username: "other", password });
        const loginOther = await request(port, "/auth/login", { method: "POST",
          headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
        assert.equal(loginOther.status, 200, loginOther.body);
        const otherCookies = loginOther.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
        const otherCookie = otherCookies.join("; ");
        const csrf = otherCookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1];
        const wrongOwner = await request(port, `/share/capabilities/${capability.token}`, {
          method: "DELETE", headers: { origin, cookie: otherCookie, "x-csrf-token": csrf,
            "content-type": "application/json", "content-length": 2 }, body: "{}",
        });
        assert.equal(wrongOwner.status, 403, "another authenticated admin cannot revoke someone else's capability");
      }
      const revoked = await authed(`/share/capabilities/${capability.token}`, {}, "DELETE");
      assert.equal(revoked.status, 204, revoked.body);
      const afterRevoke = await publicPost(capability.token, "view");
      assert.equal(afterRevoke.status, 404, "revocation prevents future bearer sessions");
      const again = await authed(`/share/capabilities/${capability.token}`, {}, "DELETE");
      assert.equal(again.status, 404, "revocation cannot resurrect a token");
      const unknown = await authed(`/share/capabilities/${crypto.randomBytes(24).toString("hex")}`, {}, "DELETE");
      assert.equal(unknown.status, 404);

      if (mode === "sqlite") {
        const Database = require("better-sqlite3");
        const database = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
        try {
          const row = database.prepare("SELECT revoked_at FROM public_links WHERE token = ?").get(capability.token);
          assert.ok(row?.revoked_at, "revoked tombstone persists in SQLite");
        } finally { database.close(); }
      } else {
        const audit = fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8");
        assert.equal(audit.includes(capability.token), false, "audit never records the bearer secret");
        assert.equal(audit.includes(FILE_NAME), false, "capability audit omits resource filenames");
      }
    });

  test(`scoped capability cannot follow file replacement and does not alter legacy shares (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, port, dataDir, legacyToken } = await startFixture(t, mode);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"], maxDownloads: 2,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const initial = await publicPost(token, "view");
      assert.equal(initial.status, 200, initial.body);

      const filePath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
      fs.renameSync(filePath, `${filePath}.old`);
      fs.writeFileSync(filePath, "REPLACEMENT_PRIVATE_FILE\n");

      const replacedView = await publicPost(token, "view");
      assert.equal(replacedView.status, 404, "path reuse cannot broaden a file-scoped grant");
      const replacedDownload = await publicPost(token, "download", viewerCookieFrom(initial));
      assert.equal(replacedDownload.status, 404);
      assert.equal(replacedDownload.body.includes("REPLACEMENT_PRIVATE_FILE"), false);

      // A truncated/corrupt persisted metadata_json must not turn a capability
      // into a permissive legacy public link with the same bearer token.
      if (mode === "sqlite") {
        const Database = require("better-sqlite3");
        const db = new Database(path.join(dataDir, "rootark.sqlite"));
        try {
          const row = db.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(token);
          const metadata = JSON.parse(row.metadata_json);
          delete metadata.shareKind;
          delete metadata.resourceBinding;
          db.prepare("UPDATE public_links SET metadata_json = ? WHERE token = ?").run(JSON.stringify(metadata), token);
        } finally { db.close(); }
      } else {
        const linksFile = path.join(dataDir, "public-links.json");
        const links = JSON.parse(fs.readFileSync(linksFile, "utf8"));
        delete links[token].shareKind;
        delete links[token].resourceBinding;
        fs.writeFileSync(linksFile, JSON.stringify(links));
      }
      const missingBinding = await publicPost(token, "download", viewerCookieFrom(initial));
      assert.equal(missingBinding.status, 404, "missing policy marker must not downgrade an issued capability");
      assert.equal(missingBinding.body.includes("REPLACEMENT_PRIVATE_FILE"), false);
      const missingBindingPage = await request(port, `/share/${token}`);
      assert.equal(missingBindingPage.status, 404, "HTML capability entry must fail closed on missing metadata");

      const legacy = await publicPost(legacyToken, "view");
      assert.equal(legacy.status, 200, "legacy share access remains compatible after a file change");
      const forged = await publicPost(crypto.randomBytes(24).toString("hex"), "view");
      assert.equal(forged.status, 404, "a forged capability cannot access other paths");
      const originalLegacy = await request(port, "/login.html");
      assert.equal(originalLegacy.status, 200, "legacy application remains reachable");
    });
}
