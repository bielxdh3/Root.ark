const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const vm = require("node:vm");
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
  const pauseMarker = path.join(sandbox, "share-exchange-read-complete.marker");
  const pauseRelease = path.join(sandbox, "share-exchange-read-release.marker");
  const env = { ...process.env, ...dbEnv, ...extraEnv,
    ...(extraEnv.ROOTARK_TEST_SHARE_PAUSE_POINT === "exchange-commit"
      ? { ROOTARK_TEST_SHARE_PAUSE_MARKER: pauseMarker,
        ROOTARK_TEST_SHARE_PAUSE_RELEASE: pauseRelease } : {}),
    NODE_ENV: "test", CLOUD_STORAGE_PROVIDER: "local", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  for (const key of Object.keys(env)) if (/^(AWS_|GOOGLE_DRIVE_)/.test(key)) delete env[key];
  delete env.TRUSTED_PROXIES;
  const port = await getUnusedPort();
  const swapAfterOpen = extraEnv.ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN === "1";
  const swapFile = path.join(sandbox, "uploads", FILE_NAME);
  const foreignFdPath = `${swapFile}.foreign-descriptor`;
  if (swapAfterOpen && extraEnv.ROOTARK_TEST_SHARE_FOREIGN_FD_ONLY === "1") {
    fs.writeFileSync(foreignFdPath, "FOREIGN_DESCRIPTOR_BYTES_NOT_AUTHORIZED\n");
  }
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
        ROOTARK_TEST_SHARE_FOREIGN_FD_PATH: foreignFdPath,
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
  const exchangedCapabilities = new Map();
  const exchangeCapability = async (token) => {
    if (exchangedCapabilities.has(token)) return exchangedCapabilities.get(token);
    const body = JSON.stringify({ token });
    const response = await request(port, "/share/c/exchange", {
      method: "POST",
      headers: { origin, "content-type": "application/json",
        "content-length": Buffer.byteLength(body) }, body,
    });
    assert.equal(response.status, 200, response.body);
    const { handle } = JSON.parse(response.body);
    assert.match(handle, /^[a-f0-9]{32}$/,
      "a non-bearer public handle selects the isolated HTTP cookie session");
    const cookies = (response.headers["set-cookie"] || [])
      .filter((value) => value.startsWith("rootark_cap_")).map((value) => value.split(";", 1)[0]);
    assert.equal(cookies.length, 1, "the exchange must issue exactly one opaque HttpOnly session cookie");
    assert.equal(cookies[0].includes(token), false,
      "the original bearer secret must never appear in a cookie name or value");
    assert.ok((response.headers["set-cookie"] || []).some((value) =>
      value.includes("HttpOnly") && value.includes("SameSite=Strict")),
    "the capability session is HttpOnly and Strict SameSite");
    const session = { handle, cookie: cookies.join("; ") };
    exchangedCapabilities.set(token, session);
    return session;
  };
  const publicPost = async (token, operationPath, viewerCookie = "") => {
    const capability = /^C[a-f0-9]{47}$/.test(token)
      ? await exchangeCapability(token) : null;
    const requestPath = capability
      ? `/share/${capability.handle}/${operationPath}`
      : `/share/${token}/${operationPath}`;
    if (capability) {
      assert.equal(requestPath.includes(token), false,
        "capability bearer may never appear in the HTTP request target");
    }
    return request(port, requestPath, {
      method: "POST",
      headers: { origin, ...((capability || viewerCookie)
        ? { cookie: [capability?.cookie, viewerCookie].filter(Boolean).join("; ") } : {}) },
    });
  };

  return { port, origin, authed, publicPost, exchangeCapability, legacyToken, dataDir, password, pauseMarker, pauseRelease };
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
    assert.equal(authorizedRetry.status, 404,
      "restoring a pathname after a foreign-descriptor swap changes kernel ctime; the old capability generation stays revoked");
    // A failed opener did not consume a quota; the security failure above is
    // due to generation drift, not artificially exhausted download allowance.
    let downloads;
    if (mode === "sqlite") {
      const Database = require("better-sqlite3");
      const db = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
      try {
        const row = db.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(token);
        downloads = JSON.parse(row.metadata_json).downloads;
      } finally { db.close(); }
    } else {
      downloads = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))[token].downloads;
    }
    assert.equal(downloads || 0, 0,
      "foreign descriptor refusal must preserve download quota despite generation revocation");
  });
}

for (const mode of ["json", "sqlite"]) {
  test(`download rejects foreign descriptor even when original pathname identity is unchanged (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, dataDir } = await startFixture(t, mode, {
        ROOTARK_TEST_SHARE_PAUSE_POINT: "reserve",
        ROOTARK_TEST_SHARE_PAUSE_MS: "1800",
        ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN: "1",
        ROOTARK_TEST_SHARE_FOREIGN_FD_ONLY: "1",
      });
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 1,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const viewer = await publicPost(token, "view");
      assert.equal(viewer.status, 200, viewer.body);

      const originalPath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
      const before = fs.statSync(originalPath);
      const pending = publicPost(token, "download", viewerCookieFrom(viewer));
      await new Promise((resolve) => setTimeout(resolve, 400));
      const marker = path.join(path.dirname(dataDir), "swap-after-open.marker");
      fs.writeFileSync(marker, "substitute only the opened file descriptor");
      const refused = await pending;
      assert.equal(fs.existsSync(marker), false,
        "test must reach the actual already-verified-open handle substitution");
      const after = fs.statSync(originalPath);
      assert.equal(after.ino, before.ino, "path inode must not change during descriptor test");
      assert.equal(after.ctimeMs, before.ctimeMs,
        "path generation must remain authorized: denial must come from opened descriptor");
      assert.equal(refused.status, 404,
        "a foreign opened descriptor must be refused despite a still-authorized pathname");
      assert.equal(refused.body.includes("FOREIGN_DESCRIPTOR_BYTES_NOT_AUTHORIZED"), false);

      const retry = await publicPost(token, "download", viewerCookieFrom(viewer));
      assert.equal(retry.status, 200,
        "the prior denied foreign handle must not invalidate a real authorized download");
      assert.equal(retry.body, FILE_CONTENT,
        "genuine authorized descriptor must return the original file bytes");
    });
}

test("SQLite exchange cannot revoke a new share or lose a parallel alias after its stale read", { timeout: 60_000 }, async (t) => {
  const { authed, port, origin, dataDir, pauseMarker, pauseRelease } = await startFixture(t, "sqlite", {
    ROOTARK_TEST_SHARE_PAUSE_POINT: "exchange-commit",
  });
  const settings = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
    permissions: ["download"], maxDownloads: 3 };
  const created = await authed("/share/capabilities", settings);
  assert.equal(created.status, 201, created.body);
  const token = JSON.parse(created.body).token;
  const exchange = () => {
    const body = JSON.stringify({ token });
    return request(port, "/share/c/exchange", {
      method: "POST", headers: { origin, "content-type": "application/json",
        "content-length": Buffer.byteLength(body) }, body,
    });
  };
  // The disposable server suspends *after* its second read of the entire
  // public links map, where the pre-fix savePublicLinks() reused stale data.
  const firstPromise = exchange();
  const deadline = Date.now() + 10_000;
  while (!fs.existsSync(pauseMarker) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(fs.readFileSync(pauseMarker, "utf8"), "snapshot-read-before-admission",
    "real server reached the vulnerable post-snapshot pause before B is created");
  let independent;
  try {
    independent = await authed("/share/capabilities", settings);
    assert.equal(independent.status, 201, independent.body);
  } finally {
    // A cannot leave its precommit barrier before B's INSERT has returned.
    // No scheduler timing assumption can make the unpatched parent pass.
    fs.writeFileSync(pauseRelease, "B-insert-confirmed");
  }
  const otherToken = JSON.parse(independent.body).token;
  assert.notEqual(otherToken, token);
  const secondPromise = exchange();
  const [first, second] = await Promise.all([firstPromise, secondPromise]);
  assert.equal(first.status, 200, first.body);
  assert.equal(second.status, 200, second.body);
  const firstHandle = JSON.parse(first.body).handle;
  const secondHandle = JSON.parse(second.body).handle;
  assert.notEqual(firstHandle, secondHandle);

  const Database = require("better-sqlite3");
  const db = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
  try {
    const firstRow = db.prepare("SELECT metadata_json, revoked_at FROM public_links WHERE token = ?").get(token);
    const otherRow = db.prepare("SELECT revoked_at FROM public_links WHERE token = ?").get(otherToken);
    assert.equal(otherRow?.revoked_at, null,
      "an exchange of A may never revoke a concurrently created unrelated B");
    const sessions = JSON.parse(firstRow.metadata_json).capabilitySessions;
    assert.ok(sessions?.[firstHandle] && sessions?.[secondHandle],
      "two overlapping exchanges of A must merge both session aliases atomically");
  } finally { db.close(); }

  for (const response of [first, second]) {
    const handle = JSON.parse(response.body).handle;
    const cookie = response.headers["set-cookie"].find((item) => item.startsWith("rootark_cap_"))
      .split(";", 1)[0];
    const view = await request(port, `/share/${handle}/view`, {
      method: "POST", headers: { origin, cookie },
    });
    assert.equal(view.status, 200, "each legitimately issued session remains live");
  }
});

for (const mode of ["json", "sqlite"]) {
  test(`scoped capability: authorized creation, per-operation limits and durable revocation (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, port, origin, publicPost, exchangeCapability, dataDir, password } = await startFixture(t, mode);
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
      assert.ok(capability.url.endsWith(`/share/c#${capability.token}`),
        "secret must be a browser fragment, absent from the HTTP request target");
      const landing = await request(port, "/share/c");
      assert.equal(landing.status, 200, "fragment-only capability landing is public");
      assert.equal(landing.body.includes(capability.token), false,
        "the landing HTML must never embed a bearer secret");
      const inlineScript = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(landing.body)?.[1];
      assert.ok(inlineScript, "fragment landing must ship the browser controller");
      assert.doesNotThrow(() => new vm.Script(inlineScript),
        "nonce-protected fragment controller must parse as browser JavaScript");
      assert.match(inlineScript, /window\.history\.replaceState\(null, "", "\/share\/c"\)/,
        "landing JS must remove the bearer fragment before contacting the server");
      assert.equal(landing.headers["cache-control"], "no-store");
      assert.equal(landing.headers["referrer-policy"], "no-referrer");
      const oldCookiePage = await request(port, "/share/c", {
        headers: { cookie: `rootark_share_pwd_${capability.token}=legacyPwd; rootark_share_${capability.token}=legacyViewer` },
      });
      assert.equal(oldCookiePage.status, 200);
      for (const prefix of [`rootark_share_pwd_${capability.token}=`,
        `rootark_share_${capability.token}=`]) {
        assert.ok((oldCookiePage.headers["set-cookie"] || []).some((value) =>
          value.startsWith(prefix) && value.includes("Expires=Thu, 01 Jan 1970")),
        "one-time response must clear pre-upgrade token-bearing cookie names");
      }
      const crossOriginExchange = await request(port, "/share/c/exchange", {
        method: "POST", headers: { origin: "https://cross-origin.invalid",
          "content-type": "application/json" },
        body: JSON.stringify({ token: capability.token }),
      });
      assert.equal(crossOriginExchange.status, 403,
        "cross-origin requests cannot create bearer-derived cookie sessions");
      const oldLeakingPath = await request(port, `/share/${capability.token}`);
      assert.equal(oldLeakingPath.status, 404,
        "old capability bearer-in-path routes fail closed, not silently aliased");
      const oldLeakingView = await request(port, `/share/${capability.token}/view`, {
        method: "POST", headers: { origin },
      });
      assert.equal(oldLeakingView.status, 404,
        "client cannot bypass the opaque capability session using a URL bearer");

      const session = await exchangeCapability(capability.token);
      const unauthenticatedAlias = await request(port, `/share/${session.handle}/view`, {
        method: "POST", headers: { origin },
      });
      assert.equal(unauthenticatedAlias.status, 404,
        "public alias alone is never sufficient without the opaque cookie");
      const duplicateCookie = await request(port, `/share/${session.handle}/view`, {
        method: "POST", headers: { origin,
          cookie: `${session.cookie}; ${session.cookie}` },
      });
      assert.equal(duplicateCookie.status, 404,
        "ambiguous duplicate capability cookies must fail closed");
      const secondCreated = await authed("/share/capabilities", input);
      assert.equal(secondCreated.status, 201);
      const secondToken = JSON.parse(secondCreated.body).token;
      const secondSession = await exchangeCapability(secondToken);
      assert.notEqual(secondSession.handle, session.handle);
      const crossAliasCookie = await request(port, `/share/${session.handle}/view`, {
        method: "POST", headers: { origin, cookie: secondSession.cookie },
      });
      assert.equal(crossAliasCookie.status, 404,
        "a valid cookie for another alias cannot authorize this capability");

      const view = await publicPost(capability.token, "view");
      assert.equal(view.status, 200, view.body);
      assert.equal("fileName" in JSON.parse(view.body), false, "download-only is metadata-blind");
      assert.equal(view.headers["cache-control"], "no-store");
      assert.equal(view.body.includes(capability.token), false);
      assert.equal((view.headers["set-cookie"] || []).some((value) =>
        value.includes(capability.token)), false,
      "viewer cookies and session headers may not contain the original capability bearer");
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
      assert.equal(first.headers["cache-control"], "no-store",
        "streaming responses must override the old share cache policy");
      assert.equal((first.headers["set-cookie"] || []).some((value) =>
        value.includes(capability.token)), false,
      "download receipt cookies must not contain the original bearer");
      assert.ok((first.headers["set-cookie"] || []).some((value) =>
        value.startsWith(`rootark_share_dl_${session.handle}=`)
          && value.includes("Path=/share/c")),
      "fragment landing page /share/c must be able to read its alias-only receipt cookie");
      assert.equal(exhausted.body.includes(FILE_CONTENT), false);

      const revokeBody = JSON.stringify({ token: capability.token });
      const unauthorizedRevoke = await request(port, "/share/capabilities/revoke", {
        method: "DELETE", headers: { origin, "content-type": "application/json" }, body: revokeBody,
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
        const wrongOwner = await request(port, "/share/capabilities/revoke", {
          method: "DELETE", headers: { origin, cookie: otherCookie, "x-csrf-token": csrf,
            "content-type": "application/json", "content-length": Buffer.byteLength(revokeBody) }, body: revokeBody,
        });
        assert.equal(wrongOwner.status, 403, "another authenticated admin cannot revoke someone else's capability");
      }
      const revoked = await authed("/share/capabilities/revoke", { token: capability.token }, "DELETE");
      assert.equal(revoked.status, 204, revoked.body);
      const afterRevoke = await publicPost(capability.token, "view");
      assert.equal(afterRevoke.status, 404, "revocation prevents future bearer sessions");
      const freshRevokedExchangeBody = JSON.stringify({ token: capability.token });
      const freshRevokedExchange = await request(port, "/share/c/exchange", {
        method: "POST", headers: { origin, "content-type": "application/json",
          "content-length": Buffer.byteLength(freshRevokedExchangeBody) },
        body: freshRevokedExchangeBody,
      });
      assert.equal(freshRevokedExchange.status, 404,
        "a revoked original bearer must not create a NEW alias session (bypass memoized fixture)");
      const again = await authed("/share/capabilities/revoke", { token: capability.token }, "DELETE");
      assert.equal(again.status, 404, "revocation cannot resurrect a token");
      const unknown = await authed("/share/capabilities/revoke", {
        token: `C${crypto.randomBytes(24).toString("hex").slice(1)}`,
      }, "DELETE");
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
      const { authed, publicPost, exchangeCapability, port, origin, dataDir, legacyToken } = await startFixture(t, mode);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"], maxDownloads: 2,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const initial = await publicPost(token, "view");
      assert.equal(initial.status, 200, initial.body);
      const { handle, cookie: sessionCookie } = await exchangeCapability(token);
      const aliasOnlyQr = await request(port, `/share/${handle}/qr`, {
        headers: { cookie: sessionCookie },
      });
      assert.equal(aliasOnlyQr.status, 404,
        "a short-lived alias+cookie cannot recover the long-lived original bearer via QR");
      const qrBody = JSON.stringify({ token });
      const qrBefore = await request(port, "/share/c/qr", {
        method: "POST", headers: { origin, "content-type": "application/json",
          "content-length": Buffer.byteLength(qrBody) }, body: qrBody,
      });
      assert.equal(qrBefore.status, 200,
        "only explicit possession of the original volatile fragment can render the QR");
      assert.equal(qrBefore.headers["content-type"], "image/png");
      assert.equal(qrBefore.headers["cache-control"], "no-store");

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
      // The prior opaque session still names the invalidated capability; it
      // must not display the swapped/corrupt resource after a policy change.
      const missingBindingQr = await request(port, "/share/c/qr", {
        method: "POST", headers: { origin, "content-type": "application/json",
          "content-length": Buffer.byteLength(qrBody) }, body: qrBody,
      });
      assert.equal(missingBindingQr.status, 404,
        "an already-exchanged cookie session cannot bypass revoked file-generation binding");

      const legacy = await publicPost(legacyToken, "view");
      assert.equal(legacy.status, 200, "legacy share access remains compatible after a file change");
      const forged = await publicPost(crypto.randomBytes(24).toString("hex"), "view");
      assert.equal(forged.status, 404, "a forged capability cannot access other paths");
      const originalLegacy = await request(port, "/login.html");
      assert.equal(originalLegacy.status, 200, "legacy application remains reachable");
    });

  test(`scoped capability rejects same-inode same-size rewrite after mtime reset (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, dataDir } = await startFixture(t, mode);
      const filePath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
      const stamp = new Date(Math.floor((Date.now() - 30_000) / 1000) * 1000);
      fs.utimesSync(filePath, stamp, stamp);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 1,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const initial = await publicPost(token, "view");
      assert.equal(initial.status, 200, initial.body);
      // Bind the hostile rewrite and both stat probes to the SAME opened
      // descriptor, rather than checking a pathname and writing it later.
      const fd = fs.openSync(filePath, fs.constants.O_RDWR
        | (fs.constants.O_NOFOLLOW || 0));
      let before, after;
      const changed = "R".repeat(Buffer.byteLength(FILE_CONTENT) - 1) + "\n";
      try {
        before = fs.fstatSync(fd);
        await new Promise((resolve) => setTimeout(resolve, 40));
        assert.notEqual(changed, FILE_CONTENT);
        assert.equal(fs.writeSync(fd, changed, 0, "utf8"), Buffer.byteLength(changed));
        fs.futimesSync(fd, stamp, stamp);
        after = fs.fstatSync(fd);
      } finally { fs.closeSync(fd); }
      assert.equal(after.ino, before.ino, "negative oracle must keep the identical inode");
      assert.equal(after.size, before.size, "negative oracle must preserve file length");
      assert.equal(after.birthtimeMs, before.birthtimeMs,
        "negative oracle must preserve inode creation identity");
      assert.equal(after.mtimeMs, before.mtimeMs,
        "attacker demonstrably restored the mtime that the old binding trusted");
      assert.notEqual(after.ctimeMs, before.ctimeMs,
        "positive tamper canary: kernel-owned change time must prove the in-place rewrite");
      const denied = await publicPost(token, "download", viewerCookieFrom(initial));
      assert.equal(denied.status, 404,
        "an old capability may not serve rewritten bytes after same-inode same-size mtime forgery");
      assert.equal(denied.body.includes(changed), false);
    });

  test(`scoped capability expires an opaque session independently of the original grant (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, exchangeCapability, dataDir } = await startFixture(t, mode);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 2,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const activated = await publicPost(token, "view");
      assert.equal(activated.status, 200);
      const { handle } = await exchangeCapability(token);
      const expired = new Date(Date.now() - 60_000).toISOString();
      if (mode === "sqlite") {
        const Database = require("better-sqlite3");
        const db = new Database(path.join(dataDir, "rootark.sqlite"));
        try {
          const row = db.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(token);
          const metadata = JSON.parse(row.metadata_json);
          assert.ok(metadata.capabilitySessions?.[handle]);
          metadata.capabilitySessions[handle].expiresAt = expired;
          db.prepare("UPDATE public_links SET metadata_json = ? WHERE token = ?").run(JSON.stringify(metadata), token);
        } finally { db.close(); }
      } else {
        const file = path.join(dataDir, "public-links.json");
        const links = JSON.parse(fs.readFileSync(file, "utf8"));
        assert.ok(links[token].capabilitySessions?.[handle]);
        links[token].capabilitySessions[handle].expiresAt = expired;
        fs.writeFileSync(file, JSON.stringify(links));
      }
      const oldSession = await publicPost(token, "download", viewerCookieFrom(activated));
      assert.equal(oldSession.status, 404,
        "expired alias+cookie cannot download even if the underlying grant has an hour remaining");
      assert.equal(oldSession.body.includes(FILE_CONTENT), false);
    });
}


test("issue 68 P2 Windows: mixed-case deletion revokes the physical file capability", { timeout: 60_000 }, async (t) => {
  if (process.platform !== "win32") return t.skip("Windows case-insensitive filesystem regression");
  const { authed, port, origin, dataDir } = await startFixture(t, "sqlite");
  const actualName = "Documento.txt";
  const diskFile = path.join(path.dirname(dataDir), "uploads", actualName);
  fs.writeFileSync(diskFile, "physical case-sensitive metadata binding");
  const created = await authed("/share/capabilities", {
    name: actualName, folderId: "root", permissions: ["download"],
    expiresInMinutes: 60, maxDownloads: 3,
  });
  assert.equal(created.status, 201, created.body);
  const { token } = JSON.parse(created.body);
  assert.match(token, /^C[a-f0-9]{47}$/);
  // The live API rejects new case-aliased issuance, but older SQLite rows
  // may already contain another spelling for this same NTFS inode. Seed that
  // exact legacy DB state independently of the current server-side snapshot.
  const aliasToken = `C${"b".repeat(47)}`;
  const legacyDb = new (require("better-sqlite3"))(path.join(dataDir, "rootark.sqlite"));
  try {
    const insert = legacyDb.prepare(`INSERT INTO public_links
      (token, folder_id, file_name, created_by, created_at, expires_at,
       max_views, views, password_hash, metadata_json, permissions_json, revoked_at)
      SELECT ?, folder_id, ?, created_by, created_at, expires_at,
             max_views, views, password_hash, metadata_json, permissions_json, revoked_at
        FROM public_links WHERE token = ?`);
    assert.equal(insert.run(aliasToken, "documento.txt", token).changes, 1);
  } finally { legacyDb.close(); }
  const exchange = () => request(port, "/share/c/exchange", {
    method: "POST", headers: { origin, "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal((await exchange()).status, 200, "real SQLite bearer was active before trash");
  const sqlRow = (whichToken = token) => {
    const db = new (require("better-sqlite3"))(path.join(dataDir, "rootark.sqlite"),
      { readonly: true, fileMustExist: true });
    try {
      return db.prepare("SELECT file_name, revoked_at FROM public_links WHERE token = ?").get(whichToken);
    } finally { db.close(); }
  };
  assert.equal(sqlRow()?.file_name, actualName,
    "SQLite must have the original-cased grant before a case-aliased deletion");
  assert.equal(sqlRow()?.revoked_at, null, "the grant is initially active");
  assert.equal(sqlRow(aliasToken)?.file_name, "documento.txt");
  assert.equal(sqlRow(aliasToken)?.revoked_at, null);
  assert.equal(fs.existsSync(path.join(path.dirname(dataDir), "uploads", "documento.txt")), true,
    "Windows accepted a case-aliased physical path before trash");
  const deleted = await authed("/delete/documento.txt?folderId=root", {});
  assert.ok([200, 202].includes(deleted.status), deleted.body);
  assert.equal(fs.existsSync(diskFile), false, "actual original-cased file moved into trash");
  assert.ok(sqlRow()?.revoked_at, "SQLite must durably tombstone the exact original-cased grant");
  assert.ok(sqlRow(aliasToken)?.revoked_at,
    "SQLite must also revoke the case-alias bearer for that same Windows inode");
  assert.equal((await exchange()).status, 404,
    "post-trash exchange cannot reactivate the revoked original-cased capability");
});
