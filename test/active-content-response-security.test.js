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
let chromium;
try { ({ chromium } = require("playwright")); } catch {}
const chromiumInstalled = Boolean(chromium && fs.existsSync(chromium.executablePath()));

const ROOT = path.resolve(__dirname, "..");

function getUnusedPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      server.close(() => resolve(port));
    });
  });
}

function request(port, url, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: url, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.setTimeout(10_000, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
  });
}

async function startFixture(t, envOverrides = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-active-content-"));
  fs.mkdirSync(path.join(dir, "data"));
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.cpSync(path.join(ROOT, "public"), path.join(dir, "public"), { recursive: true });

  const files = {
    "untrusted.html": "<!doctype html><script>window.SECURITY_TEST = true</script>",
    "untrusted.svg": '<svg xmlns="http://www.w3.org/2000/svg"><script>window.SECURITY_TEST = true</script></svg>',
    "untrusted.xml": "<?xml version=\"1.0\"?><root>safe data</root>",
    "safe.png": Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLytQAAAABJRU5ErkJggg==", "base64"),
    "safe.txt": "synthetic text preview",
  };
  for (const [name, body] of Object.entries(files)) fs.writeFileSync(path.join(dir, "uploads", name), body);
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dir, "data", "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dir, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "tester", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(dir, "data", "file-permissions.json"), JSON.stringify(Object.fromEntries(
    Object.keys(files).map((name) => [`root/${name}`, { public: true, owner: "tester", users: {} }]),
  )));
  const shares = Object.fromEntries(["untrusted.html", "untrusted.svg", "safe.png"].map((name) => [
    crypto.randomBytes(24).toString("hex"),
    { folderId: "root", fileName: name, createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 600_000).toISOString(), createdBy: "tester", views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, activeViewers: {} },
  ]));
  fs.writeFileSync(path.join(dir, "data", "public-links.json"), JSON.stringify(shares));
  const port = await getUnusedPort();
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: dir,
    env: { ...process.env, NODE_ENV: "test", PORT: String(port), DB_ENABLED: "false", CLOUD_STORAGE_PROVIDER: "local", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url"), ...envOverrides },
    stdio: "ignore", windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });
  const deadline = Date.now() + 15_000;
  let loginPage;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`disposable server exited (${child.exitCode})`);
    try { loginPage = await request(port, "/login.html"); break; } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  assert.equal(loginPage?.status, 200, "disposable server is ready");
  const body = JSON.stringify({ username: "tester", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  return { port, loginPage, shares, cookie: cookies.join("; "), csrf: cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1] };
}

test("active uploaded content cannot execute as an application-origin document", { timeout: 45_000 }, async (t) => {
  const { port, loginPage, shares, cookie, csrf } = await startFixture(t);
  const origin = `http://127.0.0.1:${port}`;
  const post = (url, value) => {
    const body = JSON.stringify(value);
    return request(port, url, { method: "POST", headers: { cookie, origin, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  };

  await t.test("global CSP, framing, referrer and HTTPS-only HSTS preserve static scripts", () => {
    assert.match(loginPage.headers["content-security-policy"], /script-src 'self'/);
    assert.doesNotMatch(loginPage.headers["content-security-policy"], /script-src[^;]*'unsafe-inline'/);
    assert.match(loginPage.headers["content-security-policy"], /frame-ancestors 'self'/);
    assert.match(loginPage.headers["content-security-policy"], /media-src 'self' blob:/, "local audio/video previews support blob URLs");
    assert.equal(loginPage.headers["x-frame-options"], "SAMEORIGIN", "same-origin file previews remain frameable");
    assert.equal(loginPage.headers["referrer-policy"], "same-origin", "private share URLs must not become cross-site referrers");
    assert.equal(loginPage.headers["x-content-type-options"], "nosniff");
    assert.equal(loginPage.headers["strict-transport-security"], undefined, "HSTS never appears over HTTP");
  });

  await t.test("file open capability returns HTML/SVG/XML as attachments for 200 and 206", async () => {
    for (const name of ["untrusted.html", "untrusted.svg", "untrusted.xml"]) {
      const token = await post("/file-open-token", { name, folderId: "root" });
      assert.equal(token.status, 200, `${name}: ${token.body}`);
      const url = JSON.parse(token.body).url;
      for (const headers of [{}, { range: "bytes=0-12" }]) {
        const response = await request(port, url, { headers });
        assert.equal(response.status, headers.range ? 206 : 200, name);
        assert.match(response.headers["content-disposition"], /^attachment;/, name);
        assert.equal(response.headers["x-content-type-options"], "nosniff");
        assert.match(response.headers["content-security-policy"], /sandbox/);
      }
    }
    const safe = await post("/file-open-token", { name: "safe.txt", folderId: "root" });
    assert.equal(safe.status, 200);
    const safeResponse = await request(port, JSON.parse(safe.body).url);
    assert.match(safeResponse.headers["content-disposition"], /^inline;/, "safe text keeps inline behavior");
  });

  await t.test("authenticated preview refuses SVG but retains safe PNG inline", async () => {
    const active = await request(port, "/preview/file/public/untrusted.svg?folderId=root", { headers: { cookie } });
    assert.equal(active.status, 415, "SVG cannot load executable markup as a same-origin image preview");
    const safe = await request(port, "/preview/file/public/safe.png?folderId=root", { headers: { cookie } });
    assert.equal(safe.status, 200);
    assert.match(safe.headers["content-disposition"], /^inline;/);
  });

  await t.test("public-share file, SVG preview and range responses cannot be active documents", async () => {
    for (const [token, link] of Object.entries(shares)) {
      const sharePage = await request(port, `/share/${token}`);
      assert.equal(sharePage.status, 200);
      const nonce = sharePage.body.match(/<script nonce="([a-zA-Z0-9+/=]+)">/)?.[1];
      assert.ok(nonce, "generated share-page inline script gets a nonce");
      assert.ok(sharePage.headers["content-security-policy"].includes(`'nonce-${nonce}'`));
      const view = await request(port, `/share/${token}/view`, { method: "POST", headers: { origin } });
      assert.equal(view.status, 200, `${link.fileName}: ${view.body}`);
      const viewerCookie = view.headers["set-cookie"]?.map((v) => v.split(";", 1)[0]).join("; ") || "";
      const file = await request(port, `/share/${token}/file`, { method: "POST", headers: { cookie: viewerCookie, origin, range: "bytes=0-12" } });
      assert.equal(file.status, 206, `${link.fileName}: ${file.body}`);
      assert.match(file.headers["content-disposition"], link.fileName === "safe.png" ? /^inline;/ : /^attachment;/, link.fileName);
      if (link.fileName === "untrusted.svg") {
        const preview = await request(port, `/share/${token}/preview`, { method: "POST", headers: { cookie: viewerCookie, origin, range: "bytes=0-12" } });
        assert.notEqual(preview.headers["content-disposition"]?.split(";", 1)[0], "inline", "SVG preview cannot serve inline active content");
      }
    }
  });
});

test("HSTS is emitted only when request originated over trusted HTTPS", { timeout: 30_000 }, async (t) => {
  const { port } = await startFixture(t, { TRUSTED_PROXIES: "127.0.0.1/32" });
  const httpResponse = await request(port, "/login.html");
  assert.equal(httpResponse.headers["strict-transport-security"], undefined);
  const trustedHttps = await request(port, "/login.html", { headers: { "x-forwarded-proto": "https" } });
  assert.equal(trustedHttps.headers["strict-transport-security"], "max-age=31536000");
});

test("browser loads static login scripts and same-origin public-share image preview under CSP", { skip: !chromiumInstalled, timeout: 45_000 }, async (t) => {
  const { port, shares } = await startFixture(t);
  const token = Object.entries(shares).find(([, link]) => link.fileName === "safe.png")[0];
  const browser = await chromium.launch({ headless: true, executablePath: chromium.executablePath() });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const cspErrors = [];
  page.on("console", (message) => {
    if (/Content Security Policy|Refused to (?:execute|load|frame|connect)/i.test(message.text())) cspErrors.push(message.text());
  });
  const origin = `http://127.0.0.1:${port}`;
  assert.equal((await page.goto(`${origin}/login.html`)).status(), 200);
  await page.waitForFunction(() => Boolean(window.RootarkApi));
  assert.equal((await page.goto(`${origin}/share/${token}`)).status(), 200);
  await page.locator("#contentBox").waitFor({ state: "visible" });
  const previewResponse = page.waitForResponse((response) => response.url().endsWith(`/share/${token}/preview`) && response.request().method() === "POST", { timeout: 10_000 });
  await page.locator("#previewButton").click();
  const preview = await previewResponse;
  assert.equal(preview.status(), 200, JSON.stringify({
    failure: "in-browser iframe preview denied",
    origin: preview.request().headers()["origin"],
    fetchSite: preview.request().headers()["sec-fetch-site"],
    response: await preview.text(),
  }));
  assert.match(preview.headers()["content-disposition"], /^inline;/);
  assert.equal(await page.locator("#previewBox iframe").count(), 1);
  assert.deepEqual(cspErrors, [], "first-party login and share preview need no blocked inline script or frame");
});
