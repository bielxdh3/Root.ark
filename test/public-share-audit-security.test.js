const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const vm = require("node:vm");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;

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

function request(port, requestPath, method = "GET", headers = {}, body = "", options = {}) {
  const requestHeaders = { ...headers };
  if (options.includeDefaultFetchSite !== false && method === "GET" && /^\/share\/[^/]+\/preview$/.test(requestPath) && !Object.hasOwn(requestHeaders, "sec-fetch-site") && !Object.hasOwn(requestHeaders, "origin")) {
    requestHeaders["sec-fetch-site"] = "same-origin";
  }
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers: requestHeaders }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
  });
}

function runSharePageScript(page, fetchImpl) {
  const isHtmlWhitespace = (character) => [" ", "\t", "\r", "\n", "\f"].includes(character);
  const elements = new Map();
  const createdElements = [];
  let activeElement = null;
  const createMockElement = (id, tagName = "") => {
    const classes = new Set(["passwordBox", "contentBox", "previewBox", "qrBox"].includes(id) ? ["hidden"] : []);
    return {
      id,
      tagName,
      textContent: "",
      innerHTML: "",
      value: "",
      disabled: false,
      hidden: false,
      dataset: {},
      listeners: {},
      children: [],
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        toggle(name) { if (classes.has(name)) classes.delete(name); else classes.add(name); },
        contains(name) { return classes.has(name); },
      },
      addEventListener(type, handler) { this.listeners[type] = handler; },
      focus() { activeElement = this; },
      replaceChildren(...children) { this.children = children; },
      append(...children) { this.children.push(...children); },
    };
  };
  const getElementById = (id) => {
    if (!elements.has(id)) {
      elements.set(id, createMockElement(id));
    }
    return elements.get(id);
  };
  const lowerPage = page.toLowerCase();
  let openingStart = lowerPage.indexOf("<script");
  while (openingStart >= 0) {
    const boundary = lowerPage[openingStart + 7];
    if (boundary === ">" || [" ", "\t", "\r", "\n", "\f"].includes(boundary)) break;
    openingStart = lowerPage.indexOf("<script", openingStart + 7);
  }
  const openingEnd = openingStart >= 0 ? lowerPage.indexOf(">", openingStart + 7) : -1;
  let closingStart = openingEnd >= 0 ? lowerPage.indexOf("</", openingEnd + 1) : -1;
  let closingEnd = -1;
  while (closingStart >= 0) {
    let closingNameStart = closingStart + 2;
    while (isHtmlWhitespace(lowerPage[closingNameStart])) closingNameStart += 1;
    if (lowerPage.slice(closingNameStart, closingNameStart + 6) === "script") {
      const boundary = lowerPage[closingNameStart + 6];
      if (boundary === ">" || isHtmlWhitespace(boundary)) {
        closingEnd = lowerPage.indexOf(">", closingNameStart + 6);
        if (closingEnd >= 0) break;
      }
    }
    closingStart = lowerPage.indexOf("</", closingStart + 2);
  }
  const script = openingEnd >= 0 && closingStart >= 0 && closingEnd >= 0
    ? page.slice(openingEnd + 1, closingStart).trim()
    : undefined;
  assert.ok(script, "share page has an inline client script");
  const document = {
    get activeElement() { return activeElement; },
    getElementById,
    createElement(tagName) {
      const element = createMockElement(`created-${createdElements.length}`, tagName);
      createdElements.push(element);
      return element;
    },
  };
  vm.runInNewContext(script, {
    document,
    fetch: fetchImpl,
    navigator: { clipboard: { writeText: async () => {} } },
    window: { location: { href: "https://rootark.test/share/example" } },
  });
  elements.createdElements = createdElements;
  Object.defineProperty(elements, "activeElement", { get: () => document.activeElement });
  return elements;
}

test("public-share script extraction accepts case-insensitive script tags", () => {
  const elements = runSharePageScript('<SCRIPT type="text/javascript" data-kind="inline">document.getElementById("status").textContent = "loaded";</ \t ScRiPt \t  >');
  assert.equal(elements.get("status").textContent, "loaded");
});

test("SQLite mode preserves counted access for a JSON-fallback public link", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-share-sqlite-fallback-"));
  const token = crypto.randomBytes(24).toString("hex");
  const secondToken = crypto.randomBytes(24).toString("hex");
  const previewToken = crypto.randomBytes(24).toString("hex");
  const invalidToken = "not-a-valid-share-token";
  const port = await getUnusedPort();
  const dataDir = path.join(sandbox, "data");
  const databasePath = path.join(dataDir, "rootark.sqlite");
  const fileName = "sqlite-fallback-share.txt";
  const previewFileName = "sqlite-fallback-preview.pdf";

  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.mkdirSync(dataDir, { recursive: true });
  fs.cpSync(PUBLIC, path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", fileName), "disposable SQLite fallback fixture\n");
  fs.writeFileSync(path.join(sandbox, "uploads", previewFileName), "range preview fixture\n");
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [token]: {
      folderId: "root",
      fileName,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 1,
      activeViewers: {},
    },
    [secondToken]: {
      folderId: "root",
      fileName,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 0,
      activeViewers: {},
    },
    [previewToken]: {
      folderId: "root",
      fileName: previewFileName,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 1,
      activeViewers: {},
    },
    [invalidToken]: {
      folderId: "root",
      fileName,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      views: 0,
    },
  }));

  const child = spawn(process.execPath, [SERVER], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "true",
      DATABASE_URL: databasePath,
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "false",
      DB_AUTO_BACKUP_ON_START: "false",
      CLOUD_STORAGE_PROVIDER: "local",
      NODE_ENV: "test",
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: "ignore",
    windowsHide: true,
  });

  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, TIMEOUT_MS);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
        child.kill();
      });
    }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  assert.equal((await request(port, `/share/${token}`)).status, 200);
  const origin = `http://127.0.0.1:${port}`;
  const view = await request(port, `/share/${token}/view`, "POST", { origin });
  assert.equal(view.status, 200, view.body);
  assert.equal(JSON.parse(view.body).views, 1);
  const previewView = await request(port, `/share/${previewToken}/view`, "POST", { origin });
  assert.equal(previewView.status, 200, previewView.body);
  const previewCookieHeader = previewView.headers["set-cookie"];
  const previewCookie = String(Array.isArray(previewCookieHeader) ? previewCookieHeader[0] : previewCookieHeader || "").split(";", 1)[0];
  assert.match(previewCookie, /^rootark_share_[a-f0-9]{48}=/);
  const rangeResponses = await Promise.all([
    request(port, `/share/${previewToken}/preview`, "GET", { cookie: previewCookie, range: "bytes=0-4" }),
    request(port, `/share/${previewToken}/preview`, "GET", { cookie: previewCookie, range: "bytes=5-9" }),
  ]);
  assert.deepEqual(rangeResponses.map((response) => response.status), [206, 206], "SQLite quota reservation is idempotent for concurrent ranges in one viewer session");
  const secondPreviewView = await request(port, `/share/${previewToken}/view`, "POST", { origin });
  assert.equal(secondPreviewView.status, 200, secondPreviewView.body);
  const secondPreviewCookieHeader = secondPreviewView.headers["set-cookie"];
  const secondPreviewCookie = String(Array.isArray(secondPreviewCookieHeader) ? secondPreviewCookieHeader[0] : secondPreviewCookieHeader || "").split(";", 1)[0];
  assert.equal((await request(port, `/share/${previewToken}/preview`, "GET", { cookie: secondPreviewCookie, range: "bytes=0-4" })).status, 410);
  assert.equal((await request(port, `/share/${secondToken}`)).status, 200, "counting one legacy link must not hide other unrecorded JSON links");
  assert.equal((await request(port, `/share/${secondToken}/view`, "POST", { origin })).status, 200);
  assert.equal((await request(port, `/share/${invalidToken}`)).status, 404, "invalid legacy JSON tokens are not served");

  const firstDownload = await request(port, `/share/${token}/download`, "POST", { origin });
  assert.equal(firstDownload.status, 200, firstDownload.body);
  assert.equal(firstDownload.body, "disposable SQLite fallback fixture\n");
  const exhaustedDownload = await request(port, `/share/${token}/download`, "POST", { origin });
  assert.equal(exhaustedDownload.status, 410);

  const Database = require("better-sqlite3");
  const database = new Database(databasePath);
  try {
    const previewMetadata = JSON.parse(database.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(previewToken).metadata_json);
    assert.equal(previewMetadata.downloads, 1);
    assert.equal(previewMetadata.activeViewers[previewCookie.split("=", 2)[1]].downloadCounted, true);
    database.prepare("UPDATE public_links SET revoked_at = ? WHERE token = ?").run(new Date().toISOString(), token);
  } finally {
    database.close();
  }
  assert.equal((await request(port, `/share/${token}`)).status, 404, "a revoked SQLite token must not be restored from stale JSON fallback data");
});

async function waitForServer(port) {
  const deadline = Date.now() + TIMEOUT_MS;
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

test("public-share audit logs correlate by token digest without storing the bearer token", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-share-audit-"));
  const token = crypto.randomBytes(24).toString("hex");
  const expiredViewerToken = crypto.randomBytes(24).toString("hex");
  const port = await getUnusedPort();
  const dataDir = path.join(sandbox, "data");
  const fileName = "shared-audit-fixture.txt";
  const previewFileName = "shared-preview-fixture.pdf";

  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.mkdirSync(dataDir, { recursive: true });
  fs.cpSync(PUBLIC, path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", fileName), "disposable share fixture\n");
  fs.writeFileSync(path.join(sandbox, "uploads", previewFileName), "disposable preview fixture\n");
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [token]: {
      folderId: "root",
      fileName,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 1,
      viewers: {},
    },
    [expiredViewerToken]: {
      folderId: "root",
      fileName: previewFileName,
      passwordHash: bcrypt.hashSync("synthetic-viewer-password", 4),
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 2,
      viewers: {},
    },
  }));

  const child = spawn(process.execPath, [SERVER], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "false",
      CLOUD_STORAGE_PROVIDER: "local",
      NODE_ENV: "test",
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: "ignore",
    windowsHide: true,
  });

  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, TIMEOUT_MS);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
        child.kill();
      });
    }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const expiredViewerPreview = await request(port, `/share/${expiredViewerToken}/preview`, "GET", {
    cookie: `rootark_share_pwd_${expiredViewerToken}=ok`,
  });
  assert.equal(expiredViewerPreview.status, 403, "an expired viewer cookie is rejected even while the password session remains valid");
  assert.equal(expiredViewerPreview.body, "Abra a pagina do compartilhamento novamente.");
  const sharePage = await request(port, `/share/${token}`);
  assert.equal(sharePage.status, 200);
  assert.match(sharePage.body, /<label[^>]*for="sharePassword">Senha do link<\/label>/, "the password field retains its visible label while users type");
  assert.match(sharePage.body, /<p class="status" id="status" role="status" aria-live="polite" aria-atomic="true">/, "status changes are announced without moving focus");
  assert.match(sharePage.body, /<form id="sharePasswordForm">[\s\S]*<input type="password" id="sharePassword"[^>]*aria-label="Senha do link"/);
  assert.match(sharePage.body, /passwordForm\.addEventListener\("submit"/);
  let shareFetchCalls = 0;
  let initialShareRequest;
  let submitRequestResolve;
  let malformedResponseResolve;
  const sharePageElements = runSharePageScript(sharePage.body, (url, options) => {
    shareFetchCalls += 1;
    if (shareFetchCalls === 1) {
      initialShareRequest = { url, options };
      return Promise.resolve({ status: 401, ok: false, json: async () => ({ passwordRequired: true }) });
    }
    if (shareFetchCalls === 2) {
      return new Promise((resolve) => { submitRequestResolve = resolve; });
    }
    if (shareFetchCalls === 3) {
      return new Promise((resolve) => { malformedResponseResolve = resolve; });
    }
    return Promise.reject(new Error("offline"));
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(initialShareRequest.url, /\/password$/);
  assert.equal(initialShareRequest.options.method, "POST");
  assert.deepEqual(JSON.parse(initialShareRequest.options.body), { password: "" }, "initial access checks send an empty password");
  const shareStatus = sharePageElements.get("status");
  assert.equal(shareStatus.textContent, "Informe a senha para continuar.", "the password-required response gives the initial password prompt");
  assert.equal(sharePageElements.get("passwordBox").classList.contains("hidden"), false, "the password form is shown after the initial challenge");
  assert.equal(sharePageElements.get("contentBox").classList.contains("hidden"), true, "shared content stays hidden until access succeeds");
  const passwordButton = sharePageElements.get("passwordButton");
  const submitPassword = () => sharePageElements.get("sharePasswordForm").listeners.submit({ preventDefault() {} });
  sharePageElements.get("sharePassword").value = "wrong-password";
  submitPassword();
  assert.equal(passwordButton.disabled, true, "the password button is disabled while access is being checked");
  assert.equal(passwordButton.textContent, "Validando...");
  submitPassword();
  assert.equal(shareFetchCalls, 2, "repeated submits do not send duplicate access requests");
  submitRequestResolve({ status: 401, ok: false, json: async () => ({ error: "Nao foi possivel acessar este link.", passwordRequired: true }) });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(shareStatus.textContent, /senha.*correta.*tente novamente/i, "an incorrect password gets an accurate generic retry message");
  assert.doesNotMatch(shareStatus.textContent, /informe a senha/i, "an incorrect password is not described as a missing password");
  assert.equal(passwordButton.disabled, false, "the password button is re-enabled after an incorrect password");
  submitPassword();
  malformedResponseResolve({ status: 200, ok: true, json: async () => { throw new SyntaxError("invalid JSON"); } });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(shareStatus.textContent, /validar o link.*tente novamente/i, "invalid JSON produces a generic recoverable status");
  assert.doesNotMatch(shareStatus.textContent, /conexao|rede|offline/i, "invalid JSON does not assume a network outage");
  assert.equal(sharePageElements.get("fileName").textContent, "Validacao indisponivel", "invalid JSON has a neutral heading");
  assert.equal(passwordButton.disabled, false, "the password button is re-enabled after invalid JSON");
  assert.equal(passwordButton.textContent, "Acessar");
  submitPassword();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.match(shareStatus.textContent, /validar o link.*tente novamente/i, "network failure produces a generic recoverable status");
  assert.doesNotMatch(shareStatus.textContent, /conexao|rede|offline/i, "network failure uses neutral recovery guidance");
  assert.equal(sharePageElements.get("fileName").textContent, "Validacao indisponivel", "network failure has a neutral heading");
  assert.equal(passwordButton.disabled, false, "the password button is re-enabled after a network failure");
  const initialFailureElements = runSharePageScript(sharePage.body, async () => { throw new Error("offline"); });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  const initialFailureStatus = initialFailureElements.get("status").textContent;
  assert.match(initialFailureStatus, /validar o link.*tente novamente/i, "initial access failure offers recovery guidance");
  assert.doesNotMatch(initialFailureStatus, /conexao|rede|offline/i, "initial access failure does not assume a network outage");
  assert.equal(initialFailureElements.get("fileName").textContent, "Validacao indisponivel", "initial access failure has a neutral heading");
  const expiredPageToken = crypto.randomBytes(24).toString("hex");
  const expiredFileToken = crypto.randomBytes(24).toString("hex");
  const countedFileToken = crypto.randomBytes(24).toString("hex");
  const previewFirstToken = crypto.randomBytes(24).toString("hex");
  const unsupportedPreviewToken = crypto.randomBytes(24).toString("hex");
  const unboundPreviewToken = crypto.randomBytes(24).toString("hex");
  const rangedPreviewToken = crypto.randomBytes(24).toString("hex");
  const protectedPreviewToken = crypto.randomBytes(24).toString("hex");
  const prototypeViewerToken = crypto.randomBytes(24).toString("hex");
  const prototypeUnmeteredViewerToken = crypto.randomBytes(24).toString("hex");
  const rangedFileToken = crypto.randomBytes(24).toString("hex");
  const rangedDownloadToken = crypto.randomBytes(24).toString("hex");
  const publicLinksPath = path.join(dataDir, "public-links.json");
  fs.writeFileSync(publicLinksPath, JSON.stringify({
    [token]: JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[token],
    [expiredPageToken]: { folderId: "root", fileName, expiresAt: new Date(Date.now() - 60_000).toISOString(), views: 0, downloads: 0, activeViewers: {} },
    [expiredFileToken]: { folderId: "root", fileName, expiresAt: new Date(Date.now() - 60_000).toISOString(), views: 0, downloads: 0, activeViewers: {} },
    [countedFileToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, viewers: {} },
    [previewFirstToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, viewers: {} },
    [unsupportedPreviewToken]: { folderId: "root", fileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, activeViewers: {} },
    [unboundPreviewToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 2, activeViewers: {} },
    [rangedPreviewToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, activeViewers: {} },
    [protectedPreviewToken]: { folderId: "root", fileName: previewFileName, passwordHash: bcrypt.hashSync("preview-fixture-password", 4), expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, activeViewers: {} },
    [prototypeViewerToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, activeViewers: {} },
    [prototypeUnmeteredViewerToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, activeViewers: {} },
    [rangedFileToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, activeViewers: {} },
    [rangedDownloadToken]: { folderId: "root", fileName: previewFileName, expiresAt: new Date(Date.now() + 60_000).toISOString(), views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, activeViewers: {} },
  }));
  const expiredPage = await request(port, `/share/${expiredPageToken}`);
  assert.equal(expiredPage.status, 410);
  assert.ok(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[expiredPageToken], "expired-link navigation does not persist cleanup");
  const expiredFile = await request(port, `/share/${expiredFileToken}/file`, "POST", { origin: `http://127.0.0.1:${port}` });
  assert.equal(expiredFile.status, 410);
  assert.ok(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[expiredFileToken], "expired-file POST does not persist cleanup");

  const unsupportedView = await request(port, `/share/${unsupportedPreviewToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(unsupportedView.status, 200);
  const unsupportedCookieHeader = unsupportedView.headers["set-cookie"];
  const unsupportedViewerCookie = String(Array.isArray(unsupportedCookieHeader) ? unsupportedCookieHeader[0] : unsupportedCookieHeader || "").split(";", 1)[0];
  const unsupportedPreview = await request(port, `/share/${unsupportedPreviewToken}/preview`, "GET", { cookie: unsupportedViewerCookie });
  assert.equal(unsupportedPreview.status, 415);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[unsupportedPreviewToken].downloads, 0, "a rejected preview does not consume download quota");
  const unsupportedPreviewDownload = await request(port, `/share/${unsupportedPreviewToken}/file`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(unsupportedPreviewDownload.status, 200, "a rejected preview leaves the allowed file download available");

  const unboundRange = await request(port, `/share/${unboundPreviewToken}/preview`, "GET", { range: "bytes=0-3" });
  assert.equal(unboundRange.status, 403, "a download-limited preview requires an active viewer before serving ranges");
  const staleViewerRange = await request(port, `/share/${unboundPreviewToken}/preview`, "GET", {
    cookie: `rootark_share_${unboundPreviewToken}=${crypto.randomBytes(16).toString("hex")}`,
    range: "bytes=4-7",
  });
  assert.equal(staleViewerRange.status, 403, "an unknown or expired viewer cannot consume preview quota");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[unboundPreviewToken].downloads, 0, "rejected ranges leave download quota untouched");
  const unboundView = await request(port, `/share/${unboundPreviewToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(unboundView.status, 200);
  const unboundCookieHeader = unboundView.headers["set-cookie"];
  const unboundViewerCookie = String(Array.isArray(unboundCookieHeader) ? unboundCookieHeader[0] : unboundCookieHeader || "").split(";", 1)[0];
  const unboundViewerRanges = await Promise.all([
    request(port, `/share/${unboundPreviewToken}/preview`, "GET", { cookie: unboundViewerCookie, range: "bytes=0-3" }),
    request(port, `/share/${unboundPreviewToken}/preview`, "GET", { cookie: unboundViewerCookie, range: "bytes=4-7" }),
  ]);
  assert.deepEqual(unboundViewerRanges.map((response) => response.status), [206, 206], "one active viewer can fetch multiple preview ranges");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[unboundPreviewToken].downloads, 1, "all ranges for one viewer share a single download quota charge");

  const rangedPreviewView = await request(port, `/share/${rangedPreviewToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(rangedPreviewView.status, 200);
  const viewerCookieHeader = rangedPreviewView.headers["set-cookie"];
  const viewerCookie = String(Array.isArray(viewerCookieHeader) ? viewerCookieHeader[0] : viewerCookieHeader || "").split(";", 1)[0];
  assert.match(viewerCookie, /^rootark_share_[a-f0-9]{48}=/, "the viewer session correlates range requests from one preview");
  const rangedPreviewParts = await Promise.all([
    request(port, `/share/${rangedPreviewToken}/preview`, "GET", { cookie: viewerCookie, range: "bytes=0-3" }),
    request(port, `/share/${rangedPreviewToken}/preview`, "GET", { cookie: viewerCookie, range: "bytes=4-7" }),
  ]);
  assert.deepEqual(rangedPreviewParts.map((response) => response.status), [206, 206], "parallel range reads for one viewer remain available");
  assert.deepEqual(rangedPreviewParts.map((response) => response.body), ["disp", "osab"]);
  const continuedPreview = await request(port, `/share/${rangedPreviewToken}/preview`, "GET", {
    cookie: viewerCookie,
    range: "bytes=8-11",
  });
  assert.equal(continuedPreview.status, 206, "later ranges from the same viewer do not consume additional downloads");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[rangedPreviewToken].downloads, 1);
  const secondRangedView = await request(port, `/share/${rangedPreviewToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(secondRangedView.status, 200);
  const secondRangedCookieHeader = secondRangedView.headers["set-cookie"];
  const secondRangedCookie = String(Array.isArray(secondRangedCookieHeader) ? secondRangedCookieHeader[0] : secondRangedCookieHeader || "").split(";", 1)[0];
  assert.equal((await request(port, `/share/${rangedPreviewToken}/preview`, "GET", { cookie: secondRangedCookie, range: "bytes=8-11" })).status, 410, "another active viewer cannot bypass the exhausted download quota");

  const protoCookie = `rootark_share_${prototypeViewerToken}=__proto__`;
  assert.equal((await request(port, `/share/${prototypeViewerToken}/preview`, "GET", { cookie: protoCookie })).status, 403, "an invalid viewer cookie cannot establish a quota-bearing preview session");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[prototypeViewerToken].downloads, 0);
  const protoUnmeteredCookie = `rootark_share_${prototypeUnmeteredViewerToken}=__proto__`;
  assert.equal((await request(port, `/share/${prototypeUnmeteredViewerToken}/preview`, "GET", { cookie: protoUnmeteredCookie })).status, 200);
  assert.equal((await request(port, `/share/${prototypeUnmeteredViewerToken}/preview`, "GET", { cookie: protoUnmeteredCookie })).status, 200);
  const protoUnmeteredLink = JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[prototypeUnmeteredViewerToken];
  assert.equal(protoUnmeteredLink.downloads, 2, "an invalid viewer cannot inherit a prior per-viewer quota marker");
  assert.equal(Object.prototype.hasOwnProperty.call(protoUnmeteredLink.activeViewers, "__proto__"), false);
  assert.equal(protoUnmeteredLink.activeViewers.downloadCounted, undefined);
  assert.equal(Object.prototype.downloadCounted, undefined, "invalid viewer input never mutates Object.prototype");

  const invalidFileRange = await request(port, `/share/${rangedFileToken}/file`, "POST", {
    origin: `http://127.0.0.1:${port}`,
    range: "bytes=999-1000",
  });
  assert.equal(invalidFileRange.status, 416);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[rangedFileToken].downloads, 0, "an unsatisfiable file Range must not consume quota");
  const validFileRange = await request(port, `/share/${rangedFileToken}/file`, "POST", {
    origin: `http://127.0.0.1:${port}`,
    range: "bytes=0-3",
  });
  assert.equal(validFileRange.status, 206);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[rangedFileToken].downloads, 1);

  const invalidDownloadRange = await request(port, `/share/${rangedDownloadToken}/download`, "POST", {
    origin: `http://127.0.0.1:${port}`,
    range: "bytes=999-1000",
  });
  assert.equal(invalidDownloadRange.status, 416);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[rangedDownloadToken].downloads, 0, "an unsatisfiable attachment Range must not consume quota");
  const validDownloadRange = await request(port, `/share/${rangedDownloadToken}/download`, "POST", {
    origin: `http://127.0.0.1:${port}`,
    range: "bytes=0-3",
  });
  assert.equal(validDownloadRange.status, 206);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[rangedDownloadToken].downloads, 1);

  const previewRefreshCalls = [];
  const previewRefreshResponses = [
    { fileName: "preview.pdf", expiresAt: new Date(Date.now() + 60_000).toISOString(), remainingViews: null, remainingDownloads: 1, canPreview: true, size: 12 },
    { fileName: "preview.pdf", expiresAt: new Date(Date.now() + 60_000).toISOString(), remainingViews: null, remainingDownloads: 0, canPreview: true, size: 12 },
  ];
  const previewRefreshElements = runSharePageScript(sharePage.body, (url, options) => {
    previewRefreshCalls.push({ url, options });
    const payload = previewRefreshResponses.shift();
    return Promise.resolve({ status: 200, ok: true, json: async () => payload });
  });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(previewRefreshElements.get("downloadButton").disabled, false);
  previewRefreshElements.get("previewButton").listeners.click();
  const previewFrame = previewRefreshElements.createdElements.find((element) => element.tagName === "iframe");
  assert.ok(previewFrame, "the preview flow creates an iframe with a load handler");
  previewFrame.listeners.load();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(previewRefreshCalls.length, 2, "preview completion reloads the current share limits");
  assert.equal(previewRefreshCalls[1].options.method, "POST");
  assert.equal(previewRefreshElements.get("meta").innerHTML.includes("0 downloads restantes"), true);
  assert.equal(previewRefreshElements.get("downloadButton").disabled, true);
  assert.match(previewRefreshElements.get("status").textContent, /limite de downloads atingido/i);

  const expiredRefreshResponses = [
    { status: 401, ok: false, json: async () => ({ passwordRequired: true, error: "Senha necessaria." }) },
    { status: 200, ok: true, json: async () => ({ fileName: "preview.pdf", expiresAt: new Date(Date.now() + 60_000).toISOString(), remainingViews: null, remainingDownloads: 1, canPreview: true, size: 12 }) },
    { status: 401, ok: false, json: async () => ({ passwordRequired: true, error: "Senha necessaria." }) },
    { status: 200, ok: true, json: async () => ({ fileName: "preview.pdf", expiresAt: new Date(Date.now() + 60_000).toISOString(), remainingViews: null, remainingDownloads: 1, canPreview: true, size: 12 }) },
  ];
  const expiredRefreshCalls = [];
  const expiredRefreshElements = runSharePageScript(sharePage.body, (url, options) => {
    expiredRefreshCalls.push({ url, options });
    return Promise.resolve(expiredRefreshResponses.shift());
  });
  const assertPasswordPost = (call, password, description) => {
    assert.equal(call.url, `/share/${token}/password`, `${description} uses a same-origin password route`);
    assert.equal(call.options.method, "POST", `${description} uses POST`);
    assert.deepEqual(JSON.parse(call.options.body), { password }, `${description} sends the expected password body`);
  };
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assertPasswordPost(expiredRefreshCalls[0], "", "initial password challenge");
  assert.equal(expiredRefreshElements.activeElement, expiredRefreshElements.get("sharePassword"), "initial password challenges focus the password field");
  expiredRefreshElements.get("sharePassword").value = "disposable-share-password";
  expiredRefreshElements.get("sharePasswordForm").listeners.submit({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assertPasswordPost(expiredRefreshCalls[1], "disposable-share-password", "initial password submission");
  assert.equal(expiredRefreshElements.get("sharePassword").value, "", "successful access clears the submitted password from the hidden field");
  expiredRefreshElements.get("previewButton").listeners.click();
  const expiredPreviewFrame = expiredRefreshElements.createdElements.find((element) => element.tagName === "iframe");
  expiredPreviewFrame.listeners.load();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assertPasswordPost(expiredRefreshCalls[2], "", "expired preview refresh");
  assert.equal(expiredRefreshElements.get("passwordBox").classList.contains("hidden"), false);
  assert.equal(expiredRefreshElements.get("contentBox").classList.contains("hidden"), true);
  assert.equal(expiredRefreshElements.activeElement, expiredRefreshElements.get("sharePassword"), "expired preview sessions return keyboard focus to the password field");
  assert.equal(expiredRefreshElements.get("sharePassword").value, "", "expired preview sessions do not reveal a retained password");
  assert.equal(expiredRefreshElements.get("previewBox").classList.contains("hidden"), true, "an expired preview is hidden until access is restored");
  assert.equal(expiredRefreshElements.get("previewBox").children.length, 0, "the expired iframe is removed so it can be retried");
  assert.equal(expiredRefreshElements.get("previewBox").dataset.loaded, undefined, "the expired preview resets its loaded marker");
  assert.match(expiredRefreshElements.get("status").textContent, /sess[aã]o do link expirou/i);
  expiredRefreshElements.get("sharePassword").value = "reauth-password";
  expiredRefreshElements.get("sharePasswordForm").listeners.submit({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assertPasswordPost(expiredRefreshCalls[3], "reauth-password", "password reauthentication");
  assert.equal(expiredRefreshElements.activeElement, expiredRefreshElements.get("previewButton"), "successful reauthentication moves keyboard focus to the available preview action");
  expiredRefreshElements.get("previewButton").listeners.click();
  const retriedPreviewFrame = expiredRefreshElements.createdElements.find((element, index) => index > 0 && element.tagName === "iframe");
  assert.ok(retriedPreviewFrame, "the user can create a new iframe after reauthentication");
  assert.equal(retriedPreviewFrame.src, `/share/${token}/preview`);
  assert.equal(expiredRefreshCalls.length, 4, "the expired preview recovery sends only the expected password checks");

  const viewerRefreshElements = runSharePageScript(sharePage.body, () => Promise.resolve({
    status: 200,
    ok: true,
    json: async () => ({ fileName: "preview.pdf", expiresAt: new Date(Date.now() + 60_000).toISOString(), remainingViews: null, remainingDownloads: 1, canPreview: true, size: 12 }),
  }));
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  viewerRefreshElements.get("previewButton").listeners.click();
  const expiredViewerFrame = viewerRefreshElements.createdElements.find((element) => element.tagName === "iframe");
  expiredViewerFrame.contentDocument = { body: { textContent: expiredViewerPreview.body } };
  expiredViewerFrame.listeners.load();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(viewerRefreshElements.get("previewBox").children.length, 0, "a viewer-expired preview response is removed after its password session refreshes");
  assert.equal(viewerRefreshElements.get("previewBox").dataset.loaded, undefined, "a viewer-expired preview can be requested again after refresh");
  viewerRefreshElements.get("previewButton").listeners.click();
  assert.equal(viewerRefreshElements.createdElements.filter((element) => element.tagName === "iframe").length, 2, "retrying preview creates a fresh iframe after the viewer session is renewed");

  const wrongPasswordResponses = [
    { status: 401, ok: false, json: async () => ({ passwordRequired: true, error: "Senha necessaria." }) },
    { status: 401, ok: false, json: async () => ({ passwordRequired: true, error: "Senha incorreta." }) },
  ];
  const wrongPasswordElements = runSharePageScript(sharePage.body, () => Promise.resolve(wrongPasswordResponses.shift()));
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  wrongPasswordElements.get("sharePassword").value = "wrong-password";
  wrongPasswordElements.get("sharePasswordForm").listeners.submit({ preventDefault() {} });
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(wrongPasswordElements.get("sharePassword").value, "", "a rejected password is cleared");
  assert.equal(wrongPasswordElements.activeElement, wrongPasswordElements.get("sharePassword"), "a rejected password returns focus to the password field");
  assert.match(wrongPasswordElements.get("status").textContent, /verifique se ela esta correta/i);

  const previewFirstView = await request(port, `/share/${previewFirstToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(previewFirstView.status, 200);
  const previewFirstCookieHeader = previewFirstView.headers["set-cookie"];
  const previewFirstCookie = String(Array.isArray(previewFirstCookieHeader) ? previewFirstCookieHeader[0] : previewFirstCookieHeader || "").split(";", 1)[0];
  const crossSitePreview = await request(port, `/share/${previewFirstToken}/preview`, "GET", {
    cookie: previewFirstCookie,
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
  });
  assert.equal(crossSitePreview.status, 403, "cross-site top-level preview navigation cannot consume quota");
  assert.equal(crossSitePreview.body.includes("disposable preview fixture"), false);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[previewFirstToken].downloads, 0, "cross-site preview does not consume download quota");
  assert.match(String(previewFirstCookieHeader), /SameSite=Strict/i, "viewer cookies are withheld on cross-site top-level navigation");
  const previewHead = await request(port, "/share/" + previewFirstToken + "/preview", "HEAD", {
    cookie: previewFirstCookie,
    "sec-fetch-site": "same-origin",
  });
  assert.equal(previewHead.status, 405, "HEAD does not act as a preview download");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[previewFirstToken].downloads, 0);
  const invalidPreviewRange = await request(port, `/share/${previewFirstToken}/preview`, "GET", { cookie: previewFirstCookie, range: "bytes=999-1000" });
  assert.equal(invalidPreviewRange.status, 416);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[previewFirstToken].downloads, 0, "an unsatisfiable range does not consume download quota");
  const previewFirst = await request(port, `/share/${previewFirstToken}/preview`, "GET", {
    cookie: previewFirstCookie,
    "sec-fetch-site": "same-origin",
  });
  assert.equal(previewFirst.status, 200);
  assert.equal(previewFirst.body, "disposable preview fixture\n");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[previewFirstToken].downloads, 1, "preview delivery consumes the shared download budget");
  const protectedPreviewAccess = await request(port, "/share/" + protectedPreviewToken + "/password", "POST", {
    origin: "http://127.0.0.1:" + port,
    "content-type": "application/json",
  }, JSON.stringify({ password: "preview-fixture-password" }));
  assert.equal(protectedPreviewAccess.status, 200, protectedPreviewAccess.body);
  const protectedPreviewSetCookies = Array.isArray(protectedPreviewAccess.headers["set-cookie"])
    ? protectedPreviewAccess.headers["set-cookie"]
    : [protectedPreviewAccess.headers["set-cookie"] || ""];
  const protectedPreviewCookies = protectedPreviewSetCookies.map((cookie) => String(cookie).split(";", 1)[0]).filter(Boolean);
  const protectedPreviewCookie = protectedPreviewCookies.join("; ");
  assert.ok(protectedPreviewCookies.some((cookie) => cookie.startsWith("rootark_share_" + protectedPreviewToken + "=")), "password access establishes a viewer session");
  assert.ok(protectedPreviewCookies.some((cookie) => cookie.startsWith("rootark_share_pwd_" + protectedPreviewToken + "=")), "password access establishes a password session");
  assert.ok(protectedPreviewSetCookies.some((cookie) => cookie.includes("rootark_share_" + protectedPreviewToken + "=") && /SameSite=Strict/i.test(cookie)), "viewer cookies are withheld on cross-site top-level navigation");
  const crossSiteProtectedPreview = await request(port, "/share/" + protectedPreviewToken + "/preview", "GET", {
    cookie: protectedPreviewCookie,
    "sec-fetch-site": "cross-site",
    "sec-fetch-mode": "navigate",
    "sec-fetch-dest": "document",
  });
  assert.equal(crossSiteProtectedPreview.status, 403, "cross-site top-level navigation cannot consume a password-protected share quota");
  assert.equal(crossSiteProtectedPreview.body.includes("disposable preview fixture"), false);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[protectedPreviewToken].downloads, 0);
  const headerlessProtectedPreview = await request(port, "/share/" + protectedPreviewToken + "/preview", "GET", {
    cookie: protectedPreviewCookie,
  }, "", { includeDefaultFetchSite: false });
  assert.equal(headerlessProtectedPreview.status, 403, "preview fails closed when Origin and Fetch Metadata are both absent");
  assert.equal(headerlessProtectedPreview.body.includes("disposable preview fixture"), false);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[protectedPreviewToken].downloads, 0);
  const protectedSameOriginPreview = await request(port, "/share/" + protectedPreviewToken + "/preview", "GET", {
    cookie: protectedPreviewCookie,
    "sec-fetch-site": "same-origin",
  });
  assert.equal(protectedSameOriginPreview.status, 200);
  assert.equal(protectedSameOriginPreview.body, "disposable preview fixture\n");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[protectedPreviewToken].downloads, 1, "same-origin preview remains available and consumes the quota");
  const secondPreviewView = await request(port, `/share/${previewFirstToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(secondPreviewView.status, 200);
  const secondPreviewCookieHeader = secondPreviewView.headers["set-cookie"];
  const secondPreviewCookie = String(Array.isArray(secondPreviewCookieHeader) ? secondPreviewCookieHeader[0] : secondPreviewCookieHeader || "").split(";", 1)[0];
  const exhaustedPreview = await request(port, `/share/${previewFirstToken}/preview`, "GET", { cookie: secondPreviewCookie });
  assert.equal(exhaustedPreview.status, 410, "preview delivery cannot exceed maxDownloads");
  assert.equal(exhaustedPreview.body.includes("disposable preview fixture"), false);

  const requestHeaders = {
    "user-agent": `audit-client-${token}`,
    "x-forwarded-for": `${token.toUpperCase()}, 198.51.100.8`,
  };
  const shareHeaders = { ...requestHeaders, origin: `http://127.0.0.1:${port}` };
  assert.equal((await request(port, `/share/${token}/view`, "POST", requestHeaders)).status, 403, "missing Origin cannot consume a share view");
  assert.equal((await request(port, `/share/${token}/password`, "POST", requestHeaders)).status, 403, "missing Origin cannot establish a password/view session");
  const unchangedAfterMissingOrigin = JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[token];
  assert.equal(unchangedAfterMissingOrigin.views, 0);
  assert.equal(unchangedAfterMissingOrigin.downloads, 0);
  const view = await request(port, `/share/${token}/view`, "POST", shareHeaders);
  assert.equal(view.status, 200);
  assert.deepEqual(JSON.parse(view.body).url, `/share/${token}/file`);
  assert.equal(JSON.parse(view.body).urlMethod, "POST", "the returned file URL identifies its required safe method");
  assert.equal((await request(port, `/share/${token}/view`, "POST", shareHeaders)).status, 200);
  assert.equal((await request(port, `/share/${token}/view`, "POST", {
    ...shareHeaders,
    origin: "https://attacker.example",
  })).status, 403);

  const legacyFile = await request(port, `/share/${countedFileToken}/file`);
  assert.equal(legacyFile.status, 405, "legacy GET file delivery is no longer reachable");
  assert.equal(legacyFile.headers.allow, "POST");
  const missingOriginFile = await request(port, `/share/${countedFileToken}/file`, "POST");
  assert.equal(missingOriginFile.status, 403, "file delivery POST requires a same-origin request");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[countedFileToken].downloads, 0);
  const countedFile = await request(port, `/share/${countedFileToken}/file`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(countedFile.status, 200);
  assert.equal(countedFile.body, "disposable preview fixture\n");
  const exhaustedFile = await request(port, `/share/${countedFileToken}/file`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(exhaustedFile.status, 410, "counted file delivery cannot exceed the download quota");
  const quotaPreviewView = await request(port, `/share/${countedFileToken}/view`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(quotaPreviewView.status, 200);
  const quotaPreviewCookieHeader = quotaPreviewView.headers["set-cookie"];
  const quotaPreviewCookie = String(Array.isArray(quotaPreviewCookieHeader) ? quotaPreviewCookieHeader[0] : quotaPreviewCookieHeader || "").split(";", 1)[0];
  const previewAfterFileQuota = await request(port, `/share/${countedFileToken}/preview`, "GET", { cookie: quotaPreviewCookie });
  assert.equal(previewAfterFileQuota.status, 410, "preview cannot bypass an exhausted download quota");
  assert.equal(previewAfterFileQuota.body.includes("disposable preview fixture"), false);
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[countedFileToken].downloads, 1);

  const legacyDownload = await request(port, `/share/${token}/download`, "GET", shareHeaders);
  assert.equal(legacyDownload.status, 405);
  assert.equal(legacyDownload.headers.allow, "POST");
  const crossOriginDownload = await request(port, `/share/${token}/download`, "POST", {
    ...shareHeaders,
    origin: "https://attacker.example",
  });
  assert.equal(crossOriginDownload.status, 403);
  assert.equal((await request(port, `/share/${token}/download`, "POST", requestHeaders)).status, 403, "missing Origin cannot consume a download");
  assert.equal(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[token].downloads, 0);

  const download = await request(port, `/share/${token}/download`, "POST", {
    ...shareHeaders,
    origin: `http://127.0.0.1:${port}`,
  });
  assert.equal(download.status, 200);
  assert.equal(download.body, "disposable share fixture\n");
  assert.equal((await request(port, `/share/${token}/download`, "POST", {
    ...shareHeaders,
    origin: `http://127.0.0.1:${port}`,
  })).status, 410);
  const publicLink = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))[token];
  assert.equal(publicLink.downloads, 1);

  const { logs } = JSON.parse(fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8"));
  const shareLogs = logs.filter((entry) => entry.eventType.startsWith("share."));
  const expectedAuditId = crypto.createHash("sha256").update(token, "utf8").digest("hex");
  const opened = shareLogs.filter((entry) => entry.eventType === "share.opened" && entry.target.id === expectedAuditId);
  assert.equal(opened.length, 2);
  assert.deepEqual(opened.map((entry) => entry.target.id), [expectedAuditId, expectedAuditId]);
  assert.equal(opened[0].actor.userAgent, `audit-client-[REDACTED]`);
  assert.equal(opened[0].actor.ip, "127.0.0.1", "untrusted forwarding headers do not replace the socket peer");
  const serializedShareLogs = JSON.stringify(shareLogs);
  assert.equal(serializedShareLogs.includes(token), false);
  assert.equal(serializedShareLogs.includes(token.toUpperCase()), false);
});
