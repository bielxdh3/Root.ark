const assert = require("node:assert/strict");
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

function request(port, requestPath, method = "GET", headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end();
  });
}

function runSharePageScript(page, fetchImpl) {
  const elements = new Map();
  const getElementById = (id) => {
    if (!elements.has(id)) {
      const classes = new Set(["passwordBox", "contentBox", "previewBox", "qrBox"].includes(id) ? ["hidden"] : []);
      const element = {
        textContent: "",
        innerHTML: "",
        value: "",
        disabled: false,
        hidden: false,
        dataset: {},
        listeners: {},
        classList: {
          add(name) { classes.add(name); },
          remove(name) { classes.delete(name); },
          toggle(name) { if (classes.has(name)) classes.delete(name); else classes.add(name); },
          contains(name) { return classes.has(name); },
        },
        addEventListener(type, handler) { this.listeners[type] = handler; },
      };
      elements.set(id, element);
    }
    return elements.get(id);
  };
  const script = page.match(/<script\b[^>]*>\s*([\s\S]*?)\s*<\/script\s*>/i)?.[1];
  assert.ok(script, "share page has an inline client script");
  vm.runInNewContext(script, {
    document: { getElementById },
    fetch: fetchImpl,
    navigator: { clipboard: { writeText: async () => {} } },
    window: { location: { href: "https://rootark.test/share/example" } },
  });
  return elements;
}

test("public-share script extraction accepts case-insensitive script tags", () => {
  const elements = runSharePageScript('<SCRIPT type="text/javascript">document.getElementById("status").textContent = "loaded";</SCRIPT>');
  assert.equal(elements.get("status").textContent, "loaded");
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
  const port = await getUnusedPort();
  const dataDir = path.join(sandbox, "data");
  const fileName = "shared-audit-fixture.txt";

  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.mkdirSync(dataDir, { recursive: true });
  fs.cpSync(PUBLIC, path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", fileName), "disposable share fixture\n");
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
  const publicLinksPath = path.join(dataDir, "public-links.json");
  fs.writeFileSync(publicLinksPath, JSON.stringify({
    [token]: JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[token],
    [expiredPageToken]: { folderId: "root", fileName, expiresAt: new Date(Date.now() - 60_000).toISOString(), views: 0, downloads: 0, activeViewers: {} },
    [expiredFileToken]: { folderId: "root", fileName, expiresAt: new Date(Date.now() - 60_000).toISOString(), views: 0, downloads: 0, activeViewers: {} },
  }));
  const expiredPage = await request(port, `/share/${expiredPageToken}`);
  assert.equal(expiredPage.status, 410);
  assert.ok(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[expiredPageToken], "expired-link navigation does not persist cleanup");
  const expiredFile = await request(port, `/share/${expiredFileToken}/file`);
  assert.equal(expiredFile.status, 410);
  assert.ok(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[expiredFileToken], "expired-file GET does not persist cleanup");

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
  assert.equal((await request(port, `/share/${token}/view`, "POST", shareHeaders)).status, 200);
  assert.equal((await request(port, `/share/${token}/view`, "POST", shareHeaders)).status, 200);
  assert.equal((await request(port, `/share/${token}/view`, "POST", {
    ...shareHeaders,
    origin: "https://attacker.example",
  })).status, 403);

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
  const opened = shareLogs.filter((entry) => entry.eventType === "share.opened");
  const expectedAuditId = crypto.createHash("sha256").update(token, "utf8").digest("hex");
  assert.equal(opened.length, 2);
  assert.deepEqual(opened.map((entry) => entry.target.id), [expectedAuditId, expectedAuditId]);
  assert.equal(opened[0].actor.userAgent, `audit-client-[REDACTED]`);
  assert.equal(opened[0].actor.ip, "127.0.0.1", "untrusted forwarding headers do not replace the socket peer");
  const serializedShareLogs = JSON.stringify(shareLogs);
  assert.equal(serializedShareLogs.includes(token), false);
  assert.equal(serializedShareLogs.includes(token.toUpperCase()), false);
});
