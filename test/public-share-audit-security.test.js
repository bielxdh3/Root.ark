const assert = require("node:assert/strict");
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
  assert.match(sharePage.body, /<form id="sharePasswordForm">[\s\S]*<input type="password" id="sharePassword"[^>]*aria-label="Senha do link"/);
  assert.match(sharePage.body, /passwordForm\.addEventListener\("submit"/);
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
