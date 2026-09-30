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
      res.on("end", () => resolve({ status: res.statusCode, body }));
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
      maxDownloads: 0,
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
  const shareHeaders = {
    "user-agent": `audit-client-${token}`,
    "x-forwarded-for": `${token.toUpperCase()}, 198.51.100.8`,
  };
  assert.equal((await request(port, `/share/${token}/view`, "POST", shareHeaders)).status, 200);
  assert.equal((await request(port, `/share/${token}/view`, "POST", shareHeaders)).status, 200);

  const { logs } = JSON.parse(fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8"));
  const shareLogs = logs.filter((entry) => entry.eventType.startsWith("share."));
  const opened = shareLogs.filter((entry) => entry.eventType === "share.opened");
  const expectedAuditId = crypto.createHash("sha256").update(token, "utf8").digest("hex");
  assert.equal(opened.length, 2);
  assert.deepEqual(opened.map((entry) => entry.target.id), [expectedAuditId, expectedAuditId]);
  assert.equal(opened[0].actor.userAgent, `audit-client-[REDACTED]`);
  assert.equal(opened[0].actor.ip, "[REDACTED]");
  const serializedShareLogs = JSON.stringify(shareLogs);
  assert.equal(serializedShareLogs.includes(token), false);
  assert.equal(serializedShareLogs.includes(token.toUpperCase()), false);
});
