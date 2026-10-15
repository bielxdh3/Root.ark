const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const { once } = require("node:events");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { encryptSecret, generateSecret, hotp } = require("../src/services/totp");

const ROOT = path.resolve(__dirname, "..");

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const body = options.body ? JSON.stringify(options.body) : "";
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: requestPath,
      method: options.method || "GET",
      headers: { ...(body ? { "content-type": "application/json", "content-length": Buffer.byteLength(body) } : {}), ...(options.headers || {}) },
    }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(child, getStartupOutput) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited");
    const match = getStartupOutput().match(/Servidor rodando em http:\/\/(?:\[[^\]]+\]|[^:\s]+):(\d+)/);
    if (match) return Number(match[1]);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("disposable server did not start");
}

test("bounded HTTP login challenge preserves cookie session and CSRF boundaries", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-totp-http-"));
  const key = crypto.randomBytes(32);
  const secret = generateSecret();
  const user = {
    username: "alice",
    password: bcrypt.hashSync("disposable-password", 4),
    role: "user",
    permissions: {},
    sessionVersion: 0,
    totpEnabled: true,
    totpSecret: encryptSecret(secret, key, "Root.ark/TOTP/alice"),
    totpRecoveryHashes: [],
    totpLastUsedStep: Math.floor(Date.now() / 1000 / 30) - 1,
  };
  fs.mkdirSync(path.join(directory, "data"), { recursive: true });
  fs.writeFileSync(path.join(directory, "data", "users.local.json"), JSON.stringify([user]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: directory,
    env: {
      ...process.env,
      PORT: "0",
      JWT_SECRET: crypto.randomBytes(32).toString("hex"),
      SERVER_MASTER_KEY: key.toString("hex"),
      DB_ENABLED: "false",
      DB_WRITE_LEGACY_JSON: "true",
      UPLOAD_SCAN_ENABLED: "false",
      LOGIN_DELAY_BASE: "0",
      NODE_ENV: "test",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let startupOutput = "";
  let startupError = "";
  child.stdout.on("data", (chunk) => { startupOutput = (startupOutput + chunk.toString()).slice(-4_096); });
  child.stderr.on("data", (chunk) => { startupError += chunk.toString().slice(0, 500); });
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill();
      await Promise.race([once(child, "exit"), new Promise((resolve) => setTimeout(resolve, 2_000))]);
    }
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  let port;
  try {
    port = await waitForServer(child, () => startupOutput);
  } catch (error) {
    throw new Error(`${error.message}: ${startupError.replace(/\r?\n/g, " ").slice(0, 300)} ${startupOutput.replace(/\r?\n/g, " ").slice(-300)}`);
  }
  const primary = await request(port, "/auth/login", { method: "POST", body: { username: "alice", password: "disposable-password" } });
  assert.equal(primary.status, 200);
  assert.equal(primary.headers["cache-control"], "no-store");
  assert.equal(primary.headers.pragma, "no-cache");
  const challenge = JSON.parse(primary.body);
  assert.equal(challenge.challengeRequired, true);
  const invalid = await request(port, "/auth/login/2fa", { method: "POST", body: { challengeId: challenge.challengeId, code: "000000" } });
  assert.equal(invalid.status, 401);
  assert.equal(invalid.headers["cache-control"], "no-store");
  const valid = await request(port, "/auth/login/2fa", {
    method: "POST",
    body: { challengeId: challenge.challengeId, code: hotp(secret, Math.floor(Date.now() / 1000 / 30)) },
  });
  assert.equal(valid.status, 200);
  assert.equal(valid.headers["cache-control"], "no-store");
  assert.equal(valid.headers.pragma, "no-cache");
  const cookie = valid.headers["set-cookie"].map((entry) => entry.split(";", 1)[0]).join("; ");
  const me = await request(port, "/auth/me", { headers: { cookie } });
  assert.equal(me.status, 200);
  assert.equal(JSON.parse(me.body).username, "alice");
  const csrfDenied = await request(port, "/auth/2fa/disable", { method: "POST", headers: { cookie }, body: { password: "disposable-password", code: "000000" } });
  assert.equal(csrfDenied.status, 403);
});
