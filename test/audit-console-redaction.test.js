const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");

function serverBootstrap() {
  return `
const http = require("node:http");
const originalListen = http.Server.prototype.listen;
let readinessSent = false;
http.Server.prototype.listen = function (...args) {
  const callbackIndex = args.findIndex((arg) => typeof arg === "function");
  if (callbackIndex >= 0) {
    const callback = args[callbackIndex];
    args[callbackIndex] = function (...callbackArgs) {
      if (!readinessSent && process.send) {
        const address = this.address();
        if (address && typeof address === "object") {
          readinessSent = true;
          process.send({ type: "rootark-test-server-ready", port: address.port });
        }
      }
      return callback.apply(this, callbackArgs);
    };
  }
  return originalListen.apply(this, args);
};
require(${JSON.stringify(SERVER)});
`;
}

function request(port, requestPath, method = "GET", headers = {}, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: text, headers: res.headers }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(child) {
  let startupError = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { startupError += chunk; });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`server readiness timed out: ${startupError}`)), 10_000);
    child.on("message", (message) => {
      if (message?.type !== "rootark-test-server-ready") return;
      clearTimeout(timer);
      resolve(message.port);
    });
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", (code, signal) => { clearTimeout(timer); reject(new Error(`server exited before readiness (code=${code}, signal=${signal}): ${startupError}`)); });
  });
}

test("critical audit console output omits actor, target, user agent, and event details", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-console-"));
  const auditOutput = path.join(sandbox, "console-audit.jsonl");
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });
  const script = `
const fs = require("node:fs");
const auditOutput = ${JSON.stringify(auditOutput)};
console.error = (...args) => fs.appendFileSync(auditOutput, JSON.stringify(args) + "\\n");
${serverBootstrap()}
`;
  const child = spawn(process.execPath, ["-e", script], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: "0",
      DB_ENABLED: "false",
      CLOUD_STORAGE_PROVIDER: "local",
      NODE_ENV: "test",
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      TOTP_POLICY: "optional",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: ["ignore", "ignore", "pipe", "ipc"],
    windowsHide: true,
  });

  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 10_000);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
        child.kill();
      });
    }
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  const port = await waitForServer(child);
  const loginBody = JSON.stringify({ username: "admin", password: "admin123" });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(loginBody)),
  }, loginBody);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"];
  const sessionCookie = cookies.find((value) => value.startsWith("rootark_session=")).split(";", 1)[0];
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split(";", 1)[0].split("=", 2)[1];
  const updateBody = JSON.stringify({ permissions: { upload: false } });
  const update = await request(port, "/users/admin", "PUT", {
    cookie: `${sessionCookie}; rootark_csrf=${csrf}`,
    origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": csrf,
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(updateBody)),
    "user-agent": "synthetic-private-user-agent",
  }, updateBody);
  assert.equal(update.status, 200, update.body);

  const consoleRows = fs.readFileSync(auditOutput, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  const encodedEvent = JSON.stringify(consoleRows).replace(/\\\\n/g, " ");
  assert.match(encodedEvent, /user\.permission\.changed/, "critical audit event identity remains visible in console logs");
  assert.doesNotMatch(encodedEvent, /synthetic-private-user-agent|permissions|admin/, "private audit attributes remain only in the protected audit store");
  const storedAudit = JSON.parse(fs.readFileSync(path.join(sandbox, "data", "audit-logs.json"), "utf8"));
  const storedEvent = storedAudit.logs.find((entry) => entry.eventType === "user.permission.changed");
  assert.equal(storedEvent.actor.username, "admin");
  assert.equal(storedEvent.actor.userAgent, "synthetic-private-user-agent");
  assert.equal(storedEvent.details.changes["permissions.upload"].to, false);
});
