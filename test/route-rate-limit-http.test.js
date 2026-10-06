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

test("rate limits are passed directly to each protected route handler", () => {
  const source = fs.readFileSync(SERVER, "utf8");
  const routeMiddleware = [
    ["/versions", [
      'app.get("/versions/:filename", versionsRateLimit,',
      'app.post("/versions/:filename/initialize", versionsRateLimit,',
      'app.delete("/versions/:filename/v/:version", versionsRateLimit,',
    ]],
    ["/share", [
      'app.post("/share", shareRateLimit,',
      'app.get("/share/:token", shareRateLimit,',
      'app.post("/share/:token/password", shareRateLimit,',
      'app.post("/share/:token/view", shareRateLimit,',
      'app.get("/share/:token/download", shareRateLimit,',
      'app.post("/share/:token/download", shareRateLimit,',
      'app.get("/share/:token/preview", shareRateLimit,',
      'app.get("/share/:token/qr", shareRateLimit,',
      'app.get("/share/:token/file", shareRateLimit,',
    ]],
    ["/pending/repair", ['app.post("/pending/repair", pendingRepairRateLimit,']],
    ["/approve", [
      'app.get("/approve/:name", approveRateLimit,',
      'app.post("/approve/:name", approveRateLimit,',
    ]],
    ["/reject", [
      'app.get("/reject/:name", rejectRateLimit,',
      'app.post("/reject/:name", rejectRateLimit,',
    ]],
    ["/delete", [
      'app.get("/delete/:name", deleteRateLimit,',
      'app.post("/delete/:name", deleteRateLimit,',
    ]],
    ["/file-access", [
      'app.get("/file-access", fileAccessRateLimit,',
      'app.put("/file-access", fileAccessRateLimit,',
    ]],
    ["/file-temporary", ['app.put("/file-temporary", fileTemporaryRateLimit,']],
  ];
  for (const [mountPath, handlers] of routeMiddleware) {
    assert.equal(source.includes(`app.use("${mountPath}",`), false, `${mountPath} must not use a prefix mount`);
    for (const handler of handlers) assert.ok(source.includes(handler), `missing direct middleware on ${handler}`);
  }
});

function request(port, requestPath, method = "GET", headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.setTimeout(10_000, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end();
  });
}

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

async function waitForServer(child) {
  let startupError = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { startupError += chunk; });
  const port = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => finish(new Error("server readiness timed out")), 10_000);
    const cleanup = () => {
      clearTimeout(timer);
      child.off("message", onMessage);
      child.off("error", onError);
      child.off("exit", onExit);
    };
    const finish = (error, readyPort) => {
      cleanup();
      error ? reject(error) : resolve(readyPort);
    };
    const onMessage = (message) => {
      if (message?.type !== "rootark-test-server-ready" || !Number.isInteger(message.port) || message.port < 1) {
        return finish(new Error("server sent invalid readiness message"));
      }
      finish(null, message.port);
    };
    const onError = (error) => finish(error);
    const onExit = (code, signal) => finish(new Error(`server exited before readiness (code=${code}, signal=${signal}): ${startupError.slice(-2_000)}`));
    child.on("message", onMessage);
    child.once("error", onError);
    child.once("exit", onExit);
    if (child.exitCode !== null || child.signalCode !== null) onExit(child.exitCode, child.signalCode);
  });
  const response = await request(port, "/login.html");
  if (response.status !== 200 || !response.body.includes('aria-labelledby="login-title"')) {
    throw new Error(`server readiness probe failed (status=${response.status})`);
  }
  return port;
}

test("route rate limits enforce separate budgets despite direct-origin X-Forwarded-For spoofing", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-route-rate-limit-"));
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });

  const child = spawn(process.execPath, ["-e", serverBootstrap()], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: "0",
      DB_ENABLED: "false",
      CLOUD_STORAGE_PROVIDER: "local",
      NODE_ENV: "test",
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      ROUTE_RATE_LIMIT_MAX: "2",
      ROUTE_RATE_LIMIT_WINDOW_MS: "60000",
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

  const repairResponses = await Promise.all([1, 2, 3].map((index) => request(port, "/pending/repair", "POST", {
    "x-forwarded-for": `198.51.100.${index}`,
  })));
  assert.deepEqual(repairResponses.map((response) => response.status), [401, 401, 429]);
  assert.equal(repairResponses[2].headers["ratelimit-limit"], "2");
  assert.equal(repairResponses[2].headers["ratelimit-remaining"], "0");
  assert.match(repairResponses[2].body, /Muitas solicitações/);

  const shareResponses = await Promise.all([1, 2, 3].map((index) => request(port, "/share/not-a-real-token", "GET", {
    "x-forwarded-for": `203.0.113.${index}`,
  })));
  assert.deepEqual(shareResponses.map((response) => response.status), [404, 404, 429]);
  assert.equal(shareResponses[2].headers["ratelimit-limit"], "2");
  assert.match(shareResponses[2].body, /Muitas solicitações/);
});
