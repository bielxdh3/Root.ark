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
    ["/list", ['app.get("/list", fileListRateLimit, authenticate, requirePermission("listFiles"),']],
    ["/files/search", ['app.get("/files/search", fileSearchRateLimit, authenticate, requirePermission("listFiles"),']],
    ["/open-file", ['app.get("/open-file/:token/:name", openFileRedemptionRateLimit,']],
  ];
  for (const [mountPath, handlers] of routeMiddleware) {
    assert.equal(source.includes(`app.use("${mountPath}",`), false, `${mountPath} must not use a prefix mount`);
    for (const handler of handlers) assert.ok(source.includes(handler), `missing direct middleware on ${handler}`);
  }
});

function request(port, requestPath, method = "GET", headers = {}, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body, headers: res.headers }));
    });
    req.setTimeout(10_000, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
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
  fs.writeFileSync(path.join(sandbox, "uploads", "open-file-limit.txt"), "valid open-file token fixture");
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
      TOTP_POLICY: "optional",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      ROUTE_RATE_LIMIT_MAX: "2",
      ROUTE_RATE_LIMIT_WINDOW_MS: "60000",
      TRUSTED_PROXIES: "",
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
  const sessionCookie = login.headers["set-cookie"].find((value) => value.startsWith("rootark_session=")).split(";", 1)[0];
  const csrf = login.headers["set-cookie"].find((value) => value.startsWith("rootark_csrf=")).split(";", 1)[0].split("=", 2)[1];
  const tokenBody = JSON.stringify({ name: "open-file-limit.txt" });
  const issued = await request(port, "/file-open-token", "POST", {
    cookie: `${sessionCookie}; rootark_csrf=${csrf}`,
    origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": csrf,
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(tokenBody)),
  }, tokenBody);
  assert.equal(issued.status, 200, issued.body);
  const openUrl = JSON.parse(issued.body).url;
  const redemptions = await Promise.all([1, 2, 3].map((index) => request(port, openUrl, "GET", {
    "x-forwarded-for": `198.51.100.${index}`,
  })));
  assert.deepEqual(redemptions.map((response) => response.status), [200, 200, 429]);
  assert.equal(redemptions[0].body, "valid open-file token fixture");
  assert.equal(redemptions[2].headers["ratelimit-limit"], "2");
  assert.match(redemptions[2].body, /Muitas solicitações/);

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

test("open-file redemption rate limits by the client IP behind configured proxy hops", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-open-file-proxy-limit-"));
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", "proxy-open-file.txt"), "trusted proxy token fixture");
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
      TOTP_POLICY: "optional",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      ROUTE_RATE_LIMIT_MAX: "2",
      ROUTE_RATE_LIMIT_WINDOW_MS: "60000",
      TRUSTED_PROXIES: "127.0.0.1/32,10.0.0.0/8",
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
  const sessionCookie = login.headers["set-cookie"].find((value) => value.startsWith("rootark_session=")).split(";", 1)[0];
  const csrf = login.headers["set-cookie"].find((value) => value.startsWith("rootark_csrf=")).split(";", 1)[0].split("=", 2)[1];
  const tokenBody = JSON.stringify({ name: "proxy-open-file.txt" });
  const issued = await request(port, "/file-open-token", "POST", {
    cookie: `${sessionCookie}; rootark_csrf=${csrf}`,
    origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": csrf,
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(tokenBody)),
  }, tokenBody);
  assert.equal(issued.status, 200, issued.body);
  const openUrl = JSON.parse(issued.body).url;
  const proxyChain = { "x-forwarded-for": "198.51.100.20, 10.0.0.7" };
  const redemptions = await Promise.all([1, 2, 3].map(() => request(port, openUrl, "GET", proxyChain)));
  assert.deepEqual(redemptions.map((response) => response.status), [200, 200, 429]);
  const otherClient = await request(port, openUrl, "GET", { "x-forwarded-for": "198.51.100.21, 10.0.0.7" });
  assert.equal(otherClient.status, 200, otherClient.body);
});

test("cloud-backed list, search, and WebDAV PROPFIND stop before another provider listing at their limits", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-list-rate-limit-"));
  const provider = http.createServer();
  let providerListings = 0;
  provider.on("request", (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.method === "GET" && url.searchParams.get("list-type") === "2") {
      providerListings += 1;
      res.writeHead(200, { "content-type": "application/xml" }).end(
        "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>rootark-test</Name><Prefix>rootark/uploads/root/</Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"
      );
      return;
    }
    res.writeHead(404, { "content-type": "application/xml" }).end("<Error><Code>NoSuchKey</Code></Error>");
  });
  await new Promise((resolve) => provider.listen(0, "127.0.0.1", resolve));
  const providerPort = provider.address().port;
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: "secondary", name: "Pasta secundaria", createdBy: "admin", allowedUsers: [], isRoot: false },
  ]));
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });

  const child = spawn(process.execPath, ["-e", serverBootstrap()], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: "0",
      DB_ENABLED: "false",
      CLOUD_STORAGE_PROVIDER: "s3",
      CLOUD_STORAGE_PREFIX: "rootark",
      AWS_S3_BUCKET: "rootark-test",
      AWS_REGION: "us-east-1",
      AWS_ENDPOINT_URL: `http://127.0.0.1:${providerPort}`,
      AWS_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "fixture-access-key",
      AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
      TRUSTED_PROXIES: "",
      NODE_ENV: "test",
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      WEBDAV_ENABLED: "true",
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
    await new Promise((resolve) => provider.close(resolve));
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  const port = await waitForServer(child);
  const body = JSON.stringify({ username: "admin", password: "admin123" });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json",
    "content-length": String(Buffer.byteLength(body)),
  }, body);
  assert.equal(login.status, 200, login.body);
  const cookie = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]).join("; ");
  const basic = `Basic ${Buffer.from("admin:admin123").toString("base64")}`;

  for (const [name, send, successStatus] of [
    ["/list", (index) => request(port, "/list", "GET", { cookie, "x-forwarded-for": `198.51.100.${index}` }), 200],
    ["/files/search", (index) => request(port, "/files/search?folderId=all", "GET", { cookie, "x-forwarded-for": `198.51.100.${index}` }), 200],
    ["WebDAV PROPFIND", (index) => request(port, "/dav", "PROPFIND", { authorization: basic, depth: "1", "x-forwarded-for": `198.51.100.${index}` }), 207],
  ]) {
    await t.test(`${name} rejects unauthorized work and limits provider enumeration`, async () => {
      const listingsBeforeAllowedRequests = providerListings;
      if (name !== "WebDAV PROPFIND") {
        const unauthenticated = await request(port, name === "/files/search" ? "/files/search?folderId=all" : "/list", "GET", {
          "x-forwarded-for": "198.51.100.99",
        });
        assert.equal(unauthenticated.status, 401, `${name} must still authenticate before doing provider work`);
        assert.equal(providerListings, listingsBeforeAllowedRequests, `${name} unauthenticated request must not enumerate the provider`);
      }
      const first = await send(1);
      assert.equal(first.status, successStatus, `${name} first request: ${first.body}`);
      const second = name === "WebDAV PROPFIND" ? await send(2) : null;
      if (second) assert.equal(second.status, successStatus, `${name} second request: ${second.body}`);
      assert.equal(providerListings - listingsBeforeAllowedRequests, name === "/files/search" ? 2 : name === "WebDAV PROPFIND" ? 2 : 1,
        `${name} accepted request must reach the disposable provider`);
      const listingsBeforeRejectedRequest = providerListings;
      const rejected = await send(name === "WebDAV PROPFIND" ? 3 : 2);
      assert.equal(rejected.status, 429, `${name} must be rate limited before provider listing`);
      assert.equal(providerListings, listingsBeforeRejectedRequest, `${name} must not enumerate the provider after 429`);
      assert.equal(rejected.headers["ratelimit-limit"], "2");
    });
  }
});
