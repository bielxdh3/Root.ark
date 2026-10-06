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
  ];
  for (const [mountPath, handlers] of routeMiddleware) {
    assert.equal(source.includes(`app.use("${mountPath}",`), false, `${mountPath} must not use a prefix mount`);
    for (const handler of handlers) assert.ok(source.includes(handler), `missing direct middleware on ${handler}`);
  }
});

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

async function waitForServer(port) {
  const deadline = Date.now() + 10_000;
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

test("route rate limits enforce separate budgets despite direct-origin X-Forwarded-For spoofing", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-route-rate-limit-"));
  const port = await getUnusedPort();
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });

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
      ROUTE_RATE_LIMIT_MAX: "2",
      ROUTE_RATE_LIMIT_WINDOW_MS: "60000",
    },
    stdio: "ignore",
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

  assert.equal((await waitForServer(port)).status, 200);

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

test("cloud-backed list, search, and WebDAV PROPFIND stop before another provider listing at their limits", { timeout: 30_000 }, async (t) => {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-list-rate-limit-"));
  const port = await getUnusedPort();
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

  const child = spawn(process.execPath, [SERVER], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: String(port),
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
    stdio: "ignore",
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

  assert.equal((await waitForServer(port)).status, 200);
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
