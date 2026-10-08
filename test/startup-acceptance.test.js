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

function sanitize(output, secrets) {
  return secrets.reduce((value, secret) => value.split(secret).join("[redacted]"), output);
}

function waitForExit(child, timeoutMs, secrets) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`process did not exit within ${timeoutMs}ms`)), timeoutMs);
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  }).catch((error) => {
    throw new Error(sanitize(error.message, secrets));
  });
}

function startServer({ cwd, port, jwtSecret, envOverrides = {} }) {
  const env = { ...process.env, PORT: String(port), DB_ENABLED: "false" };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  delete env.ROOTARK_RESTORE_INSTANCE_COUNT;
  Object.assign(env, envOverrides);
  if (jwtSecret === undefined) delete env.JWT_SECRET;
  else env.JWT_SECRET = jwtSecret;
  const child = spawn(process.execPath, [SERVER], {
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  let output = "";
  child.stdout.on("data", (chunk) => { output += chunk; });
  child.stderr.on("data", (chunk) => { output += chunk; });
  return { child, output: () => output };
}

async function request(port) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: "/login.html" }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.setTimeout(1_000, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
  });
}

async function waitForServer(port, secrets) {
  const deadline = Date.now() + TIMEOUT_MS;
  let lastError;
  while (Date.now() < deadline) {
    try {
      return await request(port);
    } catch (error) {
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(sanitize(`server did not become reachable: ${lastError?.message || "unknown error"}`, secrets));
}

async function stop(child, secrets) {
  if (!child) return;
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  await waitForExit(child, TIMEOUT_MS, secrets);
}

function createSandbox() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-startup-"));
  fs.symlinkSync(PUBLIC, path.join(dir, "public"), "junction");
  return dir;
}

test("startup accepts only an explicit strong JWT_SECRET", { timeout: 45_000 }, async (t) => {
  const weakSecret = "rootark-test-weak-secret";
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const secrets = [weakSecret, strongSecret];
  const sandboxes = [];
  let running;
  t.after(async () => {
    await stop(running?.child, secrets);
    for (const dir of sandboxes) fs.rmSync(dir, { recursive: true, force: true });
  });

  for (const [name, jwtSecret] of [["missing", undefined], ["weak", weakSecret]]) {
    const cwd = createSandbox();
    sandboxes.push(cwd);
    const port = await getUnusedPort();
    const launched = startServer({ cwd, port, jwtSecret });
    const result = await waitForExit(launched.child, TIMEOUT_MS, secrets);
    const output = sanitize(launched.output(), secrets);
    assert.notEqual(result.code, 0, `${name} secret unexpectedly succeeded`);
    assert.match(output, /JWT_SECRET deve ser definido explicitamente/);
    assert.equal(output.includes("[redacted]"), false, `${name} secret was echoed`);
  }

  const cwd = createSandbox();
  sandboxes.push(cwd);
  const port = await getUnusedPort();
  running = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "test", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" } });
  assert.equal(await waitForServer(port, secrets), 200);
  await stop(running.child, secrets);
  assert.equal(sanitize(running.output(), secrets).includes("[redacted]"), false, "strong secret was echoed");
});

test("startup loads .env from the working directory and preserves explicit environment values", { timeout: 45_000 }, async (t) => {
  const fileSecret = crypto.randomBytes(48).toString("base64url");
  const explicitSecret = crypto.randomBytes(48).toString("base64url");
  const weakFileSecret = "rootark-test-weak-env-file-secret";
  const secrets = [fileSecret, explicitSecret, weakFileSecret];
  const sandboxes = [];
  const launchedServers = [];

  t.after(async () => {
    for (const launched of launchedServers) await stop(launched.child, secrets);
    for (const dir of sandboxes) fs.rmSync(dir, { recursive: true, force: true });
  });

  const envOnlyCwd = createSandbox();
  sandboxes.push(envOnlyCwd);
  fs.writeFileSync(path.join(envOnlyCwd, ".env"), `JWT_SECRET=${fileSecret}\n`);
  const envOnlyPort = await getUnusedPort();
  const envOnlyServer = startServer({ cwd: envOnlyCwd, port: envOnlyPort, jwtSecret: undefined, envOverrides: { NODE_ENV: "test", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" } });
  launchedServers.push(envOnlyServer);
  assert.equal(await waitForServer(envOnlyPort, secrets), 200);
  await stop(envOnlyServer.child, secrets);
  assert.equal(sanitize(envOnlyServer.output(), secrets).includes("[redacted]"), false, ".env secret was echoed");

  const explicitCwd = createSandbox();
  sandboxes.push(explicitCwd);
  fs.writeFileSync(path.join(explicitCwd, ".env"), `JWT_SECRET=${weakFileSecret}\n`);
  const explicitPort = await getUnusedPort();
  const explicitServer = startServer({ cwd: explicitCwd, port: explicitPort, jwtSecret: explicitSecret, envOverrides: { NODE_ENV: "test", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" } });
  launchedServers.push(explicitServer);
  assert.equal(await waitForServer(explicitPort, secrets), 200);
  await stop(explicitServer.child, secrets);
  assert.equal(sanitize(explicitServer.output(), secrets).includes("[redacted]"), false, "JWT secret was echoed");
});

test("fresh production bootstrap fails closed instead of creating default accounts", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /No users are configured/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
  assert.equal(launched.output().includes("admin123"), false);
  assert.equal(launched.output().includes("user123"), false);
});

test("production bootstrap rejects seed usernames that collide after normalization", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  const passwordHash = bcrypt.hashSync(crypto.randomBytes(32).toString("base64url"), 10);
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify([
    { username: "Admin", password: passwordHash, role: "admin", permissions: {} },
    { username: " admin ", password: passwordHash, role: "user", permissions: {} },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /The configured user seed is invalid/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
});

test("production seed import requires explicit opt-in and does not add default users", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  const password = crypto.randomBytes(32).toString("base64url");
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify([
    { username: "seed-admin", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {}, sessionVersion: 0 },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true" } });
  t.after(async () => { await stop(launched.child, [strongSecret, password]); fs.rmSync(cwd, { recursive: true, force: true }); });

  assert.equal(await waitForServer(port, [strongSecret, password]), 200);
  const users = JSON.parse(fs.readFileSync(path.join(cwd, "data", "users.local.json"), "utf8"));
  assert.deepEqual(users.map((user) => user.username), ["seed-admin"]);
  assert.equal(launched.output().includes("admin123"), false);
  assert.equal(launched.output().includes("user123"), false);
});

test("production refuses a secure user seed unless bootstrap import is explicitly enabled", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify([
    { username: "seed-admin", password: bcrypt.hashSync(crypto.randomBytes(32).toString("base64url"), 10), role: "admin", permissions: {} },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /User seed import requires ROOTARK_BOOTSTRAP_USERS_FROM_SEED=true/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
});

test("non-production seed import also requires explicit bootstrap opt-in", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify([
    { username: "seed-admin", password: bcrypt.hashSync(crypto.randomBytes(32).toString("base64url"), 10), role: "admin", permissions: {} },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "staging" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await Promise.race([
    new Promise((resolve) => launched.child.once("exit", (code, signal) => resolve({ code, signal }))),
    new Promise((resolve) => setTimeout(() => resolve(null), 5_000)),
  ]);
  assert.ok(result, "startup should fail closed instead of importing a seed without opt-in");
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /User seed import requires ROOTARK_BOOTSTRAP_USERS_FROM_SEED=true/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
});

test("production rejects plaintext or malformed seed credentials", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify([
    { username: "seed-admin", password: "plain-secret", role: "admin", permissions: {} },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /The configured user seed is invalid/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
});

test("default accounts require explicit non-production development/test opt-in", { timeout: 30_000 }, async (t) => {
  const sandboxes = [];
  const launches = [];
  t.after(async () => {
    for (const launched of launches) await stop(launched.child, []);
    for (const cwd of sandboxes) fs.rmSync(cwd, { recursive: true, force: true });
  });

  for (const nodeEnv of ["development", "test"]) {
    const cwd = createSandbox();
    sandboxes.push(cwd);
    const strongSecret = crypto.randomBytes(48).toString("base64url");
    const port = await getUnusedPort();
    const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: nodeEnv, ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" } });
    launches.push(launched);
    assert.equal(await waitForServer(port, [strongSecret]), 200, nodeEnv);
    const users = JSON.parse(fs.readFileSync(path.join(cwd, "data", "users.local.json"), "utf8"));
    assert.deepEqual(users.map((user) => user.username), ["admin", "user"], nodeEnv);
    assert.equal(bcrypt.compareSync("admin123", users[0].password), true, nodeEnv);
    assert.equal(bcrypt.compareSync("user123", users[1].password), true, nodeEnv);
  }
});

test("production refuses a persisted development bootstrap account until its password is changed", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  fs.writeFileSync(path.join(cwd, "data", "users.local.json"), JSON.stringify([
    { username: "admin", password: bcrypt.hashSync("admin123", 10), role: "admin", permissions: {} },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /development bootstrap credentials must be changed/i);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), true, "the existing account store is preserved for operator recovery");
});

test("production startup fails when session cookies are explicitly configured without Secure", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production", SESSION_COOKIE_SECURE: "false" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /Production session cookies must use the Secure attribute/);
});

test("production emits Secure session cookies and reports readiness only with that policy", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  fs.mkdirSync(path.join(cwd, "data"), { recursive: true });
  const password = crypto.randomBytes(32).toString("base64url");
  fs.writeFileSync(path.join(cwd, "data", "users.json"), JSON.stringify([
    { username: "seed-admin", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {} },
  ]));
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const masterKey = crypto.randomBytes(32).toString("base64");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: {
    NODE_ENV: "production",
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
    TOTP_POLICY: "optional",
    SERVER_MASTER_KEY: masterKey,
  } });
  t.after(async () => { await stop(launched.child, [strongSecret, masterKey, password]); fs.rmSync(cwd, { recursive: true, force: true }); });
  assert.equal(await waitForServer(port, [strongSecret, masterKey, password]), 200);

  const readyResponse = await new Promise((resolve, reject) => {
    http.get({ host: "127.0.0.1", port, path: "/ready" }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode)); }).once("error", reject);
  });
  assert.equal(readyResponse, 200);
  const body = JSON.stringify({ username: "seed-admin", password });
  const login = await new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: "/auth/login", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) } }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode, cookies: res.headers["set-cookie"] || [] }));
    });
    req.once("error", reject);
    req.end(body);
  });
  assert.equal(login.status, 200);
  assert.equal(login.cookies.length, 2);
  assert.ok(login.cookies.every((cookie) => /; Secure(?:;|$)/i.test(cookie)));
});

test("fresh test bootstrap also fails closed when the explicit dev/test opt-in is absent", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "test" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /No users are configured/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
});

test("declared multi-instance deployment fails closed while auth state is process-local", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({
    cwd,
    port,
    jwtSecret: strongSecret,
    envOverrides: { NODE_ENV: "development", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", ROOTARK_RESTORE_INSTANCE_COUNT: "2" },
  });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await Promise.race([
    new Promise((resolve) => launched.child.once("exit", (code, signal) => resolve({ code, signal }))),
    new Promise((resolve) => setTimeout(() => resolve(null), 5_000)),
  ]);
  assert.ok(result, "server startup must reject a declared multi-instance topology without shared auth state");
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /authentication state is process-local/i);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
  assert.equal(fs.existsSync(path.join(cwd, "data", ".rootark-active-requests")), false);
});

test("production refuses the development-default opt-in", { timeout: 30_000 }, async (t) => {
  const cwd = createSandbox();
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const port = await getUnusedPort();
  const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides: { NODE_ENV: "production", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true" } });
  t.after(async () => { await stop(launched.child, [strongSecret]); fs.rmSync(cwd, { recursive: true, force: true }); });

  const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret]);
  assert.notEqual(result.code, 0);
  assert.match(launched.output(), /No users are configured/);
  assert.equal(fs.existsSync(path.join(cwd, "data", "users.local.json")), false);
});

test("startup rejects invalid TOTP policy configuration without echoing raw values", { timeout: 45_000 }, async (t) => {
  const strongSecret = crypto.randomBytes(48).toString("base64url");
  const cases = [
    ["invalid mode", { TOTP_POLICY: "typo-mode" }, "typo-mode"],
    ["blank roles", { TOTP_POLICY: "role-required", TOTP_REQUIRED_ROLES: "   " }, null],
  ];
  const sandboxes = [];
  t.after(() => { for (const dir of sandboxes) fs.rmSync(dir, { recursive: true, force: true }); });

  for (const [name, envOverrides, rawValue] of cases) {
    const cwd = createSandbox();
    sandboxes.push(cwd);
    const port = await getUnusedPort();
    const launched = startServer({ cwd, port, jwtSecret: strongSecret, envOverrides });
    const result = await waitForExit(launched.child, TIMEOUT_MS, [strongSecret, rawValue].filter(Boolean));
    const output = sanitize(launched.output(), [strongSecret, rawValue].filter(Boolean));
    assert.notEqual(result.code, 0, `${name} unexpectedly succeeded`);
    assert.match(output, /Configuracao TOTP invalida/);
    if (rawValue) assert.equal(output.includes(rawValue), false, `${name} value was echoed`);
  }
});
