const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const jwt = require("jsonwebtoken");
const test = require("node:test");
const Database = require("better-sqlite3");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");

function unusedPort() {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const port = probe.address().port;
      probe.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function request(port, requestPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method: "GET", headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.once("error", reject);
    req.end();
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited before listening");
    try {
      const response = await request(port, "/login.html");
      if (response.status === 200) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("disposable server did not listen");
}

async function runStoreOutageScenario(t, { fallbackEnabled, expectedStatus }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-auth-store-outage-"));
  const dataDirectory = path.join(directory, "data");
  const databasePath = path.join(dataDirectory, "rootark.sqlite");
  fs.mkdirSync(dataDirectory, { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const user = { username: "store-fixture", password: bcrypt.hashSync(crypto.randomBytes(24).toString("base64url"), 4), role: "admin", permissions: {}, sessionVersion: 0 };
  if (fallbackEnabled) fs.writeFileSync(path.join(dataDirectory, "users.local.json"), JSON.stringify([user]));
  const secret = crypto.randomBytes(48).toString("base64url");
  const port = await unusedPort();
  const databaseEnvironment = {
    ...process.env,
    DB_ENABLED: "true",
    DB_READ_FALLBACK_JSON: String(fallbackEnabled),
    DB_WRITE_LEGACY_JSON: "false",
    DATABASE_URL: databasePath,
    ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "false",
  };
  const prepare = [
    `process.chdir(${JSON.stringify(directory)});`,
    `process.env.DB_ENABLED = "true";`,
    `process.env.DATABASE_URL = ${JSON.stringify(databasePath)};`,
    `require(${JSON.stringify(path.join(ROOT, "db", "migrations"))}).runMigrations({ backup: false });`,
    `require(${JSON.stringify(path.join(ROOT, "repositories", "usersRepository"))}).saveUsers(${JSON.stringify([user])});`,
  ].join(" ");
  const initialized = spawnSync(process.execPath, ["-e", prepare], { cwd: directory, env: databaseEnvironment, encoding: "utf8" });
  assert.equal(initialized.status, 0, initialized.stderr || initialized.stdout);

  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    env: {
      ...databaseEnvironment,
      NODE_ENV: "test",
      PORT: String(port),
      JWT_SECRET: secret,
      BACKUP_ENABLED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
    },
    stdio: "ignore",
    windowsHide: true,
  });
  t.after(async () => {
    if (child.exitCode === null) {
      child.kill();
      await new Promise((resolve) => child.once("exit", resolve));
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });

  await waitForServer(port, child);
  const db = new Database(databasePath);
  try { db.exec("DROP TABLE users"); }
  finally { db.close(); }

  const token = jwt.sign({ username: user.username, sessionVersion: user.sessionVersion }, secret, { algorithm: "HS256", expiresIn: "1h" });
  const response = await request(port, "/auth/me", { cookie: `rootark_session=${token}` });
  assert.equal(response.status, expectedStatus, response.body);
  if (fallbackEnabled) {
    assert.equal(JSON.parse(response.body).username, user.username);
  } else {
    assert.deepEqual(JSON.parse(response.body), { error: "Autorizacao indisponivel" });
    assert.doesNotMatch(response.body, /no such table|sqlite|database/i);
  }
}

test("SQLite authentication failures remain distinct from revoked users and preserve explicit JSON fallback", async (t) => {
  await t.test("fallback disabled returns generic service unavailable", async (t) => {
    await runStoreOutageScenario(t, { fallbackEnabled: false, expectedStatus: 503 });
  });
  await t.test("explicit JSON read fallback still authenticates", async (t) => {
    await runStoreOutageScenario(t, { fallbackEnabled: true, expectedStatus: 200 });
  });
});
