const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;
const FOLDER_ID = "trash-safety";

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

function request(port, requestPath, { method = "GET", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
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

async function login(port, username, password) {
  const body = JSON.stringify({ username, password });
  const response = await request(port, "/auth/login", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.equal(response.status, 200);
  const cookies = response.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  return {
    cookie: cookies.join("; "),
    csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1],
  };
}

function statState(target) {
  try {
    const stat = fs.statSync(target);
    return { exists: true, size: stat.size, mtimeMs: stat.mtimeMs };
  } catch (error) {
    if (error.code === "ENOENT") return { exists: false };
    throw error;
  }
}

function isContained(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative !== "" && relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

test("file trash stays inside the child server runtime root", { timeout: 30_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const sandbox = fs.mkdtempSync(path.join(ROOT, ".tmp-trash-runtime-root-"));
  const source = path.join(sandbox, "uploads", FOLDER_ID, "keep.txt");
  const bytes = Buffer.from("runtime-root isolation\n");
  const checkoutJson = path.join(ROOT, "data", "trash-items.json");
  const checkoutJsonBefore = statState(checkoutJson);
  fs.mkdirSync(path.dirname(source), { recursive: true });
  fs.mkdirSync(path.join(sandbox, "data"), { recursive: true });
  fs.cpSync(PUBLIC, path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(source, bytes);
  fs.writeFileSync(path.join(sandbox, "data", "users.json"), JSON.stringify([
    { username: "deleter", password: bcrypt.hashSync(password, 10), role: "user", permissions: { delete: true, listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(sandbox, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: FOLDER_ID, name: "Trash safety", createdBy: "deleter", allowedUsers: [] },
  ]));

  const port = await getUnusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: sandbox,
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "false",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      TRASH_ENABLED: "true",
      TRASH_AUTO_CLEANUP_ENABLED: "false",
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
  const session = await login(port, "deleter", password);
  const legacyDelete = await request(port, `/delete/keep.txt?folderId=${FOLDER_ID}`, { headers: { cookie: session.cookie } });
  assert.equal(legacyDelete.status, 405, "legacy GET cannot move a file to trash");
  assert.equal(fs.existsSync(source), true, "legacy GET leaves the source unchanged");
  const deleted = await request(port, `/delete/keep.txt?folderId=${FOLDER_ID}`, {
    method: "POST",
    headers: { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf },
  });
  const result = JSON.parse(deleted.body);
  const sandboxJson = path.join(sandbox, "data", "trash-items.json");

  assert.equal(deleted.status, 200, deleted.body);
  assert.equal(result.message, "Movido para lixeira");
  assert.equal(fs.existsSync(source), false);
  assert.equal(fs.existsSync(sandboxJson), true);
  const items = JSON.parse(fs.readFileSync(sandboxJson, "utf8"));
  assert.equal(items.length, 1);
  const [item] = items;
  assert.equal(item.originalFileName, "keep.txt");
  assert.match(item.id, /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i);
  assert.equal(path.isAbsolute(item.trashPath), false);
  const trashRoot = path.join(sandbox, "data", "trash");
  const physicalPath = path.resolve(trashRoot, item.trashPath);
  assert.equal(isContained(trashRoot, physicalPath), true);
  assert.deepEqual(fs.readFileSync(physicalPath), bytes);
  assert.equal(fs.existsSync(path.join(ROOT, "data", "trash", "files", item.id, "keep.txt")), false);
  assert.deepEqual(statState(checkoutJson), checkoutJsonBefore);

  const listed = await request(port, "/trash", { headers: { cookie: session.cookie } });
  assert.equal(listed.status, 200);
  assert.equal(JSON.parse(listed.body).items.find((entry) => entry.id === item.id)?.originalFileName, "keep.txt");
});
