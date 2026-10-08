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
const unzipper = require("unzipper");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;

function request(port, requestPath, { method = "GET", headers = {}, body, binary = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => { chunks.push(chunk); });
      res.on("end", () => {
        const responseBody = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body: binary ? responseBody : responseBody.toString() });
      });
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
  });
}

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

async function waitForServer(port) {
  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 100)); }
  }
  throw new Error("server did not start");
}

async function login(port, username, password) {
  const body = JSON.stringify({ username, password });
  const response = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(response.status, 200, response.body);
  const cookies = response.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  return { cookie: cookies.join("; "), csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1] };
}

function write(root, relativePath, bytes) {
  const target = path.join(root, relativePath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, bytes);
  return target;
}

function checkoutState(target) {
  try {
    const stat = fs.lstatSync(target);
    if (stat.isFile()) return { type: "file", size: stat.size, sha256: crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex") };
    if (stat.isDirectory()) return { type: "directory" };
    return { type: "other" };
  } catch (error) {
    if (error.code === "ENOENT") return { type: "absent" };
    throw error;
  }
}

function headers(port, session) {
  return { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf };
}

test("backup and restore stay in the child runtime root", { timeout: 45_000 }, async (t) => {
  const password = crypto.randomBytes(24).toString("base64url");
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-backup-runtime-"));
  const checkoutBefore = {
    backups: checkoutState(path.join(ROOT, "data", "backups")),
    history: checkoutState(path.join(ROOT, "data", "backup-history.json")),
    restoreTemp: checkoutState(path.join(ROOT, "data", "backups", ".restore-tmp")),
  };
  const runtimeJson = Buffer.from(`runtime-json-${crypto.randomUUID()}`);
  const runtimeUpload = Buffer.from(`runtime-upload-${crypto.randomUUID()}`);
  write(sandbox, "data/runtime-only.json", runtimeJson);
  write(sandbox, "uploads/runtime-folder/runtime-upload.txt", runtimeUpload);
  fs.cpSync(PUBLIC, path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "data", "users.json"), JSON.stringify([
    { username: "manager", password: bcrypt.hashSync(password, 10), role: "user", permissions: { manageBackups: true }, sessionVersion: 0 },
    { username: "ordinary", password: bcrypt.hashSync(password, 10), role: "user", permissions: {}, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(sandbox, "data", "folders.json"), JSON.stringify([]));

  const port = await getUnusedPort();
  const childEnv = { ...process.env, PORT: String(port), DB_ENABLED: "false", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", BACKUP_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true", BACKUP_INCLUDE_TEMP: "false", BACKUP_RETENTION_COUNT: "20", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  let child = spawn(process.execPath, [SERVER], { cwd: sandbox, env: childEnv, stdio: "ignore", windowsHide: true });
  const stopChild = async () => {
    if (child.exitCode === null) await new Promise((resolve) => {
      const timer = setTimeout(resolve, TIMEOUT_MS);
      child.once("exit", () => { clearTimeout(timer); resolve(); });
      child.kill();
    });
  };
  t.after(async () => {
    await stopChild();
    fs.rmSync(sandbox, { recursive: true, force: true });
  });

  assert.equal((await waitForServer(port)).status, 200);
  const manager = await login(port, "manager", password);
  const ordinary = await login(port, "ordinary", password);
  const deniedGet = await request(port, "/backups", { headers: { cookie: ordinary.cookie } });
  const deniedPostBody = JSON.stringify({ notes: "denied" });
  const deniedPost = await request(port, "/backups", { method: "POST", headers: { ...headers(port, ordinary), "content-type": "application/json", "content-length": Buffer.byteLength(deniedPostBody) }, body: deniedPostBody });
  assert.equal(deniedGet.status, 403); assert.equal(JSON.parse(deniedGet.body).error, "Permissao negada: manageBackups");
  assert.equal(deniedPost.status, 403); assert.equal(JSON.parse(deniedPost.body).error, "Permissao negada: manageBackups");
  assert.equal(fs.existsSync(path.join(sandbox, "data", "backups")), false);
  assert.equal(fs.existsSync(path.join(sandbox, "data", "backup-history.json")), false);

  const createBody = JSON.stringify({ notes: "runtime root" });
  const created = await request(port, "/backups", { method: "POST", headers: { ...headers(port, manager), "content-type": "application/json", "content-length": Buffer.byteLength(createBody) }, body: createBody });
  assert.equal(created.status, 201, created.body);
  const backup = JSON.parse(created.body).backup;
  assert.match(backup.id, /^[a-f0-9-]{36}$/i); assert.equal(backup.type, "manual"); assert.equal(backup.status, "success"); assert.equal(backup.createdBy, "manager"); assert.match(backup.filename, /^rootark-backup-.*\.zip$/); assert.match(backup.checksum, /^[a-f0-9]{64}$/); assert.ok(backup.sizeBytes > 0);
  const archivePath = path.join(sandbox, "data", "backups", backup.filename);
  assert.equal(fs.existsSync(archivePath), true); assert.equal(fs.existsSync(path.join(sandbox, "data", "backup-history.json")), true);
  assert.deepEqual(checkoutState(path.join(ROOT, "data", "backups")), checkoutBefore.backups);
  assert.deepEqual(checkoutState(path.join(ROOT, "data", "backup-history.json")), checkoutBefore.history);
  assert.equal(fs.existsSync(path.join(ROOT, "data", "backups", backup.filename)), false);
  const zip = await unzipper.Open.file(archivePath);
  const entries = zip.files.map((entry) => entry.path);
  assert.ok(entries.includes("data/runtime-only.json")); assert.ok(entries.includes("uploads/runtime-folder/runtime-upload.txt"));
  assert.equal(entries.some((entry) => entry.includes("checkout-only")), false); assert.equal(entries.some((entry) => entry.startsWith("data/backups/")), false); assert.equal(entries.some((entry) => path.isAbsolute(entry) || entry.split("/").includes("..")), false);
  assert.deepEqual(await zip.files.find((entry) => entry.path === "data/runtime-only.json").buffer(), runtimeJson);
  assert.deepEqual(await zip.files.find((entry) => entry.path === "uploads/runtime-folder/runtime-upload.txt").buffer(), runtimeUpload);
  assert.equal((await request(port, "/backups", { headers: { cookie: manager.cookie } })).status, 200);
  assert.equal((await request(port, "/backups/latest-status", { headers: { cookie: manager.cookie } })).status, 200);
  const manifest = await request(port, `/backups/${backup.id}/manifest`, { headers: { cookie: manager.cookie } });
  assert.equal(manifest.status, 200, manifest.body); assert.equal(JSON.parse(manifest.body).backup_id, backup.id);
  const download = await request(port, `/backups/${backup.id}/download`, { headers: { cookie: manager.cookie }, binary: true });
  assert.equal(download.status, 200); assert.ok(download.body.length > 0);
  assert.equal(crypto.createHash("sha256").update(download.body).digest("hex"), backup.checksum);
  assert.deepEqual(download.body, fs.readFileSync(archivePath));

  write(sandbox, "data/runtime-only.json", Buffer.from("mutated-json")); write(sandbox, "uploads/runtime-folder/runtime-upload.txt", Buffer.from("mutated-upload"));
  const invalidBody = JSON.stringify({ confirmation: "NO" });
  const invalid = await request(port, `/backups/${backup.id}/restore`, { method: "POST", headers: { ...headers(port, manager), "content-type": "application/json", "content-length": Buffer.byteLength(invalidBody) }, body: invalidBody });
  assert.equal(invalid.status, 400); assert.equal(JSON.parse(invalid.body).error, "Confirmacao invalida. Digite RESTORE para restaurar.");
  assert.deepEqual(fs.readFileSync(path.join(sandbox, "data", "runtime-only.json")), Buffer.from("mutated-json")); assert.equal(fs.readdirSync(path.join(sandbox, "data", "backups")).length, 1);

  await new Promise((resolve) => setTimeout(resolve, 1_100));
  const validBody = JSON.stringify({ confirmation: "RESTORE" });
  const restored = await request(port, `/backups/${backup.id}/restore`, { method: "POST", headers: { ...headers(port, manager), "content-type": "application/json", "content-length": Buffer.byteLength(validBody) }, body: validBody });
  assert.equal(restored.status, 200, restored.body);
  const restoredBody = JSON.parse(restored.body);
  assert.equal(restoredBody.message, "Backup restaurado"); assert.equal(restoredBody.backup.id, backup.id); assert.equal(restoredBody.preRestoreBackup.type, "pre-restore"); assert.equal(restoredBody.restartRecommended, true);
  assert.deepEqual(fs.readFileSync(path.join(sandbox, "data", "runtime-only.json")), runtimeJson); assert.deepEqual(fs.readFileSync(path.join(sandbox, "uploads", "runtime-folder", "runtime-upload.txt")), runtimeUpload);
  assert.equal(fs.existsSync(path.join(sandbox, "data", "backups", ".restore-tmp")), false);
  assert.equal((await request(port, "/backups", { headers: { cookie: manager.cookie } })).status, 503);
  await stopChild();
  child = spawn(process.execPath, [SERVER], { cwd: sandbox, env: childEnv, stdio: "ignore", windowsHide: true });
  assert.equal((await waitForServer(port)).status, 200);
  assert.equal((await request(port, "/backups", { headers: { cookie: manager.cookie } })).status, 200);
  const removed = await request(port, `/backups/${backup.id}`, { method: "DELETE", headers: headers(port, manager) });
  assert.equal(removed.status, 400, removed.body);
  assert.match(JSON.parse(removed.body).error, /unresolved provider inventory baseline/i);
  assert.equal(fs.existsSync(archivePath), true, "the selected baseline remains available until provider reconciliation completes");
  assert.equal(fs.existsSync(path.join(sandbox, "data", "backups", restoredBody.preRestoreBackup.filename)), true);
  assert.deepEqual(checkoutState(path.join(ROOT, "data", "backups")), checkoutBefore.backups);
  assert.deepEqual(checkoutState(path.join(ROOT, "data", "backup-history.json")), checkoutBefore.history);
  assert.deepEqual(checkoutState(path.join(ROOT, "data", "backups", ".restore-tmp")), checkoutBefore.restoreTemp);
  assert.equal(fs.existsSync(path.join(ROOT, "data", "backups", backup.filename)), false);
  assert.equal(fs.existsSync(path.join(ROOT, "data", "backups", restoredBody.preRestoreBackup.filename)), false);
});
