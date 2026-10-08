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
const { createFileLifecycleLock } = require("../services/fileLifecycleLock");

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

function request(port, requestPath) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: requestPath }, (res) => {
      res.resume();
      res.once("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
  });
}

function startS3Fixture({ failListings = false, failListingPrefixes = [] } = {}) {
  let markDeleteStarted;
  let releaseDelete;
  const deleteStarted = new Promise((resolve) => { markDeleteStarted = resolve; });
  const deleteReleased = new Promise((resolve) => { releaseDelete = resolve; });
  const deleteKeys = [];
  const listPrefixes = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    if (req.method === "DELETE") {
      deleteKeys.push(decodeURIComponent(url.pathname.replace(/^\/fixture-bucket\//, "")));
      markDeleteStarted();
      return deleteReleased.then(() => {
        res.writeHead(204);
        res.end();
      });
    }
    if (req.method === "GET" && url.searchParams.has("list-type")) {
      const requestedPrefix = url.searchParams.get("prefix") || "";
      listPrefixes.push(requestedPrefix);
      if (failListings || failListingPrefixes.some((prefix) => requestedPrefix.includes(prefix))) {
        res.writeHead(503, { "content-type": "application/xml" });
        res.end("<Error><Code>ServiceUnavailable</Code></Error>");
        return;
      }
      res.writeHead(200, { "content-type": "application/xml" });
      res.end("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>fixture-bucket</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>");
      return;
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      port: server.address().port,
      deleteKeys,
      listPrefixes,
      deleteStarted,
      releaseDelete,
    }));
  });
}

function requestJson(port, requestPath, body, headers = {}) {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: requestPath,
      method: "PUT",
      headers: { ...headers, "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
    }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body: text }));
    });
    req.once("error", reject);
    req.end(payload);
  });
}

async function waitForServer(port, child, getOutput) {
  const deadline = Date.now() + 15_000;
  let lastStatus = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`disposable server exited before listening: ${getOutput()}`);
    try {
      lastStatus = await request(port, "/login.html");
      if (lastStatus === 200) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 40));
  }
  throw new Error(`disposable server did not serve login (last status ${lastStatus}): ${getOutput()}`);
}

async function waitForTrashStatus(trashFile, status, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const items = JSON.parse(fs.readFileSync(trashFile, "utf8"));
      if (items[0]?.status === status) return items[0];
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return null;
}

test("expired cloud trash cleanup holds the lifecycle lock through persisted provider deletion", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-expired-cloud-trash-"));
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), process.platform === "win32" ? "junction" : "dir");
  const cloud = await startS3Fixture();
  const port = await unusedPort();
  const id = "11111111-1111-4111-8111-111111111111";
  const name = "expired-cloud.txt";
  const oldDate = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000).toISOString();
  const trashFile = path.join(directory, "data", "trash-items.json");
  const trashPayload = path.join(directory, "data", "trash", "files", id, name);
  fs.mkdirSync(path.dirname(trashPayload), { recursive: true });
  fs.writeFileSync(trashPayload, "disposable expired trash bytes");
  fs.writeFileSync(trashFile, JSON.stringify([{
    id,
    itemType: "file",
    originalFolderId: "root",
    originalFolderName: "",
    originalFileName: name,
    storedFileName: name,
    originalPath: path.join(directory, "uploads", name),
    trashPath: path.join("files", id, name),
    deletedBy: "fixture",
    deletedAt: oldDate,
    sizeBytes: Buffer.byteLength("disposable expired trash bytes"),
    metadata: {},
    restoreMetadata: { versions: { currentVersion: 1, versions: [] } },
    status: "trashed",
  }]));

  let childOutput = "";
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "false",
      NODE_ENV: "test",
      ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      CLOUD_STORAGE_PROVIDER: "s3",
      AWS_S3_BUCKET: "fixture-bucket",
      AWS_REGION: "us-east-1",
      AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`,
      AWS_S3_PRINCIPAL_ID: "fixture-account",
      AWS_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "fixture-access-key",
      AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
      TRASH_ENABLED: "true",
      TRASH_AUTO_CLEANUP_ENABLED: "true",
      TRASH_RETENTION_DAYS: "1",
    },
  });
  child.stdout.setEncoding("utf8").on("data", (chunk) => { childOutput += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { childOutput += chunk; });
  t.after(async () => {
    cloud.releaseDelete();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    if (child.exitCode === null && child.signalCode === null) await new Promise((resolve) => child.once("exit", resolve));
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  await waitForServer(port, child, () => childOutput);
  await cloud.deleteStarted;
  assert.deepEqual(cloud.deleteKeys, ["rootark/uploads/root/expired-cloud.txt"]);
  assert.equal((await waitForTrashStatus(trashFile, "remote_delete_pending"))?.status, "remote_delete_pending");

  const locks = createFileLifecycleLock({
    directory: path.join(directory, "data", ".rootark-cloud-file-locks"),
    timeoutMs: 5000,
    pollMs: 5,
  });
  let mutationSettled = false;
  const replacementMutation = locks.run("root", name, () => { mutationSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 150));
  assert.equal(mutationSettled, false, "same-name mutation waits until the provider delete finishes");

  cloud.releaseDelete();
  await replacementMutation;
  assert.equal(mutationSettled, true);
  assert.equal((await waitForTrashStatus(trashFile, "permanently_deleted"))?.status, "permanently_deleted");
});

test("expired folder stays unavailable when cloud cleanup fails and cannot be reactivated", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-expired-folder-cloud-failure-"));
  const dataDir = path.join(directory, "data");
  const oldExpiry = new Date(Date.now() - 60_000).toISOString();
  const password = crypto.randomBytes(24).toString("base64url");
  const cloud = await startS3Fixture({ failListingPrefixes: ["rootark/temp/expired-folder"] });
  const port = await unusedPort();
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads", "expired-folder"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp", "expired-folder"), { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), process.platform === "win32" ? "junction" : "dir");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {}, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    { id: "expired-folder", name: "Expired", createdBy: "tester", allowedUsers: ["tester"], isRoot: false, expiresAt: oldExpiry },
  ]));
  const protectedFile = path.join(directory, "uploads", "expired-folder", "protected.txt");
  const permissionsPath = path.join(dataDir, "file-permissions.json");
  fs.writeFileSync(protectedFile, "disposable protected fixture");
  fs.writeFileSync(permissionsPath, JSON.stringify({
    "expired-folder/protected.txt": { folderId: "expired-folder", fileName: "protected.txt", owner: "tester", public: false, users: { tester: { read: true, edit: false } } },
  }));
  let output = "";
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "false",
      NODE_ENV: "test",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      CLOUD_STORAGE_PROVIDER: "s3",
      AWS_S3_BUCKET: "fixture-bucket",
      AWS_REGION: "us-east-1",
      AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`,
      AWS_S3_PRINCIPAL_ID: "fixture-account",
      AWS_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "fixture-access-key",
      AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
      TOTP_POLICY: "optional",
    },
  });
  child.stdout.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    if (child.exitCode === null && child.signalCode === null) await new Promise((resolve) => child.once("exit", resolve));
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  await waitForServer(port, child, () => output);
  const cleanupDeadline = Date.now() + 5000;
  while (!output.includes("Falha ao limpar pasta temporaria:") && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.match(output, /Falha ao limpar pasta temporaria: Provider operation failed/, "provider failure must be exercised before checking reactivation");
  assert.ok(cloud.listPrefixes.some((prefix) => prefix.includes("rootark/uploads/expired-folder")), "the upload prefix was listed successfully");
  assert.ok(cloud.listPrefixes.some((prefix) => prefix.includes("rootark/temp/expired-folder")), "the temp prefix failure was injected after the upload prefix request");
  const foldersPath = path.join(dataDir, "folders.json");
  const expiredFolder = JSON.parse(fs.readFileSync(foldersPath, "utf8")).find((folder) => folder.id === "expired-folder");
  assert.equal(expiredFolder.expiresAt, oldExpiry);
  assert.equal(fs.readFileSync(protectedFile, "utf8"), "disposable protected fixture", "local file bytes remain intact while provider deletion is incomplete");
  assert.equal(JSON.parse(fs.readFileSync(permissionsPath, "utf8"))["expired-folder/protected.txt"].public, false, "file permissions remain intact while provider deletion is incomplete");

  const loginBody = JSON.stringify({ username: "tester", password });
  const login = await new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: "/auth/login",
      method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) },
    }, (res) => {
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
    });
    req.once("error", reject);
    req.end(loginBody);
  });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const revive = await requestJson(port, "/folders/expired-folder/temporary", { expiresAt: null }, {
    cookie,
    origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": csrf,
  });
  assert.equal(revive.status, 409, revive.body);
  assert.equal(JSON.parse(fs.readFileSync(foldersPath, "utf8")).find((folder) => folder.id === "expired-folder").expiresAt, oldExpiry);
});

test("expired folder cleanup continues after one provider prefix fails", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-expired-folder-continues-"));
  const dataDir = path.join(directory, "data");
  const oldExpiry = new Date(Date.now() - 60_000).toISOString();
  const cloud = await startS3Fixture({ failListingPrefixes: ["expired-fail"] });
  const port = await unusedPort();
  fs.mkdirSync(dataDir, { recursive: true });
  for (const folderId of ["expired-fail", "expired-success"]) {
    fs.mkdirSync(path.join(directory, "uploads", folderId), { recursive: true });
    fs.mkdirSync(path.join(directory, "temp", folderId), { recursive: true });
  }
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), process.platform === "win32" ? "junction" : "dir");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(crypto.randomBytes(24).toString("base64url"), 10), role: "admin", permissions: {}, sessionVersion: 0 },
  ]));
  const foldersPath = path.join(dataDir, "folders.json");
  fs.writeFileSync(foldersPath, JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    { id: "expired-fail", name: "Fails", createdBy: "tester", allowedUsers: ["tester"], isRoot: false, expiresAt: oldExpiry },
    { id: "expired-success", name: "Succeeds", createdBy: "tester", allowedUsers: ["tester"], isRoot: false, expiresAt: oldExpiry },
  ]));
  let output = "";
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "false",
      NODE_ENV: "test",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      CLOUD_STORAGE_PROVIDER: "s3",
      AWS_S3_BUCKET: "fixture-bucket",
      AWS_REGION: "us-east-1",
      AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`,
      AWS_S3_PRINCIPAL_ID: "fixture-account",
      AWS_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "fixture-access-key",
      AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
      TOTP_POLICY: "optional",
    },
  });
  child.stdout.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { output += chunk; });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) child.kill();
    if (child.exitCode === null && child.signalCode === null) await new Promise((resolve) => child.once("exit", resolve));
    cloud.releaseDelete();
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  await waitForServer(port, child, () => output);
  const deadline = Date.now() + 2_000;
  let folders = [];
  while (Date.now() < deadline) {
    folders = JSON.parse(fs.readFileSync(foldersPath, "utf8"));
    if (!folders.some((folder) => folder.id === "expired-success")) break;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.match(output, /Provider operation failed/, "the first folder's provider failure is observed");
  assert.equal(folders.some((folder) => folder.id === "expired-fail"), true, "failed folder remains expired and unavailable for a later retry");
  assert.equal(folders.some((folder) => folder.id === "expired-success"), false, "later expired folders are still cleaned in the same sweep");
});
