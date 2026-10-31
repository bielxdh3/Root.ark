"use strict";
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

const SERVER = path.resolve(__dirname, "..", "server.js");
const ROOT = path.resolve(__dirname, "..");
const id = "bdb2fbc5-959a-4196-9ab0-558df650dd34";
const name = "w147-expired-disposable.txt";
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
async function unusedPort() {
  const server = net.createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}
async function request(port, route, method = "GET", headers = {}, json) {
  const body = json === undefined ? null : Buffer.from(JSON.stringify(json));
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: route, method,
      headers: { ...headers, ...(body ? { "content-type": "application/json",
        "content-length": body.length } : {}) }, signal: AbortSignal.timeout(10000) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.once("error", reject);
    req.end(body);
  });
}
async function startServer(root, port, s3Port, strict) {
  const server = spawn(process.execPath, [SERVER], {
    cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, DB_ENABLED: "false", PORT: String(port),
      ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict,
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      CLOUD_STORAGE_PROVIDER: "s3", AWS_S3_BUCKET: "w147-fixture-bucket",
      AWS_REGION: "us-east-1", AWS_ENDPOINT_URL: "http://127.0.0.1:" + s3Port,
      AWS_S3_PRINCIPAL_ID: "w147-fixture-principal", AWS_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "w147-fixture-key", AWS_SECRET_ACCESS_KEY: "w147-fixture-secret",
      TRASH_ENABLED: "true", TRASH_AUTO_CLEANUP_ENABLED: "true", TRASH_RETENTION_DAYS: "1" },
  });
  server.logs = "";
  server.stdout.on("data", (chunk) => { server.logs = (server.logs + chunk).slice(-2600); });
  server.stderr.on("data", (chunk) => { server.logs = (server.logs + chunk).slice(-2600); });
  const deadline = Date.now() + 16000;
  while (Date.now() < deadline) {
    if (server.exitCode !== null) throw new Error("fixture server exited: " + server.logs);
    try { if ((await request(port, "/login.html")).status === 200) return server; }
    catch {}
    await delay(80);
  }
  server.kill();
  throw new Error("fixture server failed to start: " + server.logs);
}
async function stop(server) {
  if (!server || server.exitCode !== null) return;
  server.kill();
  await Promise.race([new Promise((resolve) => server.once("exit", resolve)), delay(5000)]);
}
test("STRICT real boot auto-cleanup and JWT DELETE trash routes never issue physical S3 DELETE, OFF resumes", { timeout: 75000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-trash-http-p1-"));
  const password = crypto.randomBytes(24).toString("base64url");
  const data = path.join(root, "data");
  const trash = path.join(data, "trash", "files", id, name);
  const record = path.join(data, "trash-items.json");
  fs.mkdirSync(path.dirname(trash), { recursive: true });
  fs.writeFileSync(trash, "DISPOSABLE local trash");
  fs.writeFileSync(record, JSON.stringify([{ id, itemType: "file",
    originalFolderId: "root", originalFileName: name,
    trashPath: path.join("files", id, name),
    deletedBy: "manager",
    deletedAt: new Date(Date.now() - 5 * 86400_000).toISOString(),
    metadata: {}, restoreMetadata: { versions: { versions: [] } },
    status: "trashed" }]));
  fs.writeFileSync(path.join(data, "users.json"), JSON.stringify([
    { username: "manager", password: bcrypt.hashSync(password, 10),
      role: "user", permissions: { manageTrash: true, listFiles: true }, sessionVersion: 0 },
  ]));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(root, "public"),
    process.platform === "win32" ? "junction" : "dir");
  const deletes = [];
  const s3 = http.createServer((req, res) => {
    if (req.method === "DELETE") {
      deletes.push(req.url);
      res.writeHead(204);
      return res.end();
    }
    if (req.method === "GET" && req.url.includes("list-type")) {
      res.setHeader("content-type", "application/xml");
      return res.end('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>w147-fixture-bucket</Name><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>');
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code></Error>");
  });
  await new Promise((resolve) => s3.listen(0, "127.0.0.1", resolve));
  let app;
  t.after(async () => {
    await stop(app);
    await new Promise((resolve) => s3.close(resolve));
    fs.rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 75 });
  });
  const port = await unusedPort();
  app = await startServer(root, port, s3.address().port, "1");
  const login = await request(port, "/auth/login", "POST", {}, { username: "manager", password });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((entry) => entry.split(";")[0]);
  const csrf = cookies.find((entry) => entry.startsWith("rootark_csrf=")).split("=", 2)[1];
  const headers = { cookie: cookies.join("; "), "x-csrf-token": csrf,
    origin: "http://127.0.0.1:" + port };
  for (const [route, json] of [["/trash/" + id, undefined], ["/trash", { confirmation: "DELETE" }]]) {
    const response = await request(port, route, "DELETE", headers, json);
    assert.equal(response.status, 503, response.body);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.match(response.body, /ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE/);
  }
  await delay(800);
  assert.deepEqual(deletes, [], "strict startup cleanup and HTTP delete must not invoke S3 DELETE");
  assert.equal(JSON.parse(fs.readFileSync(record, "utf8"))[0].status, "trashed");
  assert.equal(fs.existsSync(trash), true);
  await stop(app);
  app = await startServer(root, port, s3.address().port, "0");
  const deadline = Date.now() + 8000;
  while (deletes.length === 0 && Date.now() < deadline) await delay(60);
  assert.deepEqual(deletes.map((url) => new URL(url, "http://fixture.invalid").pathname),
    ["/w147-fixture-bucket/rootark/uploads/root/" + name]);
  const afterDeadline = Date.now() + 7000;
  while (Date.now() < afterDeadline) {
    if (JSON.parse(fs.readFileSync(record, "utf8"))[0].status === "permanently_deleted") break;
    await delay(80);
  }
  assert.equal(JSON.parse(fs.readFileSync(record, "utf8"))[0].status, "permanently_deleted");
});
