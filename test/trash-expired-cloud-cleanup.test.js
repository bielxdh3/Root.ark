const assert = require("node:assert/strict");
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

function startS3Fixture() {
  let markDeleteStarted;
  let releaseDelete;
  const deleteStarted = new Promise((resolve) => { markDeleteStarted = resolve; });
  const deleteReleased = new Promise((resolve) => { releaseDelete = resolve; });
  const deleteKeys = [];
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
      deleteStarted,
      releaseDelete,
    }));
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
