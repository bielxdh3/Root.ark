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

function s3Fixture() {
  const counts = new Map();
  const gates = new Map();
  let markDeleteStarted;
  const deleteStarted = new Promise((resolve) => { markDeleteStarted = resolve; });
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    if (req.method === "DELETE") {
      const key = decodeURIComponent(url.pathname.replace(/^\/fixture-bucket\//, ""));
      const occurrence = (counts.get(key) || 0) + 1;
      counts.set(key, occurrence);
      markDeleteStarted({ key, occurrence });
      const gate = gates.get(`${key}#${occurrence}`);
      const finish = () => { res.writeHead(204); res.end(); };
      if (gate) { gate.markStarted(); return gate.released.then(finish); }
      return finish();
    }
    if (req.method === "GET" && url.searchParams.has("list-type")) {
      res.writeHead(200, { "content-type": "application/xml" });
      return res.end("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>fixture-bucket</Name><Prefix></Prefix><KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>");
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      port: server.address().port,
      deleteStarted,
      blockDelete(key, occurrence) {
        let release;
        let markStarted;
        const gate = {
          started: new Promise((done) => { markStarted = done; }),
          released: new Promise((done) => { release = done; }),
          markStarted: () => markStarted(),
          release: () => release(),
        };
        gates.set(`${key}#${occurrence}`, gate);
        return gate;
      },
    }));
  });
}

function request(port, pathname) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host: "127.0.0.1", port, path: pathname }, (res) => {
      res.resume();
      res.once("end", () => resolve(res.statusCode));
    });
    req.once("error", reject);
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited before listening");
    try { if (await request(port, "/login.html") === 200) return; } catch {}
    await new Promise((resolve) => setTimeout(resolve, 30));
  }
  throw new Error("disposable server did not listen");
}

test("expired-file version cleanup awaits provider deletion before releasing same-name lifecycle lock", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-expired-version-lock-"));
  fs.mkdirSync(path.join(directory, "data"), { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), process.platform === "win32" ? "junction" : "dir");

  const fileName = "expired-version-race.txt";
  const oldVersionName = `${fileName}.v1`;
  const oldVersionKey = `rootark/uploads/root/${oldVersionName}`;
  fs.writeFileSync(path.join(directory, "uploads", fileName), "disposable current bytes");
  fs.writeFileSync(path.join(directory, "uploads", oldVersionName), "disposable retained bytes");
  fs.writeFileSync(path.join(directory, "data", "file-expirations.json"), JSON.stringify({
    [`root/${fileName}`]: { folderId: "root", fileName, expiresAt: new Date(Date.now() - 60_000).toISOString() },
  }));
  fs.writeFileSync(path.join(directory, "data", "file-versions.json"), JSON.stringify({
    [`root/${fileName}`]: { currentVersion: 2, versions: [
      { version: 1, storedAs: oldVersionName, size: 26 },
      { version: 2, storedAs: fileName, size: 24 },
    ] },
  }));

  const cloud = await s3Fixture();
  const versionDeleteGate = cloud.blockDelete(oldVersionKey, 1);
  const duplicateDeleteGate = cloud.blockDelete(oldVersionKey, 2);
  const port = await unusedPort();
  const child = spawn(process.execPath, [SERVER], {
    cwd: directory,
    windowsHide: true,
    stdio: "ignore",
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
      CLOUD_TEMP_RECONCILIATION_INTERVAL_MS: "3600000",
      TRASH_AUTO_CLEANUP_ENABLED: "false",
    },
  });
  t.after(async () => {
    versionDeleteGate.release();
    duplicateDeleteGate.release();
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
      await new Promise((resolve) => child.once("exit", resolve));
    }
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  await waitForServer(port, child);
  const firstDelete = await cloud.deleteStarted;
  assert.deepEqual(firstDelete, { key: `rootark/uploads/root/${fileName}`, occurrence: 1 });
  const versionDeleteStarted = await Promise.race([
    versionDeleteGate.started.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 5000)),
  ]);
  assert.equal(versionDeleteStarted, true, "expired historical payload deletion starts before local retention cleanup");

  const lifecycle = createFileLifecycleLock({ directory: path.join(directory, "data", ".rootark-cloud-file-locks"), timeoutMs: 5000, pollMs: 5 });
  let sameNameMutationSettled = false;
  const sameNameMutation = lifecycle.run("root", fileName, () => { sameNameMutationSettled = true; });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(sameNameMutationSettled, false, "provider retention deletion is still protected by the file lifecycle lock");
  versionDeleteGate.release();
  await sameNameMutation;
  assert.equal(sameNameMutationSettled, true);
  const duplicateDeleteStarted = await Promise.race([
    duplicateDeleteGate.started.then(() => true),
    new Promise((resolve) => setTimeout(() => resolve(false), 500)),
  ]);
  assert.equal(duplicateDeleteStarted, false, "retention cleanup does not schedule an unguarded duplicate provider delete after lock release");
});
