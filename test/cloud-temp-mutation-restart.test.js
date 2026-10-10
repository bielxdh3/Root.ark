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
const { createCloudTempMutationQueue } = require("../services/cloudTempMutationQueue");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");

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
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    req.once("error", reject);
  });
}

function makeS3Fixture(objects) {
  const deletes = new Map();
  const puts = new Map();
  const deleteFailures = new Map();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    const key = decodeURIComponent(url.pathname).replace(/^\/fixture-bucket\//, "");
    if (req.method === "GET" && url.searchParams.has("list-type")) {
      const prefix = url.searchParams.get("prefix") || "";
      const entries = [...objects.entries()].filter(([name]) => name.startsWith(prefix));
      const contents = entries.map(([name, value]) => `<Contents><Key>${name}</Key><LastModified>2026-10-09T00:00:00.000Z</LastModified><ETag>&quot;fixture&quot;</ETag><Size>${value.length}</Size></Contents>`).join("");
      res.writeHead(200, { "content-type": "application/xml" });
      return res.end(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><KeyCount>${entries.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
    }
    if (req.method === "DELETE") {
      deletes.set(key, (deletes.get(key) || 0) + 1);
      const remainingFailures = deleteFailures.get(key) || 0;
      if (remainingFailures > 0) {
        deleteFailures.set(key, remainingFailures - 1);
        res.writeHead(500);
        return res.end();
      }
      objects.delete(key);
      res.writeHead(204);
      return res.end();
    }
    if (req.method === "PUT") {
      req.resume();
      req.once("end", () => {
        puts.set(key, (puts.get(key) || 0) + 1);
        objects.set(key, Buffer.from("uploaded"));
        res.writeHead(200);
        res.end();
      });
      return;
    }
    if (req.method === "HEAD") {
      res.writeHead(objects.has(key) ? 200 : 404);
      return res.end();
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      port: server.address().port,
      deletes,
      puts,
      failNextDelete(key) { deleteFailures.set(key, (deleteFailures.get(key) || 0) + 1); },
    }));
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited before listening");
    try { return await request(port, "/health"); }
    catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

async function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  await new Promise((resolve) => child.once("exit", resolve));
}

function readQueueRecords(queueDirectory) {
  if (!fs.existsSync(queueDirectory)) return [];
  return fs.readdirSync(queueDirectory).filter((name) => name.endsWith(".json")).map((name) => {
    const record = JSON.parse(fs.readFileSync(path.join(queueDirectory, name), "utf8"));
    return { name, folderId: record.folderId, fileName: record.fileName, desired: record.desired, generation: record.generation };
  });
}

async function runRestartScenario({ includePresentIntent }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-temp-restart-"));
  const dataDirectory = path.join(directory, "data");
  const tempDirectory = path.join(directory, "temp");
  const queueDirectory = path.join(dataDirectory, ".rootark-cloud-temp-mutations");
  const lockDirectory = path.join(dataDirectory, ".rootark-cloud-file-locks");
  const activeRequestDirectory = path.join(dataDirectory, ".rootark-active-requests");
  const coordinatorPath = path.join(dataDirectory, ".rootark-restore-coordinator.json");
  const absentName = "restart-absent.txt";
  const presentName = "restart-present.txt";
  const absentKey = `rootark/temp/root/${absentName}`;
  const presentKey = `rootark/temp/root/${presentName}`;
  const absentQueuePath = path.join(queueDirectory, `${crypto.createHash("sha256").update(`root\0${absentName}`).digest("hex")}.json`);
  const presentQueuePath = path.join(queueDirectory, `${crypto.createHash("sha256").update(`root\0${presentName}`).digest("hex")}.json`);
  const objects = new Map([[absentKey, Buffer.from("provider pending bytes")]]);
  const cloud = await makeS3Fixture(objects);
  let child;
  try {
    fs.mkdirSync(dataDirectory, { recursive: true });
    fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
    fs.mkdirSync(tempDirectory, { recursive: true });
    fs.writeFileSync(path.join(dataDirectory, "folders.json"), JSON.stringify([
      { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    ]));
    fs.writeFileSync(path.join(dataDirectory, "users.local.json"), JSON.stringify([
      { username: "tester", password: bcrypt.hashSync(crypto.randomBytes(24).toString("base64url"), 4), role: "admin", sessionVersion: 0 },
    ]));
    fs.writeFileSync(path.join(tempDirectory, absentName), "stale local pending bytes");
    const pendingUploads = {
      [`root/${absentName}`]: { fileName: absentName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() },
    };
    fs.writeFileSync(path.join(dataDirectory, "pending-uploads.json"), JSON.stringify(pendingUploads));

    const seedQueue = createCloudTempMutationQueue({
      directory: queueDirectory,
      lifecycleLock: { run: (_folderId, _fileName, work) => work() },
      localPathFor: (_folderId, fileName) => path.join(tempDirectory, fileName),
      upload: async () => {},
      remove: async () => {},
      isEnabled: () => false,
    });
    seedQueue.setDesired("root", absentName, "absent");

    const port = await unusedPort();
    const env = {
      ...process.env,
      PORT: String(port),
      DB_ENABLED: "false",
      NODE_ENV: "test",
      UPLOAD_SCAN_ENABLED: "false",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      TOTP_POLICY: "optional",
      CLOUD_STORAGE_PROVIDER: "s3",
      AWS_S3_BUCKET: "fixture-bucket",
      AWS_REGION: "us-east-1",
      AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`,
      AWS_FORCE_PATH_STYLE: "true",
      AWS_ACCESS_KEY_ID: "fixture-access-key",
      AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
      AWS_MAX_ATTEMPTS: "1",
      AWS_S3_PRINCIPAL_ID: "fixture-account",
      CLOUD_TEMP_RECONCILIATION_INTERVAL_MS: "60000",
      CLOUD_UPLOAD_RECONCILIATION_INTERVAL_MS: "1000",
      TRASH_ENABLED: "true",
      TRASH_AUTO_CLEANUP_ENABLED: "false",
    };
    for (const key of Object.keys(env)) if (/^GOOGLE_DRIVE_/.test(key)) delete env[key];
    delete env.TRUSTED_PROXIES;
    let childErrors = "";
    const startChild = () => {
      const serverChild = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
      serverChild.stderr?.on("data", (chunk) => { childErrors += chunk.toString(); });
      return serverChild;
    };
    const diagnostics = async () => {
      let readiness = null;
      try { readiness = JSON.parse((await request(port, "/ready")).body); } catch {}
      return {
        includePresentIntent,
        cloudEnabled: readiness?.provider?.enabled ?? null,
        readinessProvider: readiness?.provider?.provider ?? null,
        restoreCoordinatorExists: fs.existsSync(coordinatorPath),
        activeRestoreLeases: fs.existsSync(activeRequestDirectory) ? fs.readdirSync(activeRequestDirectory) : [],
        lockEntries: fs.existsSync(lockDirectory) ? fs.readdirSync(lockDirectory) : [],
        queueRecords: readQueueRecords(queueDirectory),
        deleteAttempts: cloud.deletes.get(absentKey) || 0,
        presentPutAttempts: cloud.puts.get(presentKey) || 0,
        cloudTempErrors: childErrors.split(/\r?\n/).filter((line) => line.includes("[cloud-temp]")).slice(-8),
      };
    };
    const failWithDiagnostics = async (message) => assert.fail(`${message}\n${JSON.stringify(await diagnostics(), null, 2)}`);

    cloud.failNextDelete(absentKey);
    child = startChild();
    let readyResponse;
    try { readyResponse = await waitForServer(port, child); }
    catch (error) { await failWithDiagnostics(error.message); }
    assert.equal(readyResponse.status, 200);

    const firstAttemptDeadline = Date.now() + 10_000;
    while ((cloud.deletes.get(absentKey) || 0) === 0 && Date.now() < firstAttemptDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const queuedAbsent = readQueueRecords(queueDirectory).find((record) => record.fileName === absentName);
    if ((cloud.deletes.get(absentKey) || 0) !== 1 || !objects.has(absentKey) || queuedAbsent?.desired !== "absent") {
      await failWithDiagnostics("initial provider DELETE failure did not leave the absent intent durable");
    }
    await stop(child);

    if (includePresentIntent) {
      fs.writeFileSync(path.join(tempDirectory, presentName), "pending local bytes");
      const pendingUploads = JSON.parse(fs.readFileSync(path.join(dataDirectory, "pending-uploads.json"), "utf8"));
      pendingUploads[`root/${presentName}`] = { fileName: presentName, folderId: "root", uploadedBy: "tester", uploadedAt: new Date().toISOString() };
      fs.writeFileSync(path.join(dataDirectory, "pending-uploads.json"), JSON.stringify(pendingUploads));
      seedQueue.setDesired("root", presentName, "present");
    }

    child = startChild();
    try { readyResponse = await waitForServer(port, child); }
    catch (error) { await failWithDiagnostics(error.message); }
    assert.equal(readyResponse.status, 200);

    const deadline = Date.now() + 15_000;
    while (Date.now() < deadline) {
      const absentRemoved = !objects.has(absentKey) && !fs.existsSync(absentQueuePath);
      const presentFinished = !includePresentIntent || ((cloud.puts.get(presentKey) || 0) > 0
        && !fs.existsSync(presentQueuePath));
      if (absentRemoved && presentFinished) break;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }

    const recovered = !objects.has(absentKey)
      && !fs.existsSync(absentQueuePath)
      && (!includePresentIntent || ((cloud.puts.get(presentKey) || 0) > 0 && !fs.existsSync(presentQueuePath)));
    if (!recovered) await failWithDiagnostics("restart recovery did not complete the durable mutation queue");
    assert.equal(cloud.deletes.get(absentKey), 2, "startup reconciliation retries the failed provider DELETE exactly once after restart");
    assert.equal(fs.existsSync(path.join(tempDirectory, absentName)), true, "the absent provider intent does not delete local pending bytes");
    if (includePresentIntent) assert.equal(cloud.puts.get(presentKey), 1, "same-folder present intent uploads once alongside absent recovery");
  } finally {
    await stop(child);
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

test("cloud temp absent intent recovers after restart alone and beside a same-folder present intent", { timeout: 45_000 }, async (t) => {
  await t.test("one absent intent", async () => runRestartScenario({ includePresentIntent: false }));
  await t.test("absent and present intents in one folder", async () => runRestartScenario({ includePresentIntent: true }));
});
