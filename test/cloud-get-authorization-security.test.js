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
const CLOUD_METADATA_REQUEST_LIMIT = 30;
const OBJECTS = new Map([
  ["rootark/uploads/root/private.txt", Buffer.from("private cloud fixture")],
  ["rootark/uploads/root/private.txt.v1", Buffer.from("private stored version fixture")],
  ["rootark/uploads/root/orphan-private.txt.v1", Buffer.from("orphan stored version fixture")],
  ["rootark/uploads/root/history-only.txt.v9", Buffer.from("history-only orphan version fixture")],
  ["rootark/uploads/root/public.txt", Buffer.from("public cloud fixture")],
  ["rootark/uploads/root/public.txt.v1", Buffer.from("public stored version fixture")],
  ["rootark/uploads/root/ambiguous-orphan.v1", Buffer.from("unclassified stored version fixture")],
  ["rootark/uploads/root/initialize-remote.txt", Buffer.from("remote version initialization fixture")],
  ["rootark/uploads/root/rename-me.txt", Buffer.from("remote rename fixture")],
  ["rootark/uploads/root/crash-rename.txt", Buffer.from("crash rename fixture")],
  ["rootark/uploads/root/crash-move.txt", Buffer.from("crash move fixture")],
  ["rootark/uploads/root/crash-abort.txt", Buffer.from("crash abort fixture")],
  ["rootark/uploads/root/crash-ambiguous.txt", Buffer.from("crash ambiguous fixture")],
  ["rootark/uploads/root/concurrent-delete.txt", Buffer.from("delayed cleanup fixture")],
  ["rootark/uploads/root/orphan-cleanup.txt", Buffer.from("orphan tombstone fixture")],
  ["rootark/uploads/root/foreign-claim.txt", Buffer.from("foreign-host claim fixture")],
  ["rootark/uploads/root/rename-collision.txt", Buffer.from("existing remote destination fixture")],
  ["rootark/uploads/root/versioned-rename.txt", Buffer.from("remote versioned rename current")],
  ["rootark/uploads/root/versioned-rename.txt.v1", Buffer.from("remote versioned rename archive")],
  ["rootark/uploads/root/versioned-failure.txt", Buffer.from("remote failed-rename current")],
  ["rootark/uploads/root/versioned-failure.txt.v1", Buffer.from("remote failed-rename archive")],
  ["rootark/uploads/root/versioned-ambiguous.txt", Buffer.from("remote ambiguous-rename current")],
  ["rootark/uploads/root/versioned-ambiguous.txt.v1", Buffer.from("remote ambiguous-rename archive")],
  ["rootark/uploads/root/move-me.txt", Buffer.from("remote move fixture")],
  ["rootark/uploads/root/versioned-move.txt", Buffer.from("remote versioned move current")],
  ["rootark/uploads/root/versioned-move.txt.v1", Buffer.from("remote versioned move archive")],
  ["rootark/uploads/root/trash-me.txt", Buffer.from("remote trash fixture")],
  ["rootark/uploads/root/webdav-source.txt", Buffer.from("WebDAV remote source fixture")],
  ["rootark/uploads/root/webdav-versioned-source.txt", Buffer.from("WebDAV versioned current fixture")],
  ["rootark/uploads/root/webdav-versioned-source.txt.v1", Buffer.from("WebDAV versioned archive fixture")],
  ["rootark/uploads/root/webdav-target.txt", Buffer.from("WebDAV remote destination fixture")],
  ["rootark/uploads/root/webdav-readonly-source.txt", Buffer.from("WebDAV readable but not editable fixture")],
  ["rootark/uploads/destination/move-me.txt", Buffer.from("remote move destination collision")],
  ["rootark/uploads/destination/versioned-move.txt.v1", Buffer.from("unrelated destination archive-name collision")],
  ["rootark/uploads/root/budget.v2", Buffer.from("ordinary cloud suffix fixture")],
  ["rootark/uploads/root/private.txt.v7", Buffer.from("ordinary suffix with distinct ACL")],
  ["rootark/uploads/root/private.txt.v8", Buffer.from("ordinary suffix with primary history")],
  ["rootark/uploads/root/denied.v2", Buffer.from("private ordinary suffix fixture")],
  ["rootark/uploads/root/encrypted.txt", Buffer.from("encrypted cloud fixture")],
  ["rootark/uploads/root/encrypted.txt.v1", Buffer.from("encrypted version fixture")],
  ["rootark/temp/root/private-pending.txt", Buffer.from("private pending fixture")],
  ["rootark/temp/root/orphan-pending.txt", Buffer.from("orphan pending fixture")],
]);

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

function request(port, requestPath, { method = "GET", headers = {}, body = "" } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

function startS3Fixture() {
  const getObjects = [];
  const getRequests = [];
  const listRequests = [];
  let failList = false;
  let failPutAfter = 0;
  let putCount = 0;
  let commitPutOnFailure = false;
  let getBarrier = null;
  let putBarrier = null;
  let failDelete = false;
  let deleteDelayMs = 0;
  let deleteCount = 0;
  let activeDeleteCount = 0;
  let maxConcurrentDeleteCount = 0;
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    const pathname = decodeURIComponent(url.pathname);
    const key = pathname.replace(/^\/fixture-bucket\//, "");
    if (req.method === "GET" && url.searchParams.get("list-type") === "2") {
      listRequests.push(url.searchParams.get("prefix") || "");
      if (failList) {
        res.writeHead(503, { "content-type": "application/xml" });
        return res.end("<Error><Code>ServiceUnavailable</Code></Error>");
      }
      const prefix = url.searchParams.get("prefix") || "";
      const matches = Array.from(OBJECTS.keys()).filter((objectKey) => objectKey.startsWith(prefix));
      const contents = matches.map((objectKey) => `<Contents><Key>${objectKey}</Key><LastModified>2026-10-05T00:00:00.000Z</LastModified><ETag>&quot;fixture&quot;</ETag><Size>${OBJECTS.get(objectKey).length}</Size></Contents>`).join("");
      res.writeHead(200, { "content-type": "application/xml" });
      return res.end(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><Prefix></Prefix><KeyCount>${matches.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
    }
    if (req.method === "GET") getRequests.push(key);
    if (req.method === "GET" && OBJECTS.has(key)) {
      getObjects.push(key);
      if (getBarrier?.keys.has(key)) {
        getBarrier.seen.add(key);
        if ([...getBarrier.keys].every((expected) => getBarrier.seen.has(expected))) getBarrier.readyResolve();
        await new Promise((resolve) => {
          const waiters = getBarrier.waiters.get(key) || [];
          waiters.push(resolve);
          getBarrier.waiters.set(key, waiters);
        });
      }
      res.writeHead(200, { "content-length": OBJECTS.get(key).length });
      return res.end(OBJECTS.get(key));
    }
    if (req.method === "PUT") {
      putCount += 1;
      const shouldFail = Boolean(failPutAfter && putCount >= failPutAfter);
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", async () => {
        let body = Buffer.concat(chunks);
        if (String(req.headers["content-encoding"] || "").includes("aws-chunked")) {
          const payload = [];
          let offset = 0;
          while (offset < body.length) {
            const lineEnd = body.indexOf("\r\n", offset);
            if (lineEnd < 0) break;
            const chunkSize = Number.parseInt(body.subarray(offset, lineEnd).toString("ascii").split(";", 1)[0], 16);
            offset = lineEnd + 2;
            if (!Number.isFinite(chunkSize) || chunkSize <= 0) break;
            payload.push(body.subarray(offset, offset + chunkSize));
            offset += chunkSize + 2;
          }
          body = Buffer.concat(payload);
        }
        if (putBarrier?.keys.has(key)) {
          putBarrier.seen.add(key);
          if ([...putBarrier.keys].every((expected) => putBarrier.seen.has(expected))) putBarrier.readyResolve();
          await new Promise((resolve) => {
            const waiters = putBarrier.waiters.get(key) || [];
            waiters.push(resolve);
            putBarrier.waiters.set(key, waiters);
          });
        }
        if (!shouldFail || commitPutOnFailure) OBJECTS.set(key, body);
        if (shouldFail) {
          res.writeHead(503, { "content-type": "application/xml" });
          return res.end("<Error><Code>ServiceUnavailable</Code></Error>");
        }
        res.writeHead(200);
        res.end();
      });
      return;
    }
    if (req.method === "DELETE") {
      deleteCount += 1;
      activeDeleteCount += 1;
      maxConcurrentDeleteCount = Math.max(maxConcurrentDeleteCount, activeDeleteCount);
      try {
        if (deleteDelayMs) await new Promise((resolve) => setTimeout(resolve, deleteDelayMs));
        if (failDelete) {
          res.writeHead(503, { "content-type": "application/xml" });
          return res.end("<Error><Code>ServiceUnavailable</Code></Error>");
        }
        OBJECTS.delete(key);
        res.writeHead(204);
        return res.end();
      } finally {
        activeDeleteCount -= 1;
      }
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code><Message>Not found</Message></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      port: server.address().port,
      getObjects,
      getRequests,
      listRequests,
      get putCount() { return putCount; },
      setGetBarrier(keys) {
        let readyResolve;
        const ready = new Promise((resolve) => { readyResolve = resolve; });
        getBarrier = { keys: new Set(keys), seen: new Set(), waiters: new Map(), readyResolve, ready };
        return {
          ready,
          release(key) {
            for (const resolve of getBarrier.waiters.get(key) || []) resolve();
            getBarrier.waiters.delete(key);
          },
        };
      },
      setPutBarrier(keys) {
        let readyResolve;
        const ready = new Promise((resolve) => { readyResolve = resolve; });
        putBarrier = { keys: new Set(keys), seen: new Set(), waiters: new Map(), readyResolve, ready };
        return {
          ready,
          release(key) {
            for (const resolve of putBarrier.waiters.get(key) || []) resolve();
            putBarrier.waiters.delete(key);
          },
        };
      },
      setListFailure(value) { failList = Boolean(value); },
      setPutFailureAfter(value, commit = false) { failPutAfter = Number(value) || 0; putCount = 0; commitPutOnFailure = Boolean(commit); },
      setDeleteFailure(value) { failDelete = Boolean(value); },
      setDeleteDelay(value) { deleteDelayMs = Number(value) || 0; deleteCount = 0; maxConcurrentDeleteCount = 0; },
      get deleteCount() { return deleteCount; },
      get maxConcurrentDeleteCount() { return maxConcurrentDeleteCount; },
    }));
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`disposable server exited (code=${child.exitCode}, signal=${child.signalCode}); stderr=${String(child.startupLogs || "").slice(-2000)}`);
    }
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start; stderr=" + String(child.startupLogs || "").slice(-2000));
}

async function waitFor(predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("timed out waiting for condition");
}

function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise((resolve) => {
    const finish = () => resolve();
    child.once("exit", finish);
    if (child.exitCode !== null || child.signalCode !== null) finish();
    else child.kill();
  });
}

test("cloud-backed file routes authorize access and bound repeated metadata listings", { timeout: 90_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-get-acl-"));
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.writeFileSync(path.join(directory, "uploads", "notes.v2"), "ordinary local suffix fixture");
  fs.writeFileSync(path.join(directory, "uploads", "legacy.v9"), "suffix-named primary with its own ACL fixture");
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true, delete: true, approve: true }, sessionVersion: 0 },
    { username: "other", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    "root/private.txt": { public: false, owner: "owner", users: {} },
    "root/orphan-private.txt": { public: false, owner: "owner", users: {} },
    "root/public.txt": { public: true, owner: "viewer", users: {} },
    "root/public.txt.v1": { public: true, owner: "viewer", users: {} },
    "root/legacy.v9": { public: true, owner: "viewer", users: {} },
    "root/budget.v2": { public: false, owner: "viewer", users: {} },
    "root/notes.v2": { public: false, owner: "viewer", users: { other: { read: true, edit: false } } },
    "root/rename-me.txt": { public: false, owner: "viewer", users: {} },
    "root/crash-abort.txt": { public: true, owner: "viewer", users: {} },
    "root/crash-abort-target.txt": { public: false, owner: "other", users: {} },
    "root/concurrent-delete.txt": { public: false, owner: "viewer", users: {} },
    "root/versioned-rename.txt": { public: false, owner: "viewer", users: {} },
    "root/versioned-failure.txt": { public: false, owner: "viewer", users: {} },
    "root/versioned-ambiguous.txt": { public: false, owner: "viewer", users: {} },
    "root/move-me.txt": { public: false, owner: "viewer", users: {} },
    "root/versioned-move.txt": { public: false, owner: "viewer", users: {} },
    "root/trash-me.txt": { public: false, owner: "viewer", users: {} },
    "root/webdav-source.txt": { public: false, owner: "viewer", users: {} },
    "root/webdav-versioned-source.txt": { public: false, owner: "viewer", users: {} },
    "root/webdav-target.txt": { public: false, owner: "viewer", users: {} },
    "root/webdav-readonly-source.txt": { public: true, owner: "owner", users: { other: { read: true, edit: false } } },
    "root/private.txt.v7": { public: false, owner: "viewer", users: {} },
    "root/denied.v2": { public: false, owner: "owner", users: {} },
  }));
  fs.writeFileSync(path.join(dataDir, "file-versions.json"), JSON.stringify({
    "root/history-only.txt": { currentVersion: 1, versions: [
      { version: 1, storedAs: "history-only.txt", size: 0 },
    ] },
    "root/private.txt.v8": { currentVersion: 1, versions: [
      { version: 1, storedAs: "private.txt.v8", size: OBJECTS.get("rootark/uploads/root/private.txt.v8").length },
    ] },
    "root/public.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "public.txt.v1", size: OBJECTS.get("rootark/uploads/root/public.txt.v1").length },
      { version: 2, storedAs: "public.txt", size: OBJECTS.get("rootark/uploads/root/public.txt").length },
    ] },
    "root/versioned-rename.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "versioned-rename.txt.v1", size: OBJECTS.get("rootark/uploads/root/versioned-rename.txt.v1").length },
      { version: 2, storedAs: "versioned-rename.txt", size: OBJECTS.get("rootark/uploads/root/versioned-rename.txt").length },
    ] },
    "root/versioned-failure.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "versioned-failure.txt.v1", size: OBJECTS.get("rootark/uploads/root/versioned-failure.txt.v1").length },
      { version: 2, storedAs: "versioned-failure.txt", size: OBJECTS.get("rootark/uploads/root/versioned-failure.txt").length },
    ] },
    "root/versioned-ambiguous.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "versioned-ambiguous.txt.v1", size: OBJECTS.get("rootark/uploads/root/versioned-ambiguous.txt.v1").length },
      { version: 2, storedAs: "versioned-ambiguous.txt", size: OBJECTS.get("rootark/uploads/root/versioned-ambiguous.txt").length },
    ] },
    "root/versioned-move.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "versioned-move.txt.v1", size: OBJECTS.get("rootark/uploads/root/versioned-move.txt.v1").length },
      { version: 2, storedAs: "versioned-move.txt", size: OBJECTS.get("rootark/uploads/root/versioned-move.txt").length },
    ] },
    "root/webdav-versioned-source.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "webdav-versioned-source.txt.v1", size: OBJECTS.get("rootark/uploads/root/webdav-versioned-source.txt.v1").length },
      { version: 2, storedAs: "webdav-versioned-source.txt", size: OBJECTS.get("rootark/uploads/root/webdav-versioned-source.txt").length },
    ] },
    "root/private.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "private.txt.v1", size: OBJECTS.get("rootark/uploads/root/private.txt.v1").length },
      { version: 2, storedAs: "private.txt", size: OBJECTS.get("rootark/uploads/root/private.txt").length },
    ] },
    "root/encrypted.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "encrypted.txt.v1", size: OBJECTS.get("rootark/uploads/root/encrypted.txt.v1").length },
      { version: 2, storedAs: "encrypted.txt", size: OBJECTS.get("rootark/uploads/root/encrypted.txt").length },
    ] },
  }));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: "destination", name: "Destino", createdBy: "viewer", allowedUsers: [] },
  ]));
  fs.writeFileSync(path.join(dataDir, "encrypted-files.json"), JSON.stringify({
    "root/encrypted.txt": { encryptionLevel: "server-key", originalFilename: "encrypted.txt" },
  }));
  const encryptedShareToken = "a".repeat(48);
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [encryptedShareToken]: {
      fileName: "encrypted.txt", folderId: "root", createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), createdBy: "owner",
      views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, passwordHash: "", activeViewers: {},
    },
  }));
  const cloud = await startS3Fixture();
  const port = await getUnusedPort();
  const hashCallsFile = path.join(directory, "bcrypt-hash-calls.txt");
  const preloadFile = path.join(directory, "bcrypt-hash-instrumentation.js");
  fs.writeFileSync(preloadFile, [
    'const fs = require("node:fs");',
    'const path = require("node:path");',
    `const bcrypt = require(${JSON.stringify(require.resolve("bcryptjs"))});`,
    `const counterFile = ${JSON.stringify(hashCallsFile)};`,
    "const originalHashSync = bcrypt.hashSync;",
    'bcrypt.hashSync = function (...args) { fs.appendFileSync(counterFile, "1\\n"); return originalHashSync.apply(this, args); };',
    "const originalCopyFileSync = fs.copyFileSync.bind(fs);",
    "fs.copyFileSync = function (source, destination, ...args) {",
    "  const matchesPartialCopyCrash = process.env.ROOTARK_TEST_CRASH_PARTIAL_COPY_SOURCE && path.resolve(source) === process.env.ROOTARK_TEST_CRASH_PARTIAL_COPY_SOURCE && process.env.ROOTARK_TEST_CRASH_PARTIAL_COPY_DESTINATION_PREFIX && path.resolve(destination).startsWith(process.env.ROOTARK_TEST_CRASH_PARTIAL_COPY_DESTINATION_PREFIX);",
    "  if (matchesPartialCopyCrash) { const bytes = fs.readFileSync(source); fs.writeFileSync(destination, bytes.subarray(0, Math.max(1, Math.floor(bytes.length / 2)))); process.exit(91); }",
    "  const result = originalCopyFileSync(source, destination, ...args);",
    "  const matchesCrash = process.env.ROOTARK_TEST_CRASH_COPY_SOURCE && path.resolve(source) === process.env.ROOTARK_TEST_CRASH_COPY_SOURCE && path.resolve(destination) === process.env.ROOTARK_TEST_CRASH_COPY_DESTINATION;",
    "  if (matchesCrash) process.exit(89);",
    "  return result;",
    "};",
    "const originalRenameSync = fs.renameSync.bind(fs);",
    "fs.renameSync = function (source, destination, ...args) {",
    "  const result = originalRenameSync(source, destination, ...args);",
    "  const matchesCrash = process.env.ROOTARK_TEST_CRASH_RENAME_SYNC_SOURCE && path.resolve(source) === process.env.ROOTARK_TEST_CRASH_RENAME_SYNC_SOURCE && path.resolve(destination) === process.env.ROOTARK_TEST_CRASH_RENAME_SYNC_DESTINATION;",
    "  if (matchesCrash) process.exit(90);",
    "  const matchesInstallCrash = process.env.ROOTARK_TEST_CRASH_INSTALL_DESTINATION && path.resolve(destination) === process.env.ROOTARK_TEST_CRASH_INSTALL_DESTINATION;",
    "  if (matchesInstallCrash) process.exit(92);",
    "  return result;",
    "};",
    "const originalRename = fs.promises.rename.bind(fs.promises);",
    "fs.promises.rename = async function (source, destination) {",
    "  const matchesCrash = process.env.ROOTARK_TEST_CRASH_RENAME_SOURCE && path.resolve(source) === process.env.ROOTARK_TEST_CRASH_RENAME_SOURCE && path.resolve(destination) === process.env.ROOTARK_TEST_CRASH_RENAME_DESTINATION;",
    "  if (matchesCrash && process.env.ROOTARK_TEST_CRASH_BEFORE_RENAME === '1') process.exit(87);",
    "  const result = await originalRename(source, destination);",
    "  if (matchesCrash && process.env.ROOTARK_TEST_CRASH_DUPLICATE_SOURCE === '1') fs.copyFileSync(destination, source);",
    "  if (matchesCrash) process.exit(86);",
    "  return result;",
    "};",
    "const originalLinkSync = fs.linkSync.bind(fs);",
    "fs.linkSync = function (source, destination) {",
    "  const result = originalLinkSync(source, destination);",
    "  if (process.env.ROOTARK_TEST_CRASH_CLAIM_PUBLISH && path.resolve(destination) === process.env.ROOTARK_TEST_CRASH_CLAIM_PUBLISH) process.exit(88);",
    "  return result;",
    "};",
  ].join("\n"));
  const env = {
    ...process.env,
    PORT: String(port),
    DB_ENABLED: "false",
    NODE_ENV: "test",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    TOTP_POLICY: "optional",
    ROUTE_RATE_LIMIT_MAX: "1000",
    CLOUD_STORAGE_PROVIDER: "s3",
    AWS_S3_BUCKET: "fixture-bucket",
    AWS_REGION: "us-east-1",
    AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`,
    AWS_FORCE_PATH_STYLE: "true",
    AWS_ACCESS_KEY_ID: "fixture-access-key",
    AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
    WEBDAV_ENABLED: "true",
    WEBDAV_ALLOW_MOVE: "true",
    WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS: "1000",
    WEBDAV_MOVE_RECONCILIATION_MAX_BACKOFF_MS: "1000",
    CLOUD_RELOCATION_CLEANUP_INTERVAL_MS: "1000",
    CLOUD_RELOCATION_CLEANUP_MAX_BACKOFF_MS: "1000",
    NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadFile}`].filter(Boolean).join(" "),
  };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const startChild = (childPort = port, extraEnv = {}) => {
    const child = spawn(process.execPath, [SERVER], { cwd: directory, env: { ...env, PORT: String(childPort), ...extraEnv }, stdio: ["ignore", "ignore", "pipe"], windowsHide: true });
    child.startupLogs = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { child.startupLogs += chunk; });
    return child;
  };
  let child = startChild();
  let secondChild = null;
  t.after(async () => {
    await stop(secondChild);
    await stop(child);
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  assert.equal((await waitForServer(port, child)).status, 200);

  const body = JSON.stringify({ username: "viewer", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const otherLoginBody = JSON.stringify({ username: "other", password });
  const otherLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(otherLoginBody) }, body: otherLoginBody });
  assert.equal(otherLogin.status, 200, otherLogin.body);
  const otherCookies = otherLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const otherCookie = otherCookies.join("; ");
  const otherCsrf = otherCookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const mutate = (requestPath, method, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method,
      headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };
  const mutateOther = (requestPath, method, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method,
      headers: { cookie: otherCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": otherCsrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };

  const list = await request(port, "/list", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(list.status, 200, list.body);
  assert.deepEqual(JSON.parse(list.body).map((file) => file.name).sort(), ["budget.v2", "concurrent-delete.txt", "crash-abort.txt", "crash-ambiguous.txt", "crash-move.txt", "crash-rename.txt", "encrypted.txt", "foreign-claim.txt", "initialize-remote.txt", "legacy.v9", "move-me.txt", "notes.v2", "orphan-cleanup.txt", "private.txt.v7", "private.txt.v8", "public.txt", "rename-collision.txt", "rename-me.txt", "trash-me.txt", "versioned-ambiguous.txt", "versioned-failure.txt", "versioned-move.txt", "versioned-rename.txt", "webdav-readonly-source.txt", "webdav-source.txt", "webdav-target.txt", "webdav-versioned-source.txt"]);
  const ambiguousOrphanDownload = await request(port, "/files/ambiguous-orphan.v1", { headers: { cookie } });
  assert.equal(ambiguousOrphanDownload.status, 404, "normal file download fails closed for unclassified .vN objects");
  const ambiguousOrphanOpenToken = await mutate("/file-open-token", "POST", { name: "ambiguous-orphan.v1" });
  assert.equal(ambiguousOrphanOpenToken.status, 404, ambiguousOrphanOpenToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/ambiguous-orphan.v1"), false, "ambiguous version-like object is never hydrated through the file API");
  assert.deepEqual(cloud.getObjects, [], "listing reads provider metadata without materializing file bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "budget.v2")), false, "ordinary cloud file is visible before hydration");

  const ordinaryCloudFile = await request(port, "/files/budget.v2", { headers: { cookie } });
  assert.equal(ordinaryCloudFile.status, 200, "an ordinary cloud-only .vN file must be downloadable");
  assert.equal(ordinaryCloudFile.body, "ordinary cloud suffix fixture");
  const ordinaryLocalFile = await request(port, "/files/notes.v2", { headers: { cookie } });
  assert.equal(ordinaryLocalFile.status, 200, "an ordinary local .vN file must be downloadable");
  assert.equal(ordinaryLocalFile.body, "ordinary local suffix fixture");

  const limitedDownloadKey = "rootark/uploads/root/limited-download.txt";
  const downloadPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  downloadPermissions["root/limited-download.txt"] = { public: true, owner: "other", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(downloadPermissions));
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await request(port, "/files/limited-download.txt", { headers: { cookie: otherCookie } });
    assert.equal(response.status, 404, response.body);
  }
  const downloadProviderAttempts = cloud.getRequests.filter((key) => key === limitedDownloadKey).length;
  assert.equal(downloadProviderAttempts, CLOUD_METADATA_REQUEST_LIMIT, "cloud-backed download cache misses consume the per-route provider budget");
  const limitedDownload = await request(port, "/files/limited-download.txt", { headers: { cookie: otherCookie } });
  assert.equal(limitedDownload.status, 429, limitedDownload.body);
  assert.equal(cloud.getRequests.filter((key) => key === limitedDownloadKey).length, downloadProviderAttempts, "a limited download is rejected before another provider GET");
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT + 1; index += 1) {
    const localResponse = await request(port, "/files/notes.v2", { headers: { cookie: otherCookie } });
    assert.equal(localResponse.status, 200, "local-file downloads do not consume the cloud provider budget");
  }

  const limitedRestoreName = "limited-restore.txt";
  const limitedRestoreCurrentPath = path.join(directory, "uploads", limitedRestoreName);
  const limitedRestoreVersionPath = path.join(directory, "uploads", `${limitedRestoreName}.v1`);
  const restorePermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  restorePermissions[`root/${limitedRestoreName}`] = { public: false, owner: "other", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(restorePermissions));
  const restoreVersions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-versions.json"), "utf8"));
  restoreVersions[`root/${limitedRestoreName}`] = { currentVersion: 3, versions: [
    { version: 1, storedAs: `${limitedRestoreName}.v1`, size: 1 },
    { version: 2, storedAs: `${limitedRestoreName}.v2`, size: 1 },
    { version: 3, storedAs: limitedRestoreName, size: 1 },
  ] };
  fs.writeFileSync(path.join(dataDir, "file-versions.json"), JSON.stringify(restoreVersions));
  fs.writeFileSync(limitedRestoreCurrentPath, "warm current restore fixture");
  fs.writeFileSync(limitedRestoreVersionPath, "warm archived restore fixture");
  fs.writeFileSync(path.join(directory, "uploads", `${limitedRestoreName}.v2`), "warm second archived restore fixture");
  const restorePutBaseline = cloud.putCount;
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const currentHistory = JSON.parse(fs.readFileSync(path.join(dataDir, "file-versions.json"), "utf8"))[`root/${limitedRestoreName}`];
    const availableTargets = currentHistory.versions.filter((version) => version.version !== currentHistory.currentVersion).slice(-2);
    const requestedVersion = availableTargets[index % 2].version;
    const response = await mutateOther(`/restore/${limitedRestoreName}/v/${requestedVersion}?folderId=root`, "POST", {}).catch((error) => {
      throw new Error(`warm version restore request ${index + 1} failed; child=${child.exitCode}/${child.signalCode}; stderr=${String(child.startupLogs).slice(-1000)}; ${error.message}`);
    });
    assert.equal(response.status, 200, `restore ${requestedVersion} on iteration ${index + 1}: ${response.body}; history=${fs.readFileSync(path.join(dataDir, "file-versions.json"), "utf8")}`);
  }
  assert.ok(cloud.putCount > restorePutBaseline, "warm-cache version restores reach cloud provider synchronization");
  const restoreStateAtLimit = fs.readFileSync(path.join(dataDir, "file-versions.json"), "utf8");
  const restorePutsAtLimit = cloud.putCount;
  const latestRestorableVersion = JSON.parse(restoreStateAtLimit)[`root/${limitedRestoreName}`].versions
    .filter((version) => version.version !== JSON.parse(restoreStateAtLimit)[`root/${limitedRestoreName}`].currentVersion)
    .at(-1).version;
  const limitedRestore = await mutateOther(`/restore/${limitedRestoreName}/v/${latestRestorableVersion}?folderId=root`, "POST", {});
  assert.equal(limitedRestore.status, 429, limitedRestore.body);
  assert.equal(cloud.putCount, restorePutsAtLimit, "a limited warm-cache version restore is rejected before provider synchronization");
  assert.equal(fs.readFileSync(path.join(dataDir, "file-versions.json"), "utf8"), restoreStateAtLimit, "a limited version restore does not mutate version history");

  const legacyFile = await request(port, "/files/legacy.v9", { headers: { cookie } });
  assert.equal(legacyFile.status, 200, "suffix-named primary files remain accessible when they have their own ACL");
  assert.equal(legacyFile.body, "suffix-named primary with its own ACL fixture");
  const distinctAclFile = await request(port, "/files/private.txt.v7", { headers: { cookie } });
  assert.equal(distinctAclFile.status, 200, "a primary .vN file uses its own ACL even when the base name is private");
  assert.equal(distinctAclFile.body, "ordinary suffix with distinct ACL");
  const distinctHistoryFile = await request(port, "/files/private.txt.v8", { headers: { cookie } });
  assert.equal(distinctHistoryFile.status, 200, "a .vN primary history is independent from the unsuffixed file");
  assert.equal(distinctHistoryFile.body, "ordinary suffix with primary history");
  const deniedSuffixFile = await request(port, "/files/denied.v2", { headers: { cookie } });
  assert.equal(deniedSuffixFile.status, 403, "ordinary .vN names retain file authorization");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/denied.v2"), false, JSON.stringify(cloud.getObjects));
  const ordinaryOpenToken = await mutate("/file-open-token", "POST", { name: "budget.v2" });
  assert.equal(ordinaryOpenToken.status, 200, ordinaryOpenToken.body);
  const storedPublicVersion = await request(port, "/files/public.txt.v1", { headers: { cookie } });
  assert.equal(storedPublicVersion.status, 404, "version metadata hides historical bytes even with an alias ACL");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/public.txt.v1"), false);
  cloud.getObjects.length = 0;

  const privateFile = await request(port, "/files/private.txt", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(privateFile.status, 403, privateFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "denied direct GET never downloads the object");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "private.txt")), false, "denied direct GET never materializes the object");

  const privateVersion = await request(port, "/files/private.txt.v1", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(privateVersion.status, 404, privateVersion.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt.v1"), false, "stored versions cannot bypass the primary file ACL");

  const orphanVersion = await request(port, "/files/orphan-private.txt.v1", { headers: { cookie } });
  assert.equal(orphanVersion.status, 404, orphanVersion.body);
  const orphanOpenToken = await mutate("/file-open-token", "POST", { name: "orphan-private.txt.v1" });
  assert.equal(orphanOpenToken.status, 404, orphanOpenToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/orphan-private.txt.v1"), false, "ownerless version aliases never hydrate");
  const historyOnlyOrphan = await request(port, "/files/history-only.txt.v9", { headers: { cookie } });
  assert.equal(historyOnlyOrphan.status, 404, "primary history also identifies orphan aliases without a primary ACL");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/history-only.txt.v9"), false);

  const encryptedFile = await request(port, "/files/encrypted.txt", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(encryptedFile.status, 403, encryptedFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt"), false, "direct file GET rejects encrypted objects before cache hydration");

  const encryptedVersion = await request(port, "/download/encrypted.txt/v/1", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(encryptedVersion.status, 403, encryptedVersion.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt.v1"), false, "encrypted version GET rejects before cache hydration");

  const encryptedShare = await request(port, `/share/${encryptedShareToken}/view`, {
    method: "POST",
    headers: { origin: `http://127.0.0.1:${port}` },
  });
  assert.equal(encryptedShare.status, 404, encryptedShare.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt"), false, "legacy encrypted share rejects before cache hydration");

  const versionTokenBody = JSON.stringify({ name: "encrypted.txt", version: 1 });
  const encryptedVersionToken = await request(port, "/version-open-token", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(versionTokenBody) },
    body: versionTokenBody,
  });
  assert.equal(encryptedVersionToken.status, 403, encryptedVersionToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt.v1"), false, "encrypted version token cannot materialize a rejected version");

  const deniedOpenTokenBody = JSON.stringify({ name: "private.txt" });
  const deniedOpenToken = await request(port, "/file-open-token", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(deniedOpenTokenBody) },
    body: deniedOpenTokenBody,
  });
  assert.equal(deniedOpenToken.status, 403, deniedOpenToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "unauthorized open-token request never materializes the object");

  const search = await request(port, "/files/search?q=private", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(search.status, 200, search.body);
  assert.deepEqual(JSON.parse(search.body).map((file) => file.name).sort(), ["private.txt.v7", "private.txt.v8"]);
  assert.deepEqual(cloud.getObjects, [], "search reads provider metadata without materializing file bytes");

  const webDavAuth = `Basic ${Buffer.from(`viewer:${password}`).toString("base64")}`;
  const propfind = await request(port, "/dav", { method: "PROPFIND", headers: { cookie, authorization: webDavAuth, depth: "1" } });
  assert.equal(propfind.status, 207, propfind.body);
  assert.equal(propfind.body.includes("encrypted.txt"), false, "WebDAV does not expose encrypted files");
  assert.equal(propfind.body.includes("private.txt.v1"), false, "WebDAV hides stored versions");
  assert.equal(propfind.body.includes("public.txt.v1"), false, "WebDAV hides versions recognized by metadata");
  assert.equal(propfind.body.includes("ambiguous-orphan.v1"), false, "WebDAV fails closed for suffix-named objects with no primary metadata");
  assert.equal(propfind.body.includes("budget.v2"), true, "WebDAV lists ordinary suffix names");
  assert.equal(propfind.body.includes("notes.v2"), true, "WebDAV lists ordinary local suffix names");
  assert.equal(propfind.body.includes("private.txt.v7"), true, "WebDAV preserves a suffix-named primary file with its own ACL");
  assert.equal(propfind.body.includes("private.txt.v8"), true, "WebDAV preserves a suffix-named primary file with its own history");
  assert.deepEqual(cloud.getObjects, [], "WebDAV listing does not hydrate cloud objects");
  const orphanWebDavFile = await request(port, "/dav/ambiguous-orphan.v1", { headers: { authorization: webDavAuth } });
  assert.equal(orphanWebDavFile.status, 404, orphanWebDavFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/ambiguous-orphan.v1"), false, "ambiguous suffix artifacts never hydrate through WebDAV");
  const orphanWebDavHead = await request(port, "/dav/ambiguous-orphan.v1", { method: "HEAD", headers: { authorization: webDavAuth } });
  assert.equal(orphanWebDavHead.status, 404, "HEAD does not disclose ambiguous suffix metadata");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/ambiguous-orphan.v1"), false, "denied HEAD never hydrates the object");
  cloud.getObjects.length = 0;
  const webDavMoveCollision = await request(port, "/dav/webdav-source.txt", {
    method: "MOVE",
    headers: { authorization: webDavAuth, destination: `http://127.0.0.1:${port}/dav/webdav-target.txt`, overwrite: "F" },
  });
  assert.equal(webDavMoveCollision.status, 412, webDavMoveCollision.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/webdav-target.txt"), false, "WebDAV detects a remote destination without hydrating or overwriting it");
  cloud.getObjects.length = 0;
  const webDavStoredVersionOverwrite = await request(port, "/dav/webdav-source.txt", {
    method: "MOVE",
    headers: { authorization: webDavAuth, destination: `http://127.0.0.1:${port}/dav/public.txt.v1`, overwrite: "T" },
  });
  assert.equal(webDavStoredVersionOverwrite.status, 409, webDavStoredVersionOverwrite.body);
  assert.deepEqual(cloud.getObjects, [], "WebDAV cannot overwrite stored-version bytes even with Overwrite enabled");
  const webDavListingsBeforeReadOnlyMove = cloud.listRequests.length;
  const unauthorizedWebDavMove = await request(port, "/dav/webdav-readonly-source.txt", {
    method: "MOVE",
    headers: { authorization: webDavAuth, destination: `http://127.0.0.1:${port}/dav/renamed-target.txt`, overwrite: "F" },
  });
  assert.equal(unauthorizedWebDavMove.status, 403, unauthorizedWebDavMove.body);
  assert.deepEqual(cloud.getObjects, [], "read-only WebDAV access cannot hydrate a source for MOVE before edit authorization");
  assert.equal(cloud.listRequests.length, webDavListingsBeforeReadOnlyMove, "read-only WebDAV MOVE is rejected before provider metadata listing");
  cloud.getObjects.length = 0;
  cloud.setDeleteFailure(true);
  const webDavVersionedMove = await request(port, "/dav/webdav-versioned-source.txt", {
    method: "MOVE",
    headers: { authorization: webDavAuth, destination: `http://127.0.0.1:${port}/dav/webdav-versioned-moved.txt`, overwrite: "F" },
  });
  assert.equal(webDavVersionedMove.status, 202, webDavVersionedMove.body);
  assert.equal((await request(port, "/files/webdav-versioned-source.txt", { headers: { cookie: otherCookie } })).status, 403, "the old private WebDAV source stays blocked while provider deletion is pending");
  const webDavJournalDirectory = path.join(directory, "temp", ".incoming");
  const pendingWebDavMoveName = fs.readdirSync(webDavJournalDirectory).find((file) => file.startsWith("rootark-webdav-move-") && file.endsWith(".json"));
  assert.ok(pendingWebDavMoveName, "WebDAV move journal remains durable while source deletion fails");
  cloud.setDeleteFailure(false);
  await waitFor(() => !fs.existsSync(path.join(webDavJournalDirectory, pendingWebDavMoveName)));
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/webdav-versioned-source.txt.v1"), true, "WebDAV MOVE hydrates archived bytes before changing local history metadata");
  assert.equal(OBJECTS.has("rootark/uploads/root/webdav-versioned-source.txt.v1"), false, "WebDAV MOVE removes the old archive key only after its destination copy exists");
  assert.deepEqual(OBJECTS.get("rootark/uploads/root/webdav-versioned-moved.txt.v1"), Buffer.from("WebDAV versioned archive fixture"));
  const webDavMovedArchive = await request(port, "/download/webdav-versioned-moved.txt/v/1", { headers: { cookie } });
  assert.equal(webDavMovedArchive.status, 200, webDavMovedArchive.body);
  assert.equal(webDavMovedArchive.body, "WebDAV versioned archive fixture");

  const davRaceSource = "dav-api-race-source.txt";
  const davRaceTarget = "dav-api-race-target.txt";
  const apiRaceSource = "api-dav-race-source.txt";
  const apiRaceTarget = "api-dav-race-target.txt";
  OBJECTS.set(`rootark/uploads/root/${davRaceSource}`, Buffer.from("DAV relocation winner"));
  OBJECTS.set(`rootark/uploads/root/${apiRaceSource}`, Buffer.from("API relocation loser"));
  const davRacePermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  davRacePermissions[`root/${davRaceSource}`] = { public: false, owner: "viewer", users: {} };
  davRacePermissions[`root/${apiRaceSource}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(davRacePermissions));
  const davRaceTargetKey = `rootark/uploads/root/${davRaceTarget}`;
  const davRacePutBarrier = cloud.setPutBarrier([davRaceTargetKey]);
  const davRaceRequest = request(port, `/dav/${encodeURIComponent(davRaceSource)}`, {
    method: "MOVE",
    headers: { authorization: webDavAuth, destination: `http://127.0.0.1:${port}/dav/${encodeURIComponent(davRaceTarget)}`, overwrite: "F" },
  });
  await Promise.race([
    davRacePutBarrier.ready,
    davRaceRequest.then((result) => { throw new Error(`DAV MOVE finished before provider barrier: ${result.status} ${result.body}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("DAV MOVE did not reach provider PUT barrier")), 8000)),
  ]);
  const apiDuringDav = await mutate("/rename", "PUT", { oldName: apiRaceSource, newName: apiRaceTarget });
  assert.equal(apiDuringDav.status, 503, apiDuringDav.body, "API relocation fails closed while DAV MOVE owns the shared claim");
  assert.equal(fs.existsSync(path.join(directory, "uploads", apiRaceSource)), false, "API loser is rejected before provider hydration while DAV MOVE owns the claim");
  assert.equal(fs.existsSync(path.join(directory, "uploads", apiRaceTarget)), false, "API loser does not create a local destination");
  davRacePutBarrier.release(davRaceTargetKey);
  const davRaceResult = await davRaceRequest;
  assert.equal(davRaceResult.status, 201, davRaceResult.body);
  assert.deepEqual(fs.readFileSync(path.join(directory, "uploads", davRaceTarget)), Buffer.from("DAV relocation winner"));
  assert.deepEqual(OBJECTS.get(davRaceTargetKey), Buffer.from("DAV relocation winner"));

  const deleteRaceSource = "delete-relocation-race.txt";
  const deleteRaceKey = `rootark/uploads/root/${deleteRaceSource}`;
  OBJECTS.set(deleteRaceKey, Buffer.from("delete race fixture"));
  const deleteRacePermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  deleteRacePermissions[`root/${deleteRaceSource}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(deleteRacePermissions));
  const deleteRaceGetBarrier = cloud.setGetBarrier([deleteRaceKey]);
  const deleteRaceRequest = mutate(`/delete/${encodeURIComponent(deleteRaceSource)}`, "POST", {});
  await Promise.race([
    deleteRaceGetBarrier.ready,
    deleteRaceRequest.then((result) => { throw new Error(`DELETE finished before provider GET barrier: ${result.status} ${result.body}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("DELETE did not reach provider GET barrier")), 8000)),
  ]);
  const getCountWhileDeletePaused = cloud.getObjects.length;
  const renameDuringDelete = await mutate("/rename", "PUT", { oldName: deleteRaceSource, newName: "delete-race-renamed.txt" });
  assert.equal(renameDuringDelete.status, 503, renameDuringDelete.body, "rename fails closed before provider reads while DELETE owns the shared claim");
  assert.equal(cloud.getObjects.length, getCountWhileDeletePaused, "overlapping rename performs no additional provider GET/cache hydration");
  assert.equal(fs.existsSync(path.join(directory, "uploads", deleteRaceSource)), false, "DELETE has not changed local source while provider hydration is paused");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "delete-race-renamed.txt")), false, "overlapping relocation cannot create a local destination");
  deleteRaceGetBarrier.release(deleteRaceKey);
  const deleteRaceResult = await deleteRaceRequest;
  assert.equal(deleteRaceResult.status, 200, deleteRaceResult.body);
  assert.equal(fs.existsSync(path.join(directory, "uploads", deleteRaceSource)), false, "serialized DELETE moves the source to trash");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "delete-race-renamed.txt")), false);

  const pendingWebDavId = crypto.randomUUID();
  const pendingWebDavSource = "reserved-webdav-source.txt";
  const pendingWebDavDestination = "webdav-dest.txt";
  const pendingJournalDirectory = path.join(directory, "temp", ".incoming");
  fs.mkdirSync(pendingJournalDirectory, { recursive: true });
  const pendingWebDavJournalPath = path.join(pendingJournalDirectory, `rootark-webdav-move-${pendingWebDavId}.json`);
  const pendingWebDavLockPath = path.join(pendingJournalDirectory, `rootark-webdav-move-${pendingWebDavId}.lock`);
  const pendingMetadataDirectory = path.join(pendingJournalDirectory, `rootark-webdav-move-${pendingWebDavId}`, "metadata");
  OBJECTS.set(`rootark/uploads/root/${pendingWebDavSource}`, Buffer.from("reserved source fixture"));
  OBJECTS.set("rootark/uploads/root/reservation-api-source.txt", Buffer.from("reservation API source"));
  const reservationPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  reservationPermissions[`root/${pendingWebDavSource}`] = { public: false, owner: "viewer", users: {} };
  reservationPermissions["root/reservation-api-source.txt"] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(reservationPermissions));
  fs.writeFileSync(pendingWebDavJournalPath, JSON.stringify({
    version: 1, transactionId: pendingWebDavId, phase: "cloud_source_removal_pending", journalPath: pendingWebDavJournalPath,
    sourcePath: path.join(directory, "uploads", pendingWebDavSource), destinationPath: path.join(directory, "uploads", pendingWebDavDestination),
    stagePath: path.join(directory, "uploads", `.rootark-move-${pendingWebDavId}.source`),
    destinationBackupPath: path.join(directory, "uploads", `.rootark-move-${pendingWebDavId}.destination`),
    destinationExisted: false, replacementInstalled: true, pendingOperation: null, completedOperations: [], startedAt: new Date().toISOString(),
    metadata: { directory: pendingMetadataDirectory, files: {} },
    cloud: { folderId: "root", sourceName: pendingWebDavSource, destinationName: pendingWebDavDestination, sourceNames: [pendingWebDavSource], destinationNames: [pendingWebDavDestination], state: "source_delete_uncertain", attempts: 1 },
  }));
  fs.writeFileSync(pendingWebDavLockPath, JSON.stringify({ version: 1, token: "remote-worker", transactionId: pendingWebDavId, pid: 2147483647, hostname: "unreachable-other-host", processStartIdentity: null, claimedAt: new Date().toISOString() }));
  const reservedSourceRename = await mutate("/rename", "PUT", { oldName: pendingWebDavSource, newName: "reserved-source-renamed.txt" });
  assert.equal(reservedSourceRename.status, 403, "pending WebDAV source name is reserved against API mutation");
  const reservedDestinationRename = await mutate("/rename", "PUT", { oldName: "reservation-api-source.txt", newName: pendingWebDavDestination });
  assert.equal(reservedDestinationRename.status, 409, `pending WebDAV destination name is reserved before an object exists: ${reservedDestinationRename.body}`);
  fs.rmSync(pendingWebDavJournalPath, { force: true });
  fs.rmSync(pendingWebDavLockPath, { force: true });
  cloud.getObjects.length = 0;
  const ordinaryCloudWebDavFile = await request(port, "/dav/budget.v2", { headers: { authorization: webDavAuth } });
  assert.equal(ordinaryCloudWebDavFile.status, 200, ordinaryCloudWebDavFile.body);
  assert.equal(ordinaryCloudWebDavFile.body, "ordinary cloud suffix fixture");
  const ordinaryLocalWebDavFile = await request(port, "/dav/notes.v2", { headers: { authorization: webDavAuth } });
  assert.equal(ordinaryLocalWebDavFile.status, 200, ordinaryLocalWebDavFile.body);
  assert.equal(ordinaryLocalWebDavFile.body, "ordinary local suffix fixture");

  const fileAccess = await request(port, "/file-access?name=public.txt", { headers: { cookie } });
  assert.equal(fileAccess.status, 200, fileAccess.body);
  const temporary = await mutate("/file-temporary", "PUT", { name: "public.txt", durationAmount: 1, durationUnit: "hours" });
  assert.equal(temporary.status, 200, temporary.body);
  const share = await mutate("/share", "POST", { name: "public.txt", expiresInMinutes: 60 });
  assert.equal(share.status, 201, share.body);
  const updatedAccess = await mutate("/file-access", "PUT", { name: "public.txt", public: true, users: { viewer: { edit: true } } });
  assert.equal(updatedAccess.status, 200, updatedAccess.body);
  const deniedTemporary = await mutate("/file-temporary", "PUT", { name: "private.txt", durationAmount: 1, durationUnit: "hours" });
  assert.equal(deniedTemporary.status, 403, deniedTemporary.body);
  const deniedShare = await mutate("/share", "POST", { name: "private.txt", expiresInMinutes: 60 });
  assert.equal(deniedShare.status, 403, deniedShare.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "denied metadata actions do not hydrate private objects");
  assert.deepEqual(cloud.getObjects, [], "metadata-only file actions do not download cloud bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "public.txt")), false, "metadata-only file actions do not create a local cache");

  const fileAccessListingCount = cloud.listRequests.length;
  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await request(port, "/file-access?name=public.txt", { headers: { cookie, "x-forwarded-for": `198.51.100.${index}` } });
    assert.equal(response.status, 200, response.body);
  }
  const fileAccessAtLimit = cloud.listRequests.length;
  assert.equal(fileAccessAtLimit - fileAccessListingCount, CLOUD_METADATA_REQUEST_LIMIT - 1);
  const limitedFileAccess = await request(port, "/file-access?name=public.txt", { headers: { cookie, "x-forwarded-for": "203.0.113.250" } });
  assert.equal(limitedFileAccess.status, 429, limitedFileAccess.body);
  assert.equal(cloud.listRequests.length, fileAccessAtLimit, "limited GET is rejected before provider listing");
  const limitedHeadFileAccess = await request(port, "/file-access?name=public.txt", { method: "HEAD", headers: { cookie } });
  assert.equal(limitedHeadFileAccess.status, 429, "HEAD fallback shares the GET file-access quota");
  assert.equal(cloud.listRequests.length, fileAccessAtLimit, "limited HEAD is rejected before provider listing");

  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await mutate("/file-access", "PUT", { name: "public.txt", public: true, users: { viewer: { edit: true } } });
    assert.equal(response.status, 200, response.body);
  }
  const accessStateAtLimit = fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8");
  const accessListingAtLimit = cloud.listRequests.length;
  const limitedAccessChange = await mutate("/file-access", "PUT", { name: "public.txt", public: false, users: {} });
  assert.equal(limitedAccessChange.status, 429, limitedAccessChange.body);
  assert.equal(cloud.listRequests.length, accessListingAtLimit, "limited ACL update is rejected before provider listing");
  assert.equal(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"), accessStateAtLimit, "limited ACL update does not persist state");

  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await mutate("/file-temporary", "PUT", { name: "public.txt", durationAmount: 1, durationUnit: "hours" });
    assert.equal(response.status, 200, response.body);
  }
  const expirationStateAtLimit = fs.readFileSync(path.join(dataDir, "file-expirations.json"), "utf8");
  const expirationListingAtLimit = cloud.listRequests.length;
  const limitedExpirationChange = await mutate("/file-temporary", "PUT", { name: "public.txt", durationAmount: 2, durationUnit: "days" });
  assert.equal(limitedExpirationChange.status, 429, limitedExpirationChange.body);
  assert.equal(cloud.listRequests.length, expirationListingAtLimit, "limited expiration update is rejected before provider listing");
  assert.equal(fs.readFileSync(path.join(dataDir, "file-expirations.json"), "utf8"), expirationStateAtLimit, "limited expiration update does not persist state");

  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await mutate("/share", "POST", { name: "public.txt", expiresInMinutes: 60 });
    assert.equal(response.status, 201, response.body);
  }
  const shareStateAtLimit = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"));
  const shareCountAtLimit = Object.values(shareStateAtLimit).filter((link) => link.fileName === "public.txt" && link.createdBy === "viewer").length;
  assert.equal(shareCountAtLimit, CLOUD_METADATA_REQUEST_LIMIT);
  const shareListingAtLimit = cloud.listRequests.length;
  const hashCallsAtLimit = fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0;
  const limitedShare = await mutate("/share", "POST", { name: "public.txt", expiresInMinutes: 60, maxViews: 5, password: "valid-password" });
  assert.equal(limitedShare.status, 429, limitedShare.body);
  assert.equal(fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0, hashCallsAtLimit, "limited share does not hash a password");
  assert.equal(cloud.listRequests.length, shareListingAtLimit, "limited share creation is rejected before provider listing");
  const shareStateAfterLimit = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"));
  assert.equal(Object.values(shareStateAfterLimit).filter((link) => link.fileName === "public.txt" && link.createdBy === "viewer").length, shareCountAtLimit, "limited share creation does not persist a link");

  const hashCallsBeforeDeniedShare = fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0;
  const deniedPasswordShare = await mutate("/share", "POST", { name: "private.txt", expiresInMinutes: 60, password: "valid-password" });
  assert.equal(deniedPasswordShare.status, 403, deniedPasswordShare.body);
  assert.equal(fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0, hashCallsBeforeDeniedShare, "unauthorized share does not hash a password");

  const remoteVersions = await request(port, "/versions/public.txt", { headers: { cookie } });
  assert.equal(remoteVersions.status, 200, remoteVersions.body);
  assert.equal(JSON.parse(remoteVersions.body).currentVersion, 2);
  assert.equal(JSON.parse(remoteVersions.body).versions.length, 2);
  assert.equal(fs.existsSync(path.join(directory, "uploads", "public.txt")), false, "version metadata lookup does not hydrate file bytes");

  const initializedRemoteVersion = await mutate("/versions/initialize-remote.txt/initialize", "POST", {});
  assert.equal(initializedRemoteVersion.status, 200, initializedRemoteVersion.body);
  assert.equal(JSON.parse(initializedRemoteVersion.body).currentVersion, 1);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/initialize-remote.txt"), true, "authorized version initialization hydrates the remote primary file");

  const remoteRenameCollision = await mutate("/rename", "PUT", { oldName: "rename-me.txt", newName: "rename-collision.txt" });
  assert.equal(remoteRenameCollision.status, 409, remoteRenameCollision.body);
  cloud.getObjects.length = 0;
  cloud.setListFailure(true);
  const renameDuringProviderOutage = await mutate("/rename", "PUT", { oldName: "rename-me.txt", newName: "must-not-rename.txt" });
  cloud.setListFailure(false);
  assert.equal(renameDuringProviderOutage.status, 503, renameDuringProviderOutage.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/rename-me.txt"), false, "provider listing failure does not hydrate or mutate a source as though it were absent");
  cloud.setListFailure(true);
  const outageList = await request(port, "/list", { headers: { cookie } });
  cloud.setListFailure(false);
  assert.equal(outageList.status, 503, outageList.body);
  assert.equal(outageList.body.includes("notes.v2"), false, "cloud list outage is not reported as a successful partial local-only listing");
  assert.equal((await request(port, "/files/rename-me.txt", { headers: { cookie: otherCookie } })).status, 403, "the second account cannot read the private source before relocation");
  cloud.setDeleteFailure(true);
  const remoteRename = await mutate("/rename", "PUT", { oldName: "rename-me.txt", newName: "renamed.txt" });
  assert.equal(remoteRename.status, 200, `${remoteRename.body} logs=${child.startupLogs}`);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/rename-me.txt"), true, "authorized rename hydrates the source before moving it locally");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "renamed.txt")), true);
  const cleanupDirectory = path.join(directory, "temp", ".incoming");
  const sourceCleanupFile = fs.readdirSync(cleanupDirectory).find((file) => file.startsWith("rootark-cloud-relocation-cleanup-") && file.endsWith(".json"));
  assert.ok(sourceCleanupFile, "failed source deletion is durably queued");
  assert.equal((await request(port, "/files/rename-me.txt", { headers: { cookie: otherCookie } })).status, 403, "the pending source key remains inaccessible while provider deletion is failing");
  assert.equal((await request(port, "/files/renamed.txt", { headers: { cookie: otherCookie } })).status, 403, "the destination retains the source ACL after relocation");
  const webdavBody = "replacement content must not reuse a pending cleanup key";
  const webdavReplacement = await request(port, "/dav/rename-me.txt", {
    method: "PUT",
    headers: {
      authorization: `Basic ${Buffer.from(`viewer:${password}`).toString("base64")}`,
      "content-length": Buffer.byteLength(webdavBody),
    },
    body: webdavBody,
  });
  assert.equal(webdavReplacement.status, 201, webdavReplacement.body);
  const pendingAfterReplacement = JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8"));
  assert.ok(pendingAfterReplacement["root/rename-me-1.txt"], "an upload colliding with a cleanup reservation receives a distinct filename");
  await stop(child);
  child = startChild();
  assert.equal((await waitForServer(port, child)).status, 200, "server restarts with the cleanup queue persisted");
  cloud.setDeleteFailure(false);
  await waitFor(() => !fs.existsSync(path.join(cleanupDirectory, sourceCleanupFile)));
  assert.equal(OBJECTS.has("rootark/uploads/root/rename-me.txt"), false, "restart recovery deletes the old remote source after provider recovery");

  cloud.setDeleteDelay(2500);
  const concurrentRename = mutate("/rename", "PUT", { oldName: "concurrent-delete.txt", newName: "concurrent-renamed.txt" });
  await waitFor(() => cloud.deleteCount > 0);
  const secondPort = await getUnusedPort();
  secondChild = startChild(secondPort);
  assert.equal((await waitForServer(secondPort, secondChild)).status, 200, "a second process can share the cleanup directory");
  await new Promise((resolve) => setTimeout(resolve, 1300));
  assert.equal(cloud.deleteCount, 1, "the periodic recovery worker does not issue a duplicate delete while route cleanup is active");
  assert.equal(cloud.maxConcurrentDeleteCount, 1, "only one provider deletion owns a relocation journal at a time");
  const concurrentRenameResult = await concurrentRename;
  assert.equal(concurrentRenameResult.status, 200, concurrentRenameResult.body);
  assert.equal(OBJECTS.has("rootark/uploads/root/concurrent-delete.txt"), false);
  assert.equal(cloud.deleteCount, 1, "a late duplicate deletion cannot outlive journal completion and delete a replacement object");
  await stop(secondChild);
  secondChild = null;
  cloud.setDeleteDelay(0);

  const recoveredOrphanKey = "rootark/uploads/root/orphan-cleanup.txt";
  await stop(child);
  child = null;
  const permissionsBeforeRestart = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  permissionsBeforeRestart["root/orphan-cleanup.txt"] = {
    folderId: "root", fileName: "orphan-cleanup.txt", public: false, users: {}, cleanupPending: true,
  };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(permissionsBeforeRestart));
  const orphanTransactionId = crypto.randomUUID();
  const orphanJournalPath = path.join(cleanupDirectory, "rootark-cloud-relocation-cleanup-" + orphanTransactionId + ".json");
  fs.writeFileSync(orphanJournalPath, JSON.stringify({ version: 1, transactionId: orphanTransactionId, journalPath: orphanJournalPath, provider: "s3", items: [{ folderId: "root", fileName: "orphan-cleanup.txt", area: "uploads", clearPermission: true }], attempts: 0, state: "delete_uncertain", failureCategory: null, nextAttemptAt: null, createdAt: new Date().toISOString() }));
  fs.writeFileSync(path.join(cleanupDirectory, "rootark-cloud-relocation-cleanup-" + orphanTransactionId + ".lock"), JSON.stringify({ version: 1, token: "interrupted-owner", transactionId: orphanTransactionId, pid: 2147483647, hostname: os.hostname(), processStartIdentity: null, claimedAt: new Date(0).toISOString() }));
  child = startChild();
  assert.equal((await waitForServer(port, child)).status, 200, "server restarts with an interrupted cleanup claim and tombstone");
  await waitFor(() => !OBJECTS.has(recoveredOrphanKey) && JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"))["root/orphan-cleanup.txt"] === undefined);
  const permissionsAfterRecovery = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  assert.equal(permissionsAfterRecovery["root/orphan-cleanup.txt"], undefined, "restart recovery journals and clears an orphaned cleanup tombstone");
  cloud.setDeleteDelay(0);

  const remoteMove = await mutate("/move", "PUT", { name: "move-me.txt", fromFolderId: "root", toFolderId: "destination" });
  assert.equal(remoteMove.status, 200, remoteMove.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/move-me.txt"), true, "authorized move hydrates the source before moving it locally");
  assert.equal(JSON.parse(remoteMove.body).fileName, "move-me-1.txt", "remote destination collision chooses a free suffix instead of replacing the remote object");
  assert.equal(cloud.getObjects.includes("rootark/uploads/destination/move-me.txt"), false, "remote move collision never hydrates or replaces the destination");

  const versionedRename = await mutate("/rename", "PUT", { oldName: "versioned-rename.txt", newName: "renamed-versioned.txt" });
  assert.equal(versionedRename.status, 200, versionedRename.body);
  assert.deepEqual(OBJECTS.get("rootark/uploads/root/renamed-versioned.txt.v1"), Buffer.from("remote versioned rename archive"), "rename preserves archived bytes under the new cloud key");
  assert.deepEqual(OBJECTS.get("rootark/uploads/root/renamed-versioned.txt"), Buffer.from("remote versioned rename current"));
  assert.equal((await request(port, "/download/renamed-versioned.txt/v/1", { headers: { cookie } })).body, "remote versioned rename archive", "renamed archive remains downloadable from its history entry");

  const versionedMove = await mutate("/move", "PUT", { name: "versioned-move.txt", fromFolderId: "root", toFolderId: "destination" });
  assert.equal(versionedMove.status, 200, versionedMove.body);
  assert.equal(JSON.parse(versionedMove.body).fileName, "versioned-move-1.txt", "move selects a free primary and archive-name pair");
  assert.deepEqual(OBJECTS.get("rootark/uploads/destination/versioned-move.txt.v1"), Buffer.from("unrelated destination archive-name collision"), "move leaves a colliding remote archive-like object untouched");
  assert.deepEqual(OBJECTS.get("rootark/uploads/destination/versioned-move-1.txt.v1"), Buffer.from("remote versioned move archive"), "move preserves archived bytes under the destination cloud key");
  assert.deepEqual(OBJECTS.get("rootark/uploads/destination/versioned-move-1.txt"), Buffer.from("remote versioned move current"));
  assert.equal((await request(port, "/download/versioned-move-1.txt/v/1?folderId=destination", { headers: { cookie } })).body, "remote versioned move archive", "moved archive remains downloadable from its history entry");

  const raceSources = ["relocation-race-left.txt", "relocation-race-right.txt"];
  const raceTarget = "relocation-race-target.txt";
  for (const [index, name] of raceSources.entries()) OBJECTS.set(`rootark/uploads/root/${name}`, Buffer.from(`winner-${index}`));
  const racePermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  for (const name of raceSources) racePermissions[`root/${name}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(racePermissions));
  const concurrentPort = await getUnusedPort();
  secondChild = startChild(concurrentPort);
  await waitForServer(concurrentPort, secondChild);
  const firstRaceSourceKey = `rootark/uploads/root/${raceSources[0]}`;
  const getBarrier = cloud.setGetBarrier([firstRaceSourceKey]);
  const raceMutation = (targetPort, sourceName) => {
    const body = JSON.stringify({ oldName: sourceName, newName: raceTarget });
    return request(targetPort, "/rename", {
      method: "PUT",
      headers: { cookie, origin: `http://127.0.0.1:${targetPort}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };
  const firstRaceRequest = raceMutation(port, raceSources[0]);
  await getBarrier.ready;
  const firstRaceGetCount = cloud.getObjects.length;
  const secondRaceResult = await raceMutation(concurrentPort, raceSources[1]);
  assert.equal(secondRaceResult.status, 503, secondRaceResult.body, "the second process fails closed while the first owns the mutation claim");
  assert.equal(cloud.getObjects.length, firstRaceGetCount, "the losing process is rejected before provider GET/cache hydration");
  assert.equal(fs.existsSync(path.join(directory, "uploads", raceSources[1])), false, "the losing source is not hydrated locally");
  getBarrier.release(firstRaceSourceKey);
  const firstRaceResult = await firstRaceRequest;
  assert.equal(firstRaceResult.status, 200, firstRaceResult.body, "the first request commits after provider hydration resumes");
  assert.equal(OBJECTS.has(`rootark/uploads/root/${raceSources[1]}`), true, "the losing source remains in the provider");
  const raceDestinationPath = path.join(directory, "uploads", raceTarget);
  const winnerBytes = fs.readFileSync(raceDestinationPath);
  assert.ok(["winner-0", "winner-1"].includes(winnerBytes.toString()), "the destination contains one complete source payload");
  const loserName = raceSources[winnerBytes.toString() === "winner-0" ? 1 : 0];
  assert.equal(loserName, raceSources[1], "the first request wins while the second process holds no stale preflight");
  assert.equal(fs.existsSync(path.join(directory, "uploads", loserName)), false, "the losing source remains unhydrated locally");
  assert.deepEqual(OBJECTS.get(`rootark/uploads/root/${raceTarget}`), winnerBytes, "provider and local destination agree on the winning payload");
  await stop(secondChild);
  secondChild = null;

  const approvalRaceName = "approve-race.txt";
  const approvalRaceTarget = "approve-done.txt";
  const approvalRaceSourceKey = `rootark/uploads/root/${approvalRaceName}`;
  const approvalRacePendingKey = `rootark/temp/root/${approvalRaceName}`;
  const approvalRaceSourceBytes = Buffer.from("original relocation bytes");
  OBJECTS.set(approvalRaceSourceKey, approvalRaceSourceBytes);
  OBJECTS.set(approvalRacePendingKey, Buffer.from("approved replacement bytes"));
  const pendingUploadsFile = path.join(dataDir, "pending-uploads.json");
  fs.writeFileSync(pendingUploadsFile, JSON.stringify({ [`root/${approvalRaceName}`]: { folderId: "root", fileName: approvalRaceName, uploadedBy: "viewer" } }));
  const approvalRacePermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  approvalRacePermissions[`root/${approvalRaceName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(approvalRacePermissions));
  const approvalRaceVersionsPath = path.join(dataDir, "file-versions.json");
  const approvalRaceVersionsBefore = fs.readFileSync(approvalRaceVersionsPath);
  const approvalPutKey = `rootark/uploads/root/${approvalRaceTarget}`;
  const approvalPutBarrier = cloud.setPutBarrier([approvalPutKey]);
  let approvalRenameOutcome = "pending";
  const approvalRaceRename = mutate("/rename", "PUT", { oldName: approvalRaceName, newName: approvalRaceTarget }).then((result) => {
    approvalRenameOutcome = `${result.status} ${result.body}`;
    return result;
  });
  await Promise.race([
    approvalPutBarrier.ready,
    approvalRaceRename.then((result) => { throw new Error(`relocation ended before PUT barrier: ${result.status} ${result.body}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`relocation PUT barrier not reached: result=${approvalRenameOutcome} sourceGets=${cloud.getObjects.join(",")} logs=${child.startupLogs}`)), 8000)),
  ]);
  const approvalRaceGetCount = cloud.getObjects.length;
  const approvalRace = await mutate(`/approve/${encodeURIComponent(approvalRaceName)}?folderId=root`, "POST", {});
  const approvalRacePendingBeforeReject = fs.readFileSync(pendingUploadsFile);
  const rejectedDuringRelocation = await mutate(`/reject/${encodeURIComponent(approvalRaceName)}?folderId=root`, "POST", {});
  assert.equal(rejectedDuringRelocation.status, 503, rejectedDuringRelocation.body, "rejection cannot race a relocation holding the shared mutation claim");
  assert.equal(cloud.getObjects.length, approvalRaceGetCount, "blocked rejection performs no provider GET for the remote-only pending object");
  assert.equal(fs.existsSync(path.join(directory, "temp", approvalRaceName)), false, "blocked rejection does not hydrate the remote pending object");
  assert.deepEqual(fs.readFileSync(pendingUploadsFile), approvalRacePendingBeforeReject, "blocked rejection leaves pending metadata unchanged");
  assert.equal(OBJECTS.has(approvalRacePendingKey), true, "blocked rejection preserves the remote pending object");
  assert.equal(approvalRace.status, 503, approvalRace.body, "approval cannot replace a source while relocation owns the mutation claim");
  assert.equal(cloud.getObjects.length, approvalRaceGetCount, "blocked approval performs no provider GET for the pending object");
  assert.equal(fs.existsSync(path.join(directory, "temp", approvalRaceName)), false, "blocked approval does not hydrate the remote pending object");
  assert.deepEqual(fs.readFileSync(approvalRaceVersionsPath), approvalRaceVersionsBefore, "blocked approval leaves version history unchanged");
  assert.deepEqual(OBJECTS.get(approvalRaceSourceKey), approvalRaceSourceBytes, "blocked approval leaves provider source bytes unchanged");
  assert.equal(OBJECTS.has(approvalRacePendingKey), true, "blocked approval preserves the remote pending object");
  assert.equal(fs.readFileSync(path.join(directory, "uploads", approvalRaceName), "utf8"), "original relocation bytes", "rejected approval leaves the relocation source identity unchanged");
  approvalPutBarrier.release(approvalPutKey);
  const approvalRaceRenameResult = await approvalRaceRename;
  assert.equal(approvalRaceRenameResult.status, 200, approvalRaceRenameResult.body);
  assert.deepEqual(fs.readFileSync(path.join(directory, "uploads", approvalRaceTarget)), Buffer.from("original relocation bytes"));
  assert.deepEqual(OBJECTS.get(approvalPutKey), Buffer.from("original relocation bytes"), "the staged provider destination matches the committed local file");
  assert.equal(fs.existsSync(path.join(directory, "temp", approvalRaceName)), false, "the remote pending object remains unhydrated after the rejected approval");

  const approveRejectRaceName = "approve-reject-race.txt";
  const approveRejectPendingKey = `rootark/temp/root/${approveRejectRaceName}`;
  OBJECTS.set(approveRejectPendingKey, Buffer.from("approval wins the pending-object claim"));
  const pendingBeforeApproveReject = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  pendingBeforeApproveReject[`root/${approveRejectRaceName}`] = { folderId: "root", fileName: approveRejectRaceName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(pendingBeforeApproveReject));
  const approveRejectVersionsBefore = fs.readFileSync(approvalRaceVersionsPath);
  const approveRejectGetBarrier = cloud.setGetBarrier([approveRejectPendingKey]);
  const approveRejectApproval = mutate(`/approve/${encodeURIComponent(approveRejectRaceName)}?folderId=root`, "POST", {});
  await Promise.race([
    approveRejectGetBarrier.ready,
    approveRejectApproval.then((result) => { throw new Error(`approval ended before pending GET barrier: ${result.status} ${result.body}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("approval did not reach pending GET barrier")), 8000)),
  ]);
  const approveRejectGetCount = cloud.getObjects.length;
  const overlappingReject = await mutate(`/reject/${encodeURIComponent(approveRejectRaceName)}?folderId=root`, "POST", {});
  assert.equal(overlappingReject.status, 503, overlappingReject.body, "reject fails closed while approval owns the shared mutation claim");
  assert.equal(cloud.getObjects.length, approveRejectGetCount, "overlapping rejection issues no additional provider GET");
  assert.equal(fs.existsSync(path.join(directory, "temp", approveRejectRaceName)), false, "overlapping rejection cannot hydrate or remove the pending object");
  assert.deepEqual(fs.readFileSync(pendingUploadsFile), Buffer.from(JSON.stringify(pendingBeforeApproveReject)), "overlapping rejection leaves pending metadata unchanged");
  assert.deepEqual(fs.readFileSync(approvalRaceVersionsPath), approveRejectVersionsBefore, "overlapping rejection leaves version metadata unchanged");
  approveRejectGetBarrier.release(approveRejectPendingKey);
  const approveRejectApprovalResult = await approveRejectApproval;
  assert.equal(approveRejectApprovalResult.status, 200, approveRejectApprovalResult.body, "approval commits after its pending-object read resumes");
  assert.equal(fs.readFileSync(path.join(directory, "uploads", approveRejectRaceName), "utf8"), "approval wins the pending-object claim");

  const approvalRetryName = "approve-retry.txt";
  const approvalRetryPendingKey = `rootark/temp/root/${approvalRetryName}`;
  const approvalRetryBytes = Buffer.from("approved bytes across provider retry");
  OBJECTS.set(approvalRetryPendingKey, approvalRetryBytes);
  const pendingBeforeRetry = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  pendingBeforeRetry[`root/${approvalRetryName}`] = { folderId: "root", fileName: approvalRetryName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(pendingBeforeRetry));
  cloud.setPutFailureAfter(1);
  const failedApprovalRetry = await mutate(`/approve/${encodeURIComponent(approvalRetryName)}?folderId=root`, "POST", {});
  cloud.setPutFailureAfter(0);
  assert.equal(failedApprovalRetry.status, 503, failedApprovalRetry.body, "approval reports provider upload failure instead of success");
  assert.equal(OBJECTS.has(approvalRetryPendingKey), true, "failed provider upload retains the remote pending source");
  assert.equal(fs.existsSync(path.join(directory, "temp", approvalRetryName)), true, "failed provider upload retains the local pending source");
  assert.deepEqual(fs.readFileSync(path.join(directory, "uploads", approvalRetryName)), approvalRetryBytes, "local committed approval bytes remain available for retry");
  const pendingAfterFailedApproval = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  assert.equal(pendingAfterFailedApproval[`root/${approvalRetryName}`].approvalRetry.state, "committed", "retry marker is persisted with committed version data");
  assert.equal(pendingAfterFailedApproval[`root/${approvalRetryName}`].approvalRetry.version, 1);
  const failedApprovalHistory = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"))[`root/${approvalRetryName}`];
  assert.equal(failedApprovalHistory.currentVersion, 1);
  assert.equal(failedApprovalHistory.versions.length, 1);

  await stop(child);
  child = startChild();
  await waitForServer(port, child);
  const retriedApproval = await mutate(`/approve/${encodeURIComponent(approvalRetryName)}?folderId=root`, "POST", {});
  assert.equal(retriedApproval.status, 200, retriedApproval.body, "approval retry succeeds after a server restart");
  const retriedApprovalHistory = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"))[`root/${approvalRetryName}`];
  assert.equal(retriedApprovalHistory.currentVersion, 1, "retry reuses the committed version number");
  assert.equal(retriedApprovalHistory.versions.length, 1, "retry does not append a duplicate version");
  assert.deepEqual(OBJECTS.get(`rootark/uploads/root/${approvalRetryName}`), approvalRetryBytes, "retry uploads the committed bytes to the provider");
  const pendingAfterSuccessfulRetry = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  assert.equal(pendingAfterSuccessfulRetry[`root/${approvalRetryName}`], undefined, "successful retry clears pending metadata");
  assert.equal(fs.existsSync(path.join(directory, "temp", approvalRetryName)), false, "successful retry removes the local pending source");
  await waitFor(() => !OBJECTS.has(approvalRetryPendingKey));

  const inconsistentHistoryName = "approve-inconsistent-history.txt";
  const inconsistentHistoryCurrentPath = path.join(directory, "uploads", inconsistentHistoryName);
  const inconsistentHistoryPendingPath = path.join(directory, "temp", inconsistentHistoryName);
  const inconsistentHistoryCurrentBytes = Buffer.from("authoritative current bytes with incomplete version metadata");
  const inconsistentHistoryPendingBytes = Buffer.from("replacement that must not commit against incomplete metadata");
  fs.writeFileSync(inconsistentHistoryCurrentPath, inconsistentHistoryCurrentBytes);
  fs.writeFileSync(inconsistentHistoryPendingPath, inconsistentHistoryPendingBytes);
  OBJECTS.set(`rootark/temp/root/${inconsistentHistoryName}`, inconsistentHistoryPendingBytes);
  const inconsistentPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  inconsistentPermissions[`root/${inconsistentHistoryName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(inconsistentPermissions));
  const inconsistentVersions = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"));
  inconsistentVersions[`root/${inconsistentHistoryName}`] = { currentVersion: 2, versions: [] };
  fs.writeFileSync(approvalRaceVersionsPath, JSON.stringify(inconsistentVersions));
  const inconsistentPendingUploads = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  inconsistentPendingUploads[`root/${inconsistentHistoryName}`] = { folderId: "root", fileName: inconsistentHistoryName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(inconsistentPendingUploads));

  const rejectedInconsistentApproval = await mutate(`/approve/${encodeURIComponent(inconsistentHistoryName)}?folderId=root`, "POST", {});
  assert.equal(rejectedInconsistentApproval.status, 503, rejectedInconsistentApproval.body, "inconsistent version history fails closed");
  assert.deepEqual(fs.readFileSync(inconsistentHistoryCurrentPath), inconsistentHistoryCurrentBytes, "fail-closed approval preserves the current file before any commit stage");
  assert.equal(fs.existsSync(path.join(directory, "uploads", `${inconsistentHistoryName}.v2`)), false, "inconsistent history is rejected before archiving the current file");
  assert.deepEqual(fs.readFileSync(approvalRaceVersionsPath), Buffer.from(JSON.stringify(inconsistentVersions)), "fail-closed approval leaves version metadata unchanged");

  const firstApprovalCrashName = "approve-first-crash.txt";
  const firstApprovalCurrentPath = path.join(directory, "uploads", firstApprovalCrashName);
  const firstApprovalPendingPath = path.join(directory, "temp", firstApprovalCrashName);
  const firstApprovalBytes = Buffer.from("first approval installed before its version history");
  fs.writeFileSync(firstApprovalPendingPath, firstApprovalBytes);
  OBJECTS.set(`rootark/temp/root/${firstApprovalCrashName}`, firstApprovalBytes);
  const firstApprovalPendingUploads = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  firstApprovalPendingUploads[`root/${firstApprovalCrashName}`] = { folderId: "root", fileName: firstApprovalCrashName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(firstApprovalPendingUploads));

  await stop(child);
  child = startChild(port, {
    ROOTARK_TEST_CRASH_INSTALL_DESTINATION: firstApprovalCurrentPath,
  });
  assert.equal((await waitForServer(port, child)).status, 200);
  const firstApprovalCrashExit = new Promise((resolve) => child.once("exit", resolve));
  const interruptedFirstApproval = mutate(`/approve/${encodeURIComponent(firstApprovalCrashName)}?folderId=root`, "POST", {}).catch((error) => error);
  const firstApprovalCrashCode = await Promise.race([
    firstApprovalCrashExit,
    new Promise((_, reject) => setTimeout(() => reject(new Error("first approval did not crash after installing the current file")), 8000)),
  ]);
  assert.equal(firstApprovalCrashCode, 92, "injected process crash occurs after first current-file installation and before history creation");
  assert.ok(await interruptedFirstApproval instanceof Error, "the interrupted first approval does not return a success response");

  child = startChild(port);
  await waitForServer(port, child);
  const retriedFirstApproval = await mutate(`/approve/${encodeURIComponent(firstApprovalCrashName)}?folderId=root`, "POST", {});
  assert.equal(retriedFirstApproval.status, 200, retriedFirstApproval.body, "first approval retry recovers after the process exits before history creation");
  assert.deepEqual(fs.readFileSync(firstApprovalCurrentPath), firstApprovalBytes, "recovery retains the first approved bytes");
  const recoveredFirstHistory = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"))[`root/${firstApprovalCrashName}`];
  assert.equal(recoveredFirstHistory.currentVersion, 1, "first approval recovery creates exactly version 1");
  assert.equal(recoveredFirstHistory.versions.length, 1, "first approval recovery does not create a duplicate version");
  assert.equal(JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"))[`root/${firstApprovalCrashName}`], undefined, "successful first-approval recovery clears pending metadata");

  const crashApprovalName = "approve-crash-window.txt";
  const crashApprovalCurrentPath = path.join(directory, "uploads", crashApprovalName);
  const crashApprovalPendingPath = path.join(directory, "temp", crashApprovalName);
  const crashApprovalOriginalBytes = Buffer.from("prior approved version that must survive restart");
  const crashApprovalReplacementBytes = Buffer.from("replacement approved before history commit");
  fs.writeFileSync(crashApprovalCurrentPath, crashApprovalOriginalBytes);
  fs.writeFileSync(crashApprovalPendingPath, crashApprovalReplacementBytes);
  OBJECTS.set(`rootark/temp/root/${crashApprovalName}`, crashApprovalReplacementBytes);
  const crashApprovalPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  crashApprovalPermissions[`root/${crashApprovalName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(crashApprovalPermissions));
  const crashApprovalVersions = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"));
  crashApprovalVersions[`root/${crashApprovalName}`] = {
    currentVersion: 1,
    versions: [{ version: 1, storedAs: crashApprovalName, size: crashApprovalOriginalBytes.length }],
  };
  fs.writeFileSync(approvalRaceVersionsPath, JSON.stringify(crashApprovalVersions));
  const crashApprovalPendingUploads = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  crashApprovalPendingUploads[`root/${crashApprovalName}`] = { folderId: "root", fileName: crashApprovalName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(crashApprovalPendingUploads));

  await stop(child);
  child = startChild(port, {
    ROOTARK_TEST_CRASH_INSTALL_DESTINATION: crashApprovalCurrentPath,
  });
  assert.equal((await waitForServer(port, child)).status, 200);
  const crashExit = new Promise((resolve) => child.once("exit", resolve));
  const interruptedApproval = mutate(`/approve/${encodeURIComponent(crashApprovalName)}?folderId=root`, "POST", {}).catch((error) => error);
  const crashCode = await Promise.race([
    crashExit,
    new Promise((_, reject) => setTimeout(() => reject(new Error("approval did not crash after replacing the current file")), 8000)),
  ]);
  assert.equal(crashCode, 92, "injected process crash occurs after current-file replacement and before version-history persistence");
  assert.ok(await interruptedApproval instanceof Error, "the interrupted approval does not return a success response");

  child = startChild();
  await waitForServer(port, child);
  const retriedCrashApproval = await mutate(`/approve/${encodeURIComponent(crashApprovalName)}?folderId=root`, "POST", {});
  assert.equal(retriedCrashApproval.status, 200, retriedCrashApproval.body, "approval retry recovers after the process exits in the local replacement window");

  const archiveCrashName = "approve-archive-crash.txt";
  const archiveCrashCurrentPath = path.join(directory, "uploads", archiveCrashName);
  const archiveCrashPendingPath = path.join(directory, "temp", archiveCrashName);
  const archiveCrashVersionPath = path.join(directory, "uploads", `${archiveCrashName}.v1`);
  const archiveCrashOriginalBytes = Buffer.from("previous current bytes archived before crash");
  const archiveCrashReplacementBytes = Buffer.from("pending bytes awaiting current install");
  fs.writeFileSync(archiveCrashCurrentPath, archiveCrashOriginalBytes);
  fs.writeFileSync(archiveCrashPendingPath, archiveCrashReplacementBytes);
  OBJECTS.set(`rootark/temp/root/${archiveCrashName}`, archiveCrashReplacementBytes);
  const archiveCrashPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  archiveCrashPermissions[`root/${archiveCrashName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(archiveCrashPermissions));
  const archiveCrashVersions = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"));
  archiveCrashVersions[`root/${archiveCrashName}`] = {
    currentVersion: 1,
    versions: [{ version: 1, storedAs: archiveCrashName, size: archiveCrashOriginalBytes.length }],
  };
  fs.writeFileSync(approvalRaceVersionsPath, JSON.stringify(archiveCrashVersions));
  const archiveCrashPendingUploads = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  archiveCrashPendingUploads[`root/${archiveCrashName}`] = { folderId: "root", fileName: archiveCrashName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(archiveCrashPendingUploads));

  await stop(child);
  child = startChild(port, {
    ROOTARK_TEST_CRASH_RENAME_SYNC_SOURCE: archiveCrashCurrentPath,
    ROOTARK_TEST_CRASH_RENAME_SYNC_DESTINATION: archiveCrashVersionPath,
  });
  assert.equal((await waitForServer(port, child)).status, 200);
  const archiveCrashExit = new Promise((resolve) => child.once("exit", resolve));
  const interruptedArchiveApproval = mutate(`/approve/${encodeURIComponent(archiveCrashName)}?folderId=root`, "POST", {}).catch((error) => error);
  const archiveCrashCode = await Promise.race([
    archiveCrashExit,
    new Promise((_, reject) => setTimeout(() => reject(new Error("approval did not crash after archiving the current file")), 8000)),
  ]);
  assert.equal(archiveCrashCode, 90, "injected process crash occurs after currentPath is renamed to its archive and before pending bytes are copied");
  assert.ok(await interruptedArchiveApproval instanceof Error, "the interrupted archive-stage approval does not return a success response");

  child = startChild();
  await waitForServer(port, child);
  const retriedArchiveApproval = await mutate(`/approve/${encodeURIComponent(archiveCrashName)}?folderId=root`, "POST", {});
  assert.equal(retriedArchiveApproval.status, 200, retriedArchiveApproval.body, "approval retry recovers after the archived-current process crash");
  assert.deepEqual(fs.readFileSync(archiveCrashCurrentPath), archiveCrashReplacementBytes, "recovery installs the pending bytes as current");
  assert.deepEqual(fs.readFileSync(archiveCrashVersionPath), archiveCrashOriginalBytes, "recovery preserves the archived prior current bytes");
  const recoveredArchiveHistory = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"))[`root/${archiveCrashName}`];
  assert.equal(recoveredArchiveHistory.currentVersion, 2, "recovery advances history exactly once");
  assert.deepEqual(recoveredArchiveHistory.versions.map((version) => version.storedAs), [`${archiveCrashName}.v1`, archiveCrashName]);
  assert.equal(JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"))[`root/${archiveCrashName}`], undefined, "successful recovery clears the pending approval entry");

  const partialCopyCrashName = "approve-partial-copy-crash.txt";
  const partialCopyCurrentPath = path.join(directory, "uploads", partialCopyCrashName);
  const partialCopyPendingPath = path.join(directory, "temp", partialCopyCrashName);
  const partialCopyOriginalBytes = Buffer.from("previous approved bytes preserved by archive");
  const partialCopyReplacementBytes = Buffer.from("replacement bytes must be restored after a partial copy");
  fs.writeFileSync(partialCopyCurrentPath, partialCopyOriginalBytes);
  fs.writeFileSync(partialCopyPendingPath, partialCopyReplacementBytes);
  OBJECTS.set(`rootark/temp/root/${partialCopyCrashName}`, partialCopyReplacementBytes);
  const partialCopyPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  partialCopyPermissions[`root/${partialCopyCrashName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(partialCopyPermissions));
  const partialCopyVersions = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"));
  partialCopyVersions[`root/${partialCopyCrashName}`] = {
    currentVersion: 1,
    versions: [{ version: 1, storedAs: partialCopyCrashName, size: partialCopyOriginalBytes.length }],
  };
  fs.writeFileSync(approvalRaceVersionsPath, JSON.stringify(partialCopyVersions));
  const partialCopyPendingUploads = JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"));
  partialCopyPendingUploads[`root/${partialCopyCrashName}`] = { folderId: "root", fileName: partialCopyCrashName, uploadedBy: "viewer" };
  fs.writeFileSync(pendingUploadsFile, JSON.stringify(partialCopyPendingUploads));

  await stop(child);
  child = startChild(port, {
    ROOTARK_TEST_CRASH_PARTIAL_COPY_SOURCE: partialCopyPendingPath,
    ROOTARK_TEST_CRASH_PARTIAL_COPY_DESTINATION_PREFIX: path.join(directory, "uploads"),
  });
  assert.equal((await waitForServer(port, child)).status, 200);
  const partialCopyCrashExit = new Promise((resolve) => child.once("exit", resolve));
  const interruptedPartialCopyApproval = mutate(`/approve/${encodeURIComponent(partialCopyCrashName)}?folderId=root`, "POST", {}).catch((error) => error);
  const partialCopyCrashCode = await Promise.race([
    partialCopyCrashExit,
    new Promise((_, reject) => setTimeout(() => reject(new Error("approval did not crash during the partial current-file write")), 8000)),
  ]);
  assert.equal(partialCopyCrashCode, 91, "injected process crash leaves only a partial replacement write");
  assert.ok(await interruptedPartialCopyApproval instanceof Error, "the interrupted partial-copy approval does not return success");
  assert.equal(fs.existsSync(partialCopyCurrentPath), false, "partial staging never replaces or exposes the current-file path");
  const partialCopyStagingDirectory = path.join(directory, "uploads", ".rootark-approval-staging");
  assert.equal(fs.readdirSync(partialCopyStagingDirectory).length, 1, "restart recovery has one disposable partial stage to validate");

  child = startChild(port);
  await waitForServer(port, child);
  const retriedPartialCopyApproval = await mutate(`/approve/${encodeURIComponent(partialCopyCrashName)}?folderId=root`, "POST", {});
  assert.equal(retriedPartialCopyApproval.status, 200, retriedPartialCopyApproval.body, "retry recovers after a process crash during replacement copy");
  assert.deepEqual(fs.readFileSync(partialCopyCurrentPath), partialCopyReplacementBytes, "retry restores the exact pending replacement bytes");
  assert.deepEqual(fs.readFileSync(path.join(directory, "uploads", `${partialCopyCrashName}.v1`)), partialCopyOriginalBytes, "retry preserves the previous version archive");
  const recoveredPartialCopyHistory = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"))[`root/${partialCopyCrashName}`];
  assert.equal(recoveredPartialCopyHistory.currentVersion, 2, "partial-copy recovery advances version history exactly once");
  assert.deepEqual(recoveredPartialCopyHistory.versions.map((version) => version.storedAs), [`${partialCopyCrashName}.v1`, partialCopyCrashName]);
  assert.equal(JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"))[`root/${partialCopyCrashName}`], undefined, "successful partial-copy recovery clears the pending entry");
  assert.equal(fs.readdirSync(partialCopyStagingDirectory).length, 0, "successful retry consumes the staged replacement");

  assert.deepEqual(
    fs.readFileSync(path.join(directory, "uploads", `${crashApprovalName}.v1`)),
    crashApprovalOriginalBytes,
    "crash recovery keeps the previously approved version instead of overwriting it with the stranded replacement",
  );
  const recoveredCrashHistory = JSON.parse(fs.readFileSync(approvalRaceVersionsPath, "utf8"))[`root/${crashApprovalName}`];
  assert.equal(recoveredCrashHistory.currentVersion, 2, "retry records one replacement version after recovery");
  assert.deepEqual(recoveredCrashHistory.versions.map((version) => version.storedAs), [`${crashApprovalName}.v1`, crashApprovalName]);
  assert.equal(JSON.parse(fs.readFileSync(pendingUploadsFile, "utf8"))[`root/${crashApprovalName}`], undefined, "successful crash recovery clears the pending retry marker");

  const versionMutationRaceName = "v-lock.txt";
  const versionMutationRaceTarget = "v-renamed.txt";
  const versionMutationCurrentKey = `rootark/uploads/root/${versionMutationRaceName}`;
  const versionMutationArchiveName = `${versionMutationRaceName}.v1`;
  const versionMutationArchiveKey = `rootark/uploads/root/${versionMutationArchiveName}`;
  const versionMutationRenameKey = `rootark/uploads/root/${versionMutationRaceTarget}`;
  const versionMutationCurrentBytes = Buffer.from("current version before relocation");
  const versionMutationArchiveBytes = Buffer.from("archive before relocation");
  OBJECTS.set(versionMutationCurrentKey, versionMutationCurrentBytes);
  OBJECTS.set(versionMutationArchiveKey, versionMutationArchiveBytes);
  const versionMutationHistoryPath = path.join(dataDir, "file-versions.json");
  const versionMutationHistories = JSON.parse(fs.readFileSync(versionMutationHistoryPath, "utf8"));
  versionMutationHistories[`root/${versionMutationRaceName}`] = {
    currentVersion: 2,
    versions: [
      { version: 1, storedAs: versionMutationArchiveName, size: versionMutationArchiveBytes.length },
      { version: 2, storedAs: versionMutationRaceName, size: versionMutationCurrentBytes.length },
    ],
  };
  fs.writeFileSync(versionMutationHistoryPath, JSON.stringify(versionMutationHistories));
  const versionMutationPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  versionMutationPermissions[`root/${versionMutationRaceName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(versionMutationPermissions));
  const versionMutationGetBarrier = cloud.setGetBarrier([versionMutationCurrentKey]);
  const versionMutationRename = mutate("/rename", "PUT", { oldName: versionMutationRaceName, newName: versionMutationRaceTarget });
  await Promise.race([
    versionMutationGetBarrier.ready,
    versionMutationRename.then((result) => { throw new Error(`versioned rename ended before source GET barrier: ${result.status} ${result.body}`); }),
    new Promise((_, reject) => setTimeout(() => reject(new Error("versioned rename did not reach source GET barrier")), 8000)),
  ]);
  const versionMutationGetCount = cloud.getObjects.length;
  const versionRestoreDuringRename = mutate(`/restore/${encodeURIComponent(versionMutationRaceName)}/v/1?folderId=root`, "POST", {});
  const versionDeleteDuringRename = mutate(`/versions/${encodeURIComponent(versionMutationRaceName)}/v/1?folderId=root`, "DELETE", {});
  const [versionRestoreResult, versionDeleteResult] = await Promise.all([versionRestoreDuringRename, versionDeleteDuringRename]);
  const historyWhileRenamePaused = JSON.parse(fs.readFileSync(versionMutationHistoryPath, "utf8"))[`root/${versionMutationRaceName}`];
  assert.equal(cloud.getObjects.length, versionMutationGetCount, "blocked version mutations do not issue provider GETs");
  assert.equal(fs.existsSync(path.join(directory, "uploads", versionMutationRaceName)), false, "source GET remains blocked before cache hydration completes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", versionMutationArchiveName)), false, "version mutations cannot hydrate or remove archive bytes");
  assert.equal(historyWhileRenamePaused.currentVersion, 2, "concurrent version mutations leave history unchanged");
  assert.deepEqual(historyWhileRenamePaused.versions.map((version) => version.storedAs), [versionMutationArchiveName, versionMutationRaceName]);
  assert.equal(OBJECTS.has(versionMutationCurrentKey), true);
  assert.equal(OBJECTS.has(versionMutationArchiveKey), true);
  versionMutationGetBarrier.release(versionMutationCurrentKey);
  const versionMutationRenameResult = await versionMutationRename;
  assert.equal(versionRestoreResult.status, 503, versionRestoreResult.body, "version restore fails closed while rename owns the shared claim");
  assert.equal(versionDeleteResult.status, 503, versionDeleteResult.body, "version delete fails closed while rename owns the shared claim");
  assert.equal(versionMutationRenameResult.status, 200, versionMutationRenameResult.body);
  assert.deepEqual(OBJECTS.get(versionMutationRenameKey), versionMutationCurrentBytes);

  const changedSourceName = "drift-src.txt";
  const changedSourceTarget = "drift-dst.txt";
  OBJECTS.set(`rootark/uploads/root/${changedSourceName}`, Buffer.from("staged source bytes"));
  const changedSourcePermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  changedSourcePermissions[`root/${changedSourceName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(changedSourcePermissions));
  const changedTargetKey = `rootark/uploads/root/${changedSourceTarget}`;
  const changedPutBarrier = cloud.setPutBarrier([changedTargetKey]);
  const changedSourceRename = mutate("/rename", "PUT", { oldName: changedSourceName, newName: changedSourceTarget });
  await changedPutBarrier.ready;
  const changedSourcePath = path.join(directory, "uploads", changedSourceName);
  fs.writeFileSync(changedSourcePath, "replacement from an uncoordinated writer");
  changedPutBarrier.release(changedTargetKey);
  const changedSourceResult = await changedSourceRename;
  assert.notEqual(changedSourceResult.status, 200, "source identity drift during cloud staging cannot report a successful relocation");
  assert.equal(fs.readFileSync(changedSourcePath, "utf8"), "replacement from an uncoordinated writer", "abort preserves the newer local source");
  assert.equal(fs.existsSync(path.join(directory, "uploads", changedSourceTarget)), false, "abort does not install staged bytes at the destination");
  await waitFor(() => !OBJECTS.has(changedTargetKey));

  cloud.setPutFailureAfter(2);
  const failedVersionedRename = await mutate("/rename", "PUT", { oldName: "versioned-failure.txt", newName: "renamed-failure.txt" });
  cloud.setPutFailureAfter(0);
  assert.equal(failedVersionedRename.status, 503, failedVersionedRename.body);
  assert.equal(OBJECTS.has("rootark/uploads/root/versioned-failure.txt"), true, "failed archive copy keeps the original current object");
  assert.equal(OBJECTS.has("rootark/uploads/root/versioned-failure.txt.v1"), true, "failed archive copy keeps the original historical object");
  assert.equal(OBJECTS.has("rootark/uploads/root/renamed-failure.txt"), false, "failed archive copy rolls back the staged destination current object");
  assert.equal(OBJECTS.has("rootark/uploads/root/renamed-failure.txt.v1"), false, "failed copy does not leave a committed destination archive");
  const failedRenameHistory = await request(port, "/versions/versioned-failure.txt", { headers: { cookie } });
  assert.equal(failedRenameHistory.status, 200, failedRenameHistory.body);
  assert.equal(JSON.parse(failedRenameHistory.body).fileName, "versioned-failure.txt", "failed archive copy leaves the original history metadata authoritative");

  cloud.setPutFailureAfter(2, true);
  cloud.setDeleteFailure(true);
  const ambiguousVersionedRename = await mutate("/rename", "PUT", { oldName: "versioned-ambiguous.txt", newName: "renamed-ambiguous.txt" });
  cloud.setPutFailureAfter(0);
  assert.equal(ambiguousVersionedRename.status, 503, ambiguousVersionedRename.body);
  assert.equal(JSON.parse(ambiguousVersionedRename.body).status, "reconciliation_required", ambiguousVersionedRename.body);
  assert.equal(OBJECTS.has("rootark/uploads/root/versioned-ambiguous.txt"), true, "ambiguous staging leaves original current bytes authoritative");
  assert.equal(OBJECTS.has("rootark/uploads/root/versioned-ambiguous.txt.v1"), true, "ambiguous staging leaves original archive bytes authoritative");
  assert.equal(OBJECTS.has("rootark/uploads/root/renamed-ambiguous.txt"), true, "test simulates a provider that commits a PUT before losing its response");
  assert.equal(OBJECTS.has("rootark/uploads/root/renamed-ambiguous.txt.v1"), true, "failed cleanup leaves an unreferenced copy but reports reconciliation explicitly");
  assert.equal((await request(port, "/files/renamed-ambiguous.txt", { headers: { cookie: otherCookie } })).status, 403, "staged destination bytes stay private while cleanup is pending");
  const cleanupFile = fs.readdirSync(cleanupDirectory).find((file) => file.startsWith("rootark-cloud-relocation-cleanup-") && file.endsWith(".json"));
  assert.ok(cleanupFile, "failed cleanup is durably queued before the route reports reconciliation_required");
  cloud.setDeleteFailure(false);
  await waitFor(() => !fs.existsSync(path.join(cleanupDirectory, cleanupFile)));
  assert.equal(OBJECTS.has("rootark/uploads/root/renamed-ambiguous.txt"), false, "restart-safe cleanup removes ambiguous staged current objects after the provider recovers");
  assert.equal(OBJECTS.has("rootark/uploads/root/renamed-ambiguous.txt.v1"), false, "restart-safe cleanup removes ambiguous staged archive objects after the provider recovers");

  const remoteTrash = await mutate("/delete/trash-me.txt", "POST", {});
  assert.equal(remoteTrash.status, 200, remoteTrash.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/trash-me.txt"), true, "authorized trash hydrates the source before moving it");
  cloud.getObjects.length = 0;
  const trashRename = await mutate("/rename", "PUT", { oldName: "trash-me.txt", newName: "trashed-renamed.txt" });
  assert.equal(trashRename.status, 404, trashRename.body, "rename treats a trashed cloud source as not found");
  const trashMove = await mutate("/move", "PUT", { name: "trash-me.txt", fromFolderId: "root", toFolderId: "destination" });
  assert.equal(trashMove.status, 404, trashMove.body, "move treats a trashed cloud source as not found");
  assert.deepEqual(cloud.getObjects, [], "rename and move do not hydrate a trashed provider object");
  assert.equal(OBJECTS.has("rootark/uploads/root/trash-me.txt"), true, "trash provider retention semantics remain unchanged");
  assert.equal(OBJECTS.has("rootark/uploads/root/trashed-renamed.txt"), false, "rename does not create a provider destination for a trashed source");
  assert.equal(OBJECTS.has("rootark/uploads/destination/trash-me.txt"), false, "move does not create a provider destination for a trashed source");

  const malformedCleanupJournal = path.join(cleanupDirectory, `rootark-cloud-relocation-cleanup-${crypto.randomUUID()}.json`);
  fs.writeFileSync(malformedCleanupJournal, "{malformed journal");
  const blockedUpload = await request(port, "/dav/malformed-journal-upload.txt", {
    method: "PUT",
    headers: { authorization: webDavAuth, "content-length": "0" },
  });
  assert.equal(blockedUpload.status, 503, "malformed recovery state blocks upload with a bounded unavailable response");
  fs.rmSync(malformedCleanupJournal, { force: true });

  const foreignClaimId = crypto.randomUUID();
  const foreignClaimJournal = path.join(cleanupDirectory, `rootark-cloud-relocation-cleanup-${foreignClaimId}.json`);
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    ...JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8")),
    "root/foreign-claim.txt": { folderId: "root", fileName: "foreign-claim.txt", public: false, users: {}, cleanupPending: true },
  }));
  fs.writeFileSync(foreignClaimJournal, JSON.stringify({
    version: 1, transactionId: foreignClaimId, journalPath: foreignClaimJournal, provider: "s3",
    items: [{ folderId: "root", fileName: "foreign-claim.txt", area: "uploads", clearPermission: true }],
    attempts: 0, state: "queued", failureCategory: null, nextAttemptAt: null, createdAt: new Date().toISOString(),
  }));
  fs.writeFileSync(path.join(cleanupDirectory, `rootark-cloud-relocation-cleanup-${foreignClaimId}.lock`), JSON.stringify({
    version: 1, token: "remote-owner", transactionId: foreignClaimId, pid: 2147483647,
    hostname: "unreachable-other-host", processStartIdentity: null, claimedAt: new Date(0).toISOString(),
  }));
  await new Promise((resolve) => setTimeout(resolve, 1300));
  assert.equal(OBJECTS.has("rootark/uploads/root/foreign-claim.txt"), true, "a foreign-host claim fails closed instead of risking concurrent provider deletion");
  assert.equal(JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"))["root/foreign-claim.txt"].cleanupPending, true);

  const lockCrashName = "claim-crash.txt";
  const lockCrashTarget = "claim-recovered.txt";
  OBJECTS.set(`rootark/uploads/root/${lockCrashName}`, Buffer.from("atomic claim fixture"));
  const lockCrashPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  lockCrashPermissions[`root/${lockCrashName}`] = { public: false, owner: "viewer", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(lockCrashPermissions));
  await stop(child);
  const globalClaimId = "00000000-0000-4000-8000-000000000000";
  const globalClaimPath = path.join(cleanupDirectory, `rootark-cloud-relocation-cleanup-${globalClaimId}.lock`);
  child = startChild(port, { ROOTARK_TEST_CRASH_CLAIM_PUBLISH: globalClaimPath });
  await waitForServer(port, child);
  await mutate("/rename", "PUT", { oldName: lockCrashName, newName: lockCrashTarget }).catch(() => null);
  await waitFor(() => child.exitCode !== null, 2000);
  assert.equal(child.exitCode, 88, "the disposable process exits immediately after atomically publishing the claim");
  const publishedClaim = JSON.parse(fs.readFileSync(globalClaimPath, "utf8"));
  assert.equal(publishedClaim.transactionId, globalClaimId, "a crash after publication leaves a complete claim record");
  child = startChild();
  await waitForServer(port, child);
  const recoveredLockRename = await mutate("/rename", "PUT", { oldName: lockCrashName, newName: lockCrashTarget });
  assert.equal(recoveredLockRename.status, 200, recoveredLockRename.body);
  assert.deepEqual(fs.readFileSync(path.join(directory, "uploads", lockCrashTarget)), Buffer.from("atomic claim fixture"));

  for (const scenario of [
    { route: "/rename", payload: { oldName: "crash-rename.txt", newName: "renamed-after-crash.txt" }, source: "crash-rename.txt", destination: "renamed-after-crash.txt", sourceFolder: "root", destinationFolder: "root" },
    { route: "/move", payload: { name: "crash-move.txt", fromFolderId: "root", toFolderId: "destination" }, source: "crash-move.txt", destination: "crash-move.txt", sourceFolder: "root", destinationFolder: "destination" },
    { route: "/rename", payload: { oldName: "crash-abort.txt", newName: "crash-abort-target.txt" }, source: "crash-abort.txt", destination: "crash-abort-target.txt", sourceFolder: "root", destinationFolder: "root", beforeRename: true },
    { route: "/rename", payload: { oldName: "crash-ambiguous.txt", newName: "crash-ambiguous-target.txt" }, source: "crash-ambiguous.txt", destination: "crash-ambiguous-target.txt", sourceFolder: "root", destinationFolder: "root", duplicateSource: true, ambiguous: true },
  ]) {
    await stop(child);
    const sourcePath = path.join(directory, "uploads", ...(scenario.sourceFolder === "root" ? [] : [scenario.sourceFolder]), scenario.source);
    const destinationPath = path.join(directory, "uploads", ...(scenario.destinationFolder === "root" ? [] : [scenario.destinationFolder]), scenario.destination);
    child = startChild(port, {
      ROOTARK_TEST_CRASH_RENAME_SOURCE: sourcePath,
      ROOTARK_TEST_CRASH_RENAME_DESTINATION: destinationPath,
      ...(scenario.beforeRename ? { ROOTARK_TEST_CRASH_BEFORE_RENAME: "1" } : {}),
      ...(scenario.duplicateSource ? { ROOTARK_TEST_CRASH_DUPLICATE_SOURCE: "1" } : {}),
    });
    await waitForServer(port, child);
    let crashResponse;
    try { crashResponse = await mutate(scenario.route, "PUT", scenario.payload); } catch (error) { crashResponse = { error: error.message }; }
    await waitFor(() => child.exitCode !== null, 5000).catch(() => { throw new Error(`rename crash injector did not trigger: response=${JSON.stringify(crashResponse)} stderr=${child.startupLogs}`); });
    assert.equal(child.exitCode, scenario.beforeRename ? 87 : 86, `test preload terminates at the local ${scenario.route} boundary`);
    if (scenario.ambiguous) {
      assert.equal(fs.existsSync(sourcePath), true);
      assert.equal(fs.existsSync(destinationPath), true);
    } else if (scenario.beforeRename) {
      assert.equal(fs.existsSync(sourcePath), true);
      assert.equal(fs.existsSync(destinationPath), false);
    } else {
      assert.equal(fs.existsSync(sourcePath), false, "the local commit happened before the injected process crash");
      assert.equal(fs.existsSync(destinationPath), true);
    }

    child = startChild();
    await waitForServer(port, child);
    const staleSource = await request(port, `/files/${encodeURIComponent(scenario.source)}?folderId=${encodeURIComponent(scenario.sourceFolder)}`, { headers: { cookie: otherCookie } });
    if (scenario.ambiguous) {
      const ambiguousDestination = await request(port, `/files/${encodeURIComponent(scenario.destination)}?folderId=${encodeURIComponent(scenario.destinationFolder)}`, { headers: { cookie } });
      assert.notEqual(staleSource.status, 200, "ambiguous source identity remains reserved");
      assert.notEqual(ambiguousDestination.status, 200, "ambiguous destination identity remains reserved");
      assert.equal(OBJECTS.has(`rootark/uploads/${scenario.sourceFolder}/${scenario.source}`), true, "ambiguous recovery performs no provider deletion");
      assert.equal(OBJECTS.has(`rootark/uploads/${scenario.destinationFolder}/${scenario.destination}`), true, "ambiguous staged destination remains reserved for manual recovery");
    } else if (scenario.beforeRename) {
      assert.equal(staleSource.status, 200, staleSource.body, "prepared intent abort preserves the source");
      await waitFor(() => !OBJECTS.has(`rootark/uploads/${scenario.destinationFolder}/${scenario.destination}`));
      const restoredPermissions = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
      assert.deepEqual(restoredPermissions["root/crash-abort-target.txt"], { public: false, owner: "other", users: {} }, "aborted staging restores the prior destination ACL");
    } else {
      assert.notEqual(staleSource.status, 200, `restart recovery blocks stale ${scenario.route} source access`);
      await waitFor(() => !OBJECTS.has(`rootark/uploads/${scenario.sourceFolder}/${scenario.source}`));
      const committedDestination = await request(port, `/files/${encodeURIComponent(scenario.destination)}?folderId=${encodeURIComponent(scenario.destinationFolder)}`, { headers: { cookie } });
      assert.equal(committedDestination.status, 200, committedDestination.body);
    }
  }
});
