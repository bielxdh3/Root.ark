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
const SERVER = process.env.ROOTARK_TEST_SERVER || path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;
const FOLDER_ID = "upload-safety";

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

function multipartParts(parts, { close = true } = {}) {
  const boundary = `----rootark-${crypto.randomBytes(12).toString("hex")}`;
  const chunks = [];
  for (const { field = "file", filename, bytes = Buffer.alloc(0) } of parts) {
    const disposition = filename === undefined
      ? `--${boundary}\r\nContent-Disposition: form-data; name="${field}"\r\n\r\n`
      : `--${boundary}\r\nContent-Disposition: form-data; name="${field}"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
    chunks.push(Buffer.from(disposition), Buffer.from(bytes), Buffer.from("\r\n"));
  }
  if (close) chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return {
    body: Buffer.concat(chunks),
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

function multipart(filename, bytes) {
  return multipartParts([{ filename, bytes }]);
}

function isContained(parent, candidate) {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative !== "" && !relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative);
}

async function createHarness(t, { chunkSessions = [], preloadSource = "", waitForReady = true, uploaderPermissions = {}, secondUploaderHasFolderAccess = false, envOverrides = {} } = {}) {
  const password = crypto.randomBytes(24).toString("base64url");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-upload-safety-"));
  const quarantineDir = path.join(dir, "quarantine");
  fs.mkdirSync(path.join(dir, "data"));
  fs.cpSync(PUBLIC, path.join(dir, "public"), { recursive: true });
  const users = [
    { username: "uploader", password: bcrypt.hashSync(password, 10), role: "user", permissions: { upload: true, listFiles: true, ...uploaderPermissions }, sessionVersion: 0 },
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: {}, sessionVersion: 0 },
  ];
  if (secondUploaderHasFolderAccess) {
    users.push({ username: "other-uploader", password: bcrypt.hashSync(password, 10), role: "user", permissions: { upload: true, listFiles: true }, sessionVersion: 0 });
  }
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify(users));
  fs.writeFileSync(path.join(dir, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: FOLDER_ID, name: "Upload safety", createdBy: "uploader", allowedUsers: secondUploaderHasFolderAccess ? ["other-uploader"] : [] },
  ]));
  const chunkRoot = path.join(dir, "temp", ".chunks");
  for (const session of chunkSessions) {
    const sessionDir = path.join(chunkRoot, session.folderId || FOLDER_ID, session.uploadId);
    fs.mkdirSync(sessionDir, { recursive: true });
    for (const [name, contents] of Object.entries(session.files || {})) {
      const bytes = name === "metadata.json" && typeof contents !== "string" ? JSON.stringify(contents) : contents;
      fs.writeFileSync(path.join(sessionDir, name), bytes);
    }
  }
  const preloadContents = typeof preloadSource === "function" ? preloadSource({ dir, chunkRoot }) : preloadSource;
  const preloadPath = preloadContents ? path.join(dir, "test-preload.js") : "";
  if (preloadPath) fs.writeFileSync(preloadPath, preloadContents);
  const port = await getUnusedPort();
  const stdout = [];
  const stderr = [];
  const child = spawn(process.execPath, [...(preloadPath ? ["--require", preloadPath] : []), SERVER], {
    cwd: dir,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(port),
      DB_ENABLED: "false",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      UPLOAD_SCAN_ENABLED: "true",
      UPLOAD_SCAN_PROVIDER: "disabled",
      UPLOAD_BLOCK_EXECUTABLES: "true",
      UPLOAD_QUARANTINE_DIR: quarantineDir,
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.on("data", (chunk) => stdout.push(chunk.toString()));
  child.stderr.on("data", (chunk) => stderr.push(chunk.toString()));
  t.after(async () => {
    if (child.exitCode === null) {
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, TIMEOUT_MS);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
        child.kill();
      });
    }
    fs.rmSync(dir, { recursive: true, force: true });
    assert.equal(fs.existsSync(dir), false);
  });
  if (waitForReady) assert.equal((await waitForServer(port)).status, 200);
  return { dir, port, quarantineDir, password, chunkRoot, child, stdout, stderr };
}

async function startGatedClamAv() {
  const scans = [];
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let commandReceived = false;
    let streamComplete = false;
    let releaseRequested = false;
    let responded = false;
    let markStarted;
    const gate = {
      started: new Promise((resolve) => { markStarted = resolve; }),
      release: () => {
        releaseRequested = true;
        respondWhenReady();
      },
    };
    scans.push(gate);
    function respondWhenReady() {
      if (!responded && releaseRequested && streamComplete) {
        responded = true;
        socket.end("stream: OK\0");
      }
    }
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!commandReceived) {
        if (buffer.length < 10) return;
        assert.equal(buffer.subarray(0, 10).toString("binary"), "zINSTREAM\0");
        buffer = buffer.subarray(10);
        commandReceived = true;
        markStarted();
      }

      let offset = 0;
      while (buffer.length >= offset + 4) {
        const length = buffer.readUInt32BE(offset);
        offset += 4;
        if (length === 0) {
          streamComplete = true;
          buffer = buffer.subarray(offset);
          respondWhenReady();
          return;
        }
        if (buffer.length < offset + length) {
          buffer = buffer.subarray(offset - 4);
          return;
        }
        offset += length;
      }
      buffer = buffer.subarray(offset);
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  return { server, port: server.address().port, scans };
}

async function upload(port, session, filename, bytes) {
  const payload = multipart(filename, bytes);
  return uploadPayload(port, session, payload);
}

async function uploadPayload(port, session, payload) {
  return request(port, `/upload?folderId=${FOLDER_ID}`, {
    method: "POST",
    headers: {
      cookie: session.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": session.csrf,
      "content-type": payload.contentType,
      "content-length": payload.body.length,
    },
    body: payload.body,
  });
}

async function uploadChunk(port, session, { uploadId, originalName, chunkIndex, totalChunks, bytes, encryptionLevel, password, versionComment, expiresInDays }) {
  const parts = [
    { field: "uploadId", bytes: uploadId },
    { field: "originalName", bytes: originalName },
    { field: "chunkIndex", bytes: String(chunkIndex) },
    { field: "totalChunks", bytes: String(totalChunks) },
  ];
  for (const [field, value] of [["encryptionLevel", encryptionLevel], ["password", password], ["versionComment", versionComment], ["expiresInDays", expiresInDays]]) {
    if (value !== undefined) parts.push({ field, bytes: String(value) });
  }
  parts.push({ field: "chunk", filename: originalName, bytes });
  const payload = multipartParts(parts);
  return request(port, `/upload-chunk?folderId=${FOLDER_ID}`, {
    method: "POST",
    headers: {
      cookie: session.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": session.csrf,
      "content-type": payload.contentType,
      "content-length": payload.body.length,
    },
    body: payload.body,
  });
}

async function postJson(port, session, requestPath, value) {
  const body = Buffer.from(JSON.stringify(value));
  return request(port, requestPath, {
    method: "POST",
    headers: {
      cookie: session.cookie,
      origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": session.csrf,
      "content-type": "application/json",
      "content-length": body.length,
    },
    body,
  });
}

function waitForExit(child, timeout = TIMEOUT_MS) {
  if (child.exitCode !== null) return Promise.resolve(child.exitCode);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("server process did not exit")), timeout);
    child.once("exit", (code) => { clearTimeout(timer); resolve(code); });
  });
}

async function waitForFile(filePath, timeout = TIMEOUT_MS) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (fs.existsSync(filePath)) return true;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  return fs.existsSync(filePath);
}

function legacyChunkMetadata(uploadId, overrides = {}) {
  return {
    uploadId,
    folderId: FOLDER_ID,
    originalName: "encrypted.txt",
    fileName: "encrypted.txt",
    totalChunks: 2,
    uploadedBy: "uploader",
    uploaderSessionVersion: 0,
    versionComment: "",
    encryptionLevel: "password",
    expiresInDays: "",
    createdAt: new Date().toISOString(),
    password: "legacy-secret-that-must-be-removed",
    ...overrides,
  };
}

function auditLogs(dir) {
  const file = path.join(dir, "data", "audit-logs.json");
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")).logs : [];
}

function auditLogFileSignature(file) {
  const stat = fs.statSync(file, { bigint: true });
  return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}`;
}

async function waitForAuditLogs(dir, predicate, timeout = 3000) {
  const file = path.join(dir, "data", "audit-logs.json");
  const deadline = Date.now() + timeout;
  let lastSignature = auditLogFileSignature(file);
  let activeWriteUntil = 0;

  while (Date.now() < deadline) {
    const before = auditLogFileSignature(file);
    if (before !== lastSignature) activeWriteUntil = Date.now() + 100;
    try {
      const logs = JSON.parse(fs.readFileSync(file, "utf8")).logs;
      if (predicate(logs)) return logs;
    } catch (error) {
      const after = auditLogFileSignature(file);
      if (after !== before) activeWriteUntil = Date.now() + 100;
      if (!(error instanceof SyntaxError) || Date.now() >= activeWriteUntil) throw error;
      lastSignature = after;
      await new Promise((resolve) => setTimeout(resolve, 10));
      continue;
    }

    const after = auditLogFileSignature(file);
    if (after !== before) activeWriteUntil = Date.now() + 100;
    lastSignature = after;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }

  throw new Error("timed out waiting for expected audit logs");
}

test("waits for audit logs to finish an observed rewrite before parsing", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-write-race-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, "data"));
  const file = path.join(dir, "data", "audit-logs.json");
  fs.writeFileSync(file, JSON.stringify({ logs: [] }));

  const expected = [{ id: "first" }, { id: "second" }];
  const waiting = waitForAuditLogs(dir, (logs) => logs.length === expected.length);
  await new Promise((resolve) => setTimeout(resolve, 10));
  fs.writeFileSync(file, "{\"logs\":[");
  await new Promise((resolve) => setTimeout(resolve, 20));
  fs.writeFileSync(file, JSON.stringify({ logs: expected }));
  assert.deepEqual(await waiting, expected);

  fs.writeFileSync(file, "{\"logs\":[");
  await assert.rejects(waitForAuditLogs(dir, () => true), SyntaxError, "stable malformed JSON fails without a retry window");
  fs.rmSync(file);
  await assert.rejects(waitForAuditLogs(dir, () => true), { code: "ENOENT" }, "non-JSON file errors fail immediately");
});

const CHUNK_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

test("chunk-session sweep retries leftover parts after a tombstone unlink failure", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-part-unlink-retry";
  const markerDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-chunk-unlink-markers-"));
  const failurePath = path.join(markerDir, "failure");
  const retrySweepPath = path.join(markerDir, "retry");
  t.after(() => fs.rmSync(markerDir, { recursive: true, force: true }));
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "60000" },
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }),
        "0.part": "expired plaintext",
      },
    }],
    preloadSource: `
      const fs = require("node:fs");
      const unlinkSync = fs.unlinkSync;
      const originalSetInterval = global.setInterval;
      let failedOnce = false;
      fs.unlinkSync = function (target, ...args) {
        if (!failedOnce && String(target).includes(${JSON.stringify(uploadId)}) && String(target).endsWith("0.part")) {
          failedOnce = true;
          fs.writeFileSync(${JSON.stringify(failurePath)}, "injected");
          throw Object.assign(new Error("injected one-time unlink failure"), { code: "EIO" });
        }
        return unlinkSync.call(this, target, ...args);
      };
      global.setInterval = (callback, delay, ...args) => {
        if (String(callback).includes("cleanupExpiredChunkSessions")) {
          return originalSetInterval((...callbackArgs) => {
            if (fs.existsSync(${JSON.stringify(retrySweepPath)})) callback(...callbackArgs);
          }, 25, ...args);
        }
        return originalSetInterval(callback, delay, ...args);
      };
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const metadataPath = path.join(sessionDir, "metadata.json");
  const partPath = path.join(sessionDir, "0.part");
  assert.equal(await waitForFile(failurePath), true, "startup sweep injected one unlink failure");
  const firstMarker = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  assert.deepEqual(Object.keys(firstMarker), ["__expiredAt"]);
  assert.equal(fs.existsSync(partPath), true, "part remains after the failed first sweep");

  const expiryEventsPromise = waitForAuditLogs(harness.dir, (logs) => logs.filter((entry) =>
    entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId
  ).length >= 2);
  fs.writeFileSync(retrySweepPath, "run", { flag: "wx", mode: 0o600 });
  const retryDeadline = Date.now() + 3000;
  while (fs.existsSync(partPath) && Date.now() < retryDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(partPath), false, "a later sweep removes the leftover part promptly");
  assert.deepEqual(JSON.parse(fs.readFileSync(metadataPath, "utf8")), firstMarker, "retry preserves the original tombstone and its seven-day TTL");
  const expiryEvents = (await expiryEventsPromise).filter((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.deepEqual(expiryEvents.map((entry) => ({ result: entry.result, details: entry.details })), [
    { result: "failure", details: { source: "sweeper" } },
    { result: "success", details: { source: "sweeper" } },
  ], "audit records the failed initial deletion and successful retry without payload data");
});

test("expired chunk sessions are removed at seven days while recent and unsafe sessions are preserved", { timeout: 45_000 }, async (t) => {
  const expiredId = "seven-day-expired";
  const markerExpiredId = "expired-tombstone-cleaned";
  const recentId = "seven-day-recent";
  const unsafeId = "seven-day-invalid-activity";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } },
      { uploadId: markerExpiredId, files: { "metadata.json": { __expiredAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }, "0.part": "expired leftover plaintext" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString() }), "0.part": "recent plaintext" } },
      { uploadId: unsafeId, files: { "metadata.json": legacyChunkMetadata(unsafeId, { lastActivityAt: "not-a-timestamp" }), "0.part": "preserve unsafe session" } },
    ],
  });

  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const markerExpiredDir = path.join(harness.chunkRoot, FOLDER_ID, markerExpiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  const unsafeDir = path.join(harness.chunkRoot, FOLDER_ID, unsafeId);
  const expiredMarker = JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8"));
  assert.equal(typeof expiredMarker.__expiredAt, "string", "expired uploads retain only a bounded marker that blocks stale resumes");
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, "all chunk plaintext is removed at seven days");
  assert.equal(fs.existsSync(markerExpiredDir), false, "old metadata-only tombstones are eventually removed");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent plaintext");
  const blockedMetadata = JSON.parse(fs.readFileSync(path.join(unsafeDir, "metadata.json"), "utf8"));
  assert.equal(blockedMetadata.__resumeBlocked, true, "invalid activity metadata is blocked instead of expiring by inference");
  assert.equal(fs.readFileSync(path.join(unsafeDir, "0.part"), "utf8"), "preserve unsafe session");
});

test("an expired upload cannot resume from its old chunks after restart cleanup", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-upload-cannot-resume";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 1).toISOString() }), "0.part": "expired plaintext" } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must start a new upload"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), false);
  assert.equal(typeof JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8")).__expiredAt, "string");
  assert.deepEqual(pending(harness.dir), {});
});

test("valid accepted chunk activity refreshes the seven-day session window", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-refreshes-window";
  const lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString();
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 3, encryptionLevel: "none", originalName: "activity.txt", fileName: "activity.txt", lastActivityAt }),
        "0.part": "first chunk",
      },
    }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "activity.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  assert.equal(response.status, 200, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.ok(Date.parse(metadata.lastActivityAt) > Date.parse(lastActivityAt));
  assert.ok(Math.abs(Date.now() - Date.parse(metadata.lastActivityAt)) < 5_000);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part"), "utf8"), "second chunk");
});

test("an active incoming chunk does not defer cleanup of unrelated expired sessions", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-with-other-incoming-upload";
  const incomingFile = "active-staging-fixture";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } }],
    preloadSource: ({ chunkRoot }) => {
      const incomingDir = path.join(chunkRoot, "incoming");
      fs.mkdirSync(incomingDir, { recursive: true });
      fs.writeFileSync(path.join(incomingDir, incomingFile), "active upload staging data");
      return "";
    },
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const cleanupDeadline = Date.now() + 5_000;
  while (fs.existsSync(path.join(sessionDir, "0.part")) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, "unrelated expired chunk data is still pruned");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", incomingFile), "utf8"), "active upload staging data", "the sweeper leaves incoming upload staging files untouched");
});

test("the chunk-session sweeper shares the session lock and preserves activity committed before unlock", { timeout: 45_000 }, async (t) => {
  const uploadId = "sweeper-session-lock";
  const harness = await createHarness(t, { envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" } });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  fs.mkdirSync(sessionDir, { recursive: true });
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(legacyChunkMetadata(uploadId, {
    lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString(),
    encryptionLevel: "none",
  }), null, 2));
  fs.writeFileSync(path.join(sessionDir, "0.part"), "keep active part");
  const sessionIdentity = path.resolve(sessionDir);
  const lockIdentity = process.platform === "win32" ? sessionIdentity.toLowerCase() : sessionIdentity;
  const lock = createFileLifecycleLock({ directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"), timeoutMs: 10_000, pollMs: 5 });
  let releaseLock;
  let markLockHeld;
  const lockHeld = new Promise((resolve) => { markLockHeld = resolve; });
  const heldOperation = lock.runFolder(`chunk-upload:${lockIdentity}`, async () => {
    markLockHeld();
    await new Promise((resolve) => { releaseLock = resolve; });
  });
  await lockHeld;
  await new Promise((resolve) => setTimeout(resolve, 1250));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), true, "the sweeper waits for the upload session lock");
  const metadataPath = path.join(sessionDir, "metadata.json");
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.lastActivityAt = new Date().toISOString();
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
  releaseLock();
  await heldOperation;
  await new Promise((resolve) => setTimeout(resolve, 1250));
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "keep active part");

  metadata.lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString();
  fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2));
  const cleanupDeadline = Date.now() + 5_000;
  while (fs.existsSync(sessionDir) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, "the periodic sweeper deletes expired chunk data");
  assert.equal(typeof JSON.parse(fs.readFileSync(metadataPath, "utf8")).__expiredAt, "string");
});

test("a different uploader cannot overwrite or finish another user's chunk session", { timeout: 45_000 }, async (t) => {
  const uploadId = "session-owner-binding";
  const originalPart = "owner's first chunk";
  const harness = await createHarness(t, {
    secondUploaderHasFolderAccess: true,
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 2, encryptionLevel: "none", originalName: "owner-file.txt", fileName: "owner-file.txt", uploadedBy: "uploader" }), "0.part": originalPart } }],
  });
  const otherUploader = await login(harness.port, "other-uploader", harness.password);
  const response = await uploadChunk(harness.port, otherUploader, {
    uploadId,
    originalName: "owner-file.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("attacker's final chunk"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), originalPart);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
  assert.deepEqual(pending(harness.dir), {});
});

test("case-folded account aliases cannot resume another exact uploader identity", { timeout: 45_000 }, async (t) => {
  const uploadId = "case-alias-session-owner";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { encryptionLevel: "none" }), "0.part": "original chunk" } }],
  });
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  users.push({ username: "UPLOADER", password: bcrypt.hashSync(harness.password, 10), role: "user", permissions: { upload: true, listFiles: true }, sessionVersion: 0 });
  fs.writeFileSync(usersPath, JSON.stringify(users));
  const foldersPath = path.join(harness.dir, "data", "folders.json");
  const folders = JSON.parse(fs.readFileSync(foldersPath, "utf8"));
  folders.find((folder) => folder.id === FOLDER_ID).allowedUsers.push("UPLOADER");
  fs.writeFileSync(foldersPath, JSON.stringify(folders));
  const alias = await login(harness.port, "UPLOADER", harness.password);
  const response = await uploadChunk(harness.port, alias, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("alias chunk"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "original chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

test("a recreated uploader account with a newer session generation cannot resume old chunks", { timeout: 45_000 }, async (t) => {
  const uploadId = "recreated-uploader-generation";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { encryptionLevel: "none" }), "0.part": "old account chunk" } }],
  });
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  users[0].sessionVersion = 1;
  fs.writeFileSync(usersPath, JSON.stringify(users));
  const recreatedAccount = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, recreatedAccount, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("new account chunk"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "old account chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

test("unbound pre-migration chunk sessions fail closed and preserve their parts", { timeout: 45_000 }, async (t) => {
  const uploadId = "legacy-unbound-session";
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none" });
  delete legacyMetadata.uploaderSessionVersion;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "unbound legacy chunk" } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must not bind legacy data"),
  });
  assert.equal(response.status, 409, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.equal(metadata.__resumeBlocked, true);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "unbound legacy chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

test("recent unbound legacy sessions retain only validated expiry data and remain non-resumable", { timeout: 45_000 }, async (t) => {
  const uploadId = "recent-unbound-legacy-session";
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none", lastActivityAt: new Date().toISOString() });
  delete legacyMetadata.uploaderSessionVersion;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "retain recent legacy chunk" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata).sort(), ["__resumeBlocked", "folderId", "lastActivityAt", "totalChunks", "uploadId"]);
  assert.equal(metadata.__resumeBlocked, true);
  assert.equal(metadata.uploadId, uploadId);
  assert.equal(metadata.folderId, FOLDER_ID);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain recent legacy chunk");

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("never attach to old data"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain recent legacy chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
});

test("startup gives an unbound legacy session without activity a fresh blocked retention window", { timeout: 45_000 }, async (t) => {
  const uploadId = "startup-unbound-legacy-no-activity";
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none" });
  delete legacyMetadata.uploaderSessionVersion;
  delete legacyMetadata.lastActivityAt;
  const migrationStartedAt = Date.now();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "retain legacy chunk" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata).sort(), ["__resumeBlocked", "folderId", "lastActivityAt", "totalChunks", "uploadId"]);
  assert.equal(metadata.__resumeBlocked, true);
  assert.ok(Date.parse(metadata.lastActivityAt) >= migrationStartedAt);
  assert.ok(Date.now() - Date.parse(metadata.lastActivityAt) < 5_000);
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("cannot resume old data"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain legacy chunk");
});

test("request blocks and timestamps an unbound legacy session created without activity metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "request-unbound-legacy-no-activity";
  const harness = await createHarness(t);
  const legacyMetadata = legacyChunkMetadata(uploadId, { encryptionLevel: "none" });
  delete legacyMetadata.uploaderSessionVersion;
  delete legacyMetadata.lastActivityAt;
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  fs.mkdirSync(sessionDir, { recursive: true });
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(legacyMetadata));
  fs.writeFileSync(path.join(sessionDir, "0.part"), "retain runtime legacy chunk");
  const conversionStartedAt = Date.now();
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("cannot bind runtime legacy data"),
  });
  assert.equal(response.status, 409, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(metadata).sort(), ["__resumeBlocked", "folderId", "lastActivityAt", "totalChunks", "uploadId"]);
  assert.equal(metadata.__resumeBlocked, true);
  assert.ok(Date.parse(metadata.lastActivityAt) >= conversionStartedAt);
  assert.ok(Date.now() - Date.parse(metadata.lastActivityAt) < 5_000);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "retain runtime legacy chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
});

test("stale unbound legacy sessions expire safely while remaining non-resumable", { timeout: 45_000 }, async (t) => {
  const uploadId = "stale-unbound-legacy-session";
  const legacyMetadata = legacyChunkMetadata(uploadId, {
    encryptionLevel: "none",
    lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString(),
  });
  delete legacyMetadata.uploaderSessionVersion;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyMetadata, "0.part": "expire stale legacy chunk" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const marker = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.deepEqual(Object.keys(marker), ["__expiredAt"]);
  assert.equal(typeof marker.__expiredAt, "string");
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
  const event = auditLogs(harness.dir).find((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.ok(event);
  assert.deepEqual(event.details, { source: "sweeper" });

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("cannot resume expired data"),
  });
  assert.equal(response.status, 409, response.body);
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
});

test("malformed blocked legacy sessions preserve their data instead of being swept", { timeout: 45_000 }, async (t) => {
  const uploadId = "malformed-blocked-legacy-session";
  const malformedBlockedMetadata = {
    __resumeBlocked: true,
    uploadId,
    folderId: FOLDER_ID,
    totalChunks: 2,
    lastActivityAt: "not-a-timestamp",
  };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": malformedBlockedMetadata, "0.part": "preserve malformed blocked data" } }],
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), malformedBlockedMetadata);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "preserve malformed blocked data");
  assert.equal(auditLogs(harness.dir).some((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId), false);
});

test("periodic expiry audits successful deletion with safe session identifiers", { timeout: 45_000 }, async (t) => {
  const uploadId = "audited-expired-session";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 1).toISOString() }), "0.part": "sensitive uploaded bytes" } }],
  });
  const events = auditLogs(harness.dir).filter((entry) => entry.eventType === "upload.chunk_session.expired");
  assert.equal(events.length, 1);
  assert.deepEqual(events[0].actor, { username: "system", role: "system", ip: null, userAgent: null });
  assert.deepEqual(events[0].target, { type: "chunk_session", id: uploadId, folderId: FOLDER_ID });
  assert.equal(events[0].action, "expired");
  assert.equal(events[0].result, "success");
  assert.deepEqual(events[0].details, { source: "sweeper" });
  assert.equal(JSON.stringify(events[0]).includes("sensitive uploaded bytes"), false);
});

test("request-triggered expiry audits successful deletion", { timeout: 45_000 }, async (t) => {
  const uploadId = "request-audited-expired-session";
  const harness = await createHarness(t);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  fs.mkdirSync(sessionDir, { recursive: true });
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(legacyChunkMetadata(uploadId)));
  fs.writeFileSync(path.join(sessionDir, "0.part"), "request-triggered sensitive bytes");
  const metadataPath = path.join(sessionDir, "metadata.json");
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 1).toISOString();
  fs.writeFileSync(metadataPath, JSON.stringify(metadata));
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("new chunk"),
  });
  assert.equal(response.status, 409, response.body);
  const event = auditLogs(harness.dir).find((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.ok(event);
  assert.equal(event.actor.username, "system");
  assert.deepEqual(event.target, { type: "chunk_session", id: uploadId, folderId: FOLDER_ID });
  assert.deepEqual(event.details, { source: "request" });
  assert.equal(JSON.stringify(event).includes("request-triggered sensitive bytes"), false);
});

test("non-expired sessions are inspected without acquiring durable filesystem locks", { timeout: 45_000 }, async (t) => {
  const uploadId = "recent-session-no-lock";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date().toISOString() }), "0.part": "recent chunk" } }],
  });
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(fs.existsSync(path.join(harness.dir, "data", ".rootark-cloud-file-locks")), false);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "recent chunk");
});

test("overlapping expiry sweep ticks do not start competing session-lock work", { timeout: 45_000 }, async (t) => {
  const uploadId = "overlapping-sweep-session";
  const lockAttemptsPath = path.join(os.tmpdir(), `rootark-chunk-sweep-lock-attempts-${crypto.randomUUID()}.txt`);
  t.after(() => fs.rmSync(lockAttemptsPath, { force: true }));
  const lockModulePath = path.join(ROOT, "services", "fileLifecycleLock.js");
  const harness = await createHarness(t, {
    waitForReady: false,
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired chunk" } }],
    preloadSource: `
      const fs = require("node:fs");
      const lifecycle = require(${JSON.stringify(lockModulePath)});
      const create = lifecycle.createFileLifecycleLock;
      lifecycle.createFileLifecycleLock = (options) => {
        const lock = create(options);
        const runFolder = lock.runFolder;
        lock.runFolder = async (...args) => {
          fs.appendFileSync(${JSON.stringify(lockAttemptsPath)}, "attempt\\n");
          await new Promise((resolve) => setTimeout(resolve, 2000));
          return runFolder(...args);
        };
        return lock;
      };
    `,
  });
  assert.equal(await waitForFile(lockAttemptsPath), true);
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(fs.readFileSync(lockAttemptsPath, "utf8").trim().split(/\r?\n/).length, 1);
});

test("chunk-session expiry sweep yields to requests and eventually reaches later sessions", { timeout: 45_000 }, async (t) => {
  const sweepCount = 128;
  const sweepDelayMs = 50;
  const lastUploadId = `sweep-yield-${sweepCount - 1}`;
  const markerDir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-chunk-sweep-markers-"));
  const delayEnabledPath = path.join(markerDir, "delay-enabled");
  const sweepStartedPath = `${delayEnabledPath}.started`;
  t.after(() => fs.rmSync(markerDir, { recursive: true, force: true }));
  fs.writeFileSync(delayEnabledPath, "enabled", { flag: "wx", mode: 0o600 });
  const chunkSessions = Array.from({ length: sweepCount }, (_, index) => {
    const uploadId = `sweep-yield-${index}`;
    const isLast = index === sweepCount - 1;
    return {
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          lastActivityAt: new Date().toISOString(),
        }),
        "0.part": isLast ? "late expired chunk" : "recent chunk",
      },
    };
  });
  const metadataPrefix = path.join(os.tmpdir(), "rootark-upload-safety-");
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    waitForReady: false,
    chunkSessions,
    preloadSource: `
      const fs = require("node:fs");
      const open = fs.promises.open.bind(fs.promises);
      let metadataOpens = 0;
      let delayedMetadataOpens = 0;
      fs.promises.open = async (target, ...args) => {
        const handle = await open(target, ...args);
        if (String(target).startsWith(${JSON.stringify(metadataPrefix)}) && String(target).endsWith("metadata.json")) {
          metadataOpens += 1;
          if (metadataOpens > ${sweepCount}) {
            await new Promise((resolve) => setTimeout(resolve, ${sweepDelayMs}));
            delayedMetadataOpens += 1;
            if (delayedMetadataOpens === 8) fs.writeFileSync(${JSON.stringify(sweepStartedPath)}, "8 delayed reads complete");
          }
        }
        return handle;
      };
    `,
  });

  assert.equal(await waitForFile(sweepStartedPath), true, "the periodic sweep completed eight delayed metadata reads after startup scanning");
  const lastMetadataPath = path.join(harness.chunkRoot, FOLDER_ID, lastUploadId, "metadata.json");
  const lastMetadata = JSON.parse(fs.readFileSync(lastMetadataPath, "utf8"));
  lastMetadata.lastActivityAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString();
  fs.writeFileSync(lastMetadataPath, JSON.stringify(lastMetadata));
  const finalPartPath = path.join(harness.chunkRoot, FOLDER_ID, lastUploadId, "0.part");
  assert.equal(fs.existsSync(finalPartPath), true, "the final session remains intact until the periodic sweep runs");
  const requestStartedAt = Date.now();
  const response = await request(harness.port, "/login.html");
  const requestDuration = Date.now() - requestStartedAt;
  assert.equal(response.status, 200);
  const remainingSweepDelayMs = (sweepCount - 8) * sweepDelayMs;
  assert.ok(requestDuration < remainingSweepDelayMs / 2, `normal request took ${requestDuration}ms with at least ${remainingSweepDelayMs}ms of sequential metadata delays still queued`);

  const cleanupDeadline = Date.now() + 10_000;
  while (fs.existsSync(finalPartPath) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(finalPartPath), false, "the sweep eventually processes the last expired session");
});

test("failed chunk rename does not refresh accepted activity", { timeout: 45_000 }, async (t) => {
  const uploadId = "failed-chunk-rename-preserves-activity";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3, originalName: "encrypted.txt", encryptionLevel: "none" }), "0.part": "already accepted chunk" } }],
    preloadSource: `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      fs.renameSync = (source, destination) => {
        if (String(destination).endsWith(".part")) throw Object.assign(new Error("fixture rename failure"), { code: "EIO" });
        return renameSync.call(fs, source, destination);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("rename must fail"),
  });
  assert.equal(response.status, 500, response.body);
  const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.equal(metadata.lastActivityAt, previousActivity);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "already accepted chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
});

function filesUnder(dir) {
  if (!fs.existsSync(dir)) return [];
  if (fs.statSync(dir).isFile()) return [crypto.createHash("sha256").update(fs.readFileSync(dir)).digest("hex")];
  return fs.readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name)
    .sort();
}

function assertRejectedClean(harness, response, expectedStatus = 400) {
  assert.equal(response.status, expectedStatus, response.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.deepEqual(quarantine(harness.dir).items, []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", ".incoming")), []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", FOLDER_ID)), []);
  assert.deepEqual(filesUnder(harness.quarantineDir), []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "uploads")), []);
}

function pending(dir) {
  const file = path.join(dir, "data", "pending-uploads.json");
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : {};
}

function quarantine(dir) {
  const file = path.join(dir, "data", "quarantine.json");
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : { items: [] };
}

test("authorized harmless multipart upload enters the selected folder pending area", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("harmless upload\n");
  const response = await upload(harness.port, session, "notes.txt", bytes);
  const result = JSON.parse(response.body);

  assert.equal(response.status, 200);
  assert.equal(result.message, "Upload enviado para aprovacao");
  assert.equal(result.fileName, "notes.txt");
  assert.equal(result.folderId, FOLDER_ID);
  assert.deepEqual(pending(harness.dir)[`${FOLDER_ID}/notes.txt`], {
    uploadedBy: "uploader",
    uploadedAt: pending(harness.dir)[`${FOLDER_ID}/notes.txt`].uploadedAt,
    versionComment: "",
    compressedUpload: false,
    folderId: FOLDER_ID,
  });
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "notes.txt")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
  assert.deepEqual(fs.existsSync(harness.quarantineDir) ? fs.readdirSync(harness.quarantineDir) : [], []);
});

test("unavailable ClamAV fails closed before simple, chunked, or WebDAV uploads can reach approval", { timeout: 45_000 }, async (t) => {
  const unavailablePort = await getUnusedPort();
  const harness = await createHarness(t, {
    uploaderPermissions: { approve: true },
    envOverrides: {
      UPLOAD_SCAN_PROVIDER: "clamav",
      UPLOAD_FAIL_CLOSED: "",
      CLAMAV_HOST: "127.0.0.1",
      CLAMAV_PORT: String(unavailablePort),
      WEBDAV_ENABLED: "true",
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const simple = await upload(harness.port, session, "unavailable-simple.txt", Buffer.from("disposable simple bytes"));
  const chunked = await uploadChunk(harness.port, session, {
    uploadId: "unavailable-final-chunk",
    originalName: "unavailable-chunk.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("disposable chunk bytes"),
  });
  const webDav = await request(harness.port, `/dav/${FOLDER_ID}/unavailable-webdav.txt`, {
    method: "PUT",
    headers: {
      authorization: "Basic " + Buffer.from(`uploader:${harness.password}`).toString("base64"),
      "content-length": "23",
    },
    body: Buffer.from("disposable WebDAV bytes"),
  });

  for (const response of [simple, chunked, webDav]) assert.equal(response.status, 503, response.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(quarantine(harness.dir).items.length, 3);
  assert.deepEqual(filesUnder(path.join(harness.dir, "uploads")), []);
  for (const name of ["unavailable-simple.txt", "unavailable-chunk.txt", "unavailable-webdav.txt"]) {
    const approval = await postJson(harness.port, session, `/approve/${name}?folderId=${FOLDER_ID}`, {});
    assert.equal(approval.status, 404, approval.body);
  }
});

test("clean ClamAV INSTREAM responses with the protocol NUL terminator allow pending registration", { timeout: 30_000 }, async (t) => {
  const scanner = await startGatedClamAv();
  t.after(async () => {
    for (const gate of scanner.scans) gate.release();
    await new Promise((resolve) => scanner.server.close(resolve));
  });
  const harness = await createHarness(t, {
    envOverrides: { UPLOAD_SCAN_PROVIDER: "clamav", CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.port) },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("disposable clean scan fixture");
  const uploadPromise = upload(harness.port, session, "clean-scan.txt", bytes);
  const deadline = Date.now() + TIMEOUT_MS;
  while (!scanner.scans.length && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(scanner.scans[0], "upload did not reach ClamAV");
  await scanner.scans[0].started;
  scanner.scans[0].release();

  const response = await uploadPromise;
  assert.equal(response.status, 200, response.body);
  assert.equal(pending(harness.dir)[`${FOLDER_ID}/clean-scan.txt`].folderId, FOLDER_ID);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "clean-scan.txt")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
});

test("unknown upload scan providers fail startup instead of skipping scanning", { timeout: 10_000 }, async (t) => {
  const harness = await createHarness(t, {
    waitForReady: false,
    envOverrides: { UPLOAD_SCAN_PROVIDER: "unknown-provider", UPLOAD_FAIL_CLOSED: "false" },
  });
  const exitCode = await waitForExit(harness.child, 3_000);

  assert.notEqual(exitCode, 0);
  assert.match(harness.stderr.join(""), /UPLOAD_SCAN_PROVIDER/);
});

test("non-development startup rejects disabled or fail-open upload scanning", { timeout: 30_000 }, async (t) => {
  const configurations = [
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "disabled" }, error: /production.*upload scanning/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_FAIL_CLOSED: "false" }, error: /production.*upload scanning/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_ENABLED: "false", UPLOAD_SCAN_PROVIDER: "clamav" }, error: /production.*upload scanning/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_BLOCK_EXECUTABLES: "false" }, error: /production.*executable extension blocking/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_SUSPICIOUS_EXTENSIONS: ".txt" }, error: /production.*default suspicious-extension denylist/i },
    { env: { NODE_ENV: "production", UPLOAD_SCAN_PROVIDER: "clamav", UPLOAD_SUSPICIOUS_EXTENSIONS: ", " }, error: /production.*default suspicious-extension denylist/i },
    { env: { NODE_ENV: "staging", UPLOAD_SCAN_PROVIDER: "disabled" }, error: /bypass requires NODE_ENV=development or test/i },
  ];

  for (const { env: envOverrides, error } of configurations) {
    const harness = await createHarness(t, { waitForReady: false, envOverrides });
    const exitCode = await waitForExit(harness.child, 3_000);
    assert.notEqual(exitCode, 0);
    assert.match(harness.stderr.join(""), error);
  }
});

test("production allows additive suspicious extensions while retaining its required denylist", { timeout: 15_000 }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: {
      NODE_ENV: "production",
      UPLOAD_SCAN_PROVIDER: "clamav",
      UPLOAD_SUSPICIOUS_EXTENSIONS: ".exe,.bat,.cmd,.scr,.msi,.ps1,.vbs,.jar,.com,.custom",
    },
  });

  assert.equal(harness.child.exitCode, null);
});

test("wrong encrypted-file password stays an input error and records failed decrypt only", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { uploaderPermissions: { approve: true } });
  const session = await login(harness.port, "uploader", harness.password);
  const correctPassword = "correct-test-file-password";
  const payload = multipartParts([
    { field: "encryptionLevel", bytes: "password" },
    { field: "password", bytes: correctPassword },
    { filename: "password-check.txt", bytes: Buffer.from("disposable encrypted fixture") },
  ]);
  const uploaded = await uploadPayload(harness.port, session, payload);
  assert.equal(uploaded.status, 200, uploaded.body);
  const approved = await postJson(harness.port, session, `/approve/password-check.txt?folderId=${FOLDER_ID}`, {});
  assert.equal(approved.status, 200, approved.body);

  const wrongPassword = await postJson(harness.port, session, `/encrypted-download/password-check.txt?folderId=${FOLDER_ID}`, { password: "wrong-test-file-password" });
  assert.equal(wrongPassword.status, 422, wrongPassword.body);
  const stillAuthenticated = await request(harness.port, "/auth/me", { headers: { cookie: session.cookie } });
  assert.equal(stillAuthenticated.status, 200, stillAuthenticated.body);
  const audit = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "audit-logs.json"), "utf8"));
  assert.ok(audit.logs.some((entry) => entry.eventType === "file.decrypt.failed" && entry.result === "failure"));
  assert.equal(audit.logs.some((entry) => entry.eventType === "file.decrypt" && entry.result === "success"), false);
});

test("traversal-style multipart filenames stay contained in the selected folder", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const cases = [["../../outside.txt", "outside.txt"], ["..\\..\\outside-win.txt", "outside-win.txt"]];
  const tempDir = path.join(harness.dir, "temp", FOLDER_ID);

  for (const [submittedName, expectedName] of cases) {
    const response = await upload(harness.port, session, submittedName, Buffer.from(submittedName));
    const result = JSON.parse(response.body);
    const storedPath = path.join(tempDir, result.fileName);
    assert.equal(response.status, 200);
    assert.equal(result.fileName, expectedName);
    assert.equal(result.originalName, expectedName);
    assert.equal(result.fileName.includes("/"), false);
    assert.equal(result.fileName.includes("\\"), false);
    assert.equal(result.originalName.includes("/"), false);
    assert.equal(result.originalName.includes("\\"), false);
    assert.equal(isContained(tempDir, storedPath), true);
    assert.equal(fs.existsSync(storedPath), true);
    assert.equal(fs.existsSync(path.join(harness.dir, path.basename(submittedName))), false);
    const entry = pending(harness.dir)[`${FOLDER_ID}/${result.fileName}`];
    assert.equal(entry.folderId, FOLDER_ID);
    assert.equal(entry.originalName === undefined || (!entry.originalName.includes("/") && !entry.originalName.includes("\\")), true);
  }
  assert.equal(fs.existsSync(path.join(path.dirname(harness.dir), "outside.txt")), false);
  assert.equal(fs.existsSync(path.join(path.dirname(harness.dir), "outside-win.txt")), false);
});

test("suspicious executable extensions are quarantined before pending upload registration", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const response = await upload(harness.port, session, "harmless.exe", Buffer.from("plain text only"));
  const result = JSON.parse(response.body);
  const items = quarantine(harness.dir).items;

  assert.equal(response.status, 415);
  assert.equal(result.error, "Upload bloqueado por politica de seguranca.");
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "harmless.exe")), false);
  assert.equal(items.length, 1);
  assert.equal(items[0].reason, "suspicious_extension");
  const quarantinedPath = path.join(harness.quarantineDir, items[0].storedQuarantineFilename);
  assert.equal(isContained(harness.quarantineDir, quarantinedPath), true);
  assert.deepEqual(fs.readFileSync(quarantinedPath), Buffer.from("plain text only"));
});

test("suspicious executable extensions remain blocked with Windows trailing-dot or trailing-space aliases", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const fixtures = [
    ["payload-trailing-dot.exe.", Buffer.from("trailing dot executable fixture")],
    ["payload-trailing-space.exe ", Buffer.from("trailing space executable fixture")],
  ];

  for (const [fileName, bytes] of fixtures) {
    const response = await upload(harness.port, session, fileName, bytes);
    assert.equal(response.status, 415, response.body);
  }

  assert.deepEqual(pending(harness.dir), {});
  const items = quarantine(harness.dir).items;
  assert.equal(items.length, fixtures.length);
  assert.ok(items.every((item) => item.reason === "suspicious_extension"));
  const quarantinedBytes = items.map((item) => fs.readFileSync(path.join(harness.quarantineDir, item.storedQuarantineFilename)).toString());
  assert.deepEqual(quarantinedBytes.sort(), fixtures.map(([, bytes]) => bytes.toString()).sort());
});

test("suspicious executable extensions remain quarantined when development scanning is disabled", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "true" } });
  const session = await login(harness.port, "uploader", harness.password);
  const bytesByRoute = new Map([
    ["multipart", Buffer.from("inert multipart fixture")],
    ["chunked", Buffer.from("inert chunked fixture")],
    ["webdav", Buffer.from("inert WebDAV fixture")],
  ]);
  const simple = await upload(harness.port, session, "disabled-scan-multipart.exe.", bytesByRoute.get("multipart"));
  const chunked = await uploadChunk(harness.port, session, {
    uploadId: "disabled-scan-executable",
    originalName: "disabled-scan-chunked.exe ",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: bytesByRoute.get("chunked"),
  });
  const webDav = await request(harness.port, `/dav/${FOLDER_ID}/disabled-scan-webdav.exe.`, {
    method: "PUT",
    headers: {
      authorization: "Basic " + Buffer.from(`uploader:${harness.password}`).toString("base64"),
      "content-length": bytesByRoute.get("webdav").length,
    },
    body: bytesByRoute.get("webdav"),
  });
  const items = quarantine(harness.dir).items;

  for (const response of [simple, chunked, webDav]) assert.equal(response.status, 415, response.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(items.length, bytesByRoute.size);
  assert.ok(items.every((item) => item.reason === "suspicious_extension"));
  const quarantinedBytes = items.map((item) => {
    const quarantinedPath = path.join(harness.quarantineDir, item.storedQuarantineFilename);
    assert.equal(isContained(harness.quarantineDir, quarantinedPath), true);
    return fs.readFileSync(quarantinedPath).toString();
  });
  assert.deepEqual(quarantinedBytes.sort(), Array.from(bytesByRoute.values(), (bytes) => bytes.toString()).sort());
  assert.deepEqual(filesUnder(path.join(harness.dir, "uploads")), []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", ".incoming")), []);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", FOLDER_ID)), []);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, FOLDER_ID)), []);
});

test("ordinary text uploads remain available when development scanning is disabled", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { UPLOAD_SCAN_ENABLED: "false" } });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("ordinary text upload");
  const response = await upload(harness.port, session, "disabled-scan.txt", bytes);

  assert.equal(response.status, 200, response.body);
  assert.equal(pending(harness.dir)[`${FOLDER_ID}/disabled-scan.txt`].folderId, FOLDER_ID);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "disabled-scan.txt")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
});

test("development scanning can explicitly opt out of the executable extension block", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { UPLOAD_SCAN_ENABLED: "false", UPLOAD_BLOCK_EXECUTABLES: "false" } });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("explicit development opt-out fixture");
  const response = await upload(harness.port, session, "opt-out.exe", bytes);

  assert.equal(response.status, 200, response.body);
  assert.equal(pending(harness.dir)[`${FOLDER_ID}/opt-out.exe`].folderId, FOLDER_ID);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "opt-out.exe")), bytes);
  assert.deepEqual(quarantine(harness.dir).items, []);
});

test("users without upload permission are rejected before Multer creates artifacts", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "viewer", harness.password);
  const response = await upload(harness.port, session, "denied.txt", Buffer.from("denied"));

  assert.equal(response.status, 403);
  assert.deepEqual(JSON.parse(response.body), { error: "Permissao negada: upload" });
  assertRejectedClean(harness, response, 403);
});

test("dot-segment upload IDs are rejected without touching sibling chunk sessions", { timeout: 30_000 }, async (t) => {
  const siblingId = "preserved-sibling-session";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId: siblingId, files: { "sentinel.txt": "preserve this session" } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const siblingDirectory = path.join(harness.chunkRoot, FOLDER_ID, siblingId);

  for (const uploadId of [".", ".."]) {
    const response = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "invalid.txt",
      chunkIndex: 0,
      totalChunks: 1,
      bytes: Buffer.from("must not be staged"),
    });
    assert.equal(response.status, 400, response.body);
    assert.equal(fs.readFileSync(path.join(siblingDirectory, "sentinel.txt"), "utf8"), "preserve this session");
    assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  }
});

test("upload chunk route limit rejects requests before Multer writes staging files", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { ROUTE_RATE_LIMIT_MAX: "1" } });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, {
    uploadId: "rate-limited-first",
    originalName: "first.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first"),
  });
  assert.equal(first.status, 200, first.body);

  const rejectedId = "rate-limited-before-multer";
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: rejectedId,
    originalName: "rejected.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(rejected.status, 429, rejected.body);
  assert.match(rejected.headers["retry-after"] || "", /^\d+$/);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, rejectedId)), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("chunk uploads accept the 8 MiB contract and reject larger parts without staging artifacts", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const maxPartBytes = 8 * 1024 * 1024;
  const acceptedId = "max-size-chunk-accepted";
  const accepted = await uploadChunk(harness.port, session, {
    uploadId: acceptedId,
    originalName: "large-client-file.bin",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(maxPartBytes, 0x61),
  });
  assert.equal(accepted.status, 200, accepted.body);
  assert.equal(fs.statSync(path.join(harness.chunkRoot, FOLDER_ID, acceptedId, "0.part")).size, maxPartBytes);

  const rejectedId = "oversize-chunk-rejected";
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: rejectedId,
    originalName: "oversized-client-part.bin",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(maxPartBytes + 1, 0x62),
  });
  assert.equal(rejected.status, 413, rejected.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, rejectedId)), false);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("Multer rejects malformed or disallowed multipart bodies without artifacts", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const checkout = [path.join(ROOT, "temp", ".incoming"), path.join(ROOT, "temp", FOLDER_ID), path.join(ROOT, "data", "pending-uploads.json"), path.join(ROOT, "data", "quarantine.json")];
  const checkoutBefore = checkout.map((target) => filesUnder(target));
  const normal = multipart("truncated.txt", Buffer.from("partial"));
  const cases = [
    ["truncated multipart body", { ...normal, body: normal.body.subarray(0, normal.body.length - 8) }],
    ["malformed boundary", { body: Buffer.from("not-a-multipart-body"), contentType: "multipart/form-data; boundary=missing" }],
    ["unexpected file field", multipartParts([{ field: "attachment", filename: "wrong.txt", bytes: "wrong" }])],
    ["multiple file parts", multipartParts([{ filename: "one.txt", bytes: "one" }, { filename: "two.txt", bytes: "two" }])],
    ["nested field name", multipartParts([{ field: "versionComment[nested]", bytes: "value" }, { filename: "nested.txt", bytes: "file" }])],
    ["oversized file", multipart("large.bin", Buffer.alloc(8 * 1024 * 1024 + 1, 0x61))],
  ];

  for (const [name, payload] of cases) {
    await t.test(name, async () => {
      const response = await uploadPayload(harness.port, session, payload);
      assertRejectedClean(harness, response);
      assert.deepEqual(checkout.map((target) => filesUnder(target)), checkoutBefore);
    });
  }
});

test("valid binary and UTF-8 filename uploads preserve bytes and API names", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from([0, 255, 1, 254, 13, 10, 128, 127]);
  const fileName = "ação-測試.bin";
  const response = await upload(harness.port, session, fileName, bytes);
  const result = JSON.parse(response.body);

  assert.equal(response.status, 200, response.body);
  assert.equal(result.fileName, fileName);
  assert.equal(result.originalName, fileName);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
});

test("chunk uploads scrub legacy secrets and require the final password before saving the last part", { timeout: 45_000 }, async (t) => {
  const legacyId = "legacy-resume";
  const firstPart = Buffer.from("resumed ");
  const finalPart = Buffer.from("upload\n");
  const migrationStartedAt = Date.now();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId: legacyId, files: { "metadata.json": legacyChunkMetadata(legacyId), "0.part": firstPart } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const legacyDir = path.join(harness.chunkRoot, FOLDER_ID, legacyId);
  const legacyMetadataPath = path.join(legacyDir, "metadata.json");
  const scrubbedLegacyMetadata = JSON.parse(fs.readFileSync(legacyMetadataPath, "utf8"));
  assert.equal(Object.hasOwn(scrubbedLegacyMetadata, "password"), false);
  assert.ok(Date.parse(scrubbedLegacyMetadata.lastActivityAt) >= migrationStartedAt, "legacy sessions receive a conservative fresh retention window");
  assert.equal(fs.readFileSync(path.join(legacyDir, "0.part")).toString(), firstPart.toString());

  const password = "final-only-secret-42";
  const resumed = await uploadChunk(harness.port, session, {
    uploadId: legacyId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: finalPart,
    password,
  });
  assert.equal(resumed.status, 200, resumed.body);
  assert.equal(JSON.parse(resumed.body).complete, true);
  const encryptedFilePath = path.join(harness.dir, "temp", FOLDER_ID, "encrypted.txt");
  const encryptedFile = fs.readFileSync(encryptedFilePath);
  const encryptedMetadata = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "encrypted-files.json"), "utf8"))[`${FOLDER_ID}/encrypted.txt`];
  assert.equal(encryptedMetadata.accessControl.requiresPassword, true);
  assert.equal(JSON.stringify(encryptedMetadata).includes(password), false);
  assert.notDeepEqual(encryptedFile, Buffer.concat([firstPart, finalPart]));
  const layer = encryptedMetadata.layers.find((item) => item.type === "password");
  const key = crypto.pbkdf2Sync(password, Buffer.from(layer.salt, "hex"), encryptedMetadata.iterations, 32, "sha256");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(layer.iv, "hex"));
  decipher.setAuthTag(Buffer.from(layer.authTag, "hex"));
  const decrypted = Buffer.concat([decipher.update(encryptedFile), decipher.final()]);
  assert.deepEqual(decrypted, Buffer.concat([firstPart, finalPart]));

  const newUploadId = "new-password-upload";
  const first = await uploadChunk(harness.port, session, {
    uploadId: newUploadId,
    originalName: "new-encrypted.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first "),
    encryptionLevel: "password",
    password,
  });
  assert.equal(first.status, 200, first.body);
  const newSessionDir = path.join(harness.chunkRoot, FOLDER_ID, newUploadId);
  const firstMetadata = JSON.parse(fs.readFileSync(path.join(newSessionDir, "metadata.json"), "utf8"));
  assert.equal(Object.hasOwn(firstMetadata, "password"), false);
  assert.equal(JSON.stringify(firstMetadata).includes(password), false);
  assert.equal(fs.existsSync(path.join(newSessionDir, "1.part")), false);

  const rejectedFinal = await uploadChunk(harness.port, session, {
    uploadId: newUploadId,
    originalName: "new-encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("last"),
  });
  assert.equal(rejectedFinal.status, 400, rejectedFinal.body);
  assert.match(JSON.parse(rejectedFinal.body).error, /bloco final/i);
  assert.equal(fs.readFileSync(path.join(newSessionDir, "0.part")).toString(), "first ");
  assert.equal(fs.existsSync(path.join(newSessionDir, "1.part")), false);

  const acceptedFinal = await uploadChunk(harness.port, session, {
    uploadId: newUploadId,
    originalName: "new-encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("last"),
    password,
  });
  assert.equal(acceptedFinal.status, 200, acceptedFinal.body);
  assert.equal(JSON.parse(acceptedFinal.body).complete, true);
  assert.equal(fs.existsSync(newSessionDir), false);
  assert.equal((harness.stdout.join("") + harness.stderr.join("")).includes(password), false);
});

test("chunk session ids and numeric chunk indexes remain contained at their boundaries", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);

  const traversal = await uploadChunk(harness.port, session, {
    uploadId: "../outside-session",
    originalName: "bounded.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: "must not escape",
  });
  assert.equal(traversal.status, 400, traversal.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "outside-session")), false);

  const uploadId = "bounded-index";
  const acceptedBoundary = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "bounded.txt",
    chunkIndex: 1999,
    totalChunks: 2000,
    bytes: "last allowed index",
  });
  assert.equal(acceptedBoundary.status, 200, acceptedBoundary.body);
  assert.equal(JSON.parse(acceptedBoundary.body).complete, false);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.readFileSync(path.join(sessionDir, "1999.part"), "utf8"), "last allowed index");

  const rejectedBoundary = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "bounded.txt",
    chunkIndex: 2000,
    totalChunks: 2000,
    bytes: "out of range",
  });
  assert.equal(rejectedBoundary.status, 400, rejectedBoundary.body);
  assert.equal(fs.existsSync(path.join(sessionDir, "2000.part")), false);
});

test("malformed, unreadable, and orphan chunk sessions cannot overwrite retained parts", { timeout: 45_000 }, async (t) => {
  let unreadableMetadataPath;
  let markerPath;
  const unreadableId = "unreadable-session";
  const malformedId = "malformed-session";
  const orphanId = "orphan-session";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: unreadableId, files: { "metadata.json": legacyChunkMetadata(unreadableId), "0.part": "unreadable-original" } },
      { uploadId: malformedId, files: { "metadata.json": "{invalid", "0.part": "malformed-original" } },
      { uploadId: orphanId, files: { "0.part": "orphan-original" } },
    ],
    preloadSource: ({ dir, chunkRoot }) => {
      unreadableMetadataPath = path.join(chunkRoot, FOLDER_ID, unreadableId, "metadata.json");
      markerPath = path.join(dir, "unreadable-read-attempted");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const target = ${JSON.stringify(unreadableMetadataPath)};`,
        `const marker = ${JSON.stringify(markerPath)};`,
        "const originalOpenSync = fs.openSync;",
        "fs.openSync = function (file, flags, ...args) {",
        "  if (typeof file === 'string' && path.resolve(file) === path.resolve(target) && (flags & fs.constants.O_RDONLY) === fs.constants.O_RDONLY) {",
        "    fs.writeFileSync(marker, 'triggered');",
        "    const error = new Error('injected metadata read failure'); error.code = 'EACCES'; throw error;",
        "  }",
        "  return originalOpenSync.call(this, file, flags, ...args);",
        "};",
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal(fs.readFileSync(markerPath, "utf8"), "triggered");
  for (const [uploadId, partName, original] of [
    [unreadableId, "0.part", "unreadable-original"],
    [malformedId, "0.part", "malformed-original"],
    [orphanId, "0.part", "orphan-original"],
  ]) {
    const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
    const blocked = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
    assert.equal(blocked.__resumeBlocked, true, uploadId);
    assert.equal(JSON.stringify(blocked).includes("legacy-secret-that-must-be-removed"), false);
    const response = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "encrypted.txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: "attempted-overwrite",
      encryptionLevel: "password",
      password: "new-password-42",
    });
    assert.equal(response.status, 409, response.body);
    assert.equal(fs.readFileSync(path.join(sessionDir, partName), "utf8"), original);
  }
});

test("unsafe chunk session symlinks are rejected before touching the target", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const folderDir = path.join(harness.chunkRoot, FOLDER_ID);
  const targetDir = path.join(harness.dir, "outside-session-target");
  fs.mkdirSync(folderDir, { recursive: true });
  fs.mkdirSync(targetDir);
  fs.writeFileSync(path.join(targetDir, "keep.txt"), "do not touch");
  const sessionDir = path.join(folderDir, "linked-session");
  try {
    fs.symlinkSync(targetDir, sessionDir, process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip(`directory symlink unavailable: ${error.code}`);
    throw error;
  }

  const response = await uploadChunk(harness.port, session, {
    uploadId: "linked-session",
    originalName: "encrypted.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "must-not-write",
    encryptionLevel: "password",
    password: "new-password-42",
  });
  assert.equal(response.status, 400, response.body);
  assert.equal(fs.readFileSync(path.join(targetDir, "keep.txt"), "utf8"), "do not touch");
  assert.equal(fs.existsSync(path.join(targetDir, "0.part")), false);
});

test("chunk upload storage symlinks are rejected before Multer creates files outside the storage root", { timeout: 30_000 }, async (t) => {
  let outsidePath;
  let markerPath;
  const harness = await createHarness(t, {
    waitForReady: false,
    preloadSource: ({ dir }) => {
      outsidePath = path.join(dir, "outside-chunk-storage");
      markerPath = path.join(dir, "chunk-storage-symlink-created");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const root = ${JSON.stringify(dir)};`,
        `const outside = ${JSON.stringify(outsidePath)};`,
        `const marker = ${JSON.stringify(markerPath)};`,
        'const temp = path.join(root, "temp");',
        'const chunkRoot = path.join(temp, ".chunks");',
        'fs.mkdirSync(temp, { recursive: true });',
        'fs.mkdirSync(outside, { recursive: true });',
        'try {',
        '  fs.symlinkSync(outside, chunkRoot, process.platform === "win32" ? "junction" : "dir");',
        '  fs.writeFileSync(marker, "created");',
        '} catch (error) {',
        '  fs.writeFileSync(marker, `unavailable:${error.code || "unknown"}`);',
        '}',
      ].join("\n");
    },
  });

  assert.equal(await waitForFile(markerPath), true, "startup did not reach the injected storage path setup");
  const setup = fs.readFileSync(markerPath, "utf8");
  if (setup.startsWith("unavailable:")) return t.skip(`chunk storage symlink unavailable: ${setup.slice("unavailable:".length)}`);

  assert.notEqual(await waitForExit(harness.child), 0);
  assert.equal(fs.existsSync(path.join(outsidePath, "incoming")), false);
  await assert.rejects(request(harness.port, "/login.html"));
});

test("chunk upload startup fails closed when chunk-session enumeration cannot be verified", { timeout: 45_000 }, async (t) => {
  for (const targetName of ["root", "folder"]) {
    await t.test(`${targetName} directory enumeration failure`, { timeout: 20_000 }, async (nested) => {
      let markerPath;
      const harness = await createHarness(nested, {
        waitForReady: false,
        chunkSessions: targetName === "folder" ? [{ uploadId: "enumeration-seed", files: {} }] : [],
        preloadSource: ({ dir, chunkRoot }) => {
          const targetPath = targetName === "root" ? chunkRoot : path.join(chunkRoot, FOLDER_ID);
          markerPath = path.join(dir, "enumeration-failure-injected");
          return [
            'const fs = require("node:fs");',
            'const path = require("node:path");',
            `const target = ${JSON.stringify(targetPath)};`,
            `const marker = ${JSON.stringify(markerPath)};`,
            "const originalReaddirSync = fs.readdirSync;",
            "fs.readdirSync = function (directory, ...args) {",
            "  if (typeof directory === 'string' && path.resolve(directory) === path.resolve(target)) {",
            "    fs.writeFileSync(marker, 'triggered');",
            "    const error = new Error('injected directory enumeration failure'); error.code = 'EACCES'; throw error;",
            "  }",
            "  return originalReaddirSync.call(this, directory, ...args);",
            "};",
          ].join("\n");
        },
      });
      assert.notEqual(await waitForExit(harness.child), 0);
      assert.equal(fs.readFileSync(markerPath, "utf8"), "triggered");
      await assert.rejects(request(harness.port, "/login.html"));
    });
  }
});

test("folder lifecycle lock timeouts reject uploads and remove all disposable staging files", { timeout: 30_000 }, async (t) => {
  const uploadId = "lifecycle-timeout-chunk";
  let timeoutResponseMarker;
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          originalName: "timeout-chunk.txt",
          fileName: "timeout-chunk.txt",
          totalChunks: 1,
          encryptionLevel: "none",
        }),
      },
    }],
    preloadSource: ({ dir }) => {
      const sessionDir = path.join(dir, "temp", ".chunks", FOLDER_ID, uploadId);
      timeoutResponseMarker = path.join(dir, "chunk-timeout-response-marker.txt");
      return [
        "const lockModule = require(" + JSON.stringify(path.join(ROOT, "services", "fileLifecycleLock.js")) + ");",
        "const create = lockModule.createFileLifecycleLock;",
        "lockModule.createFileLifecycleLock = (options) => create({ ...options, timeoutMs: 150, pollMs: 5 });",
        'const fs = require("node:fs");',
        `const expressResponse = require(${JSON.stringify(require.resolve("express/lib/response", { paths: [ROOT] }))});`,
        `const sessionDir = ${JSON.stringify(sessionDir)};`,
        `const markerPath = ${JSON.stringify(timeoutResponseMarker)};`,
        "const originalJson = expressResponse.json;",
        'expressResponse.json = function (...args) { if (this.statusCode === 503 && this.req?.url?.startsWith("/upload-chunk")) fs.writeFileSync(markerPath, fs.existsSync(sessionDir) ? "present" : "absent"); return originalJson.apply(this, args); };',
        'process.env.WEBDAV_ENABLED = "true";',
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const { createFileLifecycleLock } = require("../services/fileLifecycleLock");
  const lock = createFileLifecycleLock({
    directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"),
    timeoutMs: 10_000,
    pollMs: 5,
  });
  let releaseLock;
  let markLockHeld;
  const lockHeld = new Promise((resolve) => { markLockHeld = resolve; });
  const heldOperation = lock.runFolder(FOLDER_ID, async () => {
    markLockHeld();
    await new Promise((resolve) => { releaseLock = resolve; });
  });
  await lockHeld;

  try {
    const simple = await upload(harness.port, session, "timeout-simple.txt", Buffer.from("disposable simple upload"));
    assertRejectedClean(harness, simple, 503);

    const chunk = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "timeout-chunk.txt",
      chunkIndex: 0,
      totalChunks: 1,
      bytes: Buffer.from("disposable final chunk"),
    });
    assertRejectedClean(harness, chunk, 503);
    assert.equal(chunk.headers["retry-after"], "5");
    assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)), false);
    assert.equal(fs.readFileSync(timeoutResponseMarker, "utf8"), "absent", "chunk session staging is removed before the 503 response is sent");
    assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);

    const webDavBody = Buffer.from("disposable WebDAV upload");
    const webDav = await request(harness.port, "/dav/" + FOLDER_ID + "/timeout-webdav.txt", {
      method: "PUT",
      headers: {
        authorization: "Basic " + Buffer.from("uploader:" + harness.password).toString("base64"),
        "content-length": webDavBody.length,
      },
      body: webDavBody,
    });
    assertRejectedClean(harness, webDav, 503);
  } finally {
    releaseLock();
    await heldOperation;
  }
});

test("a timed-out duplicate chunk request cannot mutate an active upload session", { timeout: 30_000 }, async (t) => {
  const scanner = await startGatedClamAv();
  t.after(async () => {
    for (const gate of scanner.scans) gate.release();
    await new Promise((resolve) => scanner.server.close(resolve));
  });
  const uploadId = "Concurrent-Timeout-Chunk";
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          originalName: "concurrent-timeout.txt",
          fileName: "concurrent-timeout.txt",
          totalChunks: 2,
          encryptionLevel: "none",
        }),
        "0.part": Buffer.alloc(2 * 1024 * 1024, 0x61),
      },
    }],
    preloadSource: () => {
      return [
        "const lockModule = require(" + JSON.stringify(path.join(ROOT, "services", "fileLifecycleLock.js")) + ");",
        "const create = lockModule.createFileLifecycleLock;",
        "lockModule.createFileLifecycleLock = (options) => create({ ...options, timeoutMs: 200, pollMs: 5 });",
      ].join("\n");
    },
    envOverrides: { UPLOAD_SCAN_PROVIDER: "clamav", CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.port) },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const { createFileLifecycleLock } = require("../services/fileLifecycleLock");
  const lock = createFileLifecycleLock({
    directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"),
    timeoutMs: 10_000,
    pollMs: 5,
  });
  let releaseFolder;
  let markFolderHeld;
  const folderHeld = new Promise((resolve) => { markFolderHeld = resolve; });
  const heldOperation = lock.runFolder(FOLDER_ID, async () => {
    markFolderHeld();
    await new Promise((resolve) => { releaseFolder = resolve; });
  });
  await folderHeld;

  try {
    const uploadArgs = {
      uploadId,
      originalName: "concurrent-timeout.txt",
      chunkIndex: 1,
      totalChunks: 2,
      bytes: Buffer.alloc(2 * 1024 * 1024, 0x62),
    };
    const firstPromise = uploadChunk(harness.port, session, uploadArgs);
    const firstScanDeadline = Date.now() + 5000;
    while (scanner.scans.length < 1 && Date.now() < firstScanDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(scanner.scans[0], "first upload did not reach scanning");
    await scanner.scans[0].started;

    const secondArgs = {
      ...uploadArgs,
      uploadId: process.platform === "win32" ? uploadId.toLowerCase() : uploadId,
    };
    const secondPromise = uploadChunk(harness.port, session, secondArgs);
    const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
    const stagedPath = path.join(sessionDir, "assembled.upload");
    const second = await secondPromise;
    assert.equal(second.status, 503, second.body);
    assert.equal(fs.existsSync(stagedPath), true, "a timed-out duplicate request must not remove another request's staged file");
    const activeMetadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
    assert.notEqual(activeMetadata.__resumeBlocked, true, "an alias request must not block the active session metadata");

    scanner.scans[0].release();
    const first = await firstPromise;
    assert.equal(first.status, 503, first.body);
  } finally {
    releaseFolder();
    await heldOperation;
  }
});

test("folder mutations revalidate session and upload permission after waiting for the lifecycle lock", { timeout: 45_000 }, async (t) => {
  let markerPath;
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => {
      markerPath = path.join(dir, "folder-lock-waiting");
      const lockDirectory = path.join(dir, "data", ".rootark-cloud-file-locks");
      const expectedLockPath = path.join(lockDirectory, `${crypto.createHash("sha256").update(`folder:${FOLDER_ID}`).digest("hex")}.lock`);
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const lockDirectory = ${JSON.stringify(lockDirectory)};`,
        `const expectedLockPath = ${JSON.stringify(expectedLockPath)};`,
        `const markerPath = ${JSON.stringify(markerPath)};`,
        'const originalLinkSync = fs.linkSync;',
        'fs.linkSync = function (source, target) { try { return originalLinkSync.call(this, source, target); } catch (error) { if (error.code === "EEXIST" && typeof source === "string" && path.resolve(source).startsWith(path.resolve(lockDirectory) + path.sep) && typeof target === "string" && path.resolve(target) === path.resolve(expectedLockPath)) fs.writeFileSync(markerPath, "waiting"); throw error; } };',
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const lock = createFileLifecycleLock({ directory: path.join(harness.dir, "data", ".rootark-cloud-file-locks"), timeoutMs: 5000, pollMs: 5 });
  const mutateUser = (change) => {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    change(users[0]);
    fs.writeFileSync(usersPath, JSON.stringify(users));
  };
  const withHeldFolderLock = async (startRequest, changeUser) => {
    fs.rmSync(markerPath, { force: true });
    let release;
    let markHeld;
    const held = new Promise((resolve) => { markHeld = resolve; });
    const operation = lock.runFolder(FOLDER_ID, async () => {
      markHeld();
      await new Promise((resolve) => { release = resolve; });
    });
    await held;
    const responsePromise = startRequest();
    assert.equal(await waitForFile(markerPath), true, "request did not reach the held folder lock");
    changeUser();
    release();
    const response = await responsePromise;
    await operation;
    return response;
  };

  const simple = await withHeldFolderLock(
    () => upload(harness.port, session, "revoked-simple.txt", Buffer.from("disposable simple bytes")),
    () => mutateUser((user) => { user.permissions.upload = false; }),
  );
  assert.equal(simple.status, 403, simple.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "revoked-simple.txt")), false);

  mutateUser((user) => { user.permissions.upload = true; });
  const uploadId = "revoked-chunk-after-scan";
  const chunk = await withHeldFolderLock(
    () => uploadChunk(harness.port, session, { uploadId, originalName: "revoked-chunk.txt", chunkIndex: 0, totalChunks: 1, bytes: Buffer.from("disposable chunk bytes") }),
    () => mutateUser((user) => { user.permissions.upload = false; }),
  );
  assert.equal(chunk.status, 403, chunk.body);
  assert.deepEqual(pending(harness.dir), {});
  const chunkDirectory = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const cleanupDeadline = Date.now() + 5000;
  while (filesUnder(chunkDirectory).length && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(filesUnder(chunkDirectory), []);
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "revoked-chunk.txt")), false);

  mutateUser((user) => { user.permissions.upload = true; });
  const folderBefore = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "folders.json"), "utf8")).find((folder) => folder.id === FOLDER_ID);
  const body = JSON.stringify({ expiresAt: new Date(Date.now() + 60_000).toISOString() });
  const temporary = await withHeldFolderLock(
    () => request(harness.port, `/folders/${FOLDER_ID}/temporary`, {
      method: "PUT",
      headers: { cookie: session.cookie, origin: `http://127.0.0.1:${harness.port}`, "x-csrf-token": session.csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    }),
    () => mutateUser((user) => { user.sessionVersion += 1; }),
  );
  assert.equal(temporary.status, 401, temporary.body);
  const folderAfter = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "folders.json"), "utf8")).find((folder) => folder.id === FOLDER_ID);
  assert.equal(folderAfter.expiresAt, folderBefore.expiresAt, "revoked session cannot update folder expiration after lock wait");
});

test("simple and chunk uploads revalidate current upload permission after a long scan", { timeout: 45_000 }, async (t) => {
  const scanner = await startGatedClamAv();
  const harness = await createHarness(t, {
    envOverrides: { UPLOAD_SCAN_PROVIDER: "clamav", CLAMAV_HOST: "127.0.0.1", CLAMAV_PORT: String(scanner.port) },
  });
  t.after(async () => {
    for (const gate of scanner.scans) gate.release();
    await new Promise((resolve) => scanner.server.close(resolve));
  });
  const session = await login(harness.port, "uploader", harness.password);
  const usersPath = path.join(harness.dir, "data", "users.local.json");
  const setUploadPermission = (allowed) => {
    const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
    users[0].permissions.upload = allowed;
    fs.writeFileSync(usersPath, JSON.stringify(users));
  };
  const waitForScan = async (index) => {
    const deadline = Date.now() + TIMEOUT_MS;
    while (scanner.scans.length <= index && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.ok(scanner.scans[index], `ClamAV scan ${index + 1} did not start`);
    await scanner.scans[index].started;
  };

  const simplePromise = upload(harness.port, session, "scan-revoked-simple.txt", Buffer.from("disposable simple bytes"));
  await waitForScan(0);
  setUploadPermission(false);
  scanner.scans[0].release();
  const simple = await simplePromise;
  assert.equal(simple.status, 403, simple.body);
  assert.deepEqual(pending(harness.dir), {});
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "scan-revoked-simple.txt")), false);

  setUploadPermission(true);
  const chunkPromise = uploadChunk(harness.port, session, {
    uploadId: "scan-revoked-chunk",
    originalName: "scan-revoked-chunk.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("disposable chunk bytes"),
  });
  await waitForScan(1);
  setUploadPermission(false);
  scanner.scans[1].release();
  const chunk = await chunkPromise;
  assert.equal(chunk.status, 403, chunk.body);
  assert.deepEqual(pending(harness.dir), {});
  const chunkDirectory = path.join(harness.chunkRoot, FOLDER_ID, "scan-revoked-chunk");
  const cleanupDeadline = Date.now() + TIMEOUT_MS;
  while (filesUnder(chunkDirectory).length && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual(filesUnder(chunkDirectory), []);
  assert.equal(fs.existsSync(path.join(harness.dir, "temp", FOLDER_ID, "scan-revoked-chunk.txt")), false);
});
