const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");
const { createFileLifecycleLock } = require("../../services/fileLifecycleLock");
const { classifyProcessOwner, createChunkUploadQuota: createChunkUploadQuotaService, getCurrentProcessIdentity } = require("../../services/chunkUploadQuota");
const { ensureWindowsChunkUploadRoot } = require("../../services/chunkUploadWindowsAcl");

const ROOT = path.resolve(__dirname, "..", "..");
const SERVER = process.env.ROOTARK_TEST_SERVER || path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;
const SERVER_BOOT_TIMEOUT_MS = 40_000;
const FOLDER_ID = "upload-safety";
const CHUNK_SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const createChunkUploadQuota = (options) => createChunkUploadQuotaService({ perAccountEntries: 5000, systemEntries: 10000, ...options });

function chunkBoundaryRequestTimeout(chunkIndex, totalChunks) {
  // Only the final supported 2,000-part boundary assembles 2,000 files on this response.
  // Keep the other 1,999 socket deadlines strict and the overall 180s test budget intact.
  return totalChunks === 2000 && chunkIndex === totalChunks - 1 ? 30_000 : TIMEOUT_MS;
}

function isCanonicalNpmTestInvocation(executable, args) {
  // Linux invokes `npm test -- ...`; Windows invokes cmd.exe with a single
  // `npm.cmd test -- ...` command argument. Neither is `node --test`.
  const command = args.map(String).join(" ");
  return (/(?:^|[\\/])npm(?:\.cmd)?$/i.test(String(executable)) && args[0] === "test")
    || /(?:^|\s)npm(?:\.cmd)?\s+test(?:\s|$)/i.test(command);
}

// vm.runInNewContext creates fixture maps in a foreign realm. The actual
// sync protocol (required from this test's realm) correctly rejects them.
// Rebuild ONLY the owned synthetic fixture data before calling the real
// createOperation; never mock its signature/ciphertext security checks.
function releaseGateFixtureToHost(value) {
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (Array.isArray(value)) return Array.from(value, releaseGateFixtureToHost);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) =>
      [key, releaseGateFixtureToHost(item)]));
  }
  return value;
}

function releaseGateVmRequire(gateRequire, spawnSyncMock) {
  const protocolPath = path.join(ROOT, "sync-client", "rootark-sync-protocol");
  const resiliencePath = path.join(ROOT, "src", "services", "deploymentResilience");
  return (name) => {
    if (name === "node:child_process") return { spawnSync: spawnSyncMock };
    const module = gateRequire(name);
    if (name === protocolPath) return { ...module, createOperation: (fixture) =>
      module.createOperation(releaseGateFixtureToHost(fixture)) };
    // The release-gate VM also creates the input array and its deliberately
    // leaked-field object in the foreign realm. Keep the actual attestor, but
    // reconstruct those test fixtures before its strict host-realm checks.
    if (name === resiliencePath) return { ...module, attestCiphertextOnlyRecords: (records) =>
      module.attestCiphertextOnlyRecords(releaseGateFixtureToHost(records)) };
    return module;
  };
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

function request(port, requestPath, { method = "GET", headers = {}, body, agent, timeoutMs = TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers, agent }, (res) => {
      let responseBody = "";
      res.on("data", (chunk) => { responseBody += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: responseBody }));
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error("request timed out")));
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(port, timeout = TIMEOUT_MS) {
  const deadline = Date.now() + timeout;
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

function testDeadQuotaOwnerEnv(...processIds) {
  const ids = [...new Set(processIds.filter((id) => Number.isSafeInteger(id) && id !== process.pid))];
  return { ROOTARK_TEST_DEAD_QUOTA_OWNER_PIDS: ids.join(",") };
}

async function createHarness(t, { chunkSessions = [], preloadSource = "", waitForReady = true, readyTimeout = SERVER_BOOT_TIMEOUT_MS, uploaderPermissions = {}, secondUploaderHasFolderAccess = false, appDataMode = "json", envOverrides = {}, deterministicQuotaRecovery = false } = {}) {
  const password = crypto.randomBytes(24).toString("base64url");
  const fixtureBase = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();
  const dir = fs.mkdtempSync(path.join(fixtureBase, "rootark-upload-safety-"));
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
  if (process.platform === "win32") {
    fs.mkdirSync(path.dirname(chunkRoot), { recursive: true });
    ensureWindowsChunkUploadRoot(chunkRoot);
  }
  for (const session of chunkSessions) {
    const sessionDir = path.join(chunkRoot, session.folderId || FOLDER_ID, session.uploadId);
    fs.mkdirSync(sessionDir, { recursive: true });
    for (const [name, contents] of Object.entries(session.files || {})) {
      const bytes = name === "metadata.json" && typeof contents !== "string" ? JSON.stringify(contents) : contents;
      fs.writeFileSync(path.join(sessionDir, name), bytes);
    }
  }
  const customPreload = typeof preloadSource === "function" ? preloadSource({ dir, chunkRoot }) : preloadSource;
  const quotaRecoveryPreloadPath = deterministicQuotaRecovery
    ? path.join(ROOT, "test", "fixtures", "chunk-quota-dead-owner-preload.js")
    : "";
  const sqliteSetup = appDataMode === "sqlite" ? `
    process.env.DB_ENABLED = "true";
    process.env.DB_READ_FALLBACK_JSON = "false";
    process.env.DB_WRITE_LEGACY_JSON = "false";
    process.env.DATABASE_URL = ${JSON.stringify(path.join(dir, "data", "rootark.sqlite"))};
    require(${JSON.stringify(path.join(ROOT, "db", "migrations.js"))}).runMigrations({ backup: false });
    require(${JSON.stringify(path.join(ROOT, "repositories", "usersRepository.js"))}).saveUsers(JSON.parse(require("node:fs").readFileSync(${JSON.stringify(path.join(dir, "data", "users.json"))}, "utf8")));
    require(${JSON.stringify(path.join(ROOT, "repositories", "foldersRepository.js"))}).saveFolders(JSON.parse(require("node:fs").readFileSync(${JSON.stringify(path.join(dir, "data", "folders.json"))}, "utf8")));
  ` : "";
  const quotaFixtureShim = customPreload ? `
    const quotaFixtureModule = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
    const createQuotaFixtureService = quotaFixtureModule.createChunkUploadQuota;
    const classifyQuotaFixtureOwner = quotaFixtureModule.classifyProcessOwner;
    quotaFixtureModule.createChunkUploadQuota = (options) => createQuotaFixtureService({
      ...options,
      classifyOwner: options.classifyOwner || ((pid, identity, current) =>
        [2147483000, 2147483647].includes(pid) ? "dead" : classifyQuotaFixtureOwner(pid, identity, current)),
    });
  ` : "";
  const preloadContents = [sqliteSetup, quotaFixtureShim, customPreload].filter(Boolean).join("\n");
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
      DB_ENABLED: appDataMode === "sqlite" ? "true" : "false",
      DB_READ_FALLBACK_JSON: appDataMode === "sqlite" ? "false" : "true",
      DB_WRITE_LEGACY_JSON: appDataMode === "sqlite" ? "false" : "true",
      ...(appDataMode === "sqlite" ? { DATABASE_URL: path.join(dir, "data", "rootark.sqlite") } : {}),
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      UPLOAD_SCAN_ENABLED: "true",
      UPLOAD_SCAN_PROVIDER: "disabled",
      UPLOAD_BLOCK_EXECUTABLES: "true",
      UPLOAD_QUARANTINE_DIR: quarantineDir,
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000",
      CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
      ...envOverrides,
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  child.stdout.on("data", (chunk) => stdout.push(chunk.toString()));
  child.stderr.on("data", (chunk) => stderr.push(chunk.toString()));
  const stopServer = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    const exited = waitForExit(child);
    child.kill();
    await exited;
  };
  t.after(async () => {
    await stopServer();
    fs.rmSync(dir, { recursive: true, force: true });
    assert.equal(fs.existsSync(dir), false);
  });
  if (waitForReady) {
    try {
      assert.equal((await waitForServer(port, readyTimeout)).status, 200);
    } catch (error) {
      throw new Error(`${error.message}\nserver exit: ${child.exitCode}\nserver stdout:\n${stdout.join("")}\nserver stderr:\n${stderr.join("")}`);
    }
  }
  return { dir, port, quarantineDir, password, chunkRoot, child, stopServer, stdout, stderr, quotaRecoveryPreloadPath };
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

async function uploadPayload(port, session, payload, method = "POST") {
  return request(port, `/upload?folderId=${FOLDER_ID}`, {
    method,
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

async function uploadChunk(port, session, { uploadId, originalName, chunkIndex, totalChunks, bytes, encryptionLevel, password, versionComment, expiresInDays, forwardedFor, agent, timeoutMs }) {
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
      ...(forwardedFor ? { "x-forwarded-for": forwardedFor } : {}),
      "content-type": payload.contentType,
      "content-length": payload.body.length,
    },
    agent,
    body: payload.body,
    timeoutMs,
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

async function waitForAuditLogs(dir, predicate, timeout = 3000, onTransientSyntaxError) {
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
      if (typeof onTransientSyntaxError === "function") onTransientSyntaxError(error);
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
function filesUnder(dir) {
  let descriptor;
  try {
    descriptor = fs.openSync(dir, "r");
  } catch (error) {
    if (error.code === "ENOENT") return [];
    // Windows may reject opening directories; listing remains the directory path.
    if (["EACCES", "EISDIR", "EPERM"].includes(error.code)) return directoryEntries(dir);
    throw error;
  }

  try {
    if (fs.fstatSync(descriptor).isFile()) {
      return [crypto.createHash("sha256").update(fs.readFileSync(descriptor)).digest("hex")];
    }
  } finally {
    fs.closeSync(descriptor);
  }

  return directoryEntries(dir);
}

function directoryEntries(dir) {
  try {
    return fs.readdirSync(dir, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile())
      .map((entry) => entry.name)
      .sort();
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
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

module.exports = {
  assert, bcrypt, crypto, Database, fs, http, net, os, path, spawn, spawnSync, test,
  createFileLifecycleLock, classifyProcessOwner, createChunkUploadQuotaService, getCurrentProcessIdentity, ensureWindowsChunkUploadRoot,
  ROOT, SERVER, PUBLIC, TIMEOUT_MS, FOLDER_ID, CHUNK_SESSION_TTL_MS, createChunkUploadQuota,
  chunkBoundaryRequestTimeout, isCanonicalNpmTestInvocation, releaseGateFixtureToHost, releaseGateVmRequire,
  getUnusedPort, request, waitForServer, login, multipartParts, multipart, isContained, testDeadQuotaOwnerEnv,
  createHarness, startGatedClamAv, upload, uploadPayload, uploadChunk, postJson, waitForExit, waitForFile,
  legacyChunkMetadata, auditLogs, auditLogFileSignature, waitForAuditLogs,
  filesUnder, directoryEntries, assertRejectedClean, pending, quarantine,
};
