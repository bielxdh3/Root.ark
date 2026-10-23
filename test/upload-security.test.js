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
const { createFileLifecycleLock } = require("../services/fileLifecycleLock");
const { classifyProcessOwner, createChunkUploadQuota: createChunkUploadQuotaService, getCurrentProcessIdentity } = require("../services/chunkUploadQuota");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const ROOT = path.resolve(__dirname, "..");
const SERVER = process.env.ROOTARK_TEST_SERVER || path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;
const FOLDER_ID = "upload-safety";
const createChunkUploadQuota = (options) => createChunkUploadQuotaService({ perAccountEntries: 5000, systemEntries: 10000, ...options });

function chunkBoundaryRequestTimeout(chunkIndex, totalChunks) {
  // Only the final supported 2,000-part boundary assembles 2,000 files on this response.
  // Keep the other 1,999 socket deadlines strict. A slower Windows CI
  // fixture has a separate bounded wall-time budget for all requests.
  return totalChunks === 2000 && chunkIndex === totalChunks - 1 ? 30_000 : TIMEOUT_MS;
}

function isCanonicalNpmTestInvocation(executable, args) {
  // Linux invokes `npm test -- ...`; Windows invokes cmd.exe with a single
  // `npm.cmd test -- ...` command argument. Neither is `node --test`.
  const command = args.map(String).join(" ");
  return (/(?:^|[\\/])npm(?:\.cmd)?$/i.test(String(executable)) && args[0] === "test")
    || /(?:^|\s)npm(?:\.cmd)?\s+test(?:\s|$)/i.test(command);
}

test("release gate mock identifies native Windows and POSIX npm test calls", () => {
  assert.equal(isCanonicalNpmTestInvocation("npm", ["test", "--", "--test-reporter=tap"]), true);
  assert.equal(isCanonicalNpmTestInvocation("C:\\Windows\\System32\\cmd.exe", ["/d", "/s", "/c", "npm.cmd test -- --test-reporter=tap"]), true);
  assert.equal(isCanonicalNpmTestInvocation(process.execPath, ["--test", "test/upload-security.test.js"]), false);
  assert.equal(isCanonicalNpmTestInvocation("npm", ["audit", "--package-lock-only"]), false);
});

test("dead-owner quota test preload is inert outside the test environment", () => {
  const quotaModulePath = path.join(ROOT, "services", "chunkUploadQuota.js");
  const preloadPath = path.join(ROOT, "test", "fixtures", "chunk-quota-dead-owner-preload.js");
  const script = `const quota = require(${JSON.stringify(quotaModulePath)}); const original = quota.createChunkUploadQuota; require(${JSON.stringify(preloadPath)}); if (quota.createChunkUploadQuota !== original) process.exitCode = 1;`;
  const result = spawnSync(process.execPath, ["-e", script], {
    env: { ...process.env, NODE_ENV: "production", ROOTARK_TEST_DEAD_QUOTA_OWNER_PIDS: String(process.pid) },
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr || "production preload changed the quota factory");
});

test("release gate reports a sanitized failing test and skips redundant full tests after a required failure", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const calls = [];
  const printed = [];
  const simulatedSpawnSync = (executable, args) => {
    calls.push({ executable, args });
    if (args.some((value) => String(value).endsWith("upload-security.test.js"))) {
      return {
        status: 1,
        stdout: "not ok 7 - a second startup rejects ambiguous quota owner\n  failureType: 'testCodeFailure'\n  error: Upload denied password=synthetic-sensitive-fixture Authorization: Basic c2Vuc2l0aXZl refresh_token=synthetic-refresh-key access_token=synthetic-access-key\n",
        stderr: "Synthetic diagnostic: bearer test-secret-value\n",
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
  const simulatedProcess = { execPath: process.execPath, exitCode: 0 };
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: simulatedProcess,
    console: { log: (value) => printed.push(String(value)) },
    require: (name) => name === "node:child_process" ? { spawnSync: simulatedSpawnSync } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.match(output, /FAIL: Upload security boundary — exit 1/);
  assert.match(output, /a second startup rejects ambiguous quota owner/, "the exact failing test is visible in CI");
  assert.doesNotMatch(output, /synthetic-sensitive-fixture|test-secret-value|c2Vuc2l0aXZl|synthetic-refresh-key|synthetic-access-key/, "raw test output cannot leak any fixture secrets");
  assert.match(output, /\[REDACTED\]/, "sensitive diagnostic text is redacted rather than silently dropped");
  assert.equal(calls.some(({ args }) => /(?:^|\s)(?:npm(?:\.cmd)?\s+test|test(?:\s|$))/.test(args.join(" "))), false, "no expensive canonical npm test after an earlier hard failure on Windows or POSIX");
  assert.equal(simulatedProcess.exitCode, 1, "the gate still fails closed");
});

test("release gate emits a bounded redacted TAP failure from canonical npm test on Windows", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const printed = [];
  const commands = [];
  const simulatedProcess = { execPath: process.execPath, exitCode: 0 };
  const secret = "synthetic-canonical-npm-secret";
  const simulatedSpawnSync = (executable, args) => {
    commands.push(args.map(String).join(" "));
    if (isCanonicalNpmTestInvocation(executable, args)) {
      return {
        status: 1,
        stdout: `TAP version 13\nnot ok 327 - a concurrent upload boundary failed token=${secret}\n  error: expected success password=${secret}\n# tests 1411\n# pass 1410\n# fail 1\n`,
        stderr: `npm error code 1\nnpm error stderr=${secret}`,
      };
    }
    return { status: 0, stdout: "", stderr: "" };
  };
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: simulatedProcess,
    console: { log: (line) => printed.push(String(line)) },
    require: (name) => name === "node:child_process" ? { spawnSync: simulatedSpawnSync }
      : name === "./release-gate-environment" ? {
        ...gateRequire(name), hasSeparateWindowsCiCanonicalTest: () => false,
      } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.ok(commands.some((line) => /(?:^|\s)(?:npm(?:\.cmd)?\s+)?test -- --test-reporter=tap(?:\s|$)/.test(line)), "canonical npm still runs every test with a deterministic TAP reporter");
  assert.match(output, /FAIL diagnostics \(final-head canonical npm test\):/);
  assert.match(output, /not ok 327 - a concurrent upload boundary failed/);
  assert.match(output, /# fail 1/);
  assert.doesNotMatch(output, new RegExp(secret), "TAP and stderr secrets are not printed");
  assert.ok(output.length < 5000, "CI failure log stays bounded");
  assert.equal(simulatedProcess.exitCode, 1);
});

test("release gate prints metadata-only failure diagnostics for unknown npm output", () => {
  const vm = require("node:vm");
  const { createRequire } = require("node:module");
  const gatePath = path.join(ROOT, "scripts", "validate-release-gate.js");
  const gateRequire = createRequire(gatePath);
  const printed = [];
  const secret = "synthetic-unknown-sensitive-stdout";
  vm.runInNewContext(fs.readFileSync(gatePath, "utf8"), {
    __dirname: path.dirname(gatePath),
    process: { execPath: process.execPath, exitCode: 0 },
    console: { log: (line) => printed.push(String(line)) },
    require: (name) => name === "node:child_process" ? { spawnSync: (executable, args) => isCanonicalNpmTestInvocation(executable, args)
      ? { status: 1, stdout: `unknown-format ${secret}\n`, stderr: "", error: { code: "ENOBUFS" } }
      : { status: 0, stdout: "", stderr: "" } }
      : name === "./release-gate-environment" ? {
        ...gateRequire(name), hasSeparateWindowsCiCanonicalTest: () => false,
      } : gateRequire(name),
  }, { filename: gatePath });
  const output = printed.join("\n");
  assert.match(output, /FAIL diagnostics \(final-head canonical npm test\):/);
  assert.match(output, /ENOBUFS/);
  assert.match(output, /stdoutBytes=/);
  assert.doesNotMatch(output, new RegExp(secret), "fallback cannot expose arbitrary child stdout");
});

test("2,000-chunk boundary keeps ordinary socket timeout strict and bounds final assembly separately", () => {
  assert.equal(chunkBoundaryRequestTimeout(0, 2000), TIMEOUT_MS);
  assert.equal(chunkBoundaryRequestTimeout(1998, 2000), TIMEOUT_MS);
  assert.equal(chunkBoundaryRequestTimeout(1999, 2000), 30_000);
  assert.equal(chunkBoundaryRequestTimeout(1999, 2001), TIMEOUT_MS, "test-only final assembly allowance is restricted to the supported 2,000 part boundary");
});

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

async function waitForServer(port, timeout = process.platform === "win32" ? 30_000 : TIMEOUT_MS, child = null) {
  const deadline = Date.now() + timeout;
  let lastState = "no response";
  while (Date.now() < deadline) {
    if (child && (child.exitCode !== null || child.signalCode !== null)) {
      throw new Error(`server exited before readiness (code=${child.exitCode}, signal=${child.signalCode})`);
    }
    try {
      const result = await request(port, "/login.html", { timeoutMs: Math.max(1, Math.min(1_000, deadline - Date.now())) });
      if (result.status === 200) return result;
      lastState = `HTTP ${result.status}`;
    } catch (error) {
      lastState = error.code || error.message;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`server did not serve login within ${timeout}ms (last probe: ${lastState}; exit=${child?.exitCode ?? "unknown"})`);
}

test("upload readiness ignores a transient HTTP error before the login route is healthy", async (t) => {
  let probes = 0;
  const listener = http.createServer((_req, res) => {
    probes += 1;
    res.writeHead(probes === 1 ? 503 : 200);
    res.end();
  });
  await new Promise((resolve) => listener.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => listener.close(resolve)));
  const response = await waitForServer(listener.address().port, 2_000);
  assert.equal(response.status, 200);
  assert.equal(probes, 2);
});

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

async function createHarness(t, { chunkSessions = [], preloadSource = "", waitForReady = true, readyTimeout = process.platform === "win32" ? 30_000 : TIMEOUT_MS, uploaderPermissions = {}, secondUploaderHasFolderAccess = false, appDataMode = "json", envOverrides = {}, deterministicQuotaRecovery = false } = {}) {
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
      assert.equal((await waitForServer(port, readyTimeout, child)).status, 200);
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

test("waits for audit logs to finish an observed rewrite before parsing", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-audit-write-race-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(path.join(dir, "data"));
  const file = path.join(dir, "data", "audit-logs.json");
  fs.writeFileSync(file, JSON.stringify({ logs: [] }));

  const expected = [{ id: "first" }, { id: "second" }];
  let resolveTransientSyntaxError;
  const transientSyntaxError = new Promise((resolve) => { resolveTransientSyntaxError = resolve; });
  const waiting = waitForAuditLogs(
    dir,
    (logs) => logs.length === expected.length,
    250,
    () => resolveTransientSyntaxError()
  );
  fs.writeFileSync(file, "{\"logs\":[");
  const observation = await Promise.race([
    transientSyntaxError.then(() => "observed"),
    waiting.then(() => "completed", () => "timed out")
  ]);
  assert.equal(observation, "observed", "the helper read malformed JSON during the observed-rewrite retry window");
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
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE session_key = ?").get(`${FOLDER_ID}/${uploadId}`).count, 0, "all expiry charges release after tombstone cleanup confirms the parts are gone");
  } finally {
    quotaDatabase.close();
  }
  const expiryEvents = (await expiryEventsPromise).filter((entry) => entry.eventType === "upload.chunk_session.expired" && entry.target?.id === uploadId);
  assert.deepEqual(expiryEvents.map((entry) => ({ result: entry.result, details: entry.details })), [
    { result: "failure", details: { source: "sweeper" } },
    { result: "success", details: { source: "sweeper" } },
  ], "audit records the failed initial deletion and successful retry without payload data");
});

test("expired chunk sessions are removed at seven days while recent sessions are preserved", { timeout: 45_000 }, async (t) => {
  const expiredId = "seven-day-expired";
  const markerExpiredId = "expired-tombstone-cleaned";
  const recentId = "seven-day-recent";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } },
      { uploadId: markerExpiredId, files: { "metadata.json": { __expiredAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }, "0.part": "expired leftover plaintext" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString() }), "0.part": "recent plaintext" } },
    ],
  });

  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const markerExpiredDir = path.join(harness.chunkRoot, FOLDER_ID, markerExpiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  const expiredMarker = JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8"));
  assert.equal(typeof expiredMarker.__expiredAt, "string", "expired uploads retain only a bounded marker that blocks stale resumes");
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, "all chunk plaintext is removed at seven days");
  assert.equal(fs.existsSync(markerExpiredDir), false, "old metadata-only tombstones are eventually removed");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent plaintext");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT session_key FROM quota_sessions ORDER BY session_key").all().map((row) => row.session_key), [`${FOLDER_ID}/${expiredId}`, `${FOLDER_ID}/${recentId}`]);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 1, "expiry releases its part operation while retaining the active recent part");
  } finally {
    database.close();
  }
});

test("seven-day expiry still cleans validated sessions when the configured quota ledger is unavailable", { timeout: 45_000 }, async (t) => {
  const expiredId = "expiry-ledger-unavailable";
  const recentId = "recent-ledger-unavailable";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 60_000).toISOString() }), "0.part": "recent plaintext" } },
    ],
    preloadSource: ({ chunkRoot }) => `
      require("node:fs").writeFileSync(${JSON.stringify(path.join(chunkRoot, ".quota.sqlite"))}, "not a SQLite database");
    `,
  });

  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  assert.match(harness.stderr.join(""), /quota initialization unavailable/);
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, `a validated seven-day-old part is removed under the shared lifecycle lock; ${harness.stderr.join("")}`);
  assert.equal(typeof JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8")).__expiredAt, "string", "the expiry tombstone remains available to reject stale resumptions");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent plaintext", "recent data is preserved while the quota ledger is unavailable");

  const session = await login(harness.port, "uploader", harness.password);
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: "quota-ledger-unavailable-request",
    originalName: "quota-ledger-unavailable-request.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(rejected.status, 503, rejected.body);
  assert.equal(JSON.parse(rejected.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  assert.ok(!fs.existsSync(incomingDir) || fs.readdirSync(incomingDir).length === 0, "upload still fails closed before writing a new part");
});

test("a second startup preserves a live chunk promotion before its incoming rename", { timeout: 90_000 }, async (t) => {
  const uploadId = "live-promotion-startup";
  let promotionGate;
  const harness = await createHarness(t, {
    readyTimeout: 30_000,
    preloadSource: ({ dir }) => {
      promotionGate = {
        entered: path.join(dir, "promotion-entered"),
        release: path.join(dir, "promotion-release"),
      };
      return `
        const fs = require("node:fs");
        const path = require("node:path");
        const renameSync = fs.renameSync;
        fs.renameSync = function (source, destination, ...args) {
          const target = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part");
          if (String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(target)) {
            fs.writeFileSync(${JSON.stringify(promotionGate.entered)}, "entered");
            const signal = new Int32Array(new SharedArrayBuffer(4));
            const deadline = Date.now() + 30000;
            while (!fs.existsSync(${JSON.stringify(promotionGate.release)}) && Date.now() < deadline) Atomics.wait(signal, 0, 0, 10);
            if (!fs.existsSync(${JSON.stringify(promotionGate.release)})) throw new Error("promotion test gate timed out");
          }
          return renameSync.call(this, source, destination, ...args);
        };
      `;
    },
  });
  const originalSession = await login(harness.port, "uploader", harness.password);
  const originalBytes = Buffer.from("still owned by the active promotion");
  const originalCompletion = uploadChunk(harness.port, originalSession, {
    uploadId,
    originalName: `${uploadId}.txt`,
    chunkIndex: 0,
    totalChunks: 2,
    bytes: originalBytes,
    timeoutMs: 90_000,
  }).then((value) => ({ value }), (error) => ({ error }));
  assert.equal(await waitForFile(promotionGate.entered), true, "the original process pauses after the promoting ledger transition and before rename");

  const incomingPath = path.join(harness.chunkRoot, "incoming", fs.readdirSync(path.join(harness.chunkRoot, "incoming"))[0]);
  const sessionPartPath = path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part");
  assert.equal(fs.existsSync(sessionPartPath), false);
  assert.deepEqual(fs.readFileSync(incomingPath), originalBytes);
  const beforeStartup = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(beforeStartup.prepare("SELECT state, charge_bytes, relative_path, owner_pid FROM quota_operations").get(), {
      state: "promoting",
      charge_bytes: originalBytes.length,
      relative_path: path.join(FOLDER_ID, uploadId, "0.part"),
      owner_pid: harness.child.pid,
    });
  } finally {
    beforeStartup.close();
  }

  const secondPort = await getUnusedPort();
  const secondChild = spawn(process.execPath, [SERVER], {
    cwd: harness.dir,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(secondPort),
      DB_ENABLED: "false",
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "true",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      UPLOAD_SCAN_ENABLED: "true",
      UPLOAD_SCAN_PROVIDER: "disabled",
      UPLOAD_BLOCK_EXECUTABLES: "true",
      UPLOAD_QUARANTINE_DIR: harness.quarantineDir,
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000",
      CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const secondStderr = [];
  secondChild.stderr.on("data", (chunk) => secondStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(secondPort, 30_000)).status, 200, secondStderr.join(""));
    assert.doesNotMatch(secondStderr.join(""), /quota initialization unavailable/);
    const secondSession = await login(secondPort, "uploader", harness.password);
    const secondUpload = await uploadChunk(secondPort, secondSession, {
      uploadId: "second-process-quota-check",
      originalName: "second-process-quota-check.txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: Buffer.from("quota remains ready"),
    });
    assert.equal(secondUpload.status, 200, secondUpload.body);
    assert.deepEqual(fs.readFileSync(incomingPath), originalBytes, "startup leaves the live operation's incoming file untouched");
    const duringStartup = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(duringStartup.prepare("SELECT state, charge_bytes, relative_path, owner_pid FROM quota_operations WHERE relative_path = ?").get(path.join(FOLDER_ID, uploadId, "0.part")), {
        state: "promoting",
        charge_bytes: originalBytes.length,
        relative_path: path.join(FOLDER_ID, uploadId, "0.part"),
        owner_pid: harness.child.pid,
      });
      assert.equal(duringStartup.prepare("SELECT SUM(charge_bytes) AS bytes FROM quota_operations").get().bytes, originalBytes.length + Buffer.byteLength("quota remains ready"));
    } finally {
      duringStartup.close();
    }
  } finally {
    fs.writeFileSync(promotionGate.release, "release");
    if (secondChild.exitCode === null) {
      secondChild.kill();
      await waitForExit(secondChild);
    }
  }
  const originalResult = await originalCompletion;
  if (originalResult.error) throw originalResult.error;
  assert.equal(originalResult.value.status, 200, originalResult.value.body);
});

test("a second startup revalidates a live promotion renamed after incoming enumeration", { timeout: 90_000 }, async (t) => {
  const uploadId = "live-promotion-after-enumeration";
  let gates;
  const harness = await createHarness(t, {
    readyTimeout: 30_000,
    preloadSource: ({ dir }) => {
      gates = Object.fromEntries(["beforeRename", "allowRename", "renamed", "finishPromotion", "lstatEntered", "finishLstat"]
        .map((name) => [name, path.join(dir, name)]));
      return `
        const fs = require("node:fs");
        const path = require("node:path");
        const renameSync = fs.renameSync;
        fs.renameSync = function (source, destination, ...args) {
          const target = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part");
          if (String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(target)) {
            const signal = new Int32Array(new SharedArrayBuffer(4));
            fs.writeFileSync(${JSON.stringify(gates.beforeRename)}, "entered");
            const beforeDeadline = Date.now() + 30000;
            while (!fs.existsSync(${JSON.stringify(gates.allowRename)}) && Date.now() < beforeDeadline) Atomics.wait(signal, 0, 0, 10);
            if (!fs.existsSync(${JSON.stringify(gates.allowRename)})) throw new Error("promotion test gate timed out before rename");
            const result = renameSync.call(this, source, destination, ...args);
            fs.writeFileSync(${JSON.stringify(gates.renamed)}, "renamed");
            const afterDeadline = Date.now() + 30000;
            while (!fs.existsSync(${JSON.stringify(gates.finishPromotion)}) && Date.now() < afterDeadline) Atomics.wait(signal, 0, 0, 10);
            if (!fs.existsSync(${JSON.stringify(gates.finishPromotion)})) throw new Error("promotion test gate timed out after rename");
            return result;
          }
          return renameSync.call(this, source, destination, ...args);
        };
      `;
    },
  });
  const originalSession = await login(harness.port, "uploader", harness.password);
  const originalBytes = Buffer.from("the live rename remains charged");
  const originalCompletion = uploadChunk(harness.port, originalSession, {
    uploadId,
    originalName: `${uploadId}.txt`,
    chunkIndex: 0,
    totalChunks: 2,
    bytes: originalBytes,
    timeoutMs: 90_000,
  }).then((value) => ({ value }), (error) => ({ error }));
  assert.equal(await waitForFile(gates.beforeRename), true);

  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingPath = path.join(incomingDir, fs.readdirSync(incomingDir)[0]);
  const sessionPartPath = path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part");
  const lstatPreloadPath = path.join(harness.dir, "pause-incoming-lstat.js");
  fs.writeFileSync(lstatPreloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const lstatSync = fs.lstatSync;
    fs.lstatSync = function (target, ...args) {
      if (path.resolve(String(target)) === path.resolve(${JSON.stringify(incomingPath)})) {
        fs.writeFileSync(${JSON.stringify(gates.lstatEntered)}, "entered");
        const signal = new Int32Array(new SharedArrayBuffer(4));
        const deadline = Date.now() + 30000;
        while (!fs.existsSync(${JSON.stringify(gates.finishLstat)}) && Date.now() < deadline) Atomics.wait(signal, 0, 0, 10);
        if (!fs.existsSync(${JSON.stringify(gates.finishLstat)})) throw new Error("lstat test gate timed out");
      }
      return lstatSync.call(this, target, ...args);
    };
  `);
  const secondPort = await getUnusedPort();
  const secondChild = spawn(process.execPath, ["--require", lstatPreloadPath, SERVER], {
    cwd: harness.dir,
    env: {
      ...process.env,
      NODE_ENV: "test",
      PORT: String(secondPort),
      DB_ENABLED: "false",
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "true",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      UPLOAD_SCAN_ENABLED: "true",
      UPLOAD_SCAN_PROVIDER: "disabled",
      UPLOAD_BLOCK_EXECUTABLES: "true",
      UPLOAD_QUARANTINE_DIR: harness.quarantineDir,
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000",
      CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const secondStderr = [];
  const secondStdout = [];
  secondChild.stderr.on("data", (chunk) => secondStderr.push(chunk.toString()));
  secondChild.stdout.on("data", (chunk) => secondStdout.push(chunk.toString()));
  try {
    assert.equal(await waitForFile(gates.lstatEntered, 60_000), true, `the second process pauses after enumerating the incoming file; exit: ${secondChild.exitCode}; stdout: ${secondStdout.join("")}; stderr: ${secondStderr.join("")}`);
    fs.writeFileSync(gates.allowRename, "allow");
    assert.equal(await waitForFile(gates.renamed), true, "the live owner atomically moves the incoming file while startup is paused");
    assert.equal(fs.existsSync(incomingPath), false);
    assert.deepEqual(fs.readFileSync(sessionPartPath), originalBytes);
    const duringRename = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(duringRename.prepare("SELECT state, charge_bytes, relative_path, owner_pid FROM quota_operations").get(), {
        state: "promoting",
        charge_bytes: originalBytes.length,
        relative_path: path.join(FOLDER_ID, uploadId, "0.part"),
        owner_pid: harness.child.pid,
      });
    } finally {
      duringRename.close();
    }
    fs.writeFileSync(gates.finishLstat, "resume");
    assert.equal((await waitForServer(secondPort, 30_000)).status, 200, secondStderr.join(""));
    assert.doesNotMatch(secondStderr.join(""), /quota initialization unavailable/);
    const secondSession = await login(secondPort, "uploader", harness.password);
    const secondUpload = await uploadChunk(secondPort, secondSession, {
      uploadId: "second-process-after-rename",
      originalName: "second-process-after-rename.txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: Buffer.from("quota remains ready"),
    });
    assert.equal(secondUpload.status, 200, secondUpload.body);
  } finally {
    for (const gate of [gates.allowRename, gates.finishPromotion, gates.finishLstat]) fs.writeFileSync(gate, "release");
    if (secondChild.exitCode === null) {
      secondChild.kill();
      await waitForExit(secondChild);
    }
  }
  const originalResult = await originalCompletion;
  if (originalResult.error) throw originalResult.error;
  assert.equal(originalResult.value.status, 200, originalResult.value.body);
});

test("zero-byte multipart sessions are bounded per account and system", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, {
    secondUploaderHasFolderAccess: true,
    envOverrides: {
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "4",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "6",
    },
  });
  const uploader = await login(harness.port, "uploader", harness.password);
  for (const uploadId of ["empty-part-one", "empty-part-two"]) {
    const response = await uploadChunk(harness.port, uploader, {
      uploadId,
      originalName: uploadId + ".txt",
      chunkIndex: 0,
      totalChunks: 2,
      bytes: Buffer.alloc(0),
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }
  const accountOverflow = await uploadChunk(harness.port, uploader, {
    uploadId: "empty-part-account-overflow",
    originalName: "empty-part-account-overflow.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(0),
  });
  assert.equal(accountOverflow.status, 507, accountOverflow.body);
  assert.equal(JSON.parse(accountOverflow.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "empty-part-account-overflow")), false);

  const otherUploader = await login(harness.port, "other-uploader", harness.password);
  const systemLastEntry = await uploadChunk(harness.port, otherUploader, {
    uploadId: "empty-part-system-last-entry",
    originalName: "empty-part-system-last-entry.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(0),
  });
  assert.equal(systemLastEntry.status, 200, systemLastEntry.body);
  const systemOverflow = await uploadChunk(harness.port, otherUploader, {
    uploadId: "empty-part-system-overflow",
    originalName: "empty-part-system-overflow.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.alloc(0),
  });
  assert.equal(systemOverflow.status, 507, systemOverflow.body);
  assert.equal(JSON.parse(systemOverflow.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "empty-part-system-overflow")), false);

  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 3);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_sessions").get().count, 3);
    assert.equal(database.prepare("SELECT SUM(charge_bytes) AS bytes FROM quota_operations").get().bytes, 0);
  } finally {
    database.close();
  }
});

test("expired chunk cleanup remains serialized and runs when quota configuration is unavailable", { timeout: 45_000 }, async (t) => {
  const expiredId = "expired-without-quota";
  const recentId = "recent-without-quota";
  const harness = await createHarness(t, {
    chunkSessions: [
      { uploadId: expiredId, files: { "metadata.json": legacyChunkMetadata(expiredId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired disposable part" } },
      { uploadId: recentId, files: { "metadata.json": legacyChunkMetadata(recentId, { lastActivityAt: new Date().toISOString() }), "0.part": "recent disposable part" } },
    ],
    envOverrides: {
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "",
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "",
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "",
    },
  });
  const expiredDir = path.join(harness.chunkRoot, FOLDER_ID, expiredId);
  const recentDir = path.join(harness.chunkRoot, FOLDER_ID, recentId);
  assert.equal(fs.existsSync(path.join(expiredDir, "0.part")), false, harness.stderr.join(""));
  assert.equal(typeof JSON.parse(fs.readFileSync(path.join(expiredDir, "metadata.json"), "utf8")).__expiredAt, "string");
  assert.equal(fs.readFileSync(path.join(recentDir, "0.part"), "utf8"), "recent disposable part");

  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "quota-disabled-still-blocks-upload",
    originalName: "quota-disabled.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not stage"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
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

test("expiry wins while a multipart body is paused before its session fields are parsed", { timeout: 45_000 }, async (t) => {
  const uploadId = "expiry-wins-before-fields";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: {
      "metadata.json": legacyChunkMetadata(uploadId, {
        totalChunks: 1,
        encryptionLevel: "none",
        lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS + 5_000).toISOString(),
      }),
      "0.part": "previously accepted part",
    } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const payload = multipartParts([
    { field: "uploadId", bytes: uploadId },
    { field: "originalName", bytes: "expiry-race.txt" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
    { field: "encryptionLevel", bytes: "none" },
    { field: "chunk", filename: "expiry-race.txt", bytes: Buffer.from("stale in-flight request") },
  ]);
  const responsePromise = new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port: harness.port,
      path: "/upload-chunk?folderId=" + FOLDER_ID,
      method: "POST",
      headers: {
        cookie: session.cookie,
        origin: "http://127.0.0.1:" + harness.port,
        "x-csrf-token": session.csrf,
        "content-type": payload.contentType,
        "content-length": payload.body.length,
      },
    }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.flushHeaders();
    t.after(() => req.destroy());
    (async () => {
      const metadataPath = path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json");
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline) {
        if (fs.existsSync(metadataPath)) {
          try {
            const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
            if (typeof metadata.__expiredAt === "string") break;
          } catch {}
        }
        await new Promise((resolveWait) => setTimeout(resolveWait, 20));
      }
      const tombstone = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
      assert.equal(typeof tombstone.__expiredAt, "string", "expiry marker is durable before the body resumes");
      req.end(payload.body);
    })().catch(reject);
  });

  const response = await responsePromise;
  assert.equal(response.status, 409, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const marker = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.equal(typeof marker.__expiredAt, "string");
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    quotaDatabase.close();
  }
});

test("an active incoming chunk does not defer cleanup of unrelated expired sessions", { timeout: 45_000 }, async (t) => {
  const uploadId = "expired-with-other-incoming-upload";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString() }), "0.part": "expired plaintext" } }],
  });

  const incomingFile = crypto.randomUUID();
  const quota = createChunkUploadQuota({
    rootDir: harness.chunkRoot,
    perAccountBytes: 64 * 1024 * 1024,
    systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000,
  });
  const incomingBytes = Buffer.from("active upload staging data");
  quota.reserve({ operationId: incomingFile, accountKey: "uploader", relativePath: `incoming/${incomingFile}`, reservedBytes: incomingBytes.length });
  fs.writeFileSync(path.join(harness.chunkRoot, "incoming", incomingFile), incomingBytes, { mode: 0o600 });
  quota.close();

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const cleanupDeadline = Date.now() + 5_000;
  while (fs.existsSync(path.join(sessionDir, "0.part")) && Date.now() < cleanupDeadline) await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, "unrelated expired chunk data is still pruned");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", incomingFile), "utf8"), incomingBytes.toString(), "the sweeper leaves incoming upload staging files untouched");
});

test("the chunk-session sweeper shares the cross-process session lock when quota is unavailable", { timeout: 45_000 }, async (t) => {
  const uploadId = "sweeper-session-lock";
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const databasePath = ${JSON.stringify(path.join(chunkRoot, ".quota.sqlite"))};
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      fs.writeFileSync(databasePath, "not a SQLite database");
    `,
  });
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
  assert.match(harness.stderr.join(""), /quota initialization unavailable/);
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
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, `the periodic sweeper deletes expired chunk data; ${harness.stderr.join("")}`);
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

test("invalid chunk activity time preserves session data and disables only chunk uploads", { timeout: 30_000 }, async (t) => {
  const uploadId = "invalid-chunk-activity-time";
  const bytes = Buffer.from("preserve unattributable activity session");
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: "not-a-timestamp" });
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": bytes } }],
  });
  assert.equal((await waitForServer(harness.port)).status, 200, harness.stderr.join(""));
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const blockedMetadata = { __resumeBlocked: true };
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), blockedMetadata);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "invalid-chunk-activity-time.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), blockedMetadata);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
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
  const fixtureBase = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();
  const harnessPrefix = path.join(fixtureBase, "rootark-upload-safety-");
  const sessionPathMarker = `${path.sep}temp${path.sep}.chunks${path.sep}${FOLDER_ID}${path.sep}sweep-yield-`;
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    waitForReady: false,
    chunkSessions,
    preloadSource: `
      const fs = require("node:fs");
      const readdir = fs.promises.readdir.bind(fs.promises);
      let sessionReads = 0;
      let delayedSessionReads = 0;
      fs.promises.readdir = async (target, ...args) => {
        const entries = await readdir(target, ...args);
        if (String(target).startsWith(${JSON.stringify(harnessPrefix)}) && String(target).includes(${JSON.stringify(sessionPathMarker)})) {
          sessionReads += 1;
          if (sessionReads > ${sweepCount}) {
            await new Promise((resolve) => setTimeout(resolve, ${sweepDelayMs}));
            delayedSessionReads += 1;
            if (delayedSessionReads === 8) fs.writeFileSync(${JSON.stringify(sweepStartedPath)}, "8 delayed session reads complete");
          }
        }
        return entries;
      };
    `,
  });

  assert.equal(await waitForFile(sweepStartedPath), true, "the periodic sweep completed eight delayed session reads");
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

test("the expiry sweep does not keep a live session metadata handle open across chunk writes", { timeout: 30_000 }, async (t) => {
  const uploadId = "live-sweep-metadata-handle";
  let metadataHandleMarker;
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    preloadSource: ({ dir }) => {
      const metadataPath = path.join(dir, "temp", ".chunks", FOLDER_ID, uploadId, "metadata.json");
      metadataHandleMarker = path.join(dir, "sweep-held-metadata.txt");
      return `
        const fs = require("node:fs");
        const open = fs.promises.open.bind(fs.promises);
        const metadataPath = ${JSON.stringify(metadataPath)};
        const markerPath = ${JSON.stringify(metadataHandleMarker)};
        let metadataHandleOpen = false;
        fs.promises.open = async (target, ...args) => {
          const handle = await open(target, ...args);
          if (String(target) !== metadataPath) return handle;
          metadataHandleOpen = true;
          fs.writeFileSync(markerPath, "held");
          await new Promise((resolve) => setTimeout(resolve, 3000));
          metadataHandleOpen = false;
          return handle;
        };
        const rename = fs.renameSync;
        fs.renameSync = function (source, destination, ...args) {
          if (String(destination) === metadataPath && metadataHandleOpen) {
            throw Object.assign(new Error("metadata is temporarily held by expiry sweep"), { code: "EPERM" });
          }
          return rename.call(this, source, destination, ...args);
        };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "live-sweep.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first accepted chunk"),
  });
  assert.equal(first.status, 200, first.body);
  await new Promise((resolve) => setTimeout(resolve, 1400));
  const second = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "live-sweep.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("second accepted chunk"),
  });
  assert.equal(second.status, 200, second.body);
  assert.equal(fs.existsSync(metadataHandleMarker), false, "the expiry sweep should not open a live session metadata file asynchronously");
});

test("chunk activity metadata retries transient EPERM only on Windows", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-retries-eperm";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  let attemptsPath;
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3 });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "existing accepted chunk", "1.part": "previously accepted second chunk" } }],
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      let metadataRenameAttempts = 0;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
          metadataRenameAttempts += 1;
          fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
          if (metadataRenameAttempts <= 3) throw Object.assign(new Error("transient metadata rename failure"), { code: "EPERM" });
        }
        return renameSync.call(fs, source, destination);
      };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(response.status, process.platform === "win32" ? 200 : 500, response.body);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), process.platform === "win32" ? "4" : "1", "only Windows retries transient EPERM");
  const metadataAfter = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  if (process.platform === "win32") assert.ok(Date.parse(metadataAfter.lastActivityAt) > Date.parse(previousActivity));
  else assert.equal(metadataAfter.lastActivityAt, previousActivity, "non-Windows EPERM preserves prior metadata");
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "existing accepted chunk");
  assert.equal(fs.readFileSync(path.join(sessionDir, "1.part"), "utf8"), process.platform === "win32" ? "second chunk" : "previously accepted second chunk", "metadata failure must not commit a replacement chunk");
  assert.deepEqual(fs.readdirSync(sessionDir).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

test("persistent EPERM prevents chunk commit and preserves prior activity metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-persistent-eperm";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  let attemptsPath;
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3 });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "existing accepted chunk", "1.part": "previously accepted second chunk" } }],
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      let metadataRenameAttempts = 0;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
          metadataRenameAttempts += 1;
          fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
          throw Object.assign(new Error("persistent metadata rename failure"), { code: "EPERM" });
        }
        return renameSync.call(fs, source, destination);
      };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), process.platform === "win32" ? "5" : "1", "persistent EPERM uses the bounded Windows retry schedule and fails immediately elsewhere");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8")), metadata);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "existing accepted chunk");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part"), "utf8"), "previously accepted second chunk", "persistent metadata failure preserves the accepted replacement target");
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

test("persistent activity metadata failure releases a first chunk reservation", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-first-part-persistent-eperm";
  let attemptsPath;
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
        const fs = require("node:fs");
        const renameSync = fs.renameSync;
        let metadataRenameAttempts = 0;
        fs.renameSync = (source, destination) => {
          if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
            metadataRenameAttempts += 1;
            fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
            throw Object.assign(new Error("persistent metadata rename failure"), { code: "EPERM" });
          }
          return renameSync.call(fs, source, destination);
        };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "first-chunk.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first accepted chunk"),
  });
  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), process.platform === "win32" ? "5" : "1");
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), [], "failed metadata refresh removes the uncommitted incoming file");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), false);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0, "failed first part leaves no orphaned quota charge");
  } finally {
    database.close();
  }
});

test("non-EPERM while refreshing chunk activity fails immediately and preserves prior metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "activity-rename-non-eperm";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  let attemptsPath;
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3 });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "existing accepted chunk" } }],
    preloadSource: ({ dir }) => {
      attemptsPath = path.join(dir, "metadata-rename-attempts.txt");
      return `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      let metadataRenameAttempts = 0;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) {
          metadataRenameAttempts += 1;
          fs.writeFileSync(${JSON.stringify(attemptsPath)}, String(metadataRenameAttempts));
          throw Object.assign(new Error("metadata rename I/O failure"), { code: "EIO" });
        }
        return renameSync.call(fs, source, destination);
      };
      `;
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 3,
    bytes: Buffer.from("second chunk"),
  });
  assert.equal(response.status, 500, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.readFileSync(attemptsPath, "utf8"), "1", "non-EPERM metadata rename failures are not retried");
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), metadata);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "existing accepted chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false, "metadata failure leaves a previously absent part uncommitted");
  assert.deepEqual(fs.readdirSync(sessionDir).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

test("failed chunk rename does not refresh accepted activity", { timeout: 45_000 }, async (t) => {
  const uploadId = "failed-chunk-rename-preserves-activity";
  const previousActivity = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { lastActivityAt: previousActivity, totalChunks: 3, originalName: "encrypted.txt", encryptionLevel: "none" }), "0.part": "already accepted chunk", "1.part": "previously accepted replacement target" } }],
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
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part"), "utf8"), "previously accepted replacement target");
});

test("chunk metadata failure leaves a previously absent part uncommitted", { timeout: 45_000 }, async (t) => {
  const uploadId = "metadata-failure-no-prior-part";
  const metadata = legacyChunkMetadata(uploadId, { lastActivityAt: new Date(Date.now() - 60 * 60 * 1000).toISOString(), totalChunks: 3, originalName: "encrypted.txt", encryptionLevel: "none" });
  delete metadata.password;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": "already accepted chunk" } }],
    preloadSource: `
      const fs = require("node:fs");
      const renameSync = fs.renameSync;
      fs.renameSync = (source, destination) => {
        if (String(source).includes(".metadata-scrub-") && String(destination).endsWith("metadata.json")) throw Object.assign(new Error("metadata rename failure"), { code: "EIO" });
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
    bytes: Buffer.from("must not commit"),
  });
  assert.equal(response.status, 500, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), metadata);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "already accepted chunk");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
  assert.deepEqual(fs.readdirSync(sessionDir).filter((name) => name.startsWith(".metadata-scrub-")), []);
});

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

  // Real HTTP integration: a previously encrypted, approved upload must still decrypt
  // to the exact original bytes after PBKDF2 became asynchronous.
  const correctPasswordResponse = await postJson(harness.port, session, `/encrypted-download/password-check.txt?folderId=${FOLDER_ID}`, { password: correctPassword });
  assert.equal(correctPasswordResponse.status, 200, correctPasswordResponse.body);
  assert.equal(correctPasswordResponse.body, "disposable encrypted fixture");
  assert.equal(correctPasswordResponse.headers["cache-control"], "no-store");
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
    chunkSessions: [{ uploadId: siblingId, files: { "metadata.json": legacyChunkMetadata(siblingId, { totalChunks: 2 }), "0.part": "preserve this session" } }],
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
    assert.equal(fs.readFileSync(path.join(siblingDirectory, "0.part"), "utf8"), "preserve this session");
    assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
  }
});

test("upload chunk route limit rejects requests before Multer writes staging files", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: { API_RATE_LIMIT_MAX: "1000", UPLOAD_CHUNK_RATE_LIMIT_MAX: "1" } });
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

test("chunk upload quota is per account across upload IDs and proxy-reported client IPs", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, {
    secondUploaderHasFolderAccess: true,
    envOverrides: {
      API_RATE_LIMIT_MAX: "1000",
      TRUSTED_PROXIES: "127.0.0.1",
      UPLOAD_CHUNK_RATE_LIMIT_MAX: "1",
    },
  });
  const uploaderSession = await login(harness.port, "uploader", harness.password);
  const otherUploaderSession = await login(harness.port, "other-uploader", harness.password);

  const firstAccountFirstUpload = await uploadChunk(harness.port, uploaderSession, {
    uploadId: "account-limit-uploader-first",
    originalName: "first.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "first account chunk",
    forwardedFor: "198.51.100.10",
  });
  assert.equal(firstAccountFirstUpload.status, 200, firstAccountFirstUpload.body);

  const secondAccountFirstUpload = await uploadChunk(harness.port, otherUploaderSession, {
    uploadId: "account-limit-other-first",
    originalName: "other.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "second account chunk",
    forwardedFor: "198.51.100.10",
  });
  assert.equal(secondAccountFirstUpload.status, 200, secondAccountFirstUpload.body);

  const sameAccountSecondUpload = await uploadChunk(harness.port, uploaderSession, {
    uploadId: "account-limit-uploader-second",
    originalName: "second.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: "must not be staged",
    forwardedFor: "203.0.113.77",
  });
  assert.equal(sameAccountSecondUpload.status, 429, sameAccountSecondUpload.body);
  assert.match(sameAccountSecondUpload.headers["retry-after"] || "", /^\d+$/);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "account-limit-uploader-second")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("chunk upload bypasses the generic API ceiling only when the dedicated peer guard is active", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: { API_RATE_LIMIT_MAX: "1", UPLOAD_CHUNK_IP_RATE_LIMIT_MAX: "10" },
  });
  const exhaustedApiQuota = await request(harness.port, "/auth/me");
  assert.equal(exhaustedApiQuota.status, 401, exhaustedApiQuota.body);

  const malformedChunkRequest = await request(harness.port, "/upload-chunk", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": "1" },
    body: "{",
  });
  assert.equal(malformedChunkRequest.status, 400, malformedChunkRequest.body);
});

test("chunk upload peer guard limits requests before JSON parsing and returns Retry-After", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: { API_RATE_LIMIT_MAX: "1000", UPLOAD_CHUNK_IP_RATE_LIMIT_MAX: "2" },
  });
  const sendMalformed = () => request(harness.port, "/upload-chunk", {
    method: "POST",
    headers: { "content-type": "application/json", "content-length": "1" },
    body: "{",
  });

  assert.equal((await sendMalformed()).status, 400);
  assert.equal((await sendMalformed()).status, 400);
  const limited = await sendMalformed();
  assert.equal(limited.status, 429, limited.body);
  assert.match(limited.headers["retry-after"] || "", /^\d+$/);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("out-of-order chunk uploads complete after all required parts arrive", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const uploadId = "out-of-order-assembly";
  const parts = [Buffer.from("first "), Buffer.from("middle "), Buffer.from("last")];

  for (const chunkIndex of [2, 0]) {
    const response = await uploadChunk(harness.port, session, {
      uploadId,
      originalName: "out-of-order-assembly.txt",
      chunkIndex,
      totalChunks: parts.length,
      encryptionLevel: "none",
      bytes: parts[chunkIndex],
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }

  const completed = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "out-of-order-assembly.txt",
    chunkIndex: 1,
    totalChunks: parts.length,
    encryptionLevel: "none",
    bytes: parts[1],
  });
  assert.equal(completed.status, 200, completed.body);
  assert.equal(JSON.parse(completed.body).complete, true);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, "out-of-order-assembly.txt")), Buffer.concat(parts));
});

test("chunk assembly fails closed when a session ledger path is duplicated", { timeout: 30_000 }, async (t) => {
  const uploadId = "duplicate-ledger-path";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: {
      "metadata.json": legacyChunkMetadata(uploadId, {
        originalName: "duplicate-ledger-path.txt",
        fileName: "duplicate-ledger-path.txt",
        totalChunks: 2,
        encryptionLevel: "none",
      }),
      "0.part": "preserve trusted chunk",
    } }],
  });
  const relativePath = path.join(FOLDER_ID, uploadId, "0.part");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"));
  try {
    const original = database.prepare("SELECT * FROM quota_operations WHERE relative_path = ?").get(relativePath);
    assert.ok(original, "the accepted disposable fixture has a tracked quota charge");
    database.prepare(`
      INSERT INTO quota_operations (
        operation_id, account_key, session_key, relative_path, state, charge_bytes,
        owner_instance_id, owner_pid, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run("duplicate-path-operation", original.account_key, original.session_key, original.relative_path, "part_committed", original.charge_bytes, "injected-duplicate", process.pid, Date.now(), Date.now());
  } finally {
    database.close();
  }

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "duplicate-ledger-path.txt",
    chunkIndex: 1,
    totalChunks: 2,
    encryptionLevel: "none",
    bytes: Buffer.from("must not assemble"),
  });
  assert.equal(response.status, 500, response.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part"), "utf8"), "preserve trusted chunk");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "1.part")), false);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "assembled.upload")), false);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

// This is a real, strictly sequential 2,000-request filesystem/SQLite test,
// not a fast unit test. GitHub-hosted Windows disks have previously exceeded
// the local 180s test cap even while individual requests remained successful.
// Keep every chunk, response check, and the final assembly; permit a bounded
// slow-runner budget instead of treating CI throughput as an upload failure.
const chunkBoundarySuiteTimeoutMs = process.platform === "win32" && process.env.CI === "true"
  ? 480_000 : 180_000;
test("a valid upload can send all 2,000 allowed chunks within the configured window",
  { timeout: chunkBoundarySuiteTimeoutMs }, async (t) => {
  const harness = await createHarness(t, {
    envOverrides: { API_RATE_LIMIT_MAX: "1" },
    // The first cold child boot and Windows AV/filesystem initialization may
    // exceed the ordinary 10s readiness probe on loaded development hosts.
    // This changes no upload, admission or per-request timeout behavior.
    readyTimeout: process.platform === "win32" ? 45_000 : TIMEOUT_MS,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
  t.after(() => agent.destroy());
  const uploadId = "two-thousand-chunk-window";

  let completed;
  const startedAt = Date.now();
  let slowestMs = 0;
  let slowestIndex = -1;
  for (let chunkIndex = 0; chunkIndex < 2000; chunkIndex += 1) {
    const chunkStartedAt = Date.now();
    try {
      completed = await uploadChunk(harness.port, session, {
        uploadId,
        originalName: "two-thousand-parts.txt",
        chunkIndex,
        totalChunks: 2000,
        bytes: Buffer.from([chunkIndex % 256]),
        agent,
        timeoutMs: chunkBoundaryRequestTimeout(chunkIndex, 2000),
      });
    } catch (error) {
      throw new Error(`chunk ${chunkIndex}/2000: ${error.message}; elapsedMs=${Date.now() - chunkStartedAt}; totalElapsedMs=${Date.now() - startedAt}; previousSlowestMs=${slowestMs} at index ${slowestIndex}; serverExit=${harness.child.exitCode ?? "running"}`, { cause: error });
    }
    const elapsedMs = Date.now() - chunkStartedAt;
    if (elapsedMs > slowestMs) { slowestMs = elapsedMs; slowestIndex = chunkIndex; }
    if (chunkIndex === 0 || (chunkIndex + 1) % 250 === 0) t.diagnostic(`chunk progress ${chunkIndex + 1}/2000 elapsedMs=${Date.now() - startedAt} mostSlowMs=${slowestMs} index=${slowestIndex}`);
    assert.equal(completed.status, 200, `chunk ${chunkIndex}: ${completed.body}\n${harness.stderr.join("")}`);
  }

  assert.equal(JSON.parse(completed.body).complete, true);
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

test("one-part empty chunk uploads complete without creating a zero-byte incoming reservation", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  let response;
  try {
    response = await uploadChunk(harness.port, session, {
      uploadId: "empty-single-part",
      originalName: "empty-single-part.txt",
      chunkIndex: 0,
      totalChunks: 1,
      encryptionLevel: "none",
      bytes: Buffer.alloc(0),
    });
  } catch (error) {
    throw new Error(`${error.message}\n${harness.stderr.join("")}`);
  }

  assert.equal(response.status, 200, response.body);
  assert.equal(JSON.parse(response.body).complete, true);
  assert.equal(fs.statSync(path.join(harness.dir, "temp", FOLDER_ID, "empty-single-part.txt")).size, 0);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("ambiguous encrypted handoff without pending metadata preserves destination and quota across restart", { timeout: 30_000 }, async (t) => {
  const uploadId = "ambiguous-encrypted-handoff";
  const fileName = "ambiguous-encrypted-handoff.txt";
  const bytes = Buffer.from("published bytes with partial encryption intent");
  const metadata = legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "server-key", originalName: fileName, fileName });
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const crypto = require("node:crypto");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const bytes = Buffer.from(${JSON.stringify(bytes.toString())});
      const destination = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)});
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.writeFileSync(destination, bytes);
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "encrypted-files.json"), JSON.stringify({ [${JSON.stringify(`${FOLDER_ID}/${fileName}`)}]: { folderId: ${JSON.stringify(FOLDER_ID)}, fileName: ${JSON.stringify(fileName)}, encryptionLevel: "server-key" } }));
      const cloudQueue = path.join(${JSON.stringify(dir)}, "data", ".rootark-cloud-temp-mutations");
      fs.mkdirSync(cloudQueue, { recursive: true });
      const digest = crypto.createHash("sha256").update(${JSON.stringify(`${FOLDER_ID}\0${fileName}`)}).digest("hex");
      fs.writeFileSync(path.join(cloudQueue, digest + ".json"), JSON.stringify({ version: 1, folderId: ${JSON.stringify(FOLDER_ID)}, fileName: ${JSON.stringify(fileName)}, desired: "present", generation: "partial-cloud-intent", updatedAt: new Date().toISOString() }));
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-charge", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: bytes.length },
        { operationId: "published-charge", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_published", chargeBytes: bytes.length },
      ]);
      quota.close();
    `,
  });
  try {
    assert.equal((await waitForServer(harness.port)).status, 200, harness.stderr.join(""));
  } catch (error) {
    throw new Error(`${error.message}\n${harness.stderr.join("")}`);
  }
  const destination = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.deepEqual(fs.readFileSync(destination), bytes, "partial encrypted intent must not cause startup to delete the publication");
  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, { uploadId, originalName: fileName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "server-key", bytes });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT state, charge_bytes FROM quota_operations ORDER BY operation_id").all(), [
      { state: "part_committed", charge_bytes: bytes.length },
      { state: "handoff_published", charge_bytes: bytes.length },
    ]);
  } finally {
    database.close();
  }
});

test("chunk multipart without a file or with a parser error releases the pre-Multer reservation", { timeout: 30_000 }, async (t) => {
  const readOperationCount = (harness) => {
    const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      return database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count;
    } finally {
      database.close();
    }
  };
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const noFile = multipartParts([
    { field: "uploadId", bytes: "missing-file" },
    { field: "originalName", bytes: "missing-file.txt" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
  ]);
  let noFileResponse;
  try {
    noFileResponse = await request(harness.port, `/upload-chunk?folderId=${FOLDER_ID}`, {
      method: "POST",
      headers: { cookie: session.cookie, origin: `http://127.0.0.1:${harness.port}`, "x-csrf-token": session.csrf, "content-type": noFile.contentType, "content-length": noFile.body.length },
      body: noFile.body,
    });
  } catch (error) {
    throw new Error(`file-less multipart request failed: ${error.code || error.name}: ${error.message}`, { cause: error });
  }
  assert.equal(noFileResponse.status, 400, noFileResponse.body);
  await harness.stopServer();
  assert.equal(readOperationCount(harness), 0, "file-less multipart releases its reservation");

  const malformedHarness = await createHarness(t);
  const malformedSession = await login(malformedHarness.port, "uploader", malformedHarness.password);
  let malformed;
  try {
    malformed = await request(malformedHarness.port, `/upload-chunk?folderId=${FOLDER_ID}`, {
      method: "POST",
      headers: { cookie: malformedSession.cookie, origin: `http://127.0.0.1:${malformedHarness.port}`, "x-csrf-token": malformedSession.csrf, "content-type": "multipart/form-data; boundary=missing-boundary", "content-length": Buffer.byteLength("not multipart data") },
      body: "not multipart data",
    });
  } catch (error) {
    throw new Error(`malformed multipart request failed: ${error.code || error.name}: ${error.message}`, { cause: error });
  }
  assert.equal(malformed.status, 400, malformed.body);
  await malformedHarness.stopServer();
  assert.equal(readOperationCount(malformedHarness), 0, "parser failure before a filename path releases its reservation");
  assert.deepEqual(fs.readdirSync(path.join(malformedHarness.chunkRoot, "incoming")), []);
});

test("failed handoff destination cleanup retains its charge and blocks retries from creating orphan files", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-cleanup-failure";
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => {
      const destinationPath = path.join(dir, "temp", FOLDER_ID, "handoff-cleanup-failure.txt");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        'const destination = ' + JSON.stringify(destinationPath) + ';',
        'const originalLstatSync = fs.lstatSync;',
        'const originalRmSync = fs.rmSync;',
        'const originalUnlinkSync = fs.unlinkSync;',
        'fs.lstatSync = function (file, ...args) {',
        '  const result = originalLstatSync.call(this, file, ...args);',
        '  if (typeof file === "string" && path.resolve(file) === path.resolve(destination) && result.isFile()) throw Object.assign(new Error("injected post-rename verification failure"), { code: "EIO" });',
        '  return result;',
        '};',
        'fs.rmSync = function (file, ...args) {',
        '  if (typeof file === "string" && path.resolve(file) === path.resolve(destination)) throw Object.assign(new Error("injected published file cleanup failure"), { code: "EIO" });',
        '  return originalRmSync.call(this, file, ...args);',
        '};',
        'fs.unlinkSync = function (file, ...args) {',
        '  if (typeof file === "string" && path.resolve(file) === path.resolve(destination)) throw Object.assign(new Error("injected published file unlink failure"), { code: "EIO" });',
        '  return originalUnlinkSync.call(this, file, ...args);',
        '};',
      ].join("\n");
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "handoff-cleanup-failure.txt",
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.from("charged until handoff cleanup"),
  });
  assert.equal(response.status, 503, response.body);

  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, "handoff-cleanup-failure.txt");
  assert.equal(fs.existsSync(destinationPath), true, "the injected failed cleanup leaves the published destination present");
  const retry = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "handoff-cleanup-failure.txt",
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.from("retry must not publish another orphan"),
  });
  assert.equal(retry.status, 503, retry.body);
  assert.equal(JSON.parse(retry.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.existsSync(destinationPath), true);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  await harness.stopServer();
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const handoff = database.prepare("SELECT operation_id, state, charge_bytes, relative_path FROM quota_operations WHERE state = 'handoff_published'").get();
    assert.ok(handoff, JSON.stringify({ rows: database.prepare("SELECT operation_id, state, charge_bytes, relative_path FROM quota_operations").all(), stderr: harness.stderr }));
    assert.equal(handoff.charge_bytes, fs.statSync(destinationPath).size);
    assert.match(handoff.relative_path.replace(/\\/g, "/"), /^handoff\//);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'handoff_published'").get().count, 1);
  } finally {
    database.close();
  }
});

test("a failed handed-off ledger transition preserves registered publication for startup reconciliation", { timeout: 45_000 }, async (t) => {
  const uploadId = "handoff-transition-failure";
  const fileName = "handoff-transition-failure.txt";
  const harness = await createHarness(t, {
    deterministicQuotaRecovery: true,
    preloadSource: () => `
      const quotaModule = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const createQuota = quotaModule.createChunkUploadQuota;
      quotaModule.createChunkUploadQuota = (...args) => {
        const quota = createQuota(...args);
        const transition = quota.transition;
        let injected = false;
        quota.transition = (operation) => {
          if (!injected && operation.state === "handed_off") {
            injected = true;
            throw Object.assign(new Error("injected post-registration ledger failure"), { code: "EIO" });
          }
          return transition(operation);
        };
        return quota;
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("registered bytes survive ledger transition failure");
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes,
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");

  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  const pendingPath = path.join(harness.dir, "data", "pending-uploads.json");
  const quotaPath = path.join(harness.chunkRoot, ".quota.sqlite");
  const originalServerPid = harness.child.pid;
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
  assert.ok(JSON.parse(fs.readFileSync(pendingPath, "utf8"))[`${FOLDER_ID}/${fileName}`]);
  const retry = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.from("must not create another published copy"),
  });
  assert.equal(retry.status, 503, retry.body);
  assert.equal(JSON.parse(retry.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
  await harness.stopServer();
  const database = new Database(quotaPath, { readonly: true });
  try {
    const operation = database.prepare("SELECT state, charge_bytes, relative_path FROM quota_operations WHERE state = 'handoff_published'").get();
    assert.ok(operation);
    assert.equal(operation.charge_bytes, bytes.length);
    assert.equal(operation.relative_path.replaceAll("\\", "/"), `handoff/${FOLDER_ID}/${encodeURIComponent(fileName)}#${bytes.length}`);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'handoff_published'").get().count, 1);
  } finally {
    database.close();
  }

  const recoveryPort = await getUnusedPort();
  const recoveryChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: {
      ...process.env,
      ...testDeadQuotaOwnerEnv(originalServerPid),
      NODE_ENV: "test",
      PORT: String(recoveryPort),
      DB_ENABLED: "false",
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "true",
      ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true",
      CLOUD_STORAGE_PROVIDER: "local",
      UPLOAD_SCAN_ENABLED: "true",
      UPLOAD_SCAN_PROVIDER: "disabled",
      UPLOAD_BLOCK_EXECUTABLES: "true",
      UPLOAD_QUARANTINE_DIR: harness.quarantineDir,
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024),
      CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000",
      CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000",
      CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
      JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const recoveryStderr = [];
  recoveryChild.stderr.on("data", (chunk) => recoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(recoveryPort)).status, 200, recoveryStderr.join(""));
    assert.deepEqual(fs.readFileSync(destinationPath), bytes);
    assert.ok(JSON.parse(fs.readFileSync(pendingPath, "utf8"))[`${FOLDER_ID}/${fileName}`]);
    assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)), false, recoveryStderr.join(""));
  } finally {
    if (recoveryChild.exitCode === null) {
      recoveryChild.kill();
      await waitForExit(recoveryChild);
    }
  }
  const recoveredLedger = new Database(quotaPath, { readonly: true });
  try {
    assert.equal(recoveredLedger.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    recoveredLedger.close();
  }
});

test("partial encrypted handoff registration preserves publication and charge while startup fails closed", { timeout: 45_000 }, async (t) => {
  const fileName = "partial-registration.txt";
  const uploadId = "partial-registration";
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const writeFileSync = fs.writeFileSync;
      let pendingWasWritten = false;
      let pendingRollbackFailed = false;
      fs.writeFileSync = (file, data, ...args) => {
        const name = String(file).replaceAll("\\\\", "/");
        const content = Buffer.isBuffer(data) ? data.toString("utf8") : String(data);
        if (name.endsWith("/data/encrypted-files.json") && content.includes(${JSON.stringify(fileName)})) {
          throw Object.assign(new Error("injected encrypted metadata write failure"), { code: "EIO" });
        }
        if (name.endsWith("/data/pending-uploads.json") && content.includes(${JSON.stringify(fileName)})) pendingWasWritten = true;
        else if (pendingWasWritten && !pendingRollbackFailed && name.endsWith("/data/pending-uploads.json")) {
          pendingRollbackFailed = true;
          throw Object.assign(new Error("injected pending rollback failure"), { code: "EIO" });
        }
        return writeFileSync.call(fs, file, data, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("encrypted bytes retained after partial registration");
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "server-key",
    bytes,
  });
  assert.equal(response.status, 503, response.body);
  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.ok(fs.statSync(destinationPath).size > 0, "encrypted publication remains present");
  assert.ok(pending(harness.dir)[`${FOLDER_ID}/${fileName}`]);
  const quotaPath = path.join(harness.chunkRoot, ".quota.sqlite");
  const database = new Database(quotaPath, { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT state, charge_bytes FROM quota_operations WHERE state = 'handoff_published'").get(), {
      state: "handoff_published",
      charge_bytes: bytes.length,
    });
  } finally {
    database.close();
  }

  harness.child.kill();
  await waitForExit(harness.child);
  const recoveryPort = await getUnusedPort();
  const recoveryChild = spawn(process.execPath, [SERVER], {
    cwd: harness.dir,
    env: { ...process.env, NODE_ENV: "test", PORT: String(recoveryPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const recoveryStderr = [];
  recoveryChild.stderr.on("data", (chunk) => recoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(recoveryPort)).status, 200, recoveryStderr.join(""));
    assert.ok(fs.statSync(destinationPath).size > 0, "restart keeps the encrypted publication");
    assert.ok(pending(harness.dir)[`${FOLDER_ID}/${fileName}`]);
    const encryptedEntries = JSON.parse(fs.readFileSync(path.join(harness.dir, "data", "encrypted-files.json"), "utf8"));
    assert.equal(encryptedEntries[`${FOLDER_ID}/${fileName}`], undefined, "the fixture leaves encrypted intent incomplete");
    assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), bytes, "accepted source part remains available for reconciliation");
    const recoveredLedger = new Database(quotaPath, { readonly: true });
    try {
      assert.deepEqual(recoveredLedger.prepare("SELECT state, charge_bytes FROM quota_operations WHERE state = 'handoff_published'").get(), {
        state: "handoff_published",
        charge_bytes: bytes.length,
      });
    } finally {
      recoveredLedger.close();
    }
    const recoveredSession = await login(recoveryPort, "uploader", harness.password);
    const failClosed = await uploadChunk(recoveryPort, recoveredSession, { uploadId, originalName: fileName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "server-key", bytes });
    assert.equal(failClosed.status, 503, failClosed.body);
    assert.equal(JSON.parse(failClosed.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  } finally {
    if (recoveryChild.exitCode === null) {
      recoveryChild.kill();
      await waitForExit(recoveryChild);
    }
  }
});

test("concurrent chunk sessions preserve both payloads without replacing a colliding destination", { timeout: 45_000 }, async (t) => {
  const name = "same-requested-name.txt";
  const collision = Buffer.from("file created concurrently after name selection");
  const harness = await createHarness(t, {
    preloadSource: ({ dir }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const writeFileSync = fs.writeFileSync;
      const target = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(name)});
      const marker = path.join(${JSON.stringify(dir)}, "data", "collision-injected");
      let injected = false;
      for (const method of ["renameSync", "linkSync"]) {
        const original = fs[method];
        fs[method] = (source, destination, ...args) => {
          if (!injected && path.basename(String(source)) === "assembled.upload" && path.resolve(String(destination)) === path.resolve(target)) {
            injected = true;
            fs.mkdirSync(path.dirname(target), { recursive: true });
            writeFileSync(marker, "yes");
            writeFileSync(target, ${JSON.stringify(collision.toString())}, { flag: "wx" });
          }
          return original.call(fs, source, destination, ...args);
        };
      }
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = Buffer.from("first session content");
  const second = Buffer.from("second session content");
  for (const [uploadId, bytes] of [["same-name-first", first], ["same-name-second", second]]) {
    const response = await uploadChunk(harness.port, session, { uploadId, originalName: name, chunkIndex: 0, totalChunks: 2, encryptionLevel: "none", bytes });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }
  const completionInputs = [
    { uploadId: "same-name-first", bytes: Buffer.from("first tail") },
    { uploadId: "same-name-second", bytes: Buffer.from("second tail") },
  ];
  const completions = await Promise.all(completionInputs.map(({ uploadId, bytes }) => uploadChunk(harness.port, session, { uploadId, originalName: name, chunkIndex: 1, totalChunks: 2, encryptionLevel: "none", bytes })));
  assert.equal(fs.existsSync(path.join(harness.dir, "data", "collision-injected")), true, "fixture placed a colliding file after filename selection");
  assert.ok(completions.some((result) => result.status === 200));
  assert.ok(completions.some((result) => result.status !== 200), completions.map((result) => result.body).join("\n"));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, name)), collision, "collision target is never overwritten");
  const failedIndex = completions.findIndex((result) => result.status !== 200);
  const retry = await uploadChunk(harness.port, session, {
    uploadId: completionInputs[failedIndex].uploadId,
    originalName: name,
    chunkIndex: 1,
    totalChunks: 2,
    encryptionLevel: "none",
    bytes: completionInputs[failedIndex].bytes,
  });
  assert.equal(retry.status, 200, retry.body);
  const names = Object.keys(pending(harness.dir)).map((key) => key.split("/").at(-1)).sort();
  assert.deepEqual(names, ["same-requested-name-1.txt", "same-requested-name-2.txt"]);
  const pendingEntries = pending(harness.dir);
  assert.equal(Object.keys(pendingEntries).length, 2);
  const contents = names.filter((fileName) => fileName !== name).map((fileName) => fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName), "utf8")).sort();
  assert.deepEqual(contents, ["first session contentfirst tail", "second session contentsecond tail"].sort());
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

test("chunk metadata rejects path swaps with adjacent 64-bit file IDs", { timeout: 45_000 }, async (t) => {
  const uploadId = "file-id-precision";
  const adjacent = 9_007_199_254_740_992n;
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId), "0.part": "original first part" } }],
    preloadSource: [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const adjacent = 9007199254740992n;',
      'const matches = (target) => path.resolve(String(target)).split(path.sep).join("/").endsWith("/file-id-precision/metadata.json");',
      'const originalOpen = fs.openSync;',
      'const originalFstat = fs.fstatSync;',
      'const originalLstat = fs.lstatSync;',
      'const originalClose = fs.closeSync;',
      'const originalPromisesOpen = fs.promises.open;',
      'const originalPromisesLstat = fs.promises.lstat;',
      'const descriptors = new Set();',
      'const identify = (stats, args, ino) => new Proxy(stats, { get(target, key, receiver) { if (key === "dev") return args[0]?.bigint === true ? 1n : 1; if (key === "ino") return args[0]?.bigint === true ? ino : Number(ino); return Reflect.get(target, key, receiver); } });',
      'fs.openSync = function (target, ...args) { const fd = originalOpen.call(this, target, ...args); if (matches(target)) descriptors.add(fd); return fd; };',
      'fs.fstatSync = function (fd, ...args) { const stats = originalFstat.call(this, fd, ...args); return descriptors.has(fd) ? identify(stats, args, adjacent) : stats; };',
      'fs.closeSync = function (fd) { descriptors.delete(fd); return originalClose.call(this, fd); };',
      'fs.lstatSync = function (target, ...args) { const stats = originalLstat.call(this, target, ...args); return matches(target) ? identify(stats, args, adjacent + 1n) : stats; };',
      'fs.promises.open = async function (target, ...args) { const handle = await originalPromisesOpen.call(this, target, ...args); if (matches(target)) { const stat = handle.stat.bind(handle); handle.stat = async (...statArgs) => identify(await stat(...statArgs), statArgs, adjacent); } return handle; };',
      'fs.promises.lstat = async function (target, ...args) { const stats = await originalPromisesLstat.call(this, target, ...args); return matches(target) ? identify(stats, args, adjacent + 1n) : stats; };'
    ].join("\n"),
  });
  try { await waitForServer(harness.port); } catch (error) { throw new Error(error.message + "\n" + harness.stderr.join("")); }
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "encrypted.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("second part"),
    password: "disposable-final-password",
  });
  assert.equal(Number(adjacent), Number(adjacent + 1n), "the injected adjacent file IDs collide as Numbers");
  assert.notEqual(response.status, 200, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "original first part");
  assert.equal(fs.existsSync(path.join(sessionDir, "1.part")), false);
});

test("chunk-session expiry sweep rejects path swaps with adjacent 64-bit file IDs", { timeout: 45_000 }, async (t) => {
  const uploadId = "async-file-id-precision";
  let metadataPath;
  let enablePath;
  let observedPath;
  const harness = await createHarness(t, {
    envOverrides: { CHUNK_UPLOAD_SESSION_SWEEP_INTERVAL_MS: "1000" },
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId), "0.part": "original first part" } }],
    preloadSource: ({ dir, chunkRoot }) => {
      metadataPath = path.join(chunkRoot, FOLDER_ID, uploadId, "metadata.json");
      enablePath = path.join(dir, "enable-async-file-id-injection");
      observedPath = path.join(dir, "async-file-id-injection-observations");
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const target = ${JSON.stringify(metadataPath)};`,
        `const enable = ${JSON.stringify(enablePath)};`,
        `const observed = ${JSON.stringify(observedPath)};`,
        'const adjacent = 9007199254740992n;',
        'const matches = (candidate) => path.resolve(String(candidate)) === path.resolve(target);',
        'const identify = (stats, args, ino) => new Proxy(stats, { get(value, key, receiver) { if (key === "dev") return args[0]?.bigint === true ? 1n : 1; if (key === "ino") return args[0]?.bigint === true ? ino : Number(ino); return Reflect.get(value, key, receiver); } });',
        'const originalOpenSync = fs.openSync;',
        'const originalFstatSync = fs.fstatSync;',
        'const originalLstatSync = fs.lstatSync;',
        'const targetDescriptors = new Set();',
        'fs.openSync = function (candidate, ...args) { const descriptor = originalOpenSync.call(this, candidate, ...args); if (matches(candidate)) targetDescriptors.add(descriptor); return descriptor; };',
        'fs.fstatSync = function (descriptor, ...args) { const value = originalFstatSync.call(this, descriptor, ...args); return targetDescriptors.has(descriptor) && fs.existsSync(enable) ? identify(value, args, adjacent) : value; };',
        'fs.lstatSync = function (candidate, ...args) { const value = originalLstatSync.call(this, candidate, ...args); if (!matches(candidate) || !fs.existsSync(enable)) return value; fs.appendFileSync(observed, "x"); return identify(value, args, adjacent + 1n); };',
      ].join("\n");
    },
  });

  fs.writeFileSync(enablePath, "enabled", { flag: "wx" });
  const firstSweepDeadline = Date.now() + 5_000;
  while ((!fs.existsSync(observedPath) || fs.readFileSync(observedPath, "utf8").length < 1) && Date.now() < firstSweepDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(fs.existsSync(observedPath), true, "the expiry reader inspected the metadata after injection was enabled");

  const expiredAt = new Date(Date.now() - CHUNK_SESSION_TTL_MS - 60_000).toISOString();
  const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  metadata.lastActivityAt = expiredAt;
  fs.writeFileSync(metadataPath, JSON.stringify(metadata));
  const secondSweepDeadline = Date.now() + 5_000;
  while (fs.readFileSync(observedPath, "utf8").length < 2 && Date.now() < secondSweepDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.ok(fs.readFileSync(observedPath, "utf8").length >= 2, "the expiry reader reached a second sweep after the fixture became expired");
  await new Promise((resolve) => setTimeout(resolve, 100));

  const sessionDir = path.dirname(metadataPath);
  assert.equal(fs.readFileSync(path.join(sessionDir, "0.part"), "utf8"), "original first part");
  const preservedMetadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
  assert.equal(preservedMetadata.lastActivityAt, expiredAt);
  assert.equal(Object.hasOwn(preservedMetadata, "__expiredAt"), false, "an identity-mismatched session is not expired or rewritten");
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
    assert.equal(response.status, 503, response.body);
    assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
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

test("unsafe chunk storage symlinks disable only chunk uploads at startup", { timeout: 30_000 }, async (t) => {
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

  assert.equal((await waitForServer(harness.port)).status, 200);
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "unsafe-storage-startup",
    originalName: "unsafe-storage-startup.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not write"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.existsSync(path.join(outsidePath, "incoming")), false);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
});

test("chunk upload startup disables only chunk uploads when session enumeration cannot be verified", { timeout: 45_000 }, async (t) => {
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
      assert.equal((await waitForServer(harness.port)).status, 200);
      assert.equal(fs.readFileSync(markerPath, "utf8"), "triggered");
      const session = await login(harness.port, "uploader", harness.password);
      const response = await uploadChunk(harness.port, session, {
        uploadId: `enumeration-${targetName}`,
        originalName: "enumeration.txt",
        chunkIndex: 0,
        totalChunks: 1,
        bytes: Buffer.from("must not stage"),
      });
      assert.equal(response.status, 503, response.body);
      assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
      assert.equal((await request(harness.port, "/login.html")).status, 200);
    });
  }
});

test("folder lifecycle lock timeouts reject uploads, remove transient staging, and preserve accepted session data", { timeout: 30_000 }, async (t) => {
  const uploadId = "lifecycle-timeout-chunk";
  let timeoutResponseMarker;
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, {
          originalName: "timeout-chunk.txt",
          fileName: "timeout-chunk.txt",
          totalChunks: 2,
          encryptionLevel: "none",
        }),
        "0.part": "preserve accepted chunk",
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
  const existingSessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
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
      chunkIndex: 1,
      totalChunks: 2,
      bytes: Buffer.from("disposable final chunk"),
    });
    assertRejectedClean(harness, chunk, 503);
    assert.equal(chunk.headers["retry-after"], "5");
    assert.equal(fs.existsSync(existingSessionDir), true);
    assert.equal(fs.readFileSync(path.join(existingSessionDir, "0.part"), "utf8"), "preserve accepted chunk");
    assert.equal(fs.readFileSync(path.join(existingSessionDir, "1.part"), "utf8"), "disposable final chunk");
    assert.equal(fs.readFileSync(timeoutResponseMarker, "utf8"), "present", "the existing session remains present when the 503 response is sent");
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
  await harness.stopServer();
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const sessionOperations = quotaDatabase.prepare("SELECT state, relative_path FROM quota_operations WHERE session_key = ? ORDER BY relative_path").all(`${FOLDER_ID}/${uploadId}`);
    assert.deepEqual(sessionOperations.map((operation) => [operation.state, operation.relative_path]), [
      ["part_committed", path.join(FOLDER_ID, uploadId, "0.part")],
      ["part_committed", path.join(FOLDER_ID, uploadId, "1.part")],
    ]);
  } finally {
    quotaDatabase.close();
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

test("chunk uploads stay disabled without explicit quota limits while the server remains available", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "",
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "",
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-config-missing",
    originalName: "quota-config-missing.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("small disposable chunk"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("startup imports only validated legacy chunk parts into the quota ledger and scrubs legacy passwords", { timeout: 30_000 }, async (t) => {
  const uploadId = "legacy-quota-import";
  const payload = Buffer.from("legacy staged bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId),
        "0.part": payload,
      },
    }],
  });
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const row = database.prepare("SELECT account_key, session_key, state, charge_bytes FROM quota_operations WHERE relative_path = ?").get(path.join(FOLDER_ID, uploadId, "0.part"));
    assert.deepEqual(row, {
      account_key: "uploader",
      session_key: `${FOLDER_ID}/${uploadId}`,
      state: "part_committed",
      charge_bytes: payload.length,
    }, harness.stderr.join(""));
    const metadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
    assert.equal(Object.hasOwn(metadata, "password"), false);
    assert.equal((await request(harness.port, "/login.html")).status, 200);
  } finally {
    database.close();
  }
});

test("a committed chunk whose file size disagrees with its live ledger charge fails closed and is preserved", { timeout: 30_000 }, async (t) => {
  const uploadId = "quota-charge-mismatch";
  const payload = Buffer.from("preserve mismatched committed bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId), "0.part": payload } }],
    preloadSource: ({ chunkRoot }) => `
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const quota = createChunkUploadQuota({ rootDir: ${JSON.stringify(chunkRoot)}, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "live-owner", processId: process.pid });
      quota.initialize([{ operationId: "mismatched-charge", accountKey: "uploader", sessionKey: ${JSON.stringify(`${FOLDER_ID}/${uploadId}`)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"), state: "part_committed", chargeBytes: ${payload.length + 1} }]);
      quota.close();
    `,
  });

  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "quota-charge-mismatch.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), payload);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT charge_bytes FROM quota_operations WHERE operation_id = 'mismatched-charge'").get().charge_bytes, payload.length + 1);
  } finally {
    database.close();
  }
});

test("chunk handoff persists pending metadata when app data uses SQLite", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { appDataMode: "sqlite" });
  const session = await login(harness.port, "uploader", harness.password);
  const bytes = Buffer.from("sqlite pending handoff");
  const response = await uploadChunk(harness.port, session, {
    uploadId: "sqlite-app-pending",
    originalName: "sqlite-app-pending.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes,
  });
  assert.equal(response.status, 200, response.body);
  assert.equal(JSON.parse(response.body).complete, true);
  const database = new Database(path.join(harness.dir, "data", "rootark.sqlite"), { readonly: true });
  try {
    const pending = database.prepare("SELECT folder_id, file_name, uploaded_by FROM pending_uploads WHERE id = ?").get(`${FOLDER_ID}/sqlite-app-pending.txt`);
    assert.deepEqual(pending, { folder_id: FOLDER_ID, file_name: "sqlite-app-pending.txt", uploaded_by: "uploader" });
  } finally {
    database.close();
  }
  assert.equal(fs.statSync(path.join(harness.dir, "temp", FOLDER_ID, "sqlite-app-pending.txt")).size, bytes.length);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "sqlite-app-pending")), false);
  const quota = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quota.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    quota.close();
  }
});

test("startup removes a dead-owner incoming reservation only after reconciling its exact file", { timeout: 30_000 }, async (t) => {
  const operationId = "a".repeat(32);
  const bytes = "stale incoming";
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(operationId)}), ${JSON.stringify(bytes)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize();
      quota.reserve({ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), reservedBytes: 8 * 1024 * 1024 });
      quota.close();
    `,
  });
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", operationId)), false, [...harness.stdout, ...harness.stderr].join(""));
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("startup does not claim a suspicious stale incoming file it cannot safely remove", { timeout: 30_000 }, async (t) => {
  const operationId = "e".repeat(32);
  const bytes = "suspicious incoming with a hard link";
  const originalOwnerPid = 2147483000;
  const harness = await createHarness(t, {
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const quotaModule = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const createChunkUploadQuota = quotaModule.createChunkUploadQuota;
      const root = ${JSON.stringify(chunkRoot)};
      const incomingPath = path.join(root, "incoming", ${JSON.stringify(operationId)});
      fs.mkdirSync(path.dirname(incomingPath), { recursive: true });
      fs.writeFileSync(incomingPath, ${JSON.stringify(bytes)});
      const oldTime = new Date(Date.now() - 10 * 60 * 1000);
      fs.utimesSync(incomingPath, oldTime, oldTime);
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: ${originalOwnerPid} });
      quota.initialize();
      quota.reserve({ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), reservedBytes: 8 * 1024 * 1024 });
      quota.close();
      quotaModule.createChunkUploadQuota = function (...args) {
        const service = createChunkUploadQuota(...args);
        const ownerStatus = service.ownerStatus.bind(service);
        const claim = service.claim.bind(service);
        const lstatSync = fs.lstatSync;
        let checks = 0;
        let operationClaimed = false;
        let injectedHardLink = false;
        service.claim = function (operation) {
          const result = claim(operation);
          if (operation.operationId === ${JSON.stringify(operationId)} && result) operationClaimed = true;
          return result;
        };
        fs.lstatSync = function (filePath, ...statArgs) {
          if (operationClaimed && !injectedHardLink && path.resolve(filePath) === path.resolve(incomingPath)) {
            fs.linkSync(incomingPath, path.join(${JSON.stringify(dir)}, "suspicious-alias"));
            injectedHardLink = true;
          }
          return lstatSync.call(this, filePath, ...statArgs);
        };
        service.ownerStatus = function (operation) {
          if (operation.operationId === ${JSON.stringify(operationId)}) {
            checks += 1;
            if (checks === 1) return "live";
            if (checks <= 3) return "dead";
          }
          return ownerStatus(operation);
        };
        return service;
      };
    `,
  });

  const incomingPath = path.join(harness.chunkRoot, "incoming", operationId);
  assert.equal(fs.readFileSync(incomingPath, "utf8"), bytes);
  assert.equal(fs.statSync(incomingPath).nlink, 2);
  const aliasPath = path.join(harness.dir, "suspicious-alias");
  assert.equal(fs.readFileSync(aliasPath, "utf8"), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const operation = database.prepare("SELECT owner_pid, state, charge_bytes FROM quota_operations WHERE operation_id = ?").get(operationId);
    assert.equal(operation.owner_pid, originalOwnerPid, "invalid file state must leave the claim with the dead owner for restart recovery");
    assert.equal(operation.state, "reserved");
    assert.equal(operation.charge_bytes, 8 * 1024 * 1024);
  } finally {
    database.close();
  }
});

test("startup recovers a reused PID only when process-start identity proves it is stale", { timeout: 30_000 }, async (t) => {
  const operationId = "b".repeat(32);
  const bytes = "live incoming";
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const quotaModule = require(' + JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js")) + ');',
      'const { createChunkUploadQuota, getCurrentProcessIdentity } = quotaModule;',
      'const root = ' + JSON.stringify(chunkRoot) + ';',
      'const currentIdentity = getCurrentProcessIdentity();',
      'const oldIdentity = process.platform === "linux" && currentIdentity ? { ...currentIdentity, processStartTime: "0" } : currentIdentity;',
      'fs.mkdirSync(path.join(root, "incoming"), { recursive: true });',
      'fs.writeFileSync(path.join(root, "incoming", ' + JSON.stringify(operationId) + '), ' + JSON.stringify(bytes) + ');',
      'const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "prior-owner", processId: process.pid, processIdentity: oldIdentity });',
      'quota.initialize([{ operationId: ' + JSON.stringify(operationId) + ', accountKey: "uploader", relativePath: path.join("incoming", ' + JSON.stringify(operationId) + '), state: "writing", chargeBytes: Buffer.byteLength(' + JSON.stringify(bytes) + ') }]);',
      'quota.close();',
    ].join("\n"),
  });
  const shouldRecover = process.platform === "linux" && Boolean(getCurrentProcessIdentity());
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", operationId)), !shouldRecover, harness.stderr.join(""));
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE operation_id = ?").get(operationId).count, shouldRecover ? 0 : 1);
  } finally {
    database.close();
  }
});

test("startup preserves incoming bytes and disables chunk uploads when an operation owner is from another host", { timeout: 30_000 }, async (t) => {
  const operationId = "d".repeat(32);
  const bytes = "preserve ambiguous owner";
  const foreignIdentity = { version: 1, platform: "linux", hostId: "b".repeat(64), bootId: "00000000-0000-0000-0000-000000000002", pidNamespace: "pid:[999999]", processStartTime: "1" };
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(operationId)}), ${JSON.stringify(bytes)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "foreign-owner", processId: 4242, processIdentity: ${JSON.stringify(foreignIdentity)} });
      quota.initialize([{ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), state: "writing", chargeBytes: Buffer.byteLength(${JSON.stringify(bytes)}) }]);
      quota.close();
    `,
  });
  assert.match(harness.stderr.join(""), /quota initialization unavailable/);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", operationId), "utf8"), bytes, "ambiguous ownership leaves the incoming payload untouched");
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "ambiguous-owner-blocked",
    originalName: "ambiguous-owner.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must remain blocked"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", operationId), "utf8"), bytes);
});

test("chunk quota fails closed when a persisted owner PID belongs to another PID namespace", () => {
  const currentIdentity = {
    version: 1,
    platform: "linux",
    hostId: "a".repeat(64),
    bootId: "00000000-0000-0000-0000-000000000001",
    pidNamespace: "pid:[100]",
    processStartTime: "500",
  };
  const ownerIdentity = { ...currentIdentity, pidNamespace: "pid:[200]", processStartTime: "1" };
  let signaled = false;

  const status = classifyProcessOwner(4242, ownerIdentity, currentIdentity, {
    platform: "linux",
    kill() { signaled = true; },
  });

  assert.equal(status, "unknown", "a numeric PID from a different namespace is ambiguous even when host and boot match");
  assert.equal(signaled, false, "namespace ambiguity must not be resolved by probing the colliding PID");
});

test("startup preserves an old incoming file owned by the exact live instance", { timeout: 30_000 }, async (t) => {
  const operationId = "c".repeat(32);
  const bytes = "old but actively owned incoming data";
  const harness = await createHarness(t, {
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const modulePath = ${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))};
      const quotaModule = require(modulePath);
      const createQuota = quotaModule.createChunkUploadQuota;
      quotaModule.createChunkUploadQuota = (options) => createQuota({ ...options, processInstanceId: "exact-live-instance" });
      const root = ${JSON.stringify(chunkRoot)};
      const incomingDir = path.join(root, "incoming");
      fs.mkdirSync(incomingDir, { recursive: true });
      const incomingPath = path.join(incomingDir, ${JSON.stringify(operationId)});
      fs.writeFileSync(incomingPath, ${JSON.stringify(bytes)});
      const old = new Date(Date.now() - 10 * 60 * 1000);
      fs.utimesSync(incomingPath, old, old);
      const quota = createQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "exact-live-instance", processId: process.pid });
      quota.initialize([{ operationId: ${JSON.stringify(operationId)}, accountKey: "uploader", relativePath: path.join("incoming", ${JSON.stringify(operationId)}), state: "writing", chargeBytes: Buffer.byteLength(${JSON.stringify(bytes)}) }]);
      quota.close();
      const simpleDir = path.join(${JSON.stringify(dir)}, "temp", ".incoming");
      fs.mkdirSync(simpleDir, { recursive: true });
      const simplePath = path.join(simpleDir, "1234567890123-0123456789abcdef.upload");
      fs.writeFileSync(simplePath, "stale simple upload");
      fs.utimesSync(simplePath, old, old);
    `,
  });
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", operationId), "utf8"), bytes);
  assert.deepEqual(filesUnder(path.join(harness.dir, "temp", ".incoming")), [], "ordinary simple-upload staging still receives age-based cleanup");
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT state, charge_bytes FROM quota_operations WHERE operation_id = ?").get(operationId), {
      state: "writing",
      charge_bytes: Buffer.byteLength(bytes),
    });
  } finally {
    database.close();
  }
});

test("startup removes an interrupted assembly and preserves charged source parts", { timeout: 30_000 }, async (t) => {
  const uploadId = "interrupted-assembly";
  const first = Buffer.from("part zero");
  const second = Buffer.from("part one");
  const assembly = Buffer.from("partial ciphertext");
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 2, encryptionLevel: "password" }), "0.part": first, "1.part": second, "assembled.upload": assembly },
    }],
    preloadSource: ({ chunkRoot }) => `
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${first.length} },
        { operationId: "part-one", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "1.part"), state: "part_committed", chargeBytes: ${second.length} },
        { operationId: "assembly-op", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "assembled.upload"), state: "encrypting", chargeBytes: ${assembly.length} },
      ]);
      quota.close();
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), first);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "1.part")), second);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, charge_bytes FROM quota_operations ORDER BY operation_id").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "1.part"), charge_bytes: second.length },
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), charge_bytes: first.length },
    ]);
  } finally {
    database.close();
  }
});

test("partial in-place encryption failure removes assembly scratch but preserves charged parts", { timeout: 30_000 }, async (t) => {
  const uploadId = "partial-encryption-failure";
  const source = Buffer.from("accepted source bytes that must remain intact");
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'const target = path.join(' + JSON.stringify(chunkRoot) + ', ' + JSON.stringify(FOLDER_ID) + ', ' + JSON.stringify(uploadId) + ', "assembled.upload");',
      'const originalWriteFileSync = fs.writeFileSync;',
      'fs.writeFileSync = function (file, data, ...args) {',
      '  if (typeof file === "string" && path.resolve(file) === path.resolve(target) && Buffer.isBuffer(data)) {',
      '    originalWriteFileSync.call(this, file, data.subarray(0, Math.max(1, Math.floor(data.length / 2))), ...args);',
      '    throw Object.assign(new Error("injected partial encryption write"), { code: "EIO" });',
      '  }',
      '  return originalWriteFileSync.call(this, file, data, ...args);',
      '};',
    ].join("\n"),
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: "partial-encryption-failure.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: source,
    encryptionLevel: "password",
    password: "disposable-encryption-password",
  });
  assert.equal(response.status, 400, response.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), source);
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  const metadata = JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8"));
  assert.equal(Object.hasOwn(metadata, "password"), false);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, state, charge_bytes FROM quota_operations ORDER BY operation_id").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), state: "part_committed", charge_bytes: source.length },
    ]);
  } finally {
    database.close();
  }
});

test("startup recovers an assembly interrupted during scanning from intact source parts", { timeout: 30_000 }, async (t) => {
  const uploadId = "scan-interrupted-assembly";
  const source = Buffer.from("source part remains charged");
  const assembly = Buffer.from("assembled bytes being scanned");
  const harness = await createHarness(t, {
    chunkSessions: [{
      uploadId,
      files: {
        "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none" }),
        "0.part": source,
        "assembled.upload": assembly,
      },
    }],
    preloadSource: ({ chunkRoot }) => [
      'const path = require("node:path");',
      'const { createChunkUploadQuota } = require(' + JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js")) + ');',
      'const root = ' + JSON.stringify(chunkRoot) + ';',
      'const session = path.join(' + JSON.stringify(FOLDER_ID) + ', ' + JSON.stringify(uploadId) + ');',
      'const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });',
      'quota.initialize([',
      '  { operationId: "scan-source", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ' + source.length + ' },',
      '  { operationId: "scan-assembly", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "assembled.upload"), state: "assembled", chargeBytes: ' + assembly.length + ' },',
      ']);',
      'quota.close();',
    ].join("\n"),
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), source);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, state, charge_bytes FROM quota_operations").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), state: "part_committed", charge_bytes: source.length },
    ]);
  } finally {
    database.close();
  }
});

test("startup finishes a replacement only when target, backup, incoming file, and ledger identities agree", { timeout: 30_000 }, async (t) => {
  const uploadId = "replacement-crash-recovery";
  const oldBytes = Buffer.from("old part");
  const newBytes = Buffer.from("replacement part");
  const newOperationId = "new-replacement-operation";
  const backupName = `.replacement-${newOperationId}.part`;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1 }), [backupName]: oldBytes } }],
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(newOperationId)}), ${JSON.stringify(newBytes.toString())});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "old-replacement-operation", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, ${JSON.stringify(backupName)}), state: "promoting", chargeBytes: ${oldBytes.length} },
        { operationId: ${JSON.stringify(newOperationId)}, accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "promoting", chargeBytes: ${newBytes.length} },
      ]);
      quota.close();
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), newBytes);
  assert.equal(fs.existsSync(path.join(sessionDir, backupName)), false);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", newOperationId)), false);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT operation_id, state, charge_bytes FROM quota_operations").all(), [
      { operation_id: newOperationId, state: "part_committed", charge_bytes: newBytes.length },
    ]);
  } finally {
    database.close();
  }
});

test("replacement recovery preserves session data when quota ownership disagrees with metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-owner-mismatch";
  const oldBytes = Buffer.from("accepted old part must survive");
  const newBytes = Buffer.from("untrusted replacement input");
  const newOperationId = "new-replacement-operation";
  const backupName = `.replacement-${newOperationId}.part`;
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const harness = await createHarness(t, {
    waitForReady: false,
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1 }), [backupName]: oldBytes } }],
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(sessionKey)};
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.writeFileSync(path.join(root, "incoming", ${JSON.stringify(newOperationId)}), ${JSON.stringify(newBytes.toString())});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "old-replacement-operation", accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, ${JSON.stringify(backupName)}), state: "promoting", chargeBytes: ${oldBytes.length} },
        { operationId: ${JSON.stringify(newOperationId)}, accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "promoting", chargeBytes: ${newBytes.length} },
      ]);
      quota.close();
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  try {
    assert.equal((await waitForServer(harness.port)).status, 200);
  } catch (error) {
    throw new Error(`${error.message}\nserver exit: ${harness.child.exitCode}\nserver stdout:\n${harness.stdout.join("")}\nserver stderr:\n${harness.stderr.join("")}`);
  }
  let loginSession;
  try {
    loginSession = await login(harness.port, "uploader", harness.password);
  } catch (error) {
    throw new Error(`${error.message}\nserver stdout:\n${harness.stdout.join("")}\nserver stderr:\n${harness.stderr.join("")}`);
  }
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  const blocked = await uploadChunk(harness.port, loginSession, {
    uploadId: "replacement-owner-mismatch-blocked",
    originalName: "replacement-owner-mismatch-blocked.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not start staging"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, backupName)), oldBytes);
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, "incoming", newOperationId)), newBytes);
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false);
  assert.equal(fs.existsSync(path.join(sessionDir, "metadata.json")), true);
});

test("startup releases a deleted part only when its seven-day expiry tombstone proves cleanup intent", { timeout: 30_000 }, async (t) => {
  const uploadId = "expired-part-recovery";
  const tombstone = { __expiredAt: new Date().toISOString() };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": tombstone } }],
    preloadSource: ({ chunkRoot }) => `
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const relative = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part");
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([{ operationId: "expired-part", accountKey: "uploader", sessionKey: ${JSON.stringify(`${FOLDER_ID}/${uploadId}`)}, relativePath: relative, state: "part_committed", chargeBytes: 10 }]);
      quota.close();
    `,
  });
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8")), tombstone);
});

test("startup completes a durable handoff only with matching pending record and destination", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-crash-recovery";
  const bytes = Buffer.from("published bytes");
  const fileName = "published.txt";
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }), "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const parts = [{ operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} }];
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([...parts, { operationId: "handoff-operation", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_pending", chargeBytes: ${bytes.length} }]);
      quota.close();
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(`${FOLDER_ID}/${fileName}`)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(path.join(sessionDir, "0.part")), false, harness.stderr.join(""));
  assert.equal(fs.existsSync(sessionDir), false, JSON.stringify({ entries: fs.existsSync(sessionDir) ? fs.readdirSync(sessionDir) : [], stderr: harness.stderr.join("") }));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("startup completes an injected metadata-unlink handoff interruption with an empty session directory", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-empty-session-crash";
  const fileName = "handoff-empty-session.txt";
  const bytes = Buffer.from("durably published bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }) } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(FOLDER_ID + "/" + uploadId)};
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([{ operationId: "handed-off-marker", accountKey: "uploader", sessionKey: session, relativePath: ${JSON.stringify("handoff/" + FOLDER_ID + "/" + encodeURIComponent(fileName) + "#" + bytes.length)}, state: "handed_off", chargeBytes: 0 }]);
      quota.close();
      // Inject the crash boundary after metadata unlink and before session rmdir.
      fs.unlinkSync(path.join(root, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "metadata.json"));
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(FOLDER_ID + "/" + fileName)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.equal(fs.existsSync(sessionDir), false, harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_sessions").get().count, 0);
  } finally {
    database.close();
  }
});

test("startup rejects unexpected contents in an empty-metadata handoff session directory", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-unexpected-session-content";
  const fileName = "handoff-unexpected-content.txt";
  const bytes = Buffer.from("durably published bytes");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: {
      "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }),
      "unexpected.bin": "must be preserved",
    } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(FOLDER_ID + "/" + uploadId)};
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([{ operationId: "handed-off-marker", accountKey: "uploader", sessionKey: session, relativePath: ${JSON.stringify("handoff/" + FOLDER_ID + "/" + encodeURIComponent(fileName) + "#" + bytes.length)}, state: "handed_off", chargeBytes: 0 }]);
      quota.close();
      fs.unlinkSync(path.join(root, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "metadata.json"));
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(FOLDER_ID + "/" + fileName)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "unexpected.bin"), "utf8"), "must be preserved", harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    bytes,
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
});

test("startup removes an unregistered published handoff and keeps charged parts retryable", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-published-no-pending";
  const fileName = "unregistered-published.txt";
  const bytes = Buffer.from("source part survives an unregistered publication");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }), "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} },
        { operationId: "published-output", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_published", chargeBytes: ${bytes.length} },
      ]);
      quota.close();
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), Buffer.from(${JSON.stringify(bytes.toString())}));
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.equal(fs.existsSync(destinationPath), false, harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);

  const session = await login(harness.port, "uploader", harness.password);
  const retry = await uploadChunk(harness.port, session, {
    uploadId,
    originalName: fileName,
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes,
  });
  assert.equal(retry.status, 200, `${retry.body}\n${harness.stdout.join("")}\n${harness.stderr.join("")}`);
  assert.equal(JSON.parse(retry.body).complete, true);
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
  await harness.stopServer();
  const finalLedger = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    const remainingOperations = finalLedger.prepare("SELECT operation_id, account_key, session_key, relative_path, state, charge_bytes FROM quota_operations ORDER BY operation_id").all();
    assert.deepEqual(remainingOperations, [], `unexpected operations after successful retry: ${JSON.stringify(remainingOperations)}`);
  } finally {
    finalLedger.close();
  }
});

test("startup cleans an interrupted hard-link handoff and keeps its accepted part retryable", { timeout: 30_000 }, async (t) => {
  const uploadId = "hardlink-handoff-recovery";
  const fileName = "hardlink-recovery.txt";
  const bytes = Buffer.from("accepted source part survives interrupted publication");
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName }), "0.part": bytes, "assembled.upload": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const source = path.join(root, session, "assembled.upload");
      const destination = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)});
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.linkSync(source, destination);
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "a-part", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} },
        { operationId: "z-handoff", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handoff_pending", chargeBytes: ${bytes.length} },
      ]);
      quota.close();
    `,
  });
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const destinationPath = path.join(harness.dir, "temp", FOLDER_ID, fileName);
  assert.equal(fs.existsSync(destinationPath), false, harness.stderr.join(""));
  assert.equal(fs.existsSync(path.join(sessionDir, "assembled.upload")), false);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT operation_id, state, charge_bytes FROM quota_operations").all(), [
      { operation_id: "a-part", state: "part_committed", charge_bytes: bytes.length },
    ]);
  } finally {
    database.close();
  }
  const session = await login(harness.port, "uploader", harness.password);
  const retry = await uploadChunk(harness.port, session, { uploadId, originalName: fileName, chunkIndex: 0, totalChunks: 1, encryptionLevel: "none", bytes });
  assert.equal(retry.status, 200, retry.body);
  assert.deepEqual(fs.readFileSync(destinationPath), bytes);
});

test("startup resumes per-part cleanup after a durable handoff crash", { timeout: 30_000 }, async (t) => {
  const uploadId = "handoff-part-cleanup-recovery";
  const bytes = Buffer.from("published bytes");
  const remainingPart = Buffer.from("last source part");
  const fileName = "published-after-crash.txt";
  const completedMetadata = {
    ...legacyChunkMetadata(uploadId, { totalChunks: 2, encryptionLevel: "none", fileName }),
    __resumeBlocked: true,
    __chunkQuotaHandoffComplete: true,
  };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": completedMetadata, "1.part": remainingPart } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483000 });
      quota.initialize([
        { operationId: "part-zero", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: 8 },
        { operationId: "part-one", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "1.part"), state: "part_committed", chargeBytes: ${remainingPart.length} },
        { operationId: "handoff-operation", accountKey: "uploader", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${fileName}#${bytes.length}`)}, state: "handed_off", chargeBytes: 0 },
      ]);
      quota.close();
      fs.mkdirSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}), { recursive: true });
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({ ${JSON.stringify(`${FOLDER_ID}/${fileName}`)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" } }));
    `,
  });
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)), false, harness.stderr.join(""));
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("aborted chunk bodies remove their reserved incoming file before releasing quota", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "uploader", harness.password);
  const body = multipartParts([
    { field: "uploadId", bytes: "abort-reservation" },
    { field: "originalName", bytes: "abort.bin" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
    { field: "chunk", filename: "abort.bin", bytes: Buffer.alloc(512 * 1024, 0x61) },
  ], { close: false });
  const req = http.request({
    host: "127.0.0.1",
    port: harness.port,
    path: "/upload-chunk",
    method: "POST",
    headers: {
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      "content-type": body.contentType,
      "content-length": body.body.length + 128,
    },
  });
  req.on("error", () => {});
  req.write(body.body);
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingDeadline = Date.now() + 3000;
  while ((!fs.existsSync(incomingDir) || fs.readdirSync(incomingDir).length === 0) && Date.now() < incomingDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(fs.existsSync(incomingDir) && fs.readdirSync(incomingDir).length > 0, "Multer began writing after a prior reservation");
  req.destroy();
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"));
  try {
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      const incomingCount = fs.readdirSync(incomingDir).length;
      const operationCount = database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count;
      if (incomingCount === 0 && operationCount === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(fs.readdirSync(incomingDir).length, 0);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
  }
});

test("bounded request timeout aborts a stalled chunk body and releases it only after cleanup", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    preloadSource: [
      'const originalSetTimeout = global.setTimeout;',
      'global.setTimeout = function (callback, delay, ...args) { return originalSetTimeout(callback, delay === 5 * 60 * 1000 ? 1000 : delay, ...args); };',
    ].join("\n"),
  });
  const session = await login(harness.port, "uploader", harness.password);
  const body = multipartParts([
    { field: "uploadId", bytes: "timeout-reservation" },
    { field: "originalName", bytes: "timeout.bin" },
    { field: "chunkIndex", bytes: "0" },
    { field: "totalChunks", bytes: "1" },
    { field: "chunk", filename: "timeout.bin", bytes: Buffer.alloc(512 * 1024, 0x61) },
  ], { close: false });
  let timedOut;
  const timeoutResult = new Promise((resolve) => { timedOut = resolve; });
  const req = http.request({
    host: "127.0.0.1",
    port: harness.port,
    path: "/upload-chunk",
    method: "POST",
    headers: {
      cookie: session.cookie,
      "x-csrf-token": session.csrf,
      "content-type": body.contentType,
      "content-length": body.body.length + 128,
    },
  }, (res) => {
    res.resume();
    res.on("end", () => timedOut({ status: res.statusCode }));
  });
  req.on("error", (error) => timedOut({ error: error.code || error.name }));
  req.write(body.body);

  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingDeadline = Date.now() + 3000;
  while ((!fs.existsSync(incomingDir) || fs.readdirSync(incomingDir).length === 0) && Date.now() < incomingDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(fs.existsSync(incomingDir) && fs.readdirSync(incomingDir).length > 0, "the reservation and incoming write start before timeout");
  const timeout = await Promise.race([
    timeoutResult,
    new Promise((resolve) => setTimeout(() => resolve(null), 5000)),
  ]);
  assert.ok(timeout, "the HTTP server terminates the incomplete request within its configured timeout");
  assert.ok(timeout.status === 408 || timeout.error, JSON.stringify(timeout));

  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"));
  try {
    const cleanupDeadline = Date.now() + 5000;
    while (Date.now() < cleanupDeadline) {
      if (fs.readdirSync(incomingDir).length === 0 && database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count === 0) break;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.deepEqual(fs.readdirSync(incomingDir), []);
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    database.close();
    req.destroy();
  }
});

test("a corrupt chunk quota ledger disables only chunk uploads at startup", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `require("node:fs").mkdirSync(${JSON.stringify(chunkRoot)}, { recursive: true }); require("node:fs").writeFileSync(${JSON.stringify(path.join(chunkRoot, ".quota.sqlite"))}, "corrupt ledger");`,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-ledger-corrupt",
    originalName: "quota-ledger-corrupt.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("small disposable chunk"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("semantically invalid quota rows preserve session payloads while startup scrubs legacy passwords", { timeout: 45_000 }, async (t) => {
  const uploadId = "invalid-quota-state-path";
  const partBytes = Buffer.from("accepted disposable chunk data");
  const metadata = legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", password: "disposable-legacy-encryption-password" });
  const staleIncomingId = "a".repeat(32);
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": partBytes } }],
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      `const chunkRoot = ${JSON.stringify(chunkRoot)};`,
      `const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});`,
      `const { ensureWindowsChunkUploadRoot } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadWindowsAcl.js"))});`,
      'fs.mkdirSync(path.join(chunkRoot, "incoming"), { recursive: true });',
      `if (process.platform !== "win32") fs.chmodSync(path.join(chunkRoot, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}), 0o755);`,
      'ensureWindowsChunkUploadRoot(chunkRoot);',
      'const quota = createChunkUploadQuota({ rootDir: chunkRoot, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "stale-fixture", processId: 2147483647 });',
      'quota.initialize();',
      `const staleIncomingId = ${JSON.stringify(staleIncomingId)};`,
      'quota.reserve({ operationId: staleIncomingId, accountKey: "uploader", relativePath: path.join("incoming", staleIncomingId), reservedBytes: 12 });',
      'fs.writeFileSync(path.join(chunkRoot, "incoming", staleIncomingId), "retain during fail-closed validation");',
      `quota.reserve({ operationId: ${JSON.stringify("b".repeat(32))}, accountKey: "uploader", sessionKey: ${JSON.stringify(sessionKey)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"), reservedBytes: ${partBytes.length} });`,
      `quota.reserve({ operationId: ${JSON.stringify("c".repeat(32))}, accountKey: "uploader", sessionKey: ${JSON.stringify(sessionKey)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "metadata.json"), reservedBytes: ${Buffer.byteLength(JSON.stringify(metadata))} });`,
      'quota.close();',
    ].join("\n"),
  });

  if (process.platform !== "win32") {
    const sessionMode = fs.statSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId)).mode & 0o777;
    assert.equal(sessionMode, 0o700, "startup keeps legacy chunk sessions private while validating an invalid ledger");
  }
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")), partBytes);
  const preservedMetadata = JSON.parse(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json"), "utf8"));
  assert.equal(preservedMetadata.uploadId, uploadId);
  assert.equal(preservedMetadata.folderId, FOLDER_ID);
  assert.equal(preservedMetadata.uploadedBy, "uploader");
  assert.equal(preservedMetadata.totalChunks, 1);
  assert.equal(preservedMetadata.encryptionLevel, "none");
  assert.equal(Object.hasOwn(preservedMetadata, "password"), false, "invalid-ledger startup still scrubs legacy plaintext upload passwords");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", staleIncomingId), "utf8"), "retain during fail-closed validation");
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-invalid-row-blocked",
    originalName: "quota-invalid-row-blocked.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not start staging"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "0.part")).toString(), partBytes.toString());
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, uploadId, "metadata.json")), true);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, "incoming", staleIncomingId)), true);
});

test("legacy quota import defers part permission changes and tombstone cleanup until every session validates", { timeout: 45_000 }, async (t) => {
  const firstUploadId = "first-valid-session";
  const expiredUploadId = "expired-session";
  const invalidUploadId = "invalid-session";
  const firstBytes = Buffer.from("preserve first legacy part");
  const expiredBytes = Buffer.from("preserve tombstone part until full scan");
  const invalidBytes = Buffer.from("preserve later invalid session part");
  const firstMetadata = legacyChunkMetadata(firstUploadId, { folderId: "a-legacy-first", totalChunks: 1, encryptionLevel: "none" });
  const expiredMetadata = { __expiredAt: new Date().toISOString() };
  const harness = await createHarness(t, {
    chunkSessions: [
      { folderId: "a-legacy-first", uploadId: firstUploadId, files: { "metadata.json": firstMetadata, "0.part": firstBytes } },
      { folderId: "b-legacy-expired", uploadId: expiredUploadId, files: { "metadata.json": expiredMetadata, "0.part": expiredBytes } },
      { folderId: "z-legacy-invalid", uploadId: invalidUploadId, files: { "metadata.json": "{invalid", "0.part": invalidBytes } },
    ],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const firstSession = path.join(${JSON.stringify(chunkRoot)}, "a-legacy-first", ${JSON.stringify(firstUploadId)});
      const expiredSession = path.join(${JSON.stringify(chunkRoot)}, "b-legacy-expired", ${JSON.stringify(expiredUploadId)});
      const chmodLog = path.join(${JSON.stringify(dir)}, "legacy-import-chmod-events.jsonl");
      const originalChmodSync = fs.chmodSync;
      fs.chmodSync = function (target, mode, ...args) {
        fs.appendFileSync(chmodLog, JSON.stringify({ target: String(target), stack: new Error().stack }) + "\\n");
        return originalChmodSync.call(this, target, mode, ...args);
      };
      if (process.platform !== "win32") {
        fs.chmodSync(path.join(firstSession, "0.part"), 0o644);
        fs.chmodSync(path.join(expiredSession, "0.part"), 0o644);
      }
    `,
  });

  const firstSession = path.join(harness.chunkRoot, "a-legacy-first", firstUploadId);
  const expiredSession = path.join(harness.chunkRoot, "b-legacy-expired", expiredUploadId);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(firstSession, "0.part")).mode & 0o777, 0o644);
    assert.equal(fs.statSync(path.join(expiredSession, "0.part")).mode & 0o777, 0o644);
  }
  assert.deepEqual(fs.readFileSync(path.join(firstSession, "0.part")), firstBytes);
  assert.deepEqual(fs.readFileSync(path.join(expiredSession, "0.part")), expiredBytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(expiredSession, "metadata.json"), "utf8")), expiredMetadata);
  const invalidSession = path.join(harness.chunkRoot, "z-legacy-invalid", invalidUploadId);
  assert.deepEqual(fs.readFileSync(path.join(invalidSession, "0.part")), invalidBytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(invalidSession, "metadata.json"), "utf8")), { __resumeBlocked: true });
  if (process.platform !== "win32") {
    const chmodLog = path.join(harness.dir, "legacy-import-chmod-events.jsonl");
    const events = fs.readFileSync(chmodLog, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
    assert.deepEqual(events.filter((event) => event.stack.includes("readLegacyChunkQuotaOperations")), [], "legacy scan must complete before it changes any session permissions");
  }

  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "legacy-import-fail-closed",
    originalName: "legacy-import-fail-closed.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("quota import must remain unavailable"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
});

test("ownerless blocked legacy metadata cannot authorize quota recovery", { timeout: 45_000 }, async (t) => {
  const uploadId = "ownerless-blocked-ledger-session";
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const partBytes = Buffer.from("preserve blocked legacy bytes");
  const blockedMetadata = {
    __resumeBlocked: true,
    uploadId,
    folderId: FOLDER_ID,
    totalChunks: 1,
    lastActivityAt: new Date().toISOString(),
  };
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": blockedMetadata, "0.part": partBytes } }],
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const root = ${JSON.stringify(chunkRoot)};
      const sessionDir = path.join(root, ${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)});
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const { ensureWindowsChunkUploadRoot } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadWindowsAcl.js"))});
      ensureWindowsChunkUploadRoot(root);
      if (process.platform !== "win32") {
        fs.chmodSync(sessionDir, 0o755);
        fs.chmodSync(path.join(sessionDir, "metadata.json"), 0o644);
        fs.chmodSync(path.join(sessionDir, "0.part"), 0o644);
      }
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "stale-owner", processId: 2147483647 });
      quota.initialize([{ operationId: "blocked-part", accountKey: "different-account", sessionKey: ${JSON.stringify(sessionKey)}, relativePath: path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"), state: "part_committed", chargeBytes: ${partBytes.length} }]);
      quota.close();
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(path.join(sessionDir, "0.part")).mode & 0o777, 0o644);
  }
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), partBytes);
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(sessionDir, "metadata.json"), "utf8")), blockedMetadata);
  const session = await login(harness.port, "uploader", harness.password);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "ownerless-blocked-ledger-probe",
    originalName: "ownerless-blocked-ledger-probe.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must remain blocked"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), partBytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT operation_id, account_key, state FROM quota_operations").all(), [
      { operation_id: "blocked-part", account_key: "different-account", state: "part_committed" },
    ]);
  } finally {
    database.close();
  }
});

test("handoff recovery preserves session data when quota ownership disagrees with metadata", { timeout: 45_000 }, async (t) => {
  const uploadId = "handoff-owner-mismatch";
  const fileName = "handoff-owner-mismatch.txt";
  const bytes = Buffer.from("accepted disposable source part");
  const sessionKey = `${FOLDER_ID}/${uploadId}`;
  const metadata = legacyChunkMetadata(uploadId, { totalChunks: 1, encryptionLevel: "none", originalName: fileName, fileName });
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId, files: { "metadata.json": metadata, "0.part": bytes } }],
    preloadSource: ({ dir, chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const { createChunkUploadQuota } = require(${JSON.stringify(path.join(ROOT, "services", "chunkUploadQuota.js"))});
      const root = ${JSON.stringify(chunkRoot)};
      const session = ${JSON.stringify(sessionKey)};
      const folderTemp = path.join(${JSON.stringify(dir)}, "temp", ${JSON.stringify(FOLDER_ID)});
      fs.mkdirSync(path.join(root, "incoming"), { recursive: true });
      fs.mkdirSync(folderTemp, { recursive: true });
      fs.writeFileSync(path.join(folderTemp, ${JSON.stringify(fileName)}), ${JSON.stringify(bytes.toString())});
      fs.writeFileSync(path.join(${JSON.stringify(dir)}, "data", "pending-uploads.json"), JSON.stringify({
        ${JSON.stringify(`${FOLDER_ID}/${fileName}`)}: { folderId: ${JSON.stringify(FOLDER_ID)}, uploadedBy: "uploader" },
      }));
      const quota = createChunkUploadQuota({ rootDir: root, perAccountBytes: 64 * 1024 * 1024, systemBytes: 128 * 1024 * 1024, perAccountEntries: 5000, systemEntries: 10000, processInstanceId: "dead-owner", processId: 2147483647 });
      quota.initialize([
        { operationId: "a-part", accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: path.join(session, "0.part"), state: "part_committed", chargeBytes: ${bytes.length} },
        { operationId: "z-handoff", accountKey: "different-account", sessionKey: session.replace(path.sep, "/"), relativePath: ${JSON.stringify(`handoff/${FOLDER_ID}/${encodeURIComponent(fileName)}#${bytes.length}`)}, state: "handoff_pending", chargeBytes: ${bytes.length} },
      ]);
      quota.close();
    `,
  });

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  assert.equal(fs.existsSync(path.join(sessionDir, "metadata.json")), true);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
  const blocked = await uploadChunk(harness.port, session, {
    uploadId: "quota-owner-mismatch-blocked",
    originalName: "quota-owner-mismatch-blocked.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not start staging"),
  });
  assert.equal(blocked.status, 503, blocked.body);
  assert.equal(JSON.parse(blocked.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), bytes);
  assert.equal(fs.existsSync(path.join(sessionDir, "metadata.json")), true);
  assert.deepEqual(fs.readFileSync(path.join(harness.dir, "temp", FOLDER_ID, fileName)), bytes);
});

test("an untracked incoming file is preserved and disables only chunk uploads at startup", { timeout: 30_000 }, async (t) => {
  const untrackedBytes = "preserve until operator reconciliation";
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => [
      'const fs = require("node:fs");',
      'const path = require("node:path");',
      'fs.mkdirSync(path.join(' + JSON.stringify(chunkRoot) + ', "incoming"), { recursive: true });',
      'fs.writeFileSync(path.join(' + JSON.stringify(chunkRoot) + ', "incoming", "untracked-file"), ' + JSON.stringify(untrackedBytes) + ');',
    ].join("\n"),
  });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-untracked-incoming",
    originalName: "quota-untracked-incoming.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, "incoming", "untracked-file"), "utf8"), untrackedBytes);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), ["untracked-file"]);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
});

test("chunk quota exhaustion rejects before creating a Multer incoming file", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: "1",
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: "1",
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "quota-capacity-exhausted",
    originalName: "quota-capacity-exhausted.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("small disposable chunk"),
  });
  assert.equal(response.status, 507, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
  } finally {
    quotaDatabase.close();
  }
});

test("chunk uploads fail closed before Multer when local single-host topology is unverified", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "",
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "unverified-chunk-topology",
    originalName: "unverified-chunk-topology.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("must not be staged"),
  });
  assert.equal(response.status, 503, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_UNAVAILABLE");
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), [], "the disabled endpoint creates no incoming staged file");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, ".quota.sqlite")), false);
  assert.equal((await request(harness.port, "/login.html")).status, 200);
});

test("chunk completion reserves assembly capacity before committing the final part", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(8 * 1024 * 1024),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(8 * 1024 * 1024),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "assembly-quota-capacity",
    originalName: "assembly-quota-capacity.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.alloc(5 * 1024 * 1024, 0x61),
  });
  assert.equal(response.status, 507, response.body);
  assert.equal(JSON.parse(response.body).code, "CHUNK_QUOTA_EXCEEDED");
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "assembly-quota-capacity", "0.part")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("verified incoming reservations shrink before exact-capacity final assembly", { timeout: 45_000 }, async (t) => {
  const cap = 8 * 1024 * 1024;
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(cap),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(cap),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const response = await uploadChunk(harness.port, session, {
    uploadId: "assembly-quota-exact-capacity",
    originalName: "assembly-quota-exact-capacity.txt",
    chunkIndex: 0,
    totalChunks: 1,
    encryptionLevel: "none",
    bytes: Buffer.alloc(4 * 1024 * 1024, 0x61),
  });
  assert.equal(response.status, 200, response.body);
  assert.equal(JSON.parse(response.body).complete, true);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const quotaDatabase = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(quotaDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
    assert.equal(quotaDatabase.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'").get().value, "0");
  } finally {
    quotaDatabase.close();
  }
});

test("maximum-size parts reserve and release the full bounded assembly charge", { timeout: 120_000 }, async (t) => {
  const partBytes = 8 * 1024 * 1024;
  const partCount = 3;
  const assemblyBytes = partBytes * partCount;
  const peakBytes = assemblyBytes * 2;
  const originalName = "bounded-maximum-assembly.txt";
  const part = Buffer.alloc(partBytes, 0x61);

  const deniedHarness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(peakBytes - 1),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(peakBytes - 1),
  } });
  const deniedSession = await login(deniedHarness.port, "uploader", deniedHarness.password);
  for (let chunkIndex = 0; chunkIndex < partCount - 1; chunkIndex += 1) {
    const response = await uploadChunk(deniedHarness.port, deniedSession, {
      uploadId: "bounded-assembly-under-cap",
      originalName,
      chunkIndex,
      totalChunks: partCount,
      bytes: part,
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, false);
  }

  const rejectedFinalPart = await uploadChunk(deniedHarness.port, deniedSession, {
    uploadId: "bounded-assembly-under-cap",
    originalName,
    chunkIndex: partCount - 1,
    totalChunks: partCount,
    bytes: part,
  });
  assert.equal(rejectedFinalPart.status, 507, rejectedFinalPart.body);
  assert.equal(JSON.parse(rejectedFinalPart.body).code, "CHUNK_QUOTA_EXCEEDED");
  const deniedSessionDir = path.join(deniedHarness.chunkRoot, FOLDER_ID, "bounded-assembly-under-cap");
  assert.deepEqual(fs.readFileSync(path.join(deniedSessionDir, "0.part")), part);
  assert.deepEqual(fs.readFileSync(path.join(deniedSessionDir, "1.part")), part);
  assert.equal(fs.existsSync(path.join(deniedSessionDir, "2.part")), false);
  assert.deepEqual(fs.readdirSync(path.join(deniedHarness.chunkRoot, "incoming")), []);
  const deniedDatabase = new Database(path.join(deniedHarness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(deniedDatabase.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'").get().value, String(partBytes * 2));
    assert.equal(deniedDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 2);
  } finally {
    deniedDatabase.close();
  }

  const exactHarness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(peakBytes),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(peakBytes),
  } });
  const exactSession = await login(exactHarness.port, "uploader", exactHarness.password);
  for (let chunkIndex = 0; chunkIndex < partCount; chunkIndex += 1) {
    const response = await uploadChunk(exactHarness.port, exactSession, {
      uploadId: "bounded-assembly-exact-cap",
      originalName,
      chunkIndex,
      totalChunks: partCount,
      bytes: part,
    });
    assert.equal(response.status, 200, response.body);
    assert.equal(JSON.parse(response.body).complete, chunkIndex === partCount - 1);
  }
  assert.deepEqual(fs.readdirSync(path.join(exactHarness.chunkRoot, "incoming")), []);
  assert.equal(fs.existsSync(path.join(exactHarness.chunkRoot, FOLDER_ID, "bounded-assembly-exact-cap", "assembled.upload")), false);
  const exactDatabase = new Database(path.join(exactHarness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(exactDatabase.prepare("SELECT COUNT(*) AS count FROM quota_operations").get().count, 0);
    assert.equal(exactDatabase.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'").get().value, "0");
  } finally {
    exactDatabase.close();
  }
});

test("an incoming reservation that exceeds the quota preserves the previously accepted part", { timeout: 45_000 }, async (t) => {
  const cap = 8 * 1024 * 1024;
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(cap),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(cap),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const original = Buffer.alloc(8 * 1024 * 1024, 0x4f);
  const first = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-preserve",
    originalName: "replacement-quota-preserve.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: original,
  });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-preserve",
    originalName: "replacement-quota-preserve.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("replacement"),
  });
  assert.equal(replacement.status, 507, replacement.body);
  assert.deepEqual(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, "replacement-quota-preserve", "0.part")), original);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
});

test("a replacement is promoted with the previous part kept charged until it is removed", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t, { envOverrides: {
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(32 * 1024 * 1024),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(32 * 1024 * 1024),
  } });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-success",
    originalName: "replacement-quota-success.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("original part"),
  });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, {
    uploadId: "replacement-quota-success",
    originalName: "replacement-quota-success.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("replacement part"),
  });
  assert.equal(replacement.status, 200, replacement.body);
  assert.equal(fs.readFileSync(path.join(harness.chunkRoot, FOLDER_ID, "replacement-quota-success", "0.part"), "utf8"), "replacement part");
  assert.equal(fs.readdirSync(path.join(harness.chunkRoot, FOLDER_ID, "replacement-quota-success")).some((name) => name.startsWith(".replacement-")), false);
});

test("a failed replacement rename restores the prior accepted part and its ledger charge", { timeout: 30_000 }, async (t) => {
  const uploadId = "replacement-rename-rollback";
  const original = Buffer.from("accepted source part");
  const harness = await createHarness(t, {
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const renameSync = fs.renameSync;
      let incomingPromotions = 0;
      fs.renameSync = function (source, destination, ...args) {
        if (String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part")) && ++incomingPromotions === 2) {
          throw Object.assign(new Error("injected promotion rename failure"), { code: "EIO" });
        }
        return renameSync.call(this, source, destination, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: original });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: Buffer.from("replacement data") });
  assert.equal(replacement.status, 500, replacement.body);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
  assert.equal(fs.readdirSync(sessionDir).some((name) => name.startsWith(".replacement-")), false);
  assert.deepEqual(fs.readdirSync(path.join(harness.chunkRoot, "incoming")), []);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(database.prepare("SELECT relative_path, state, charge_bytes FROM quota_operations ORDER BY relative_path").all(), [
      { relative_path: path.join(FOLDER_ID, uploadId, "0.part"), state: "part_committed", charge_bytes: original.length },
    ]);
  } finally {
    database.close();
  }
});

async function prepareFailedReplacement(t, uploadId) {
  const original = Buffer.from("accepted part before failed replacement");
  const replacementBytes = Buffer.from("replacement remains charged for recovery");
  const harness = await createHarness(t, {
    deterministicQuotaRecovery: true,
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const renameSync = fs.renameSync;
      let incomingPromotions = 0;
      fs.renameSync = function (source, destination, ...args) {
        const isPartTarget = String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"));
        if (isPartTarget && String(source).includes(path.join(".chunks", "incoming")) && ++incomingPromotions === 2) {
          throw Object.assign(new Error("injected replacement promotion failure"), { code: "EIO" });
        }
        if (isPartTarget && path.basename(String(source)).startsWith(".replacement-")) {
          throw Object.assign(new Error("injected prior-part rollback failure"), { code: "EIO" });
        }
        return renameSync.call(this, source, destination, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  assert.equal((await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: original })).status, 200);
  assert.equal((await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: replacementBytes })).status, 500);
  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  let operations;
  try { operations = rows.prepare("SELECT operation_id, relative_path FROM quota_operations ORDER BY relative_path").all(); }
  finally { rows.close(); }
  const backupOperation = operations.find((row) => row.relative_path.includes(".replacement-"));
  return {
    harness,
    original,
    replacementBytes,
    sessionDir,
    backupOperationId: backupOperation.operation_id,
    backupFileName: path.basename(backupOperation.relative_path),
  };
}

test("restart reconciles a replacement when restoring its prior part fails", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-rollback-recovery";
  const original = Buffer.from("accepted part before failed replacement");
  const replacementBytes = Buffer.from("replacement remains charged for recovery");
  const harness = await createHarness(t, {
    deterministicQuotaRecovery: true,
    preloadSource: ({ chunkRoot }) => `
      const fs = require("node:fs");
      const path = require("node:path");
      const renameSync = fs.renameSync;
      let incomingPromotions = 0;
      fs.renameSync = function (source, destination, ...args) {
        const isPartTarget = String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"));
        if (isPartTarget && String(source).includes(path.join(".chunks", "incoming")) && ++incomingPromotions === 2) {
          throw Object.assign(new Error("injected replacement promotion failure"), { code: "EIO" });
        }
        if (isPartTarget && path.basename(String(source)).startsWith(".replacement-")) {
          throw Object.assign(new Error("injected prior-part rollback failure"), { code: "EIO" });
        }
        return renameSync.call(this, source, destination, ...args);
      };
    `,
  });
  const session = await login(harness.port, "uploader", harness.password);
  const first = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: original });
  assert.equal(first.status, 200, first.body);
  const replacement = await uploadChunk(harness.port, session, { uploadId, originalName: `${uploadId}.txt`, chunkIndex: 0, totalChunks: 2, bytes: replacementBytes });
  assert.equal(replacement.status, 500, replacement.body);

  const sessionDir = path.join(harness.chunkRoot, FOLDER_ID, uploadId);
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const backupName = fs.readdirSync(sessionDir).find((name) => name.startsWith(".replacement-"));
  assert.ok(backupName, "failed rollback retains the charged prior-part backup for recovery");
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, backupName)), original);
  const incomingName = fs.readdirSync(incomingDir)[0];
  assert.ok(incomingName, "failed replacement remains in its charged incoming path");
  assert.deepEqual(fs.readFileSync(path.join(incomingDir, incomingName)), replacementBytes);
  const database = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.equal(database.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'promoting'").get().count, 2);
  } finally {
    database.close();
  }

  harness.child.kill();
  await waitForExit(harness.child);
  const recoveryPort = await getUnusedPort();
  const recoveryPreloadPath = path.join(harness.dir, "replacement-recovery-preload.js");
  fs.writeFileSync(recoveryPreloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const renameSync = fs.renameSync;
    const unlinkSync = fs.unlinkSync;
    let failedPromotion = false;
    let failedAfterIncomingUnlink = false;
    fs.renameSync = function (source, destination, ...args) {
      if (!failedPromotion && String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedPromotion = true;
        throw Object.assign(new Error("injected recovery promotion failure"), { code: "EIO" });
      }
      return renameSync.call(this, source, destination, ...args);
    };
    fs.unlinkSync = function (target, ...args) {
      const isIncoming = String(target).includes(path.join(".chunks", "incoming"));
      const result = unlinkSync.call(this, target, ...args);
      if (isIncoming && !failedAfterIncomingUnlink) {
        failedAfterIncomingUnlink = true;
        throw Object.assign(new Error("injected crash after incoming unlink"), { code: "EIO" });
      }
      return result;
    };
  `);
  const recoveryChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, "--require", recoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid), NODE_ENV: "test", PORT: String(recoveryPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const recoveryStderr = [];
  recoveryChild.stderr.on("data", (chunk) => recoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(recoveryPort)).status, 200, recoveryStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    assert.deepEqual(fs.readdirSync(incomingDir), [], "the injected boundary leaves the restored part but no replacement incoming file");
    const interrupted = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.equal(interrupted.prepare("SELECT COUNT(*) AS count FROM quota_operations WHERE state = 'promoting'").get().count, 2);
    } finally {
      interrupted.close();
    }
  } finally {
    if (recoveryChild.exitCode === null) {
      recoveryChild.kill();
      await waitForExit(recoveryChild);
    }
  }

  const finalRecoveryPort = await getUnusedPort();
  const finalRecoveryChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid, recoveryChild.pid), NODE_ENV: "test", PORT: String(finalRecoveryPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const finalRecoveryStderr = [];
  finalRecoveryChild.stderr.on("data", (chunk) => finalRecoveryStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(finalRecoveryPort)).status, 200, finalRecoveryStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original, `second restart preserves the accepted part after an interruption between filesystem and ledger recovery: ${finalRecoveryStderr.join("")}`);
    assert.deepEqual(fs.readdirSync(incomingDir), []);
    const recovered = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(recovered.prepare("SELECT state, charge_bytes, relative_path FROM quota_operations").all(), [
        { state: "part_committed", charge_bytes: original.length, relative_path: path.join(FOLDER_ID, uploadId, "0.part") },
      ]);
    } finally {
      recovered.close();
    }
  } finally {
    if (finalRecoveryChild.exitCode === null) {
      finalRecoveryChild.kill();
      await waitForExit(finalRecoveryChild);
    }
  }
});

test("restart reconciles a replacement after the restored-part ledger transition", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-transition-recovery";
  const fixture = await prepareFailedReplacement(t, uploadId);
  const { harness, original, sessionDir, backupOperationId } = fixture;
  harness.child.kill();
  await waitForExit(harness.child);
  const failedPort = await getUnusedPort();
  const preloadPath = path.join(harness.dir, "replacement-transition-preload.js");
  fs.writeFileSync(preloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const renameSync = fs.renameSync;
    let failedPromotion = false;
    fs.renameSync = function (source, destination, ...args) {
      if (!failedPromotion && String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedPromotion = true;
        throw Object.assign(new Error("injected recovery promotion failure"), { code: "EIO" });
      }
      return renameSync.call(this, source, destination, ...args);
    };
    const quotaPath = path.join(${JSON.stringify(ROOT)}, "services", "chunkUploadQuota.js");
    const quota = require(quotaPath);
    const create = quota.createChunkUploadQuota;
    quota.createChunkUploadQuota = function (...args) {
      const service = create.apply(this, args);
      const transition = service.transition.bind(service);
      let failedTransition = false;
      service.transition = function (input) {
        const result = transition(input);
        if (!failedTransition && input.operationId === ${JSON.stringify(backupOperationId)} && input.state === "part_committed") {
          failedTransition = true;
          throw Object.assign(new Error("injected crash after backup transition"), { code: "EIO" });
        }
        return result;
      };
      return service;
    };
  `);
  const failedChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, "--require", preloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid), NODE_ENV: "test", PORT: String(failedPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const failedStderr = [];
  failedChild.stderr.on("data", (chunk) => failedStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(failedPort)).status, 200, failedStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(rows.prepare("SELECT state, charge_bytes FROM quota_operations ORDER BY state").all(), [
        { state: "part_committed", charge_bytes: original.length },
        { state: "promoting", charge_bytes: fixture.replacementBytes.length },
      ]);
    } finally { rows.close(); }
  } finally {
    if (failedChild.exitCode === null) { failedChild.kill(); await waitForExit(failedChild); }
  }

  const finalPort = await getUnusedPort();
  const finalChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid, failedChild.pid), NODE_ENV: "test", PORT: String(finalPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
  });
  const finalStderr = [];
  finalChild.stderr.on("data", (chunk) => finalStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(finalPort)).status, 200, finalStderr.join(""));
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try {
      assert.deepEqual(rows.prepare("SELECT state, charge_bytes, relative_path FROM quota_operations").all(), [
        { state: "part_committed", charge_bytes: original.length, relative_path: path.join(FOLDER_ID, uploadId, "0.part") },
      ], finalStderr.join(""));
    } finally { rows.close(); }
  } finally {
    if (finalChild.exitCode === null) { finalChild.kill(); await waitForExit(finalChild); }
  }
});

test("restart reconciles a replacement after restoring the original target", { timeout: 45_000 }, async (t) => {
  const uploadId = "replacement-restore-boundary";
  const { harness, original, replacementBytes, sessionDir, backupFileName } = await prepareFailedReplacement(t, uploadId);
  harness.child.kill();
  await waitForExit(harness.child);
  const failedPort = await getUnusedPort();
  const preloadPath = path.join(harness.dir, "replacement-restore-preload.js");
  const restoreMarkerPath = path.join(harness.dir, "replacement-restore-hook-fired");
  fs.writeFileSync(preloadPath, `
    const fs = require("node:fs");
    const path = require("node:path");
    const markerPath = ${JSON.stringify(restoreMarkerPath)};
    const renameSync = fs.renameSync;
    let failedPromotion = false;
    let failedAfterRestore = false;
    fs.renameSync = function (source, destination, ...args) {
      if (!failedPromotion && String(source).includes(path.join(".chunks", "incoming")) && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedPromotion = true;
        throw Object.assign(new Error("injected recovery promotion failure"), { code: "EIO" });
      }
      const result = renameSync.call(this, source, destination, ...args);
      if (!failedAfterRestore && path.basename(String(source)) === ${JSON.stringify(backupFileName)} && String(destination).endsWith(path.join(${JSON.stringify(FOLDER_ID)}, ${JSON.stringify(uploadId)}, "0.part"))) {
        failedAfterRestore = true;
        fs.writeFileSync(markerPath, "fired");
        throw Object.assign(new Error("injected interruption after target restore"), { code: "EIO" });
      }
      return result;
    };
  `);
  const failedChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, "--require", preloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid), NODE_ENV: "test", PORT: String(failedPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  const failedStderr = [];
  failedChild.stderr.on("data", (chunk) => failedStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(failedPort)).status, 200, failedStderr.join(""));
    assert.equal(fs.existsSync(restoreMarkerPath), true, "the injected interruption must occur after the original target is restored");
  }
  finally { if (failedChild.exitCode === null) { failedChild.kill(); await waitForExit(failedChild); } }
  const incomingDir = path.join(harness.chunkRoot, "incoming");
  const incomingName = fs.readdirSync(incomingDir)[0];
  assert.ok(incomingName, "the replacement remains at its charged incoming path after the interruption");
  assert.deepEqual(fs.readFileSync(path.join(incomingDir, incomingName)), replacementBytes);
  assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
  assert.equal(fs.readdirSync(sessionDir).some((name) => name === backupFileName), false);
  const interruptedRows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
  try {
    assert.deepEqual(interruptedRows.prepare("SELECT state, charge_bytes FROM quota_operations ORDER BY charge_bytes").all(), [
      { state: "promoting", charge_bytes: original.length },
      { state: "promoting", charge_bytes: replacementBytes.length },
    ]);
  } finally { interruptedRows.close(); }
  const finalPort = await getUnusedPort();
  const finalChild = spawn(process.execPath, ["--require", harness.quotaRecoveryPreloadPath, SERVER], {
    cwd: harness.dir,
    env: { ...process.env, ...testDeadQuotaOwnerEnv(harness.child.pid, failedChild.pid), NODE_ENV: "test", PORT: String(finalPort), DB_ENABLED: "false", DB_READ_FALLBACK_JSON: "true", DB_WRITE_LEGACY_JSON: "true", ROOTARK_BOOTSTRAP_USERS_FROM_SEED: "true", CLOUD_STORAGE_PROVIDER: "local", UPLOAD_SCAN_ENABLED: "true", UPLOAD_BLOCK_EXECUTABLES: "true", UPLOAD_QUARANTINE_DIR: harness.quarantineDir, CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024), CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000", CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000", CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume", JWT_SECRET: crypto.randomBytes(48).toString("base64url") },
    stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  const finalStderr = [];
  finalChild.stderr.on("data", (chunk) => finalStderr.push(chunk.toString()));
  try {
    assert.equal((await waitForServer(finalPort)).status, 200);
    assert.deepEqual(fs.readFileSync(path.join(sessionDir, "0.part")), original);
    const rows = new Database(path.join(harness.chunkRoot, ".quota.sqlite"), { readonly: true });
    try { assert.deepEqual(rows.prepare("SELECT state, charge_bytes FROM quota_operations").all(), [{ state: "part_committed", charge_bytes: original.length }], finalStderr.join("")); }
    finally { rows.close(); }
  } finally { if (finalChild.exitCode === null) { finalChild.kill(); await waitForExit(finalChild); } }
});
