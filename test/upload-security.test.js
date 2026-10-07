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

async function createHarness(t, { chunkSessions = [], preloadSource = "", waitForReady = true, uploaderPermissions = {}, envOverrides = {} } = {}) {
  const password = crypto.randomBytes(24).toString("base64url");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-upload-safety-"));
  const quarantineDir = path.join(dir, "quarantine");
  fs.mkdirSync(path.join(dir, "data"));
  fs.cpSync(PUBLIC, path.join(dir, "public"), { recursive: true });
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "uploader", password: bcrypt.hashSync(password, 10), role: "user", permissions: { upload: true, listFiles: true, ...uploaderPermissions }, sessionVersion: 0 },
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: {}, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dir, "data", "folders.json"), JSON.stringify([
    { id: "root", name: "Arquivos atuais", createdBy: "sistema", allowedUsers: [], isRoot: true },
    { id: FOLDER_ID, name: "Upload safety", createdBy: "uploader", allowedUsers: [] },
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
      PORT: String(port),
      DB_ENABLED: "false",
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
    let markStarted;
    let release;
    const gate = {
      started: new Promise((resolve) => { markStarted = resolve; }),
      release: () => release(),
    };
    gate.releasePromise = new Promise((resolve) => { release = resolve; });
    scans.push(gate);
    socket.once("data", () => markStarted());
    gate.releasePromise.then(() => socket.end("stream: OK\0"));
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
    versionComment: "",
    encryptionLevel: "password",
    expiresInDays: "",
    createdAt: new Date().toISOString(),
    password: "legacy-secret-that-must-be-removed",
    ...overrides,
  };
}

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

test("users without upload permission are rejected before Multer creates artifacts", { timeout: 30_000 }, async (t) => {
  const harness = await createHarness(t);
  const session = await login(harness.port, "viewer", harness.password);
  const response = await upload(harness.port, session, "denied.txt", Buffer.from("denied"));

  assert.equal(response.status, 403);
  assert.deepEqual(JSON.parse(response.body), { error: "Permissao negada: upload" });
  assertRejectedClean(harness, response, 403);
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
  const harness = await createHarness(t, {
    chunkSessions: [{ uploadId: legacyId, files: { "metadata.json": legacyChunkMetadata(legacyId), "0.part": firstPart } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const legacyDir = path.join(harness.chunkRoot, FOLDER_ID, legacyId);
  const legacyMetadataPath = path.join(legacyDir, "metadata.json");
  const scrubbedLegacyMetadata = JSON.parse(fs.readFileSync(legacyMetadataPath, "utf8"));
  assert.equal(Object.hasOwn(scrubbedLegacyMetadata, "password"), false);
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
      return [
        'const fs = require("node:fs");',
        'const path = require("node:path");',
        `const lockDirectory = ${JSON.stringify(lockDirectory)};`,
        `const markerPath = ${JSON.stringify(markerPath)};`,
        'const originalOpenSync = fs.openSync;',
        'fs.openSync = function (file, ...args) { try { return originalOpenSync.call(this, file, ...args); } catch (error) { if (error.code === "EEXIST" && typeof file === "string" && path.resolve(file).startsWith(path.resolve(lockDirectory) + path.sep)) fs.writeFileSync(markerPath, "waiting"); throw error; } };',
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
