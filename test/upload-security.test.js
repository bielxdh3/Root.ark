const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const UploadChunkSlidingWindowStore = require("../src/middlewares/uploadChunkSlidingWindowStore");
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

async function createHarness(t, { chunkSessions = [], preloadSource = "", waitForReady = true, extraEnv = {}, extraUsers = [] } = {}) {
  const password = crypto.randomBytes(24).toString("base64url");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-upload-safety-"));
  const quarantineDir = path.join(dir, "quarantine");
  fs.mkdirSync(path.join(dir, "data"));
  fs.cpSync(PUBLIC, path.join(dir, "public"), { recursive: true });
  fs.writeFileSync(path.join(dir, "data", "users.json"), JSON.stringify([
    { username: "uploader", password: bcrypt.hashSync(password, 10), role: "user", permissions: { upload: true, listFiles: true }, sessionVersion: 0 },
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: {}, sessionVersion: 0 },
    ...extraUsers.map(({ username, role, permissions }) => ({ username, password: bcrypt.hashSync(password, 10), role, permissions, sessionVersion: 0 })),
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
      ...extraEnv,
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

async function uploadChunk(port, session, { uploadId, originalName, chunkIndex, totalChunks, bytes, encryptionLevel, password, versionComment, expiresInDays, folderId = FOLDER_ID }) {
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
  return request(port, `/upload-chunk?folderId=${encodeURIComponent(folderId)}`, {
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

test("chunk uploads are rate limited per account before Multer writes to disk", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, {
    extraEnv: {
      UPLOAD_CHUNK_RATE_LIMIT_MAX: "3",
      UPLOAD_CHUNK_RATE_LIMIT_WINDOW_MS: "60000",
    },
    extraUsers: [{ username: "other-uploader", role: "user", permissions: { upload: true, listFiles: true } }],
  });
  const session = await login(harness.port, "uploader", harness.password);
  const firstPart = await uploadChunk(harness.port, session, {
    uploadId: "rate-limit-complete",
    originalName: "rate-limit-complete.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("first "),
  });
  assert.equal(firstPart.status, 200, firstPart.body);
  const finalPart = await uploadChunk(harness.port, session, {
    uploadId: "rate-limit-complete",
    originalName: "rate-limit-complete.txt",
    chunkIndex: 1,
    totalChunks: 2,
    bytes: Buffer.from("part"),
  });
  assert.equal(finalPart.status, 200, finalPart.body);
  assert.equal(JSON.parse(finalPart.body).complete, true);

  const otherUpload = await uploadChunk(harness.port, session, {
    uploadId: "rate-limit-other-id",
    originalName: "other.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("other"),
  });
  assert.equal(otherUpload.status, 200, otherUpload.body);

  const rejectedId = "rate-limit-rejected-id";
  const rejected = await uploadChunk(harness.port, session, {
    uploadId: rejectedId,
    originalName: "rejected.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("rejected"),
  });
  assert.equal(rejected.status, 429, rejected.body);
  assert.match(rejected.headers["retry-after"] || "", /^\d+$/);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, rejectedId)), false);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);

  const otherUploader = await login(harness.port, "other-uploader", harness.password);
  const otherAccountUpload = await uploadChunk(harness.port, otherUploader, {
    uploadId: "rate-limit-other-account",
    originalName: "other-account.txt",
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from("other account"),
    folderId: "root",
  });
  assert.equal(otherAccountUpload.status, 200, otherAccountUpload.body);

  const viewer = await login(harness.port, "viewer", harness.password);
  const deniedId = "rate-limit-no-permission";
  const denied = await uploadChunk(harness.port, viewer, {
    uploadId: deniedId,
    originalName: "denied.txt",
    chunkIndex: 0,
    totalChunks: 1,
    bytes: Buffer.from("denied"),
  });
  assert.equal(denied.status, 403, denied.body);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, deniedId)), false);
  assert.deepEqual(filesUnder(path.join(harness.chunkRoot, "incoming")), []);
});

test("rejected chunk requests do not grow the rolling-window store", (t) => {
  const store = new UploadChunkSlidingWindowStore(60_000, 3);
  t.after(() => store.shutdown());

  store.increment("uploader");
  store.increment("uploader");
  store.increment("uploader");
  for (let attempt = 0; attempt < 100; attempt += 1) {
    assert.equal(store.increment("uploader").totalHits, 4);
  }

  assert.equal(store.get("uploader").totalHits, 3);
});

test("chunk upload throttling expires each account request on a rolling window", { timeout: 45_000 }, async (t) => {
  const harness = await createHarness(t, {
    extraEnv: {
      UPLOAD_CHUNK_RATE_LIMIT_MAX: "2",
      UPLOAD_CHUNK_RATE_LIMIT_WINDOW_MS: "2000",
    },
  });
  const session = await login(harness.port, "uploader", harness.password);
  const sendPart = (uploadId) => uploadChunk(harness.port, session, {
    uploadId,
    originalName: `${uploadId}.txt`,
    chunkIndex: 0,
    totalChunks: 2,
    bytes: Buffer.from(uploadId),
  });

  assert.equal((await sendPart("rolling-window-first")).status, 200);
  await new Promise((resolve) => setTimeout(resolve, 1300));
  assert.equal((await sendPart("rolling-window-second")).status, 200);
  await new Promise((resolve) => setTimeout(resolve, 800));

  const afterFirstExpired = await sendPart("rolling-window-third");
  assert.equal(afterFirstExpired.status, 200, afterFirstExpired.body);
  const overLimit = await sendPart("rolling-window-fourth");
  assert.equal(overLimit.status, 429, overLimit.body);
  assert.match(overLimit.headers["retry-after"] || "", /^\d+$/);
  assert.equal(fs.existsSync(path.join(harness.chunkRoot, FOLDER_ID, "rolling-window-fourth")), false);
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
