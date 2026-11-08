"use strict";

// Real HTTP RED/GREEN: a JWT and any caller-owned signature fields cannot
// authorize legacy plaintext ingress while the external ZK10 proof is absent.
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
const SENTINEL = "ZK10_LEGACY_INGRESS_DISPOSABLE_BYTES";

function request(port, route, method = "GET", headers = {}, body) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: route, method,
      headers, signal: AbortSignal.timeout(15000) }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.once("error", reject);
      res.once("end", () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

function multipart(parts) {
  const boundary = `----zk10-${crypto.randomBytes(12).toString("hex")}`;
  const chunks = [];
  for (const part of parts) {
    const header = part.fileName === undefined
      ? `--${boundary}\r\nContent-Disposition: form-data; name="${part.field}"\r\n\r\n`
      : `--${boundary}\r\nContent-Disposition: form-data; name="${part.field}"; filename="${part.fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n`;
    chunks.push(Buffer.from(header), Buffer.from(part.value), Buffer.from("\r\n"));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return { body: Buffer.concat(chunks), contentType: `multipart/form-data; boundary=${boundary}` };
}

async function freePort() {
  const probe = net.createServer();
  await new Promise((resolve, reject) => {
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", resolve);
  });
  const port = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));
  return port;
}

async function fixture(t, strict) {
  const base = process.platform === "win32" ? process.env.USERPROFILE : os.tmpdir();
  const dir = fs.mkdtempSync(path.join(base, "zk10-ingress-http-"));
  const data = path.join(dir, "data");
  fs.mkdirSync(data);
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const password = crypto.randomBytes(20).toString("base64url");
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify([
    { username: "alice", password: bcrypt.hashSync(password, 4), role: "user",
      permissions: { upload: true, listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(data, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "sistema", isRoot: true },
  ]));
  const port = await freePort();
  const env = { ...process.env, PORT: String(port), NODE_ENV: "test", DB_ENABLED: "false",
    DB_WRITE_LEGACY_JSON: "true", CLOUD_STORAGE_PROVIDER: "local",
    WEBDAV_ENABLED: "false", UPLOAD_SCAN_ENABLED: "false", BACKUP_ENABLED: "false",
    BACKUP_AUTO_ENABLED: "false", ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict ? "true" : "off",
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES: String(64 * 1024 * 1024),
    CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES: String(128 * 1024 * 1024),
    CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES: "5000",
    CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES: "10000",
    CHUNK_UPLOAD_STORAGE_TOPOLOGY: "single-host-local-volume",
    UPLOAD_CHUNK_IP_RATE_LIMIT_MAX: "6",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: dir, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  let diagnostic = "";
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => { diagnostic = (diagnostic + chunk.toString()).slice(-2000); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const stopped = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await stopped;
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  let ready = false;
  for (let n = 0; n < 220 && child.exitCode === null; n++) {
    try { ready = (await request(port, "/login.html")).status === 200; } catch {}
    if (ready) break;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  assert.ok(ready, "isolated server startup failed: " + diagnostic);
  const loginBody = JSON.stringify({ username: "alice", password });
  const login = await request(port, "/auth/login", "POST", {
    "content-type": "application/json", "content-length": Buffer.byteLength(loginBody),
  }, loginBody);
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((c) => c.split(";", 1)[0]);
  const csrfCookie = cookies.find((c) => c.startsWith("rootark_csrf="));
  assert.ok(csrfCookie);
  const headers = { cookie: cookies.join("; "),
    origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrfCookie.split("=", 2)[1] };
  return { dir, port, headers };
}

function storedSnapshot(dir) {
  const result = {};
  for (const area of ["uploads", "temp", "data"]) {
    const root = path.join(dir, area);
    if (!fs.existsSync(root)) continue;
    const walk = (folder) => {
      for (const name of fs.readdirSync(folder).sort()) {
        const absolute = path.join(folder, name);
        const relative = path.relative(dir, absolute).replaceAll("\\", "/");
        const before = fs.lstatSync(absolute, { bigint: true });
        if (before.isDirectory() && !before.isSymbolicLink()) {
          result[relative] = "DIR";
          walk(absolute);
          continue;
        }
        // The snapshot is a security regression assertion, not permission to
        // follow a server-created link outside the isolated test directory.
        // Hash the verified file descriptor, never re-open the checked path.
        assert.ok(before.isFile() && !before.isSymbolicLink() && before.nlink === 1n,
          `Unexpected nonregular snapshot entry: ${relative}`);
        const fd = fs.openSync(absolute,
          fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
        try {
          const opened = fs.fstatSync(fd, { bigint: true });
          assert.ok(opened.isFile() && opened.nlink === 1n
            && opened.dev === before.dev && opened.ino === before.ino,
          `Snapshot file identity changed: ${relative}`);
          result[relative] = crypto.createHash("sha256").update(fs.readFileSync(fd)).digest("hex");
          const after = fs.lstatSync(absolute, { bigint: true });
          assert.ok(after.isFile() && !after.isSymbolicLink()
            && after.dev === before.dev && after.ino === before.ino,
          `Snapshot pathname identity changed: ${relative}`);
        } finally { fs.closeSync(fd); }
      }
    };
    walk(root);
  }
  return result;
}

const forged = [
  { field: "ownerSignedOriginalSha256", value: "1".repeat(64) },
  { field: "ownerPublicKey", value: "caller-controls-this-key" },
  { field: "ownerHeadRevision", value: "99" },
  { field: "ownerSignature", value: "caller-controls-this-signature" },
];
function uploadParts(name, late = false) {
  const file = { field: "file", fileName: name, value: SENTINEL };
  return late ? [file, ...forged] : [...forged, file];
}
function chunkParts(name, late = false) {
  const fields = [
    { field: "uploadId", value: "zk10-disposable-session" },
    { field: "originalName", value: name },
    { field: "chunkIndex", value: "0" },
    { field: "totalChunks", value: "2" },
  ];
  const chunk = { field: "chunk", fileName: name, value: SENTINEL };
  return late ? [chunk, ...fields, ...forged] : [...fields, ...forged, chunk];
}
async function submit(f, method, route, parts, authenticated = true) {
  const body = multipart(parts);
  return request(f.port, route, method, {
    ...(authenticated ? f.headers : {}),
    "content-type": body.contentType, "content-length": body.body.length,
  }, body.body);
}

test("strict ZK10 rejects authenticated legacy POST, PUT and chunk multipart before any disk or cloud intent", {
  timeout: 90000,
}, async (t) => {
  const f = await fixture(t, true);
  const anonymous = await submit(f, "POST", "/upload?folderId=root", uploadParts("anonymous.txt"), false);
  assert.equal(anonymous.status, 401, "strict cannot bypass JWT authentication");
  const before = storedSnapshot(f.dir);
  const paths = [
    ["POST", "/upload?folderId=root", uploadParts("simple.txt")],
    ["PUT", "/upload?folderId=root", [...uploadParts("strict-put.txt", true),
      { field: "rootarkSyncStrictFilename", value: "true" }]],
    ["POST", "/upload?folderId=root", uploadParts("simple-late.txt", true)],
    ["POST", "/upload-chunk?folderId=root", chunkParts("chunk.txt")],
    ["POST", "/upload-chunk?folderId=root", chunkParts("chunk-late.txt", true)],
    // Express route matching is case-insensitive and accepts a trailing slash.
    // These aliases must not evade the earlier, pre-Multer strict fence.
    ["POST", "/UPLOAD?folderId=root", uploadParts("upper-simple.txt")],
    ["PUT", "/upload/?folderId=root", [...uploadParts("slash-put.txt"),
      { field: "rootarkSyncStrictFilename", value: "true" }]],
    ["POST", "/UPLOAD-CHUNK/?folderId=root", chunkParts("upper-chunk.txt")],
  ];
  for (const [method, route, parts] of paths) {
    const response = await submit(f, method, route, parts);
    assert.equal(response.status, 503, `${method} ${route}: ${response.status} ${response.body.slice(0, 150)}`);
    assert.equal(response.headers["cache-control"], "no-store");
    assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
    assert.deepEqual(storedSnapshot(f.dir), before,
      `${method} ${route} must not open incoming bytes or write pending, version or cloud records`);
  }
  let throttled = false;
  for (let attempt = 0; attempt < 6; attempt++) {
    const response = await submit(f, "POST", "/upload-chunk?folderId=root",
      chunkParts(`throttle-${attempt}.txt`));
    if (response.status === 429) { throttled = true; break; }
    assert.equal(response.status, 503, response.body);
  }
  assert.equal(throttled, true, "the existing peer limiter must still bound strict ingress before JWT work");
  assert.deepEqual(storedSnapshot(f.dir), before, "strict rate limiting cannot create chunk SQLite or upload files");
});

test("strict OFF preserves real authenticated POST, PUT and chunk uploads", {
  timeout: 90000,
}, async (t) => {
  const f = await fixture(t, false);
  for (const [method, name, parts] of [
    ["POST", "off-post.txt", [{ field: "file", fileName: "off-post.txt", value: SENTINEL }]],
    ["PUT", "off-put.txt", [{ field: "file", fileName: "off-put.txt", value: SENTINEL },
      { field: "rootarkSyncStrictFilename", value: "true" }]],
  ]) {
    const response = await submit(f, method, "/upload?folderId=root", parts);
    assert.equal(response.status, 200, `${method} ${name}: ${response.status} ${response.body}`);
    assert.equal(JSON.parse(response.body).fileName, name);
    const staged = [path.join(f.dir, "temp", name), path.join(f.dir, "temp", "root", name)]
      .find((candidate) => fs.existsSync(candidate));
    assert.ok(staged, "ordinary pending upload remains materialized");
    assert.equal(fs.readFileSync(staged, "utf8"), SENTINEL);
  }
  const chunk = await submit(f, "POST", "/upload-chunk?folderId=root", chunkParts("off-chunk.txt"));
  assert.equal(chunk.status, 200, `chunk OFF: ${chunk.status} ${chunk.body}`);
  assert.equal(JSON.parse(chunk.body).complete, false);
});
