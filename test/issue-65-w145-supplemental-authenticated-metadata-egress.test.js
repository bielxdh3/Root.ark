"use strict";

// Independent real-server JWT/ACL proof of the remaining authenticated
// legacy read surface. RED baseline uses c5c09513; no mocks of handlers.
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
const SECRET = "W145_SUPPLEMENTAL_REAL_DECRYPTED_OWNER_BYTES";
const FILE = "alice-private-content.txt";
const FOLDER = "alice-private-folder";
const PENDING = "alice-pending-private.txt";
const QUARANTINE = "alice-quarantine-private.txt";
const send = (port, url, { method = "GET", headers = {}, body } = {}) => new Promise((resolve, reject) => {
  const req = http.request({ hostname: "127.0.0.1", port, path: url, method,
    headers, signal: AbortSignal.timeout(12000) }, (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("error", reject);
    res.on("end", () => resolve({ status: res.statusCode, headers: res.headers,
      body: Buffer.concat(chunks).toString("utf8") }));
  });
  req.on("error", reject);
  req.end(body);
});
const freePort = () => new Promise((resolve, reject) => {
  const probe = net.createServer();
  probe.once("error", reject);
  probe.listen(0, "127.0.0.1", () => {
    const port = probe.address().port;
    probe.close(() => resolve(port));
  });
});

async function fixture(t, strict) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w145-auth-metadata-"));
  const data = path.join(dir, "data");
  fs.mkdirSync(data);
  fs.mkdirSync(path.join(dir, "uploads"));
  fs.mkdirSync(path.join(dir, "temp"));
  fs.symlinkSync(path.join(ROOT, "public"), path.join(dir, "public"), "junction");
  const passwords = { alice: crypto.randomBytes(15).toString("hex"), bob: crypto.randomBytes(15).toString("hex") };
  fs.writeFileSync(path.join(data, "users.local.json"), JSON.stringify(
    Object.entries(passwords).map(([username, password]) => ({
      username, password: bcrypt.hashSync(password, 4),
      role: username === "alice" ? "admin" : "user", sessionVersion: 0,
      permissions: { listFiles: true, listPending: true, upload: true, createFolders: true,
        manageUsers: username === "alice", manageBackups: username === "alice",
        viewAnalytics: username === "alice", viewAudit: username === "alice" },
    }))));
  fs.writeFileSync(path.join(data, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "sistema", isRoot: true },
    { id: FOLDER, name: "Alice private folder marker", createdBy: "alice",
      users: { alice: { read: true, edit: true } }, allowedUsers: ["alice"], isRoot: false },
  ]));
  fs.writeFileSync(path.join(data, "file-permissions.json"), JSON.stringify({
    [`root/${FILE}`]: { folderId: "root", fileName: FILE, owner: "alice", public: false, users: {} },
  }));
  // Actual production-format server-key AES-256-GCM fixture, not a fake file
  // or an error response standing in for plaintext egress.
  const key = crypto.randomBytes(32);
  fs.writeFileSync(path.join(data, "server-master.key"), key.toString("hex"));
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const sealed = Buffer.concat([cipher.update(Buffer.from(SECRET)), cipher.final()]);
  const tag = cipher.getAuthTag();
  fs.writeFileSync(path.join(dir, "uploads", FILE), sealed);
  fs.writeFileSync(path.join(data, "encrypted-files.json"), JSON.stringify({
    [`root/${FILE}`]: {
      originalFilename: FILE, fileName: FILE, folderId: "root", uploadedBy: "alice",
      encryptionLevel: "server-key", algorithm: "aes-256-gcm",
      layers: [{ type: "server", iv: iv.toString("hex"), authTag: tag.toString("hex") }],
      accessControl: { owner: "alice", authorizedUsers: ["alice"], requiresPassword: false },
      metadata: { mimeType: "text/plain", isEncrypted: true, canPreview: false },
    },
  }));
  fs.writeFileSync(path.join(dir, "temp", PENDING), "private pending upload bytes");
  fs.writeFileSync(path.join(data, "pending-uploads.json"), JSON.stringify({
    [`root/${PENDING}`]: { fileName: PENDING, folderId: "root", uploadedBy: "alice" },
  }));
  fs.writeFileSync(path.join(data, "quarantine.json"), JSON.stringify({
    items: [{ id: "alice-private-q", originalFilename: QUARANTINE, uploader: "alice",
      folderId: "root", size: 41, reason: "fixture", scanResult: "test" }],
  }));

  const port = await freePort();
  const env = { ...process.env, NODE_ENV: "test", PORT: String(port),
    DB_ENABLED: "false", CLOUD_STORAGE_PROVIDER: "local",
    UPLOAD_SCAN_ENABLED: "false", WEBDAV_ENABLED: "false",
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict ? "true" : "off",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [path.join(ROOT, "server.js")], {
    cwd: dir, env, stdio: ["ignore", "pipe", "pipe"], windowsHide: true,
  });
  let startupLog = "";
  for (const stream of [child.stdout, child.stderr])
    stream.on("data", (chunk) => { startupLog = (startupLog + chunk.toString()).slice(-2000); });
  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const done = new Promise((resolve) => child.once("exit", resolve));
      child.kill();
      await done;
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  let ready = false;
  for (let i = 0; i < 240 && child.exitCode === null; i++) {
    try { ready = (await send(port, "/login.html")).status === 200; } catch {}
    if (ready) break;
    await new Promise((resolve) => setTimeout(resolve, 75));
  }
  assert.ok(ready, "real server startup failure: " + startupLog);
  const sessions = {};
  for (const [username, password] of Object.entries(passwords)) {
    const body = JSON.stringify({ username, password });
    const login = await send(port, "/auth/login", {
      method: "POST", headers: { "content-type": "application/json",
        "content-length": Buffer.byteLength(body) }, body,
    });
    assert.equal(login.status, 200, `${username} login failed: ${login.body}`);
    const cookies = login.headers["set-cookie"].map((v) => v.split(";")[0]);
    sessions[username] = { cookie: cookies.join("; "),
      csrf: cookies.find((v) => v.startsWith("rootark_csrf="))?.split("=")[1] };
    assert.ok(sessions[username].cookie.includes("rootark_session="));
  }
  return { port, sessions };
}

const scopedGet = [
  ["/folders", "folder inventory"],
  [`/folders/${FOLDER}/access`, "private folder ACL"],
  [`/file-access?name=${FILE}&folderId=root`, "private file ACL"],
  [`/encrypted/${FILE}/metadata?folderId=root`, "private encryption metadata"],
  ["/pending?folderId=root", "pending upload inventory"],
  ["/quarantine", "quarantine admin private uploader"],
  ["/trash", "trashed file inventory"],
  ["/trash/summary", "trash summary"],
  ["/backups", "backup metadata"],
  ["/backups/latest-status", "backup job status"],
  ["/analytics/recent", "analytics file activity"],
  ["/audit/logs", "audit metadata"],
  ["/audit/summary", "audit summary"],
  ["/groups", "groups membership"],
  ["/groups/unknown/key-manifest", "group key-manifest lookup"],
  ["/backups/unknown/manifest", "backup manifest lookup"],
  ["/backups/unknown/download", "backup ZIP byte egress"],
  ["/analytics/summary", "analytics summary"],
  ["/analytics/uploads-by-user", "analytics upload ownership"],
  ["/analytics/downloads-by-file", "analytics private download names"],
  ["/analytics/file-types", "analytics file type inventory"],
  ["/analytics/active-users", "analytics active user listing"],
  ["/analytics/uploads-by-month", "analytics upload date patterns"],
];
const postPlaintext = `/encrypted-download/${FILE}?folderId=root`;

test("strict cutover denies authentic JWT legacy metadata GET and HEAD including conditional and Range", {
  timeout: 90_000,
}, async (t) => {
  const { port, sessions } = await fixture(t, true);
  assert.equal((await send(port, "/folders")).status, 401, "fence must preserve unauthenticated 401");
  for (const [route, description] of scopedGet) {
    await t.test(description, async () => {
      for (const method of ["GET", "HEAD"]) {
        const response = await send(port, route, { method, headers: {
          cookie: sessions.alice.cookie, range: "bytes=0-5",
          "if-none-match": "*",
          "if-modified-since": new Date(Date.now() + 86_400_000).toUTCString(),
        } });
        assert.equal(response.status, 503,
          `strict ${method} ${route} should deny metadata before conditional response: ${response.status} ${response.body.slice(0, 120)}`);
        assert.equal(response.headers["cache-control"], "no-store");
        if (method === "GET")
          assert.equal(JSON.parse(response.body).code, "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE");
        else assert.equal(response.body, "");
      }
    });
  }
  for (const username of ["alice", "bob"]) {
    const result = await send(port, postPlaintext, { method: "POST", headers: {
      cookie: sessions[username].cookie, "content-type": "application/json",
      "content-length": "2", origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": sessions[username].csrf,
    }, body: "{}" });
    assert.equal(result.status, 503, `strict POST decrypt ${username} should fail closed: ${result.body}`);
    assert.ok(!result.body.includes(SECRET));
  }
  const auditBody = JSON.stringify({});
  const exportResult = await send(port, "/audit/export?format=csv", { method: "POST", headers: {
    cookie: sessions.alice.cookie, origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": sessions.alice.csrf, "content-type": "application/json",
    "content-length": Buffer.byteLength(auditBody),
  }, body: auditBody });
  assert.equal(exportResult.status, 503, "strict audit POST/export must not emit CSV");
  assert.equal(exportResult.headers["cache-control"], "no-store");
  assert.equal((await send(port, "/audit/export", { headers: { cookie: sessions.alice.cookie } })).status,
    405, "legacy GET audit export 405-only method refusal must not be overblocked");
  const folderBody = JSON.stringify({ name: "strict-mode-unrelated-create-folder" });
  const mutation = await send(port, "/folders", { method: "POST", headers: {
    cookie: sessions.alice.cookie, origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": sessions.alice.csrf, "content-type": "application/json",
    "content-length": Buffer.byteLength(folderBody),
  }, body: folderBody });
  assert.equal(mutation.status, 201, "POST /folders must not be intercepted by GET/HEAD egress guard: " + mutation.body);
  const wrongVerb = await send(port, "/file-access?name=" + FILE, {
    method: "PUT", headers: { cookie: sessions.alice.cookie, origin: `http://127.0.0.1:${port}`,
      "x-csrf-token": sessions.alice.csrf, "content-type": "application/json", "content-length": "2" },
    body: "{}",
  });
  assert.notEqual(wrongVerb.status, 503, "file-access PUT is not an egress response and must not be denied by this fence");
  assert.equal((await send(port, "/auth/me", { headers: { cookie: sessions.alice.cookie } })).status, 200,
    "do not block unrelated authenticated account control");
});

test("default OFF retains real private folder, ACL, encrypted metadata, pending and decrypted bytes", {
  timeout: 75_000,
}, async (t) => {
  const { port, sessions } = await fixture(t, false);
  const headers = { cookie: sessions.alice.cookie };
  const checks = [
    ["/folders", FOLDER],
    [`/folders/${FOLDER}/access`, "Alice private folder marker"],
    [`/file-access?name=${FILE}&folderId=root`, FILE],
    [`/encrypted/${FILE}/metadata?folderId=root`, "server-key"],
    ["/pending", PENDING],
    ["/quarantine", QUARANTINE],
  ];
  for (const [route, needle] of checks) {
    const response = await send(port, route, { headers });
    assert.equal(response.status, 200, `default OFF ${route}: ${response.body}`);
    assert.ok(response.body.includes(needle), `${route} should emit fixture private metadata`);
  }
  const decrypted = await send(port, postPlaintext, { method: "POST", headers: {
    ...headers, "content-type": "application/json", "content-length": "2",
    origin: `http://127.0.0.1:${port}`, "x-csrf-token": sessions.alice.csrf,
  }, body: "{}" });
  assert.equal(decrypted.status, 200, decrypted.body);
  assert.equal(decrypted.body, SECRET, "real encrypted owner bytes must decrypt in legacy OFF mode");
  const auditExport = await send(port, "/audit/export?format=json", { method: "POST", headers: {
    ...headers, origin: `http://127.0.0.1:${port}`,
    "x-csrf-token": sessions.alice.csrf, "content-type": "application/json",
    "content-length": "2",
  }, body: "{}" });
  assert.equal(auditExport.status, 200, `default OFF audit export ${auditExport.body}`);
  const bobAcl = await send(port, `/file-access?name=${FILE}&folderId=root`, {
    headers: { cookie: sessions.bob.cookie },
  });
  assert.equal(bobAcl.status, 403, "cross-account Bob still denied by legacy ACL");
  const account = await send(port, "/auth/me", { headers });
  assert.equal(account.status, 200, "unrelated account management must be left reachable");
});
