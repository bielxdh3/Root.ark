const assert = require("node:assert/strict");
const bcrypt = require("bcryptjs");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const vm = require("node:vm");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const FILE_NAME = "permission-fixture.txt";
const FILE_CONTENT = "disposable share permission fixture\n";
const PNG_NAME = "permission-fixture.png";
const PNG_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLytQAAAABJRU5ErkJggg==";
const DENIED = "Operacao nao permitida por este link.";
const ALL_OPERATIONS = ["view", "preview", "download"];

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

function request(port, requestPath, { method = "GET", headers = {}, body = "", signal } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, method, headers, signal }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => {
        const bodyBytes = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, body: bodyBytes.toString(), bodyBytes });
      });
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function startFixture(t, mode, extraEnv = {}, options = {}) {
  const sandbox = createPrivateAuthorityFixture(`rootark-share-permissions-${mode}-`);
  const dataDir = path.join(sandbox, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(sandbox, "uploads"), { recursive: true });
  fs.cpSync(path.join(ROOT, "public"), path.join(sandbox, "public"), { recursive: true });
  fs.writeFileSync(path.join(sandbox, "uploads", FILE_NAME), FILE_CONTENT);
  fs.writeFileSync(path.join(sandbox, "uploads", PNG_NAME), Buffer.from(PNG_BASE64, "base64"));

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 4),
      role: options.caseDistinctAccounts ? "user" : "admin",
      permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "other", password: bcrypt.hashSync(password, 4), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "tester", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    [`root/${FILE_NAME}`]: { public: true, owner: "tester", users: {} },
    [`root/${PNG_NAME}`]: { public: true, owner: "tester", users: {} },
  }));

  // A legacy link created before the permissions capability existed: no permissions field at all.
  const legacyToken = crypto.randomBytes(24).toString("hex");
  const now = Date.now();
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [legacyToken]: {
      folderId: "root",
      fileName: FILE_NAME,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60 * 60 * 1000).toISOString(),
      createdBy: "tester",
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 0,
      activeViewers: {},
    },
  }));

  const dbEnv = mode === "sqlite"
    ? {
      DB_ENABLED: "true",
      DATABASE_URL: path.join(dataDir, "rootark.sqlite"),
      DB_READ_FALLBACK_JSON: "true",
      DB_WRITE_LEGACY_JSON: "false",
      DB_AUTO_BACKUP_ON_START: "false",
    }
    : { DB_ENABLED: "false" };
  const pauseMarker = path.join(sandbox, "share-exchange-read-complete.marker");
  const pauseRelease = path.join(sandbox, "share-exchange-read-release.marker");
  const env = { ...process.env, ...dbEnv, ...extraEnv,
    ...(extraEnv.ROOTARK_TEST_SHARE_PAUSE_POINT === "exchange-commit"
      ? { ROOTARK_TEST_SHARE_PAUSE_MARKER: pauseMarker,
        ROOTARK_TEST_SHARE_PAUSE_RELEASE: pauseRelease } : {}),
    NODE_ENV: "test", UPLOAD_SCAN_ENABLED: "true", UPLOAD_SCAN_PROVIDER: "disabled",
    CLOUD_STORAGE_PROVIDER: "local", ROOTARK_DEV_BOOTSTRAP_DEFAULTS: "true", JWT_SECRET: crypto.randomBytes(48).toString("base64url") };
  for (const key of Object.keys(env)) if (/^(AWS_|GOOGLE_DRIVE_)/.test(key)) delete env[key];
  delete env.TRUSTED_PROXIES;
  const port = await getUnusedPort();
  const swapAfterOpen = extraEnv.ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN === "1";
  const swapFile = path.join(sandbox, "uploads", FILE_NAME);
  const foreignFdPath = `${swapFile}.foreign-descriptor`;
  if (swapAfterOpen && extraEnv.ROOTARK_TEST_SHARE_FOREIGN_FD_ONLY === "1") {
    fs.writeFileSync(foreignFdPath, "FOREIGN_DESCRIPTOR_BYTES_NOT_AUTHORIZED\n");
  }
  const child = spawn(process.execPath, [
    ...(swapAfterOpen ? ["--require", path.join(ROOT, "test", "support", "issue-68-share-after-open-swap.js")] : []),
    SERVER,
  ], {
    cwd: sandbox,
    env: {
      ...env,
      PORT: String(port),
      ...(swapAfterOpen ? {
        ROOTARK_TEST_SHARE_SWAP_FILE: swapFile,
        ROOTARK_TEST_SHARE_SWAP_SAVED_FILE: `${swapFile}.granted`,
        ROOTARK_TEST_SHARE_SWAP_MARKER: path.join(sandbox, "swap-after-open.marker"),
        ROOTARK_TEST_SHARE_FOREIGN_FD_PATH: foreignFdPath,
      } : {}),
    },
    stdio: "ignore",
    windowsHide: true,
  });

  t.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      await new Promise((resolve) => { child.once("exit", resolve); child.kill(); });
    }
    fs.rmSync(sandbox, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  // Windows process/SQLite startup can exceed 15s under concurrent test load.
  // Keep a finite platform-specific readiness budget, without weakening auth.
  const deadline = Date.now() + (process.platform === "win32" ? 35_000 : 15_000);
  let ready = null;
  let lastProbeErrorCode = null;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`disposable server exited (${child.exitCode})`);
    try {
      // Bound each localhost probe too: an accepted but stalled HTTP socket
      // must not hold readiness past its finite startup budget.
      ready = await request(port, "/login.html", { signal: AbortSignal.timeout(2_500) });
      lastProbeErrorCode = null;
      if (ready.status === 200) break;
    } catch (error) {
      // Report only a short transport code, never credentials or env values.
      lastProbeErrorCode = typeof error?.code === "string" ? error.code : "unknown";
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(ready?.status, 200,
    `disposable server must serve its public login page (last status: ${ready?.status ?? "none"}; last transport code: ${lastProbeErrorCode ?? "none"}; child exit: ${child.exitCode ?? "running"})`);

  // SQLite mode stores users in the database, so it uses the non-production bootstrap admin (NODE_ENV=test).
  const credentials = mode === "sqlite" ? { username: "admin", password: "admin123" } : { username: "tester", password };
  const body = JSON.stringify(credentials);
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const origin = `http://127.0.0.1:${port}`;

  const authed = (url, value, method = "POST") => {
    const payload = JSON.stringify(value);
    return request(port, url, {
      method,
      headers: { cookie, origin, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
      body: payload,
    });
  };
  const exchangedCapabilities = new Map();
  const exchangeCapability = async (token) => {
    if (exchangedCapabilities.has(token)) return exchangedCapabilities.get(token);
    const body = JSON.stringify({ token });
    const response = await request(port, "/share/c/exchange", {
      method: "POST",
      headers: { origin, "content-type": "application/json",
        "content-length": Buffer.byteLength(body) }, body,
    });
    assert.equal(response.status, 200, response.body);
    const { handle } = JSON.parse(response.body);
    assert.match(handle, /^[a-f0-9]{32}$/,
      "a non-bearer public handle selects the isolated HTTP cookie session");
    const cookies = (response.headers["set-cookie"] || [])
      .filter((value) => value.startsWith("rootark_cap_")).map((value) => value.split(";", 1)[0]);
    assert.equal(cookies.length, 1, "the exchange must issue exactly one opaque HttpOnly session cookie");
    assert.equal(cookies[0].includes(token), false,
      "the original bearer secret must never appear in a cookie name or value");
    assert.ok((response.headers["set-cookie"] || []).some((value) =>
      value.includes("HttpOnly") && value.includes("SameSite=Strict")),
    "the capability session is HttpOnly and Strict SameSite");
    const session = { handle, cookie: cookies.join("; ") };
    exchangedCapabilities.set(token, session);
    return session;
  };
  const publicPost = async (token, operationPath, viewerCookie = "") => {
    const capability = /^C[a-f0-9]{47}$/.test(token)
      ? await exchangeCapability(token) : null;
    const requestPath = capability
      ? `/share/${capability.handle}/${operationPath}`
      : `/share/${token}/${operationPath}`;
    if (capability) {
      assert.equal(requestPath.includes(token), false,
        "capability bearer may never appear in the HTTP request target");
    }
    return request(port, requestPath, {
      method: "POST",
      headers: { origin, ...((capability || viewerCookie)
        ? { cookie: [capability?.cookie, viewerCookie].filter(Boolean).join("; ") } : {}) },
    });
  };

  return { port, origin, authed, publicPost, exchangeCapability, legacyToken, dataDir, password, pauseMarker, pauseRelease };
}

test("P2 SQLite WebDAV Basic: case-distinct users authenticate against their exact stored account", {
  timeout: 120_000,
}, async (t) => {
  const { port, authed, dataDir } = await startFixture(t, "sqlite", {
    WEBDAV_ENABLED: "true",
    WEBDAV_PATH: "/dav",
    TOTP_POLICY: "optional",
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "off",
  });
  const lowerPassword = crypto.randomBytes(24).toString("base64url");
  const upperPassword = crypto.randomBytes(24).toString("base64url");
  assert.notEqual(lowerPassword, upperPassword);
  for (const [username, password] of [["tester", lowerPassword], ["TESTER", upperPassword]]) {
    const created = await authed("/users", {
      username, password, role: "user", permissions: { listFiles: true },
    });
    assert.equal(created.status, 201, created.body);
  }

  const Database = require("better-sqlite3");
  const db = new Database(path.join(dataDir, "rootark.sqlite"),
    { readonly: true, fileMustExist: true });
  try {
    // This is the exact ordering of usersRepository.loadUsers(), not an
    // assumption about which colliding account SQLite enumerates first.
    const users = db.prepare(`SELECT id, username, password_hash FROM users
      WHERE username IN (?, ?) AND deleted_at IS NULL ORDER BY id ASC`)
      .all("tester", "TESTER");
    assert.deepEqual(users.map((user) => user.username), ["tester", "TESTER"],
      "the lowercase account must precede the distinct uppercase account");
    assert.notEqual(users[0].password_hash, users[1].password_hash);
    assert.equal(bcrypt.compareSync(lowerPassword, users[0].password_hash), true);
    assert.equal(bcrypt.compareSync(upperPassword, users[1].password_hash), true);
    assert.equal(bcrypt.compareSync(upperPassword, users[0].password_hash), false,
      "the uppercase user's valid password must NOT verify against the first account");
  } finally { db.close(); }

  const propfind = (username, password) => request(port, "/dav", {
    method: "PROPFIND",
    headers: {
      authorization: `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`,
      depth: "0",
    },
  });
  const lower = await propfind("tester", lowerPassword);
  assert.equal(lower.status, 207, lower.body);
  assert.match(lower.body, /<D:multistatus\b/);
  const upper = await propfind("TESTER", upperPassword);
  assert.equal(upper.status, 207,
    "valid uppercase Basic credentials must reach the real WebDAV handler");
  assert.match(upper.body, /<D:multistatus\b/);
  assert.equal((await propfind("TESTER", lowerPassword)).status, 401,
    "uppercase identity must not inherit the lowercase password");
  // The reciprocal incorrect password is already proved against the exact
  // persisted bcrypt hash above. A second failed Basic attempt on this same
  // server legitimately trips the production IP rate limiter (429), so do
  // not confuse that security response with a WebDAV identity regression.
});

test("P2 SQLite WebDAV Basic: case-aliased identity cannot authenticate with another account password", {
  timeout: 120_000,
}, async (t) => {
  const { port, authed } = await startFixture(t, "sqlite", {
    WEBDAV_ENABLED: "true", WEBDAV_PATH: "/dav", TOTP_POLICY: "optional",
    ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "off",
  });
  const lowerPassword = crypto.randomBytes(24).toString("base64url");
  const upperPassword = crypto.randomBytes(24).toString("base64url");
  assert.notEqual(lowerPassword, upperPassword);
  for (const [username, password] of [["tester", lowerPassword], ["TESTER", upperPassword]]) {
    const created = await authed("/users", {
      username, password, role: "user", permissions: { listFiles: true },
    });
    assert.equal(created.status, 201, created.body);
  }
  // This is the FIRST Basic attempt in a fresh server process. Neither
  // expired/locked credentials nor a prior 401/429 can explain the result.
  // The original code resolves TESTER to the earlier 'tester' account via
  // sameUsername and incorrectly accepts that account's lower-case password.
  const forged = await request(port, "/dav", {
    method: "PROPFIND", headers: {
      authorization: `Basic ${Buffer.from(`TESTER:${lowerPassword}`, "utf8").toString("base64")}`,
      depth: "0",
    },
  });
  assert.equal(forged.status, 401,
    "case-aliased Basic username must never select a different SQLite principal's hash");
  assert.doesNotMatch(forged.body, /<D:multistatus\b/,
    "a forged Basic identity must not reach an authenticated WebDAV listing");
});

function viewerCookieFrom(response) {
  return (response.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]).join("; ");
}

test("P2 SQLite: case-distinct uploader cannot preview or enumerate another account's pending bytes", {
  timeout: 120_000,
}, async (t) => {
  const { port, origin, authed, dataDir } = await startFixture(t, "sqlite");
  const ownerPassword = crypto.randomBytes(24).toString("base64url");
  const otherPassword = crypto.randomBytes(24).toString("base64url");
  assert.notEqual(ownerPassword, otherPassword, "the accounts have separate credentials");
  for (const [username, password] of [["tester", ownerPassword], ["TESTER", otherPassword]]) {
    const created = await authed("/users", {
      username, password, role: "user", permissions: { upload: true, listPending: false },
    });
    assert.equal(created.status, 201, created.body);
  }
  const loginAs = async (username, password) => {
    const body = JSON.stringify({ username, password });
    const login = await request(port, "/auth/login", {
      method: "POST", body,
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    });
    assert.equal(login.status, 200, login.body);
    assert.equal(JSON.parse(login.body).username, username);
    assert.equal(JSON.parse(login.body).role, "user");
    const cookies = (login.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]);
    const csrf = cookies.find((value) => value.startsWith("rootark_csrf="))?.split("=", 2)[1];
    assert.ok(csrf);
    return { cookie: cookies.join("; "), csrf };
  };
  const owner = await loginAs("tester", ownerPassword);
  const impostor = await loginAs("TESTER", otherPassword);
  assert.notEqual(owner.cookie, impostor.cookie);

  // Server-created SQLite custody via real authenticated multipart upload.
  const name = `p-${crypto.randomBytes(8).toString("hex")}.png`;
  const bytes = Buffer.from(PNG_BASE64, "base64");
  const boundary = `----rootark-${crypto.randomBytes(12).toString("hex")}`;
  const multipart = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\nContent-Type: image/png\r\n\r\n`),
    bytes, Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  const upload = await request(port, "/upload?folderId=root", {
    method: "POST", body: multipart,
    headers: { origin, cookie: owner.cookie, "x-csrf-token": owner.csrf,
      "content-type": `multipart/form-data; boundary=${boundary}`,
      "content-length": multipart.length },
  });
  assert.equal(upload.status, 200, upload.body);
  // Keep the randomly unique basename below the 30-character server limit.
  // The HTTP receipt must prove no shortening/alias before SQLite lookup.
  const uploadInfo = JSON.parse(upload.body);
  assert.equal(uploadInfo.folderId, "root");
  assert.equal(uploadInfo.originalName, name);
  assert.equal(uploadInfo.fileName, name);
  assert.equal(uploadInfo.renamed, false);
  const Database = require("better-sqlite3");
  const db = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
  try {
    const users = db.prepare("SELECT username, role, permissions_json FROM users WHERE username IN (?, ?) AND deleted_at IS NULL")
      .all("tester", "TESTER");
    assert.deepEqual(users.map((u) => u.username).sort(), ["TESTER", "tester"].sort());
    for (const user of users) {
      assert.equal(user.role, "user");
      assert.equal(JSON.parse(user.permissions_json).upload, true);
      assert.equal(JSON.parse(user.permissions_json).listPending, false);
    }
    const pending = db.prepare("SELECT uploaded_by, folder_id, file_name, original_name FROM pending_uploads WHERE id = ?")
      .get(`root/${name}`);
    assert.deepEqual(pending, { uploaded_by: "tester", folder_id: "root",
      file_name: name, original_name: null },
    "real pending SQLite row must match the HTTP-returned filename and original owner");
  } finally { db.close(); }

  const url = `/preview/file/pending/${encodeURIComponent(name)}?folderId=root`;
  const ownerRead = await request(port, url, { headers: { cookie: owner.cookie, origin } });
  assert.equal(ownerRead.status, 200, ownerRead.body);
  assert.deepEqual(ownerRead.bodyBytes, bytes, "owner receives the exact original PNG bytes, without lossy UTF-8 decoding");
  const otherRead = await request(port, url, { headers: { cookie: impostor.cookie, origin } });
  // Unmodified HEAD returns 200 with owner PNG; patched code must return 403.
  assert.equal(otherRead.status, 403, "cross-principal pending preview denied");
  assert.notEqual(otherRead.body, ownerRead.body);
  const ownerList = await request(port, "/pending?folderId=root", { headers: { cookie: owner.cookie, origin } });
  const otherList = await request(port, "/pending?folderId=root", { headers: { cookie: impostor.cookie, origin } });
  assert.equal(ownerList.status, 200, ownerList.body);
  assert.equal(otherList.status, 200, otherList.body);
  assert.equal(JSON.parse(ownerList.body).some((item) => item.name === name), true);
  assert.equal(JSON.parse(otherList.body).some((item) => item.name === name), false);
});

test("P2 SQLite: case-distinct ACL reader cannot decrypt owner-only user-key file", {
  timeout: 120_000,
}, async (t) => {
  const { port, origin, authed, dataDir } = await startFixture(t, "sqlite");
  const ownerPassword = crypto.randomBytes(24).toString("base64url");
  const otherPassword = crypto.randomBytes(24).toString("base64url");
  assert.notEqual(ownerPassword, otherPassword);
  for (const [username, password, uploadAllowed] of [
    ["tester", ownerPassword, true], ["TESTER", otherPassword, false],
  ]) {
    const created = await authed("/users", {
      username, password, role: "user",
      permissions: { upload: uploadAllowed, listFiles: true, listPending: false },
    });
    assert.equal(created.status, 201, created.body);
  }
  const loginAs = async (username, password) => {
    const body = JSON.stringify({ username, password });
    const loggedIn = await request(port, "/auth/login", { method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
    assert.equal(loggedIn.status, 200, loggedIn.body);
    assert.equal(JSON.parse(loggedIn.body).username, username);
    assert.equal(JSON.parse(loggedIn.body).role, "user");
    const cookies = (loggedIn.headers["set-cookie"] || []).map((value) => value.split(";", 1)[0]);
    const csrf = cookies.find((value) => value.startsWith("rootark_csrf="))?.split("=", 2)[1];
    assert.ok(csrf);
    return { cookie: cookies.join("; "), csrf };
  };
  const owner = await loginAs("tester", ownerPassword);
  const other = await loginAs("TESTER", otherPassword);
  assert.notEqual(owner.cookie, other.cookie);

  // Real upload encrypts plaintext with a user-key derived from the exact
  // "tester" owner. The server, not this fixture, creates encrypted metadata.
  const name = `k-${crypto.randomBytes(8).toString("hex")}.txt`;
  const plaintext = `owner-only decrypted secret ${crypto.randomUUID()}`;
  const boundary = `----rootark-${crypto.randomBytes(12).toString("hex")}`;
  const multipart = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="encryptionLevel"\r\n\r\nuser-key\r\n`),
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\nContent-Type: text/plain\r\n\r\n`),
    Buffer.from(plaintext), Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  const upload = await request(port, "/upload?folderId=root", { method: "POST",
    headers: { origin, cookie: owner.cookie, "x-csrf-token": owner.csrf,
      "content-type": `multipart/form-data; boundary=${boundary}`,
      "content-length": multipart.length }, body: multipart });
  assert.equal(upload.status, 200, upload.body);
  const uploadInfo = JSON.parse(upload.body);
  assert.equal(uploadInfo.folderId, "root");
  assert.equal(uploadInfo.originalName, name);
  assert.equal(uploadInfo.fileName, name);
  assert.equal(uploadInfo.renamed, false);
  assert.equal(uploadInfo.encryptionLevel, "user-key");
  assert.equal(uploadInfo.encrypted, true);
  const pendingDb = new (require("better-sqlite3"))(path.join(dataDir, "rootark.sqlite"),
    { readonly: true, fileMustExist: true });
  try {
    const pending = pendingDb.prepare(`SELECT id, file_name, original_name, folder_id, uploaded_by
      FROM pending_uploads WHERE folder_id = ? AND file_name = ?`).get("root", name);
    assert.deepEqual(pending, { id: `root/${name}`, file_name: name,
      original_name: null, folder_id: "root", uploaded_by: "tester" },
    "owner's genuine encrypted upload must be pending before authenticated approval");
  } finally { pendingDb.close(); }
  const approved = await authed(`/approve/${encodeURIComponent(name)}?folderId=root`, {}, "POST");
  assert.equal(approved.status, 200, approved.body);

  // File ACL read access is deliberately valid for TESTER; encrypted metadata
  // remains a SECOND, owner-only authorization boundary.
  const acl = { name, folderId: "root", public: false,
    users: { TESTER: { read: true, edit: false } } };
  const savedAcl = await authed("/file-access", acl, "PUT");
  assert.equal(savedAcl.status, 200, savedAcl.body);
  assert.equal(JSON.parse(savedAcl.body).owner, "tester");
  const Database = require("better-sqlite3");
  const db = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
  try {
    const users = db.prepare("SELECT username, role, permissions_json FROM users WHERE username IN (?, ?) AND deleted_at IS NULL")
      .all("tester", "TESTER");
    assert.deepEqual(users.map((u) => u.username).sort(), ["TESTER", "tester"].sort());
    assert.ok(users.every((u) => u.role === "user"));
    const encrypted = db.prepare("SELECT encryption_level, metadata_json FROM encrypted_files WHERE folder_id = ? AND file_name = ?")
      .get("root", name);
    assert.equal(encrypted?.encryption_level, "user-key", "real encryption metadata persisted to SQLite");
    const authorized = JSON.parse(encrypted.metadata_json).accessControl;
    assert.equal(authorized.owner, "tester");
    assert.deepEqual(authorized.authorizedUsers, ["tester"],
      "TESTER is a legitimate file ACL reader, not an authorized decryptor");
    const fileAccess = db.prepare("SELECT allowed_users_json FROM file_permissions WHERE folder_id = ? AND file_name = ?")
      .get("root", name);
    const persistedAcl = JSON.parse(fileAccess.allowed_users_json);
    assert.equal(persistedAcl.owner, "tester");
    assert.equal(persistedAcl.public, false);
    assert.equal(persistedAcl.users.TESTER.read, true);
  } finally { db.close(); }

  const metadataUrl = `/encrypted/${encodeURIComponent(name)}/metadata?folderId=root`;
  const plaintextUrl = `/encrypted-download/${encodeURIComponent(name)}?folderId=root`;
  const postDecrypt = (session) => {
    const body = "{}";
    return request(port, plaintextUrl, { method: "POST", body, headers: {
      cookie: session.cookie, origin, "x-csrf-token": session.csrf,
      "content-type": "application/json", "content-length": Buffer.byteLength(body),
    } });
  };
  const ownerMetadata = await request(port, metadataUrl, { headers: { cookie: owner.cookie, origin } });
  assert.equal(ownerMetadata.status, 200, ownerMetadata.body);
  assert.equal(JSON.parse(ownerMetadata.body).encryptionLevel, "user-key");
  const ownerDecrypt = await postDecrypt(owner);
  assert.equal(ownerDecrypt.status, 200, ownerDecrypt.body);
  assert.equal(ownerDecrypt.body, plaintext, "exact owner genuinely decrypts original AES-GCM bytes");
  const aclControl = await request(port, `/files/${encodeURIComponent(name)}?folderId=root`,
    { headers: { cookie: other.cookie, origin } });
  assert.equal(aclControl.status, 403);
  assert.match(aclControl.body, /Use a rota de download criptografado/,
    "TESTER must pass the independent file-level ACL before the encrypted-only route veto");
  const otherMetadata = await request(port, metadataUrl, { headers: { cookie: other.cookie, origin } });
  assert.equal(otherMetadata.status, 403,
    "valid read ACL cannot bypass case-sensitive owner-only encryption authorization");
  const otherDecrypt = await postDecrypt(other);
  // RED production would return HTTP 200 + owner plaintext: server derives the
  // decryption key from signed-off metadata.owner, not the requesting user.
  assert.equal(otherDecrypt.status, 403, "case-colliding account must not decrypt owner user-key file");
  assert.equal(otherDecrypt.body.includes(plaintext), false);
});

test("P2 SQLite: distinct non-admin tester and TESTER cannot cross-read or edit a private file", { timeout: 60_000 }, async (t) => {
  const { port, origin, authed, password, dataDir } = await startFixture(t, "sqlite", {},
    { caseDistinctAccounts: true });
  const otherPassword = crypto.randomBytes(24).toString("base64url");
  assert.notEqual(password, otherPassword, "two SQLite case-distinct accounts must have separate passwords");
  // The JSON-to-SQLite bootstrap may already import tester; either way the
  // actual account must authenticate as a non-admin and the case-distinct
  // TESTER must be a separately created, non-admin SQLite principal.
  const ownerCreate = await authed("/users", {
    username: "tester", password, role: "user", permissions: { listFiles: true },
  });
  assert.ok([201, 409].includes(ownerCreate.status), ownerCreate.body);
  const otherCreate = await authed("/users", {
    username: "TESTER", password: otherPassword, role: "user", permissions: { listFiles: true },
  });
  assert.equal(otherCreate.status, 201, otherCreate.body);

  const loginAs = async (username, credential) => {
    const body = JSON.stringify({ username, password: credential });
    const login = await request(port, "/auth/login", { method: "POST",
      headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
    assert.equal(login.status, 200, login.body);
    assert.equal(JSON.parse(login.body).username, username,
      "login must bind the exact case-sensitive SQLite account");
    assert.equal(JSON.parse(login.body).role, "user", "neither principal may be administrator");
    const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
    const cookie = cookies.join("; ");
    const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
    const get = (url) => request(port, url, { headers: { origin, cookie } });
    const put = (url, payload) => {
      const body = JSON.stringify(payload);
      return request(port, url, { method: "PUT", headers: {
        origin, cookie, "x-csrf-token": csrf,
        "content-type": "application/json", "content-length": Buffer.byteLength(body),
      }, body });
    };
    return { cookie, get, put };
  };
  const owner = await loginAs("tester", password);
  const impostor = await loginAs("TESTER", otherPassword);
  assert.notEqual(owner.cookie, impostor.cookie, "two independent authenticated sessions are required");

  // Change ACL through the actual authenticated mutation endpoint and verify
  // SQLite persistence: no mocked `public:false` response or synthetic guard.
  const acl = { name: FILE_NAME, folderId: "root", public: false, users: {} };
  const restrict = await authed("/file-access", acl, "PUT");
  assert.equal(restrict.status, 200, restrict.body);
  assert.equal(JSON.parse(restrict.body).owner, "tester");
  assert.equal(JSON.parse(restrict.body).public, false);
  const Database = require("better-sqlite3");
  const database = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
  try {
    const accounts = database.prepare("SELECT username, role FROM users WHERE username IN (?, ?) AND deleted_at IS NULL")
      .all("tester", "TESTER");
    assert.deepEqual(accounts.map(({ username, role }) => [username, role]).sort(),
      [["TESTER", "user"], ["tester", "user"]].sort(),
      "SQLite must store distinct non-admin accounts differing only by case");
    const saved = database.prepare("SELECT allowed_users_json FROM file_permissions WHERE folder_id = ? AND file_name = ?")
      .get("root", FILE_NAME);
    assert.ok(saved, "a private ACL must be persisted in SQLite");
    const persisted = JSON.parse(saved.allowed_users_json);
    assert.equal(persisted.owner, "tester");
    assert.equal(persisted.public, false);
    assert.deepEqual(persisted.users, {});
  } finally { database.close(); }

  const fileUrl = `/files/${encodeURIComponent(FILE_NAME)}?folderId=root`;
  const aclUrl = `/file-access?name=${encodeURIComponent(FILE_NAME)}&folderId=root`;
  const legitimateRead = await owner.get(fileUrl);
  assert.equal(legitimateRead.status, 200, legitimateRead.body);
  assert.equal(legitimateRead.body, FILE_CONTENT, "exact private owner retains file access");
  assert.equal((await owner.get(aclUrl)).status, 200,
    "exact private owner retains permission management");

  const illegalRead = await impostor.get(fileUrl);
  const illegalAclRead = await impostor.get(aclUrl);
  const illegalEdit = await impostor.put("/file-access", { ...acl, public: true });
  // On the original HEAD these are 200, 200 and 200 respectively: the second
  // account is falsely identified as the owner and can expose private bytes
  // and promote the private ACL to public. The fixed policy must reject all.
  assert.equal(illegalRead.status, 403, "case-colliding non-admin cannot GET private owner bytes");
  assert.equal(illegalRead.body.includes(FILE_CONTENT), false, "denied read contains no private bytes");
  assert.equal(illegalAclRead.status, 403, "case-colliding account cannot read owner ACL");
  assert.equal(illegalEdit.status, 403, "case-colliding account cannot publish/modify owner ACL");

  const unchanged = await owner.get(aclUrl);
  assert.equal(unchanged.status, 200);
  assert.equal(JSON.parse(unchanged.body).owner, "tester");
  assert.equal(JSON.parse(unchanged.body).public, false,
    "rejected edit cannot change the persisted private ACL");
  assert.equal((await owner.put("/file-access", acl)).status, 200,
    "exact owner may still edit their own file permissions");
});

for (const mode of ["json", "sqlite"]) {
  test(`P2: case-distinct account cannot create or revoke another account's capability (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, port, origin, password, publicPost } = await startFixture(t, mode);
      const issuer = mode === "json" ? "tester" : "admin";
      const wrongAccount = issuer.toUpperCase();
      const wrongPassword = crypto.randomBytes(24).toString("base64url");
      assert.notEqual(wrongPassword, password, "case-distinct issuer has independent credentials");
      // Both names are legitimate, separately authenticated users: the
      // account store and login perform exact-case lookup, unlike the old
      // share-owner comparison. No forged cookie or storage mutation needed.
      const createdAccount = await authed("/users", {
        username: wrongAccount, password: wrongPassword, role: "user", permissions: { listFiles: true },
      });
      assert.equal(createdAccount.status, 201, createdAccount.body);
      const loginBody = JSON.stringify({ username: wrongAccount, password: wrongPassword });
      const login = await request(port, "/auth/login", {
        method: "POST", headers: { "content-type": "application/json",
          "content-length": Buffer.byteLength(loginBody) }, body: loginBody,
      });
      assert.equal(login.status, 200, login.body);
      assert.equal(JSON.parse(login.body).username, wrongAccount,
        "login really authenticated a separate case-sensitive account");
      const cookies = login.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
      const impostorCookie = cookies.join("; ");
      const csrf = cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1];
      const asImpostor = (url, data, method = "POST") => {
        const body = JSON.stringify(data);
        return request(port, url, { method,
          headers: { cookie: impostorCookie, origin, "x-csrf-token": csrf,
            "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
      };

      const policy = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 2 };
      if (mode === "json") {
        const spoofedOwner = await asImpostor("/share/capabilities", policy);
        assert.equal(spoofedOwner.status, 403,
          "a case-colliding user with listFiles cannot issue a capability for the original file owner");
      }
      const created = await authed("/share/capabilities", policy);
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const deniedRevoke = await asImpostor("/share/capabilities/revoke", { token }, "DELETE");
      assert.equal(deniedRevoke.status, 403,
        "a different account cannot revoke an issuer's capability just by matching username casing");
      const stillLive = await publicPost(token, "view");
      assert.equal(stillLive.status, 200,
        "denied cross-account revocation must leave the legitimate issuer's grant live");
      const legitimateRevoke = await authed("/share/capabilities/revoke", { token }, "DELETE");
      assert.equal(legitimateRevoke.status, 204,
        "exact issuer must retain the ability to revoke their own capability");
      const afterRevoke = await publicPost(token, "view");
      assert.equal(afterRevoke.status, 404);
    });
}

for (const mode of ["json", "sqlite"]) {
  test(`download checks the actual opened descriptor before stream (${mode})`, { timeout: 60_000 }, async (t) => {
    const { authed, publicPost, dataDir } = await startFixture(t, mode, {
      ROOTARK_TEST_SHARE_PAUSE_POINT: "reserve",
      ROOTARK_TEST_SHARE_PAUSE_MS: "1800",
      ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN: "1",
    });

    const created = await authed("/share/capabilities", {
      name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
      permissions: ["download"], maxDownloads: 1,
    });
    assert.equal(created.status, 201, created.body);
    const { token } = JSON.parse(created.body);
    const viewer = await publicPost(token, "view");
    assert.equal(viewer.status, 200, viewer.body);

    const pending = publicPost(token, "download", viewerCookieFrom(viewer));
    await new Promise((resolve) => setTimeout(resolve, 400));

    const originalPath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
    const grantedPath = `${originalPath}.granted`;
    fs.renameSync(originalPath, grantedPath);
    fs.writeFileSync(originalPath, "FORBIDDEN_AFTER_OPEN_BYTES\n");
    const marker = path.join(path.dirname(dataDir), "swap-after-open.marker");
    fs.writeFileSync(marker, "swap once after verified open");

    const response = await pending;
    assert.equal(fs.existsSync(marker), false, "hook must have restored the pathname after fd open");
    assert.equal(fs.readFileSync(originalPath, "utf8"), FILE_CONTENT,
      "the path is authorized again while the open descriptor remains foreign");
    assert.equal(fs.readFileSync(`${originalPath}.untrusted-opened`, "utf8"), "FORBIDDEN_AFTER_OPEN_BYTES\n",
      "the foreign file is retained only by the outgoing descriptor");
    assert.equal(response.status, 404, "never stream bytes from a descriptor outside the capability generation");
    assert.equal(response.body.includes("FORBIDDEN_AFTER_OPEN_BYTES"), false);
    const authorizedRetry = await publicPost(token, "download", viewerCookieFrom(viewer));
    assert.equal(authorizedRetry.status, 404,
      "restoring a pathname after a foreign-descriptor swap changes kernel ctime; the old capability generation stays revoked");
    // A failed opener did not consume a quota; the security failure above is
    // due to generation drift, not artificially exhausted download allowance.
    let downloads;
    if (mode === "sqlite") {
      const Database = require("better-sqlite3");
      const db = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
      try {
        const row = db.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(token);
        downloads = JSON.parse(row.metadata_json).downloads;
      } finally { db.close(); }
    } else {
      downloads = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))[token].downloads;
    }
    assert.equal(downloads || 0, 0,
      "foreign descriptor refusal must preserve download quota despite generation revocation");
  });
}

for (const mode of ["json", "sqlite"]) {
  test(`download rejects foreign descriptor even when original pathname identity is unchanged (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, dataDir } = await startFixture(t, mode, {
        ROOTARK_TEST_SHARE_PAUSE_POINT: "reserve",
        ROOTARK_TEST_SHARE_PAUSE_MS: "1800",
        ROOTARK_TEST_SHARE_SWAP_AFTER_OPEN: "1",
        ROOTARK_TEST_SHARE_FOREIGN_FD_ONLY: "1",
      });
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 1,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const viewer = await publicPost(token, "view");
      assert.equal(viewer.status, 200, viewer.body);

      const originalPath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
      const before = fs.statSync(originalPath);
      const pending = publicPost(token, "download", viewerCookieFrom(viewer));
      await new Promise((resolve) => setTimeout(resolve, 400));
      const marker = path.join(path.dirname(dataDir), "swap-after-open.marker");
      fs.writeFileSync(marker, "substitute only the opened file descriptor");
      const refused = await pending;
      assert.equal(fs.existsSync(marker), false,
        "test must reach the actual already-verified-open handle substitution");
      const after = fs.statSync(originalPath);
      assert.equal(after.ino, before.ino, "path inode must not change during descriptor test");
      assert.equal(after.ctimeMs, before.ctimeMs,
        "path generation must remain authorized: denial must come from opened descriptor");
      assert.equal(refused.status, 404,
        "a foreign opened descriptor must be refused despite a still-authorized pathname");
      assert.equal(refused.body.includes("FOREIGN_DESCRIPTOR_BYTES_NOT_AUTHORIZED"), false);

      const retry = await publicPost(token, "download", viewerCookieFrom(viewer));
      assert.equal(retry.status, 200,
        "the prior denied foreign handle must not invalidate a real authorized download");
      assert.equal(retry.body, FILE_CONTENT,
        "genuine authorized descriptor must return the original file bytes");
    });
}

test("SQLite exchange cannot revoke a new share or lose a parallel alias after its stale read", { timeout: 60_000 }, async (t) => {
  const { authed, port, origin, dataDir, pauseMarker, pauseRelease } = await startFixture(t, "sqlite", {
    ROOTARK_TEST_SHARE_PAUSE_POINT: "exchange-commit",
  });
  const settings = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
    permissions: ["download"], maxDownloads: 3 };
  const created = await authed("/share/capabilities", settings);
  assert.equal(created.status, 201, created.body);
  const token = JSON.parse(created.body).token;
  const exchange = () => {
    const body = JSON.stringify({ token });
    return request(port, "/share/c/exchange", {
      method: "POST", headers: { origin, "content-type": "application/json",
        "content-length": Buffer.byteLength(body) }, body,
    });
  };
  // The disposable server suspends *after* its second read of the entire
  // public links map, where the pre-fix savePublicLinks() reused stale data.
  const firstPromise = exchange();
  const deadline = Date.now() + 10_000;
  while (!fs.existsSync(pauseMarker) && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  assert.equal(fs.readFileSync(pauseMarker, "utf8"), "snapshot-read-before-admission",
    "real server reached the vulnerable post-snapshot pause before B is created");
  let independent;
  try {
    independent = await authed("/share/capabilities", settings);
    assert.equal(independent.status, 201, independent.body);
  } finally {
    // A cannot leave its precommit barrier before B's INSERT has returned.
    // No scheduler timing assumption can make the unpatched parent pass.
    fs.writeFileSync(pauseRelease, "B-insert-confirmed");
  }
  const otherToken = JSON.parse(independent.body).token;
  assert.notEqual(otherToken, token);
  const secondPromise = exchange();
  const [first, second] = await Promise.all([firstPromise, secondPromise]);
  assert.equal(first.status, 200, first.body);
  assert.equal(second.status, 200, second.body);
  const firstHandle = JSON.parse(first.body).handle;
  const secondHandle = JSON.parse(second.body).handle;
  assert.notEqual(firstHandle, secondHandle);

  const Database = require("better-sqlite3");
  const db = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
  try {
    const firstRow = db.prepare("SELECT metadata_json, revoked_at FROM public_links WHERE token = ?").get(token);
    const otherRow = db.prepare("SELECT revoked_at FROM public_links WHERE token = ?").get(otherToken);
    assert.equal(otherRow?.revoked_at, null,
      "an exchange of A may never revoke a concurrently created unrelated B");
    const sessions = JSON.parse(firstRow.metadata_json).capabilitySessions;
    assert.ok(sessions?.[firstHandle] && sessions?.[secondHandle],
      "two overlapping exchanges of A must merge both session aliases atomically");
  } finally { db.close(); }

  for (const response of [first, second]) {
    const handle = JSON.parse(response.body).handle;
    const cookie = response.headers["set-cookie"].find((item) => item.startsWith("rootark_cap_"))
      .split(";", 1)[0];
    const view = await request(port, `/share/${handle}/view`, {
      method: "POST", headers: { origin, cookie },
    });
    assert.equal(view.status, 200, "each legitimately issued session remains live");
  }
});

for (const mode of ["json", "sqlite"]) {
  test(`scoped capability: authorized creation, per-operation limits and durable revocation (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, port, origin, publicPost, exchangeCapability, dataDir, password } = await startFixture(t, mode);
      const input = { name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 1 };

      const unauthenticated = await request(port, "/share/capabilities", {
        method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(input),
      });
      assert.notEqual(unauthenticated.status, 201, "bearer possession cannot create a grant");

      for (const invalid of [
        { ...input, permissions: undefined },
        { ...input, permissions: ["upload"] },
        { ...input, maxDownloads: -1 },
        { ...input, expiresInMinutes: 0 },
        { ...input, recipient: "someone@example.test" },
      ]) {
        const denied = await authed("/share/capabilities", invalid);
        assert.equal(denied.status, 400, JSON.stringify(invalid));
      }
      const alias = await authed("/share/CaPaBiLiTiEs/", { ...input, permissions: undefined });
      assert.equal(alias.status, 400, "case-insensitive and trailing-slash routes must retain strict capability admission");

      const created = await authed("/share/capabilities", input);
      assert.equal(created.status, 201, created.body);
      const capability = JSON.parse(created.body);
      assert.equal(capability.capability, true);
      assert.deepEqual(capability.permissions, ["download"]);
      assert.equal(capability.scope?.folderId, "root");
      assert.equal(capability.scope?.fileName, FILE_NAME);
      assert.match(capability.token, /^C[a-f0-9]{47}$/);
      assert.ok(capability.url.endsWith(`/share/c#${capability.token}`),
        "secret must be a browser fragment, absent from the HTTP request target");
      const landing = await request(port, "/share/c");
      assert.equal(landing.status, 200, "fragment-only capability landing is public");
      assert.equal(landing.body.includes(capability.token), false,
        "the landing HTML must never embed a bearer secret");
      const inlineScript = /<script nonce="[^"]+">([\s\S]*?)<\/script>/.exec(landing.body)?.[1];
      assert.ok(inlineScript, "fragment landing must ship the browser controller");
      assert.doesNotThrow(() => new vm.Script(inlineScript),
        "nonce-protected fragment controller must parse as browser JavaScript");
      assert.match(inlineScript, /window\.history\.replaceState\(null, "", "\/share\/c"\)/,
        "landing JS must remove the bearer fragment before contacting the server");
      assert.equal(landing.headers["cache-control"], "no-store");
      assert.equal(landing.headers["referrer-policy"], "no-referrer");
      const oldCookiePage = await request(port, "/share/c", {
        headers: { cookie: `rootark_share_pwd_${capability.token}=legacyPwd; rootark_share_${capability.token}=legacyViewer` },
      });
      assert.equal(oldCookiePage.status, 200);
      for (const prefix of [`rootark_share_pwd_${capability.token}=`,
        `rootark_share_${capability.token}=`]) {
        assert.ok((oldCookiePage.headers["set-cookie"] || []).some((value) =>
          value.startsWith(prefix) && value.includes("Expires=Thu, 01 Jan 1970")),
        "one-time response must clear pre-upgrade token-bearing cookie names");
      }
      const crossOriginExchange = await request(port, "/share/c/exchange", {
        method: "POST", headers: { origin: "https://cross-origin.invalid",
          "content-type": "application/json" },
        body: JSON.stringify({ token: capability.token }),
      });
      assert.equal(crossOriginExchange.status, 403,
        "cross-origin requests cannot create bearer-derived cookie sessions");
      const oldLeakingPath = await request(port, `/share/${capability.token}`);
      assert.equal(oldLeakingPath.status, 404,
        "old capability bearer-in-path routes fail closed, not silently aliased");
      const oldLeakingView = await request(port, `/share/${capability.token}/view`, {
        method: "POST", headers: { origin },
      });
      assert.equal(oldLeakingView.status, 404,
        "client cannot bypass the opaque capability session using a URL bearer");

      const session = await exchangeCapability(capability.token);
      const unauthenticatedAlias = await request(port, `/share/${session.handle}/view`, {
        method: "POST", headers: { origin },
      });
      assert.equal(unauthenticatedAlias.status, 404,
        "public alias alone is never sufficient without the opaque cookie");
      const duplicateCookie = await request(port, `/share/${session.handle}/view`, {
        method: "POST", headers: { origin,
          cookie: `${session.cookie}; ${session.cookie}` },
      });
      assert.equal(duplicateCookie.status, 404,
        "ambiguous duplicate capability cookies must fail closed");
      const secondCreated = await authed("/share/capabilities", input);
      assert.equal(secondCreated.status, 201);
      const secondToken = JSON.parse(secondCreated.body).token;
      const secondSession = await exchangeCapability(secondToken);
      assert.notEqual(secondSession.handle, session.handle);
      const crossAliasCookie = await request(port, `/share/${session.handle}/view`, {
        method: "POST", headers: { origin, cookie: secondSession.cookie },
      });
      assert.equal(crossAliasCookie.status, 404,
        "a valid cookie for another alias cannot authorize this capability");

      const view = await publicPost(capability.token, "view");
      assert.equal(view.status, 200, view.body);
      assert.equal("fileName" in JSON.parse(view.body), false, "download-only is metadata-blind");
      assert.equal(view.headers["cache-control"], "no-store");
      assert.equal(view.body.includes(capability.token), false);
      assert.equal((view.headers["set-cookie"] || []).some((value) =>
        value.includes(capability.token)), false,
      "viewer cookies and session headers may not contain the original capability bearer");
      const cookie = viewerCookieFrom(view);
      const deniedPreview = await publicPost(capability.token, "preview", cookie);
      assert.equal(deniedPreview.status, 403, "download token cannot preview");
      const anotherViewer = await publicPost(capability.token, "view");
      assert.equal(anotherViewer.status, 200, anotherViewer.body);
      const results = await Promise.all([
        publicPost(capability.token, "download", cookie),
        publicPost(capability.token, "download", viewerCookieFrom(anotherViewer)),
      ]);
      assert.deepEqual(results.map((response) => response.status).sort(), [200, 410],
        "competing independent viewers must consume exactly one allowed download");
      const first = results.find((response) => response.status === 200);
      const exhausted = results.find((response) => response.status === 410);
      assert.equal(first.body, FILE_CONTENT);
      assert.equal(first.headers["cache-control"], "no-store",
        "streaming responses must override the old share cache policy");
      assert.equal((first.headers["set-cookie"] || []).some((value) =>
        value.includes(capability.token)), false,
      "download receipt cookies must not contain the original bearer");
      assert.ok((first.headers["set-cookie"] || []).some((value) =>
        value.startsWith(`rootark_share_dl_${session.handle}=`)
          && value.includes("Path=/share/c")),
      "fragment landing page /share/c must be able to read its alias-only receipt cookie");
      assert.equal(exhausted.body.includes(FILE_CONTENT), false);

      const revokeBody = JSON.stringify({ token: capability.token });
      const unauthorizedRevoke = await request(port, "/share/capabilities/revoke", {
        method: "DELETE", headers: { origin, "content-type": "application/json" }, body: revokeBody,
      });
      assert.notEqual(unauthorizedRevoke.status, 204, "anonymous client cannot revoke");
      if (mode === "json") {
        const loginBody = JSON.stringify({ username: "other", password });
        const loginOther = await request(port, "/auth/login", { method: "POST",
          headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
        assert.equal(loginOther.status, 200, loginOther.body);
        const otherCookies = loginOther.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
        const otherCookie = otherCookies.join("; ");
        const csrf = otherCookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1];
        const wrongOwner = await request(port, "/share/capabilities/revoke", {
          method: "DELETE", headers: { origin, cookie: otherCookie, "x-csrf-token": csrf,
            "content-type": "application/json", "content-length": Buffer.byteLength(revokeBody) }, body: revokeBody,
        });
        assert.equal(wrongOwner.status, 403, "another authenticated admin cannot revoke someone else's capability");
      }
      const revoked = await authed("/share/capabilities/revoke", { token: capability.token }, "DELETE");
      assert.equal(revoked.status, 204, revoked.body);
      const afterRevoke = await publicPost(capability.token, "view");
      assert.equal(afterRevoke.status, 404, "revocation prevents future bearer sessions");
      const freshRevokedExchangeBody = JSON.stringify({ token: capability.token });
      const freshRevokedExchange = await request(port, "/share/c/exchange", {
        method: "POST", headers: { origin, "content-type": "application/json",
          "content-length": Buffer.byteLength(freshRevokedExchangeBody) },
        body: freshRevokedExchangeBody,
      });
      assert.equal(freshRevokedExchange.status, 404,
        "a revoked original bearer must not create a NEW alias session (bypass memoized fixture)");
      const again = await authed("/share/capabilities/revoke", { token: capability.token }, "DELETE");
      assert.equal(again.status, 404, "revocation cannot resurrect a token");
      const unknown = await authed("/share/capabilities/revoke", {
        token: `C${crypto.randomBytes(24).toString("hex").slice(1)}`,
      }, "DELETE");
      assert.equal(unknown.status, 404);

      if (mode === "sqlite") {
        const Database = require("better-sqlite3");
        const database = new Database(path.join(dataDir, "rootark.sqlite"), { readonly: true });
        try {
          const row = database.prepare("SELECT revoked_at FROM public_links WHERE token = ?").get(capability.token);
          assert.ok(row?.revoked_at, "revoked tombstone persists in SQLite");
        } finally { database.close(); }
      } else {
        const audit = fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8");
        assert.equal(audit.includes(capability.token), false, "audit never records the bearer secret");
        assert.equal(audit.includes(FILE_NAME), false, "capability audit omits resource filenames");
      }
    });

  test(`scoped capability cannot follow file replacement and does not alter legacy shares (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, exchangeCapability, port, origin, dataDir, legacyToken } = await startFixture(t, mode);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60, permissions: ["download"], maxDownloads: 2,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const initial = await publicPost(token, "view");
      assert.equal(initial.status, 200, initial.body);
      const { handle, cookie: sessionCookie } = await exchangeCapability(token);
      const aliasOnlyQr = await request(port, `/share/${handle}/qr`, {
        headers: { cookie: sessionCookie },
      });
      assert.equal(aliasOnlyQr.status, 404,
        "a short-lived alias+cookie cannot recover the long-lived original bearer via QR");
      const qrBody = JSON.stringify({ token });
      const qrBefore = await request(port, "/share/c/qr", {
        method: "POST", headers: { origin, "content-type": "application/json",
          "content-length": Buffer.byteLength(qrBody) }, body: qrBody,
      });
      assert.equal(qrBefore.status, 200,
        "only explicit possession of the original volatile fragment can render the QR");
      assert.equal(qrBefore.headers["content-type"], "image/png");
      assert.equal(qrBefore.headers["cache-control"], "no-store");

      const filePath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
      fs.renameSync(filePath, `${filePath}.old`);
      fs.writeFileSync(filePath, "REPLACEMENT_PRIVATE_FILE\n");

      const replacedView = await publicPost(token, "view");
      assert.equal(replacedView.status, 404, "path reuse cannot broaden a file-scoped grant");
      const replacedDownload = await publicPost(token, "download", viewerCookieFrom(initial));
      assert.equal(replacedDownload.status, 404);
      assert.equal(replacedDownload.body.includes("REPLACEMENT_PRIVATE_FILE"), false);

      // A truncated/corrupt persisted metadata_json must not turn a capability
      // into a permissive legacy public link with the same bearer token.
      if (mode === "sqlite") {
        const Database = require("better-sqlite3");
        const db = new Database(path.join(dataDir, "rootark.sqlite"));
        try {
          const row = db.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(token);
          const metadata = JSON.parse(row.metadata_json);
          delete metadata.shareKind;
          delete metadata.resourceBinding;
          db.prepare("UPDATE public_links SET metadata_json = ? WHERE token = ?").run(JSON.stringify(metadata), token);
        } finally { db.close(); }
      } else {
        const linksFile = path.join(dataDir, "public-links.json");
        const links = JSON.parse(fs.readFileSync(linksFile, "utf8"));
        delete links[token].shareKind;
        delete links[token].resourceBinding;
        fs.writeFileSync(linksFile, JSON.stringify(links));
      }
      const missingBinding = await publicPost(token, "download", viewerCookieFrom(initial));
      assert.equal(missingBinding.status, 404, "missing policy marker must not downgrade an issued capability");
      assert.equal(missingBinding.body.includes("REPLACEMENT_PRIVATE_FILE"), false);
      // The prior opaque session still names the invalidated capability; it
      // must not display the swapped/corrupt resource after a policy change.
      const missingBindingQr = await request(port, "/share/c/qr", {
        method: "POST", headers: { origin, "content-type": "application/json",
          "content-length": Buffer.byteLength(qrBody) }, body: qrBody,
      });
      assert.equal(missingBindingQr.status, 404,
        "an already-exchanged cookie session cannot bypass revoked file-generation binding");

      const legacy = await publicPost(legacyToken, "view");
      assert.equal(legacy.status, 200, "legacy share access remains compatible after a file change");
      const forged = await publicPost(crypto.randomBytes(24).toString("hex"), "view");
      assert.equal(forged.status, 404, "a forged capability cannot access other paths");
      const originalLegacy = await request(port, "/login.html");
      assert.equal(originalLegacy.status, 200, "legacy application remains reachable");
    });

  test(`scoped capability rejects same-inode same-size rewrite after mtime reset (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, dataDir } = await startFixture(t, mode);
      const filePath = path.join(path.dirname(dataDir), "uploads", FILE_NAME);
      const stamp = new Date(Math.floor((Date.now() - 30_000) / 1000) * 1000);
      fs.utimesSync(filePath, stamp, stamp);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 1,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const initial = await publicPost(token, "view");
      assert.equal(initial.status, 200, initial.body);
      // Bind the hostile rewrite and both stat probes to the SAME opened
      // descriptor, rather than checking a pathname and writing it later.
      const fd = fs.openSync(filePath, fs.constants.O_RDWR
        | (fs.constants.O_NOFOLLOW || 0));
      let before, after;
      const changed = "R".repeat(Buffer.byteLength(FILE_CONTENT) - 1) + "\n";
      try {
        before = fs.fstatSync(fd);
        await new Promise((resolve) => setTimeout(resolve, 40));
        assert.notEqual(changed, FILE_CONTENT);
        assert.equal(fs.writeSync(fd, changed, 0, "utf8"), Buffer.byteLength(changed));
        fs.futimesSync(fd, stamp, stamp);
        after = fs.fstatSync(fd);
      } finally { fs.closeSync(fd); }
      assert.equal(after.ino, before.ino, "negative oracle must keep the identical inode");
      assert.equal(after.size, before.size, "negative oracle must preserve file length");
      assert.equal(after.birthtimeMs, before.birthtimeMs,
        "negative oracle must preserve inode creation identity");
      assert.equal(after.mtimeMs, before.mtimeMs,
        "attacker demonstrably restored the mtime that the old binding trusted");
      assert.notEqual(after.ctimeMs, before.ctimeMs,
        "positive tamper canary: kernel-owned change time must prove the in-place rewrite");
      const denied = await publicPost(token, "download", viewerCookieFrom(initial));
      assert.equal(denied.status, 404,
        "an old capability may not serve rewritten bytes after same-inode same-size mtime forgery");
      assert.equal(denied.body.includes(changed), false);
    });

  test(`scoped capability expires an opaque session independently of the original grant (${mode})`,
    { timeout: 60_000 }, async (t) => {
      const { authed, publicPost, exchangeCapability, dataDir } = await startFixture(t, mode);
      const created = await authed("/share/capabilities", {
        name: FILE_NAME, folderId: "root", expiresInMinutes: 60,
        permissions: ["download"], maxDownloads: 2,
      });
      assert.equal(created.status, 201, created.body);
      const { token } = JSON.parse(created.body);
      const activated = await publicPost(token, "view");
      assert.equal(activated.status, 200);
      const { handle } = await exchangeCapability(token);
      const expired = new Date(Date.now() - 60_000).toISOString();
      if (mode === "sqlite") {
        const Database = require("better-sqlite3");
        const db = new Database(path.join(dataDir, "rootark.sqlite"));
        try {
          const row = db.prepare("SELECT metadata_json FROM public_links WHERE token = ?").get(token);
          const metadata = JSON.parse(row.metadata_json);
          assert.ok(metadata.capabilitySessions?.[handle]);
          metadata.capabilitySessions[handle].expiresAt = expired;
          db.prepare("UPDATE public_links SET metadata_json = ? WHERE token = ?").run(JSON.stringify(metadata), token);
        } finally { db.close(); }
      } else {
        const file = path.join(dataDir, "public-links.json");
        const links = JSON.parse(fs.readFileSync(file, "utf8"));
        assert.ok(links[token].capabilitySessions?.[handle]);
        links[token].capabilitySessions[handle].expiresAt = expired;
        fs.writeFileSync(file, JSON.stringify(links));
      }
      const oldSession = await publicPost(token, "download", viewerCookieFrom(activated));
      assert.equal(oldSession.status, 404,
        "expired alias+cookie cannot download even if the underlying grant has an hour remaining");
      assert.equal(oldSession.body.includes(FILE_CONTENT), false);
    });
}


test("issue 68 P2 Windows: mixed-case deletion revokes the physical file capability", { timeout: 60_000 }, async (t) => {
  if (process.platform !== "win32") return t.skip("Windows case-insensitive filesystem regression");
  const { authed, port, origin, dataDir } = await startFixture(t, "sqlite");
  const actualName = "Documento.txt";
  const diskFile = path.join(path.dirname(dataDir), "uploads", actualName);
  fs.writeFileSync(diskFile, "physical case-sensitive metadata binding");
  const created = await authed("/share/capabilities", {
    name: actualName, folderId: "root", permissions: ["download"],
    expiresInMinutes: 60, maxDownloads: 3,
  });
  assert.equal(created.status, 201, created.body);
  const { token } = JSON.parse(created.body);
  assert.match(token, /^C[a-f0-9]{47}$/);
  // The live API rejects new case-aliased issuance, but older SQLite rows
  // may already contain another spelling for this same NTFS inode. Seed that
  // exact legacy DB state independently of the current server-side snapshot.
  const aliasToken = `C${"b".repeat(47)}`;
  const legacyDb = new (require("better-sqlite3"))(path.join(dataDir, "rootark.sqlite"));
  try {
    const insert = legacyDb.prepare(`INSERT INTO public_links
      (token, folder_id, file_name, created_by, created_at, expires_at,
       max_views, views, password_hash, metadata_json, permissions_json, revoked_at)
      SELECT ?, folder_id, ?, created_by, created_at, expires_at,
             max_views, views, password_hash, metadata_json, permissions_json, revoked_at
        FROM public_links WHERE token = ?`);
    assert.equal(insert.run(aliasToken, "documento.txt", token).changes, 1);
  } finally { legacyDb.close(); }
  const exchange = () => request(port, "/share/c/exchange", {
    method: "POST", headers: { origin, "content-type": "application/json" },
    body: JSON.stringify({ token }),
  });
  assert.equal((await exchange()).status, 200, "real SQLite bearer was active before trash");
  const sqlRow = (whichToken = token) => {
    const db = new (require("better-sqlite3"))(path.join(dataDir, "rootark.sqlite"),
      { readonly: true, fileMustExist: true });
    try {
      return db.prepare("SELECT file_name, revoked_at FROM public_links WHERE token = ?").get(whichToken);
    } finally { db.close(); }
  };
  assert.equal(sqlRow()?.file_name, actualName,
    "SQLite must have the original-cased grant before a case-aliased deletion");
  assert.equal(sqlRow()?.revoked_at, null, "the grant is initially active");
  assert.equal(sqlRow(aliasToken)?.file_name, "documento.txt");
  assert.equal(sqlRow(aliasToken)?.revoked_at, null);
  assert.equal(fs.existsSync(path.join(path.dirname(dataDir), "uploads", "documento.txt")), true,
    "Windows accepted a case-aliased physical path before trash");
  const deleted = await authed("/delete/documento.txt?folderId=root", {});
  assert.ok([200, 202].includes(deleted.status), deleted.body);
  assert.equal(fs.existsSync(diskFile), false, "actual original-cased file moved into trash");
  assert.ok(sqlRow()?.revoked_at, "SQLite must durably tombstone the exact original-cased grant");
  assert.ok(sqlRow(aliasToken)?.revoked_at,
    "SQLite must also revoke the case-alias bearer for that same Windows inode");
  assert.equal((await exchange()).status, 404,
    "post-trash exchange cannot reactivate the revoked original-cased capability");
});
