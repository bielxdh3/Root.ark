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
const zlib = require("node:zlib");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const TIMEOUT_MS = 10_000;

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
      let text = "";
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function waitForServer(port, child) {
  const deadline = Date.now() + TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited");
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("approval, rejection, and trash actions reject legacy GET without mutation and require CSRF POST", { timeout: 45_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-state-methods-"));
  const dataDir = path.join(directory, "data");
  const tempDir = path.join(directory, "temp");
  const uploadsDir = path.join(directory, "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(tempDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "admin", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {}, sessionVersion: 0 },
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: { upload: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(tempDir, "approve.txt"), "approved fixture\n");
  fs.writeFileSync(path.join(tempDir, "reject.txt"), "rejected fixture\n");
  fs.writeFileSync(path.join(tempDir, "unowned.txt"), "legacy upload without an owner\n");
  fs.writeFileSync(path.join(uploadsDir, "trash.txt"), "trash fixture\n");
  const pendingFile = path.join(dataDir, "pending-uploads.json");
  fs.writeFileSync(pendingFile, JSON.stringify({
    "root/approve.txt": { folderId: "root", fileName: "approve.txt", uploadedBy: "submitter" },
    "root/reject.txt": { folderId: "root", fileName: "reject.txt", uploadedBy: "submitter" },
  }));
  const pendingTrashId = "45454545-4545-4545-8545-454545454545";
  const trashItemsFile = path.join(dataDir, "trash-items.json");
  fs.writeFileSync(trashItemsFile, JSON.stringify([{
    id: pendingTrashId,
    itemType: "file",
    originalFolderId: "root",
    originalFileName: "approve.txt",
    trashPath: `files/${pendingTrashId}/approve.txt`,
    deletedAt: new Date().toISOString(),
    status: "remote_delete_pending",
    metadata: { remoteDeletion: { operationId: "old-delete", state: "pending", attempts: 0, transitions: [] } },
    restoreMetadata: { versions: { versions: [] } },
  }]));

  const port = await getUnusedPort();
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const env = { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: jwtSecret, TRASH_ENABLED: "true" };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  assert.equal((await waitForServer(port, child)).status, 200);

  const body = JSON.stringify({ username: "admin", password });
  const loggedIn = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(loggedIn.status, 200);
  const cookies = loggedIn.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  const session = {
    cookie: cookies.join("; "),
    csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1],
  };
  const postHeaders = { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf };
  const viewerBody = JSON.stringify({ username: "viewer", password });
  const viewerLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(viewerBody) }, body: viewerBody });
  assert.equal(viewerLogin.status, 200, viewerLogin.body);
  const viewerCookie = viewerLogin.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]).join("; ");
  const viewerPending = await request(port, "/pending?folderId=root", { headers: { cookie: viewerCookie } });
  assert.equal(viewerPending.status, 200, viewerPending.body);
  assert.deepEqual(JSON.parse(viewerPending.body), [], "upload permission only exposes files owned by the requester, never ownerless pending files");

  const legacyAuditExport = await request(port, "/audit/export?format=csv", { headers: { cookie: session.cookie } });
  assert.equal(legacyAuditExport.status, 405, "legacy audit export GET is no longer reachable as a mutation");
  assert.equal(legacyAuditExport.headers.allow, "POST");
  const auditLogsAfterGet = JSON.parse(fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8")).logs;
  assert.equal(auditLogsAfterGet.some((entry) => entry.eventType === "audit.exported"), false);

  const auditExportWithoutCsrf = await request(port, "/audit/export?format=csv", { method: "POST", headers: { cookie: session.cookie } });
  assert.equal(auditExportWithoutCsrf.status, 403, "cookie-authenticated audit export requires CSRF");
  const auditExport = await request(port, "/audit/export?format=csv", { method: "POST", headers: postHeaders });
  assert.equal(auditExport.status, 200, auditExport.body);
  assert.match(auditExport.headers["content-type"], /text\/csv/);
  const auditLogsAfterPost = JSON.parse(fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8")).logs;
  assert.equal(auditLogsAfterPost.filter((entry) => entry.eventType === "audit.exported").length, 1);

  for (const [action, filename] of [["approve", "approve.txt"], ["reject", "reject.txt"]]) {
    const legacy = await request(port, `/${action}/${filename}`, {
      headers: { cookie: session.cookie, origin: "https://attacker.invalid" },
    });
    assert.equal(legacy.status, 405, `${action} legacy GET`);
    assert.equal(fs.existsSync(path.join(tempDir, filename)), true, `${action} pending file unchanged`);
    const topLevel = await request(port, `/${action}/${filename}`, { headers: { cookie: session.cookie } });
    assert.equal(topLevel.status, 405, `${action} top-level navigation GET`);
    assert.equal(fs.existsSync(path.join(tempDir, filename)), true, `${action} top-level GET leaves pending file unchanged`);
  }
  const legacyTrash = await request(port, "/delete/trash.txt", {
    headers: { cookie: session.cookie, origin: "https://attacker.invalid" },
  });
  assert.equal(legacyTrash.status, 405, "trash legacy GET");
  assert.equal(legacyTrash.headers.allow, "POST");
  assert.equal(fs.readFileSync(path.join(uploadsDir, "trash.txt"), "utf8"), "trash fixture\n");
  const topLevelTrash = await request(port, "/delete/trash.txt", { headers: { cookie: session.cookie } });
  assert.equal(topLevelTrash.status, 405, "top-level trash navigation GET");
  assert.equal(fs.readFileSync(path.join(uploadsDir, "trash.txt"), "utf8"), "trash fixture\n");
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(pendingFile, "utf8"))).sort(), ["root/approve.txt", "root/reject.txt"]);

  const noCsrf = await request(port, "/approve/approve.txt", { method: "POST", headers: { cookie: session.cookie } });
  assert.equal(noCsrf.status, 403);
  assert.equal(fs.existsSync(path.join(tempDir, "approve.txt")), true);

  const approved = await request(port, "/approve/approve.txt", { method: "POST", headers: postHeaders });
  assert.equal(approved.status, 200, approved.body);
  assert.equal(fs.existsSync(path.join(tempDir, "approve.txt")), false);
  assert.equal(fs.existsSync(path.join(uploadsDir, "approve.txt")), true);
  const retiredDeletion = JSON.parse(fs.readFileSync(trashItemsFile, "utf8")).find((item) => item.id === pendingTrashId);
  assert.equal(retiredDeletion.status, "permanently_deleted", "same-name approval retires the obsolete trash operation before success");
  assert.equal(retiredDeletion.metadata.remoteDeletion.state, "cancelled");
  assert.equal(retiredDeletion.metadata.remoteDeletion.cancellationReason, "replacement_active");

  const rejected = await request(port, "/reject/reject.txt", { method: "POST", headers: postHeaders });
  assert.equal(rejected.status, 200, rejected.body);
  assert.equal(fs.existsSync(path.join(tempDir, "reject.txt")), false);
  const trashed = await request(port, "/delete/trash.txt", { method: "POST", headers: postHeaders });
  assert.equal(trashed.status, 200, trashed.body);
  assert.equal(fs.existsSync(path.join(uploadsDir, "trash.txt")), false);
  const legacyRestore = await request(port, `/trash/${JSON.parse(trashed.body).trashItem.id}/restore`, {
    headers: { cookie: session.cookie, origin: "https://attacker.invalid" },
  });
  assert.equal(legacyRestore.status, 404, "trash restore has no legacy GET route");
  assert.equal(fs.existsSync(path.join(uploadsDir, "trash.txt")), false, "legacy restore GET leaves item in trash");
  const restoreWithoutCsrf = await request(port, `/trash/${JSON.parse(trashed.body).trashItem.id}/restore`, {
    method: "POST",
    headers: { cookie: session.cookie },
  });
  assert.equal(restoreWithoutCsrf.status, 403);
  assert.equal(fs.existsSync(path.join(uploadsDir, "trash.txt")), false);
  const restored = await request(port, `/trash/${JSON.parse(trashed.body).trashItem.id}/restore`, {
    method: "POST",
    headers: postHeaders,
  });
  assert.equal(restored.status, 200, restored.body);
  assert.equal(fs.readFileSync(path.join(uploadsDir, "trash.txt"), "utf8"), "trash fixture\n");
  const pending = JSON.parse(fs.readFileSync(pendingFile, "utf8"));
  assert.deepEqual(Object.keys(pending), []);

  const events = JSON.parse(fs.readFileSync(path.join(dataDir, "audit-logs.json"), "utf8")).logs.map((entry) => entry.eventType);
  assert.ok(events.includes("file.approve"));
  assert.ok(events.includes("file.reject"));
});

test("local-storage GET version history and pending listing do not initialize or repair authoritative metadata", { timeout: 45_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-safe-get-state-"));
  const dataDir = path.join(directory, "data");
  const tempDir = path.join(directory, "temp");
  const uploadsDir = path.join(directory, "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(tempDir, { recursive: true });
  fs.mkdirSync(uploadsDir, { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "admin", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {}, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(uploadsDir, "legacy.txt"), "existing file without version metadata\n");

  const port = await getUnusedPort();
  const jwtSecret = crypto.randomBytes(48).toString("base64url");
  const env = { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: jwtSecret, TRASH_ENABLED: "true", CLOUD_STORAGE_PROVIDER: "local" };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  t.after(async () => { await stop(child); fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); });
  assert.equal((await waitForServer(port, child)).status, 200);

  const body = JSON.stringify({ username: "admin", password });
  const loggedIn = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(loggedIn.status, 200);
  const cookies = loggedIn.headers["set-cookie"].map((cookie) => cookie.split(";", 1)[0]);
  const session = { cookie: cookies.join("; "), csrf: cookies.find((cookie) => cookie.startsWith("rootark_csrf=")).split("=", 2)[1] };
  const expiredFileName = "expired-after-startup.txt";
  const expiredFilePath = path.join(uploadsDir, expiredFileName);
  fs.writeFileSync(expiredFilePath, "expiry fixture remains until scheduled cleanup\n");
  const expirationsPath = path.join(dataDir, "file-expirations.json");
  fs.writeFileSync(expirationsPath, JSON.stringify({
    [`root/${expiredFileName}`]: { folderId: "root", fileName: expiredFileName, expiresAt: new Date(Date.now() - 60_000).toISOString() },
  }));

  const passiveGet = await request(port, "/auth/me", { headers: { cookie: session.cookie, origin: "https://attacker.invalid" } });
  assert.equal(passiveGet.status, 200, passiveGet.body);
  assert.equal(fs.readFileSync(expiredFilePath, "utf8"), "expiry fixture remains until scheduled cleanup\n");
  assert.ok(JSON.parse(fs.readFileSync(expirationsPath, "utf8"))[`root/${expiredFileName}`]);

  const versionsFile = path.join(dataDir, "file-versions.json");
  const versionsBefore = fs.readFileSync(versionsFile, "utf8");

  const versions = await request(port, "/versions/legacy.txt?folderId=root", { headers: { cookie: session.cookie, origin: "https://attacker.invalid" } });
  assert.equal(versions.status, 200, versions.body);
  assert.equal(JSON.parse(versions.body).currentVersion, 0);
  assert.equal(fs.readFileSync(versionsFile, "utf8"), versionsBefore);

  const initializeWithoutCsrf = await request(port, "/versions/legacy.txt/initialize?folderId=root", { method: "POST", headers: { cookie: session.cookie } });
  assert.equal(initializeWithoutCsrf.status, 403);
  assert.equal(fs.readFileSync(versionsFile, "utf8"), versionsBefore);
  const initialized = await request(port, "/versions/legacy.txt/initialize?folderId=root", {
    method: "POST",
    headers: { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf },
  });
  assert.equal(initialized.status, 200, initialized.body);
  assert.equal(JSON.parse(initialized.body).currentVersion, 1);

  const compressedPath = path.join(tempDir, "legacy-pending.txt");
  const compressedBytes = zlib.gzipSync(Buffer.from("recovered pending upload\n"));
  fs.writeFileSync(compressedPath, compressedBytes);
  const pending = await request(port, "/pending?folderId=root", { headers: { cookie: session.cookie, origin: "https://attacker.invalid" } });
  assert.equal(pending.status, 200, pending.body);
  assert.deepEqual(fs.readFileSync(compressedPath), compressedBytes);

  const expiredLinkToken = crypto.randomBytes(24).toString("hex");
  const publicLinksPath = path.join(dataDir, "public-links.json");
  fs.writeFileSync(publicLinksPath, JSON.stringify({
    [expiredLinkToken]: { fileName: "legacy.txt", folderId: "root", expiresAt: new Date(Date.now() - 60_000).toISOString(), activeViewers: {} },
  }));
  const list = await request(port, "/list?folderId=root", { headers: { cookie: session.cookie, origin: "https://attacker.invalid" } });
  assert.equal(list.status, 200, list.body);
  assert.ok(JSON.parse(fs.readFileSync(publicLinksPath, "utf8"))[expiredLinkToken], "GET file listing does not prune persisted share state");

  const repairWithoutCsrf = await request(port, "/pending/repair?folderId=root", { method: "POST", headers: { cookie: session.cookie } });
  assert.equal(repairWithoutCsrf.status, 403);
  assert.deepEqual(fs.readFileSync(compressedPath), compressedBytes);
  const repair = await request(port, "/pending/repair?folderId=root", {
    method: "POST",
    headers: { cookie: session.cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": session.csrf },
  });
  assert.equal(repair.status, 200, repair.body);
  assert.equal(fs.readFileSync(compressedPath, "utf8"), "recovered pending upload\n");
});
