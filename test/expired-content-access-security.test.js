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

async function waitForServer(port, child) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error("disposable server exited");
    try { return await request(port, "/login.html"); } catch { await new Promise((resolve) => setTimeout(resolve, 50)); }
  }
  throw new Error("disposable server did not start");
}

function stop(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("expired cached files and folders are denied across direct, preview, token, list, and share reads", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-expired-read-"));
  const dataDir = path.join(directory, "data");
  const uploadsDir = path.join(directory, "uploads");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(uploadsDir, "dead"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(path.join(ROOT, "public"), path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  const shareToken = "a".repeat(48);
  const fileName = "expired-cache.txt";
  const folderFileName = "inside-expired-folder.txt";
  const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  const past = new Date(Date.now() - 60 * 1000).toISOString();
  const filePath = path.join(uploadsDir, fileName);
  fs.writeFileSync(filePath, "DISPOSABLE EXPIRED FILE CONTENT");
  fs.writeFileSync(path.join(uploadsDir, "dead", folderFileName), "DISPOSABLE EXPIRED FOLDER CONTENT");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "tester", password: bcrypt.hashSync(password, 10), role: "admin", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
    { id: "dead", name: "Expired folder", createdBy: "tester", allowedUsers: ["tester"], isRoot: false, expiresAt: past },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    [`root/${fileName}`]: { public: false, owner: "tester", users: {} },
    [`dead/${folderFileName}`]: { public: false, owner: "tester", users: {} },
  }));
  fs.writeFileSync(path.join(dataDir, "file-expirations.json"), JSON.stringify({
    [`root/${fileName}`]: { folderId: "root", fileName, expiresAt: future },
  }));
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [shareToken]: {
      fileName,
      folderId: "root",
      createdAt: new Date().toISOString(),
      expiresAt: future,
      createdBy: "tester",
      views: 0,
      maxViews: 0,
      downloads: 0,
      maxDownloads: 0,
      passwordHash: "",
      activeViewers: {},
    },
  }));

  const port = await getUnusedPort();
  const env = { ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test", JWT_SECRET: crypto.randomBytes(48).toString("base64url"), TOTP_POLICY: "optional", TRASH_ENABLED: "true" };
  for (const key of Object.keys(env)) if (/^(AWS_|GOOGLE_DRIVE_)/.test(key)) delete env[key];
  delete env.CLOUD_STORAGE_PROVIDER;
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  t.after(async () => {
    await stop(child);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });

  assert.equal((await waitForServer(port, child)).status, 200);
  const loginBody = JSON.stringify({ username: "tester", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const body = JSON.stringify({ name: fileName, folderId: "root" });
  const openToken = await request(port, "/file-open-token", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.equal(openToken.status, 200, openToken.body);
  const openUrl = JSON.parse(openToken.body).url;

  const expirationsPath = path.join(dataDir, "file-expirations.json");
  const expirations = JSON.parse(fs.readFileSync(expirationsPath, "utf8"));
  expirations[`root/${fileName}`].expiresAt = past;
  fs.writeFileSync(expirationsPath, JSON.stringify(expirations));

  const directRead = await request(port, `/files/${encodeURIComponent(fileName)}?folderId=root`, { headers: { cookie } });
  assert.notEqual(directRead.status, 200, "an expired file with a local cache must not be served");
  assert.equal(directRead.body.includes("DISPOSABLE EXPIRED FILE CONTENT"), false);

  const listing = await request(port, "/list?folderId=root", { headers: { cookie } });
  assert.equal(listing.status, 200, listing.body);
  assert.equal(JSON.parse(listing.body).some((file) => file.name === fileName), false, "expired files are omitted from listings");

  const preview = await request(port, `/preview/text/public/${encodeURIComponent(fileName)}?folderId=root`, { headers: { cookie } });
  assert.notEqual(preview.status, 200, "preview must reject expired local content");
  assert.equal(preview.body.includes("DISPOSABLE EXPIRED FILE CONTENT"), false);
  const remintToken = await request(port, "/file-open-token", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
    body,
  });
  assert.notEqual(remintToken.status, 200, "an expired file cannot mint a new open token");

  const redeemedToken = await request(port, openUrl, { headers: { cookie } });
  assert.notEqual(redeemedToken.status, 200, "a token minted before expiry must stop serving the cached file after expiry");
  assert.equal(redeemedToken.body.includes("DISPOSABLE EXPIRED FILE CONTENT"), false);

  const shareViewBody = "{}";
  const shareView = await request(port, `/share/${shareToken}/view`, {
    method: "POST",
    headers: { origin: `http://127.0.0.1:${port}`, "content-type": "application/json", "content-length": Buffer.byteLength(shareViewBody) },
    body: shareViewBody,
  });
  assert.notEqual(shareView.status, 200, "a valid share link must stop granting access when its file expires");
  const shareFile = await request(port, `/share/${shareToken}/file`, "POST", {
    origin: `http://127.0.0.1:${port}`,
  });
  assert.notEqual(shareFile.status, 200, "public share file route must reject expired content");
  assert.equal(shareFile.body.includes("DISPOSABLE EXPIRED FILE CONTENT"), false);
  const sharePreview = await request(port, `/share/${shareToken}/preview`, {
    method: "POST",
    headers: { origin: `http://127.0.0.1:${port}` },
  });
  assert.notEqual(sharePreview.status, 200, "public share preview POST must reject expired content");
  assert.equal(sharePreview.body.includes("DISPOSABLE EXPIRED FILE CONTENT"), false);

  const folders = await request(port, "/folders", { headers: { cookie } });
  assert.equal(folders.status, 200, folders.body);
  assert.equal(JSON.parse(folders.body).some((folder) => folder.id === "dead"), false, "expired folders are omitted from folder navigation");
  const expiredFolderList = await request(port, `/list?folderId=dead`, { headers: { cookie } });
  assert.notEqual(expiredFolderList.status, 200, "an expired folder cannot be listed");
  const expiredFolderRead = await request(port, `/files/${encodeURIComponent(folderFileName)}?folderId=dead`, { headers: { cookie } });
  assert.notEqual(expiredFolderRead.status, 200, "an expired folder cannot serve cached files");
  assert.equal(expiredFolderRead.body.includes("DISPOSABLE EXPIRED FOLDER CONTENT"), false);
});
