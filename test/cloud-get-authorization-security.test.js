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
const PUBLIC = path.join(ROOT, "public");
const OBJECTS = new Map([
  ["rootark/uploads/root/private.txt", Buffer.from("private cloud fixture")],
  ["rootark/uploads/root/private.txt.v1", Buffer.from("private stored version fixture")],
  ["rootark/uploads/root/orphan-private.txt.v1", Buffer.from("orphan stored version fixture")],
  ["rootark/uploads/root/history-only.txt.v9", Buffer.from("history-only orphan version fixture")],
  ["rootark/uploads/root/public.txt", Buffer.from("public cloud fixture")],
  ["rootark/uploads/root/public.txt.v1", Buffer.from("public stored version fixture")],
  ["rootark/uploads/root/budget.v2", Buffer.from("ordinary cloud suffix fixture")],
  ["rootark/uploads/root/private.txt.v7", Buffer.from("ordinary suffix with distinct ACL")],
  ["rootark/uploads/root/private.txt.v8", Buffer.from("ordinary suffix with primary history")],
  ["rootark/uploads/root/denied.v2", Buffer.from("private ordinary suffix fixture")],
  ["rootark/uploads/root/encrypted.txt", Buffer.from("encrypted cloud fixture")],
  ["rootark/uploads/root/encrypted.txt.v1", Buffer.from("encrypted version fixture")],
  ["rootark/temp/root/private-pending.txt", Buffer.from("private pending fixture")],
  ["rootark/temp/root/orphan-pending.txt", Buffer.from("orphan pending fixture")],
]);

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

function startS3Fixture() {
  const getObjects = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    const pathname = decodeURIComponent(url.pathname);
    const key = pathname.replace(/^\/fixture-bucket\//, "");
    if (req.method === "GET" && url.searchParams.get("list-type") === "2") {
      const prefix = url.searchParams.get("prefix") || "";
      const matches = Array.from(OBJECTS.keys()).filter((objectKey) => objectKey.startsWith(prefix));
      const contents = matches.map((objectKey) => `<Contents><Key>${objectKey}</Key><LastModified>2026-10-05T00:00:00.000Z</LastModified><ETag>&quot;fixture&quot;</ETag><Size>${OBJECTS.get(objectKey).length}</Size></Contents>`).join("");
      res.writeHead(200, { "content-type": "application/xml" });
      return res.end(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><Prefix>${prefix}</Prefix><KeyCount>${matches.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
    }
    if (req.method === "GET" && OBJECTS.has(key)) {
      getObjects.push(key);
      res.writeHead(200, { "content-length": OBJECTS.get(key).length });
      return res.end(OBJECTS.get(key));
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code><Message>Not found</Message></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, getObjects }));
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
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  child.kill();
  return new Promise((resolve) => child.once("exit", resolve));
}

test("cloud-backed GET routes authorize files before cache hydration", { timeout: 60_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-get-acl-"));
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.writeFileSync(path.join(directory, "uploads", "notes.v2"), "ordinary local suffix fixture");
  fs.writeFileSync(path.join(directory, "uploads", "legacy.v9"), "legacy file without ACL fixture");
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    "root/private.txt": { public: false, owner: "owner", users: {} },
    "root/orphan-private.txt": { public: false, owner: "owner", users: {} },
    "root/public.txt": { public: true, owner: "viewer", users: {} },
    "root/public.txt.v1": { public: true, owner: "viewer", users: {} },
    "root/budget.v2": { public: false, owner: "viewer", users: {} },
    "root/notes.v2": { public: false, owner: "viewer", users: {} },
    "root/private.txt.v7": { public: false, owner: "viewer", users: {} },
    "root/denied.v2": { public: false, owner: "owner", users: {} },
  }));
  fs.writeFileSync(path.join(dataDir, "file-versions.json"), JSON.stringify({
    "root/history-only.txt": { currentVersion: 1, versions: [
      { version: 1, storedAs: "history-only.txt", size: 0 },
    ] },
    "root/private.txt.v8": { currentVersion: 1, versions: [
      { version: 1, storedAs: "private.txt.v8", size: OBJECTS.get("rootark/uploads/root/private.txt.v8").length },
    ] },
    "root/public.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "public.txt.v1", size: OBJECTS.get("rootark/uploads/root/public.txt.v1").length },
      { version: 2, storedAs: "public.txt", size: OBJECTS.get("rootark/uploads/root/public.txt").length },
    ] },
    "root/private.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "private.txt.v1", size: OBJECTS.get("rootark/uploads/root/private.txt.v1").length },
      { version: 2, storedAs: "private.txt", size: OBJECTS.get("rootark/uploads/root/private.txt").length },
    ] },
    "root/encrypted.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "encrypted.txt.v1", size: OBJECTS.get("rootark/uploads/root/encrypted.txt.v1").length },
      { version: 2, storedAs: "encrypted.txt", size: OBJECTS.get("rootark/uploads/root/encrypted.txt").length },
    ] },
  }));
  fs.writeFileSync(path.join(dataDir, "encrypted-files.json"), JSON.stringify({
    "root/encrypted.txt": { encryptionLevel: "server-key", originalFilename: "encrypted.txt" },
  }));
  const encryptedShareToken = "a".repeat(48);
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [encryptedShareToken]: {
      fileName: "encrypted.txt", folderId: "root", createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), createdBy: "owner",
      views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, passwordHash: "", activeViewers: {},
    },
  }));
  const cloud = await startS3Fixture();
  const port = await getUnusedPort();
  const env = {
    ...process.env,
    PORT: String(port),
    DB_ENABLED: "false",
    NODE_ENV: "test",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"),
    TOTP_POLICY: "optional",
    CLOUD_STORAGE_PROVIDER: "s3",
    AWS_S3_BUCKET: "fixture-bucket",
    AWS_REGION: "us-east-1",
    AWS_ENDPOINT_URL: `http://127.0.0.1:${cloud.port}`,
    AWS_FORCE_PATH_STYLE: "true",
    AWS_ACCESS_KEY_ID: "fixture-access-key",
    AWS_SECRET_ACCESS_KEY: "fixture-secret-key",
    WEBDAV_ENABLED: "true",
  };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  t.after(async () => {
    await stop(child);
    await new Promise((resolve) => cloud.server.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  assert.equal((await waitForServer(port, child)).status, 200);

  const body = JSON.stringify({ username: "viewer", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, body });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const mutate = (requestPath, method, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method,
      headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };

  const list = await request(port, "/list", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(list.status, 200, list.body);
  assert.deepEqual(JSON.parse(list.body).map((file) => file.name).sort(), ["budget.v2", "encrypted.txt", "legacy.v9", "notes.v2", "private.txt.v7", "private.txt.v8", "public.txt"]);
  assert.deepEqual(cloud.getObjects, [], "listing reads provider metadata without materializing file bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "budget.v2")), false, "ordinary cloud file is visible before hydration");

  const ordinaryCloudFile = await request(port, "/files/budget.v2", { headers: { cookie } });
  assert.equal(ordinaryCloudFile.status, 200, "an ordinary cloud-only .vN file must be downloadable");
  assert.equal(ordinaryCloudFile.body, "ordinary cloud suffix fixture");
  const ordinaryLocalFile = await request(port, "/files/notes.v2", { headers: { cookie } });
  assert.equal(ordinaryLocalFile.status, 200, "an ordinary local .vN file must be downloadable");
  assert.equal(ordinaryLocalFile.body, "ordinary local suffix fixture");
  const legacyFile = await request(port, "/files/legacy.v9", { headers: { cookie } });
  assert.equal(legacyFile.status, 200, "unmatched .vN names retain legacy default-public access");
  assert.equal(legacyFile.body, "legacy file without ACL fixture");
  const distinctAclFile = await request(port, "/files/private.txt.v7", { headers: { cookie } });
  assert.equal(distinctAclFile.status, 200, "a primary .vN file uses its own ACL even when the base name is private");
  assert.equal(distinctAclFile.body, "ordinary suffix with distinct ACL");
  const distinctHistoryFile = await request(port, "/files/private.txt.v8", { headers: { cookie } });
  assert.equal(distinctHistoryFile.status, 200, "a .vN primary history is independent from the unsuffixed file");
  assert.equal(distinctHistoryFile.body, "ordinary suffix with primary history");
  const deniedSuffixFile = await request(port, "/files/denied.v2", { headers: { cookie } });
  assert.equal(deniedSuffixFile.status, 403, "ordinary .vN names retain file authorization");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/denied.v2"), false, JSON.stringify(cloud.getObjects));
  const ordinaryOpenToken = await mutate("/file-open-token", "POST", { name: "budget.v2" });
  assert.equal(ordinaryOpenToken.status, 200, ordinaryOpenToken.body);
  const storedPublicVersion = await request(port, "/files/public.txt.v1", { headers: { cookie } });
  assert.equal(storedPublicVersion.status, 404, "version metadata hides historical bytes even with an alias ACL");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/public.txt.v1"), false);
  cloud.getObjects.length = 0;

  const privateFile = await request(port, "/files/private.txt", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(privateFile.status, 403, privateFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "denied direct GET never downloads the object");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "private.txt")), false, "denied direct GET never materializes the object");

  const privateVersion = await request(port, "/files/private.txt.v1", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(privateVersion.status, 404, privateVersion.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt.v1"), false, "stored versions cannot bypass the primary file ACL");

  const orphanVersion = await request(port, "/files/orphan-private.txt.v1", { headers: { cookie } });
  assert.equal(orphanVersion.status, 404, orphanVersion.body);
  const orphanOpenToken = await mutate("/file-open-token", "POST", { name: "orphan-private.txt.v1" });
  assert.equal(orphanOpenToken.status, 404, orphanOpenToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/orphan-private.txt.v1"), false, "ownerless version aliases never hydrate");
  const historyOnlyOrphan = await request(port, "/files/history-only.txt.v9", { headers: { cookie } });
  assert.equal(historyOnlyOrphan.status, 404, "primary history also identifies orphan aliases without a primary ACL");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/history-only.txt.v9"), false);

  const encryptedFile = await request(port, "/files/encrypted.txt", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(encryptedFile.status, 403, encryptedFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt"), false, "direct file GET rejects encrypted objects before cache hydration");

  const encryptedVersion = await request(port, "/download/encrypted.txt/v/1", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(encryptedVersion.status, 403, encryptedVersion.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt.v1"), false, "encrypted version GET rejects before cache hydration");

  const encryptedShare = await request(port, `/share/${encryptedShareToken}/view`, {
    method: "POST",
    headers: { origin: `http://127.0.0.1:${port}` },
  });
  assert.equal(encryptedShare.status, 404, encryptedShare.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt"), false, "legacy encrypted share rejects before cache hydration");

  const versionTokenBody = JSON.stringify({ name: "encrypted.txt", version: 1 });
  const encryptedVersionToken = await request(port, "/version-open-token", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(versionTokenBody) },
    body: versionTokenBody,
  });
  assert.equal(encryptedVersionToken.status, 403, encryptedVersionToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/encrypted.txt.v1"), false, "encrypted version token cannot materialize a rejected version");

  const deniedOpenTokenBody = JSON.stringify({ name: "private.txt" });
  const deniedOpenToken = await request(port, "/file-open-token", {
    method: "POST",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": Buffer.byteLength(deniedOpenTokenBody) },
    body: deniedOpenTokenBody,
  });
  assert.equal(deniedOpenToken.status, 403, deniedOpenToken.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "unauthorized open-token request never materializes the object");

  const search = await request(port, "/files/search?q=private", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(search.status, 200, search.body);
  assert.deepEqual(JSON.parse(search.body).map((file) => file.name).sort(), ["private.txt.v7", "private.txt.v8"]);
  assert.deepEqual(cloud.getObjects, [], "search reads provider metadata without materializing file bytes");

  const webDavAuth = `Basic ${Buffer.from(`viewer:${password}`).toString("base64")}`;
  const propfind = await request(port, "/dav", { method: "PROPFIND", headers: { cookie, authorization: webDavAuth, depth: "1" } });
  assert.equal(propfind.status, 207, propfind.body);
  assert.equal(propfind.body.includes("encrypted.txt"), false, "WebDAV does not expose encrypted files");
  assert.equal(propfind.body.includes("private.txt.v1"), false, "WebDAV hides stored versions");
  assert.equal(propfind.body.includes("public.txt.v1"), false, "WebDAV hides versions recognized by metadata");
  assert.equal(propfind.body.includes("budget.v2"), true, "WebDAV lists ordinary suffix names");
  assert.equal(propfind.body.includes("notes.v2"), true, "WebDAV lists ordinary local suffix names");
  assert.deepEqual(cloud.getObjects, [], "WebDAV listing does not hydrate cloud objects");

  const fileAccess = await request(port, "/file-access?name=public.txt", { headers: { cookie } });
  assert.equal(fileAccess.status, 200, fileAccess.body);
  const temporary = await mutate("/file-temporary", "PUT", { name: "public.txt", durationAmount: 1, durationUnit: "hours" });
  assert.equal(temporary.status, 200, temporary.body);
  const share = await mutate("/share", "POST", { name: "public.txt", expiresInMinutes: 60 });
  assert.equal(share.status, 201, share.body);
  const updatedAccess = await mutate("/file-access", "PUT", { name: "public.txt", public: true, users: { viewer: { edit: true } } });
  assert.equal(updatedAccess.status, 200, updatedAccess.body);
  const deniedTemporary = await mutate("/file-temporary", "PUT", { name: "private.txt", durationAmount: 1, durationUnit: "hours" });
  assert.equal(deniedTemporary.status, 403, deniedTemporary.body);
  const deniedShare = await mutate("/share", "POST", { name: "private.txt", expiresInMinutes: 60 });
  assert.equal(deniedShare.status, 403, deniedShare.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "denied metadata actions do not hydrate private objects");
  assert.deepEqual(cloud.getObjects, [], "metadata-only file actions do not download cloud bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "public.txt")), false, "metadata-only file actions do not create a local cache");
});
