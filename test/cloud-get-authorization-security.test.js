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
const { createCloudTempMutationQueue } = require("../services/cloudTempMutationQueue");

const ROOT = path.resolve(__dirname, "..");
const SERVER = path.join(ROOT, "server.js");
const PUBLIC = path.join(ROOT, "public");
const CLOUD_METADATA_REQUEST_LIMIT = 30;
const OBJECTS = new Map([
  ["rootark/uploads/root/private.txt", Buffer.from("private cloud fixture")],
  ["rootark/uploads/root/private.txt.v1", Buffer.from("private stored version fixture")],
  ["rootark/uploads/root/orphan-private.txt.v1", Buffer.from("orphan stored version fixture")],
  ["rootark/uploads/root/history-only.txt.v9", Buffer.from("history-only orphan version fixture")],
  ["rootark/uploads/root/version-primary.txt", Buffer.from("authorized version primary fixture")],
  ["rootark/uploads/root/cloud-only-version-init.txt", Buffer.from("cloud-only version initialization fixture")],
  ["rootark/uploads/root/version-primary.txt.v1", Buffer.from("suppressed provider-only version fixture")],
  ["rootark/uploads/root/version-primary.txt.v2", Buffer.from("authorized stored version fixture")],
  ["rootark/uploads/root/version-race.txt.v1", Buffer.from("version download race fixture")],
  ["rootark/uploads/root/token-race.txt.v1", Buffer.from("version token race fixture")],
  ["rootark/uploads/root/restore-race.txt.v1", Buffer.from("version restore race fixture")],
  ["rootark/uploads/root/issued-token-race.txt.v1", Buffer.from("previously issued version token fixture")],
  ["rootark/uploads/root/webdav-session-revocation.txt", Buffer.from("WebDAV session revocation fixture")],
  ["rootark/uploads/root/webdav-listfiles-revocation.txt", Buffer.from("WebDAV listFiles revocation fixture")],
  ["rootark/uploads/root/webdav-acl-revocation.txt", Buffer.from("WebDAV ACL revocation fixture")],
  ["rootark/uploads/root/public.txt", Buffer.from("public cloud fixture")],
  ["rootark/uploads/root/share-download-race.txt", Buffer.from("public share download race fixture")],
  ["rootark/uploads/root/share-trash-race.txt", Buffer.from("share trash race fixture")],
  ["rootark/uploads/root/access-trash-race.txt", Buffer.from("access trash race fixture")],
  ["rootark/uploads/root/encrypted-grant-trash-race.txt", Buffer.from("encrypted grant trash race fixture")],
  ["rootark/uploads/root/public.txt.v1", Buffer.from("public stored version fixture")],
  ["rootark/uploads/root/ambiguous-orphan.v1", Buffer.from("unclassified stored version fixture")],
  ["rootark/uploads/root/budget.v2", Buffer.from("ordinary cloud suffix fixture")],
  ["rootark/uploads/root/private.txt.v7", Buffer.from("ordinary suffix with distinct ACL")],
  ["rootark/uploads/root/private.txt.v8", Buffer.from("ordinary suffix with primary history")],
  ["rootark/uploads/root/denied.v2", Buffer.from("private ordinary suffix fixture")],
  ["rootark/uploads/root/encrypted.txt", Buffer.from("encrypted cloud fixture")],
  ["rootark/uploads/root/encrypted.txt.v1", Buffer.from("encrypted version fixture")],
  ["rootark/temp/root/private-pending.txt", Buffer.from("private pending fixture")],
  ["rootark/temp/root/orphan-pending.txt", Buffer.from("orphan pending fixture")],
  ["rootark/temp/root/restore-orphan-pending.txt", Buffer.from("post-backup pending bytes")],
  ["rootark/uploads/root/cloud-limit.txt", Buffer.from("cloud cache miss limiter fixture")],
  ["rootark/uploads/root/cloud-open-token-limit.txt", Buffer.from("cloud open token limiter fixture")],
  ["rootark/uploads/root/cloud-open-token-limit.txt.v1", Buffer.from("cloud version open token limiter fixture")],
  ["rootark/uploads/root/restore-limit.txt", Buffer.from("current restore limiter fixture")],
  ["rootark/uploads/root/restore-limit.txt.v1", Buffer.from("old restore limiter fixture")],
  ["rootark/uploads/root/Case-Orphan.TXT", Buffer.from("suppressed case-alias provider bytes")],
  ["rootark/uploads/root/case-orphan.txt", Buffer.from("distinct lowercase provider bytes")],
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

async function waitForNoActiveRequests(directory, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!fs.existsSync(directory) || fs.readdirSync(directory).length === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const remaining = fs.existsSync(directory) ? fs.readdirSync(directory) : [];
  throw new Error(`active request leases did not clear within ${timeoutMs}ms; remaining leases: ${remaining.join(", ") || "none"}`);
}

async function waitForNoCloudUploadMutationRecords(directory, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const records = fs.existsSync(directory)
      ? fs.readdirSync(directory).filter((name) => /^[a-f0-9]{64}\.json$/.test(name))
      : [];
    if (records.length === 0) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`cloud upload mutation records did not drain within ${timeoutMs}ms`);
}

async function waitForActiveRequestCount(directory, expectedCount, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const count = fs.existsSync(directory) ? fs.readdirSync(directory).length : 0;
    if (count >= expectedCount) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const count = fs.existsSync(directory) ? fs.readdirSync(directory).length : 0;
  throw new Error(`expected at least ${expectedCount} active request leases, observed ${count}`);
}

test("active request lease wait allows delayed teardown and reports remaining leases", { timeout: 20_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-active-request-lease-wait-"));
  const leasePath = path.join(directory, "fixture-lease.json");
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.writeFileSync(leasePath, "{}\n");
  const delayedRelease = setTimeout(() => fs.rmSync(leasePath, { force: true }), 5_100);
  try {
    await waitForNoActiveRequests(directory);
  } finally {
    clearTimeout(delayedRelease);
  }

  fs.writeFileSync(leasePath, "{}\n");
  await assert.rejects(waitForNoActiveRequests(directory, 10), /remaining leases: fixture-lease\.json/);
});

function startS3Fixture() {
  const getObjects = [];
  const putObjects = [];
  const deleteObjects = [];
  const failedDeleteKeys = new Set();
  const listRequests = [];
  const getGates = new Map();
  const listGates = new Map();
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://fixture.invalid");
    const pathname = decodeURIComponent(url.pathname);
    const key = pathname.replace(/^\/fixture-bucket\//, "");
    if (req.method === "GET" && url.searchParams.get("list-type") === "2") {
      listRequests.push(url.searchParams.get("prefix") || "");
      const prefix = url.searchParams.get("prefix") || "";
      const send = () => {
        const matches = Array.from(OBJECTS.keys()).filter((objectKey) => objectKey.startsWith(prefix));
        const contents = matches.map((objectKey) => `<Contents><Key>${objectKey}</Key><LastModified>2026-10-05T00:00:00.000Z</LastModified><ETag>&quot;fixture&quot;</ETag><Size>${OBJECTS.get(objectKey).length}</Size></Contents>`).join("");
        res.writeHead(200, { "content-type": "application/xml" });
        res.end(`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>fixture-bucket</Name><Prefix></Prefix><KeyCount>${matches.length}</KeyCount><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>${contents}</ListBucketResult>`);
      };
      const gate = listGates.get(prefix)?.shift();
      if (gate) { gate.markStarted(); return gate.released.then(send); }
      return send();
    }
    if (req.method === "GET" && OBJECTS.has(key)) {
      getObjects.push(key);
      const send = () => { res.writeHead(200, { "content-length": OBJECTS.get(key).length }); res.end(OBJECTS.get(key)); };
      const gate = getGates.get(key)?.shift();
      if (gate) { gate.markStarted(); return gate.released.then(send); }
      return send();
    }
    if (req.method === "PUT") {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        putObjects.push(key);
        OBJECTS.set(key, Buffer.concat(chunks));
        res.writeHead(200, { etag: '"fixture"' });
        res.end();
      });
      return;
    }
    if (req.method === "DELETE") {
      deleteObjects.push(key);
      if (failedDeleteKeys.has(key)) {
        res.writeHead(503);
        res.end();
      } else {
        OBJECTS.delete(key);
        res.writeHead(204);
        res.end();
      }
      return;
    }
    res.writeHead(404, { "content-type": "application/xml" });
    res.end("<Error><Code>NoSuchKey</Code><Message>Not found</Message></Error>");
  });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve({
      server,
      port: server.address().port,
      getObjects,
      putObjects,
      deleteObjects,
      failDelete(key) { failedDeleteKeys.add(key); },
      listRequests,
      block(map, key, skippedRequests = 0) {
        let markStarted;
        let release;
        const gate = {
          started: new Promise((resolveStarted) => { markStarted = resolveStarted; }),
          released: new Promise((resolveReleased) => { release = resolveReleased; }),
          markStarted: () => markStarted(),
          release: () => release(),
        };
        const queue = map.get(key) || [];
        for (let index = 0; index < skippedRequests; index += 1) queue.push(null);
        queue.push(gate);
        map.set(key, queue);
        return gate;
      },
      blockGet(key) { return this.block(getGates, key); },
      blockList(prefix, skippedRequests = 0) { return this.block(listGates, prefix, skippedRequests); },
    }));
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

test("cloud-backed file routes authorize access and bound repeated metadata listings", { timeout: 60_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-get-acl-"));
  const unregisteredMagicNames = ["constructor", "toString", "__proto__"];
  for (const name of unregisteredMagicNames) OBJECTS.set(`rootark/temp/root/${name}`, Buffer.from("unregistered pending fixture"));
  t.after(() => {
    for (const name of unregisteredMagicNames) OBJECTS.delete(`rootark/temp/root/${name}`);
  });
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.writeFileSync(path.join(directory, "uploads", "notes.v2"), "ordinary local suffix fixture");
  fs.writeFileSync(path.join(directory, "uploads", "legacy.v9"), "legacy file without ACL fixture");
  fs.writeFileSync(path.join(directory, "uploads", "restore-limit.txt"), "current restore limiter fixture");
  fs.writeFileSync(path.join(directory, "uploads", "restore-limit.txt.v1"), "old restore limiter fixture");
  fs.writeFileSync(path.join(directory, "uploads", "version-primary.txt"), "authorized version primary fixture");
  fs.writeFileSync(path.join(directory, "uploads", "Case-Orphan.TXT"), "stale mixed-case orphan cache");
  OBJECTS.set("rootark/uploads/root/restore-orphan.txt", Buffer.from("post-backup provider bytes"));
  const orphanStatePath = path.join(dataDir, ".rootark-restore-provider-orphans-state.json");
  fs.writeFileSync(path.join(dataDir, ".rootark-restore-provider-orphans.json"), JSON.stringify({
    version: 1,
    providerInventory: { state: "known" },
    objects: [
      { area: "uploads", folderId: "root", name: "restore-orphan.txt" },
      { area: "uploads", folderId: "root", name: "version-primary.txt.v1" },
      { area: "uploads", folderId: "root", name: "Case-Orphan.TXT" },
    ],
  }));
  fs.writeFileSync(orphanStatePath, JSON.stringify({ version: 1, providerInventory: { state: "known" } }));
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "viewer", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true }, sessionVersion: 0 },
    { username: "editor", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, upload: true }, sessionVersion: 0 },
    { username: "owner", password: bcrypt.hashSync(password, 10), role: "admin", permissions: {}, sessionVersion: 0 },
    { username: "cache-limiter", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
    { username: "restore-limiter", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify({
    "root/private.txt": { public: false, owner: "owner", users: {} },
    "root/revoke-download.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/file-access-session-revocation.txt": { public: false, owner: "owner", users: {} },
    "root/share-session-revocation.txt": { public: false, owner: "owner", users: {} },
    "root/share-race-first.txt": { public: false, owner: "owner", users: {} },
    "root/share-race-second.txt": { public: false, owner: "owner", users: {} },
    "root/encrypted-grant-session-revocation.txt": { public: false, owner: "owner", users: {} },
    "root/revoke-preview.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/revoke-share.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/revoke-version.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/revoke-version-token.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/revoke-encrypted.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/revoke-webdav.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/webdav-session-revocation.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/webdav-listfiles-revocation.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/webdav-acl-revocation.txt": { public: false, owner: "owner", users: { viewer: { read: true, edit: false } } },
    "root/session-target.txt": { public: false, owner: "owner", users: { editor: { read: true, edit: true } } },
    "root/orphan-private.txt": { public: false, owner: "owner", users: {} },
    "root/public.txt": { public: true, owner: "viewer", users: {} },
    "root/public.txt.v1": { public: true, owner: "viewer", users: {} },
    "root/share-trash-race.txt": { public: false, owner: "owner", users: {} },
    "root/access-trash-race.txt": { public: false, owner: "owner", users: {} },
    "root/encrypted-grant-trash-race.txt": { public: false, owner: "owner", users: {} },
    "root/budget.v2": { public: false, owner: "viewer", users: {} },
    "root/notes.v2": { public: false, owner: "viewer", users: {} },
    "root/private.txt.v7": { public: false, owner: "viewer", users: {} },
    "root/denied.v2": { public: false, owner: "owner", users: {} },
    "root/cloud-limit.txt": { public: false, owner: "cache-limiter", users: {} },
    "root/cloud-open-token-limit.txt": { public: false, owner: "cache-limiter", users: {} },
    "root/local-limit.txt": { public: false, owner: "cache-limiter", users: {} },
    "root/restore-limit.txt": { public: false, owner: "restore-limiter", users: {} },
    "root/version-primary.txt": { public: false, owner: "viewer", users: { viewer: { read: true, edit: true } } },
    "root/cloud-only-version-init.txt": { public: false, owner: "viewer", users: { viewer: { read: true, edit: true } } },
    "root/restore-race.txt": { public: false, owner: "viewer", users: { viewer: { read: true, edit: true } } },
    "root/issued-token-race.txt": { public: false, owner: "viewer", users: { viewer: { read: true, edit: false } } },
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
    "root/restore-limit.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "restore-limit.txt.v1", size: OBJECTS.get("rootark/uploads/root/restore-limit.txt.v1").length },
      { version: 2, storedAs: "restore-limit.txt", size: OBJECTS.get("rootark/uploads/root/restore-limit.txt").length },
    ] },
    "root/cloud-open-token-limit.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "cloud-open-token-limit.txt.v1", size: OBJECTS.get("rootark/uploads/root/cloud-open-token-limit.txt.v1").length },
      { version: 2, storedAs: "cloud-open-token-limit.txt", size: OBJECTS.get("rootark/uploads/root/cloud-open-token-limit.txt").length },
    ] },
    "root/private.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "private.txt.v1", size: OBJECTS.get("rootark/uploads/root/private.txt.v1").length },
      { version: 2, storedAs: "private.txt", size: OBJECTS.get("rootark/uploads/root/private.txt").length },
    ] },
    "root/encrypted.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "encrypted.txt.v1", size: OBJECTS.get("rootark/uploads/root/encrypted.txt.v1").length },
      { version: 2, storedAs: "encrypted.txt", size: OBJECTS.get("rootark/uploads/root/encrypted.txt").length },
    ] },
    "root/revoke-version.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "revoke-version.txt.v1", size: 0 },
      { version: 2, storedAs: "revoke-version.txt", size: 0 },
    ] },
    "root/revoke-version-token.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "revoke-version-token.txt.v1", size: 0 },
      { version: 2, storedAs: "revoke-version-token.txt", size: 0 },
    ] },
    "root/version-primary.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "version-primary.txt.v1", size: OBJECTS.get("rootark/uploads/root/version-primary.txt.v1").length },
      { version: 2, storedAs: "version-primary.txt.v2", size: OBJECTS.get("rootark/uploads/root/version-primary.txt.v2").length },
    ] },
    "root/version-race.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "version-race.txt.v1", size: OBJECTS.get("rootark/uploads/root/version-race.txt.v1").length },
      { version: 2, storedAs: "version-race.txt", size: 0 },
    ] },
    "root/token-race.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "token-race.txt.v1", size: OBJECTS.get("rootark/uploads/root/token-race.txt.v1").length },
      { version: 2, storedAs: "token-race.txt", size: 0 },
    ] },
    "root/restore-race.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "restore-race.txt.v1", size: OBJECTS.get("rootark/uploads/root/restore-race.txt.v1").length },
      { version: 2, storedAs: "restore-race.txt", size: 0 },
    ] },
    "root/issued-token-race.txt": { currentVersion: 2, versions: [
      { version: 1, storedAs: "issued-token-race.txt.v1", size: OBJECTS.get("rootark/uploads/root/issued-token-race.txt.v1").length },
      { version: 2, storedAs: "issued-token-race.txt", size: 0 },
    ] },
  }));
  fs.writeFileSync(path.join(dataDir, "encrypted-files.json"), JSON.stringify({
    "root/encrypted.txt": { encryptionLevel: "server-key", originalFilename: "encrypted.txt" },
    "root/revoke-encrypted.txt": { encryptionLevel: "server-key", originalFilename: "revoke-encrypted.txt" },
    "root/encrypted-grant-trash-race.txt": { encryptionLevel: "server-key", originalFilename: "encrypted-grant-trash-race.txt", accessControl: { owner: "owner", authorizedUsers: [] } },
    "root/encrypted-grant-session-revocation.txt": { encryptionLevel: "server-key", originalFilename: "encrypted-grant-session-revocation.txt", accessControl: { owner: "owner", authorizedUsers: [] } },
  }));
  fs.writeFileSync(path.join(dataDir, "pending-uploads.json"), JSON.stringify({
    "root/restore-orphan-pending.txt": { fileName: "restore-orphan-pending.txt", folderId: "root", uploadedBy: "viewer", uploadedAt: new Date().toISOString() },
  }));
  fs.writeFileSync(path.join(directory, "temp", "restore-orphan-pending.txt"), "stale local pending cache");
  fs.writeFileSync(path.join(dataDir, ".rootark-restore-provider-orphans.json"), JSON.stringify({
    version: 1,
    providerInventory: { state: "known" },
    objects: [
      { area: "uploads", folderId: "root", name: "restore-orphan.txt" },
      { area: "uploads", folderId: "root", name: "version-primary.txt.v1" },
      { area: "uploads", folderId: "root", name: "Case-Orphan.TXT" },
      { area: "temp", folderId: "root", name: "restore-orphan-pending.txt" },
    ],
  }));
  fs.writeFileSync(orphanStatePath, JSON.stringify({ version: 1, providerInventory: { state: "known" } }));
  const encryptedShareToken = "a".repeat(48);
  const restoreOrphanShareToken = "b".repeat(48);
  const limitedShareDownloadToken = "c".repeat(48);
  fs.writeFileSync(path.join(dataDir, "public-links.json"), JSON.stringify({
    [encryptedShareToken]: {
      fileName: "encrypted.txt", folderId: "root", createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), createdBy: "owner",
      views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, passwordHash: "", activeViewers: {},
    },
    [restoreOrphanShareToken]: {
      fileName: "restore-orphan.txt", folderId: "root", createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), createdBy: "owner",
      views: 0, maxViews: 0, downloads: 0, maxDownloads: 0, passwordHash: "", activeViewers: {},
    },
    [limitedShareDownloadToken]: {
      fileName: "share-download-race.txt", folderId: "root", createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 60 * 60 * 1000).toISOString(), createdBy: "owner",
      views: 0, maxViews: 0, downloads: 0, maxDownloads: 1, passwordHash: "", activeViewers: {},
    },
  }));
  const cloud = await startS3Fixture();
  const port = await getUnusedPort();
  const hashCallsFile = path.join(directory, "bcrypt-hash-calls.txt");
  const preloadFile = path.join(directory, "bcrypt-hash-instrumentation.js");
  fs.writeFileSync(preloadFile, [
    'const fs = require("node:fs");',
    `const bcrypt = require(${JSON.stringify(require.resolve("bcryptjs"))});`,
    `const counterFile = ${JSON.stringify(hashCallsFile)};`,
    "const originalHashSync = bcrypt.hashSync;",
    'bcrypt.hashSync = function (...args) { fs.appendFileSync(counterFile, "1\\n"); return originalHashSync.apply(this, args); };',
  ].join("\n"));
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
    ROUTE_RATE_LIMIT_MAX: "1000",
    WEBDAV_ENABLED: "true",
    NODE_OPTIONS: [process.env.NODE_OPTIONS, `--require=${preloadFile}`].filter(Boolean).join(" "),
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
  const ownerBody = JSON.stringify({ username: "owner", password });
  const ownerLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(ownerBody) }, body: ownerBody });
  assert.equal(ownerLogin.status, 200, ownerLogin.body);
  const ownerCookies = ownerLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const ownerCookie = ownerCookies.join("; ");
  const ownerCsrf = ownerCookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const mutateAsOwner = (requestPath, method, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method,
      headers: { cookie: ownerCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": ownerCsrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };

  const concurrentShareFolderResponse = await mutateAsOwner("/folders", "POST", { name: "share-created-during-download-folder" });
  assert.equal(concurrentShareFolderResponse.status, 201, concurrentShareFolderResponse.body);
  const concurrentShareFolderId = JSON.parse(concurrentShareFolderResponse.body).id;
  OBJECTS.set(`rootark/uploads/${concurrentShareFolderId}/share-created-during-download.txt`, Buffer.from("share created during download fixture"));
  const permissionsBeforeConcurrentShare = JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"));
  permissionsBeforeConcurrentShare[`${concurrentShareFolderId}/share-created-during-download.txt`] = { public: false, owner: "owner", users: {} };
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(permissionsBeforeConcurrentShare));

  const downloadRaceFirstGate = cloud.blockGet("rootark/uploads/root/share-download-race.txt");
  const downloadRaceFirst = request(port, `/share/${limitedShareDownloadToken}/download`, {
    method: "POST",
    headers: { origin: `http://127.0.0.1:${port}` },
  });
  await downloadRaceFirstGate.started;
  const downloadRaceSecond = request(port, `/share/${limitedShareDownloadToken}/download`, {
    method: "POST",
    headers: { origin: `http://127.0.0.1:${port}` },
  });
  await waitForActiveRequestCount(path.join(dataDir, ".rootark-active-requests"), 2);
  const shareCreatedDuringDownload = await mutateAsOwner("/share", "POST", {
    folderId: concurrentShareFolderId,
    name: "share-created-during-download.txt",
    expiresInMinutes: 60,
  });
  assert.equal(shareCreatedDuringDownload.status, 201, shareCreatedDuringDownload.body);
  downloadRaceFirstGate.release();
  const firstShareDownload = await downloadRaceFirst;
  assert.equal(firstShareDownload.status, 200, firstShareDownload.body);
  const secondShareDownload = await downloadRaceSecond;
  assert.equal(secondShareDownload.status, 410, "a concurrent request must not exceed maxDownloads after provider hydration");
  const limitedShareAfterDownloads = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))[limitedShareDownloadToken];
  assert.equal(limitedShareAfterDownloads.downloads, 1, "the permitted download count is committed once");
  const linksAfterConcurrentDownload = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"));
  assert.equal(linksAfterConcurrentDownload[JSON.parse(shareCreatedDuringDownload.body).token].fileName, "share-created-during-download.txt", "a link created during provider hydration is not overwritten by the download counter update");

  async function assertNameBoundMutationSerializesWithTrash(name, pathName, method, payload, expectedStatus) {
    const gate = cloud.blockList("rootark/uploads/root/");
    const mutation = mutateAsOwner(pathName, method, payload);
    await gate.started;
    let deleteSettled = false;
    const deletion = mutateAsOwner(`/delete/${name}?folderId=root`, "POST", {});
    deletion.then(() => { deleteSettled = true; });
    await new Promise((resolve) => setTimeout(resolve, 150));
    const waitedForMutation = !deleteSettled;
    gate.release();
    const [mutationResponse, deletionResponse] = await Promise.all([mutation, deletion]);
    assert.equal(mutationResponse.status, expectedStatus, mutationResponse.body);
    assert.equal(deletionResponse.status, 200, deletionResponse.body);
    assert.equal(waitedForMutation, true, "trash waits for the name-bound mutation's in-flight provider listing");
    const trashItems = JSON.parse(fs.readFileSync(path.join(dataDir, "trash-items.json"), "utf8"));
    assert.ok(trashItems.some((item) => item.originalFileName === name && item.status === "trashed"));
    return mutationResponse;
  }

  await assertNameBoundMutationSerializesWithTrash(
    "share-trash-race.txt",
    "/share",
    "POST",
    { name: "share-trash-race.txt", expiresInMinutes: 60 },
    201,
  );
  assert.equal(
    Object.values(JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))).some((link) => link.fileName === "share-trash-race.txt"),
    false,
    "trash retires any same-name public link created before its lifecycle commit",
  );
  await assertNameBoundMutationSerializesWithTrash(
    "access-trash-race.txt",
    "/file-access",
    "PUT",
    { name: "access-trash-race.txt", public: true, users: {} },
    200,
  );
  assert.equal(
    Object.hasOwn(JSON.parse(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8")), "root/access-trash-race.txt"),
    false,
    "trash leaves no same-name access grant persisted after its lifecycle commit",
  );
  await assertNameBoundMutationSerializesWithTrash(
    "encrypted-grant-trash-race.txt",
    "/encrypted/encrypted-grant-trash-race.txt/grant-access",
    "POST",
    { username: "viewer" },
    200,
  );
  assert.equal(
    Object.hasOwn(JSON.parse(fs.readFileSync(path.join(dataDir, "encrypted-files.json"), "utf8")), "root/encrypted-grant-trash-race.txt"),
    false,
    "trash leaves no same-name encrypted access grant persisted after its lifecycle commit",
  );

  const caseAliasResponse = await request(port, "/files/case-orphan.txt", { headers: { cookie } });
  if (process.platform === "win32") {
    assert.equal(caseAliasResponse.status, 403, caseAliasResponse.body);
    assert.equal(caseAliasResponse.body.includes("stale mixed-case orphan cache"), false, "Windows case aliases of suppressed provider objects remain denied");
    assert.equal(cloud.getObjects.includes("rootark/uploads/root/Case-Orphan.TXT"), false, "case-alias denial happens before provider hydration");
  } else {
    assert.equal(caseAliasResponse.status, 200, caseAliasResponse.body);
    assert.equal(caseAliasResponse.body, "distinct lowercase provider bytes", "Linux keeps differently cased names distinct");
    assert.equal(cloud.getObjects.includes("rootark/uploads/root/Case-Orphan.TXT"), false);
  }

  const pendingOrphanListing = await request(port, "/pending?folderId=root", { headers: { cookie } });
  assert.equal(pendingOrphanListing.status, 200, pendingOrphanListing.body);
  const pendingOrphan = JSON.parse(pendingOrphanListing.body).find((entry) => entry.name === "restore-orphan-pending.txt");
  assert.equal(pendingOrphan?.restoreOrphan, true, "restored metadata remains visible as a recoverable pending item without exposing its payload");
  assert.equal(pendingOrphan?.availability, "recovery_required");
  const pendingOrphanPreview = await request(port, "/preview/text/pending/restore-orphan-pending.txt?folderId=root", { headers: { cookie } });
  assert.equal(pendingOrphanPreview.status, 409, pendingOrphanPreview.body);
  const pendingOrphanApproval = await mutateAsOwner("/approve/restore-orphan-pending.txt?folderId=root", "POST", {});
  assert.equal(pendingOrphanApproval.status, 409, pendingOrphanApproval.body);
  assert.equal(fs.readFileSync(path.join(directory, "temp", "restore-orphan-pending.txt"), "utf8"), "stale local pending cache", "approval does not promote stale cached bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "restore-orphan-pending.txt")), false);
  assert.equal(cloud.getObjects.includes("rootark/temp/root/restore-orphan-pending.txt"), false, "preview and approval do not hydrate a suppressed temp object");
  const pendingOrphanReject = await mutateAsOwner("/reject/restore-orphan-pending.txt?folderId=root", "POST", {});
  assert.ok([200, 202].includes(pendingOrphanReject.status), pendingOrphanReject.body);
  assert.equal(fs.existsSync(path.join(directory, "temp", "restore-orphan-pending.txt")), false, "authorized rejection cleans stale local cache without fetching provider bytes");
  assert.equal(Object.hasOwn(JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8")), "root/restore-orphan-pending.txt"), false, "authorized rejection removes stale metadata explicitly");
  assert.equal(cloud.getObjects.includes("rootark/temp/root/restore-orphan-pending.txt"), false, "authorized cleanup never hydrates the stale provider payload");

  for (const name of unregisteredMagicNames) {
    const pendingMetadata = JSON.parse(fs.readFileSync(path.join(dataDir, "pending-uploads.json"), "utf8"));
    assert.equal(Object.hasOwn(pendingMetadata, `root/${name}`), false);
    assert.equal(Object.hasOwn(pendingMetadata, name), false);
    const providerGetsBeforeApproval = cloud.getObjects.length;
    const approval = await mutateAsOwner(`/approve/${encodeURIComponent(name)}?folderId=root`, "POST", {});
    assert.equal(approval.status, 404, `${name} without own pending metadata cannot be approved: ${approval.body}`);
    assert.equal(cloud.getObjects.length, providerGetsBeforeApproval, `${name} without own pending metadata is not hydrated`);
    assert.equal(fs.existsSync(path.join(directory, "temp", name)), false);
    assert.equal(fs.existsSync(path.join(directory, "uploads", name)), false);
    const rejection = await mutateAsOwner(`/reject/${encodeURIComponent(name)}?folderId=root`, "POST", {});
    assert.equal(rejection.status, 404, `${name} without own pending metadata cannot be rejected: ${rejection.body}`);
  }

  const providerGetsBeforeList = cloud.getObjects.length;
  const list = await request(port, "/list", { headers: { cookie, referer: "https://attacker.invalid/" } });
  assert.equal(list.status, 200, list.body);
  assert.equal(JSON.parse(list.body).some((file) => file.name === "restore-orphan.txt"), false, "persisted restore orphans remain hidden after server restart");
  const expectedVisibleNames = ["ambiguous-orphan.v1", "budget.v2", "cloud-only-version-init.txt", "encrypted.txt", "legacy.v9", "notes.v2", "private.txt.v7", "private.txt.v8", "public.txt", "share-download-race.txt", "version-primary.txt", "webdav-acl-revocation.txt", "webdav-listfiles-revocation.txt", "webdav-session-revocation.txt"];
  if (process.platform !== "win32") expectedVisibleNames.push("case-orphan.txt");
  assert.deepEqual(JSON.parse(list.body).map((file) => file.name).sort(), expectedVisibleNames.sort());
  assert.equal(cloud.getObjects.length, providerGetsBeforeList, "listing reads provider metadata without materializing file bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "budget.v2")), false, "ordinary cloud file is visible before hydration");
  OBJECTS.set("rootark/uploads/root/revoke-download.txt", Buffer.from("download access revocation fixture"));
  OBJECTS.set("rootark/uploads/root/file-access-session-revocation.txt", Buffer.from("file access session revocation fixture"));
  OBJECTS.set("rootark/uploads/root/share-session-revocation.txt", Buffer.from("share session revocation fixture"));
  OBJECTS.set("rootark/uploads/root/share-race-first.txt", Buffer.from("first concurrent share fixture"));
  OBJECTS.set("rootark/uploads/root/share-race-second.txt", Buffer.from("second concurrent share fixture"));
  OBJECTS.set("rootark/uploads/root/encrypted-grant-session-revocation.txt", Buffer.from("encrypted grant session revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-preview.txt", Buffer.from("preview access revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-share.txt", Buffer.from("share access revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-version.txt", Buffer.from("version current revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-version.txt.v1", Buffer.from("version history revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-version-token.txt", Buffer.from("version token current revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-version-token.txt.v1", Buffer.from("version token history revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-encrypted.txt", Buffer.from("encrypted download revocation fixture"));
  OBJECTS.set("rootark/uploads/root/revoke-webdav.txt", Buffer.from("WebDAV access revocation fixture"));
  OBJECTS.set("rootark/uploads/root/session-target.txt", Buffer.from("session revocation fixture"));

  const ordinaryCloudFile = await request(port, "/files/budget.v2", { headers: { cookie } });
  assert.equal(ordinaryCloudFile.status, 200, "an ordinary cloud-only .vN file must be downloadable");
  assert.equal(ordinaryCloudFile.body, "ordinary cloud suffix fixture");
  const cloudOnlyVersionInit = await mutate("/versions/cloud-only-version-init.txt/initialize?folderId=root", "POST", {});
  assert.equal(cloudOnlyVersionInit.status, 200, cloudOnlyVersionInit.body);
  assert.equal(JSON.parse(cloudOnlyVersionInit.body).fileName, "cloud-only-version-init.txt");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "cloud-only-version-init.txt")), true, "version initialization hydrates an authorized cloud-only file");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/cloud-only-version-init.txt"), true);

  const restoreOrphanFile = await request(port, "/files/restore-orphan.txt", { headers: { cookie } });
  assert.equal(restoreOrphanFile.status, 403, "restore-orphan provider objects are denied despite legacy default-public ACLs");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/restore-orphan.txt"), false, "denied restore-orphan downloads never hydrate provider bytes");
  const restoreOrphanToken = await mutate("/file-open-token", "POST", { name: "restore-orphan.txt" });
  assert.equal(restoreOrphanToken.status, 403, "restore-orphan files cannot issue open tokens");
  const managerOrphanToken = await mutateAsOwner("/file-open-token", "POST", { name: "restore-orphan.txt" });
  assert.equal(managerOrphanToken.status, 200, managerOrphanToken.body);
  const managerOrphanUrl = JSON.parse(managerOrphanToken.body).url;
  const managerOrphanOpen = await request(port, managerOrphanUrl, { headers: { cookie: ownerCookie } });
  assert.equal(managerOrphanOpen.status, 200, "a manager-issued orphan review token must remain usable by its manager");
  assert.equal(managerOrphanOpen.body, "post-backup provider bytes");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/restore-orphan.txt"), true, "manager review may hydrate the reviewed provider orphan");
  const managerOrphanOpenAnonymous = await request(port, managerOrphanUrl);
  assert.notEqual(managerOrphanOpenAnonymous.status, 200, "a manager review token must not become an anonymous bearer link");
  const restoreOrphanSearch = await request(port, "/files/search?q=restore-orphan", { headers: { cookie } });
  assert.equal(restoreOrphanSearch.status, 200, restoreOrphanSearch.body);
  assert.deepEqual(JSON.parse(restoreOrphanSearch.body), [], "search uses the same restore-orphan visibility boundary");
  const restoreOrphanVersion = await request(port, "/download/restore-orphan.txt/v/1", { headers: { cookie } });
  assert.equal(restoreOrphanVersion.status, 403, "restore-orphan versions remain inaccessible");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/restore-orphan.txt.v1"), false);
  const aliasVersionPath = path.join(directory, "uploads", "version-primary.txt.v1");
  const versionAliasGetsBefore = cloud.getObjects.length;
  const suppressedVersionDownload = await request(port, "/download/version-primary.txt/v/1", { headers: { cookie } });
  const suppressedVersionToken = await mutate("/version-open-token", "POST", { name: "version-primary.txt", version: 1 });
  const versionHistoryPath = path.join(dataDir, "file-versions.json");
  const versionHistoryBeforeSuppressedRestore = fs.readFileSync(versionHistoryPath, "utf8");
  const primaryBytesBeforeSuppressedRestore = fs.readFileSync(path.join(directory, "uploads", "version-primary.txt"), "utf8");
  const suppressedVersionRestore = await mutate("/restore/version-primary.txt/v/1?folderId=root", "POST", {});
  const suppressedVersionRouteEvidence = {
    downloadStatus: suppressedVersionDownload.status,
    tokenStatus: suppressedVersionToken.status,
    restoreStatus: suppressedVersionRestore.status,
    providerGets: cloud.getObjects.slice(versionAliasGetsBefore),
    aliasCached: fs.existsSync(aliasVersionPath),
    historyUnchanged: fs.readFileSync(versionHistoryPath, "utf8") === versionHistoryBeforeSuppressedRestore,
    primaryBytesUnchanged: fs.readFileSync(path.join(directory, "uploads", "version-primary.txt"), "utf8") === primaryBytesBeforeSuppressedRestore,
  };
  assert.deepEqual(suppressedVersionRouteEvidence, {
    downloadStatus: 403,
    tokenStatus: 403,
    restoreStatus: 403,
    providerGets: [],
    aliasCached: false,
    historyUnchanged: true,
    primaryBytesUnchanged: true,
  }, "suppressed storedAs aliases are denied across download, token, and restore even when the primary is authorized");
  const managerSuppressedVersionToken = await mutateAsOwner("/version-open-token", "POST", { name: "version-primary.txt", version: 1 });
  assert.equal(managerSuppressedVersionToken.status, 200, managerSuppressedVersionToken.body);
  const managerSuppressedVersionUrl = JSON.parse(managerSuppressedVersionToken.body).downloadUrl;
  const managerSuppressedVersionOpen = await request(port, managerSuppressedVersionUrl, { headers: { cookie: ownerCookie } });
  assert.equal(managerSuppressedVersionOpen.status, 200, "a manager may review a restore-suppressed historical version");
  assert.equal(managerSuppressedVersionOpen.body, "suppressed provider-only version fixture");
  assert.notEqual((await request(port, managerSuppressedVersionUrl)).status, 200, "a manager review version token is not an anonymous bearer link");
  assert.notEqual((await request(port, managerSuppressedVersionUrl, { headers: { cookie } })).status, 200, "a manager review version token is bound to its issuing manager");
  fs.rmSync(aliasVersionPath, { force: true });
  const ownerUsersPath = path.join(dataDir, "users.local.json");
  const ownerUsersBeforeRevocation = fs.readFileSync(ownerUsersPath, "utf8");
  const ownerUsersWithoutManagerAccess = JSON.parse(ownerUsersBeforeRevocation);
  ownerUsersWithoutManagerAccess.find((user) => user.username === "owner").role = "user";
  fs.writeFileSync(ownerUsersPath, JSON.stringify(ownerUsersWithoutManagerAccess));
  const versionReviewGetsBeforeReauthorization = cloud.getObjects.length;
  const managerVersionTokenWithoutCurrentRole = await request(port, managerSuppressedVersionUrl, { headers: { cookie: ownerCookie } });
  assert.notEqual(managerVersionTokenWithoutCurrentRole.status, 200, "manager access is rechecked before version-token hydration");
  assert.equal(cloud.getObjects.length, versionReviewGetsBeforeReauthorization, "a demoted manager cannot hydrate a suppressed version");
  fs.writeFileSync(ownerUsersPath, ownerUsersBeforeRevocation);
  const secondManagerVersionToken = await mutateAsOwner("/version-open-token", "POST", { name: "version-primary.txt", version: 1 });
  assert.equal(secondManagerVersionToken.status, 200, secondManagerVersionToken.body);
  const secondManagerVersionUrl = JSON.parse(secondManagerVersionToken.body).downloadUrl;
  fs.rmSync(aliasVersionPath, { force: true });
  const versionReviewGate = cloud.blockGet("rootark/uploads/root/version-primary.txt.v1");
  const managerVersionReviewAfterHydration = request(port, secondManagerVersionUrl, { headers: { cookie: ownerCookie } });
  await versionReviewGate.started;
  const ownerUsersDuringHydration = JSON.parse(fs.readFileSync(ownerUsersPath, "utf8"));
  ownerUsersDuringHydration.find((user) => user.username === "owner").role = "user";
  fs.writeFileSync(ownerUsersPath, JSON.stringify(ownerUsersDuringHydration));
  versionReviewGate.release();
  const revokedManagerVersionReview = await managerVersionReviewAfterHydration;
  assert.notEqual(revokedManagerVersionReview.status, 200, "manager access is rechecked after version-token hydration");
  assert.equal(revokedManagerVersionReview.body.includes("suppressed provider-only version fixture"), false);
  fs.writeFileSync(ownerUsersPath, ownerUsersBeforeRevocation);
  fs.rmSync(aliasVersionPath, { force: true });
  const authorizedSiblingVersion = await request(port, "/download/version-primary.txt/v/2", { headers: { cookie } });
  assert.equal(authorizedSiblingVersion.status, 200, "an authorized sibling version remains available when only v1 is suppressed");
  assert.equal(authorizedSiblingVersion.body, "authorized stored version fixture");
  cloud.getObjects.length = 0;

  const orphanPolicyPath = path.join(dataDir, ".rootark-restore-provider-orphans.json");
  const suppressAlias = (name) => {
    const policy = JSON.parse(fs.readFileSync(orphanPolicyPath, "utf8"));
    policy.objects.push({ area: "uploads", folderId: "root", name });
    fs.writeFileSync(orphanPolicyPath, JSON.stringify(policy));
  };
  {
    const name = "version-race.txt";
    const gate = cloud.blockGet(`rootark/uploads/root/${name}.v1`);
    const read = request(port, `/download/${name}/v/1`, { headers: { cookie } });
    await gate.started;
    suppressAlias(`${name}.v1`);
    gate.release();
    const response = await read;
    assert.equal(response.status, 403, "version download rechecks suppression after cloud hydration");
    assert.equal(response.body.includes("version download race fixture"), false);
  }
  {
    const name = "token-race.txt";
    const gate = cloud.blockGet(`rootark/uploads/root/${name}.v1`);
    const token = mutate("/version-open-token", "POST", { name, version: 1 });
    await gate.started;
    suppressAlias(`${name}.v1`);
    gate.release();
    const response = await token;
    assert.equal(response.status, 403, "version token rechecks suppression after cloud hydration");
    assert.equal(JSON.parse(response.body).downloadUrl, undefined, "suppressed version never receives an open token");
  }
  {
    const name = "restore-race.txt";
    const currentBytes = Buffer.from("authorized restore race current bytes");
    const currentPath = path.join(directory, "uploads", name);
    fs.writeFileSync(currentPath, currentBytes);
    OBJECTS.set(`rootark/uploads/root/${name}`, currentBytes);
    const gate = cloud.blockGet(`rootark/uploads/root/${name}.v1`);
    const historyBefore = fs.readFileSync(versionHistoryPath, "utf8");
    const restore = mutate(`/restore/${name}/v/1?folderId=root`, "POST", {});
    await gate.started;
    suppressAlias(`${name}.v1`);
    gate.release();
    const response = await restore;
    assert.equal(response.status, 403, "version restore rechecks suppression after cloud hydration");
    assert.equal(fs.readFileSync(currentPath).equals(currentBytes), true, "raced suppression preserves the current file bytes");
    assert.equal(fs.readFileSync(versionHistoryPath, "utf8"), historyBefore, "raced suppression preserves version history");
  }
  {
    const name = "issued-token-race.txt";
    const token = await mutate("/version-open-token", "POST", { name, version: 1 });
    assert.equal(token.status, 200, token.body);
    suppressAlias(`${name}.v1`);
    const aliasPath = path.join(directory, "uploads", `${name}.v1`);
    fs.rmSync(aliasPath, { force: true });
    const getsBeforeStaleTokenUse = cloud.getObjects.length;
    const response = await request(port, JSON.parse(token.body).downloadUrl, { headers: { cookie } });
    assert.equal(response.status, 404, "an already-issued bearer token is revoked when its storedAs object becomes suppressed");
    assert.equal(response.body.includes("previously issued version token fixture"), false, "suppressed storedAs bytes are not served through a stale bearer token");
    assert.equal(cloud.getObjects.length, getsBeforeStaleTokenUse, "stale bearer token is rejected before provider hydration");
    assert.equal(fs.existsSync(aliasPath), false, "stale bearer token does not recache the suppressed version");
  }
  const authorizedVersionDownload = await request(port, "/download/public.txt/v/1", { headers: { cookie } });
  assert.equal(authorizedVersionDownload.status, 200, "non-suppressed historical versions remain available");
  assert.equal(authorizedVersionDownload.body, "public stored version fixture");
  const ownerOrphanFile = await request(port, "/files/restore-orphan.txt", { headers: { cookie: ownerCookie } });
  assert.equal(ownerOrphanFile.status, 200, "admins retain restore-orphan review access");
  assert.equal(ownerOrphanFile.body, "post-backup provider bytes");
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
  cloud.getObjects.length = 0;
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
  for (const [route, method] of [["view", "POST"], ["download", "POST"], ["preview", "GET"], ["file", "GET"]]) {
    const sharedOrphan = await request(port, `/share/${restoreOrphanShareToken}/${route}`, {
      method,
      headers: method === "POST" ? { origin: `http://127.0.0.1:${port}` } : {},
    });
    assert.equal(sharedOrphan.status, 404, `${route} cannot expose a restore-orphan share`);
    assert.equal(sharedOrphan.body.includes("post-backup provider bytes"), false);
  }
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/restore-orphan.txt"), false, "public share denial happens before provider hydration");

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
  assert.equal(propfind.body.includes("ambiguous-orphan.v1"), false, "WebDAV fails closed for suffix-named objects with no primary metadata");
  assert.equal(propfind.body.includes("budget.v2"), true, "WebDAV lists ordinary suffix names");
  assert.equal(propfind.body.includes("notes.v2"), true, "WebDAV lists ordinary local suffix names");
  assert.equal(propfind.body.includes("private.txt.v7"), true, "WebDAV preserves a suffix-named primary file with its own ACL");
  assert.equal(propfind.body.includes("private.txt.v8"), true, "WebDAV preserves a suffix-named primary file with its own history");
  assert.deepEqual(cloud.getObjects, [], "WebDAV listing does not hydrate cloud objects");
  const orphanWebDavFile = await request(port, "/dav/ambiguous-orphan.v1", { headers: { authorization: webDavAuth } });
  assert.equal(orphanWebDavFile.status, 404, orphanWebDavFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/ambiguous-orphan.v1"), false, "ambiguous suffix artifacts never hydrate through WebDAV");
  const orphanWebDavHead = await request(port, "/dav/ambiguous-orphan.v1", { method: "HEAD", headers: { authorization: webDavAuth } });
  assert.equal(orphanWebDavHead.status, 404, "HEAD does not disclose ambiguous suffix metadata");
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/ambiguous-orphan.v1"), false, "denied HEAD never hydrates the object");
  const ordinaryCloudWebDavFile = await request(port, "/dav/budget.v2", { headers: { authorization: webDavAuth } });
  assert.equal(ordinaryCloudWebDavFile.status, 200, ordinaryCloudWebDavFile.body);
  assert.equal(ordinaryCloudWebDavFile.body, "ordinary cloud suffix fixture");
  const ordinaryLocalWebDavFile = await request(port, "/dav/notes.v2", { headers: { authorization: webDavAuth } });
  assert.equal(ordinaryLocalWebDavFile.status, 200, ordinaryLocalWebDavFile.body);
  assert.equal(ordinaryLocalWebDavFile.body, "ordinary local suffix fixture");
  const restoreOrphanWebDavList = await request(port, "/dav", { method: "PROPFIND", headers: { authorization: webDavAuth, depth: "1" } });
  assert.equal(restoreOrphanWebDavList.status, 207, restoreOrphanWebDavList.body);
  assert.equal(restoreOrphanWebDavList.body.includes("restore-orphan.txt"), false, "WebDAV does not disclose restored orphans");
  const restoreOrphanWebDavFile = await request(port, "/dav/restore-orphan.txt", { headers: { authorization: webDavAuth } });
  assert.equal(restoreOrphanWebDavFile.status, 404, restoreOrphanWebDavFile.body);
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/restore-orphan.txt"), false, "denied WebDAV access never hydrates provider bytes");

  const webDavUsersPath = path.join(dataDir, "users.local.json");
  const originalWebDavUsers = fs.readFileSync(webDavUsersPath, "utf8");
  const filePermissionsPath = path.join(dataDir, "file-permissions.json");
  const originalFilePermissions = fs.readFileSync(filePermissionsPath, "utf8");
  async function assertWebDavReadRevalidation(method, name, mutateState, restoreState) {
    const localPath = path.join(directory, "uploads", name);
    fs.rmSync(localPath, { force: true });
    const gate = cloud.blockGet(`rootark/uploads/root/${name}`);
    const pendingRead = request(port, `/dav/${name}`, { method, headers: { authorization: webDavAuth } });
    await gate.started;
    mutateState();
    gate.release();
    const response = await pendingRead;
    restoreState();
    fs.rmSync(localPath, { force: true });
    assert.notEqual(response.status, 200, `${method} does not serve a file after authorization changes during hydration`);
    assert.notEqual(response.status, 207, `${method} does not expose file metadata after authorization changes during hydration`);
    assert.equal(response.body.includes(OBJECTS.get(`rootark/uploads/root/${name}`).toString()), false);
  }
  await assertWebDavReadRevalidation(
    "GET",
    "webdav-session-revocation.txt",
    () => {
      const users = JSON.parse(originalWebDavUsers);
      users.find((user) => user.username === "viewer").sessionVersion += 1;
      fs.writeFileSync(webDavUsersPath, JSON.stringify(users));
    },
    () => fs.writeFileSync(webDavUsersPath, originalWebDavUsers)
  );
  await assertWebDavReadRevalidation(
    "HEAD",
    "webdav-listfiles-revocation.txt",
    () => {
      const users = JSON.parse(originalWebDavUsers);
      users.find((user) => user.username === "viewer").permissions.listFiles = false;
      fs.writeFileSync(webDavUsersPath, JSON.stringify(users));
    },
    () => fs.writeFileSync(webDavUsersPath, originalWebDavUsers)
  );
  await assertWebDavReadRevalidation(
    "PROPFIND",
    "webdav-acl-revocation.txt",
    () => {
      const permissions = JSON.parse(originalFilePermissions);
      permissions["root/webdav-acl-revocation.txt"].users = {};
      fs.writeFileSync(filePermissionsPath, JSON.stringify(permissions));
    },
    () => fs.writeFileSync(filePermissionsPath, originalFilePermissions)
  );

  const revokeFileAccessDuringHydration = (name) => {
    const permissions = JSON.parse(fs.readFileSync(filePermissionsPath, "utf8"));
    const entry = permissions[`root/${name}`];
    assert.ok(entry, `fixture permissions exist for ${name}`);
    entry.public = false;
    entry.users = {};
    fs.writeFileSync(filePermissionsPath, JSON.stringify(permissions));
  };

  const validOrphanPolicy = fs.readFileSync(orphanPolicyPath, "utf8");
  const pendingRegistryPath = path.join(dataDir, "pending-uploads.json");
  const validPendingRegistry = fs.readFileSync(pendingRegistryPath, "utf8");
  const pendingRegistryWithRestoreOrphan = JSON.parse(validPendingRegistry);
  pendingRegistryWithRestoreOrphan["root/restore-orphan-pending.txt"] = { fileName: "restore-orphan-pending.txt", folderId: "root", uploadedBy: "viewer" };
  fs.writeFileSync(pendingRegistryPath, JSON.stringify(pendingRegistryWithRestoreOrphan));
  fs.writeFileSync(orphanPolicyPath, "{");
  const pendingWithInvalidPolicy = await request(port, "/pending?folderId=root", { headers: { cookie } });
  assert.equal(pendingWithInvalidPolicy.status, 503, pendingWithInvalidPolicy.body);
  assert.ok(Number(pendingWithInvalidPolicy.headers["retry-after"]) > 0, "policy read failures are retryable");
  fs.writeFileSync(orphanPolicyPath, validOrphanPolicy);
  fs.writeFileSync(pendingRegistryPath, validPendingRegistry);

  cloud.getObjects.length = 0;
  for (const [name, route] of [["revoke-download.txt", "/files/revoke-download.txt"], ["revoke-preview.txt", "/preview/file/public/revoke-preview.txt"]]) {
    const gate = cloud.blockGet(`rootark/uploads/root/${name}`);
    const read = request(port, route, { headers: { cookie } });
    await gate.started;
    revokeFileAccessDuringHydration(name);
    gate.release();
    const response = await read;
    assert.equal(response.status, 403, `${route} rechecks the current ACL after cache hydration`);
    assert.equal(response.body.includes("revocation fixture"), false, `${route} does not return content after access is revoked`);
  }
  {
    const name = "revoke-version.txt";
    const gate = cloud.blockGet("rootark/uploads/root/revoke-version.txt.v1");
    const read = request(port, "/download/revoke-version.txt/v/1", { headers: { cookie } });
    await gate.started;
    revokeFileAccessDuringHydration(name);
    gate.release();
    const response = await read;
    assert.equal(response.status, 403, "version download rechecks the current ACL after cache hydration");
    assert.equal(response.body.includes("version history revocation fixture"), false);
  }
  {
    const name = "revoke-version-token.txt";
    const gate = cloud.blockGet("rootark/uploads/root/revoke-version-token.txt.v1");
    const read = mutate("/version-open-token", "POST", { name, version: 1 });
    await gate.started;
    revokeFileAccessDuringHydration(name);
    gate.release();
    const response = await read;
    assert.equal(response.status, 403, "version token issuance rechecks the current ACL after cache hydration");
    assert.equal(response.body.includes("version token history revocation fixture"), false);
    assert.equal(response.body.includes("/open-file/"), false, "revoked access does not receive a bearer URL");
  }
  {
    const name = "revoke-encrypted.txt";
    const gate = cloud.blockGet("rootark/uploads/root/revoke-encrypted.txt");
    const read = mutate(`/encrypted-download/${name}`, "POST", {});
    await gate.started;
    revokeFileAccessDuringHydration(name);
    gate.release();
    const response = await read;
    assert.equal(response.status, 403, "encrypted download rechecks current ACL after cache hydration");
    assert.equal(response.body.includes("encrypted download revocation fixture"), false);
  }
  {
    const name = "revoke-webdav.txt";
    const gate = cloud.blockGet(`rootark/uploads/root/${name}`);
    const read = request(port, `/dav/${name}`, { headers: { authorization: webDavAuth } });
    await gate.started;
    revokeFileAccessDuringHydration(name);
    gate.release();
    const response = await read;
    assert.equal(response.status, 404, "WebDAV hides files after ACL revocation during cache hydration");
    assert.equal(response.body.includes("WebDAV access revocation fixture"), false);
  }
  cloud.getObjects.length = 0;

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
  const shareGate = cloud.blockList("rootark/uploads/root/");
  const hashCallsBeforeRevokedShare = fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0;
  const revokedShareRequest = mutate("/share", "POST", { name: "revoke-share.txt", expiresInMinutes: 60, password: "valid-password" });
  await shareGate.started;
  revokeFileAccessDuringHydration("revoke-share.txt");
  shareGate.release();
  const revokedShare = await revokedShareRequest;
  assert.equal(revokedShare.status, 403, revokedShare.body);
  assert.equal(fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0, hashCallsBeforeRevokedShare, "share password is not hashed after requester access is revoked");
  assert.equal(Object.values(JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"))).some((link) => link.fileName === "revoke-share.txt"), false);

  const shareRaceFolderResponse = await mutateAsOwner("/folders", "POST", { name: "share-race-second-folder" });
  assert.equal(shareRaceFolderResponse.status, 201, shareRaceFolderResponse.body);
  const shareRaceFolderId = JSON.parse(shareRaceFolderResponse.body).id;
  OBJECTS.set(`rootark/uploads/${shareRaceFolderId}/share-race-second.txt`, Buffer.from("second concurrent share fixture"));
  const shareRacePermissions = JSON.parse(fs.readFileSync(filePermissionsPath, "utf8"));
  shareRacePermissions[`${shareRaceFolderId}/share-race-second.txt`] = { public: false, owner: "owner", users: {} };
  fs.writeFileSync(filePermissionsPath, JSON.stringify(shareRacePermissions));
  const shareRaceFirstGate = cloud.blockList("rootark/uploads/root/", 1);
  const shareRaceFirst = mutateAsOwner("/share", "POST", { name: "share-race-first.txt", expiresInMinutes: 60 });
  await shareRaceFirstGate.started;
  const shareRaceSecondGate = cloud.blockList(`rootark/uploads/${shareRaceFolderId}/`, 1);
  const shareRaceSecond = mutateAsOwner("/share", "POST", { folderId: shareRaceFolderId, name: "share-race-second.txt", expiresInMinutes: 60 });
  await shareRaceSecondGate.started;
  shareRaceFirstGate.release();
  const firstShareResponse = await shareRaceFirst;
  assert.equal(firstShareResponse.status, 201, firstShareResponse.body);
  shareRaceSecondGate.release();
  const secondShareResponse = await shareRaceSecond;
  assert.equal(secondShareResponse.status, 201, secondShareResponse.body);
  const concurrentShares = Object.values(JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8")));
  assert.ok(concurrentShares.some((link) => link.fileName === "share-race-first.txt"));
  assert.ok(concurrentShares.some((link) => link.fileName === "share-race-second.txt"), "serially released share saves must preserve earlier concurrent links");

  const folderCreation = await mutateAsOwner("/folders", "POST", {
    name: "folder-eligibility-race",
    users: { viewer: { read: true, edit: true } },
  });
  assert.equal(folderCreation.status, 201, folderCreation.body);
  const folderId = JSON.parse(folderCreation.body).id;
  OBJECTS.set(`rootark/uploads/${folderId}/folder-acl-race.txt`, Buffer.from("folder ACL eligibility race fixture"));
  const filePermissionsBeforeFolderAccessChange = fs.readFileSync(filePermissionsPath, "utf8");
  const folderFileAccessGate = cloud.blockList(`rootark/uploads/${folderId}/`, 1);
  const folderFileAccess = mutateAsOwner("/file-access", "PUT", {
    folderId,
    name: "folder-acl-race.txt",
    public: false,
    users: { viewer: { read: true } },
  });
  await folderFileAccessGate.started;
  const removeViewerFromFolder = await mutateAsOwner(`/folders/${folderId}/access`, "PUT", { users: {} });
  assert.equal(removeViewerFromFolder.status, 200, removeViewerFromFolder.body);
  folderFileAccessGate.release();
  const staleFolderGrant = await folderFileAccess;
  assert.equal(staleFolderGrant.status, 400, staleFolderGrant.body);
  assert.equal(fs.readFileSync(filePermissionsPath, "utf8"), filePermissionsBeforeFolderAccessChange, "file ACL is not persisted for a target removed from folder eligibility during listing");

  async function assertFreshSessionBeforeMutationPersistence(requestPath, method, payload, gate, statePath) {
    const stateBefore = fs.readFileSync(statePath, "utf8");
    const pending = mutateAsOwner(requestPath, method, payload);
    await gate.started;
    const users = JSON.parse(fs.readFileSync(webDavUsersPath, "utf8"));
    users.find((user) => user.username === "owner").sessionVersion += 1;
    fs.writeFileSync(webDavUsersPath, JSON.stringify(users));
    gate.release();
    const response = await pending;
    fs.writeFileSync(webDavUsersPath, originalWebDavUsers);
    assert.equal(response.status, 401, response.body);
    assert.equal(fs.readFileSync(statePath, "utf8"), stateBefore, `${requestPath} must not persist after session revocation`);
  }

  const fileAccessStatePath = path.join(dataDir, "file-permissions.json");
  await assertFreshSessionBeforeMutationPersistence(
    "/file-access",
    "PUT",
    { name: "file-access-session-revocation.txt", public: true, users: {} },
    cloud.blockList("rootark/uploads/root/", 1),
    fileAccessStatePath,
  );
  await assertFreshSessionBeforeMutationPersistence(
    "/share",
    "POST",
    { name: "share-session-revocation.txt", expiresInMinutes: 60 },
    cloud.blockList("rootark/uploads/root/", 1),
    path.join(dataDir, "public-links.json"),
  );
  await assertFreshSessionBeforeMutationPersistence(
    "/encrypted/encrypted-grant-session-revocation.txt/grant-access",
    "POST",
    { username: "viewer" },
    cloud.blockList("rootark/uploads/root/"),
    path.join(dataDir, "encrypted-files.json"),
  );
  await assertFreshSessionBeforeMutationPersistence(
    "/encrypted/encrypted-grant-session-revocation.txt/grant-access",
    "POST",
    { username: "viewer" },
    cloud.blockList("rootark/uploads/root/", 1),
    path.join(dataDir, "encrypted-files.json"),
  );
  assert.equal(cloud.getObjects.includes("rootark/uploads/root/private.txt"), false, "denied metadata actions do not hydrate private objects");
  assert.deepEqual(cloud.getObjects, [], "metadata-only file actions do not download cloud bytes");
  assert.equal(fs.existsSync(path.join(directory, "uploads", "public.txt")), false, "metadata-only file actions do not create a local cache");

  const fileAccessListingCount = cloud.listRequests.length;
  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await request(port, "/file-access?name=public.txt", { headers: { cookie, "x-forwarded-for": `198.51.100.${index}` } });
    assert.equal(response.status, 200, response.body);
  }
  const fileAccessAtLimit = cloud.listRequests.length;
  assert.equal(fileAccessAtLimit - fileAccessListingCount, CLOUD_METADATA_REQUEST_LIMIT - 1);
  const limitedFileAccess = await request(port, "/file-access?name=public.txt", { headers: { cookie, "x-forwarded-for": "203.0.113.250" } });
  assert.equal(limitedFileAccess.status, 429, limitedFileAccess.body);
  assert.equal(cloud.listRequests.length, fileAccessAtLimit, "limited GET is rejected before provider listing");
  const limitedHeadFileAccess = await request(port, "/file-access?name=public.txt", { method: "HEAD", headers: { cookie } });
  assert.equal(limitedHeadFileAccess.status, 429, "HEAD fallback shares the GET file-access quota");
  assert.equal(cloud.listRequests.length, fileAccessAtLimit, "limited HEAD is rejected before provider listing");

  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await mutate("/file-access", "PUT", { name: "public.txt", public: true, users: { viewer: { edit: true } } });
    assert.equal(response.status, 200, response.body);
  }
  const accessStateAtLimit = fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8");
  const accessListingAtLimit = cloud.listRequests.length;
  const limitedAccessChange = await mutate("/file-access", "PUT", { name: "public.txt", public: false, users: {} });
  assert.equal(limitedAccessChange.status, 429, limitedAccessChange.body);
  assert.equal(cloud.listRequests.length, accessListingAtLimit, "limited ACL update is rejected before provider listing");
  assert.equal(fs.readFileSync(path.join(dataDir, "file-permissions.json"), "utf8"), accessStateAtLimit, "limited ACL update does not persist state");

  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await mutate("/file-temporary", "PUT", { name: "public.txt", durationAmount: 1, durationUnit: "hours" });
    assert.equal(response.status, 200, response.body);
  }
  const expirationStateAtLimit = fs.readFileSync(path.join(dataDir, "file-expirations.json"), "utf8");
  const expirationListingAtLimit = cloud.listRequests.length;
  const limitedExpirationChange = await mutate("/file-temporary", "PUT", { name: "public.txt", durationAmount: 2, durationUnit: "days" });
  assert.equal(limitedExpirationChange.status, 429, limitedExpirationChange.body);
  assert.equal(cloud.listRequests.length, expirationListingAtLimit, "limited expiration update is rejected before provider listing");
  assert.equal(fs.readFileSync(path.join(dataDir, "file-expirations.json"), "utf8"), expirationStateAtLimit, "limited expiration update does not persist state");

  for (let index = 1; index < CLOUD_METADATA_REQUEST_LIMIT - 1; index += 1) {
    const response = await mutate("/share", "POST", { name: "public.txt", expiresInMinutes: 60 });
    assert.equal(response.status, 201, response.body);
  }
  const shareStateAtLimit = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"));
  const shareCountAtLimit = Object.values(shareStateAtLimit).filter((link) => link.fileName === "public.txt" && link.createdBy === "viewer").length;
  assert.equal(shareCountAtLimit, CLOUD_METADATA_REQUEST_LIMIT - 1);
  const shareListingAtLimit = cloud.listRequests.length;
  const hashCallsAtLimit = fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0;
  const limitedShare = await mutate("/share", "POST", { name: "public.txt", expiresInMinutes: 60, maxViews: 5, password: "valid-password" });
  assert.equal(limitedShare.status, 429, limitedShare.body);
  assert.equal(fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0, hashCallsAtLimit, "limited share does not hash a password");
  assert.equal(cloud.listRequests.length, shareListingAtLimit, "limited share creation is rejected before provider listing");
  const shareStateAfterLimit = JSON.parse(fs.readFileSync(path.join(dataDir, "public-links.json"), "utf8"));
  assert.equal(Object.values(shareStateAfterLimit).filter((link) => link.fileName === "public.txt" && link.createdBy === "viewer").length, shareCountAtLimit, "limited share creation does not persist a link");

  const hashCallsBeforeDeniedShare = fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0;
  const deniedPasswordShare = await mutate("/share", "POST", { name: "private.txt", expiresInMinutes: 60, password: "valid-password" });
  assert.equal(deniedPasswordShare.status, 403, deniedPasswordShare.body);
  assert.equal(fs.existsSync(hashCallsFile) ? fs.readFileSync(hashCallsFile, "utf8").length : 0, hashCallsBeforeDeniedShare, "unauthorized share does not hash a password");

  const editorBody = JSON.stringify({ username: "editor", password });
  const editorLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(editorBody) }, body: editorBody });
  assert.equal(editorLogin.status, 200, editorLogin.body);
  const editorCookies = editorLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const editorCookie = editorCookies.join("; ");
  const editorCsrf = editorCookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const editorMutation = (requestPath, method, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method,
      headers: { cookie: editorCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": editorCsrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };
  const accessGate = cloud.blockList("rootark/uploads/root/");
  const temporaryGate = cloud.blockList("rootark/uploads/root/");
  const expirationsPath = path.join(dataDir, "file-expirations.json");
  const expirationsBeforeStaleSession = fs.readFileSync(expirationsPath, "utf8");
  const pendingAccessRead = request(port, "/file-access?name=session-target.txt", { headers: { cookie: editorCookie } });
  const pendingTemporaryUpdate = editorMutation("/file-temporary", "PUT", { name: "session-target.txt", durationAmount: 1, durationUnit: "hours" });
  await Promise.all([accessGate.started, temporaryGate.started]);
  const usersPath = path.join(dataDir, "users.local.json");
  const users = JSON.parse(fs.readFileSync(usersPath, "utf8"));
  users.find((user) => user.username === "editor").sessionVersion += 1;
  fs.writeFileSync(usersPath, JSON.stringify(users));
  accessGate.release();
  temporaryGate.release();
  const [staleAccessRead, staleTemporaryUpdate] = await Promise.all([pendingAccessRead, pendingTemporaryUpdate]);
  assert.equal(staleAccessRead.status, 401, "file-access GET refreshes session state after provider listing");
  assert.equal(staleTemporaryUpdate.status, 401, "file-temporary PUT refreshes session state after provider listing");
  assert.equal(fs.readFileSync(expirationsPath, "utf8"), expirationsBeforeStaleSession, "stale file-temporary request does not persist an expiration");

  const limiterBody = JSON.stringify({ username: "cache-limiter", password });
  const limiterLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(limiterBody) }, body: limiterBody });
  assert.equal(limiterLogin.status, 200, limiterLogin.body);
  const limiterCookies = limiterLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const limiterCookie = limiterCookies.join("; ");
  const limiterCsrf = limiterCookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const limiterMutation = (requestPath, payload) => {
    const body = JSON.stringify(payload);
    return request(port, requestPath, {
      method: "POST",
      headers: { cookie: limiterCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": limiterCsrf, "content-type": "application/json", "content-length": Buffer.byteLength(body) },
      body,
    });
  };
  const cachePath = path.join(directory, "uploads", "cloud-limit.txt");
  const providerGetsBeforeCacheBudget = cloud.getObjects.length;
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    fs.rmSync(cachePath, { force: true });
    const response = await request(port, "/files/cloud-limit.txt", { headers: { cookie: limiterCookie } });
    assert.equal(response.status, 200, response.body);
  }
  assert.equal(cloud.getObjects.length - providerGetsBeforeCacheBudget, CLOUD_METADATA_REQUEST_LIMIT, "each cloud cache miss consumes one provider GET budget unit");
  const warmCloudGets = cloud.getObjects.length;
  const warmCloudFile = await request(port, "/files/cloud-limit.txt", { headers: { cookie: limiterCookie } });
  assert.equal(warmCloudFile.status, 200, "warm cloud cache reads remain available after the miss budget is exhausted");
  assert.equal(cloud.getObjects.length, warmCloudGets, "warm cloud cache reads do not call the provider");
  fs.writeFileSync(path.join(directory, "uploads", "local-limit.txt"), "local file does not use cloud budget");
  const localFile = await request(port, "/files/local-limit.txt", { headers: { cookie: limiterCookie } });
  assert.equal(localFile.status, 200, "local-file reads remain available after the cloud miss budget is exhausted");
  assert.equal(cloud.getObjects.length, warmCloudGets, "local-file reads do not call the provider");
  fs.rmSync(cachePath, { force: true });
  const cloudMissesBeforeLimit = cloud.getObjects.length;
  const limitedCloudMiss = await request(port, "/files/cloud-limit.txt", { headers: { cookie: limiterCookie } });
  assert.equal(limitedCloudMiss.status, 429, limitedCloudMiss.body);
  assert.equal(cloud.getObjects.length, cloudMissesBeforeLimit, "the rejected cloud cache miss is stopped before provider GET");

  const openTokenCachePath = path.join(directory, "uploads", "cloud-open-token-limit.txt");
  const providerGetsBeforeOpenTokenBudget = cloud.getObjects.length;
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    fs.rmSync(openTokenCachePath, { force: true });
    const response = await limiterMutation("/file-open-token", { name: "cloud-open-token-limit.txt" });
    assert.equal(response.status, 200, response.body);
  }
  assert.equal(cloud.getObjects.length - providerGetsBeforeOpenTokenBudget, CLOUD_METADATA_REQUEST_LIMIT, "open-token cloud misses consume the metadata budget");
  fs.rmSync(openTokenCachePath, { force: true });
  const providerGetsAtOpenTokenLimit = cloud.getObjects.length;
  const limitedOpenToken = await limiterMutation("/file-open-token", { name: "cloud-open-token-limit.txt" });
  assert.equal(limitedOpenToken.status, 429, limitedOpenToken.body);
  assert.equal(cloud.getObjects.length, providerGetsAtOpenTokenLimit, "a rejected open-token cache miss does not call the provider");

  const versionOpenTokenCachePath = path.join(directory, "uploads", "cloud-open-token-limit.txt.v1");
  const providerGetsBeforeVersionOpenTokenBudget = cloud.getObjects.length;
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    fs.rmSync(versionOpenTokenCachePath, { force: true });
    const response = await limiterMutation("/version-open-token", { name: "cloud-open-token-limit.txt", version: 1 });
    assert.equal(response.status, 200, response.body);
  }
  assert.equal(cloud.getObjects.length - providerGetsBeforeVersionOpenTokenBudget, CLOUD_METADATA_REQUEST_LIMIT, "version-token cloud misses consume the metadata budget");
  fs.rmSync(versionOpenTokenCachePath, { force: true });
  const providerGetsAtVersionOpenTokenLimit = cloud.getObjects.length;
  const limitedVersionOpenToken = await limiterMutation("/version-open-token", { name: "cloud-open-token-limit.txt", version: 1 });
  assert.equal(limitedVersionOpenToken.status, 429, limitedVersionOpenToken.body);
  assert.equal(cloud.getObjects.length, providerGetsAtVersionOpenTokenLimit, "a rejected version-token cache miss does not call the provider");

  const restoreLimiterBody = JSON.stringify({ username: "restore-limiter", password });
  const restoreLimiterLogin = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(restoreLimiterBody) }, body: restoreLimiterBody });
  assert.equal(restoreLimiterLogin.status, 200, restoreLimiterLogin.body);
  const restoreLimiterCookies = restoreLimiterLogin.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const restoreLimiterCookie = restoreLimiterCookies.join("; ");
  const restoreLimiterCsrf = restoreLimiterCookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  let currentVersion = 2;
  for (let index = 0; index < CLOUD_METADATA_REQUEST_LIMIT; index += 1) {
    const response = await request(port, `/restore/restore-limit.txt/v/${currentVersion - 1}`, {
      method: "POST",
      headers: { cookie: restoreLimiterCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": restoreLimiterCsrf },
    });
    assert.equal(response.status, 200, response.body);
    currentVersion = JSON.parse(response.body).version;
  }
  const versionsPath = path.join(dataDir, "file-versions.json");
  const versionsAtRestoreLimit = fs.readFileSync(versionsPath, "utf8");
  await waitForNoActiveRequests(path.join(dataDir, ".rootark-active-requests"));
  await waitForNoCloudUploadMutationRecords(path.join(dataDir, ".rootark-cloud-upload-mutations"));
  const providerGetsAtRestoreLimit = cloud.getObjects.length;
  const providerPutsAtRestoreLimit = cloud.putObjects.length;
  const limitedRestore = await request(port, `/restore/restore-limit.txt/v/${currentVersion - 1}`, {
    method: "POST",
    headers: { cookie: restoreLimiterCookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": restoreLimiterCsrf },
  });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(limitedRestore.status, 429, limitedRestore.body);
  assert.equal(fs.readFileSync(versionsPath, "utf8"), versionsAtRestoreLimit, "the rejected warm-cache restore does not mutate version history");
  assert.equal(cloud.getObjects.length, providerGetsAtRestoreLimit, "the rejected warm-cache restore makes no provider GET");
  assert.equal(cloud.putObjects.length, providerPutsAtRestoreLimit, "the rejected warm-cache restore makes no provider PUT");

  const durableDeleteName = "durable-version-delete.txt";
  const durableDeleteStoredName = `${durableDeleteName}.v1`;
  const durableDeleteKey = `rootark/uploads/root/${durableDeleteStoredName}`;
  cloud.failDelete(durableDeleteKey);
  OBJECTS.set(durableDeleteKey, Buffer.from("disposable historical version"));
  fs.writeFileSync(path.join(directory, "uploads", durableDeleteStoredName), "disposable historical version");
  const deletePermissionsPath = path.join(dataDir, "file-permissions.json");
  const deletePermissions = JSON.parse(fs.readFileSync(deletePermissionsPath, "utf8"));
  deletePermissions[`root/${durableDeleteName}`] = { public: false, owner: "owner", users: {} };
  fs.writeFileSync(deletePermissionsPath, JSON.stringify(deletePermissions));
  const deleteVersionsPath = path.join(dataDir, "file-versions.json");
  const deleteVersions = JSON.parse(fs.readFileSync(deleteVersionsPath, "utf8"));
  deleteVersions[`root/${durableDeleteName}`] = { currentVersion: 2, versions: [
    { version: 1, storedAs: durableDeleteStoredName, size: Buffer.byteLength("disposable historical version") },
    { version: 2, storedAs: durableDeleteName, size: 0 },
  ] };
  fs.writeFileSync(deleteVersionsPath, JSON.stringify(deleteVersions));
  const deletedVersionResponse = await mutateAsOwner(`/versions/${durableDeleteName}/v/1?folderId=root`, "DELETE", {});
  assert.equal(deletedVersionResponse.status, 200, deletedVersionResponse.body);
  assert.equal(fs.existsSync(path.join(directory, "uploads", durableDeleteStoredName)), false, "the explicit delete removes local archived bytes");
  const durableIntentPath = path.join(dataDir, ".rootark-cloud-upload-mutations", `${crypto.createHash("sha256").update(`root\0${durableDeleteStoredName}`).digest("hex")}.json`);
  const durableIntent = JSON.parse(fs.readFileSync(durableIntentPath, "utf8"));
  assert.equal(durableIntent.desired, "absent", "failed provider deletion leaves a durable absent intent after local version removal");
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(cloud.deleteObjects.includes(durableDeleteKey), true, "reconciliation attempted provider deletion");
  assert.equal(OBJECTS.has(durableDeleteKey), true, "provider failure leaves remote data for retry");
  assert.equal(JSON.parse(fs.readFileSync(durableIntentPath, "utf8")).desired, "absent", "failed reconciliation retains its durable intent");
});

test("local version deletion cancels an existing cloud-present intent without queueing local-only history", { timeout: 30_000 }, async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-local-version-delete-intent-"));
  const dataDir = path.join(directory, "data");
  fs.mkdirSync(dataDir, { recursive: true });
  fs.mkdirSync(path.join(directory, "uploads"), { recursive: true });
  fs.mkdirSync(path.join(directory, "temp"), { recursive: true });
  fs.symlinkSync(PUBLIC, path.join(directory, "public"), "junction");

  const pendingName = "pending-cloud-version.txt.v1";
  const localName = "local-only-version.txt.v1";
  for (const name of [pendingName, localName]) fs.writeFileSync(path.join(directory, "uploads", name), "disposable archived version");
  const password = crypto.randomBytes(24).toString("base64url");
  fs.writeFileSync(path.join(dataDir, "users.local.json"), JSON.stringify([
    { username: "owner", password: bcrypt.hashSync(password, 10), role: "user", permissions: { listFiles: true, delete: true }, sessionVersion: 0 },
  ]));
  fs.writeFileSync(path.join(dataDir, "folders.json"), JSON.stringify([
    { id: "root", name: "Root", createdBy: "system", allowedUsers: [], isRoot: true },
  ]));
  fs.writeFileSync(path.join(dataDir, "file-permissions.json"), JSON.stringify(Object.fromEntries([
    "pending-cloud-version.txt", "local-only-version.txt",
  ].map((name) => [`root/${name}`, { public: false, owner: "owner", users: {} }]))));
  fs.writeFileSync(path.join(dataDir, "file-versions.json"), JSON.stringify(Object.fromEntries([
    ["pending-cloud-version.txt", pendingName], ["local-only-version.txt", localName],
  ].map(([name, storedAs]) => [`root/${name}`, { currentVersion: 2, versions: [
    { version: 1, storedAs, size: Buffer.byteLength("disposable archived version") },
    { version: 2, storedAs: name, size: 0 },
  ] }]))));

  const queueDirectory = path.join(dataDir, ".rootark-cloud-upload-mutations");
  const disabledQueue = createCloudTempMutationQueue({
    area: "uploads", directory: queueDirectory,
    lifecycleLock: { run: async (_folderId, _fileName, work) => work() },
    localPathFor: () => "", upload: async () => {}, remove: async () => {}, isEnabled: () => false,
  });
  disabledQueue.setDesired("root", pendingName, "present");
  const port = await getUnusedPort();
  const env = {
    ...process.env, PORT: String(port), DB_ENABLED: "false", NODE_ENV: "test",
    JWT_SECRET: crypto.randomBytes(48).toString("base64url"), TOTP_POLICY: "optional",
    CLOUD_STORAGE_PROVIDER: "local", WEBDAV_ENABLED: "false",
  };
  delete env.ROOTARK_DEV_BOOTSTRAP_DEFAULTS;
  delete env.ROOTARK_BOOTSTRAP_USERS_FROM_SEED;
  delete env.TRUSTED_PROXIES;
  const child = spawn(process.execPath, [SERVER], { cwd: directory, env, stdio: "ignore", windowsHide: true });
  t.after(async () => {
    await stop(child);
    fs.rmSync(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  });
  assert.equal((await waitForServer(port, child)).status, 200);
  const loginBody = JSON.stringify({ username: "owner", password });
  const login = await request(port, "/auth/login", { method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(loginBody) }, body: loginBody });
  assert.equal(login.status, 200, login.body);
  const cookies = login.headers["set-cookie"].map((value) => value.split(";", 1)[0]);
  const cookie = cookies.join("; ");
  const csrf = cookies.find((value) => value.startsWith("rootark_csrf=")).split("=", 2)[1];
  const removeVersion = (fileName) => request(port, `/versions/${fileName}/v/1?folderId=root`, {
    method: "DELETE",
    headers: { cookie, origin: `http://127.0.0.1:${port}`, "x-csrf-token": csrf, "content-type": "application/json", "content-length": 2 },
    body: "{}",
  });

  const existingIntentDelete = await removeVersion("pending-cloud-version.txt");
  assert.equal(existingIntentDelete.status, 200, existingIntentDelete.body);
  assert.equal(disabledQueue.getRecord("root", pendingName)?.desired, "absent", "local deletion supersedes a persisted cloud-present intent while the provider is disabled");
  const localOnlyDelete = await removeVersion("local-only-version.txt");
  assert.equal(localOnlyDelete.status, 200, localOnlyDelete.body);
  assert.equal(disabledQueue.getRecord("root", localName), null, "local-only version deletion does not create a cloud mutation intent");
});
