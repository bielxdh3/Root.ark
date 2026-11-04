"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const crypto = require("node:crypto");
const http = require("node:http");
const os = require("node:os");
const file = require("../public/client/rootark-zk1-file-content");
const legacy = require("../public/client/rootark-dev-vault-migration");

const SRC = path.resolve(__dirname, "../server.js");
const code = fs.readFileSync(SRC, "utf8");

function section(start, end) {
  const a = code.indexOf(start);
  const b = code.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, "server route exists");
  return code.slice(a, b);
}

test("incomplete historical uploadedAt is stable and never fabricated at read time", () => {
  const fn = vm.runInNewContext("(" + section("function normalizeVersionHistory(entry) {",
    "\nfunction getVersionHistory(") + ")", { path, Date });
  const record = { currentVersion: 1, versions: [{ version: 1, storedAs: "old.v1", size: 1 }] };
  const first = fn(record).versions[0].uploadedAt;
  const second = fn(record).versions[0].uploadedAt;
  assert.equal(first, null, "missing historical date must fail closed");
  assert.equal(second, first);
  assert.equal(fn({ currentVersion: 1, versions: [{ ...record.versions[0],
    uploadedAt: "2026-10-22T01:00:00.000Z" }] }).versions[0].uploadedAt,
  "2026-10-22T01:00:00.000Z");
});

test("historical Last-Modified uses pinned version metadata even after cloud cache rehydration", async () => {
  let handler;
  let cacheMtime = "Mon, 19 Oct 2026 01:00:00 GMT";
  let historicalUploadedAt = "2026-10-22T01:00:00.000Z";
  const transmitted = [];
  const app = { get(_route, ...args) { handler = args.at(-1); } };
  const serverContext = {
    app, authenticate() {}, requirePermission() { return () => {}; }, path,
    getReadableFolderOrRespond() { return { id: "folder", uploadDir: "/cache" }; },
    isFileInTrash() { return false; }, hasFileAccess() { return true; },
    getEncryptedFileMetadata() { return null; },
    getVersionFilePath() { return { filePath: "/cache/old.v1",
      version: { storedAs: "old.v1", uploadedAt: historicalUploadedAt } }; },
    isRestoreProviderOrphanDenied() { return false; },
    ensureCloudFileCached() { return Promise.resolve(true); },
    refreshAuthenticatedUser() { return true; },
    getFolderById() { return { id: "folder" }; },
    hasFolderAccess() { return true; }, isFolderAvailable() { return true; },
    isFileExpired() { return false; }, isExistingFile() { return true; },
    sendOptimizedFile(_req, _res, _filePath, _name, _disposition, options) {
      transmitted.push({ cacheMtime, options });
    },
  };
  vm.runInNewContext(section('app.get("/download/:filename/v/:version"',
    '\napp.post("/version-open-token"'), serverContext);
  const req = { params: { filename: "old.txt", version: "1" }, query: {},
    user: { permissions: { listFiles: true } } };
  const res = { status(n) { this.statusCode = n; return this; },
    json() { return this; } };
  await handler(req, res);
  cacheMtime = "Fri, 23 Oct 2026 01:37:00 GMT";
  await handler(req, res);
  assert.equal(transmitted.length, 2);
  assert.deepEqual(transmitted.map((entry) => entry.options.lastModified),
    ["Thu, 22 Oct 2026 01:00:00 GMT", "Thu, 22 Oct 2026 01:00:00 GMT"]);
  historicalUploadedAt = null;
  await handler(req, res);
  assert.equal(res.statusCode, 409);
  assert.equal(transmitted.length, 2, "missing timestamp must not stream historical bytes");
});

test("real historical HTTP responses emit pinned Last-Modified for full and range GET and deny invalid pins", async (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-legacy-lastmodified-http-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const localPath = path.join(temp, "rehydrated.ct");
  const bytes = Buffer.from("historical ciphertext bytes", "utf8");
  fs.writeFileSync(localPath, bytes);
  fs.utimesSync(localPath, new Date("2026-10-26T12:01:00.000Z"), new Date("2026-10-26T12:01:00.000Z"));
  const pinned = "Thu, 22 Oct 2026 01:00:00 GMT";
  const parseRangeHeader = vm.runInNewContext("(" + section("function parseRangeHeader(",
    "\nfunction sendOptimizedFile(") + ")");
  const sendOptimizedFile = vm.runInNewContext("(" + section("function sendOptimizedFile(",
    "\nfunction removeFileExpiration(") + ")", {
    fs, path, parseRangeHeader,
    openReadHandle(name) {
      const fd = fs.openSync(name, fs.constants.O_RDONLY);
      return { fd, stats: fs.fstatSync(fd) };
    },
    getMimeType() { return "application/octet-stream"; },
    getFileContentDisposition() { return 'attachment; filename="archive.ct"'; },
    isActiveContentFile() { return false; }, console,
  });
  const server = http.createServer((req, res) => {
    res.status = function (status) { this.statusCode = status; return this; };
    res.send = function (message) { this.end(message); return this; };
    sendOptimizedFile(req, res, localPath, "archive.ct", "attachment", {
      includeLastModified: true,
      lastModified: req.url === "/invalid" ? "Thu, 22 Oct 2026 01:00:00 GMT\r\nX-Injected: yes" : pinned,
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}`;
  for (const [name, headers, status, expected] of [
    ["full", {}, 200, bytes],
    ["range", { Range: "bytes=0-3" }, 206, bytes.subarray(0, 4)],
  ]) {
    const response = await fetch(base + "/" + name, { headers });
    assert.equal(response.status, status);
    assert.equal(response.headers.get("last-modified"), pinned,
      `${name} must use the stored, not newly rehydrated, file timestamp`);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), expected);
  }
  const rejected = await fetch(base + "/invalid");
  assert.equal(rejected.status, 409, "a noncanonical/injected pin must fail before bytes are sent");
  assert.notDeepEqual(Buffer.from(await rejected.arrayBuffer()), bytes);
});

test("oversized MIME header cancels plaintext response without returning bytes", async () => {
  let canceled = false;
  await assert.rejects(legacy.readLegacyPlaintext({ name: "old.txt",
    fetchImpl: async () => ({ status: 200, headers: { get(key) {
      if (key === "content-disposition") return "attachment";
      if (key === "content-length") return "1";
      return "x".repeat(129);
    } }, body: { getReader() { throw Error("should never read"); },
      cancel() { canceled = true; return Promise.resolve(); } } }),
  }));
  assert.equal(canceled, true);
});

test("late noncooperative plaintext fetch is canceled after the deadline", async () => {
  const ctx = acceleratedContext();
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-dev-vault-migration.js"), "utf8"), ctx);
  let publishLate, canceled = false;
  const noncooperative = new Promise((resolve) => { publishLate = resolve; });
  const pending = ctx.RootarkDevVaultMigration.readLegacyPlaintext({
    name: "old.txt", fetchImpl: () => noncooperative,
  });
  await assert.rejects(Promise.race([pending,
    new Promise((_, reject) => setTimeout(() => reject(Error("watchdog")), 350))]),
  (error) => error.message !== "watchdog");
  publishLate({ status: 200, body: { cancel() { canceled = true; return Promise.resolve(); } } });
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(canceled, true);
});

function acceleratedContext() {
  return vm.createContext({ crypto: crypto.webcrypto, Uint8Array, ArrayBuffer,
    TextEncoder, TextDecoder, AbortController, atob, btoa,
    setTimeout: (fn, duration) => setTimeout(fn, Math.min(duration, 10)), clearTimeout });
}

test("legacy plaintext stream aborts and cancels a stalled body within the deadline", async () => {
  const ctx = acceleratedContext();
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-dev-vault-migration.js"), "utf8"), ctx);
  let signal, canceled = false;
  const body = new ReadableStream({ cancel() { canceled = true; } });
  const migration = ctx.RootarkDevVaultMigration;
  await assert.rejects(Promise.race([migration.readLegacyPlaintext({ name: "old.txt",
    fetchImpl: async (_url, options) => {
      signal = options.signal;
      return { status: 200, headers: { get(key) {
        return key === "content-disposition" ? "attachment"
          : key === "content-length" ? "1" : "text/plain";
      } }, body };
    },
  }), new Promise((_, reject) => setTimeout(() => reject(Error("watchdog")), 350))]),
  (error) => error.message !== "watchdog");
  assert.equal(signal.aborted, true);
  assert.equal(canceled, true);
});

test("stalled legacy catalog fails within deadline and never starts ciphertext PUT", async () => {
  const ctx = acceleratedContext();
  let writes = 0;
  ctx.RootarkZk1LegacyMigrationWorkflow = { beginLegacyMigration() { writes++; } };
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-legacy-batch-migration.js"), "utf8"), ctx);
  const cek = await file.generateFileCek();
  let signal, canceled = false;
  const blockedBody = new ReadableStream({ cancel() { canceled = true; } });
  const input = vm.runInContext(`({ optIn: true, entries: [{
    legacy: { name: "old.txt", folderId: "" },
    sourcePin: { version: 1, storedAs: "old.v1", uploadedAt: "2026-10-22T01:00:00.000Z",
      size: 1, lastModified: "Thu, 22 Oct 2026 01:00:00 GMT",
      sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", mediaType: "text/plain" },
    cek: null }], migrationSecret: new Uint8Array(32),
    trust: { signedDeviceGrant: { account_id: "a", compartment_id: "b", keyring_id: "c" },
      independentOwnerSpkiSha256: new Uint8Array(32),
      pinnedCurrentHead: { digest: new Uint8Array(32), revision: 1, epoch: 1 } },
    origin: "http://localhost/", journal: null, nowSeconds: 1400, fetchImpl: null })`, ctx);
  input.entries[0].cek = cek;
  input.fetchImpl = async (_url, options) => {
    signal = options.signal;
    return { status: 200, headers: { get() { return "application/json"; } }, body: blockedBody };
  };
  const result = await Promise.race([ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(input),
    new Promise((_, reject) => setTimeout(() => reject(Error("watchdog")), 350))]);
  assert.equal(result.verified, 0);
  assert.equal(result.results[0].phase, "needs-manual-review");
  assert.equal(signal.aborted, true);
  assert.equal(canceled, true);
  assert.equal(writes, 0);
});

test("legacy batch authenticates root and nested folder identity before and after copying", async () => {
  const ctx = acceleratedContext();
  let writes = 0;
  ctx.RootarkZk1LegacyMigrationWorkflow = {
    async beginLegacyMigration() {
      writes++;
      return { phase: "awaiting-independent-owner-checkpoint", root: "signed-get-root" };
    },
  };
  vm.runInContext(fs.readFileSync(path.resolve(__dirname,
    "../public/client/rootark-zk1-legacy-batch-migration.js"), "utf8"), ctx);
  const input = vm.runInContext(`({ optIn: true, entries: [{
    legacy: { name: "old.txt", folderId: "" },
    sourcePin: { version: 1, storedAs: "old.v1", uploadedAt: "2026-10-22T01:00:00.000Z",
      size: 1, lastModified: "Thu, 22 Oct 2026 01:00:00 GMT",
      sha256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", mediaType: "text/plain" },
    cek: null }], migrationSecret: new Uint8Array(32),
    trust: { signedDeviceGrant: { account_id: "a", compartment_id: "b", keyring_id: "c" },
      independentOwnerSpkiSha256: new Uint8Array(32),
      pinnedCurrentHead: { digest: new Uint8Array(32), revision: 1, epoch: 1 } },
    origin: "http://localhost/", journal: null, nowSeconds: 1400, fetchImpl: null })`, ctx);
  input.entries[0].cek = await file.generateFileCek();
  const catalogResponse = (folderId) => new Response(JSON.stringify({
    folderId, fileName: "old.txt", versions: [{
      version: 1, storedAs: "old.v1", uploadedAt: "2026-10-22T01:00:00.000Z", size: 1,
    }],
  }), { status: 200, headers: { "content-type": "application/json" } });
  const check = async (folders) => {
    let reads = 0;
    const urls = [];
    input.fetchImpl = async (url) => {
      urls.push(url);
      return catalogResponse(folders[Math.min(reads++, folders.length - 1)]);
    };
    const result = await ctx.RootarkZk1LegacyBatchMigration.runLegacyMigrationBatch(input);
    return { result, urls, reads };
  };

  // Existing lab fixtures identify root as "", while the real server uses "root".
  for (const folderId of ["", "root"]) {
    const verified = await check([folderId]);
    assert.equal(verified.result.verified, 1);
    assert.equal(verified.reads, 2);
    assert.deepEqual(verified.urls, ["/versions/old.txt", "/versions/old.txt"]);
  }
  const baselineWrites = writes;
  for (const malicious of ["foreign-folder", undefined, null, "../traversal", {}]) {
    const rejected = await check([malicious]);
    assert.equal(rejected.result.verified, 0);
    assert.equal(rejected.result.results[0].phase, "needs-manual-review");
    assert.equal(rejected.reads, 1, "mismatched source blocks copy before PUT");
    assert.equal(writes, baselineWrites);
  }
  const swappedAfterCopy = await check(["root", "foreign-folder"]);
  assert.equal(swappedAfterCopy.result.verified, 0);
  assert.equal(swappedAfterCopy.result.results[0].phase, "needs-manual-review");
  assert.equal(swappedAfterCopy.reads, 2);
  assert.equal(writes, baselineWrites + 1, "post-copy source swap never reports verified");

  input.entries[0].legacy.folderId = "nested-folder";
  const wrongNested = await check(["root"]);
  assert.equal(wrongNested.result.verified, 0);
  assert.equal(wrongNested.reads, 1);
  assert.equal(writes, baselineWrites + 1);
  const exactNested = await check(["nested-folder"]);
  assert.equal(exactNested.result.verified, 1);
  assert.deepEqual(exactNested.urls, [
    "/versions/old.txt?folderId=nested-folder", "/versions/old.txt?folderId=nested-folder",
  ]);
});
