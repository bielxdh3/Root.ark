"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const { createRequire } = require("node:module");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { promisify } = require("node:util");
const vm = require("node:vm");

const execFileAsync = promisify(execFile);
const syncScript = path.resolve(__dirname, "../sync-client/rootark-sync.js");
const requireSyncModule = createRequire(syncScript);

async function listen(t, handler) {
  const server = http.createServer(handler);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  t.after(async () => {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

function capture(request, response, received, reply = "{}") {
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    received.push(Buffer.concat(chunks));
    response.writeHead(200, { "content-type": "application/json" });
    response.end(reply);
  });
}

test("legacy uploader rejects cross-origin 307 without forwarding local file bytes", {
  timeout: 20_000,
}, async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-redirect-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const localFolder = path.join(root, "sync");
  await fsp.mkdir(localFolder);
  const secret = `fixture-only-${crypto.randomBytes(16).toString("hex")}`;
  await fsp.writeFile(path.join(localFolder, "payload.txt"), secret);

  const received = [];
  const foreign = await listen(t, (req, res) => capture(req, res, received,
    '{"fileName":"payload.txt"}'));
  let redirectCount = 0;
  const trusted = await listen(t, (req, res) => {
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end("[]");
    } else if (req.url.startsWith("/upload?")) {
      redirectCount++;
      req.resume();
      res.writeHead(307, { location: `${foreign}/capture` });
      res.end();
    } else { res.writeHead(404); res.end(); }
  });
  const config = path.join(root, "config.json");
  await fsp.writeFile(config, JSON.stringify({
    serverUrl: trusted, token: "synthetic-test-token", localFolder,
    targetFolderId: "root", retryLimit: 1, debounceMs: 1, stabilityMs: 1,
  }));

  await execFileAsync(process.execPath,
    [syncScript, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { timeout: 15_000, cwd: root, windowsHide: true });
  assert.equal(redirectCount, 1, "the protected upload route was reached");
  assert.equal(received.length, 0,
    "a malicious 307 must never forward multipart ciphertext or files to another origin");
});

test("legacy login rejects cross-origin 307 without forwarding password", {
  timeout: 10_000,
}, async (t) => {
  const received = [];
  const foreign = await listen(t, (req, res) => capture(req, res, received,
    '{"token":"synthetic-attacker-issued-token"}'));
  let loginCount = 0;
  const trusted = await listen(t, (req, res) => {
    loginCount++;
    req.resume();
    res.writeHead(307, { location: `${foreign}/capture-login` });
    res.end();
  });
  const source = fs.readFileSync(syncScript, "utf8");
  const context = vm.createContext({
    require: requireSyncModule, Buffer, fetch, setTimeout, clearTimeout,
    console: { log() {}, error() {} },
    process: { argv: ["node", syncScript, "help"], cwd: () => process.cwd(), env: {} },
  });
  vm.runInContext(`${source}\n;globalThis.testLogin = login;`, context,
    { filename: syncScript });
  await context.testLogin(trusted, "synthetic-user", "synthetic-password").catch(() => {});
  assert.equal(loginCount, 1);
  assert.equal(received.length, 0,
    "a malicious login redirect must not send the password to another origin");
});

test("legacy JSON writer cannot truncate a file hardlinked to predictable PID stage", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-stage-alias-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const protectedFile = path.join(root, "keep.txt");
  const destination = path.join(root, "state.json");
  const marker = "must-not-be-truncated-by-config-save";
  await fsp.writeFile(protectedFile, marker);
  // The legacy stage name is fully predictable from the process ID.
  const planted = `${destination}.tmp-${process.pid}`;
  await fsp.link(protectedFile, planted);

  const context = vm.createContext({
    require: requireSyncModule, Buffer, fetch, setTimeout, clearTimeout,
    console: { log() {}, error() {} },
    process: {
      argv: ["node", syncScript, "help"], cwd: () => root,
      pid: process.pid, env: {},
    },
  });
  vm.runInContext(`${fs.readFileSync(syncScript, "utf8")}\n;
    globalThis.writeAtomic = writeJsonAtomic;`, context, { filename: syncScript });
  await context.writeAtomic(destination, { status: "safe" });
  assert.equal(await fsp.readFile(protectedFile, "utf8"), marker,
    "a preexisting hardlink must not redirect writes into unrelated files");
  assert.deepEqual(JSON.parse(await fsp.readFile(destination, "utf8")), { status: "safe" });
});
