"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } = require("../sync-client/rootark-sync-private-config");

test("two relative paths with identical remote basename must fail closed before HTTP", {
  timeout: 60000,
}, async (t) => {
  const privateDir = createPrivateAuthorityFixture("rootark-basename-private-");
  const shared = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-basename-source-"));
  t.after(async () => {
    await fs.rm(shared, { recursive: true, force: true });
    await fs.rm(privateDir, { recursive: true, force: true });
  });
  for (const dir of ["first", "second"]) {
    await fs.mkdir(path.join(shared, dir));
    await fs.writeFile(path.join(shared, dir, "same.txt"), `UNIQUE_${dir}`);
  }
  let uploads = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    } else if (req.url.startsWith("/upload?")) {
      uploads++;
      req.resume();
      req.on("end", () => res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ fileName: "same.txt" })));
    } else res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const configPath = path.join(privateDir, "config.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    localFolder: shared, targetFolderId: "root", username: "fixture",
    token: "fixture-token", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--once", "--config", configPath],
    { cwd: privateDir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (part) => { output += part; });
  child.stderr.on("data", (part) => { output += part; });
  t.after(() => child.kill());
  const done = await new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  assert.notEqual(done, 0, "ambiguous remote basename must not report successful mirror");
  assert.match(output, /SYNC_REMOTE_BASENAME_COLLISION/);
  assert.equal(uploads, 0, "collision preflight must reject before remote side effects");
});

test("renaming the source during an unacknowledged POST cannot release remote basename ownership", {
  timeout: 30000,
}, async (t) => {
  const privateDir = createPrivateAuthorityFixture("rootark-basename-aba-private-");
  const shared = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-basename-aba-source-"));
  t.after(async () => {
    await fs.rm(shared, { recursive: true, force: true });
    await fs.rm(privateDir, { recursive: true, force: true });
  });
  for (const dir of ["first", "second"]) await fs.mkdir(path.join(shared, dir));
  const oldPath = path.join(shared, "first", "same.txt");
  await fs.writeFile(oldPath, "OLD_REMOTE_BYTES");
  let uploads = 0;
  let releaseOld;
  let notifyOld;
  const oldReceived = new Promise((resolve) => { notifyOld = resolve; });
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    } else if (req.url.startsWith("/upload?")) {
      uploads++;
      req.resume();
      req.on("end", () => {
        if (uploads === 1) {
          releaseOld = () => {
            if (!res.destroyed) res.writeHead(200, { "Content-Type": "application/json" })
              .end(JSON.stringify({ fileName: "same.txt" }));
          };
          notifyOld();
        } else {
          res.writeHead(200, { "Content-Type": "application/json" })
            .end(JSON.stringify({ fileName: "same.txt" }));
        }
      });
    } else res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const configPath = path.join(privateDir, "config.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    localFolder: shared, targetFolderId: "root", username: "fixture",
    token: "fixture-token", debounceMs: 1, stabilityMs: 1,
    scanIntervalMs: 75, retryLimit: 1,
  }));
  const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--config", configPath],
    { cwd: privateDir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (part) => { output += part; });
  child.stderr.on("data", (part) => { output += part; });
  t.after(() => child.kill());
  const exited = new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  try {
    await oldReceived;
    await fs.unlink(oldPath);
    await fs.writeFile(path.join(shared, "second", "same.txt"), "NEW_REMOTE_BYTES");
    const deadline = Date.now() + 5000;
    while (!output.includes("SYNC_REMOTE_BASENAME_COLLISION") && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.match(output, /SYNC_REMOTE_BASENAME_COLLISION/);
    assert.equal(uploads, 1,
      "new path must not start a second POST while old basename remains active");
  } finally {
    if (releaseOld) releaseOld();
    child.kill("SIGINT");
    await exited;
  }
  assert.equal(uploads, 1);
});

test("basename conflict appearing during stability preflight prevents the first POST", {
  timeout: 30000,
  skip: process.platform === "win32"
    ? "Timing-sensitive pre-POST race fixture runs on POSIX; Windows exercises atomic conflict detection"
    : false,
}, async (t) => {
  const privateDir = createPrivateAuthorityFixture("rootark-basename-prepost-private-");
  const shared = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-basename-prepost-source-"));
  t.after(async () => {
    await fs.rm(shared, { recursive: true, force: true });
    await fs.rm(privateDir, { recursive: true, force: true });
  });
  for (const dir of ["first", "second"]) await fs.mkdir(path.join(shared, dir));
  await fs.writeFile(path.join(shared, "first", "same.txt"), "OLD_SOURCE");
  let uploads = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    } else if (req.url.startsWith("/upload?")) {
      uploads++;
      req.resume();
      req.on("end", () => res.writeHead(200, { "Content-Type": "application/json" }).end("{}"));
    } else res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const configPath = path.join(privateDir, "config.json");
  await writePrivateSyncConfig(configPath, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    localFolder: shared, targetFolderId: "root", username: "fixture",
    token: "fixture-token", debounceMs: 1, stabilityMs: 1500,
    scanIntervalMs: 50, retryLimit: 1,
  }));
  const cli = path.resolve(__dirname, "../sync-client/rootark-sync.js");
  const child = spawn(process.execPath,
    [cli, "start", "--legacy-development-opt-in", "--config", configPath],
    { cwd: privateDir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (part) => { output += part; });
  child.stderr.on("data", (part) => { output += part; });
  t.after(() => child.kill());
  const exited = new Promise((resolve, reject) => {
    child.once("close", resolve);
    child.once("error", reject);
  });
  try {
    const startedDeadline = Date.now() + 5000;
    while (!output.includes("Sync iniciado") && Date.now() < startedDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.match(output, /Sync iniciado/);
    // Allow initial scan to claim the first path, but do not let its 1.5s
    // stability snapshot complete before planting the colliding path.
    await new Promise((resolve) => setTimeout(resolve, 250));
    await fs.writeFile(path.join(shared, "second", "same.txt"), "NEW_SOURCE");
    const deadline = Date.now() + 4000;
    while (!output.includes("SYNC_REMOTE_BASENAME_COLLISION") && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.match(output, /SYNC_REMOTE_BASENAME_COLLISION/);
    await new Promise((resolve) => setTimeout(resolve, 1700));
    assert.equal(uploads, 0, "first task must recheck collision at POST boundary");
  } finally {
    child.kill("SIGINT");
    await exited;
  }
});
