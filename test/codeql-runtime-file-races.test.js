"use strict";

const assert = require("node:assert/strict");
const { execFile, spawn } = require("node:child_process");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { promisify } = require("node:util");
const { previewText } = require("../services/documentPreviewService");

const execFileAsync = promisify(execFile);

test("preview rejects a text symlink pointing to another file", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-link-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const outside = path.join(dir, "other.txt");
  const alias = path.join(dir, "requested.txt");
  fs.writeFileSync(outside, "outside-file-sentinel");
  try { fs.symlinkSync(outside, alias, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("OS does not allow disposable file symlinks");
    throw error;
  }
  await assert.rejects(previewText(alias, "requested.txt"));
});

test("document preview rejects symlink input before launching a parser", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-preview-doc-link-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const outside = path.join(dir, "outside.doc");
  const alias = path.join(dir, "requested.doc");
  fs.writeFileSync(outside, "disposable-data");
  try { fs.symlinkSync(outside, alias, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("OS does not allow disposable file symlinks");
    throw error;
  }
  let spawned = false;
  await assert.rejects(previewText(alias, "requested.doc", { spawnImpl: () => {
    spawned = true;
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.exitCode = null;
    setImmediate(() => {
      child.stdout.emit("data", Buffer.from(JSON.stringify({ ok: true, content: "unwanted" })));
      child.exitCode = 0;
      child.emit("close", 0);
    });
    return child;
  } }));
  assert.equal(spawned, false);
});

test("legacy sync ignores directory junctions and symlinks leading outside selected folder", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-link-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const selected = path.join(dir, "selected");
  const outside = path.join(dir, "outside");
  await fsp.mkdir(selected);
  await fsp.mkdir(outside);
  await fsp.writeFile(path.join(outside, "outside.txt"), "outside-file-sentinel");
  await fsp.writeFile(path.join(selected, "inside.txt"), "inside-file-sentinel");
  try { fs.symlinkSync(outside, path.join(selected, "external"), process.platform === "win32" ? "junction" : "dir"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("OS does not allow disposable directory links");
    throw error;
  }

  const uploads = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) return res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (part) => chunks.push(part));
      req.on("end", () => {
        uploads.push(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ fileName: "uploaded.txt" }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(dir, "config.json");
  await fsp.writeFile(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "test", token: "fixture-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  await execFileAsync(process.execPath, [path.resolve(__dirname, "../sync-client/rootark-sync.js"), "start", "--legacy-development-opt-in", "--once", "--config", config], { timeout: 15_000 });
  assert.ok(uploads.some((value) => value.includes("inside-file-sentinel")), "in-folder file should upload");
  assert.equal(uploads.some((value) => value.includes("outside-file-sentinel")), false, "outside file must not upload");
});

test("legacy sync uploads its verified snapshot if the file is replaced during remote listing", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-swap-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const selected = path.join(dir, "selected");
  await fsp.mkdir(selected);
  const source = path.join(selected, "inside.txt");
  const outside = path.join(dir, "other.txt");
  await fsp.writeFile(source, "inside-snapshot-sentinel");
  await fsp.writeFile(outside, "outside-swap-sentinel");
  let uploaded = "";
  let swapped = false;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      if (!swapped) {
        swapped = true;
        fs.unlinkSync(source);
        fs.symlinkSync(outside, source, "file");
      }
      return res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (part) => chunks.push(part));
      req.on("end", () => {
        uploaded += Buffer.concat(chunks).toString("utf8");
        res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ fileName: "inside.txt" }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(dir, "config.json");
  await fsp.writeFile(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "test", token: "fixture-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  await execFileAsync(process.execPath, [path.resolve(__dirname, "../sync-client/rootark-sync.js"), "start", "--legacy-development-opt-in", "--once", "--config", config], { timeout: 15_000 });
  assert.equal(swapped, true, "fixture should race the remote-list response");
  assert.match(uploaded, /inside-snapshot-sentinel/);
  assert.doesNotMatch(uploaded, /outside-swap-sentinel/);
});

test("legacy sync bounds pinned snapshots while many remote listings stall", { timeout: 30_000 }, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-memory-bound-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const selected = path.join(dir, "selected");
  await fsp.mkdir(selected);
  const fileCount = 28;
  for (let index = 0; index < fileCount; index++) {
    await fsp.writeFile(path.join(selected, `file-${index}.txt`), Buffer.alloc(128 * 1024, index + 1));
  }
  let pendingLists = [];
  let listings = 0;
  let releaseListings = false;
  const uploaded = [];
  const listOk = (res) => res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      listings++;
      if (releaseListings) listOk(res);
      else pendingLists.push(res);
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (part) => chunks.push(part));
      req.on("end", () => {
        uploaded.push(Buffer.concat(chunks));
        res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ fileName: "uploaded.txt" }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    releaseListings = true;
    for (const res of pendingLists) if (!res.writableEnded) listOk(res);
    pendingLists = [];
    await new Promise((resolve) => server.close(resolve));
  });
  const config = path.join(dir, "config.json");
  await fsp.writeFile(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "test", token: "fixture-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const child = spawn(process.execPath, [
    path.resolve(__dirname, "../sync-client/rootark-sync.js"), "start",
    "--legacy-development-opt-in", "--once", "--config", config,
  ], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
  let stderr = "";
  child.stderr.on("data", (part) => { stderr += part; });
  child.stdout.resume();
  const completion = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code) => resolve(code));
  });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  await new Promise((resolve) => setTimeout(resolve, 1000));
  const stalledListCount = listings;
  releaseListings = true;
  for (const res of pendingLists) if (!res.writableEnded) listOk(res);
  pendingLists = [];
  assert.ok(stalledListCount > 0, "uploads must reach the stalled network boundary");
  assert.ok(stalledListCount <= 4,
    `at most four resident file snapshots may wait for the network; saw ${stalledListCount}`);
  assert.equal(await completion, 0, stderr);
  assert.equal(uploaded.length, fileCount, "once mode must drain every queued file");
});

test("legacy sync never re-stats an enlarged file into an unbounded read allocation", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-growth-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const selected = path.join(dir, "selected");
  await fsp.mkdir(selected);
  const target = path.join(selected, "mutable.txt");
  const marker = path.join(dir, "unbounded-read.marker");
  await fsp.writeFile(target, "small");
  let uploads = 0;
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      return res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    }
    if (req.url.startsWith("/upload?")) {
      uploads++;
      req.resume();
      return res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(dir, "config.json");
  await fsp.writeFile(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "test", token: "fixture-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const preload = path.resolve(__dirname, "support/legacy-sync-grow-file-hook.js");
  await execFileAsync(process.execPath,
    ["-r", preload, path.resolve(__dirname, "../sync-client/rootark-sync.js"),
      "start", "--legacy-development-opt-in", "--once", "--config", config], {
      timeout: 15_000,
      env: { ...process.env, ROOTARK_TEST_SYNC_GROW_PATH: target,
        ROOTARK_TEST_SYNC_UNBOUNDED_READ_MARKER: marker },
    });
  assert.ok((await fsp.stat(target)).size > 8 * 1024 * 1024, "fixture must grow a pinned inode");
  assert.equal(fs.existsSync(marker), false, "a post-stat FileHandle.readFile must never allocate from a grown size");
  assert.equal(uploads, 0, "a grown file must never be sent");
});

test("remote deletion refuses a symlinked claim coordination directory", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-trash-coordination-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const outside = path.join(dir, "outside");
  const data = path.join(dir, "data");
  await fsp.mkdir(outside);
  await fsp.mkdir(data);
  try { fs.symlinkSync(outside, path.join(data, "trash-remote-locks"), process.platform === "win32" ? "junction" : "dir"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("OS does not allow disposable directory links");
    throw error;
  }
  const servicePath = path.resolve(__dirname, "../services/trashService.js");
  const script = `const svc = require(${JSON.stringify(servicePath)});\n` +
    "try { svc.claimRemoteDeletion({ item: { id: 'fixture', metadata: { remoteDeletion: { state: 'pending', operationId: 'fixture' } } } }); process.exit(9); } catch { process.exit(0); }";
  await execFileAsync(process.execPath, ["-e", script], { cwd: dir, timeout: 5000 });
  assert.deepEqual(await fsp.readdir(outside), [], "no database or lock should be written through the link");
});
