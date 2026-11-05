"use strict";

const assert = require("node:assert/strict");
const { execFile, execFileSync, spawn } = require("node:child_process");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { promisify } = require("node:util");
const { previewText } = require("../services/documentPreviewService");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");

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
  // Keep the bearer config independent of the adversarial selected tree:
  // Windows authority preflight must not traverse its intentional junction.
  const configRoot = createPrivateAuthorityFixture("rootark-sync-config-link-");
  t.after(() => fsp.rm(configRoot, { recursive: true, force: true }));
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
  const config = path.join(configRoot, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
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
  const configRoot = createPrivateAuthorityFixture("rootark-sync-config-swap-");
  t.after(() => fsp.rm(configRoot, { recursive: true, force: true }));
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
  const config = path.join(configRoot, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "test", token: "fixture-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  await execFileAsync(process.execPath, [path.resolve(__dirname, "../sync-client/rootark-sync.js"), "start", "--legacy-development-opt-in", "--once", "--config", config], { timeout: 15_000 });
  assert.equal(swapped, true, "fixture should race the remote-list response");
  assert.match(uploaded, /inside-snapshot-sentinel/);
  assert.doesNotMatch(uploaded, /outside-swap-sentinel/);
});

test("legacy sync bounds pinned snapshots while many remote listings stall", {
  // The native Windows authority ACL check runs for each of the 28 durable
  // private-state publications. Preserve the strict four-snapshot boundary,
  // but give hosted Windows enough wall-clock to finish the verified writes.
  timeout: process.platform === "win32" ? 180_000 : 30_000,
}, async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-sync-memory-bound-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const configRoot = createPrivateAuthorityFixture("rootark-sync-config-memory-");
  t.after(() => fsp.rm(configRoot, { recursive: true, force: true }));
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
  const config = path.join(configRoot, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
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
  // On Windows, the native owner/DACL verification precedes the first /list
  // and may take longer than 1s. Wait for the actual stalled-network boundary
  // instead of assuming a fixed process startup time. Keep the bound finite.
  const deadline = Date.now() + (process.platform === "win32" ? 45_000 : 12_000);
  while (listings === 0 && child.exitCode === null && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
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
  const configRoot = createPrivateAuthorityFixture("rootark-sync-config-growth-");
  t.after(() => fsp.rm(configRoot, { recursive: true, force: true }));
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
  const config = path.join(configRoot, "config.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "test", token: "fixture-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  const preload = path.resolve(__dirname, "support/legacy-sync-grow-file-hook.js");
  await execFileAsync(process.execPath,
    ["-r", preload, path.resolve(__dirname, "../sync-client/rootark-sync.js"),
      "start", "--legacy-development-opt-in", "--once", "--config", config], {
      timeout: 15_000,
      env: { ...process.env, ROOTARK_TEST_SYNC_GROW_FIXTURE: "1",
        ROOTARK_TEST_SYNC_GROW_PATH: target,
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

test("remote deletion refuses a junction in the data ancestor before any external write", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-trash-data-ancestor-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const outside = path.join(dir, "outside");
  const selected = path.join(dir, "selected");
  await fsp.mkdir(outside);
  await fsp.mkdir(selected);
  try {
    fs.symlinkSync(outside, path.join(selected, "data"), process.platform === "win32" ? "junction" : "dir");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("OS does not allow disposable directory links");
    throw error;
  }
  const servicePath = path.resolve(__dirname, "../services/trashService.js");
  const script = `const svc = require(${JSON.stringify(servicePath)});\n` +
    "try { svc.claimRemoteDeletion({ item: { id: 'ancestor-fixture', metadata: { remoteDeletion: { state: 'pending', operationId: 'ancestor-fixture' } } } }); process.exit(9); } catch { process.exit(0); }";
  await execFileAsync(process.execPath, ["-e", script], {
    cwd: selected, timeout: 5000, env: { ...process.env, DB_ENABLED: "false" },
  });
  assert.deepEqual(await fsp.readdir(outside), [],
    "a reparse-point ancestor must not redirect the claim DB or lock outside runtime data");
});

test("Windows remote claims deny Users:Modify on the data parent before creating locks or SQLite", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async () => {
  const selected = createPrivateAuthorityFixture("rootark-trash-acl-parent-");
  const data = path.join(selected, "data");
  const icacls = "C:\\Windows\\System32\\icacls.exe";
  const users = "*S-1-5-32-545";
  let granted = false;
  try {
    require("../services/chunkUploadWindowsAcl").ensureWindowsChunkUploadRoot(data);
    execFileSync(icacls, [data, "/grant", `${users}:(OI)(CI)M`],
      { windowsHide: true, stdio: "ignore", timeout: 12000 });
    granted = true;
    const servicePath = path.resolve(__dirname, "../services/trashService.js");
    const script = `const svc = require(${JSON.stringify(servicePath)});\n` +
      "try { svc.claimRemoteDeletion({ item: { id: 'acl-fixture', metadata: { remoteDeletion: { state: 'pending', operationId: 'acl-fixture' } } } }); process.exit(9); } catch (error) { if (!/ACL|Untrusted|unsafe/i.test(error.message)) throw error; process.exit(0); }";
    await execFileAsync(process.execPath, ["-e", script], {
      cwd: selected, timeout: 12000, env: { ...process.env, DB_ENABLED: "false" },
    });
    assert.deepEqual(fs.readdirSync(data), [],
      "untrusted DELETE_CHILD ACL must be denied before lockdir or SQLite/WAL/SHM creation");
  } finally {
    if (granted) {
      execFileSync(icacls, [data, "/remove:g", users],
        { windowsHide: true, stdio: "ignore", timeout: 12000 });
    }
    fs.rmSync(selected, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test("Windows remote claims safely migrate an old owned inherited-DACL lock directory", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async () => {
  const selected = createPrivateAuthorityFixture("rootark-trash-inherited-lock-");
  try {
    const data = path.join(selected, "data");
    const locks = path.join(data, "trash-remote-locks");
    const acl = require("../services/chunkUploadWindowsAcl");
    acl.ensureWindowsChunkUploadRoot(data);
    // Old code used fs.mkdirSync(mode:0700), which does NOT protect Windows
    // DACL inheritance. The inherited ACEs are still trusted owner-only.
    fs.mkdirSync(locks);
    const original = acl.getWindowsChunkAclDescriptor(locks);
    assert.doesNotMatch(original, /D:P/, "fixture must start with an unprotected inherited NTFS DACL");
    const preserved = path.join(locks, "old-owned-claim.lock");
    fs.writeFileSync(preserved, "existing-owner-claim");
    const servicePath = path.resolve(__dirname, "../services/trashService.js");
    const script = `const svc = require(${JSON.stringify(servicePath)});\n` +
      "const claim = svc.claimRemoteDeletion({ item: { id: 'legacy-acl-fixture', metadata: { remoteDeletion: { state: 'pending', operationId: 'legacy-acl-fixture' } } } }); if (!claim) process.exit(9);";
    await execFileAsync(process.execPath, ["-e", script], {
      cwd: selected, timeout: 15000, env: { ...process.env, DB_ENABLED: "false" },
    });
    assert.match(acl.getWindowsChunkAclDescriptor(locks), /D:P/,
      "trusted inherited ACEs must become an owner-private protected DACL");
    assert.equal(fs.readFileSync(preserved, "utf8"), "existing-owner-claim");
    assert.ok(fs.existsSync(path.join(locks, ".coordination.sqlite")));
  } finally {
    fs.rmSync(selected, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test("Windows remote claim migration never seals an inherited Users:Modify lock directory", {
  skip: process.platform !== "win32", timeout: 30_000,
}, async () => {
  const selected = createPrivateAuthorityFixture("rootark-trash-hostile-acl-");
  const icacls = "C:\\Windows\\System32\\icacls.exe";
  const users = "*S-1-5-32-545";
  const data = path.join(selected, "data");
  const locks = path.join(data, "trash-remote-locks");
  let granted = false;
  try {
    const acl = require("../services/chunkUploadWindowsAcl");
    acl.ensureWindowsChunkUploadRoot(data);
    fs.mkdirSync(locks);
    execFileSync(icacls, [locks, "/grant", `${users}:(OI)(CI)M`],
      { windowsHide: true, stdio: "ignore", timeout: 12000 });
    granted = true;
    const servicePath = path.resolve(__dirname, "../services/trashService.js");
    const script = `const svc = require(${JSON.stringify(servicePath)});\n` +
      "try { svc.claimRemoteDeletion({ item: { id: 'hostile-acl-fixture', metadata: { remoteDeletion: { state: 'pending', operationId: 'hostile-acl-fixture' } } } }); process.exit(9); } catch (error) { if (!/ACL|Untrusted|unsafe/i.test(error.message)) throw error; process.exit(0); }";
    await execFileAsync(process.execPath, ["-e", script], {
      cwd: selected, timeout: 15000, env: { ...process.env, DB_ENABLED: "false" },
    });
    assert.doesNotMatch(acl.getWindowsChunkAclDescriptor(locks), /D:P/,
      "unsafe legacy ACL must remain unsealed, with no opportunistic chmod");
    assert.deepEqual(fs.readdirSync(locks), [],
      "no lock, database or WAL/SHM may be created under an unsafe inherited ACL");
  } finally {
    if (granted) {
      execFileSync(icacls, [locks, "/remove:g", users],
        { windowsHide: true, stdio: "ignore", timeout: 12000 });
    }
    fs.rmSync(selected, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});
