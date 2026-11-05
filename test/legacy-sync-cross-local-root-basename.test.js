"use strict";

const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");
const { privateSyncStatePath } =
  require("../sync-client/rootark-sync-private-state");

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync.js");

async function runOnce(config, cwd) {
  const child = spawn(process.execPath,
    [CLI, "start", "--legacy-development-opt-in", "--once", "--config", config],
    { cwd, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  for (const stream of [child.stdout, child.stderr]) {
    stream.on("data", (part) => { output += part.toString("utf8"); });
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`legacy sync timed out: ${output}`));
    }, process.platform === "win32" ? 90000 : 30000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code) => { clearTimeout(timer); resolve({ code, output }); });
  });
}

test("different local roots with same remote basename cannot overwrite one another", {
  timeout: 180000,
}, async (t) => {
  const confA = createPrivateAuthorityFixture("rootark-cross-root-a-");
  const confB = createPrivateAuthorityFixture("rootark-cross-root-b-");
  const sources = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cross-root-source-"));
  t.after(async () => {
    await fs.rm(sources, { recursive: true, force: true });
    await fs.rm(confA, { recursive: true, force: true });
    await fs.rm(confB, { recursive: true, force: true });
  });
  const folderA = path.join(sources, "source-A");
  const folderB = path.join(sources, "source-B");
  await Promise.all([fs.mkdir(folderA), fs.mkdir(folderB)]);
  await fs.writeFile(path.join(folderA, "same.txt"), "OLD_FROM_A");
  await fs.writeFile(path.join(folderB, "same.txt"), "NEW_FROM_B");

  const uploads = [];
  let remote = "";
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (data) => chunks.push(data));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const source = body.includes("NEW_FROM_B") ? "B" : "A";
        remote = source;
        uploads.push(source);
        res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ fileName: "same.txt" }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const common = { serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", targetFolderId: "root", token: "disposable-token",
    debounceMs: 1, stabilityMs: 1, retryLimit: 1 };
  const configA = path.join(confA, "config.json");
  const configB = path.join(confB, "config.json");
  await writePrivateSyncConfig(configA, JSON.stringify({ ...common, localFolder: folderA }));
  await writePrivateSyncConfig(configB, JSON.stringify({ ...common, localFolder: folderB }));
  const stateA = privateSyncStatePath(configA, { ...common, localFolder: folderA });
  const stateB = privateSyncStatePath(configB, { ...common, localFolder: folderB });
  assert.equal(stateA, stateB,
    "the private cache/lock must have the same remote authority for both configs");

  const a = await runOnce(configA, sources);
  assert.equal(a.code, 0, a.output);
  assert.deepEqual(uploads, ["A"]);
  assert.equal(remote, "A");
  const b = await runOnce(configB, sources);
  assert.notEqual(b.code, 0, "a different local source must not take over same remote basename");
  assert.match(b.output, /SYNC_REMOTE_BASENAME_(?:AUTHORITY|OWNER)_CONFLICT/);
  assert.deepEqual(uploads, ["A"], "B must be rejected BEFORE HTTP mutation");
  assert.equal(remote, "A");
  const aAgain = await runOnce(configA, sources);
  assert.equal(aAgain.code, 0, aAgain.output);
  assert.deepEqual(uploads, ["A"], "unchanged original owner must not upload twice");

  const privateState = JSON.parse(await fs.readFile(stateA, "utf8"));
  assert.deepEqual(privateState.remoteBasenameOwners["same.txt"], {
    // Case-exact provenance is required even on Windows, since NTFS can
    // enable case-sensitive behavior for selected directories.
    localFolder: path.resolve(folderA),
    relativePath: "same.txt",
  });

  // State created before provenance claims has no trustworthy owner root.
  // It must not be silently acquired by A or B, even if its hash matches.
  const unowned = JSON.stringify({ ...privateState, remoteBasenameOwners: undefined });
  await writePrivateSyncConfig(stateA, unowned);
  const blockedOld = await runOnce(configA, sources);
  assert.notEqual(blockedOld.code, 0);
  assert.match(blockedOld.output, /SYNC_REMOTE_BASENAME_AUTHORITY_UNVERIFIED/);
  assert.deepEqual(uploads, ["A"]);
  assert.equal(await fs.readFile(stateA, "utf8"), unowned,
    "ambiguous old private state bytes must remain intact for recovery");
});

test("different local roots can upload non-overlapping basenames to one remote authority", {
  timeout: 180000,
}, async (t) => {
  const confA = createPrivateAuthorityFixture("rootark-cross-noncollision-a-");
  const confB = createPrivateAuthorityFixture("rootark-cross-noncollision-b-");
  const sources = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cross-noncollision-source-"));
  t.after(async () => {
    await fs.rm(sources, { recursive: true, force: true });
    await fs.rm(confA, { recursive: true, force: true });
    await fs.rm(confB, { recursive: true, force: true });
  });
  const folderA = path.join(sources, "source-A");
  const folderB = path.join(sources, "source-B");
  await Promise.all([fs.mkdir(folderA), fs.mkdir(folderB)]);
  await fs.writeFile(path.join(folderA, "a-only.txt"), "CONTENT_A");
  await fs.writeFile(path.join(folderB, "b-only.txt"), "CONTENT_B");
  const uploads = [];
  const server = http.createServer((req, res) => {
    // Disposable server fixture advertises the strict-name protocol contract.
    if (req.url === "/legacy-sync/capabilities") {
      return res.writeHead(200, { "Content-Type": "application/json" })
        .end(JSON.stringify({ strictFilename: true }));
    }
    if (req.url.startsWith("/list?")) {
      res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
      return;
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        const filename = body.includes('filename="b-only.txt"') ? "b-only.txt" : "a-only.txt";
        uploads.push(filename);
        res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ fileName: filename }));
      });
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const policy = { serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "fixture", targetFolderId: "root", token: "test-token",
    debounceMs: 1, stabilityMs: 1, retryLimit: 1 };
  const configA = path.join(confA, "config.json");
  const configB = path.join(confB, "config.json");
  await writePrivateSyncConfig(configA, JSON.stringify({ ...policy, localFolder: folderA }));
  await writePrivateSyncConfig(configB, JSON.stringify({ ...policy, localFolder: folderB }));
  const a = await runOnce(configA, sources);
  const b = await runOnce(configB, sources);
  assert.equal(a.code, 0, a.output);
  assert.equal(b.code, 0, b.output);
  assert.deepEqual(uploads, ["a-only.txt", "b-only.txt"]);
  const sharedState = privateSyncStatePath(configA, { ...policy, localFolder: folderA });
  const state = JSON.parse(await fs.readFile(sharedState, "utf8"));
  assert.deepEqual(Object.keys(state.remoteBasenameOwners).sort(), ["a-only.txt", "b-only.txt"]);
  assert.deepEqual(Object.keys(state.files).sort(), ["a-only.txt", "b-only.txt"]);
  const repeat = await runOnce(configB, sources);
  assert.equal(repeat.code, 0, repeat.output);
  assert.deepEqual(uploads, ["a-only.txt", "b-only.txt"]);
});
