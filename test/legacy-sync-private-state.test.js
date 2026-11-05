"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");
const { privateSyncStatePath, inspectHistoricalSyncState } =
  require("../sync-client/rootark-sync-private-state");

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync.js");
const STATE_NAME = ".rootark-sync-state.json";

test("historical shared-folder state inspection never opens untrusted bytes", async (t) => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-state-metadata-only-"));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const oldPath = path.join(dir, STATE_NAME);
  const sentinel = "PRESERVE_HISTORICAL_BYTES";
  await fsp.writeFile(oldPath, sentinel);
  const opened = t.mock.method(fsp, "open", async () => {
    throw new Error("HISTORICAL_STATE_MUST_NOT_OPEN");
  });
  assert.deepEqual(await inspectHistoricalSyncState(dir),
    { present: true, status: "preserved" });
  assert.equal(opened.mock.callCount(), 0);
  opened.mock.restore();
  assert.equal(await fsp.readFile(oldPath, "utf8"), sentinel);
});

function expectedPrivateState(configPath, selected, overrides = {}) {
  return privateSyncStatePath(configPath, {
    localFolder: selected, serverUrl: overrides.serverUrl,
    username: overrides.username || "fixture", targetFolderId: overrides.targetFolderId || "root",
    deviceId: overrides.deviceId || "", keyEpoch: overrides.keyEpoch || "",
  });
}

function runClient(dir, config, extraEnv = {}, { symlinkSentinel = "" } = {}) {
  const args = ["start", "--legacy-development-opt-in", "--once", "--config", config];
  const injected = String.raw`
    const fs = require('node:fs');
    const path = require('node:path');
    const local = process.env.ROOTARK_TEST_SELECTED;
    fs.symlinkSync(process.env.ROOTARK_TEST_SENTINEL,
      path.join(local, '.rootark-sync-state.json.tmp-' + process.pid), 'file');
    process.argv = [process.execPath, process.env.ROOTARK_TEST_CLI,
      ...JSON.parse(process.env.ROOTARK_TEST_ARGS)];
    require(process.env.ROOTARK_TEST_CLI);
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, symlinkSentinel ? ["-e", injected] : [CLI, ...args], {
      cwd: dir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, ...extraEnv, ROOTARK_TEST_CLI: CLI,
        ROOTARK_TEST_ARGS: JSON.stringify(args), ROOTARK_TEST_SENTINEL: symlinkSentinel },
    });
    let output = "";
    // Windows native authority checks are deliberately synchronous and can
    // cost several seconds per serialized write on loaded hosted runners.
    const timeout = setTimeout(() => child.kill(), process.platform === "win32" ? 90000 : 30000);
    for (const pipe of [child.stdout, child.stderr]) {
      pipe.on("data", (data) => { output += data.toString("utf8"); });
    }
    child.once("error", (error) => { clearTimeout(timeout); reject(error); });
    child.once("close", (code) => {
      clearTimeout(timeout);
      resolve({ code, output });
    });
  });
}

async function fixture(t, prefix) {
  // The selected folder is intentionally a separate potentially shared tree.
  // The private config/state root must never contain our adversarial symlinks:
  // Windows native ACL verification correctly refuses reparse entries there.
  const configRoot = createPrivateAuthorityFixture(prefix + "config-");
  t.after(() => fsp.rm(configRoot, { recursive: true, force: true }));
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), prefix));
  t.after(() => fsp.rm(dir, { recursive: true, force: true }));
  const selected = path.join(dir, "selected");
  await fsp.mkdir(selected);
  if (process.platform !== "win32") await fsp.chmod(selected, 0o777);
  const uploads = [];
  const server = http.createServer((req, res) => {
    if (req.url.startsWith("/list?")) {
      return res.writeHead(200, { "Content-Type": "application/json" }).end("[]");
    }
    if (req.url.startsWith("/upload?")) {
      const chunks = [];
      req.on("data", (data) => chunks.push(data));
      req.on("end", () => {
        uploads.push(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ fileName: "uploaded.txt" }));
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
    username: "fixture", token: "test-token", localFolder: selected,
    targetFolderId: "root", debounceMs: 1, stabilityMs: 1, retryLimit: 1,
  }));
  return { dir, configRoot, selected, config, uploads,
    serverUrl: `http://127.0.0.1:${server.address().port}` };
}

test("legacy PID-temporary symlink cannot clobber a private external file", async (t) => {
  const f = await fixture(t, "rootark-state-clobber-");
  await fsp.writeFile(path.join(f.selected, "new.txt"), "REQUIRED_UPLOAD");
  const sentinel = path.join(f.configRoot, "private-sentinel");
  await fsp.writeFile(sentinel, "DO_NOT_CLOBBER", { mode: 0o600 });
  // Hosted Windows runners may lack SeCreateSymbolicLinkPrivilege. Skip
  // only when that platform cannot create the adversarial fixture at all;
  // POSIX must execute the actual planted-symlink regression.
  const probe = path.join(f.selected, ".rootark-test-symlink-probe");
  try {
    await fsp.symlink(sentinel, probe, "file");
  } catch (error) {
    if (process.platform === "win32"
      && ["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.skip("Windows runner lacks symlink fixture permission");
      return;
    }
    throw error;
  } finally {
    await fsp.unlink(probe).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  }
  const result = await runClient(f.dir, f.config, { ROOTARK_TEST_SELECTED: f.selected },
    { symlinkSentinel: sentinel });
  assert.equal(result.code, 0, result.output);
  assert.equal(await fsp.readFile(sentinel, "utf8"), "DO_NOT_CLOBBER");
  assert.equal(f.uploads.length, 1);
  const privateState = expectedPrivateState(f.config, f.selected, f);
  assert.equal(JSON.parse(await fsp.readFile(privateState, "utf8"))
    .files["new.txt"].lastStatus, "uploaded");
  assert.equal(fs.existsSync(path.join(f.selected, STATE_NAME)), false);
});

test("forged historical uploaded status cannot suppress an actual upload", async (t) => {
  const f = await fixture(t, "rootark-state-forged-");
  const source = path.join(f.selected, "new.txt");
  await fsp.writeFile(source, "MUST_REUPLOAD");
  const stat = await fsp.stat(source);
  const legacy = path.join(f.selected, STATE_NAME);
  const forged = JSON.stringify({ files: { "new.txt": {
    size: stat.size, mtimeMs: stat.mtimeMs,
    hash: crypto.createHash("sha256").update("MUST_REUPLOAD").digest("hex"),
    lastStatus: "uploaded", remoteFileName: "forged.txt",
  } } });
  await fsp.writeFile(legacy, forged);
  const result = await runClient(f.dir, f.config);
  assert.equal(result.code, 0, result.output);
  assert.equal(f.uploads.length, 1, "untrusted historical cache cannot authorize skipping upload");
  assert.equal(await fsp.readFile(legacy, "utf8"), forged,
    "legacy state must stay untouched for explicit operator-led recovery");
  const state = JSON.parse(await fsp.readFile(expectedPrivateState(f.config, f.selected, f), "utf8"));
  assert.equal(state.files["new.txt"].lastStatus, "uploaded");
});

test("simultaneous legacy uploads serialize private state without lost entries", async (t) => {
  const f = await fixture(t, "rootark-state-serial-");
  for (let i = 0; i < 8; i++) {
    await fsp.writeFile(path.join(f.selected, `new-${i}.txt`), `UPLOAD-${i}`);
  }
  const result = await runClient(f.dir, f.config);
  assert.equal(result.code, 0, result.output);
  assert.equal(f.uploads.length, 8);
  const state = JSON.parse(await fsp.readFile(expectedPrivateState(f.config, f.selected, f), "utf8"));
  for (let i = 0; i < 8; i++) assert.equal(state.files[`new-${i}.txt`].lastStatus, "uploaded");
});

test("switching remote destination never imports uploaded acknowledgements from prior target", async (t) => {
  const f = await fixture(t, "rootark-state-target-switch-");
  await fsp.writeFile(path.join(f.selected, "new.txt"), "MUST_UPLOAD_TWICE");
  const first = await runClient(f.dir, f.config);
  assert.equal(first.code, 0, first.output);
  assert.equal(f.uploads.length, 1);
  const oldStatePath = expectedPrivateState(f.config, f.selected, f);
  const original = await fsp.readFile(oldStatePath, "utf8");
  const config = JSON.parse(await fsp.readFile(f.config, "utf8"));
  config.targetFolderId = "different-folder";
  await writePrivateSyncConfig(f.config, JSON.stringify(config));
  const second = await runClient(f.dir, f.config);
  assert.equal(second.code, 0, second.output);
  assert.equal(f.uploads.length, 2, "new target must upload even when local contents match");
  assert.equal(await fsp.readFile(oldStatePath, "utf8"), original,
    "old destination state must remain intact for recovery");
  const nextState = expectedPrivateState(f.config, f.selected,
    { ...f, targetFolderId: "different-folder" });
  assert.notEqual(nextState, oldStatePath);
  assert.equal(JSON.parse(await fsp.readFile(nextState, "utf8"))
    .files["new.txt"].lastStatus, "uploaded");
});

test("private cache cannot skip changed bytes with original size and restored mtime", async (t) => {
  const f = await fixture(t, "rootark-state-rehash-");
  const source = path.join(f.selected, "new.txt");
  const pinnedTime = new Date("2025-01-01T00:00:00.000Z");
  await fsp.writeFile(source, "AAAAAA");
  await fsp.utimes(source, pinnedTime, pinnedTime);
  const initial = await runClient(f.dir, f.config);
  assert.equal(initial.code, 0, initial.output);
  assert.equal(f.uploads.length, 1);
  const prior = JSON.parse(await fsp.readFile(expectedPrivateState(f.config, f.selected, f), "utf8"))
    .files["new.txt"];
  await fsp.writeFile(source, "BBBBBB");
  await fsp.utimes(source, pinnedTime, pinnedTime);
  const nextStats = await fsp.stat(source);
  assert.equal(nextStats.size, prior.size);
  assert.equal(nextStats.mtimeMs, prior.mtimeMs);
  const next = await runClient(f.dir, f.config);
  assert.equal(next.code, 0, next.output);
  assert.equal(f.uploads.length, 2, "same-size, same-mtime content changes require reupload");
  assert.match(f.uploads[1], /BBBBBB/);
});

test("a shared-folder file named __proto__ cannot corrupt the private state map", async (t) => {
  const f = await fixture(t, "rootark-state-prototype-");
  await fsp.writeFile(path.join(f.selected, "__proto__"), "PROTOTYPE_FILE");
  const result = await runClient(f.dir, f.config);
  assert.equal(result.code, 0, result.output);
  assert.equal(f.uploads.length, 1);
  const state = JSON.parse(await fsp.readFile(expectedPrivateState(f.config, f.selected, f), "utf8"));
  assert.equal(Object.hasOwn(state.files, "__proto__"), true);
  assert.equal(state.files["__proto__"].lastStatus, "uploaded");
  const next = await runClient(f.dir, f.config);
  assert.equal(next.code, 0, next.output);
  assert.equal(f.uploads.length, 1, "unchanged content must not be duplicated");
});

test("explicit --config path cannot alias the derived private state file", async (t) => {
  const f = await fixture(t, "rootark-state-config-collision-");
  await fsp.writeFile(path.join(f.selected, "new.txt"), "NO_COLLISION_UPLOAD");
  const configContents = await fsp.readFile(f.config, "utf8");
  const statePath = expectedPrivateState(f.config, f.selected, f);
  await writePrivateSyncConfig(statePath, configContents);
  const run = await runClient(f.dir, statePath);
  assert.notEqual(run.code, 0);
  assert.match(run.output, /SYNC_STATE_CONFIG_PATH_COLLISION/);
  assert.equal(f.uploads.length, 0);
  assert.equal(await fsp.readFile(statePath, "utf8"), configContents,
    "private config must not be overwritten by state");
});

test("state binding mismatch fails closed without overwriting the state", async (t) => {
  const f = await fixture(t, "rootark-state-binding-mismatch-");
  await fsp.writeFile(path.join(f.selected, "new.txt"), "NO_FORGED_ACK");
  const statePath = expectedPrivateState(f.config, f.selected, f);
  const forged = JSON.stringify({ version: 1, binding: "0".repeat(64),
    files: { "new.txt": { size: 13, mtimeMs: 1, lastStatus: "uploaded" } } });
  await writePrivateSyncConfig(statePath, forged);
  const run = await runClient(f.dir, f.config);
  assert.notEqual(run.code, 0);
  assert.match(run.output, /SYNC_STATE_BINDING_MISMATCH/);
  assert.equal(await fsp.readFile(statePath, "utf8"), forged);
  assert.equal(f.uploads.length, 0);
});
