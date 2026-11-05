"use strict";

const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { writePrivateSyncConfig } =
  require("../sync-client/rootark-sync-private-config");
const { start } = require("../sync-client/rootark-sync-v2");

const CLI = path.resolve(__dirname, "../sync-client/rootark-sync-v2.js");
const UNSAFE_CONFIG = /SYNC_V2_UNSAFE_CONFIG.*--config/;
const SIGNED_POLICY_STAGE = /Unsupported Sync v2 historical admission mode/;

function fixture(t) {
  const root = createPrivateAuthorityFixture("rootark-v2-private-config-");
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const localFolder = path.join(root, "synced");
  fs.mkdirSync(localFolder, { mode: 0o700 });
  const keys = crypto.generateKeyPairSync("ed25519");
  const spki = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const env = {
    ...process.env,
    ROOTARK_SYNC_FILE_KEY: crypto.randomBytes(32).toString("base64url"),
    ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keys.privateKey.export({
      type: "pkcs8", format: "der",
    }).toString("base64url"),
    ROOTARK_SYNC_DEVICE_PUBLIC_KEY: spki,
  };
  const config = {
    serverUrl: "https://example.invalid",
    username: "fixture-user",
    token: "synthetic-v2-token",
    localFolder,
    deviceId: "fixture-device",
    keyEpoch: "fixture-epoch",
    trustedDevicePublicKeys: { "fixture-device": spki },
    revokedDeviceIds: [],
    // The successful, private read must reach this intentional next-stage error.
    historicalAdmissionMode: "unrecognized-test-sentinel",
  };
  return { root, env, config };
}

function runCli(cwd, env, configPath = null) {
  const args = [CLI, "start", "--once"];
  if (configPath) args.push("--config", configPath);
  return spawnSync(process.execPath, args, {
    cwd, env, encoding: "utf8", timeout: 10000, windowsHide: true,
  });
}

function runCliAsync(cwd, env, configPath) {
  const args = [CLI, "start", "--once", "--config", configPath];
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, args, {
      cwd, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    let expired = false;
    const timer = setTimeout(() => { expired = true; child.kill(); }, 12000);
    child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
    child.stdout.resume();
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (status) => {
      clearTimeout(timer);
      if (expired) reject(new Error("V2_FIXTURE_TIMEOUT"));
      else resolve({ status, stderr });
    });
  });
}

test("v2 rejects an unsafe CWD default config before reading a bearer or URL", async (t) => {
  const f = fixture(t);
  const unsafe = path.join(f.root, "unsafe-parent");
  fs.mkdirSync(unsafe);
  if (process.platform !== "win32") fs.chmodSync(unsafe, 0o777);
  fs.writeFileSync(path.join(unsafe, ".rootark-sync.json"), JSON.stringify(f.config),
    { mode: 0o600 });
  const run = runCli(unsafe, f.env);
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, UNSAFE_CONFIG,
    "a planted CWD config must fail before any trust policy or network use");
  assert.doesNotMatch(run.stderr, /synthetic-v2-token|example\.invalid/);
});

test("v2 rejects a symlink to a private config without contacting the destination", async (t) => {
  const f = fixture(t);
  const source = path.join(f.root, "provisioned.json");
  const alias = path.join(f.root, "alias.json");
  await writePrivateSyncConfig(source, JSON.stringify(f.config));
  try { fs.symlinkSync(source, alias, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("symlinks unavailable");
    throw error;
  }
  const run = runCli(f.root, f.env, alias);
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, UNSAFE_CONFIG);
  assert.equal(fs.lstatSync(alias).isSymbolicLink(), true);
});

test("v2 refuses a hard-linked config even when both paths are private", async (t) => {
  const f = fixture(t);
  const source = path.join(f.root, "provisioned.json");
  const alias = path.join(f.root, "alias.json");
  await writePrivateSyncConfig(source, JSON.stringify(f.config));
  fs.linkSync(source, alias);
  const run = runCli(f.root, f.env, alias);
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, UNSAFE_CONFIG);
  assert.equal(fs.statSync(source).nlink, 2);
});

test("v2 rejects a planted symlink before sending a bearer to a loopback HTTP endpoint", async (t) => {
  const f = fixture(t);
  let requests = 0;
  const endpoint = http.createServer((req, res) => {
    requests++;
    req.resume();
    res.writeHead(401, { "content-type": "application/json" }).end("{}");
  });
  await new Promise((resolve) => endpoint.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => endpoint.close(resolve)));
  const source = path.join(f.root, "private.json");
  const alias = path.join(f.root, "planted.json");
  const networkConfig = { ...f.config,
    serverUrl: `http://127.0.0.1:${endpoint.address().port}` };
  delete networkConfig.historicalAdmissionMode;
  await writePrivateSyncConfig(source, JSON.stringify(networkConfig));
  try { fs.symlinkSync(source, alias, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip("symlinks unavailable");
    throw error;
  }
  const run = await runCliAsync(f.root, f.env, alias);
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, UNSAFE_CONFIG);
  assert.equal(requests, 0, "a planted config must never trigger HTTP bearer delivery");
});

test("v2 accepts a private config through the unchanged independently pinned policy path", async (t) => {
  const f = fixture(t);
  const source = path.join(f.root, "provisioned.json");
  await writePrivateSyncConfig(source, JSON.stringify(f.config));
  const run = runCli(f.root, f.env, source);
  assert.equal(run.status, 1, run.stderr);
  assert.match(run.stderr, SIGNED_POLICY_STAGE,
    "a trusted config must reach the existing strict historical-mode validation");
  assert.doesNotMatch(run.stderr, /synthetic-v2-token/);
});
