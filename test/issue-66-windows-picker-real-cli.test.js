"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const test = require("node:test");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { writePrivateSyncConfig } = require("../sync-client/rootark-sync-private-config");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const picker = path.resolve(__dirname, "../sync-client/rootark-sync-windows-picker.ps1");
const cli = path.resolve(__dirname, "../sync-client/rootark-sync-v2.js");

const { args } = require("../sync-client/rootark-sync-v2");

test("issue 66: Sync v2 CLI --once parses boolean values instead of truthy strings", () => {
  assert.strictEqual(args(["--once"]).once, true);
  assert.strictEqual(args(["--once", "true"]).once, true);
  assert.strictEqual(args(["--once", "false"]).once, false);
  assert.strictEqual(args(["--once=true"]).once, true);
  assert.strictEqual(args(["--once=false"]).once, false);
  assert.throws(() => args(["--once=bad"]), /Invalid Sync v2 --once value/);
});

test("issue 66: malformed or ambiguous --path fails before reading config", () => {
  for (const flags of [
    ["--config", "dummy", "--path"],
    ["--config", "dummy", "--path", "--config", "other"],
    ["--config", "dummy", "--path="],
    ["--config", "dummy", "--path", "--other"],
  ]) {
    const result = spawnSync(process.execPath, [cli, "hydrate", ...flags], { encoding: "utf8" });
    assert.notEqual(result.status, 0, flags.join(" "));
    assert.match(result.stderr, /Invalid Sync v2 .*path/i, flags.join(" "));
  }
});

const chooser = `
$ErrorActionPreference = 'Stop'
if ($env:ROOTARK_TEST_CWD) { Set-Location -LiteralPath $env:ROOTARK_TEST_CWD }
function Out-GridView {
  [CmdletBinding()]
  param([string]$Title, [switch]$PassThru, [Parameter(ValueFromPipeline = $true)]$InputObject)
  process { $InputObject }
}
function Start-Process {
  param([string]$FilePath, [string[]]$ArgumentList)
  Set-Content -LiteralPath $env:ROOTARK_TEST_LAUNCH -Value (@{ executable = $FilePath; args = @($ArgumentList) } | ConvertTo-Json -Compress) -Encoding UTF8
}
try { & $env:ROOTARK_TEST_PICKER -Config $env:ROOTARK_TEST_CONFIG } catch { Write-Error $_.Exception.Message; exit 42 }
`;

async function runPowershell(env) {
  return new Promise((resolve, reject) => {
    const process = spawn(ps, ["-NoProfile", "-NonInteractive", "-Command", chooser], {
      env, cwd: env.ROOTARK_TEST_START_CWD || undefined,
      windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => process.kill(), 15000);
    process.stdout.on("data", (part) => { stdout += part; });
    process.stderr.on("data", (part) => { stderr += part; });
    process.on("error", (error) => { clearTimeout(timeout); reject(error); });
    process.on("close", (status) => { clearTimeout(timeout); resolve({ status, stdout, stderr }); });
  });
}

for (const { filename, relativeRoot } of [
  { filename: "relatório verão.txt", relativeRoot: false },
  { filename: "--relatorio.txt", relativeRoot: false },
  { filename: "arquivo relativo.txt", relativeRoot: true },
]) {
test(`issue 66 Windows: real signed picker hydrate ${filename}, relativeRoot=${relativeRoot}`, { skip: process.platform !== "win32", timeout: 30000 }, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-picker-live-");
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const localFolder = path.join(root, "sync-data");
  await fsp.mkdir(localFolder);
  const staleCwd = path.join(root, "stale-cwd");
  const remotePath = filename.startsWith("--") ? filename : `docs/${filename}`;
  if (relativeRoot) {
    const staleFile = path.join(staleCwd, "sync-data", remotePath);
    await fsp.mkdir(path.dirname(staleFile), { recursive: true });
    await fsp.writeFile(staleFile, "UNVERIFIED STALE FILE");
  }
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const epoch = "epoch-test";
  const master = crypto.randomBytes(32);
  const fileId = "picker-verified-file";
  const objectId = "picker-verified-object";
  const fileKey = crypto.createHmac("sha256", master).update(`${fileId}\0${epoch}`).digest();
  const original = Buffer.from("owner signed Windows hydrated bytes", "utf8");
  const operation = createOperation({
    operation: "create", objectId, fileId, deviceId: "device-a",
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    keyEpoch: epoch, compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: remotePath, name: filename, size: original.length },
    plaintext: original, fileKey,
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", publicKey, privateKey: keys.privateKey, expiresAt: Date.now() + 60000,
  });
  const { ciphertext, nonce, tag, aad, authorization, ...inventory } = operation;
  const requests = [];
  let tamper = false;
  const server = http.createServer((request, response) => {
    requests.push(request.url);
    response.setHeader("content-type", "application/json");
    if (request.url === "/sync/v1/objects?view=metadata&limit=64") {
      response.end(JSON.stringify({ protocolVersion: 2, view: "metadata", objects: [inventory], nextCursor: null }));
    } else if (request.url === `/sync/v1/objects/${objectId}`) {
      response.end(JSON.stringify({ protocolVersion: 2, objects: [
        tamper ? { ...operation, ciphertext: Buffer.from("forged payload").toString("base64url") } : operation,
      ] }));
    } else { response.writeHead(404); response.end("{}"); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = path.join(root, "sync-private.json");
  const launch = path.join(root, "launch.json");
  await writePrivateSyncConfig(config, JSON.stringify({
    serverUrl: `http://127.0.0.1:${server.address().port}`,
    username: "alice", token: "fixture-bearer", localFolder: relativeRoot ? "sync-data" : localFolder, deviceId: "device-a",
    keyEpoch: epoch, filesOnDemand: true, selectedPaths: filename.startsWith("--") ? [filename] : ["docs"],
    trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [],
  }));
  const env = { ...process.env,
    ROOTARK_SYNC_FILE_KEY: master.toString("base64url"),
    ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
    ROOTARK_SYNC_DEVICE_PUBLIC_KEY: publicKey,
    ROOTARK_TEST_CONFIG: config, ROOTARK_TEST_PICKER: picker, ROOTARK_TEST_LAUNCH: launch,
    ...(relativeRoot ? { ROOTARK_TEST_START_CWD: staleCwd } : {}),
  };

  const good = await runPowershell(env);
  assert.equal(good.status, 0, good.stderr);
  assert.deepEqual(await fsp.readFile(path.join(localFolder, remotePath)), original);
  assert.equal(requests.filter((request) => request === `/sync/v1/objects/${objectId}`).length, 1);
  const reveal = JSON.parse((await fsp.readFile(launch, "utf8")).replace(/^\uFEFF/, ""));
  assert.match(reveal.executable, /explorer\.exe$/i);
  assert.deepEqual(reveal.args, [`/select,"${path.join(localFolder, remotePath)}"`],
    "Explorer must receive /select,\"<target>\" without a space after the comma under Node's resolved root");
  if (relativeRoot) {
    assert.equal((await fsp.readFile(path.join(staleCwd, "sync-data", remotePath), "utf8")), "UNVERIFIED STALE FILE");
  }

  await fsp.unlink(launch);
  tamper = true;
  const denied = await runPowershell(env);
  assert.notEqual(denied.status, 0);
  assert.equal(fs.existsSync(launch), false, "tampered envelope must not reveal Explorer");
  assert.deepEqual(await fsp.readFile(path.join(localFolder, remotePath)), original);
});
}
