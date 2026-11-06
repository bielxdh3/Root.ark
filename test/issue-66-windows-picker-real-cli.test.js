"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { spawn } = require("node:child_process");
const test = require("node:test");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { writePrivateSyncConfig } = require("../sync-client/rootark-sync-private-config");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const picker = path.resolve(__dirname, "../sync-client/rootark-sync-windows-picker.ps1");

const chooser = `
$ErrorActionPreference = 'Stop'
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
      env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
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

test("issue 66 Windows: picker invokes real CLI, HTTP signed hydrate and verified local plaintext", { skip: process.platform !== "win32", timeout: 30000 }, async (t) => {
  const root = createPrivateAuthorityFixture("rootark-picker-live-");
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const localFolder = path.join(root, "sync-data");
  await fsp.mkdir(localFolder);
  const keys = crypto.generateKeyPairSync("ed25519");
  const publicKey = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const epoch = "epoch-test";
  const master = crypto.randomBytes(32);
  const fileId = "picker-verified-file";
  const objectId = "picker-verified-object";
  const filename = "relatório verão.txt";
  const fileKey = crypto.createHmac("sha256", master).update(`${fileId}\0${epoch}`).digest();
  const original = Buffer.from("owner signed Windows hydrated bytes", "utf8");
  const operation = createOperation({
    operation: "create", objectId, fileId, deviceId: "device-a",
    versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
    keyEpoch: epoch, compartmentId: "private",
    revision: { counter: 1, deviceId: "device-a" },
    metadata: { path: `docs/${filename}`, name: filename, size: original.length },
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
    username: "alice", token: "fixture-bearer", localFolder, deviceId: "device-a",
    keyEpoch: epoch, filesOnDemand: true, selectedPaths: ["docs"],
    trustedDevicePublicKeys: { "device-a": publicKey }, revokedDeviceIds: [],
  }));
  const env = { ...process.env,
    ROOTARK_SYNC_FILE_KEY: master.toString("base64url"),
    ROOTARK_SYNC_DEVICE_PRIVATE_KEY: keys.privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url"),
    ROOTARK_SYNC_DEVICE_PUBLIC_KEY: publicKey,
    ROOTARK_TEST_CONFIG: config, ROOTARK_TEST_PICKER: picker, ROOTARK_TEST_LAUNCH: launch,
  };

  const good = await runPowershell(env);
  assert.equal(good.status, 0, good.stderr);
  assert.deepEqual(await fsp.readFile(path.join(localFolder, "docs", filename)), original);
  assert.equal(requests.filter((request) => request === `/sync/v1/objects/${objectId}`).length, 1);
  const reveal = JSON.parse((await fsp.readFile(launch, "utf8")).replace(/^\uFEFF/, ""));
  assert.match(reveal.executable, /explorer\.exe$/i);
  assert.ok(reveal.args.join(" ").includes(filename));

  await fsp.unlink(launch);
  tamper = true;
  const denied = await runPowershell(env);
  assert.notEqual(denied.status, 0);
  assert.equal(fs.existsSync(launch), false, "tampered envelope must not reveal Explorer");
  assert.deepEqual(await fsp.readFile(path.join(localFolder, "docs", filename)), original);
});
