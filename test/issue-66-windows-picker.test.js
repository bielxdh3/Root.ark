"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const picker = path.join(__dirname, "..", "sync-client", "rootark-sync-windows-picker.ps1");
const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const harness = `
$ErrorActionPreference = 'Stop'
function node {
  $argv = @($args)
  Add-Content -LiteralPath $env:ROOTARK_TEST_TRACE -Value ($argv -join '|')
  if ($argv[1] -eq 'browse') {
    $global:LASTEXITCODE = 0
    if ($env:ROOTARK_TEST_MODE -eq 'empty') {
      return (@{ objects = @(); nextCursor = $null } | ConvertTo-Json -Compress)
    }
    if ($argv -contains '--cursor') {
      $next = if ($env:ROOTARK_TEST_MODE -eq 'repeat') { 'page-2' } else { $null }
      return (@{ objects = @(@{ tombstone = $false; selectedOnDevice = $true; metadata = @{ path = $env:ROOTARK_TEST_CHOICE; size = 14 } }); nextCursor = $next } | ConvertTo-Json -Depth 7 -Compress)
    }
    return (@{ objects = @(@{ tombstone = $false; selectedOnDevice = $false; metadata = @{ path = 'excluded/secret.txt'; size = 99 } }); nextCursor = 'page-2' } | ConvertTo-Json -Depth 7 -Compress)
  }
  if ($argv[1] -eq 'hydrate') {
    if ($env:ROOTARK_TEST_MODE -eq 'deny') { $global:LASTEXITCODE = 1; return '' }
    $global:LASTEXITCODE = 0
    return '{"path":"verified","action":"hydrate","result":true}'
  }
  throw 'Unexpected Node command'
}
function Out-GridView {
  [CmdletBinding()]
  param([string]$Title, [switch]$PassThru, [Parameter(ValueFromPipeline=$true)]$InputObject)
  process { if ($env:ROOTARK_TEST_MODE -ne 'cancel' -and $InputObject.Path -eq $env:ROOTARK_TEST_CHOICE) { $InputObject } }
}
function Start-Process {
  param([string]$FilePath, [string[]]$ArgumentList)
  Set-Content -LiteralPath $env:ROOTARK_TEST_LAUNCH -Value (@{ process = $FilePath; arguments = @($ArgumentList) } | ConvertTo-Json -Compress)
}
if ($env:ROOTARK_TEST_LOCATION) { Set-Location -LiteralPath $env:ROOTARK_TEST_LOCATION }
try { & $env:ROOTARK_TEST_PICKER -Config $env:ROOTARK_TEST_CONFIG } catch { Write-Output $_.Exception.Message; exit 42 }
`;

async function runPicker(t, mode, selectedPath = "docs/verified.txt") {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-picker-test-"));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const local = path.join(temp, "Root Ark Files");
  await fs.mkdir(path.join(local, "docs"), { recursive: true });
  await fs.writeFile(path.join(local, "docs", "verified.txt"), "unchanged local bytes");
  const config = path.join(temp, "private-config.json");
  const trace = path.join(temp, "trace.txt");
  const launch = path.join(temp, "launch.json");
  await fs.writeFile(config, JSON.stringify({ localFolder: local }));
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", harness], {
    env: { ...process.env, ROOTARK_TEST_MODE: mode, ROOTARK_TEST_CHOICE: selectedPath,
      ROOTARK_TEST_TRACE: trace, ROOTARK_TEST_LAUNCH: launch,
      ROOTARK_TEST_CONFIG: config, ROOTARK_TEST_PICKER: picker },
    encoding: "utf8", timeout: 20000,
  });
  return { result, local, trace: await fs.readFile(trace, "utf8").catch(() => ""),
    launch: await fs.readFile(launch, "utf8").then(JSON.parse, () => null) };
}

test("issue 66 Windows: Explorer picker pages metadata then reveals only a verified hydrated file", { skip: process.platform !== "win32" }, async (t) => {
  const { result, local, trace, launch } = await runPicker(t, "ok");
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  assert.equal(trace.split(/\r?\n/).filter((line) => line.includes("|browse|")).length, 2);
  assert.equal(trace.split(/\r?\n/).filter((line) => line.includes("|hydrate|")).length, 1);
  assert.match(trace, /--path=docs\/verified\.txt/);
  assert.equal(launch.process.toLowerCase().endsWith("explorer.exe"), true);
  assert.deepEqual(launch.arguments, [`/select,"${path.join(local, "docs", "verified.txt")}"`]);
  assert.equal(await fs.readFile(path.join(local, "docs", "verified.txt"), "utf8"), "unchanged local bytes");
});

test("issue 66 Windows: failed verified hydration does not reveal or alter local bytes", { skip: process.platform !== "win32" }, async (t) => {
  const { result, local, launch, trace } = await runPicker(t, "deny");
  assert.notEqual(result.status, 0);
  assert.equal(launch, null);
  assert.match(trace, /\|hydrate\|/);
  assert.equal(await fs.readFile(path.join(local, "docs", "verified.txt"), "utf8"), "unchanged local bytes");
});

test("issue 66 Windows: advisory traversal metadata cannot reveal outside local root", { skip: process.platform !== "win32" }, async (t) => {
  const { result, launch } = await runPicker(t, "ok", "../outside.txt");
  assert.notEqual(result.status, 0);
  assert.equal(launch, null);
});

test("issue 66 Windows: cancel is read-only and never asks for ciphertext", { skip: process.platform !== "win32" }, async (t) => {
  const { result, launch, trace } = await runPicker(t, "cancel");
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  assert.equal(launch, null);
  assert.doesNotMatch(trace, /\|hydrate\|/);
});

test("issue 66 Windows: repeated advisory cursor stops before hydration", { skip: process.platform !== "win32" }, async (t) => {
  const { result, launch, trace } = await runPicker(t, "repeat");
  assert.notEqual(result.status, 0);
  assert.equal(launch, null);
  assert.doesNotMatch(trace, /\|hydrate\|/);
});

test("issue 66 Windows: empty remote catalog exits without fetching ciphertext", { skip: process.platform !== "win32" }, async (t) => {
  const { result, launch, trace } = await runPicker(t, "empty");
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  assert.equal(launch, null);
  assert.doesNotMatch(trace, /\|hydrate\|/);
});

test("issue 66 Windows: relative -Config resolves against PowerShell provider location, not stale Environment CurrentDirectory", { skip: process.platform !== "win32" }, async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-picker-test-"));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const local = path.join(temp, "Root Ark Files");
  await fs.mkdir(path.join(local, "docs"), { recursive: true });
  await fs.writeFile(path.join(local, "docs", "verified.txt"), "unchanged local bytes");
  const config = path.join(temp, "private-config.json");
  await fs.writeFile(config, JSON.stringify({ localFolder: local }));
  const trace = path.join(temp, "trace.txt");
  const launch = path.join(temp, "launch.json");

  // PowerShell Set-Location points to temp, but configArg is relative ".\private-config.json"
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", harness], {
    env: {
      ...process.env,
      ROOTARK_TEST_MODE: "ok",
      ROOTARK_TEST_CHOICE: "docs/verified.txt",
      ROOTARK_TEST_TRACE: trace,
      ROOTARK_TEST_LAUNCH: launch,
      ROOTARK_TEST_LOCATION: temp,
      ROOTARK_TEST_CONFIG: ".\\private-config.json",
      ROOTARK_TEST_PICKER: picker,
    },
    encoding: "utf8", timeout: 20000,
  });
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  const launchData = await fs.readFile(launch, "utf8").then(JSON.parse, () => null);
  assert.equal(launchData.process.toLowerCase().endsWith("explorer.exe"), true);
  assert.deepEqual(launchData.arguments, [`/select,"${path.join(local, "docs", "verified.txt")}"`]);
});

test("issue 66 Windows: drive-relative localFolder (e.g. C:sync) resolves against config directory", { skip: process.platform !== "win32" }, async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-picker-test-"));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const local = path.join(temp, "Root Ark Files");
  await fs.mkdir(path.join(local, "docs"), { recursive: true });
  await fs.writeFile(path.join(local, "docs", "verified.txt"), "unchanged local bytes");
  const config = path.join(temp, "private-config.json");
  const drive = path.parse(temp).root.slice(0, 2);
  const driveRelative = `${drive}Root Ark Files`;
  await fs.writeFile(config, JSON.stringify({ localFolder: driveRelative }));
  const trace = path.join(temp, "trace.txt");
  const launch = path.join(temp, "launch.json");

  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", harness], {
    env: {
      ...process.env,
      ROOTARK_TEST_MODE: "ok",
      ROOTARK_TEST_CHOICE: "docs/verified.txt",
      ROOTARK_TEST_TRACE: trace,
      ROOTARK_TEST_LAUNCH: launch,
      ROOTARK_TEST_CONFIG: config,
      ROOTARK_TEST_PICKER: picker,
    },
    encoding: "utf8", timeout: 20000,
  });
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  const launchData = await fs.readFile(launch, "utf8").then(JSON.parse, () => null);
  assert.equal(launchData.process.toLowerCase().endsWith("explorer.exe"), true);
  assert.deepEqual(launchData.arguments, [`/select,"${path.join(local, "docs", "verified.txt")}"`]);
});

test("issue 66 Windows: root-relative localFolder (e.g. \\sync) resolves against drive root", { skip: process.platform !== "win32" }, async (t) => {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-picker-test-"));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const local = path.join(temp, "Root Ark Files");
  await fs.mkdir(path.join(local, "docs"), { recursive: true });
  await fs.writeFile(path.join(local, "docs", "verified.txt"), "unchanged local bytes");
  const config = path.join(temp, "private-config.json");
  const rootRelative = local.slice(path.parse(local).root.length - 1);
  await fs.writeFile(config, JSON.stringify({ localFolder: rootRelative }));
  const trace = path.join(temp, "trace.txt");
  const launch = path.join(temp, "launch.json");

  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", harness], {
    env: {
      ...process.env,
      ROOTARK_TEST_MODE: "ok",
      ROOTARK_TEST_CHOICE: "docs/verified.txt",
      ROOTARK_TEST_TRACE: trace,
      ROOTARK_TEST_LAUNCH: launch,
      ROOTARK_TEST_CONFIG: config,
      ROOTARK_TEST_PICKER: picker,
    },
    encoding: "utf8", timeout: 20000,
  });
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  const launchData = await fs.readFile(launch, "utf8").then(JSON.parse, () => null);
  assert.equal(launchData.process.toLowerCase().endsWith("explorer.exe"), true);
  assert.deepEqual(launchData.arguments, [`/select,"${path.join(local, "docs", "verified.txt")}"`]);
});

test("issue 66 Windows: Resolve-RootArkPath handles bare root (\\\\) and bare drive (C:) cleanly", { skip: process.platform !== "win32" }, async () => {
  const pickerSource = await fs.readFile(picker, "utf8");
  const fnMatch = pickerSource.match(/function Resolve-RootArkPath[\s\S]*?\r?\n\}/);
  assert.ok(fnMatch, "Resolve-RootArkPath helper should be defined in picker");
  const script = `${fnMatch[0]}
@((Resolve-RootArkPath 'C:\\work\\cfg' '\\'), (Resolve-RootArkPath 'C:\\work\\cfg' '/'), (Resolve-RootArkPath 'C:\\work\\cfg' 'C:'), (Resolve-RootArkPath 'C:\\work\\cfg' 'D:')) -join '|'`;
  const runPs5 = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", timeout: 15000 });
  assert.equal(runPs5.status, 0, `${runPs5.stdout} ${runPs5.stderr}`);
  assert.equal(runPs5.stdout.trim(), "C:\\|C:\\|C:\\work\\cfg|D:\\");
  const pwshCheck = spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", timeout: 15000 });
  if (!pwshCheck.error) {
    assert.equal(pwshCheck.status, 0, `${pwshCheck.stdout} ${pwshCheck.stderr}`);
    assert.equal(pwshCheck.stdout.trim(), "C:\\|C:\\|C:\\work\\cfg|D:\\");
  }
});

