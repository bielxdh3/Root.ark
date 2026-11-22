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
function Get-Command {
  [CmdletBinding()]
  param([string]$Name)
  if ($env:ROOTARK_TEST_MODE -eq ('missing-' + $Name)) { return }
  Microsoft.PowerShell.Core\\Get-Command -Name $Name -ErrorAction SilentlyContinue
}
function node {
  if ($env:ROOTARK_TEST_MODE -like 'missing-*') { throw 'Unexpected Node call' }
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
    if ($env:ROOTARK_TEST_MODE -eq 'reparse-leaf') {
      # Node created the real symlink before this PowerShell process started.
      # Windows PowerShell 5.1 New-Item -ItemType SymbolicLink can fail for a
      # non-admin even when Node can create unprivileged Windows symlinks.
      [IO.File]::Move($env:ROOTARK_TEST_TARGET, ($env:ROOTARK_TEST_TARGET + '.before-swap'))
      [IO.File]::Move($env:ROOTARK_TEST_PREPARED_LINK, $env:ROOTARK_TEST_TARGET)
      $global:LASTEXITCODE = 0
      return '{"path":"docs/verified.txt","action":"hydrate","result":true}'
    }
    if ($env:ROOTARK_TEST_MODE -eq 'reparse-parent') {
      [IO.Directory]::Move($env:ROOTARK_TEST_PARENT, ($env:ROOTARK_TEST_PARENT + '.before-swap'))
      [IO.Directory]::Move($env:ROOTARK_TEST_PREPARED_LINK, $env:ROOTARK_TEST_PARENT)
      $global:LASTEXITCODE = 0
      return '{"path":"docs/verified.txt","action":"hydrate","result":true}'
    }
    $global:LASTEXITCODE = 0
    return '{"path":"verified","action":"hydrate","result":true}'
  }
  throw 'Unexpected Node command'
}
function Out-GridView {
  [CmdletBinding()]
  param([string]$Title, [string]$OutputMode, [Parameter(ValueFromPipeline=$true)]$InputObject)
  begin {
    if ($env:ROOTARK_TEST_MODE -like 'missing-*') { throw 'Unexpected GUI call' }
    if ($OutputMode -ne 'Single') { throw 'Picker must use single selection' }
  }
  process { if ($env:ROOTARK_TEST_MODE -ne 'cancel' -and $InputObject.Path -eq $env:ROOTARK_TEST_CHOICE) { $InputObject } }
}
function Start-Process {
  param([string]$FilePath, [string[]]$ArgumentList)
  Set-Content -LiteralPath $env:ROOTARK_TEST_LAUNCH -Value (@{ process = $FilePath; arguments = @($ArgumentList) } | ConvertTo-Json -Compress)
}
if ($env:ROOTARK_TEST_LOCATION) { Set-Location -LiteralPath $env:ROOTARK_TEST_LOCATION }
try { & $env:ROOTARK_TEST_PICKER -Config $env:ROOTARK_TEST_CONFIG } catch { Write-Output $_.Exception.Message; exit 42 }
`;

async function runPicker(t, mode, selectedPath = "docs/verified.txt", options = {}) {
  const temp = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-picker-test-"));
  t.after(() => fs.rm(temp, { recursive: true, force: true }));
  const local = path.join(temp, "Root Ark Files");
  await fs.mkdir(path.join(local, "docs"), { recursive: true });
  await fs.writeFile(path.join(local, "docs", "verified.txt"), "unchanged local bytes");
  const config = path.join(temp, "private-config.json");
  const trace = path.join(temp, "trace.txt");
  const launch = path.join(temp, "launch.json");
  const target = path.join(local, "docs", "verified.txt");
  const outside = path.join(temp, mode === "reparse-parent" ? "outside-dir" : "outside.txt");
  const prepared = path.join(temp, mode === "reparse-parent" ? "prepared-junction" : "prepared-symlink.txt");
  if (mode === "reparse-leaf" || mode === "reparse-parent") {
    if (mode === "reparse-parent") {
      await fs.mkdir(outside);
      await fs.writeFile(path.join(outside, "verified.txt"), "foreign bytes never hydrated by the engine");
    } else {
      await fs.writeFile(outside, "foreign bytes never hydrated by the engine");
    }
    try {
      await fs.symlink(outside, prepared, mode === "reparse-parent" ? "junction" : "file");
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
        t.skip("Windows symlink/junction creation requires sufficient privileges");
        return null;
      }
      throw error;
    }
    assert.equal((await fs.lstat(prepared)).isSymbolicLink(), true,
      "the prepared reparse point must be real before running PowerShell");
  }
  const drive = path.parse(temp).root.slice(0, 2);
  const configuredFolder = options.folderMode === "relative" ? "Root Ark Files"
    : options.folderMode === "drive-relative" ? `${drive}Root Ark Files`
      : options.folderMode === "root-relative" ? local.slice(path.parse(local).root.length - 1)
        : local;
  await fs.writeFile(config, JSON.stringify({ localFolder: configuredFolder }));
  const otherLocation = path.join(temp, "other-working-directory");
  if (options.differentLocation) await fs.mkdir(otherLocation);
  const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", harness], {
    env: { ...process.env, ROOTARK_TEST_MODE: mode, ROOTARK_TEST_CHOICE: selectedPath,
      ROOTARK_TEST_TRACE: trace, ROOTARK_TEST_LAUNCH: launch,
      ROOTARK_TEST_CONFIG: options.relativeConfig ? ".\\private-config.json" : config,
      ROOTARK_TEST_LOCATION: options.relativeConfig ? temp : options.differentLocation ? otherLocation : "",
      ROOTARK_TEST_PICKER: picker,
      ROOTARK_TEST_TARGET: target, ROOTARK_TEST_PARENT: path.dirname(target),
      ROOTARK_TEST_PREPARED_LINK: prepared },
    encoding: "utf8", timeout: 20000,
  });
  return { result, local, trace: await fs.readFile(trace, "utf8").catch(() => ""),
    launch: await fs.readFile(launch, "utf8").then(JSON.parse, () => null) };
}

async function assertExplorerRevealsFile(launch, expectedFile) {
  assert.ok(launch, "Explorer must be launched after verified hydration");
  assert.equal(launch.process.toLowerCase().endsWith("explorer.exe"), true);
  assert.equal(launch.arguments.length, 1, "Explorer must receive exactly one selection argument");
  const selection = /^\/select,"([^"]+)"$/i.exec(launch.arguments[0]);
  assert.ok(selection, "Explorer must receive a quoted, single-file /select argument");
  // Windows PowerShell's GetFullPath expands NTFS 8.3 components while Node's
  // os.tmpdir() can report RUNNER~1. Compare the actual on-disk destination;
  // different names, symlinks, or sibling files must never satisfy this check.
  const [actualCanonical, expectedCanonical] = await Promise.all([
    fs.realpath(selection[1]), fs.realpath(expectedFile),
  ]);
  assert.equal(actualCanonical.toLowerCase(), expectedCanonical.toLowerCase(),
    "Explorer must reveal the exact verified local file");
}

for (const [mode, message] of [
  ["missing-Out-GridView", "Out-GridView requires Windows PowerShell with the GraphicalTools feature."],
  ["missing-node", "Node.js is required to run the Root.ark Windows picker. Ensure node is available on PATH."],
]) {
  test(`issue 66 Windows: picker rejects ${mode} before querying inventory`, { skip: process.platform !== "win32" }, () => {
    const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-Command", harness], {
      env: { ...process.env, ROOTARK_TEST_MODE: mode,
        ROOTARK_TEST_CONFIG: "synthetic-unused-config.json", ROOTARK_TEST_PICKER: picker },
      encoding: "utf8", timeout: 20000,
    });
    assert.equal(result.status, 42, result.stderr);
    assert.equal(result.stdout.trim(), message);
  });
}

test("issue 66 Windows: Explorer picker pages metadata then reveals only a verified hydrated file", { skip: process.platform !== "win32" }, async (t) => {
  const { result, local, trace, launch } = await runPicker(t, "ok");
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  assert.equal(trace.split(/\r?\n/).filter((line) => line.includes("|browse|")).length, 2);
  assert.equal(trace.split(/\r?\n/).filter((line) => line.includes("|hydrate|")).length, 1);
  assert.match(trace, /--path=docs\/verified\.txt/);
  await assertExplorerRevealsFile(launch, path.join(local, "docs", "verified.txt"));
  assert.equal(await fs.readFile(path.join(local, "docs", "verified.txt"), "utf8"), "unchanged local bytes");
});

test("issue 66 Windows: relative config argument uses PowerShell provider location", { skip: process.platform !== "win32" }, async (t) => {
  const { result, local, trace, launch } = await runPicker(t, "ok", "docs/verified.txt", { relativeConfig: true });
  assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
  assert.match(trace, /\|browse\|/);
  await assertExplorerRevealsFile(launch, path.join(local, "docs", "verified.txt"));
});

for (const folderMode of ["relative", "drive-relative", "root-relative"]) {
  test(`issue 66 Windows: ${folderMode} localFolder resolves from config directory`, { skip: process.platform !== "win32" }, async (t) => {
    const { result, local, launch, trace } = await runPicker(t, "ok", "docs/verified.txt", {
      folderMode, differentLocation: true,
    });
    assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`);
    assert.match(trace, /\|hydrate\|/);
    await assertExplorerRevealsFile(launch, path.join(local, "docs", "verified.txt"));
  });
}

test("issue 66 Windows: failed verified hydration does not reveal or alter local bytes", { skip: process.platform !== "win32" }, async (t) => {
  const { result, local, launch, trace } = await runPicker(t, "deny");
  assert.notEqual(result.status, 0);
  assert.equal(launch, null);
  assert.match(trace, /\|hydrate\|/);
  assert.equal(await fs.readFile(path.join(local, "docs", "verified.txt"), "utf8"), "unchanged local bytes");
});

for (const { mode, reparseComponent } of [
  { mode: "reparse-leaf", reparseComponent: "verified.txt" },
  { mode: "reparse-parent", reparseComponent: "docs" },
]) {
  test(`issue 66 Windows: post-hydrate ${mode} fails before Explorer reveal`,
    { skip: process.platform !== "win32" }, async (t) => {
      const outcome = await runPicker(t, mode);
      if (!outcome) return;
      const { result, local, trace, launch } = outcome;
      const swapped = path.join(local, "docs", "verified.txt");
      const reparse = path.join(local, "docs", ...(reparseComponent === "docs" ? [] : ["verified.txt"]));
      assert.equal((await fs.lstat(reparse).catch((error) => {
        throw new Error(`the adversarial swap did not create a reparse point (${error.code}); PowerShell: ${result.stdout} ${result.stderr}`);
      })).isSymbolicLink(), true,
      `the adversarial hook must actually rename the prepared ${reparseComponent} link`);
      assert.match(trace, /\|hydrate\|/, "the fake successful hydrate must be invoked first");
      assert.notEqual(result.status, 0, "a swapped path must fail closed after hydrate");
      assert.match(result.stdout + result.stderr, /reparse point/i);
      assert.equal(launch, null, "Explorer must not reveal a now-unverified foreign target");
      assert.equal(await fs.readFile(swapped, "utf8"), "foreign bytes never hydrated by the engine");
    });
}

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
