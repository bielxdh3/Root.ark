"use strict";

// A self-contained ABI *shape* probe, NOT a positive Cloud Files provider.
// Never register a sync root, connect a callback, decrypt, or hydrate a file.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const win = process.platform === "win32";
const source = path.resolve(__dirname, "../sync-client/rootark-sync-windows-cfapi-positive-shape.cpp");
const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";
const systemCmd = "C:\\Windows\\System32\\cmd.exe";

function findVcvars() {
  const found = spawnSync(vswhere, ["-all", "-products", "*", "-prerelease",
    "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"], {
    encoding: "utf8", timeout: 5000, windowsHide: true,
  });
  return found.status === 0 ? found.stdout.trim().split(/\r?\n/).filter(Boolean)[0] : null;
}

test("#66 positive CFAPI ABI fixture cannot register a provider or call real transfer", async () => {
  const text = await fs.readFile(source, "utf8");
  for (const forbidden of [/\bCfRegisterSyncRoot\s*\(/, /\bCfConnectSyncRoot\s*\(/,
    /\bCfHydratePlaceholder\s*\(/, /\bCfExecute\s*\(/]) {
    assert.doesNotMatch(text, forbidden);
  }
  assert.match(text, /--self-test/);
  assert.match(text, /CF_OPERATION_TYPE_TRANSFER_DATA/);
  assert.match(text, /STATUS_SUCCESS/);
  assert.match(text, /positiveHydrationAuthorized/);
});

test("#66 real Windows SDK validates bounded mock TRANSFER_DATA ranges, not kernel hydration",
  { skip: !win, timeout: 60000 }, async (t) => {
    const vcvars = findVcvars();
    if (!vcvars) { t.skip("MSVC x64 toolchain unavailable"); return; }
    const temporary = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-positive-abi-"));
    t.after(() => fs.rm(temporary, { recursive: true, force: true }));
    const executable = path.join(temporary, "positive-shape.exe");
    const script = path.join(temporary, "compile.cmd");
    await fs.writeFile(script, [
      "@echo off", `call "${vcvars}" >nul`, "if errorlevel 1 exit /b 1",
      `cl /nologo /std:c++17 /W4 /WX /EHsc /Fe:"${executable}" "${source}" cldapi.lib`,
      "exit /b %errorlevel%", "",
    ].join("\r\n"));
    const built = spawnSync(systemCmd, ["/d", "/c", script], {
      cwd: temporary, encoding: "utf8", timeout: 30000, windowsHide: true,
    });
    assert.equal(built.status, 0, `SDK compile failed: ${built.stdout}\n${built.stderr}`);
    const executed = spawnSync(executable, ["--self-test"], {
      cwd: temporary, encoding: "utf8", timeout: 10000, windowsHide: true,
    });
    assert.equal(executed.status, 0, `ABI shape failed: ${executed.stdout}\n${executed.stderr}`);
    const result = JSON.parse(executed.stdout.trim());
    assert.equal(result.nativeApiPresent, true);
    assert.ok(result.platformBuild >= 16299);
    assert.equal(result.syncRootRegistered, false);
    assert.equal(result.providerConnected, false);
    assert.equal(result.kernelCallbackInvoked, false);
    assert.equal(result.positiveHydrationAuthorized, false);
    assert.equal(result.mockPositiveOperations, 3);
    assert.equal(result.mockPositiveBytes, 4098);
    assert.ok(result.mockRejectedRanges >= 7);
    assert.equal(result.cloudDataBytesTransferred, 0);
    for (const args of [["--connect", temporary], ["--register", temporary],
      ["--hydrate", temporary], []]) {
      const forbidden = spawnSync(executable, args, {
        cwd: temporary, encoding: "utf8", timeout: 10000, windowsHide: true,
      });
      assert.notEqual(forbidden.status, 0);
      assert.equal(forbidden.stdout.trim(), "");
    }
  });
