"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const win = process.platform === "win32";
const source = path.resolve(__dirname, "../sync-client/rootark-sync-windows-cfapi-deny-callback.cpp");
const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";

function findVcvars() {
  const found = spawnSync(vswhere, ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"], {
    encoding: "utf8", timeout: 5000, windowsHide: true,
  });
  return found.status === 0 ? found.stdout.trim().split(/\r?\n/).filter(Boolean)[0] : null;
}

test("issue 66 native CFAPI: real SDK ABI compiles and FETCH_DATA returns failed TRANSFER_DATA with no bytes", { skip: !win }, async (t) => {
  const vcvars = findVcvars();
  if (!vcvars) { t.skip("native x64 MSVC toolchain unavailable"); return; }
  try { await fs.access(vcvars); }
  catch { t.skip("native x64 MSVC vcvars64.bat unavailable"); return; }
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-abi-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const executable = path.join(dir, "deny-fetch.exe");
  const script = path.join(dir, "compile.cmd");
  await fs.writeFile(script, [
    "@echo off",
    `call "${vcvars}" >nul`,
    "if errorlevel 1 exit /b 1",
    `cl /nologo /std:c++17 /W4 /WX /EHsc /Fe:"${executable}" "${source}" cldapi.lib`,
    "exit /b %errorlevel%",
    "",
  ].join("\r\n"));
  const built = spawnSync("cmd.exe", ["/d", "/c", script], {
    cwd: dir, encoding: "utf8", timeout: 30000, windowsHide: true,
  });
  assert.equal(built.status, 0, `SDK compile failed: ${built.stdout}\n${built.stderr}`);
  const denied = spawnSync(executable, ["--self-test"], {
    cwd: dir, encoding: "utf8", timeout: 10000, windowsHide: true,
  });
  assert.equal(denied.status, 0, `native callback test failed: ${denied.stdout}\n${denied.stderr}`);
  const result = JSON.parse(denied.stdout.trim());
  assert.equal(result.nativeCallback, "FETCH_DATA");
  assert.ok(result.platformBuild >= 16299);
  assert.equal(result.failedTransferCompletions, 1);
  assert.equal(result.dataBytesTransferred, 0);
  assert.equal(result.syncRootRegistered, false);
  const forbiddenArgs = spawnSync(executable, ["--connect", dir], { encoding: "utf8", timeout: 10000, windowsHide: true });
  assert.notEqual(forbiddenArgs.status, 0);
  assert.equal(forbiddenArgs.stdout.trim(), "");
});
