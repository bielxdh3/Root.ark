"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { buildCompiledFixture, runCompiledFixture } =
  require("./support/issue-66-cfapi-built-artifact");

const win = process.platform === "win32";
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
  // A hostile compile.cmd in scratch may exist but must never be invoked.
  const marker = path.join(dir, "untrusted-compile-ran.txt");
  await fs.writeFile(path.join(dir, "compile.cmd"),
    `@echo off\r\necho UNTRUSTED > "${marker}"\r\n`);
  const { receipt, buildResult: built } =
    buildCompiledFixture(dir, "deny-fetch.exe", vcvars);
  assert.equal(built.status, 0, "NATIVE_DENY_CALLBACK_COMPILE_FAILED");
  await assert.rejects(fs.access(marker), { code: "ENOENT" });
  const denied = runCompiledFixture(receipt, ["--self-test"]);
  assert.equal(denied.status, 0, "NATIVE_DENY_CALLBACK_SELF_TEST_FAILED");
  const result = JSON.parse(denied.stdout.trim());
  assert.equal(result.nativeCallback, "FETCH_DATA");
  assert.ok(result.platformBuild >= 16299);
  assert.equal(result.failedTransferCompletions, 1);
  assert.equal(result.dataBytesTransferred, 0);
  assert.equal(result.syncRootRegistered, false);
  const forbiddenArgs = runCompiledFixture(receipt, ["--connect", dir]);
  assert.notEqual(forbiddenArgs.status, 0);
  assert.equal(forbiddenArgs.stdout.trim(), "");
});
