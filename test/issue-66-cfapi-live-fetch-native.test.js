"use strict";

// Real Windows kernel FETCH_DATA fixture. The registered sync root and its
// entire content live under disposable TEMP paths; the production gate remains
// closed until native RootSession custody and signed authority are proven.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { buildCompiledFixture, runCompiledFixture } =
  require("./support/issue-66-cfapi-built-artifact");

test("#66 live Windows CFAPI kernel FETCH_DATA completes and unregisters the disposable root",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const where = spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
      ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
      { encoding: "utf8", timeout: 6000, windowsHide: true });
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 unavailable"); return; }
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-live-"));
    const root = `${scratch}-root`;
    t.after(async () => {
      await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });
    await fs.mkdir(root);
    const { receipt, buildResult } = buildCompiledFixture(scratch, "live-fetch.exe", vcvars);
    assert.equal(buildResult.status, 0);
    assert.throws(() => runCompiledFixture(receipt, ["--disposable-live", scratch]),
      /UNTRUSTED_EXECUTABLE/, "the test runner must reject a non-dedicated root");
    const result = runCompiledFixture(receipt, ["--disposable-live", root], 20000);
    assert.equal(result.status, 0, `CFAPI live callback failed: ${result.stdout}\n${result.stderr}`);
    const evidence = JSON.parse(result.stdout.trim());
    assert.ok(evidence.liveKernelCallbackCount >= 1);
    assert.ok(evidence.successfulTransfers >= 1);
    assert.equal(evidence.rejectedTransfers, 0);
    assert.equal(evidence.verifiedBytes, 4097,
      "native real callback must hydrate the final unaligned EOF byte");
    assert.equal(evidence.unregistered, true);
    assert.equal(evidence.positiveReadVerified, true);
  });
