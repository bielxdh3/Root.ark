"use strict";

// Opt-in native NTFS interop experiment only. This is NOT an operational
// CFAPI admission gate, process-image binding, or power-loss durability test.
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const allowed = process.platform === "win32" &&
  process.env.ROOTARK_ISSUE66_W25_NATIVE_IO_LAB === "1";
const localAppData = process.env.LOCALAPPDATA;
const script = path.join(__dirname, "support", "issue-66-w25-native-rooted-io-lab.ps1");
const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const fixedResult = /^ROOTARK_W25_ROOTED_IO_V1 originalRead=1 originalDelete=1 foreignPreserved=1 postSwapCreate=1 postSwapRead=1 postSwapDelete=1\r?\n$/;

function run(scriptScratch, optIn = true) {
  return spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Scratch", scriptScratch,
  ], {
    windowsHide: true, encoding: "utf8", timeout: 30000, maxBuffer: 16384,
    env: { ...process.env, ROOTARK_ISSUE66_W25_NATIVE_IO_LAB: optIn ? "1" : "0" },
  });
}

test("#66 W25 physical NTFS rooted handle IO remains bound through real ancestor rename and replacement",
  { skip: !allowed, timeout: 45000 }, (t) => {
    // This random scratch is inside the user's LocalAppData, not public TEMP.
    // The PowerShell helper refuses arbitrary parent paths and aliases.
    assert.ok(localAppData && path.win32.isAbsolute(localAppData));
    const scratch = fs.mkdtempSync(path.join(localAppData, "rootark-w25-native-rooted-io-"));
    t.after(() => {
      assert.match(path.basename(scratch), /^rootark-w25-native-rooted-io-[A-Za-z0-9_-]{6,}$/);
      assert.equal(path.dirname(scratch).toLowerCase(), localAppData.toLowerCase());
      fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 });
    });
    const outcome = run(scratch);
    assert.equal(outcome.status, 0, "rooted NTFS test rejected; do not fall back to path-based IO");
    assert.match(outcome.stdout, fixedResult);
    assert.equal(outcome.stderr, "", "native lab must never expose error, path, SID or ACL details");
    // The replacement's same-name canary is verified as untouched in native
    // code. Neither production nor another checkout is changed by the test.
  });

test("#66 W25 native test helper denies arbitrary external scratch and disabled opt-in",
  { skip: !allowed, timeout: 45000 }, (t) => {
    const foreign = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w25-native-rooted-io-"));
    t.after(() => fs.rmSync(foreign, { recursive: true, force: true }));
    fs.writeFileSync(path.join(foreign, "outside-canary.txt"), "UNCHANGED");
    for (const optIn of [true, false]) {
      const result = run(foreign, optIn);
      assert.equal(result.status, 41);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /^ROOTARK_W25_ROOTED_IO_REJECTED\r?\n$/);
    }
    assert.equal(fs.readFileSync(path.join(foreign, "outside-canary.txt"), "utf8"), "UNCHANGED");
    assert.deepEqual(fs.readdirSync(foreign), ["outside-canary.txt"]);
    const existing = fs.mkdtempSync(path.join(localAppData, "rootark-w25-native-rooted-io-"));
    t.after(() => fs.rmSync(existing, { recursive: true, force: true }));
    fs.writeFileSync(path.join(existing, "existing-owner-data.txt"), "DO_NOT_TOUCH");
    const rejected = run(existing);
    assert.equal(rejected.status, 41, "nonempty eligible-looking scratch must fail closed");
    assert.equal(rejected.stdout, "");
    assert.match(rejected.stderr, /^ROOTARK_W25_ROOTED_IO_REJECTED\r?\n$/);
    assert.deepEqual(fs.readdirSync(existing), ["existing-owner-data.txt"]);
    assert.equal(fs.readFileSync(path.join(existing, "existing-owner-data.txt"), "utf8"), "DO_NOT_TOUCH");
  });
