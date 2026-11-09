"use strict";

// Independent, opt-in native Windows identity/rename probe. Do NOT infer that
// a held HANDLE alone makes a Win32 pathname immutable.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const available = process.platform === "win32" &&
  process.env.ROOTARK_ISSUE66_W25_NATIVE_IO_LAB === "1";
const localAppData = process.env.LOCALAPPDATA;
const script = path.join(__dirname, "support", "issue-66-w25-native-rename-identity.ps1");
const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

function invoke(scratch, share, move, enabled = true) {
  return spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
    "-File", script, "-Scratch", scratch, "-Share", share, "-Move", move,
  ], {
    windowsHide: true, encoding: "utf8", timeout: 15000, maxBuffer: 8192,
    env: { ...process.env, ROOTARK_ISSUE66_W25_NATIVE_IO_LAB: enabled ? "1" : "0" },
  });
}

test("#66 W25 native CreateFileW directory sharing and actual rename identity (four modes)",
  { skip: !available, timeout: 90000 }, (t) => {
    assert.ok(localAppData && path.win32.isAbsolute(localAppData));
    for (const share of ["RW", "NONE"]) {
      for (const move of ["DOTNET", "WIN32"]) {
        const scratch = fs.mkdtempSync(path.join(localAppData, "rootark-w25-rename-identity-"));
        t.after(() => {
          assert.match(path.basename(scratch), /^rootark-w25-rename-identity-[A-Za-z0-9_-]{6,}$/);
          assert.equal(path.dirname(scratch).toLowerCase(), localAppData.toLowerCase());
          fs.rmSync(scratch, { recursive: true, force: true, maxRetries: 8, retryDelay: 150 });
        });
        const result = invoke(scratch, share, move);
        assert.equal(result.status, 0, "native identity proof rejected");
        assert.equal(result.stderr, "", "native stderr must not disclose paths/IDs/ACLs");
        // A real FileIdInfo comparison must map the held handle AND the moved
        // name to O1, while the replacement has a separate on-disk identity.
        const expected = new RegExp(`^ROOTARK_W25_RENAME_V2 mode=${move} share=${share === "RW" ? 3 : 0} handle=VALID move=SUCCESS win32LastError=${move === "WIN32" ? "[0-9]+" : "NA_DOTNET"} ntstatus=0x00000000 rootBefore=O1 rootAfter=O1 moved=O1 replacement=O2 child=ORIGINAL\\r?\\n$`);
        assert.match(result.stdout, expected,
          "real move must succeed with Win32 status and distinct verified original/replacement IDs");
      }
    }
  });

test("#66 W25 independent rename helper rejects non-empty and external scratch without mutations",
  { skip: !available, timeout: 45000 }, (t) => {
    for (const root of [os.tmpdir(), localAppData]) {
      const scratch = fs.mkdtempSync(path.join(root, "rootark-w25-rename-identity-"));
      t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
      fs.writeFileSync(path.join(scratch, "owner-canary"), "DO_NOT_TOUCH");
      for (const enabled of [true, false]) {
        const result = invoke(scratch, "RW", "WIN32", enabled);
        assert.equal(result.status, 41);
        assert.equal(result.stdout, "");
        assert.match(result.stderr, /^ROOTARK_W25_RENAME_REJECTED\r?\n$/);
      }
      assert.deepEqual(fs.readdirSync(scratch), ["owner-canary"]);
      assert.equal(fs.readFileSync(path.join(scratch, "owner-canary"), "utf8"), "DO_NOT_TOUCH");
    }
  });
