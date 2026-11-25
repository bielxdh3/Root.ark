"use strict";

// Test-only native Windows NTFS proof: the retained ancestor HANDLE must read
// its original UTF-16 marker while its former name points at replacement B,
// and again after the name returns to A. No pathname content reads or cleanup.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const enabled = process.platform === "win32" &&
  process.env.ROOTARK_ISSUE66_W25_NATIVE_IO_LAB === "1";
const localAppData = process.env.LOCALAPPDATA;
const helper = path.join(__dirname, "support", "issue-66-w25-native-rename-identity.ps1");
const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const prefix = "rootark-w25-rename-identity-";

function invoke(scratch, proofEnabled = true) {
  return spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", helper,
    "-Scratch", scratch, "-Share", "RW", "-Move", "INFO",
  ], {
    windowsHide: true, encoding: "utf8", timeout: 15000, maxBuffer: 8192,
    env: {
      ...process.env,
      ROOTARK_ISSUE66_W25_NATIVE_IO_LAB: "1",
      ROOTARK_W25_HELD_UTF16_PROOF: proofEnabled ? "1" : "0",
      ROOTARK_W25_SOURCE_SWAP_TEST: "0",
    },
  });
}

test("#66 W25 native root-relative UTF-16 enumeration/read after A→B→A name swap",
  { skip: !enabled, timeout: 30000 }, () => {
    assert.ok(localAppData && path.win32.isAbsolute(localAppData));
    const scratch = fs.mkdtempSync(path.join(localAppData, prefix));
    assert.equal(path.dirname(scratch).toLowerCase(), localAppData.toLowerCase());
    assert.match(path.basename(scratch), /^rootark-w25-rename-identity-[A-Za-z0-9_-]{6,}$/);
    const result = invoke(scratch);
    assert.equal(result.status, 0, "native root-relative read proof must succeed");
    assert.equal(result.stderr, "", "no paths, IDs, contents, or security data in stderr");
    assert.match(result.stdout,
      /^ROOTARK_W25_HELD_READ_V1 filesystem=NTFS storage=LOCAL rename=HANDLE phases=A_B_A original=READ_A replacement=READ_B rebound=READ_A utf16=EXACT enumeration=EXACT collision=DENIED identity=PINNED reparse=CHECKED\r?\n$/);
    // Only inspect our own named fixture after the native proof, without
    // reading file content by pathname or deleting anything.
    assert.deepEqual(fs.readdirSync(scratch).sort(),
      ["held-ancestor", "replacement-ancestor"]);
  });

test("#66 W25 native UTF-16 helper rejects populated scratch without mutation",
  { skip: !enabled, timeout: 30000 }, () => {
    assert.ok(localAppData && path.win32.isAbsolute(localAppData));
    const scratch = fs.mkdtempSync(path.join(localAppData, prefix));
    fs.writeFileSync(path.join(scratch, "owner-canary"), "DO_NOT_TOUCH");
    const result = invoke(scratch);
    assert.equal(result.status, 41);
    assert.equal(result.stdout, "");
    assert.match(result.stderr, /^ROOTARK_W25_RENAME_REJECTED\r?\n$/);
    assert.deepEqual(fs.readdirSync(scratch), ["owner-canary"]);
    assert.equal(fs.readFileSync(path.join(scratch, "owner-canary"), "utf8"), "DO_NOT_TOUCH");
  });
