"use strict";
const assert = require("node:assert/strict");
const test = require("node:test");
const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const CHILD = path.join(__dirname, "support", "issue-65-startup-cleanup-child.cjs");

function run(strict, flip = false) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-startup-cleanup-"));
  try {
    const result = spawnSync(process.execPath, [CHILD, ...(flip ? ["flip"] : [])], {
      cwd: root, encoding: "utf8", windowsHide: true, timeout: 30000,
      env: { ...process.env, DB_ENABLED: "false", ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict },
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test("STRICT startup preserves orphaned owner-private cloud and SQLite backup stage evidence", () => {
  const strict = run("1");
  assert.deepEqual([strict.cloudBytesRetained, strict.sqliteBytesRetained], [true, true],
    "strict startup must preserve interrupted legacy evidence without external owner consent");
  const legacy = run("0");
  assert.equal(legacy.allowed, true);
  assert.deepEqual([legacy.cloudBytesRetained, legacy.sqliteBytesRetained], [false, false],
    "ordinary legacy recovery still cleans stale staging");
});

test("STRICT transition after startup async inventory cannot erase existing stages", () => {
  const late = run("0", true);
  assert.deepEqual([late.cloudBytesRetained, late.sqliteBytesRetained], [true, true]);
});
