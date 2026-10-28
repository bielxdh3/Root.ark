"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const CHILD = path.join(__dirname, "support", "issue-65-retention-strict-child.cjs");

function attempt(strict, mode = "") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-retention-direct-"));
  try {
    const result = spawnSync(process.execPath, [CHILD, ...(mode ? [mode] : [])], {
      cwd: dir, windowsHide: true, encoding: "utf8", timeout: 45000,
      env: { ...process.env, DB_ENABLED: "false", BACKUP_RETENTION_COUNT: "1",
        BACKUP_RETENTION_DAYS: "0", ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict },
    });
    assert.equal(result.status, 0, `child failed: ${result.stderr}`);
    return JSON.parse(result.stdout.trim().split(/\r?\n/).at(-1));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("direct retention service cannot erase archived owner bytes and history under STRICT", () => {
  const strict = attempt("1");
  assert.deepEqual({ allowed: strict.allowed, code: strict.code },
    { allowed: false, code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE" });
  assert.deepEqual(strict.survivingArchives, [true, true]);
  assert.deepEqual(strict.survivingRecords, [true, true]);
  assert.deepEqual(strict.originalContents, [true, true]);

  const legacy = attempt("0");
  assert.equal(legacy.allowed, true);
  assert.deepEqual(legacy.survivingArchives, [false, true]);
  assert.deepEqual(legacy.survivingRecords, [false, true]);
  assert.deepEqual(legacy.originalContents, [false, true]);
});

test("late STRICT transition during inventory await cannot delete historical ZIP and records", () => {
  const result = attempt("0", "flip");
  assert.deepEqual({ allowed: result.allowed, code: result.code },
    { allowed: false, code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE" });
  assert.deepEqual(result.survivingArchives, [true, true]);
  assert.deepEqual(result.survivingRecords, [true, true]);
  assert.deepEqual(result.originalContents, [true, true]);
});

test("exported tombstone recovery cannot erase an orphaned historical archive under STRICT", () => {
  const strict = attempt("1", "tombstone");
  assert.deepEqual({ allowed: strict.allowed, code: strict.code },
    { allowed: false, code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE" });
  assert.equal(strict.orphanPreserved, true);
  assert.equal(strict.metadataPreserved, true);

  const legacy = attempt("0", "tombstone");
  assert.equal(legacy.allowed, true);
  assert.equal(legacy.orphanPreserved, false);
  assert.equal(legacy.metadataPreserved, false);
});

test("late STRICT flip at real archive hash EOF never publishes a retention intent", () => {
  for (const operation of ["hashflip", "deletehashflip"]) {
    const result = attempt("0", operation);
    assert.deepEqual({ allowed: result.allowed, code: result.code },
      { allowed: false, code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE" }, operation);
    assert.deepEqual(result.survivingArchives, [true, true], operation);
    assert.deepEqual(result.survivingRecords, [true, true], operation);
    assert.deepEqual(result.originalContents, [true, true], operation);
    assert.equal(result.retentionJournalCount, 0,
      `${operation}: strict transition cannot persist an orphaned delete journal`);
  }
});
