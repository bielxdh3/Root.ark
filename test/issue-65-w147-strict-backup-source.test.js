"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const CHILD = path.join(__dirname, "..", "lab", "issue-65-test-processes", "w147-strict-backup-child.cjs");
function run(root, action, strict, id) {
  const proc = spawnSync(process.execPath, [CHILD, action, ...(id ? [id] : [])], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true",
      BACKUP_AUTO_ENABLED: "true", BACKUP_INCLUDE_UPLOADS: "true",
      ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict },
    timeout: 60000,
    windowsHide: true,
  });
  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  return JSON.parse(proc.stdout.trim().split(/\r?\n/).at(-1));
}
test("strict ZK10 has no external authority: global ZIP source, restore and scheduler deny before plaintext while default OFF works", { timeout: 130000 }, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-zip-source-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const uploads = path.join(root, "uploads", "root");
  fs.mkdirSync(uploads, { recursive: true });
  fs.writeFileSync(path.join(uploads, "legacy.txt"), "W147_DISPOSABLE_LEGACY_PLAINTEXT");
  const original = run(root, "create", "0");
  assert.equal(original.allowed, true, JSON.stringify(original));

  const bundle = run(root, "strict-bundle", "1", original.id);
  for (const [action, denied] of Object.entries(bundle.attempts)) {
    assert.deepEqual({ allowed: denied.allowed, code: denied.code },
      { allowed: false, code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE" }, action + ": " + JSON.stringify(denied));
  }
  assert.equal(bundle.scheduled, false);
  assert.equal(bundle.allowed, false);
  assert.equal(fs.existsSync(path.join(root, "raw-direct.zip")), false, "no bytes streamed to unmanaged direct ZIP");

  // Characterization, NOT a monotonicity GREEN: a local flag cannot enforce offhost history.
  const restartedWithoutStrict = run(root, "lookup", "0", original.id);
  assert.equal(restartedWithoutStrict.allowed, true, "removing the local flag regresses without offhost floor");
});
