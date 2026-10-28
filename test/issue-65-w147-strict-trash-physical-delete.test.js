"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const child = path.join(__dirname, "support", "w147-trash-provider-child.cjs");
function run(root, phase, strict, itemType) {
  const proc = spawnSync(process.execPath, [child, phase, itemType], {
    cwd: root, encoding: "utf8", windowsHide: true, timeout: 20000,
    env: { ...process.env, DB_ENABLED: "false",
      ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict },
  });
  assert.equal(proc.status, 0, proc.stderr || proc.stdout);
  return JSON.parse(proc.stdout.trim().split(/\r?\n/).at(-1));
}

test("strict cloud trash DELETE after real persisted file/folder queues never runs provider; OFF resumes", { timeout: 85000 }, (t) => {
  for (const itemType of ["file", "folder"]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-trash-p1-"));
    t.after(() => fs.rmSync(root, { force: true, recursive: true }));
    const staged = run(root, "stage", "0", itemType);
    assert.deepEqual({ status: staged.status, state: staged.state },
      { status: "remote_delete_pending", state: "pending" });
    for (const [phase, strict] of [["delete", "1"], ["late", "0"]]) {
      const result = run(root, phase, strict, itemType);
      assert.deepEqual({
        strict: result.strict, deletes: result.deletes, errorCode: result.errorCode,
        state: result.state, status: result.status, remotePreserved: result.remotePreserved,
      }, {
        strict: "1", deletes: 0, errorCode: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE",
        state: "pending", status: "remote_delete_pending", remotePreserved: true,
      }, itemType + ": strict and late cutover must retain durable job and remote bytes");
    }
    const resumed = run(root, "delete", "0", itemType);
    assert.equal(resumed.deletes, 1);
    assert.equal(resumed.errorCode, null);
    assert.equal(resumed.state, "completed");
    assert.equal(resumed.status, "permanently_deleted");
    assert.equal(resumed.remotePreserved, false);
  }
});
