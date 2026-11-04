"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

test("real SQLite claim fencing preserves the new owner on stale success and failure", () => {
  const dir = createPrivateAuthorityFixture("rootark-trash-owner-sqlite-");
  try {
    const worker = path.join(__dirname, "support", "trash-claim-owner-sqlite-worker.js");
    const result = spawnSync(process.execPath, [worker], {
      cwd: dir, encoding: "utf8", timeout: 20_000, windowsHide: true,
      env: { ...process.env, DB_ENABLED: "true",
        DATABASE_URL: path.join(dir, "data", "rootark.sqlite") },
    });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    assert.match(result.stdout, /SQLITE_REMOTE_CLAIM_FENCE_OK/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
