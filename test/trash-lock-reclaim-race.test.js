const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-lock-race-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const trash = require("../services/trashService");

test("CodeQL #133: stale lock reclamation never deletes a newer active claim", (t) => {
  t.after(() => { process.chdir(originalCwd); fs.rmSync(runtime, { recursive: true, force: true }); });
  const operationId = "test-remote-lock-race";
  const lockDir = path.join(runtime, "data", "trash-remote-locks");
  const target = path.join(lockDir, `${operationId}.lock`);
  fs.mkdirSync(lockDir, { recursive: true });
  fs.writeFileSync(target, "old-owner");
  const now = Date.now();
  fs.utimesSync(target, new Date(now - 100_000), new Date(now - 100_000));
  const current = {
    id: "99999999-9999-4999-8999-999999999999",
    metadata: { remoteDeletion: { state: "pending", operationId } },
  };
  const originalStat = fs.statSync;
  let insertedNewLock = false;
  fs.statSync = function (file, ...args) {
    const snapshot = originalStat.call(fs, file, ...args);
    if (file === target && !insertedNewLock) {
      insertedNewLock = true;
      fs.rmSync(target);
      fs.writeFileSync(target, "new-active-owner");
    }
    return snapshot;
  };
  try {
    const claimed = trash.claimRemoteDeletion({ item: current, clock: () => now, leaseMs: 60_000 });
    assert.equal(claimed, null, "second claimant must not take the new owner's lock");
    assert.equal(fs.readFileSync(target, "utf8"), insertedNewLock ? "new-active-owner" : "old-owner");
  } finally {
    fs.statSync = originalStat;
  }
});
