const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");

const originalCwd = process.cwd();
const runtime = createPrivateAuthorityFixture("rootark-archive-ownership-");
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const backupService = require("../services/backupService");

function reset() {
  fs.rmSync(path.join(runtime, "data"), { recursive: true, force: true });
  fs.rmSync(path.join(runtime, "uploads"), { recursive: true, force: true });
  // The JSON audit lock caches ACL verification per process. Recreate its
  // private directory after each reset so the cached coordinator can open.
  fs.mkdirSync(path.join(runtime, "data"), { recursive: true });
  if (process.platform === "win32") {
    ensureWindowsChunkUploadRoot(path.join(runtime, "data", ".rootark-json-audit-private"));
  }
  fs.mkdirSync(path.join(runtime, "uploads"), { recursive: true });
}

test("exclusive archive reservations preserve pre-existing files and bound collisions", async () => {
  reset();
  const originalOpen = fs.openSync;
  const reserved = [];
  let collisions = 0;
  fs.openSync = (target, flags, ...rest) => {
    if (flags === "wx" && String(target).endsWith(".zip") && collisions < 1) {
      collisions += 1;
      reserved.push(target);
      fs.writeFileSync(target, "pre-existing");
    }
    return originalOpen(target, flags, ...rest);
  };
  let saved;
  try { saved = await backupService.createBackup(); } finally { fs.openSync = originalOpen; }
  assert.equal(fs.readFileSync(reserved[0], "utf8"), "pre-existing");
  assert.notEqual(saved.filename, path.basename(reserved[0]));
  assert.doesNotThrow(() => fs.statSync(path.join(backupService.BACKUPS_DIR, saved.filename)));
});

test("collision retry bound never removes unowned files", async () => {
  reset();
  process.env.BACKUP_ARCHIVE_COLLISION_RETRIES = "2";
  const originalOpen = fs.openSync;
  const reserved = [];
  fs.openSync = (target, flags, ...rest) => {
    if (flags === "wx" && String(target).endsWith(".zip")) {
      reserved.push(target);
      fs.writeFileSync(target, `keep-${reserved.length}`);
    }
    return originalOpen(target, flags, ...rest);
  };
  try { await assert.rejects(backupService.createBackup(), { code: "BACKUP_ARCHIVE_COLLISION_LIMIT" }); } finally {
    fs.openSync = originalOpen;
    delete process.env.BACKUP_ARCHIVE_COLLISION_RETRIES;
  }
  assert.equal(reserved.length, 2);
  for (const [index, file] of reserved.entries()) assert.equal(fs.readFileSync(file, "utf8"), `keep-${index + 1}`);
});

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
