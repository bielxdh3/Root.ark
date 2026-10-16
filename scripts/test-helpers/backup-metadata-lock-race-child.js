const fs = require("node:fs");
const path = require("node:path");
const repository = require("../../repositories/backupRepository");

function waitForFile(filePath) {
  const waitArray = new Int32Array(new SharedArrayBuffer(4));
  const deadline = Date.now() + 10_000;
  while (!fs.existsSync(filePath) && Date.now() < deadline) Atomics.wait(waitArray, 0, 0, 10);
  return fs.existsSync(filePath);
}

function holdLease(activeFile, releaseFile) {
  const lease = repository.acquireJsonMutationLock("stale-lock-race");
  fs.writeFileSync(activeFile, lease.token);
  if (!waitForFile(releaseFile)) throw new Error("timed out waiting to release the mutation lease");
  lease.release();
  process.exit(0);
}

try {
  const mode = process.argv[2];
  if (mode === "paused-stale-claim") {
    const originalRenameSync = fs.renameSync;
    let paused = false;
    fs.renameSync = function (source, destination) {
      if (!paused && path.resolve(String(source)) === path.resolve(repository.MUTATION_LOCK_FILE)) {
        paused = true;
        fs.writeFileSync(process.env.STALE_CLASSIFIED_FILE, "ready");
        if (!waitForFile(process.env.ALLOW_FIRST_CLAIM_FILE)) {
          throw new Error("timed out waiting to resume stale-lock claim");
        }
      }
      return originalRenameSync.call(this, source, destination);
    };
    holdLease(process.env.FIRST_ACTIVE_FILE, process.env.RELEASE_FIRST_FILE);
  } else if (mode === "competing-claim") {
    holdLease(process.env.SECOND_ACTIVE_FILE, process.env.RELEASE_SECOND_FILE);
  } else if (mode === "hold-coordination-lock") {
    const Database = require("better-sqlite3");
    const db = new Database(repository.MUTATION_COORDINATION_DB_FILE);
    db.exec("BEGIN IMMEDIATE");
    fs.writeFileSync(process.env.COORDINATION_HELD_FILE, "ready");
    setTimeout(() => {
      try { db.exec("COMMIT"); } finally { db.close(); }
      process.exit(0);
    }, Number(process.env.COORDINATION_HOLD_MS) || 300);
  } else {
    throw new Error("unknown backup metadata lock race mode");
  }
} catch (error) {
  if (error.code === "BACKUP_METADATA_LOCK_BUSY") {
    process.stderr.write(`${error.code}:${error.reason || "unknown"}\n`);
    process.exit(2);
  }
  process.stderr.write(`${error.stack || error}\n`);
  process.exit(1);
}
