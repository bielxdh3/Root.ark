const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

test("SQLite stage cleanup failure is observable without invalidating a completed archive", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-stage-cleanup-"));
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  try {
    const result = spawnSync(process.execPath, ["-e", `
      const fs = require("node:fs");
      process.chdir(${JSON.stringify(runtime)});
      process.env.DB_ENABLED = "true";
      process.env.DATABASE_URL = ${JSON.stringify(path.join(runtime, "data", "rootark.sqlite"))};
      const db = require(${JSON.stringify(path.join(__dirname, "..", "db"))});
      const live = db.getDb();
      live.exec("CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES ('stage');");
      const service = require(${JSON.stringify(servicePath)});
      const originalRemove = fs.rmSync;
      fs.rmSync = (target, options) => String(target).includes(".sqlite-backup-")
        ? (() => { throw Object.assign(new Error("locked stage"), { code: "EBUSY" }); })()
        : originalRemove(target, options);
      (async () => {
        try { await service.createBackup(); }
        catch (error) {
          const backup = error.backup;
          console.log(JSON.stringify({
            status: backup?.status,
            cleanup: backup?.metadata?.sqliteStageCleanup,
            archive: Boolean(backup && fs.existsSync(service.getArchivePath(backup.filename))),
            code: error.code,
            historyState: error.backupHistoryState,
            operationState: error.backupOperationState,
            cleanupFailureCodes: error.cleanupFailureCodes,
          }));
        }
        finally { db.closeDb(); }
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `], { encoding: "utf8", env: process.env });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
    assert.equal(output.status, "success");
    assert.deepEqual(output, {
      status: "success",
      cleanup: { code: "SQLITE_STAGE_CLEANUP_FAILED", message: "SQLite staging cleanup failed" },
      archive: true,
      code: "BACKUP_STAGE_CLEANUP_FAILED",
      historyState: "durable",
      operationState: "created-post-processing-failed",
      cleanupFailureCodes: ["SQLITE_STAGE_CLEANUP_FAILED"],
    });
    assert.equal(output.archive, true);
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});

test("SQLite archive output failure preserves the primary error and owned-archive boundary", () => {
  const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-sqlite-output-failure-"));
  const servicePath = path.join(__dirname, "..", "services", "backupService");
  try {
    const result = spawnSync(process.execPath, ["-e", `
      const fs = require("node:fs");
      process.chdir(${JSON.stringify(runtime)});
      process.env.DB_ENABLED = "true";
      process.env.DATABASE_URL = ${JSON.stringify(path.join(runtime, "data", "rootark.sqlite"))};
      const db = require(${JSON.stringify(path.join(__dirname, "..", "db"))});
      const live = db.getDb();
      live.exec("CREATE TABLE proof(value TEXT); INSERT INTO proof VALUES ('output');");
      const originalCreateWriteStream = fs.createWriteStream;
      const originalRemove = fs.rmSync;
      fs.createWriteStream = (target, options) => {
        const stream = originalCreateWriteStream(target, options);
        if (String(target).includes("rootark-backup-") && String(target).endsWith(".zip")) {
          process.nextTick(() => stream.emit("error", Object.assign(new Error("output failed"), { code: "OUTPUT_FAILED" })));
        }
        return stream;
      };
      fs.rmSync = (target, options) => String(target).includes(".sqlite-backup-")
        ? (() => { throw Object.assign(new Error("locked stage"), { code: "EBUSY" }); })()
        : originalRemove(target, options);
      const service = require(${JSON.stringify(servicePath)});
      (async () => {
        try { await service.createBackup(); }
        catch (error) {
          const archive = error.backup && service.getArchivePath(error.backup.filename);
          console.log(JSON.stringify({ code: error.code, message: error.message, backupStatus: error.backup?.status, archiveCleanup: error.archiveCleanupError?.code || null, sqliteCleanup: error.sqliteStageCleanupFailure?.code || null, archiveExists: Boolean(archive && fs.existsSync(archive)), zipCount: fs.readdirSync(service.BACKUPS_DIR).filter((name) => name.endsWith(".zip")).length }));
        }
        finally { db.closeDb(); }
      })().catch((error) => { console.error(error); process.exitCode = 1; });
    `], { encoding: "utf8", env: process.env });
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout.trim().split(/\r?\n/).pop());
    assert.deepEqual(output, { code: "OUTPUT_FAILED", message: "output failed", backupStatus: "failed", archiveCleanup: null, sqliteCleanup: "SQLITE_STAGE_CLEANUP_FAILED", archiveExists: false, zipCount: 0 });
  } finally {
    fs.rmSync(runtime, { recursive: true, force: true });
  }
});
