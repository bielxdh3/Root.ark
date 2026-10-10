"use strict";

const fs = require("node:fs");
const path = require("node:path");
const service = require("../../services/backupService.js");
const repository = require("../../repositories/backupRepository.js");

function readInput() {
  const input = JSON.parse(process.argv[2] || "{}");
  if (!input || typeof input !== "object" || typeof input.mode !== "string") {
    throw new Error("invalid backup crash helper input");
  }
  return input;
}

function killAfterRename(source, destination) {
  const original = fs.renameSync;
  fs.renameSync = function (from, to) {
    const result = original.call(this, from, to);
    if (path.resolve(from) === path.resolve(source) && path.resolve(to) === path.resolve(destination)) {
      process.kill(process.pid, "SIGKILL");
    }
    return result;
  };
}

function cleanupWithCrash(mode, data) {
  if (mode === "crash-after-archive-tombstone-rename") {
    killAfterRename(data.archivePath, data.tombstonePath);
  } else if (mode === "crash-after-repository-deletion") {
    const original = repository.deleteBackup;
    repository.deleteBackup = (...args) => {
      const result = original(...args);
      process.kill(process.pid, "SIGKILL");
      return result;
    };
  } else if (mode === "crash-after-tombstone-removal") {
    const original = fs.rmSync;
    fs.rmSync = function (target, options) {
      const result = original.call(this, target, options);
      if (path.resolve(target) === path.resolve(data.tombstonePath)) process.kill(process.pid, "SIGKILL");
      return result;
    };
  } else if (mode === "fail-repository-deletion") {
    repository.deleteBackup = () => { throw Object.assign(new Error("repository"), { code: "EFAIL" }); };
  } else if (mode === "fail-tombstone-removal-once") {
    const original = fs.rmSync;
    let failed = false;
    fs.rmSync = function (target, options) {
      if (path.resolve(target) === path.resolve(data.tombstonePath) && !failed) {
        failed = true;
        throw Object.assign(new Error("busy"), { code: data.errorCode });
      }
      return original.call(this, target, options);
    };
  }
  process.env.BACKUP_RETENTION_DAYS = "1";
  process.env.BACKUP_RETENTION_COUNT = "0";
  return service.cleanupRetention();
}

async function deleteBackupWithCrash(mode, data) {
  if (mode === "crash-delete-backup-after-archive-tombstone-rename") {
    killAfterRename(data.archivePath, data.tombstonePath);
  } else {
    const original = repository.deleteBackup;
    repository.deleteBackup = (...args) => {
      const result = original(...args);
      process.kill(process.pid, "SIGKILL");
      return result;
    };
  }
  await service.deleteBackup(data.backupId);
}

function trackDurabilityEvents(data) {
  const events = [];
  const fdPaths = new Map();
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  const originalFsync = fs.fsyncSync;
  const originalRename = fs.renameSync;
  const originalRm = fs.rmSync;
  fs.openSync = function (target, ...args) {
    const fd = originalOpen.call(this, target, ...args);
    fdPaths.set(fd, String(target));
    return fd;
  };
  fs.closeSync = function (fd) {
    fdPaths.delete(fd);
    return originalClose.call(this, fd);
  };
  fs.fsyncSync = function (fd) {
    const target = fdPaths.get(fd);
    if (target && fs.statSync(target).isDirectory()) events.push(`dir-sync:${path.resolve(target)}`);
    else events.push(`file-sync:${target}`);
    return originalFsync.call(this, fd);
  };
  fs.renameSync = function (from, to) {
    const result = originalRename.call(this, from, to);
    if (String(to).endsWith("transaction.json")) events.push(`journal-rename:${path.resolve(to)}`);
    if (path.resolve(from) === path.resolve(data.archivePath) && path.resolve(to) === path.resolve(data.tombstonePath)) events.push("archive-rename");
    return result;
  };
  fs.rmSync = function (target, options) {
    const result = originalRm.call(this, target, options);
    const resolved = path.resolve(target);
    if (resolved === path.resolve(data.tombstonePath)) events.push("tombstone-remove");
    if (String(target).endsWith("transaction.json")) events.push(`transaction-file-remove:${path.dirname(resolved)}`);
    if (path.dirname(resolved) === path.resolve(service.RETENTION_TRANSACTIONS_DIR)) events.push(`transaction-directory-remove:${path.dirname(resolved)}`);
    return result;
  };
  return events;
}

async function startServerAtListener(data) {
  const net = require("node:net");
  net.Server.prototype.listen = function () {
    const history = repository.getBackup(data.backupId);
    const result = {
      archiveExists: fs.existsSync(data.archivePath),
      tombstoneExists: fs.existsSync(data.tombstonePath),
      historyExists: Boolean(history),
      transactionRootExists: fs.existsSync(data.transactionRootPath)
        && fs.readdirSync(data.transactionRootPath).length > 0,
    };
    fs.writeFileSync(data.resultPath, JSON.stringify(result));
    process.exit(JSON.stringify(result) === JSON.stringify(data.expected) ? 0 : 4);
  };
  require("../../server.js");
}

async function main() {
  const { mode, data = {} } = readInput();
  switch (mode) {
    case "critical-section": {
      let release;
      try {
        release = service.acquireLock("backup");
        fs.appendFileSync(data.enteredPath, `${process.pid}\n`);
        const fd = fs.openSync(data.criticalPath, "wx");
        setTimeout(() => {
          fs.closeSync(fd);
          fs.rmSync(data.criticalPath, { force: true });
          release();
          process.exit(0);
        }, 250);
      } catch (error) {
        if (release) release();
        process.exit(error.code === "BACKUP_LOCKED" ? 10 : 11);
      }
      break;
    }
    case "remote-lock-check": {
      const before = fs.readFileSync(data.lockPath, "utf8");
      try {
        const release = service.acquireLock("restore");
        release();
        process.exit(1);
      } catch (error) {
        if (error.code !== "BACKUP_LOCKED") process.exit(2);
        if (fs.readFileSync(data.lockPath, "utf8") !== before) process.exit(3);
        console.log(JSON.stringify({ locked: true, preserved: true }));
      }
      break;
    }
    case "crash-after-stale-evidence-quarantine": {
      const original = fs.renameSync;
      fs.renameSync = function (from, to) {
        const result = original.call(this, from, to);
        if (path.resolve(from) === path.resolve(service.LOCK_FILE) && String(to).endsWith("evidence")) process.kill(process.pid, "SIGKILL");
        return result;
      };
      service.acquireLock("backup");
      break;
    }
    case "crash-after-takeover-authority-removal": {
      const target = path.join(path.dirname(service.LOCK_FILE), ".backup.lock.takeover", "evidence");
      const original = fs.rmSync;
      fs.rmSync = function (candidate, options) {
        if (path.resolve(String(candidate)) === path.resolve(target)) process.kill(process.pid, "SIGKILL");
        return original.call(this, candidate, options);
      };
      const release = service.acquireLock("backup");
      release();
      break;
    }
    case "expect-lock-error": {
      try { service.acquireLock(data.operation || "backup"); process.exit(1); }
      catch (error) { process.exit(error.code === data.expectedCode ? 0 : 2); }
      break;
    }
    case "operations-share-lock": {
      const release = service.acquireLock("backup");
      const values = [];
      for (const operation of ["restore", "delete"]) {
        try { service.acquireLock(operation); } catch (error) { values.push(error.code); }
      }
      release();
      console.log(JSON.stringify(values));
      break;
    }
    case "recover-retention":
      service.recoverRetentionTombstones();
      break;
    case "cleanup-retention":
      await service.cleanupRetention();
      break;
    case "crash-after-archive-tombstone-rename":
    case "crash-after-repository-deletion":
    case "crash-after-tombstone-removal":
    case "fail-repository-deletion":
    case "fail-tombstone-removal-once":
      await cleanupWithCrash(mode, data);
      break;
    case "crash-delete-backup-after-archive-tombstone-rename":
    case "crash-delete-backup-after-repository-deletion":
      await deleteBackupWithCrash(mode, data);
      break;
    case "server-recovery-at-listen":
      await startServerAtListener(data);
      break;
    case "corrupt-journal-blocks-listener": {
      const net = require("node:net");
      net.Server.prototype.listen = function () {
        fs.writeFileSync(data.listenerMarker, "started");
        process.exit(0);
      };
      require("../../server.js");
      break;
    }
    case "track-retention-durability": {
      const events = trackDurabilityEvents(data);
      process.env.BACKUP_RETENTION_DAYS = "1";
      process.env.BACKUP_RETENTION_COUNT = "0";
      await service.cleanupRetention();
      console.log(JSON.stringify(events));
      break;
    }
    case "fail-parent-fsync-after-rename": {
      const fdPaths = new Map();
      const originalOpen = fs.openSync;
      const originalFsync = fs.fsyncSync;
      const originalRename = fs.renameSync;
      let moved = false;
      let injected = false;
      fs.openSync = function (target, ...args) {
        const fd = originalOpen.call(this, target, ...args);
        fdPaths.set(fd, String(target));
        return fd;
      };
      fs.fsyncSync = function (fd) {
        const target = fdPaths.get(fd);
        if (moved && !injected && target === service.BACKUPS_DIR) {
          injected = true;
          throw Object.assign(new Error("injected parent directory fsync failure"), { code: "EIO" });
        }
        return originalFsync.call(this, fd);
      };
      fs.renameSync = function (from, to) {
        const result = originalRename.call(this, from, to);
        if (path.resolve(from) === path.resolve(data.archivePath) && path.resolve(to) === path.resolve(data.tombstonePath)) moved = true;
        return result;
      };
      process.env.BACKUP_RETENTION_DAYS = "1";
      process.env.BACKUP_RETENTION_COUNT = "0";
      try {
        await service.cleanupRetention();
        console.log(JSON.stringify({ injected, unexpectedSuccess: true }));
      } catch (error) {
        console.log(JSON.stringify({
          injected,
          error: error.message,
          archive: fs.existsSync(data.archivePath),
          tombstone: fs.existsSync(data.tombstonePath),
          history: Boolean(repository.getBackup(data.backupId)),
        }));
      }
      break;
    }
    case "roundtrip-runtime-path":
      fs.writeFileSync(data.resultPath, JSON.stringify({ runtime: data.runtime }));
      break;
    default:
      throw new Error(`unknown backup crash helper mode: ${mode}`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
