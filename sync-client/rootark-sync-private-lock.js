"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const { preparePrivateSyncConfigPath } =
  require("./rootark-sync-private-config");
const { assertPrivateSqliteAuthorityDirectory, assertPrivateSqliteFile } =
  require("../src/services/zk1PrivateSqlitePath");

function sameInode(left, right) {
  return left && right && left.dev === right.dev && left.ino === right.ino;
}

function lockHeld(filename) {
  const error = new Error(`SYNC_STATE_LOCK_HELD: another legacy sync process may be using this state, or a prior process left a stale lock at ${filename}. Do not delete it while any instance is running; inspect its PID and confirm all instances have stopped before manual removal.`);
  error.code = "SYNC_STATE_LOCK_HELD";
  return error;
}

// Node 22/24 has no portable kernel advisory-lock primitive. O_EXCL is an
// atomic cross-process acquisition on one private filesystem; refusing an
// existing lock is safer than racing two writers or reclaiming an apparently
// stale PID (which could have been reused). Recovery is explicitly manual.
function acquirePrivateSyncStateLock(statePath) {
  const lockPath = `${preparePrivateSyncConfigPath(statePath)}.lock`;
  assertPrivateSqliteAuthorityDirectory(lockPath);
  let fd;
  try {
    fd = fs.openSync(lockPath, fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0), 0o600);
  } catch (error) {
    if (error?.code === "EEXIST" || error?.code === "ELOOP") throw lockHeld(lockPath);
    throw error;
  }

  let pinned;
  let releaseOnExit;
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    if (releaseOnExit) {
      process.removeListener("exit", releaseOnExit);
      releaseOnExit = null;
    }
    try {
      // Never unlink a file another process published after our lock name
      // was exchanged, including an attacker-created symlink or hardlink.
      assertPrivateSqliteAuthorityDirectory(lockPath);
      const named = fs.lstatSync(lockPath, { bigint: true });
      if (pinned && named.isFile() && !named.isSymbolicLink()
        && named.nlink === 1n && sameInode(pinned, named)) {
        fs.unlinkSync(lockPath);
      }
    } catch (error) {
      if (error?.code !== "ENOENT") {
        // Preserve the stale lock rather than risk deleting a foreign inode.
        console.error(`SYNC_STATE_LOCK_RELEASE_FAILED: ${lockPath}: ${error.message}`);
      }
    }
  };
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    // Capture our own exclusive FD identity before any second pathname
    // lookup, including failure paths that need to release only our inode.
    pinned = { dev: opened.dev, ino: opened.ino };
    const named = fs.lstatSync(lockPath, { bigint: true });
    if (!opened.isFile() || !named.isFile() || named.isSymbolicLink()
      || opened.nlink !== 1n || named.nlink !== 1n
      || !sameInode(opened, named)) throw new Error("SYNC_STATE_LOCK_UNSAFE");
    assertPrivateSqliteAuthorityDirectory(lockPath);
    const checked = assertPrivateSqliteFile(lockPath);
    if (!sameInode(pinned, checked)) throw new Error("SYNC_STATE_LOCK_UNSAFE");
    if (process.platform === "win32") {
      require("../services/chunkUploadWindowsAcl").verifyWindowsAuthorityFilePath(lockPath);
    }
    const metadata = JSON.stringify({ version: 1, pid: process.pid,
      startedAt: new Date().toISOString(), nonce: crypto.randomUUID() });
    fs.writeSync(fd, `${metadata}\n`);
    fs.fsyncSync(fd);
    const after = fs.fstatSync(fd, { bigint: true });
    if (!sameInode(pinned, after) || after.nlink !== 1n) {
      throw new Error("SYNC_STATE_LOCK_CHANGED");
    }
    fs.closeSync(fd);
    fd = null;
    // Synchronous exit handler releases even if the app uses process.exit()
    // after SIGINT, without accidentally letting a concurrent SyncClient in.
    releaseOnExit = () => release();
    process.once("exit", releaseOnExit);
    return { lockPath, release };
  } catch (error) {
    if (fd !== null && fd !== undefined) fs.closeSync(fd);
    release();
    throw error;
  }
}

module.exports = { acquirePrivateSyncStateLock };
