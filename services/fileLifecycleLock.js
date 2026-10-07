const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const os = require("node:os");
const { AsyncLocalStorage } = require("node:async_hooks");

function createFileLifecycleLock({ directory, timeoutMs = 30_000, pollMs = 25 } = {}) {
  if (!directory) throw new TypeError("File lifecycle lock requires a shared directory");
  const lockDirectory = path.resolve(directory);
  const context = new AsyncLocalStorage();

  function lockPathFor(folderId, fileName) {
    const basename = path.basename(String(fileName || ""));
    const fileIdentity = process.platform === "win32" ? basename.toLowerCase() : basename;
    const identity = `${String(folderId || "root")}\0${fileIdentity}`;
    const digest = crypto.createHash("sha256").update(identity).digest("hex");
    return path.join(lockDirectory, `${digest}.lock`);
  }

  function folderLockPath(folderId) {
    const identity = "folder:" + String(folderId || "root");
    const digest = crypto.createHash("sha256").update(identity).digest("hex");
    return path.join(lockDirectory, digest + ".lock");
  }

  function releaseIfOwned(lockPath, token) {
    try {
      const stat = fs.lstatSync(lockPath);
      if (!stat.isFile() || stat.isSymbolicLink()) return;
      const owner = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      if (owner.token === token) fs.unlinkSync(lockPath);
    } catch {}
  }

  function sameHostOwnerIsDead(owner) {
    if (!owner || typeof owner.token !== "string" || !owner.token || owner.hostname !== os.hostname() || !Number.isInteger(Number(owner.pid)) || Number(owner.pid) <= 0) return false;
    try {
      process.kill(Number(owner.pid), 0);
      return false;
    } catch (error) {
      return error.code === "ESRCH";
    }
  }

  function reclaimDeadOwner(lockPath) {
    let owner;
    try {
      const stat = fs.lstatSync(lockPath);
      if (!stat.isFile() || stat.isSymbolicLink()) return false;
      owner = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    } catch { return false; }
    if (!sameHostOwnerIsDead(owner)) return false;

    const reaperPath = `${lockPath}.reaper`;
    const reaperToken = crypto.randomUUID();
    let descriptor;
    try {
      descriptor = fs.openSync(reaperPath, "wx", 0o600);
      fs.writeFileSync(descriptor, JSON.stringify({ token: reaperToken, pid: process.pid, hostname: os.hostname() }));
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
    } catch (error) {
      if (descriptor !== undefined) try { fs.closeSync(descriptor); } catch {}
      return false;
    }

    try {
      let current;
      try {
        const stat = fs.lstatSync(lockPath);
        if (!stat.isFile() || stat.isSymbolicLink()) return false;
        current = JSON.parse(fs.readFileSync(lockPath, "utf8"));
      } catch { return false; }
      if (current.token !== owner.token || !sameHostOwnerIsDead(current)) return false;
      fs.unlinkSync(lockPath);
      return true;
    } catch {
      return false;
    } finally {
      try {
        const reaper = JSON.parse(fs.readFileSync(reaperPath, "utf8"));
        if (reaper.token === reaperToken) fs.unlinkSync(reaperPath);
      } catch {}
    }
  }

  async function acquire(lockPath) {
    fs.mkdirSync(lockDirectory, { recursive: true, mode: 0o700 });
    const deadline = Date.now() + Math.max(1, timeoutMs);
    const token = crypto.randomUUID();
    while (true) {
      let descriptor;
      try {
        descriptor = fs.openSync(lockPath, "wx", 0o600);
        fs.writeFileSync(descriptor, `${JSON.stringify({ token, pid: process.pid, hostname: require("node:os").hostname(), createdAt: new Date().toISOString() })}\n`);
        fs.fsyncSync(descriptor);
        fs.closeSync(descriptor);
        return () => releaseIfOwned(lockPath, token);
      } catch (error) {
        if (descriptor !== undefined) {
          try { fs.closeSync(descriptor); } catch {}
          releaseIfOwned(lockPath, token);
        }
        if (error.code !== "EEXIST") {
          const unavailable = new Error("File lifecycle lock is unavailable");
          unavailable.code = "FILE_LIFECYCLE_LOCK_UNAVAILABLE";
          throw unavailable;
        }
        reclaimDeadOwner(lockPath);
        if (Date.now() >= deadline) {
          const timeout = new Error("File lifecycle lock acquisition timed out");
          timeout.code = "FILE_LIFECYCLE_LOCK_TIMEOUT";
          throw timeout;
        }
        await new Promise((resolve) => setTimeout(resolve, Math.min(pollMs, Math.max(1, deadline - Date.now()))));
      }
    }
  }

  async function runAt(lockPath, work) {
    if (typeof work !== "function") throw new TypeError("File lifecycle lock requires a work function");
    const held = context.getStore();
    if (held?.has(lockPath)) return work();

    const release = await acquire(lockPath);
    const nextHeld = new Set(held || []);
    nextHeld.add(lockPath);
    return context.run(nextHeld, async () => {
      try { return await work(); }
      finally { release(); }
    });
  }

  function runWithFolderLocks(folderIds, work) {
    const folderLocks = [...new Set((folderIds || []).map((folderId) => folderLockPath(folderId)))].sort();
    const acquireNextFolderLock = (index) => {
      if (index >= folderLocks.length) return work();
      return runAt(folderLocks[index], () => acquireNextFolderLock(index + 1));
    };
    return acquireNextFolderLock(0);
  }

  function runAcrossFolders(folderIds, fileFolderId, fileName, work) {
    return runWithFolderLocks(folderIds, () => runAt(lockPathFor(fileFolderId, fileName), work));
  }

  function run(folderId, fileName, work) {
    // The parent lock intentionally serializes file and folder lifecycle work within one folder.
    return runAcrossFolders([folderId], folderId, fileName, work);
  }

  function runFolder(folderId, work) {
    return runWithFolderLocks([folderId], work);
  }

  return { run, runAcrossFolders, runFolder };
}

module.exports = { createFileLifecycleLock };
