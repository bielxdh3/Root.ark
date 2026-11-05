"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { ensurePrivateSqliteDirectory, assertPrivateSqliteAuthorityDirectory,
  assertPrivateSqliteFile } = require("../src/services/zk1PrivateSqlitePath");

function inspectExistingConfig(filename) {
  let named;
  try { named = fs.lstatSync(filename, { bigint: true }); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
  if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n) {
    throw new Error("SYNC_CONFIG_UNSAFE_FILE");
  }
  // This descriptor check also rejects group-readable old credentials. Never
  // silently reuse a pre-existing foreign inode or hardlink as our config.
  const checked = assertPrivateSqliteFile(filename);
  if (process.platform === "win32") {
    require("../services/chunkUploadWindowsAcl").verifyWindowsAuthorityFilePath(filename);
  }
  return checked;
}

function equalIdentity(first, second) {
  return first && second && first.dev === second.dev && first.ino === second.ino;
}

function preparePrivateSyncConfigPath(filename, { createParent = false } = {}) {
  const configPath = path.resolve(filename);
  // Do not enter a caller-selected, writable directory or junction before
  // asking for credentials. New private children use the existing native
  // protected-ACL-at-creation path; no chmod-after-creation security gap.
  if (createParent) {
    try { fs.lstatSync(path.dirname(configPath)); }
    catch (error) {
      if (error.code !== "ENOENT") throw error;
      ensurePrivateSqliteDirectory(configPath);
    }
  }
  assertPrivateSqliteAuthorityDirectory(configPath);
  return configPath;
}

async function readPrivateSyncConfig(filename, fallback, { createParent = false } = {}) {
  if (!createParent) {
    try { fs.lstatSync(path.dirname(path.resolve(filename))); }
    catch (error) {
      if (error.code === "ENOENT") return fallback;
      throw error;
    }
  }
  const configPath = preparePrivateSyncConfigPath(filename, { createParent });
  const before = inspectExistingConfig(configPath);
  if (!before) return fallback;
  // Read from an opened, unlinked-to-foreign-inodes descriptor. Never trust a
  // preliminary lstat or follow a mutable symlink to obtain bearer tokens or
  // a server URL which could otherwise redirect an operator's login.
  const fd = fs.openSync(configPath, fs.constants.O_RDONLY
    | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  let bytes;
  try {
    const pinned = fs.fstatSync(fd, { bigint: true });
    if (!pinned.isFile() || pinned.nlink !== 1n || pinned.dev !== before.dev
      || pinned.ino !== before.ino || pinned.size > 1024n * 1024n) {
      throw new Error("SYNC_CONFIG_UNSAFE_FILE");
    }
    bytes = fs.readFileSync(fd, { encoding: "utf8" });
    const afterFd = fs.fstatSync(fd, { bigint: true });
    const afterName = inspectExistingConfig(configPath);
    if (afterFd.dev !== pinned.dev || afterFd.ino !== pinned.ino
      || afterFd.size !== pinned.size || !equalIdentity(before, afterName)) {
      throw new Error("SYNC_CONFIG_CHANGED_DURING_READ");
    }
  } finally { fs.closeSync(fd); }
  try { return JSON.parse(bytes); }
  catch { throw new Error("SYNC_CONFIG_INVALID_JSON"); }
}

async function writePrivateSyncConfig(filename, contents) {
  const configPath = preparePrivateSyncConfigPath(filename, { createParent: true });
  const existing = inspectExistingConfig(configPath);
  const staged = `${configPath}.tmp-${crypto.randomUUID()}`;
  let handle;
  let published = false;
  try {
    handle = await fsp.open(staged,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY
        | (fs.constants.O_NOFOLLOW || 0), 0o600);
    await handle.writeFile(contents, "utf8");
    await handle.sync();
    const opened = await handle.stat({ bigint: true });
    const named = fs.lstatSync(staged, { bigint: true });
    if (!opened.isFile() || !named.isFile() || named.isSymbolicLink()
      || opened.nlink !== 1n || named.nlink !== 1n
      || opened.dev !== named.dev || opened.ino !== named.ino
      || (process.platform !== "win32"
        && (opened.uid !== BigInt(process.getuid()) || (opened.mode & 0o077n) !== 0n))) {
      throw new Error("SYNC_CONFIG_UNSAFE_TEMP");
    }
    await handle.close();
    handle = null;
    assertPrivateSqliteAuthorityDirectory(configPath);
    if (process.platform === "win32") {
      require("../services/chunkUploadWindowsAcl").verifyWindowsAuthorityFilePath(staged);
    }
    const beforePublish = inspectExistingConfig(configPath);
    if (existing ? !equalIdentity(existing, beforePublish) : beforePublish !== null) {
      throw new Error("SYNC_CONFIG_CHANGED_DURING_WRITE");
    }
    const tempAfter = fs.lstatSync(staged, { bigint: true });
    if (!tempAfter.isFile() || tempAfter.isSymbolicLink() || tempAfter.nlink !== 1n
      || tempAfter.dev !== opened.dev || tempAfter.ino !== opened.ino) {
      throw new Error("SYNC_CONFIG_TEMP_CHANGED");
    }
    if (existing) {
      // The containing directory is private and the old inode was verified
      // immediately above; no untrusted principal can exchange that name.
      await fsp.rename(staged, configPath);
    } else {
      // Hard-link publication is exclusive on both POSIX and NTFS: unlike
      // rename, it cannot overwrite a file created after our last lstat.
      await fsp.link(staged, configPath);
      // Drop the staging link before validating the final single-link file.
      await fsp.unlink(staged);
    }
    published = true;
    inspectExistingConfig(configPath);
  } finally {
    if (handle) await handle.close();
    try { await fsp.unlink(staged); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  if (!published) throw new Error("SYNC_CONFIG_NOT_PUBLISHED");
}

module.exports = { writePrivateSyncConfig, readPrivateSyncConfig,
  preparePrivateSyncConfigPath };
