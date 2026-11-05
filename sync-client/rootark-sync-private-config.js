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

async function writePrivateSyncConfig(filename, contents) {
  const configPath = path.resolve(filename);
  // An existing private parent needs only the authority check; avoid scanning
  // unrelated sibling files. Missing parents are created one level at a time
  // with protected permissions before writing any credential bytes.
  try { fs.lstatSync(path.dirname(configPath)); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    ensurePrivateSqliteDirectory(configPath);
  }
  assertPrivateSqliteAuthorityDirectory(configPath);
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

module.exports = { writePrivateSyncConfig };
