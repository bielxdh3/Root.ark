"use strict";

const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { readPrivateSyncConfig, writePrivateSyncConfig } =
  require("./rootark-sync-private-config");
const { normalizeTrustedSyncServerUrl } =
  require("./rootark-sync-transport-policy");

const LEGACY_STATE_NAME = ".rootark-sync-state.json";
const MAX_STATE_BYTES = 16 * 1024 * 1024;
const MAX_HISTORICAL_INSPECTION_BYTES = 1024 * 1024;
const STATE_VERSION = 1;
// Different protected --config files can describe the very same remote
// authority. Keeping state/lock beside each config would create independent
// caches and locks, allowing concurrent stale remote writes. Use one
// owner-private home shared by every config for this operating-system user.
// `os.homedir()` may honor HOME/USERPROFILE overrides and split a lock across
// invocations. The platform account database home is invariant under those
// caller-controlled environment overrides for this OS principal.
const STATE_HOME = path.join(os.userInfo().homedir, ".rootark", "sync", "private-state");

function privateSyncStateBinding(config) {
  // The legacy API uploads basename(relativePath) into the account's remote
  // folder; neither localFolder, deviceId nor keyEpoch is sent as a remote
  // mutation discriminator. Binding the lock/cache to those local-only
  // fields would let two distinct --config invocations race the SAME remote
  // file and publish contradictory acknowledged hashes. Share one private
  // state per actual server+account+target folder authority instead.
  const identity = JSON.stringify({
    serverUrl: normalizeTrustedSyncServerUrl(config.serverUrl),
    targetFolderId: String(config.targetFolderId || "root"),
    username: String(config.username || ""),
  });
  const digest = crypto.createHash("sha256").update(identity).digest("hex");
  return digest;
}

function privateSyncStatePath(configPath, config) {
  const digest = privateSyncStateBinding(config);
  return path.join(STATE_HOME, `.rootark-sync-state-${digest}.json`);
}

function assertStateSeparateFromConfig(configPath, config) {
  const configAbsolute = path.resolve(configPath);
  const stateAbsolute = privateSyncStatePath(configPath, config);
  const match = process.platform === "win32"
    ? configAbsolute.toLowerCase() === stateAbsolute.toLowerCase()
    : configAbsolute === stateAbsolute;
  if (match) throw new Error("SYNC_STATE_CONFIG_PATH_COLLISION");
  return stateAbsolute;
}

function validatedState(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !value.files || typeof value.files !== "object" || Array.isArray(value.files)) {
    throw new Error("SYNC_STATE_INVALID");
  }
  // File keys are local paths, not permissions. Fail closed instead of
  // adopting corrupt/private-state bytes as uploaded acknowledgements.
  const safeFiles = Object.create(null);
  for (const [name, entry] of Object.entries(value.files)) {
    if (!name || name.length > 4096 || !entry || typeof entry !== "object"
      || Array.isArray(entry) || !["uploaded", "failed"].includes(entry.lastStatus)
      || !Number.isFinite(entry.size) || entry.size < 0
      || !Number.isFinite(entry.mtimeMs)) throw new Error("SYNC_STATE_INVALID");
    // `__proto__` is a valid user filename; ordinary objects would mutate
    // their prototype instead of recording its upload status as an own key.
    safeFiles[name] = entry;
  }
  // The legacy uploader uses basename(relativePath) for the remote object.
  // A cache shared by multiple source folders therefore needs a durable,
  // private provenance claim for each remote basename. A pre-existing v1
  // cache has no trusted source-root provenance: retain those old entries,
  // but never invent authority for them while reading.
  const rawOwners = value.remoteBasenameOwners;
  if (rawOwners !== undefined && (!rawOwners || typeof rawOwners !== "object"
    || Array.isArray(rawOwners))) throw new Error("SYNC_STATE_INVALID_BASENAME_OWNERS");
  const remoteBasenameOwners = Object.create(null);
  for (const [basename, owner] of Object.entries(rawOwners || {})) {
    if (!basename || basename.length > 4096 || basename !== basename.normalize("NFC").toLowerCase()
      || basename.includes("/") || basename.includes("\\")
      || !owner || typeof owner !== "object" || Array.isArray(owner)
      || typeof owner.localFolder !== "string" || !path.isAbsolute(owner.localFolder)
      || owner.localFolder.length > 4096
      || typeof owner.relativePath !== "string" || !owner.relativePath
      || owner.relativePath.length > 4096 || path.isAbsolute(owner.relativePath)) {
      throw new Error("SYNC_STATE_INVALID_BASENAME_OWNER");
    }
    remoteBasenameOwners[basename] = {
      localFolder: owner.localFolder, relativePath: owner.relativePath,
    };
  }
  return { files: safeFiles, remoteBasenameOwners };
}

async function readPrivateSyncState(statePath, config) {
  const existing = await readPrivateSyncConfig(statePath, null,
    { maxBytes: MAX_STATE_BYTES });
  if (existing === null) return {
    files: Object.create(null), remoteBasenameOwners: Object.create(null),
  };
  if (existing.version !== STATE_VERSION || existing.binding !== privateSyncStateBinding(config)) {
    throw new Error("SYNC_STATE_BINDING_MISMATCH");
  }
  return validatedState(existing);
}

async function writePrivateSyncState(statePath, state, config) {
  const validated = validatedState(state);
  const content = `${JSON.stringify({
    version: STATE_VERSION, binding: privateSyncStateBinding(config),
    files: validated.files, remoteBasenameOwners: validated.remoteBasenameOwners,
  }, null, 2)}\n`;
  if (Buffer.byteLength(content, "utf8") > MAX_STATE_BYTES) {
    throw new Error("SYNC_STATE_TOO_LARGE");
  }
  await writePrivateSyncConfig(statePath, content);
}

// Old `.rootark-sync-state.json` files were writable by anyone able to write
// the selected source folder. Importing `lastStatus:uploaded` would let a
// forged historical cache silently suppress an actual upload. Never import
// it as authority. Preserve the original bytes on disk for manual recovery.
// This metadata-only inspection never opens the historical path, preventing
// any race between a pathname check and an open. No untrusted bytes are read.
async function inspectHistoricalSyncState(localFolder) {
  const filename = path.join(path.resolve(localFolder), LEGACY_STATE_NAME);
  try {
    const named = await fsp.lstat(filename);
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1) {
      return { present: true, status: "unsafe" };
    }
    if (named.size > MAX_HISTORICAL_INSPECTION_BYTES) {
      return { present: true, status: "oversized" };
    }
    // Classification is advisory only. Never import `uploaded` markers or
    // acquire an FD: another principal may change this shared-folder entry
    // at any moment without affecting trusted state.
    return { present: true, status: "preserved" };
  } catch (error) {
    if (error.code === "ENOENT") return { present: false };
    return { present: true, status: "unreadable" };
  }
}

module.exports = { privateSyncStatePath, assertStateSeparateFromConfig,
  readPrivateSyncState,
  writePrivateSyncState, inspectHistoricalSyncState };
