const fs = require("fs");
const path = require("path");
const crypto = require("node:crypto");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { acquireJsonMutationLock } = require("../repositories/backupRepository");

const POLICY_PATH = resolveRuntimePath("data", ".rootark-restore-provider-orphans.json");
const STATE_PATH = resolveRuntimePath("data", ".rootark-restore-provider-orphans-state.json");
let suppressionSnapshot = null;
const renameRetryWait = new Int32Array(new SharedArrayBuffer(4));

async function acquirePolicyLock() {
  const deadline = Date.now() + 10_000;
  while (true) {
    try { return acquireJsonMutationLock("restore-provider-orphans"); }
    catch (error) {
      if (error.code !== "BACKUP_METADATA_LOCK_BUSY" || error.reason === "runtime-root-mismatch" || Date.now() >= deadline) throw error;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

function identityKey(area, folderId, name) {
  return `${area}\0${String(folderId)}\0${String(name)}`;
}

function assertUnambiguousProviderInventory(objects) {
  if (process.platform !== "win32") return true;
  const identities = new Map();
  for (const entry of normalizeObjects(objects)) {
    const exact = identityKey(entry.area, entry.folderId, entry.name);
    const folded = exact.toLowerCase();
    const previous = identities.get(folded);
    if (previous !== undefined && previous !== exact) {
      throw new Error("Cloud provider inventory contains case-colliding paths; restore is blocked on Windows");
    }
    identities.set(folded, exact);
  }
  return true;
}

function normalizeObjects(objects) {
  if (!Array.isArray(objects)) throw new Error("Restore provider suppression policy is invalid");
  const unique = new Map();
  for (const value of objects) {
    const area = String(value?.area || "");
    const folderId = String(value?.folderId || "");
    const name = String(value?.name || "");
    if (!(["uploads", "temp"].includes(area)) || !folderId || folderId === "." || folderId === ".." || /[\\/\u0000-\u001f\u007f]/.test(folderId)
      || !name || name === "." || name === ".." || path.basename(name) !== name || /[\\/\u0000-\u001f\u007f]/.test(name)) {
      throw new Error("Restore provider suppression policy contains an invalid object");
    }
    unique.set(identityKey(area, folderId, name), { area, folderId, name });
  }
  return [...unique.values()].sort((left, right) => left.area.localeCompare(right.area) || left.folderId.localeCompare(right.folderId) || left.name.localeCompare(right.name));
}

function validateInventoryMarker(marker, label) {
  if (marker === undefined) return null;
  if (!marker || typeof marker !== "object" || !["known", "unknown", "reconciled"].includes(marker.state)
    || (marker.backupId != null && !/^[a-f0-9-]{36}$/i.test(String(marker.backupId)))
    || (marker.inventoryContext != null && !/^[a-f0-9]{64}$/i.test(String(marker.inventoryContext)))
    || (marker.previousInventoryContext != null && !/^[a-f0-9]{64}$/i.test(String(marker.previousInventoryContext)))) {
    throw new Error(`${label} is invalid; provider access is blocked`);
  }
  if (marker.state === "reconciled" && (!marker.backupId || typeof marker.reconciledAt !== "string")) {
    throw new Error(`${label} is invalid; provider access is blocked`);
  }
  return marker;
}

function readState() {
  let text;
  try { text = readControlFile(STATE_PATH, "Restore provider suppression state"); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
  let value;
  try { value = JSON.parse(text); }
  catch { throw new Error("Restore provider suppression state is invalid; file access is blocked"); }
  if (value?.version !== 1) throw new Error("Restore provider suppression state version is unsupported; file access is blocked");
  validateInventoryMarker(value.providerInventory, "Restore provider inventory state");
  return value;
}

function readPolicyDocument() {
  let text;
  try { text = readControlFile(POLICY_PATH, "Restore provider suppression policy"); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
  let value;
  try { value = JSON.parse(text); }
  catch { throw new Error("Restore provider suppression policy is invalid; file access is blocked"); }
  if (value?.version !== 1) throw new Error("Restore provider suppression policy version is unsupported; file access is blocked");
  validateInventoryMarker(value.providerInventory, "Restore provider inventory policy");
  return {
    ...value,
    objects: normalizeObjects(value.objects),
    pendingRestoreUploads: value.pendingRestoreUploads === undefined
      ? []
      : normalizeObjects(value.pendingRestoreUploads),
  };
}

function sameControlFileSnapshot(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode
    && left.nlink === right.nlink && left.size === right.size
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs;
}

function readControlFile(filePath, label) {
  let descriptor;
  try {
    let flags = fs.constants.O_RDONLY;
    if (typeof fs.constants.O_NOFOLLOW === "number") flags |= fs.constants.O_NOFOLLOW;
    if (typeof fs.constants.O_NONBLOCK === "number") flags |= fs.constants.O_NONBLOCK;
    descriptor = fs.openSync(filePath, flags);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || opened.nlink !== 1n) {
      throw Object.assign(new Error(label + " is unsafe; file access is blocked"), { code: "CONTROL_FILE_UNSAFE" });
    }

    const text = fs.readFileSync(descriptor, "utf8");
    const afterRead = fs.fstatSync(descriptor, { bigint: true });
    fs.closeSync(descriptor);
    descriptor = undefined;
    const currentPath = fs.lstatSync(filePath, { bigint: true });
    if (!currentPath.isFile() || currentPath.isSymbolicLink()
      || !sameControlFileSnapshot(opened, afterRead) || !sameControlFileSnapshot(opened, currentPath)) {
      throw Object.assign(new Error(label + " changed while being read; file access is blocked"), { code: "CONTROL_FILE_CHANGED" });
    }
    return text;
  } catch (error) {
    if (["ENOENT", "CONTROL_FILE_UNSAFE", "CONTROL_FILE_CHANGED"].includes(error.code)) throw error;
    throw Object.assign(new Error(label + " is invalid; file access is blocked"), { code: "CONTROL_FILE_INVALID", cause: error });
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

function policyFileExists() {
  try { fs.lstatSync(POLICY_PATH); return true; }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

function readPolicyState() {
  const state = readState();
  const policy = readPolicyDocument();
  if (!policy && state) throw new Error("Restore provider suppression policy is missing; file access is blocked");
  return { state, policy };
}

function markerForStatus(status) {
  if (status.state === "unknown") return {
    state: "unknown",
    ...(status.backupId ? { backupId: status.backupId } : {}),
    ...(status.inventoryContext ? { inventoryContext: status.inventoryContext } : {}),
    ...(status.previousInventoryContext ? { previousInventoryContext: status.previousInventoryContext } : {}),
  };
  if (status.state === "reconciled") return { state: "reconciled", backupId: status.backupId, reconciledAt: status.reconciledAt || new Date().toISOString(), ...(status.inventoryContext ? { inventoryContext: status.inventoryContext } : {}) };
  return { state: "known" };
}

function writeJsonAtomically(destination, value) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const temporary = `${destination}.${crypto.randomUUID()}.tmp`;
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value, null, 2)}\n`);
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  try {
    renameWithSharingRetry(temporary, destination);
    if (process.platform !== "win32") {
      const directory = fs.openSync(path.dirname(destination), "r");
      try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
    }
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function renameWithSharingRetry(source, destination) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      fs.renameSync(source, destination);
      return;
    } catch (error) {
      const retryable = process.platform === "win32" && ["EACCES", "EBUSY", "EPERM"].includes(error.code);
      if (!retryable || attempt >= 9) throw error;
      Atomics.wait(renameRetryWait, 0, 0, 10);
    }
  }
}

function getInventoryStatus(provider = null) {
  const state = readState();
  const policy = readPolicyDocument();
  if (!state && !policy) return { state: "known" };
  const stateMarker = validateInventoryMarker(state?.providerInventory, "Restore provider inventory state");
  const policyMarker = validateInventoryMarker(policy?.providerInventory, "Restore provider inventory policy");
  if (stateMarker && policyMarker
    && (stateMarker.inventoryContext !== policyMarker.inventoryContext
      || stateMarker.previousInventoryContext !== policyMarker.previousInventoryContext)) {
    return {
      state: "unknown",
      backupId: stateMarker.backupId === policyMarker.backupId ? stateMarker.backupId || null : null,
      contextConflict: true,
    };
  }
  if (!state || !policy || !stateMarker || !policyMarker) {
    const unknown = [stateMarker, policyMarker].filter((marker) => marker?.state === "unknown");
    const ids = new Set(unknown.map((marker) => marker.backupId).filter(Boolean));
    const marker = unknown.find((value) => value.inventoryContext || value.previousInventoryContext) || {};
    return { state: "unknown", backupId: ids.size === 1 ? [...ids][0] : null,
      ...(marker.inventoryContext ? { inventoryContext: marker.inventoryContext } : {}),
      ...(marker.previousInventoryContext ? { previousInventoryContext: marker.previousInventoryContext } : {}) };
  }
  if (stateMarker.state === policyMarker.state && stateMarker.backupId === policyMarker.backupId) {
    if (stateMarker.state === "unknown") return { state: "unknown", backupId: stateMarker.backupId || null,
      ...(stateMarker.inventoryContext ? { inventoryContext: stateMarker.inventoryContext } : {}),
      ...(stateMarker.previousInventoryContext ? { previousInventoryContext: stateMarker.previousInventoryContext } : {}) };
    if (stateMarker.state === "reconciled") {
      if (stateMarker.inventoryContext !== policyMarker.inventoryContext) return {
        state: "unknown", backupId: stateMarker.backupId,
        previousInventoryContext: stateMarker.inventoryContext || undefined,
      };
      const context = typeof provider?.inventoryContext === "function" ? provider.inventoryContext() : null;
      if (context && (stateMarker.inventoryContext !== context || policyMarker.inventoryContext !== context)) {
        return { state: "unknown", backupId: stateMarker.backupId, inventoryContext: context,
          previousInventoryContext: stateMarker.inventoryContext || undefined };
      }
      return { state: "reconciled", backupId: stateMarker.backupId, reconciledAt: stateMarker.reconciledAt,
        ...(stateMarker.inventoryContext ? { inventoryContext: stateMarker.inventoryContext } : {}) };
    }
    return { state: "known" };
  }
  const unknown = [stateMarker, policyMarker].filter((marker) => marker.state === "unknown");
  const ids = new Set(unknown.map((marker) => marker.backupId).filter(Boolean));
  const marker = unknown.find((value) => value.inventoryContext || value.previousInventoryContext) || {};
  return { state: "unknown", backupId: ids.size === 1 ? [...ids][0] : null,
    ...(marker.inventoryContext ? { inventoryContext: marker.inventoryContext } : {}),
    ...(marker.previousInventoryContext ? { previousInventoryContext: marker.previousInventoryContext } : {}) };
}

function writeState(marker) {
  const current = readState() || {};
  writeJsonAtomically(STATE_PATH, {
    ...current,
    version: 1,
    initializedAt: current.initializedAt || new Date().toISOString(),
    providerInventory: marker,
  });
}

function isInventoryUnknown(provider = null) {
  return getInventoryStatus(provider).state === "unknown";
}

function assertProviderAvailable(provider = null) {
  if (isInventoryUnknown(provider)) {
    throw Object.assign(new Error("Cloud provider inventory is unknown after restore; reconciliation is required"), { code: "PROVIDER_INVENTORY_UNKNOWN" });
  }
}

function guardProvider(provider) {
  if (!provider || typeof provider !== "object") return provider;
  const guarded = Object.create(provider);
  for (const operation of ["inventory", "list", "download", "upload", "remove", "removePrefix", "resolveUploadId"]) {
    if (typeof provider[operation] !== "function") continue;
    guarded[operation] = async (...args) => {
      if (provider.provider === "local" && typeof provider.enabled === "function" && provider.enabled() === false) {
        return provider[operation](...args);
      }
      if (getInventoryStatus().state === "unknown") assertProviderAvailable();
      if (operation === "download" && isRestoreUploadPending(args[0], args[1], args[3] || "uploads")) {
        throw Object.assign(new Error("Selected restore bytes are still pending provider reconciliation"), {
          code: "PROVIDER_RESTORE_SYNC_PENDING",
        });
      }
      if (typeof provider.resolveInventoryContext === "function") await provider.resolveInventoryContext();
      assertProviderAvailable(provider);
      const result = await provider[operation](...args);
      if (typeof provider.resolveInventoryContext === "function") {
        await provider.resolveInventoryContext();
        assertProviderAvailable(provider);
      }
      return result;
    };
  }
  return guarded;
}

async function markInventoryUnknown(backupId, context = {}, options = {}) {
  const id = String(backupId || "");
  if (!/^[a-f0-9-]{36}$/i.test(id)) throw new Error("Restore provider inventory baseline is invalid");
  const lease = await acquirePolicyLock();
  try {
    if (typeof options.validateBaseline === "function") await options.validateBaseline(id);
    const policy = readPolicyDocument();
    writeUnlocked(policy?.objects || [], { state: "unknown", backupId: id,
      ...(context.inventoryContext ? { inventoryContext: context.inventoryContext } : {}),
      ...(context.previousInventoryContext ? { previousInventoryContext: context.previousInventoryContext } : {}) });
  } finally { lease.release(); }
}

async function reconcileInventory(backupId, objects, inventoryContext = null, pendingRestoreUploads) {
  const id = String(backupId || "");
  if (!/^[a-f0-9-]{36}$/i.test(id)) throw new Error("Restore provider inventory baseline is invalid");
  const normalized = normalizeObjects(objects);
  const lease = await acquirePolicyLock();
  try {
    const status = getInventoryStatus();
    if (status.contextConflict) {
      throw new Error("Restore provider inventory context records are inconsistent during reconciliation");
    }
    if (status.state === "reconciled" && status.backupId === id) {
      if ((status.inventoryContext ?? null) !== (inventoryContext ?? null)) {
        throw new Error("Restore provider inventory context changed during reconciliation");
      }
      return read();
    }
    if (status.state !== "unknown" || (status.backupId && status.backupId !== id)) {
      throw new Error("Restore provider inventory baseline changed during reconciliation");
    }
    if (status.inventoryContext && status.inventoryContext !== inventoryContext) {
      throw new Error("Restore provider inventory context changed during reconciliation");
    }
    writeUnlocked(normalized, { state: "reconciled", backupId: id, reconciledAt: new Date().toISOString(), inventoryContext }, pendingRestoreUploads);
    return normalized;
  } finally { lease.release(); }
}

async function setPendingRestoreUploads(objects) {
  const normalized = normalizeObjects(objects);
  const lease = await acquirePolicyLock();
  try {
    const policy = readPolicyDocument();
    const status = getInventoryStatus();
    if (status.contextConflict) {
      throw new Error("Restore provider inventory context records are inconsistent while updating restore download fences");
    }
    if (JSON.stringify(policy?.pendingRestoreUploads || []) === JSON.stringify(normalized)) return normalized;
    if (!policy && normalized.length === 0) return normalized;
    writeUnlocked(policy?.objects || [], status, normalized);
    return normalized;
  } finally { lease.release(); }
}

function read() {
  return readPolicyState().policy?.objects || [];
}

function policySignature() {
  if (readState() && !policyFileExists()) throw new Error("Restore provider suppression policy is missing; file access is blocked");
  try {
    const stat = fs.statSync(POLICY_PATH, { bigint: true });
    return [stat.dev, stat.ino, stat.size, stat.mtimeNs, stat.ctimeNs].map(String).join(":");
  } catch (error) {
    if (error.code === "ENOENT") return "missing";
    throw error;
  }
}

function readSuppressionSnapshot() {
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const before = policySignature();
    if (suppressionSnapshot?.signature === before) return suppressionSnapshot;
    const { policy } = readPolicyState();
    const after = policySignature();
    if (before === after) {
      const entries = policy?.objects || [];
      const keys = new Set(entries.map((entry) => identityKey(entry.area, entry.folderId, entry.name)));
      const pendingRestoreUploads = new Set((policy?.pendingRestoreUploads || [])
        .map((entry) => identityKey(entry.area, entry.folderId, entry.name)));
      suppressionSnapshot = {
        signature: after,
        keys,
        foldedKeys: process.platform === "win32" ? new Set([...keys].map((key) => key.toLowerCase())) : null,
        pendingRestoreUploads,
        foldedPendingRestoreUploads: process.platform === "win32"
          ? new Set([...pendingRestoreUploads].map((key) => key.toLowerCase()))
          : null,
      };
      return suppressionSnapshot;
    }
  }
  throw new Error("Restore provider suppression policy changed repeatedly; file access is blocked");
}

function writeUnlocked(objects, inventoryStatus = getInventoryStatus(), pendingRestoreUploads) {
  const normalized = normalizeObjects(objects);
  const currentPolicy = readPolicyDocument();
  const pendingUploads = pendingRestoreUploads === undefined
    ? currentPolicy?.pendingRestoreUploads || []
    : normalizeObjects(pendingRestoreUploads);
  if (inventoryStatus.state === "reconciled" && !inventoryStatus.inventoryContext) {
    inventoryStatus = { ...inventoryStatus, inventoryContext: currentPolicy?.providerInventory?.inventoryContext };
  }
  const marker = markerForStatus(inventoryStatus);
  writeJsonAtomically(POLICY_PATH, {
    version: 1,
    objects: normalized,
    pendingRestoreUploads: pendingUploads,
    providerInventory: marker,
  });
  suppressionSnapshot = null;
  writeState(marker);
  return normalized;
}

function initialize({ requirePolicy = false } = {}) {
  const state = readState();
  const policy = readPolicyDocument();
  if (state && !policy) throw new Error("Restore provider suppression policy is missing; startup is blocked for recovery");
  if (!policy && requirePolicy) throw new Error("Restore provider suppression policy is missing after cloud restore; startup is blocked for recovery");
  const status = getInventoryStatus();
  if (!state && !policy) writeUnlocked([], { state: "known" });
  else writeUnlocked(policy?.objects || [], status);
  suppressionSnapshot = null;
  return read();
}

async function write(objects, inventoryStatus, pendingRestoreUploads) {
  const lease = await acquirePolicyLock();
  try {
    const status = inventoryStatus === undefined ? getInventoryStatus() : inventoryStatus;
    if (status.contextConflict) throw new Error("Restore provider inventory context records are inconsistent; explicit repair is required");
    return writeUnlocked(objects, status, pendingRestoreUploads);
  }
  finally { lease.release(); }
}

function createSnapshot() {
  const current = readSuppressionSnapshot();
  const keys = new Set(current.keys);
  const foldedKeys = current.foldedKeys ? new Set(current.foldedKeys) : null;
  return Object.freeze({
    assertCurrent() {
      if (policySignature() !== current.signature) {
        throw new Error("Restore provider suppression policy changed during backup");
      }
    },
    isSuppressed(folderId, fileName, area = "uploads") {
      const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
      return keys.has(key) || Boolean(foldedKeys?.has(key.toLowerCase()));
    },
  });
}

async function lockSnapshot(snapshot) {
  const lease = await acquirePolicyLock();
  try {
    if (typeof snapshot?.assertCurrent !== "function") throw new Error("Restore provider suppression snapshot is invalid");
    snapshot.assertCurrent();
    const release = () => lease.release();
    release.mutationLease = lease;
    return release;
  } catch (error) {
    lease.release();
    throw error;
  }
}

function isSuppressed(folderId, fileName, area = "uploads", snapshot = null) {
  if (typeof snapshot?.isSuppressed === "function") return snapshot.isSuppressed(folderId, fileName, area);
  const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
  const current = readSuppressionSnapshot();
  return current.keys.has(key) || Boolean(current.foldedKeys?.has(key.toLowerCase()));
}

function isRestoreUploadPending(folderId, fileName, area = "uploads") {
  const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
  const current = readSuppressionSnapshot();
  return current.pendingRestoreUploads.has(key)
    || Boolean(current.foldedPendingRestoreUploads?.has(key.toLowerCase()));
}

async function assertSafeToUnhide(provider) {
  if (process.platform !== "win32") return true;
  if (typeof provider?.inventory !== "function") {
    throw Object.assign(new Error("Provider inventory is required before un-hiding restored files on Windows"), { code: "configuration" });
  }
  const inventory = await provider.inventory();
  try {
    assertUnambiguousProviderInventory(inventory
      .filter((entry) => ["uploads", "temp"].includes(entry.area))
      .map(({ area, folderId, name }) => ({ area, folderId, name })));
  } catch {
    throw Object.assign(new Error("Case-colliding provider objects keep restored files suppressed on Windows"), { code: "configuration" });
  }
  return true;
}

async function suppress(folderId, fileName, area = "uploads") {
  const entry = normalizeObjects([{ area, folderId: String(folderId || "root"), name: String(fileName || "") }])[0];
  const key = identityKey(entry.area, entry.folderId, entry.name);
  const lease = await acquirePolicyLock();
  try {
    const current = read();
    if (current.some((value) => identityKey(value.area, value.folderId, value.name) === key)) return false;
    writeUnlocked([...current, entry]);
    return true;
  } finally { lease.release(); }
}

async function clear(folderId, fileName, area = "uploads", provider = null) {
  const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
  try {
    if (!read().some((entry) => identityKey(entry.area, entry.folderId, entry.name) === key)) return false;
  } catch (error) {
    if (error.code !== "CONTROL_FILE_CHANGED") throw error;
  }
  await assertSafeToUnhide(provider);
  const lease = await acquirePolicyLock();
  try {
    const objects = read();
    if (!objects.some((entry) => identityKey(entry.area, entry.folderId, entry.name) === key)) return false;
    writeUnlocked(objects.filter((entry) => identityKey(entry.area, entry.folderId, entry.name) !== key), getInventoryStatus());
    return true;
  } finally { lease.release(); }
}

module.exports = { POLICY_PATH, STATE_PATH, acquireInventoryLock: acquirePolicyLock, assertProviderAvailable, assertSafeToUnhide, assertUnambiguousProviderInventory, clear, createSnapshot, getInventoryStatus, guardProvider, identityKey, initialize, isInventoryUnknown, isSuppressed, isRestoreUploadPending, lockSnapshot, markInventoryUnknown, normalizeObjects, read, reconcileInventory, setPendingRestoreUploads, suppress, write };
