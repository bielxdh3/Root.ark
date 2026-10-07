const fs = require("fs");
const path = require("path");
const crypto = require("node:crypto");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { acquireJsonMutationLock } = require("../repositories/backupRepository");

const POLICY_PATH = resolveRuntimePath("data", ".rootark-restore-provider-orphans.json");
const STATE_PATH = resolveRuntimePath("data", ".rootark-restore-provider-orphans-state.json");
let suppressionSnapshot = null;

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

function readState() {
  let stat;
  try { stat = fs.lstatSync(STATE_PATH); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
  if (stat.isSymbolicLink() || !stat.isFile()) throw new Error("Restore provider suppression state is unsafe; file access is blocked");
  let value;
  try { value = JSON.parse(fs.readFileSync(STATE_PATH, "utf8")); }
  catch { throw new Error("Restore provider suppression state is invalid; file access is blocked"); }
  if (value?.version !== 1) throw new Error("Restore provider suppression state version is unsupported; file access is blocked");
  return value;
}

function policyFileExists() {
  try { fs.lstatSync(POLICY_PATH); return true; }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
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
    fs.renameSync(temporary, destination);
    if (process.platform !== "win32") {
      const directory = fs.openSync(path.dirname(destination), "r");
      try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
    }
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function writeState() {
  writeJsonAtomically(STATE_PATH, { version: 1, initializedAt: new Date().toISOString() });
}

function read() {
  const state = readState();
  let text;
  try { text = fs.readFileSync(POLICY_PATH, "utf8"); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    if (state) throw new Error("Restore provider suppression policy is missing; file access is blocked");
    return [];
  }
  let value;
  try { value = JSON.parse(text); }
  catch { throw new Error("Restore provider suppression policy is invalid; file access is blocked"); }
  if (value?.version !== 1) throw new Error("Restore provider suppression policy version is unsupported; file access is blocked");
  return normalizeObjects(value.objects);
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
    const entries = read();
    const after = policySignature();
    if (before === after) {
      const keys = new Set(entries.map((entry) => identityKey(entry.area, entry.folderId, entry.name)));
      suppressionSnapshot = {
        signature: after,
        keys,
        foldedKeys: process.platform === "win32" ? new Set([...keys].map((key) => key.toLowerCase())) : null,
      };
      return suppressionSnapshot;
    }
  }
  throw new Error("Restore provider suppression policy changed repeatedly; file access is blocked");
}

function writeUnlocked(objects) {
  const normalized = normalizeObjects(objects);
  const state = readState();
  if (state && !policyFileExists()) throw new Error("Restore provider suppression policy is missing; file access is blocked");
  writeJsonAtomically(POLICY_PATH, { version: 1, objects: normalized });
  suppressionSnapshot = null;
  if (!state) writeState();
  return normalized;
}

function initialize({ requirePolicy = false } = {}) {
  const state = readState();
  const hasPolicy = policyFileExists();
  if (state && !hasPolicy) throw new Error("Restore provider suppression policy is missing; startup is blocked for recovery");
  if (!hasPolicy && requirePolicy) throw new Error("Restore provider suppression policy is missing after cloud restore; startup is blocked for recovery");
  if (!hasPolicy) writeUnlocked([]);
  else {
    read();
    if (!state) writeState();
  }
  suppressionSnapshot = null;
  return read();
}

async function write(objects) {
  const lease = await acquirePolicyLock();
  try { return writeUnlocked(objects); }
  finally { lease.release(); }
}

function isSuppressed(folderId, fileName, area = "uploads") {
  const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
  const snapshot = readSuppressionSnapshot();
  return snapshot.keys.has(key) || Boolean(snapshot.foldedKeys?.has(key.toLowerCase()));
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
  if (!read().some((entry) => identityKey(entry.area, entry.folderId, entry.name) === key)) return false;
  await assertSafeToUnhide(provider);
  const lease = await acquirePolicyLock();
  try {
    const current = read();
    if (!current.some((entry) => identityKey(entry.area, entry.folderId, entry.name) === key)) return false;
    writeUnlocked(current.filter((entry) => identityKey(entry.area, entry.folderId, entry.name) !== key));
    return true;
  } finally { lease.release(); }
}

module.exports = { POLICY_PATH, STATE_PATH, assertSafeToUnhide, assertUnambiguousProviderInventory, clear, identityKey, initialize, isSuppressed, normalizeObjects, read, suppress, write };
