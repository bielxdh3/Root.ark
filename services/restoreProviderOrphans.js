const fs = require("fs");
const path = require("path");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { acquireJsonMutationLock } = require("../repositories/backupRepository");

const POLICY_PATH = resolveRuntimePath("data", ".rootark-restore-provider-orphans.json");
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

function read() {
  let text;
  try { text = fs.readFileSync(POLICY_PATH, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return []; throw error; }
  let value;
  try { value = JSON.parse(text); }
  catch { throw new Error("Restore provider suppression policy is invalid; file access is blocked"); }
  if (value?.version !== 1) throw new Error("Restore provider suppression policy version is unsupported; file access is blocked");
  return normalizeObjects(value.objects);
}

function policySignature() {
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
  fs.mkdirSync(path.dirname(POLICY_PATH), { recursive: true });
  const temporary = `${POLICY_PATH}.${require("node:crypto").randomUUID()}.tmp`;
  const descriptor = fs.openSync(temporary, "wx", 0o600);
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify({ version: 1, objects: normalized }, null, 2)}\n`);
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  try {
    fs.renameSync(temporary, POLICY_PATH);
    suppressionSnapshot = null;
    if (process.platform !== "win32") {
      const directory = fs.openSync(path.dirname(POLICY_PATH), "r");
      try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
    }
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
  return normalized;
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

module.exports = { POLICY_PATH, assertSafeToUnhide, assertUnambiguousProviderInventory, clear, identityKey, isSuppressed, normalizeObjects, read, suppress, write };
