const fs = require("fs");
const path = require("path");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { acquireJsonMutationLock } = require("../repositories/backupRepository");

const POLICY_PATH = resolveRuntimePath("data", ".rootark-restore-provider-orphans.json");
const LOCK_WAIT = new Int32Array(new SharedArrayBuffer(4));

function acquirePolicyLock() {
  const deadline = Date.now() + 10_000;
  while (true) {
    try { return acquireJsonMutationLock("restore-provider-orphans"); }
    catch (error) {
      if (error.code !== "BACKUP_METADATA_LOCK_BUSY" || error.reason === "runtime-root-mismatch" || Date.now() >= deadline) throw error;
      Atomics.wait(LOCK_WAIT, 0, 0, 10);
    }
  }
}

function identityKey(area, folderId, name) {
  const normalizePathPart = (value) => process.platform === "win32" ? String(value).toLowerCase() : String(value);
  return `${area}\0${normalizePathPart(folderId)}\0${normalizePathPart(name)}`;
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

function write(objects) {
  const lease = acquirePolicyLock();
  try { return writeUnlocked(objects); }
  finally { lease.release(); }
}

function isSuppressed(folderId, fileName, area = "uploads") {
  const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
  return read().some((entry) => identityKey(entry.area, entry.folderId, entry.name) === key);
}

function clear(folderId, fileName, area = "uploads") {
  const key = identityKey(area, String(folderId || "root"), String(fileName || ""));
  const lease = acquirePolicyLock();
  try {
    const current = read();
    if (!current.some((entry) => identityKey(entry.area, entry.folderId, entry.name) === key)) return false;
    writeUnlocked(current.filter((entry) => identityKey(entry.area, entry.folderId, entry.name) !== key));
    return true;
  } finally { lease.release(); }
}

module.exports = { POLICY_PATH, clear, identityKey, isSuppressed, normalizeObjects, read, write };
