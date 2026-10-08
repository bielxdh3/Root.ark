const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { resolveRuntimePath } = require("../src/runtime-paths");
const trashRepository = require("../repositories/trashRepository");

const TRASH_STORAGE_DIR = resolveRuntimePath("data", "trash");
const REMOTE_LOCK_DIR = resolveRuntimePath("data", "trash-remote-locks");
const DEFAULT_MAX_REMOTE_ATTEMPTS = 25;
const MAX_REMOTE_BACKOFF_MS = 60 * 60 * 1000;

function getClock(clock) {
  if (typeof clock === "function") return clock;
  if (clock && typeof clock.now === "function") return () => clock.now();
  return () => Date.now();
}

function nowIso(clock) {
  return new Date(getClock(clock)()).toISOString();
}

function remoteState(item) {
  const state = item?.metadata?.remoteDeletion;
  if (!state) return null;
  if (state.state === "failed") return { ...state, state: "retry_wait" };
  return state;
}

function remoteIdentity(item, provider) {
  const folderId = item.originalFolderId || "root";
  if (item.itemType === "folder") {
    return {
      provider,
      kind: "prefix",
      prefixes: [`uploads/${folderId}`, `temp/${folderId}`],
    };
  }
  const objects = [item.originalFileName].filter(Boolean);
  for (const version of item.restoreMetadata?.versions?.versions || []) {
    if (version.storedAs && !objects.includes(version.storedAs)) objects.push(version.storedAs);
  }
  return { provider, kind: "object", folderId, area: "uploads", objects };
}

function failureCategory(error) {
  const code = String(error?.code || "");
  if (["not_found", "NoSuchKey", "notFound"].includes(code) || error?.missing === true) return "missing_object";
  if (["partial_delete", "partial_failure"].includes(code)) return "partial_failure";
  if (["configuration", "invalid_path", "invalid_prefix", "unsupported_provider"].includes(code)) return code;
  return "provider_error";
}

function backoffMs(attempts) {
  return Math.min(MAX_REMOTE_BACKOFF_MS, 1000 * (2 ** Math.max(0, attempts - 1)));
}

function transition(state, next, at, details = {}) {
  return {
    ...state,
    ...details,
    state: next,
    transitions: [...(Array.isArray(state.transitions) ? state.transitions : []), { state: next, at }],
  };
}

function lockFile(operationId) {
  return path.join(REMOTE_LOCK_DIR, `${safeName(operationId)}.lock`);
}

function releaseRemoteClaim(claim) {
  if (!claim?.path) return;
  try {
    const current = fs.readFileSync(claim.path, "utf8");
    if (current === claim.token) fs.rmSync(claim.path, { force: true });
  } catch {
    // A missing lock is already released; never mask the operation result.
  }
}

function claimRemoteDeletion({ item, clock, leaseMs = 60 * 1000, workerId = crypto.randomUUID() }) {
  const current = trashRepository.getTrashItem(item.id) || item;
  const previous = remoteState(current);
  if (!previous || !["pending", "retry_wait"].includes(previous.state)) return null;
  const now = getClock(clock)();
  const nextAt = new Date(previous.nextAttemptAt || 0).getTime();
  if (Number.isFinite(nextAt) && nextAt > now) return null;
  const operationId = previous.operationId || crypto.randomUUID();
  const token = `${workerId}:${crypto.randomUUID()}`;
  const target = lockFile(operationId);
  fs.mkdirSync(REMOTE_LOCK_DIR, { recursive: true });
  try {
    const fd = fs.openSync(target, "wx");
    fs.writeFileSync(fd, token, "utf8");
    fs.closeSync(fd);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    try {
      const lockState = fs.statSync(target);
      if (lockState.mtimeMs + leaseMs <= now) fs.rmSync(target, { force: true });
    } catch {
      return null;
    }
    try {
      const fd = fs.openSync(target, "wx");
      fs.writeFileSync(fd, token, "utf8");
      fs.closeSync(fd);
    } catch {
      return null;
    }
  }
  const at = new Date(now).toISOString();
  const claimed = transition(previous, previous.state, at, {
    operationId,
    leaseToken: token,
    leaseUntil: new Date(now + leaseMs).toISOString(),
    workerId,
  });
  try {
    const fresh = trashRepository.getTrashItem(item.id) || current;
    const freshState = remoteState(fresh);
    if (!freshState || !["pending", "retry_wait"].includes(freshState.state)) {
      releaseRemoteClaim({ path: target, token });
      return null;
    }
    const saved = trashRepository.saveTrashItem({ ...fresh, metadata: { ...fresh.metadata, remoteDeletion: claimed } });
    return { item: saved, token, path: target };
  } catch (error) {
    releaseRemoteClaim({ path: target, token });
    throw error;
  }
}

function ensureTrashStorage() {
  fs.mkdirSync(TRASH_STORAGE_DIR, { recursive: true });
}

function safeName(name) {
  return path.basename(String(name || ""));
}

function ensureInside(base, target) {
  const resolvedBase = path.resolve(base);
  const resolvedTarget = path.resolve(target);
  if (resolvedTarget !== resolvedBase && !resolvedTarget.startsWith(resolvedBase + path.sep)) {
    throw new Error("Caminho inseguro bloqueado");
  }
  return resolvedTarget;
}

function directorySize(dir) {
  if (!fs.existsSync(dir)) return 0;
  let total = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const filePath = path.join(dir, entry.name);
    if (entry.isDirectory()) total += directorySize(filePath);
    else if (entry.isFile()) total += fs.statSync(filePath).size;
  }
  return total;
}

function getAvailableRestoreName(destinationDir, originalName) {
  const parsed = path.parse(safeName(originalName));
  let candidate = safeName(originalName);
  let index = 1;
  while (fs.existsSync(path.join(destinationDir, candidate))) {
    candidate = `${parsed.name} (restored${index > 1 ? ` ${index}` : ""})${parsed.ext}`;
    index += 1;
  }
  return candidate;
}

function movePath(source, destination) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.renameSync(source, destination);
}

function buildFileMetadata(context) {
  const { folder, fileName, loaders } = context;
  const key = `${folder.id}/${fileName}`;
  return {
    permissions: loaders.loadFilePermissions()[key] || null,
    expiration: loaders.loadFileExpirations()[key] || null,
    versions: loaders.loadFileVersions()[key] || null,
    encryption: loaders.loadEncryptedFiles()[key] || null,
    publicLinks: Object.fromEntries(
      Object.entries(loaders.loadPublicLinks()).filter(([, link]) => (
        (link.folderId || "root") === folder.id && link.fileName === fileName
      ))
    ),
  };
}

function removeFileMetadata(context) {
  const { folder, fileName, loaders } = context;
  const key = `${folder.id}/${fileName}`;
  for (const [load, save] of [
    [loaders.loadFilePermissions, loaders.saveFilePermissions],
    [loaders.loadFileExpirations, loaders.saveFileExpirations],
    [loaders.loadEncryptedFiles, loaders.saveEncryptedFiles],
  ]) {
    const entries = load();
    if (entries[key]) {
      delete entries[key];
      save(entries);
    }
  }

  const publicLinks = loaders.loadPublicLinks();
  let linksChanged = false;
  for (const [token, link] of Object.entries(publicLinks)) {
    if ((link.folderId || "root") === folder.id && link.fileName === fileName) {
      delete publicLinks[token];
      linksChanged = true;
    }
  }
  if (linksChanged) loaders.savePublicLinks(publicLinks);
}

function removeFolderMetadata({ folderId, loaders }) {
  for (const [load, save] of [
    [loaders.loadFilePermissions, loaders.saveFilePermissions],
    [loaders.loadFileExpirations, loaders.saveFileExpirations],
    [loaders.loadFileVersions, loaders.saveFileVersions],
    [loaders.loadEncryptedFiles, loaders.saveEncryptedFiles],
  ]) {
    const entries = load();
    let changed = false;
    for (const key of Object.keys(entries)) {
      if (key.startsWith(`${folderId}/`)) {
        delete entries[key];
        changed = true;
      }
    }
    if (changed) save(entries);
  }
}

function restoreFileMetadata(context, metadata, restoredName) {
  const { folder, loaders } = context;
  const key = `${folder.id}/${restoredName}`;
  if (metadata.permissions) {
    const entries = loaders.loadFilePermissions();
    entries[key] = { ...metadata.permissions, fileName: restoredName, folderId: folder.id };
    loaders.saveFilePermissions(entries);
  }
  if (metadata.expiration) {
    const entries = loaders.loadFileExpirations();
    entries[key] = { ...metadata.expiration, fileName: restoredName, folderId: folder.id };
    loaders.saveFileExpirations(entries);
  }
  if (metadata.versions) {
    const entries = loaders.loadFileVersions();
    entries[key] = { ...metadata.versions, fileName: restoredName, folderId: folder.id };
    loaders.saveFileVersions(entries);
  }
  if (metadata.encryption) {
    const entries = loaders.loadEncryptedFiles();
    entries[key] = { ...metadata.encryption, fileName: restoredName, folderId: folder.id };
    loaders.saveEncryptedFiles(entries);
  }
}

function moveFileToTrash({ folder, fileName, deletedBy, loaders }) {
  ensureTrashStorage();
  const cleanName = safeName(fileName);
  const sourcePath = ensureInside(folder.uploadDir, path.join(folder.uploadDir, cleanName));
  if (!fs.existsSync(sourcePath)) throw new Error("Arquivo nao encontrado");
  const id = crypto.randomUUID();
  const trashRelative = path.posix.join("files", id, cleanName);
  const trashPath = path.join(TRASH_STORAGE_DIR, "files", id, cleanName);
  const metadata = buildFileMetadata({ folder, fileName: cleanName, loaders });
  const size = fs.statSync(sourcePath).size;

  movePath(sourcePath, trashPath);
  removeFileMetadata({ folder, fileName: cleanName, loaders });

  return trashRepository.saveTrashItem({
    id,
    itemType: "file",
    originalFolderId: folder.id,
    originalFolderName: folder.name,
    originalFileName: cleanName,
    storedFileName: cleanName,
    originalPath: `${folder.id}/${cleanName}`,
    trashPath: trashRelative,
    deletedBy,
    deletedAt: new Date().toISOString(),
    sizeBytes: size,
    metadata: { folderName: folder.name },
    restoreMetadata: metadata,
    status: "trashed",
  });
}

function moveFolderToTrash({ folder, deletedBy, loaders }) {
  ensureTrashStorage();
  if (!folder || folder.isRoot || folder.id === "root") throw new Error("A pasta padrao nao pode ir para lixeira");
  const id = crypto.randomUUID();
  const uploadDir = ensureInside(resolveRuntimePath("uploads"), folder.uploadDir);
  const tempDir = ensureInside(resolveRuntimePath("temp"), folder.tempDir);
  const trashFolderDir = path.join(TRASH_STORAGE_DIR, "folders", id);
  const trashUploads = path.join(trashFolderDir, "uploads");
  const trashTemp = path.join(trashFolderDir, "temp");
  const size = directorySize(uploadDir);
  const folderMetadata = {
    folder,
    filePermissions: Object.fromEntries(Object.entries(loaders.loadFilePermissions()).filter(([key]) => key.startsWith(`${folder.id}/`))),
    fileExpirations: Object.fromEntries(Object.entries(loaders.loadFileExpirations()).filter(([key]) => key.startsWith(`${folder.id}/`))),
    fileVersions: Object.fromEntries(Object.entries(loaders.loadFileVersions()).filter(([key]) => key.startsWith(`${folder.id}/`))),
    encryptedFiles: Object.fromEntries(Object.entries(loaders.loadEncryptedFiles()).filter(([key]) => key.startsWith(`${folder.id}/`))),
  };

  fs.mkdirSync(trashFolderDir, { recursive: true });
  if (fs.existsSync(uploadDir)) movePath(uploadDir, trashUploads);
  if (fs.existsSync(tempDir)) movePath(tempDir, trashTemp);

  loaders.saveFolders(loaders.loadFolders().filter((item) => item.id !== folder.id));
  const publicLinks = loaders.loadPublicLinks();
  let linksChanged = false;
  for (const [token, link] of Object.entries(publicLinks)) {
    if ((link.folderId || "root") === folder.id) {
      delete publicLinks[token];
      linksChanged = true;
    }
  }
  if (linksChanged) loaders.savePublicLinks(publicLinks);
  removeFolderMetadata({ folderId: folder.id, loaders });

  return trashRepository.saveTrashItem({
    id,
    itemType: "folder",
    originalFolderId: folder.id,
    originalFolderName: folder.name,
    originalFileName: folder.name,
    storedFileName: folder.id,
    originalPath: folder.id,
    trashPath: path.posix.join("folders", id),
    deletedBy,
    deletedAt: new Date().toISOString(),
    sizeBytes: size,
    metadata: { folderName: folder.name },
    restoreMetadata: folderMetadata,
    status: "trashed",
  });
}

function getTrashAbsolutePath(item) {
  return ensureInside(TRASH_STORAGE_DIR, path.join(TRASH_STORAGE_DIR, String(item.trashPath || "")));
}

function restoreFile({ item, folder, restoredBy, loaders }) {
  cancelRemoteDeletion(item, "restored");
  const sourcePath = getTrashAbsolutePath(item);
  const destinationDir = folder.uploadDir;
  const restoredName = getAvailableRestoreName(destinationDir, item.originalFileName);
  movePath(sourcePath, path.join(destinationDir, restoredName));
  restoreFileMetadata({ folder, loaders }, item.restoreMetadata || {}, restoredName);
  item.status = "restored";
  item.restoredBy = restoredBy;
  item.restoredAt = new Date().toISOString();
  item.metadata = { ...item.metadata, restoredName };
  return trashRepository.saveTrashItem(item);
}

function restoreFolder({ item, restoredBy, loaders, getDefaultFolder }) {
  cancelRemoteDeletion(item, "restored");
  const trashPath = getTrashAbsolutePath(item);
  const metadata = item.restoreMetadata || {};
  const folder = metadata.folder || {
    id: item.originalFolderId,
    name: item.originalFolderName,
    createdBy: restoredBy,
    createdAt: new Date().toISOString(),
    allowedUsers: [],
    isRoot: false,
  };
  const folders = loaders.loadFolders();
  const existing = folders.find((entry) => entry.id === folder.id);
  const restoredFolder = existing
    ? { ...folder, id: `${folder.id}-restored-${Date.now()}`, name: `${folder.name} restored` }
    : folder;
  loaders.saveFolders([...folders, restoredFolder]);

  const uploadSource = path.join(trashPath, "uploads");
  const tempSource = path.join(trashPath, "temp");
  const uploadDestination = resolveRuntimePath("uploads", restoredFolder.id === "root" ? "" : restoredFolder.id);
  const tempDestination = resolveRuntimePath("temp", restoredFolder.id === "root" ? "" : restoredFolder.id);
  if (fs.existsSync(uploadSource)) movePath(uploadSource, uploadDestination);
  if (fs.existsSync(tempSource)) movePath(tempSource, tempDestination);

  for (const [keyName, load, save] of [
    ["filePermissions", loaders.loadFilePermissions, loaders.saveFilePermissions],
    ["fileExpirations", loaders.loadFileExpirations, loaders.saveFileExpirations],
    ["fileVersions", loaders.loadFileVersions, loaders.saveFileVersions],
    ["encryptedFiles", loaders.loadEncryptedFiles, loaders.saveEncryptedFiles],
  ]) {
    const entries = load();
    for (const [key, value] of Object.entries(metadata[keyName] || {})) {
      const newKey = key.replace(`${folder.id}/`, `${restoredFolder.id}/`);
      entries[newKey] = { ...value, folderId: restoredFolder.id };
    }
    save(entries);
  }

  fs.rmSync(trashPath, { recursive: true, force: true });
  item.status = "restored";
  item.restoredBy = restoredBy;
  item.restoredAt = new Date().toISOString();
  item.metadata = { ...item.metadata, restoredFolderId: restoredFolder.id };
  return trashRepository.saveTrashItem(item);
}

function permanentlyDelete({ item, deletedBy, loaders, remoteDeletion = null }) {
  const target = getTrashAbsolutePath(item);
  fs.rmSync(target, { recursive: true, force: true });
  if (item.itemType === "file") {
    const versions = item.restoreMetadata?.versions?.versions || [];
    const uploadDir = resolveRuntimePath("uploads", item.originalFolderId === "root" ? "" : item.originalFolderId);
    for (const version of versions) {
      if (version.storedAs && version.storedAs !== item.originalFileName) {
        fs.rmSync(path.join(uploadDir, safeName(version.storedAs)), { force: true });
      }
    }
  } else if (item.itemType === "folder") {
    removeFolderMetadata({ folderId: item.originalFolderId, loaders });
  }
  if (remoteDeletion) item.metadata = { ...item.metadata, remoteDeletion };
  item.status = remoteDeletion ? "remote_delete_pending" : "permanently_deleted";
  item.permanentlyDeletedBy = deletedBy;
  item.permanentlyDeletedAt = new Date().toISOString();
  return trashRepository.saveTrashItem(item);
}

function queueRemoteDeletion({ item, deletedBy, loaders, provider = "unknown", clock, maxAttempts, operationId }) {
  if (item.status !== "trashed") return item;
  const existing = remoteState(item);
  if (existing) return item;
  maxAttempts = Math.max(1, Math.min(100, Number(maxAttempts) || DEFAULT_MAX_REMOTE_ATTEMPTS));
  const queuedAt = nowIso(clock);
  operationId = operationId || crypto.randomUUID();
  return permanentlyDelete({
    item,
    deletedBy,
    loaders,
    remoteDeletion: {
      operationId,
      provider,
      identity: remoteIdentity(item, provider),
      state: "pending",
      attempts: 0,
      maxAttempts,
      queuedAt,
      lastAttemptAt: null,
      nextAttemptAt: queuedAt,
      completedAt: null,
      failureCategory: null,
      cancellationReason: null,
      leaseToken: null,
      leaseUntil: null,
      transitions: [{ state: "pending", at: queuedAt }],
    },
  });
}

function completeRemoteDeletion(item, { clock, claimToken } = {}) {
  const previous = remoteState(item);
  if (item.status !== "remote_delete_pending" || !previous || ["completed", "cancelled", "terminal_failure"].includes(previous.state)) return item;
  if (claimToken && previous.leaseToken !== claimToken) return item;
  const completedAt = nowIso(clock);
  const completed = transition(previous, "completed", completedAt, {
    completedAt,
    lastAttemptAt: previous.lastAttemptAt || completedAt,
    nextAttemptAt: null,
    failureCategory: null,
    leaseToken: null,
    leaseUntil: null,
  });
  item.status = "permanently_deleted";
  item.metadata = { ...item.metadata, remoteDeletion: completed };
  return trashRepository.saveTrashItem(item);
}

function failRemoteDeletion(item, error, { clock, claimToken } = {}) {
  const previous = remoteState(item);
  if (item.status !== "remote_delete_pending" || !previous || ["completed", "cancelled", "terminal_failure"].includes(previous.state)) return item;
  if (claimToken && previous.leaseToken !== claimToken) return item;
  const attempts = Math.min(Number(previous.maxAttempts) || DEFAULT_MAX_REMOTE_ATTEMPTS, (Number(previous.attempts) || 0) + 1);
  const failedAt = nowIso(clock);
  const terminal = attempts >= (Number(previous.maxAttempts) || DEFAULT_MAX_REMOTE_ATTEMPTS);
  const nextState = terminal ? "terminal_failure" : "retry_wait";
  const nextAttemptAt = terminal ? null : new Date(getClock(clock)() + backoffMs(attempts)).toISOString();
  item.metadata = { ...item.metadata, remoteDeletion: transition(previous, nextState, failedAt, {
    attempts,
    lastAttemptAt: failedAt,
    nextAttemptAt,
    failureCategory: failureCategory(error),
    leaseToken: null,
    leaseUntil: null,
  }) };
  return trashRepository.saveTrashItem(item);
}

function cancelRemoteDeletion(item, reason = "cancelled", { clock, status } = {}) {
  const previous = remoteState(item);
  if (!previous || ["completed", "cancelled"].includes(previous.state)) return item;
  const at = nowIso(clock);
  if (status) item.status = status;
  item.metadata = { ...item.metadata, remoteDeletion: transition(previous, "cancelled", at, {
    cancellationReason: String(reason).slice(0, 120),
    nextAttemptAt: null,
    leaseToken: null,
    leaseUntil: null,
  }) };
  return trashRepository.saveTrashItem(item);
}

async function processRemoteDeletion({ item, provider, clock, leaseMs, workerId, runFileLifecycleMutation, runFolderLifecycleMutation, isReplacementActive } = {}) {
  if (typeof provider !== "function") throw new TypeError("Remote deletion provider is required");
  const processLocked = async () => {
    const latest = trashRepository.getTrashItem(item.id) || item;
    const latestState = remoteState(latest);
    if (latest.status === "remote_delete_pending" && latestState?.state === "cancelled") {
      // Repair records written by older two-save cancellation logic. A cancelled
      // deletion must not remain visible as retryable work after a restart. A
      // replacement has superseded the trash record; a restore cancellation
      // remains available in trash if its separate restore operation stopped.
      latest.status = latestState.cancellationReason === "replacement_active" ? "permanently_deleted" : "trashed";
      return trashRepository.saveTrashItem(latest);
    }
    if (latest.status !== "remote_delete_pending" || !latestState) return latest;
    if (latest.itemType !== item.itemType || latest.originalFolderId !== item.originalFolderId || latest.originalFileName !== item.originalFileName) return latest;
    if (typeof isReplacementActive === "function" && await isReplacementActive(latest)) {
      return cancelRemoteDeletion(latest, "replacement_active", { clock, status: "permanently_deleted" });
    }

    const claim = claimRemoteDeletion({ item: latest, clock, leaseMs, workerId });
    if (!claim) return trashRepository.getTrashItem(item.id) || latest;
    try {
      const current = trashRepository.getTrashItem(item.id) || claim.item;
      const state = remoteState(current);
      if (current.status !== "remote_delete_pending" || !state || state.state === "cancelled") return current;
      await provider(current);
      // Provider remove operations are idempotent; false means the object was already absent.
      return completeRemoteDeletion(current, { clock, claimToken: claim.token });
    } catch (error) {
      const current = trashRepository.getTrashItem(item.id) || claim.item;
      if (failureCategory(error) === "missing_object") return completeRemoteDeletion(current, { clock, claimToken: claim.token });
      return failRemoteDeletion(current, error, { clock, claimToken: claim.token });
    } finally {
      releaseRemoteClaim(claim);
    }
  };

  if (item.itemType === "file" && typeof runFileLifecycleMutation === "function") {
    return runFileLifecycleMutation(item.originalFolderId, item.originalFileName, processLocked);
  }
  if (item.itemType === "folder" && typeof runFolderLifecycleMutation === "function") {
    return runFolderLifecycleMutation(item.originalFolderId, processLocked);
  }
  return processLocked();
}

function summary() {
  const items = trashRepository.listTrashItems();
  return {
    count: items.length,
    sizeBytes: items.reduce((sum, item) => sum + (Number(item.sizeBytes) || 0), 0),
    files: items.filter((item) => item.itemType === "file").length,
    folders: items.filter((item) => item.itemType === "folder").length,
  };
}

module.exports = {
  moveFileToTrash,
  moveFolderToTrash,
  permanentlyDelete,
  queueRemoteDeletion,
  completeRemoteDeletion,
  failRemoteDeletion,
  cancelRemoteDeletion,
  processRemoteDeletion,
  claimRemoteDeletion,
  restoreFile,
  restoreFolder,
  summary,
};
