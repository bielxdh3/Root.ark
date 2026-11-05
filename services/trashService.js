const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("node:child_process");
const Database = require("better-sqlite3");
const { resolveRuntimePath } = require("../src/runtime-paths");
const trashRepository = require("../repositories/trashRepository");
const { assertZk10LegacyBackupNotStrict } = require("../src/services/zk10LegacyBackupDeny");

const TRASH_STORAGE_DIR = resolveRuntimePath("data", "trash");
const REMOTE_LOCK_DIR = resolveRuntimePath("data", "trash-remote-locks");
const REMOTE_LOCK_COORDINATION_FILE = path.join(REMOTE_LOCK_DIR, ".coordination.sqlite");
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

function isAlreadyPrivateOwnedPosixDirectory(directoryPath, owner) {
  const directory = fs.lstatSync(directoryPath, { bigint: true });
  if (!directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== owner) {
    throw new Error("Remote deletion claim directory is unsafe");
  }
  // Existing owner-only write/search (0300) directories are legitimate and
  // require no migration; opening those with O_RDONLY would fail EACCES.
  return (directory.mode & 0o077n) === 0n;
}

function ensurePrivateOwnedPosixDirectory(directoryPath, parentPath) {
  // Never try to repair a child underneath a replaceable parent. Historical
  // installs often have both data/ and its lock directory at umask-0002 0775.
  const parent = fs.lstatSync(parentPath, { bigint: true });
  const owner = BigInt(process.getuid());
  if (!parent.isDirectory() || parent.isSymbolicLink() ||
      parent.uid !== owner || (parent.mode & 0o022n) !== 0n) {
    throw new Error("Remote deletion claim directory is unsafe");
  }
  try { fs.mkdirSync(directoryPath, { mode: 0o700 }); }
  catch (error) { if (error.code !== "EEXIST") throw error; }
  if (isAlreadyPrivateOwnedPosixDirectory(directoryPath, owner)) return;
  if (!fs.constants.O_NOFOLLOW || !fs.constants.O_DIRECTORY) {
    throw new Error("Remote deletion claim directory cannot be pinned");
  }

  // Pin the directory before inspecting the pathname. O_NOFOLLOW rejects a
  // substituted symlink at the kernel boundary rather than trusting lstat.
  const fd = fs.openSync(directoryPath,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_DIRECTORY);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(directoryPath, { bigint: true });
    if (!opened.isDirectory() || opened.isSymbolicLink() ||
        named.isSymbolicLink() || opened.uid !== owner ||
        opened.dev !== named.dev || opened.ino !== named.ino) {
      throw new Error("Remote deletion claim directory changed during migration");
    }
    if ((opened.mode & 0o077n) === 0n) return;
    fs.fchmodSync(fd, 0o700);
    const after = fs.fstatSync(fd, { bigint: true });
    const afterName = fs.lstatSync(directoryPath, { bigint: true });
    if (!after.isDirectory() || after.dev !== opened.dev ||
        after.ino !== opened.ino || after.dev !== afterName.dev ||
        after.ino !== afterName.ino || afterName.isSymbolicLink() ||
        (after.mode & 0o077n) !== 0n) {
      throw new Error("Remote deletion claim directory migration failed");
    }
  } finally {
    fs.closeSync(fd);
  }
}

function ensurePrivateRemoteClaimDirectory() {
  if (process.platform === "win32") {
    // A junction at data/ can redirect SQLite's main DB and WAL/SHM as well
    // as lock files. A pathname lstat alone is insufficient on Windows:
    // another SID with DELETE_CHILD/Modify may replace the ancestor after
    // inspection. Pin this authority to native owner-only ACL checks, and
    // create missing levels with a protected DACL at CreateDirectoryW time.
    const { ensureWindowsChunkUploadRoot } = require("./chunkUploadWindowsAcl");
    const { assertPrivateSqliteAuthorityDirectory } =
      require("../src/services/zk1PrivateSqlitePath");
    const dataDir = path.dirname(REMOTE_LOCK_DIR);
    const runtimeRoot = path.dirname(dataDir);
    const runtime = fs.lstatSync(runtimeRoot, { bigint: true });
    if (!runtime.isDirectory() || runtime.isSymbolicLink()) {
      throw new Error("Remote deletion claim directory is unsafe");
    }
    for (const directory of [dataDir, REMOTE_LOCK_DIR]) {
      try {
        const stat = fs.lstatSync(directory);
        if (!stat.isDirectory() || stat.isSymbolicLink()) {
          throw new Error("Remote deletion claim directory is unsafe");
        }
      } catch (error) {
        if (error.code !== "ENOENT") throw error;
        // Native creation checks the full parent ACL before writing and
        // never adopts an untrusted replacement as a private authority.
        ensureWindowsChunkUploadRoot(directory);
      }
    }
    const data = fs.lstatSync(dataDir, { bigint: true });
    if (!data.isDirectory() || data.isSymbolicLink()) {
      throw new Error("Remote deletion claim directory is unsafe");
    }
    const directory = fs.lstatSync(REMOTE_LOCK_DIR, { bigint: true });
    const finalData = fs.lstatSync(dataDir, { bigint: true });
    if (!directory.isDirectory() || directory.isSymbolicLink()
        || !finalData.isDirectory() || finalData.isSymbolicLink()
        || finalData.dev !== data.dev || finalData.ino !== data.ino) {
      throw new Error("Remote deletion claim directory is unsafe");
    }
    // A fresh native ACL/ancestry verification is required on EVERY claim,
    // including with an existing coordinator DB, and before SQLite opens its
    // path-based database/WAL/SHM handles or any O_EXCL claim lock.
    try {
      assertPrivateSqliteAuthorityDirectory(REMOTE_LOCK_COORDINATION_FILE);
    } catch (strictError) {
      // Older versions used fs.mkdirSync(mode:0700), which leaves an NTFS
      // directory with an inherited (unprotected) DACL. Migrate ONLY when
      // native full-tree checks confirm owner/SYSTEM/Admin-only ACEs, real
      // paths and trusted ancestors. Never seal an untrusted Users:Modify
      // DACL or change permissions before these checks.
      const { verifyWindowsLocalWebDavTree, getWindowsChunkAclDescriptor } =
        require("./chunkUploadWindowsAcl");
      try {
        verifyWindowsLocalWebDavTree(REMOTE_LOCK_DIR);
        // Do not mutate a path whose ACL is already protected: its failed
        // strict admission has a different cause and must remain fail-closed.
        if (/D:P/.test(getWindowsChunkAclDescriptor(REMOTE_LOCK_DIR))) {
          throw strictError;
        }
        execFileSync("C:\\Windows\\System32\\icacls.exe",
          [REMOTE_LOCK_DIR, "/inheritance:d"], {
            stdio: "ignore", windowsHide: true, timeout: 12000,
          });
        // Fail closed if conversion, DACL, ancestor or a descendant changed.
        assertPrivateSqliteAuthorityDirectory(REMOTE_LOCK_COORDINATION_FILE);
      } catch (error) {
        throw new Error("Remote deletion claim directory needs a protected owner-only Windows ACL", {
          cause: error,
        });
      }
    }
    return;
  }
  const dataDir = path.dirname(REMOTE_LOCK_DIR);
  const runtimeRoot = path.dirname(dataDir);
  ensurePrivateOwnedPosixDirectory(dataDir, runtimeRoot);
  ensurePrivateOwnedPosixDirectory(REMOTE_LOCK_DIR, dataDir);
}

function withRemoteClaimCoordination(operation) {
  // A filesystem lease alone cannot safely reclaim an expired path: two
  // processes can both stat the old lock and erase a newer owner's claim.
  // SQLite's BEGIN IMMEDIATE serializes claim, stale recovery and release.
  ensurePrivateRemoteClaimDirectory();
  try {
    const file = fs.lstatSync(REMOTE_LOCK_COORDINATION_FILE);
    if (!file.isFile() || file.isSymbolicLink()) throw new Error("Remote deletion claim coordinator is unsafe");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const db = new Database(REMOTE_LOCK_COORDINATION_FILE);
  try {
    db.pragma("busy_timeout = 2000");
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = operation();
      db.exec("COMMIT");
      return result;
    } catch (error) {
      try { db.exec("ROLLBACK"); } catch {}
      throw error;
    }
  } finally {
    try { if (db.inTransaction) db.exec("ROLLBACK"); } catch {}
    db.close();
  }
}

function releaseRemoteClaimUnlocked(claim) {
  if (!claim?.path) return;
  try {
    const current = fs.readFileSync(claim.path, "utf8");
    if (current === claim.token) fs.rmSync(claim.path, { force: true });
  } catch {
    // A missing lock is already released; never mask the operation result.
  }
}

function releaseRemoteClaim(claim) {
  if (!claim?.path) return;
  try { withRemoteClaimCoordination(() => releaseRemoteClaimUnlocked(claim)); }
  catch { /* Preserve the operation result; an unreleased lock is fail-closed. */ }
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
  const at = new Date(now).toISOString();
  const saveClaim = () => {
    const fresh = trashRepository.getTrashItem(item.id);
    const update = (entry) => {
      const state = remoteState(entry);
      return { ...entry, metadata: { ...entry.metadata, remoteDeletion: transition(state,
        state.state, at, { operationId, leaseToken: token,
          leaseUntil: new Date(now + leaseMs).toISOString(), workerId }) } };
    };
    const saved = fresh
      ? trashRepository.saveRemoteDeletionIfExpectedLease(item.id,
        previous.leaseToken ?? null, operationId, update)
      : trashRepository.saveTrashItem(update(current));
    return saved?.metadata?.remoteDeletion?.leaseToken === token ? { item: saved, token, path: target } : null;
  };
  if (!trashRepository.usesSqliteTrashStore()) {
    // Legacy JSON read/compare/write is protected by the SAME coordination
    // mutex as lease-file reclaim. This path never acquires the application DB.
    return withRemoteClaimCoordination(() => {
      if (!reserveRemoteClaimPath(target, token, now, leaseMs)) return null;
      try {
        const claimed = saveClaim();
        if (!claimed) releaseRemoteClaimUnlocked({ path: target, token });
        return claimed;
      } catch (error) {
        releaseRemoteClaimUnlocked({ path: target, token });
        throw error;
      }
    });
  }
  // SQLite's claim-row CAS is atomic, but it is never nested under the
  // independent claim-coordination DB transaction (no lock inversion).
  if (!withRemoteClaimCoordination(() => reserveRemoteClaimPath(target, token, now, leaseMs))) return null;
  try {
    const claimed = saveClaim();
    if (!claimed) releaseRemoteClaim({ path: target, token });
    return claimed;
  } catch (error) {
    releaseRemoteClaim({ path: target, token });
    throw error;
  }
}

function createRemoteClaimExclusive(target, token) {
  // An exclusive create remains atomic even after a competing stale-lock
  // reclamation. Never reuse a pathname check as authority to overwrite it.
  const fd = fs.openSync(target, "wx", 0o600);
  try {
    fs.writeFileSync(fd, token, "utf8");
  } finally {
    // A failed token write must not strand a live writable descriptor.
    fs.closeSync(fd);
  }
}

function reserveRemoteClaimPath(target, token, now, leaseMs) {
  try {
    createRemoteClaimExclusive(target, token);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    try {
      const lockState = fs.lstatSync(target);
      if (!lockState.isFile() || lockState.isSymbolicLink()) return null;
      if (lockState.mtimeMs + leaseMs <= now) fs.rmSync(target, { force: true });
    } catch {
      return false;
    }
    try {
      createRemoteClaimExclusive(target, token);
    } catch {
      return false;
    }
  }
  return true;
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

function saveClaimedRemoteTransition(item, token, update) {
  const operationId = remoteState(item)?.operationId;
  if (!operationId) return trashRepository.getTrashItem(item.id) || item;
  const save = () => trashRepository.saveRemoteDeletionIfLeaseOwner(
    item.id, token, operationId, update) || item;
  // JSON's synchronous read/compare/write must share the lease coordination
  // mutex with JSON claim/reclaim. SQLite mode instead uses an atomic guarded
  // UPDATE in the main database, with no coordinator lock held.
  return trashRepository.usesSqliteTrashStore() ? save() : withRemoteClaimCoordination(save);
}

function completeRemoteDeletion(item, { clock, claimToken } = {}) {
  if (claimToken) {
    return saveClaimedRemoteTransition(item, claimToken, (fresh) => {
      const previous = remoteState(fresh);
      const completedAt = nowIso(clock);
      return {
        ...fresh, status: "permanently_deleted",
        metadata: { ...fresh.metadata, remoteDeletion: transition(previous, "completed", completedAt, {
          completedAt, lastAttemptAt: previous.lastAttemptAt || completedAt,
          nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null,
        }) },
      };
    });
  }
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
  if (claimToken) {
    return saveClaimedRemoteTransition(item, claimToken, (fresh) => {
      const previous = remoteState(fresh);
      const attempts = Math.min(Number(previous.maxAttempts) || DEFAULT_MAX_REMOTE_ATTEMPTS,
        (Number(previous.attempts) || 0) + 1);
      const failedAt = nowIso(clock);
      const terminal = attempts >= (Number(previous.maxAttempts) || DEFAULT_MAX_REMOTE_ATTEMPTS);
      const nextAttemptAt = terminal ? null : new Date(getClock(clock)() + backoffMs(attempts)).toISOString();
      return {
        ...fresh, metadata: { ...fresh.metadata, remoteDeletion: transition(previous,
          terminal ? "terminal_failure" : "retry_wait", failedAt, {
            attempts, lastAttemptAt: failedAt, nextAttemptAt,
            failureCategory: failureCategory(error), leaseToken: null, leaseUntil: null,
          }) },
      };
    });
  }
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
  if (item.status === "remote_delete_pending" && previous.operationId
      && ["pending", "retry_wait"].includes(previous.state)) {
    const save = () => {
      const persisted = trashRepository.saveRemoteDeletionIfExpectedLease(
        item.id, previous.leaseToken ?? null, previous.operationId, (fresh) => {
          const currentState = remoteState(fresh);
          const at = nowIso(clock);
          return {
            ...fresh, status: status || fresh.status,
            metadata: { ...fresh.metadata, remoteDeletion: transition(currentState,
              "cancelled", at, {
                cancellationReason: String(reason).slice(0, 120),
                nextAttemptAt: null, leaseToken: null, leaseUntil: null,
              }) },
          };
        });
      if (persisted) Object.assign(item, persisted);
      return persisted || item;
    };
    return trashRepository.usesSqliteTrashStore() ? save() : withRemoteClaimCoordination(save);
  }
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
  // This is the shared physical-delete dispatcher for scheduled cleanup,
  // authenticated trash routes and restart retry. No per-owner off-host
  // authority can be inferred from the locally persisted trash record.
  assertZk10LegacyBackupNotStrict();
  if (typeof provider !== "function") throw new TypeError("Remote deletion provider is required");
  const processLocked = async () => {
    assertZk10LegacyBackupNotStrict();
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
    // Replacement checks can await filesystem/provider state; a strict
    // cutover after that await must not begin claiming or deleting the job.
    assertZk10LegacyBackupNotStrict();

    const claim = claimRemoteDeletion({ item: latest, clock, leaseMs, workerId });
    if (!claim) return trashRepository.getTrashItem(item.id) || latest;
    try {
      const current = trashRepository.getTrashItem(item.id) || claim.item;
      const state = remoteState(current);
      if (current.status !== "remote_delete_pending" || !state || state.state === "cancelled") return current;
      assertZk10LegacyBackupNotStrict();
      await provider(current);
      // Provider remove operations are idempotent; false means the object was already absent.
      return completeRemoteDeletion(current, { clock, claimToken: claim.token });
    } catch (error) {
      // Local STRICT denial is not a failed provider DELETE. Preserve the
      // retryable pending record and propagate the precise fail-closed code;
      // finally still releases the physical claim lock.
      if (error.code === "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE") throw error;
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
