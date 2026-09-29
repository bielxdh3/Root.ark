const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const unzipper = require("unzipper");
const { closeDb, getDatabasePath, isDbEnabled } = require("../db");
const { resolveRuntimePath } = require("../src/runtime-paths");
const backupRepository = require("../repositories/backupRepository");
const backupService = require("./backupService");
const { attestCiphertextOnlyArchive } = require("../src/services/deploymentResilience");
const { getUploadQuarantineDir, isSensitiveQuarantineItem, quarantineDirContainsUploads, readQuarantineMetadata, readQuarantineRegularFile, validateQuarantinePayloads } = require("../src/quarantine-paths");

const RESTORE_TMP_DIR = path.join(backupService.BACKUPS_DIR, ".restore-tmp");
const RESTORE_SYNC_LOCK_DIR = resolveRuntimePath("data", "restore-sync-locks");
const RESTORABLE_ROOTS = new Set(["data", "uploads"]);
const S_IFMT = 0xf000;
const S_IFLNK = 0xa000;
let cloudStorage = null;

function setCloudStorage(storage) {
  cloudStorage = storage || null;
}

function syncNow(clock) {
  return new Date(typeof clock === "function" ? clock() : clock?.now ? clock.now() : Date.now()).toISOString();
}

function syncEntries(manifest) {
  return (manifest?.included_files || [])
    .map((entry) => String(entry.path || "").replace(/\\/g, "/"))
    .filter((entryPath) => entryPath.startsWith("uploads/") || entryPath.startsWith("temp/"))
    .map((entryPath) => {
      const [area, ...parts] = entryPath.split("/");
      const name = parts.pop();
      const folderId = parts.join("/") || "root";
      if (!name || !folderId || folderId.includes("/") || folderId === "." || folderId === ".." || /(^|\/)(\.env|.*credentials.*|.*\.key)$/i.test(name)) return null;
      return { entryId: crypto.randomUUID(), path: entryPath, area, folderId, name, providerIdentity: null, state: "pending", attempts: 0, maxAttempts: 5, nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null };
    })
    .filter(Boolean);
}

function createRestoreSync(manifest, clock) {
  const queuedAt = syncNow(clock);
  const entries = syncEntries(manifest);
  const state = entries.length ? "pending" : "completed";
  return {
    operationId: crypto.randomUUID(),
    revision: 0,
    state,
    queuedAt,
    lastAttemptAt: null,
    completedAt: state === "completed" ? queuedAt : null,
    failureCategory: null,
    entries,
    transitions: [{ state, at: queuedAt }],
  };
}

function syncTransition(sync, state, at, details = {}) {
  return { ...sync, ...details, state, transitions: [...(sync.transitions || []), { state, at }] };
}

function claimSyncEntry(backupId, entryId, { now, leaseMs = 60 * 1000, workerId = crypto.randomUUID(), providerIdentity } = {}) {
  const current = backupRepository.getBackup(backupId);
  const sync = current?.metadata?.restoreSync;
  const index = sync?.entries?.findIndex((entry) => entry.entryId === entryId);
  if (!current || !sync || index < 0) return null;
  const existing = sync.entries[index];
  const leaseUntil = new Date(existing.leaseUntil || 0).getTime();
  if (existing.state === "completed" || existing.state === "terminal_failure" || (existing.leaseToken && leaseUntil > now)) return null;
  const token = `${workerId}:${crypto.randomUUID()}`;
  try {
    const saved = backupRepository.mutateRestoreSyncEntry({
      backupId,
      operationId: sync.operationId,
      entryId,
      expectedState: ["pending", "retry_wait", "in_progress"],
      expectedLeaseToken: existing.leaseToken || null,
      expectedRevision: Number(sync.revision) || 0,
      mutate: (entry) => ({
        entry: {
          ...entry,
          state: "in_progress",
          attempts: (Number(entry.attempts) || 0) + 1,
          nextAttemptAt: null,
          leaseToken: token,
          leaseUntil: new Date(now + leaseMs).toISOString(),
          providerIdentity: providerIdentity || entry.providerIdentity || "cloud",
        },
        details: { lastAttemptAt: new Date(now).toISOString() },
        at: new Date(now).toISOString(),
      }),
    });
    const claimedEntry = saved.metadata.restoreSync.entries.find((entry) => entry.entryId === entryId);
    return { backup: saved, entry: claimedEntry, token };
  } catch (error) {
    if (["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(error.code)) return null;
    throw error;
  }
}

function cancelRestoreSync(backupId, reason = "cancelled", { clock } = {}) {
  let backup = backupRepository.getBackup(backupId);
  const current = backup?.metadata?.restoreSync;
  if (!backup || !current || ["completed", "cancelled"].includes(current.state)) return backup;
  const at = syncNow(clock);
  for (const entry of current.entries || []) {
    if (entry.state === "cancelled" || entry.state === "completed") continue;
    try {
      backup = backupRepository.mutateRestoreSyncEntry({
        backupId,
        operationId: backup.metadata.restoreSync.operationId,
        entryId: entry.entryId,
        expectedState: entry.state,
        expectedLeaseToken: entry.leaseToken || null,
        expectedRevision: Number(backup.metadata.restoreSync.revision) || 0,
        mutate: (latestEntry) => ({
          entry: { ...latestEntry, state: "cancelled", leaseToken: null, leaseUntil: null, nextAttemptAt: null },
          details: { cancellationReason: String(reason).slice(0, 120) },
          at,
        }),
      });
    } catch (error) {
      if (!["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(error.code)) throw error;
      backup = backupRepository.getBackup(backupId) || backup;
    }
  }
  return backupRepository.getBackup(backupId) || backup;
}

async function processRestoreSync({ backupId, clock, maxAttempts = 5, uploader, leaseMs = 60 * 1000, workerId } = {}) {
  const provider = uploader || cloudStorage;
  let latest = backupRepository.getBackup(backupId);
  if (!latest || !latest.metadata?.restoreSync || !provider?.enabled?.()) return latest;
  if (latest.metadata.restoreSync.entries?.length
    && latest.metadata.restoreSync.entries.every((entry) => entry.state === "completed")
    && latest.metadata.restoreSync.state !== "completed") {
    const entry = latest.metadata.restoreSync.entries[0];
    try {
      latest = backupRepository.mutateRestoreSyncEntry({
        backupId,
        operationId: latest.metadata.restoreSync.operationId,
        entryId: entry.entryId,
        expectedState: "completed",
        expectedLeaseToken: null,
        expectedRevision: Number(latest.metadata.restoreSync.revision) || 0,
        mutate: (latestEntry) => ({ entry: latestEntry, details: { failureCategory: null }, at: syncNow(clock) }),
      });
    } catch (error) {
      if (!["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(error.code)) throw error;
      latest = backupRepository.getBackup(backupId) || latest;
    }
  }
  if (["completed", "cancelled", "terminal_failure"].includes(latest.metadata.restoreSync.state)) return latest;
  const now = typeof clock === "function" ? clock() : clock?.now ? clock.now() : Date.now();
  const providerIdentity = provider.provider || provider.name || "cloud";
  for (const candidate of latest.metadata.restoreSync.entries || []) {
    if (candidate.state === "completed" || candidate.state === "terminal_failure") continue;
    if (candidate.nextAttemptAt && new Date(candidate.nextAttemptAt).getTime() > now) continue;
    const lease = claimSyncEntry(backupId, candidate.entryId, { now, leaseMs, workerId, providerIdentity });
    if (!lease) continue;
    try {
      const localPath = resolveRuntimePath(lease.entry.path);
      if (!fs.existsSync(localPath) || !fs.statSync(localPath).isFile()) throw Object.assign(new Error("restore source unavailable"), { code: "source_unavailable" });
      await provider.upload(localPath, lease.entry.folderId, lease.entry.name, lease.entry.area);
      const current = backupRepository.getBackup(backupId);
      const entry = current?.metadata?.restoreSync?.entries?.find((value) => value.entryId === lease.entry.entryId);
      if (!entry || entry.leaseToken !== lease.token) continue;
      const at = syncNow(clock);
      backupRepository.mutateRestoreSyncEntry({
        backupId,
        operationId: current.metadata.restoreSync.operationId,
        entryId: lease.entry.entryId,
        expectedState: "in_progress",
        expectedLeaseToken: lease.token,
        expectedRevision: Number(current.metadata.restoreSync.revision) || 0,
        mutate: (latestEntry) => ({ entry: { ...latestEntry, state: "completed", failureCategory: null, nextAttemptAt: null, leaseToken: null, leaseUntil: null }, details: { failureCategory: null }, at }),
      });
    } catch (error) {
      if (error.code?.startsWith("backup_")) throw error;
      const current = backupRepository.getBackup(backupId);
      const entry = current?.metadata?.restoreSync?.entries?.find((value) => value.entryId === lease.entry.entryId && value.leaseToken === lease.token);
      if (!entry) continue;
      const attempts = Math.max(1, Number(entry.attempts) || 1);
      const failureCategory = ["source_unavailable", "configuration"].includes(error.code) ? error.code : "provider_error";
      const terminal = attempts >= Math.max(1, Number(entry.maxAttempts || maxAttempts));
      const at = syncNow(clock);
      const nextAttemptAt = terminal ? null : new Date(now + Math.min(60 * 60 * 1000, 1000 * (2 ** (attempts - 1)))).toISOString();
      try {
        backupRepository.mutateRestoreSyncEntry({
          backupId,
          operationId: current.metadata.restoreSync.operationId,
          entryId: lease.entry.entryId,
          expectedState: "in_progress",
          expectedLeaseToken: lease.token,
          expectedRevision: Number(current.metadata.restoreSync.revision) || 0,
          mutate: (latestEntry) => ({ entry: { ...latestEntry, state: terminal ? "terminal_failure" : "retry_wait", failureCategory, nextAttemptAt, leaseToken: null, leaseUntil: null }, details: { failureCategory: terminal ? failureCategory : null }, at }),
        });
      } catch (mutationError) {
        if (!["backup_revision_conflict", "backup_state_conflict", "backup_lease_conflict", "backup_mutation_conflict"].includes(mutationError.code)) throw mutationError;
      }
    }
    latest = backupRepository.getBackup(backupId) || latest;
  }
  return backupRepository.getBackup(backupId) || latest;
}

function isZipSymlink(entry) {
  if (entry.type === "SymbolicLink") return true;
  const madeByUnix = (Number(entry.versionMadeBy) >>> 8) === 3;
  const unixMode = Number(entry.externalFileAttributes) >>> 16;
  return madeByUnix && (unixMode & S_IFMT) === S_IFLNK;
}

function assertSafeZipPath(entryPath) {
  const archivePath = String(entryPath || "").replace(/\\/g, "/");
  if (!archivePath || archivePath.startsWith("/") || /^[a-zA-Z]:/.test(archivePath)) {
    throw new Error(`Caminho invalido no backup: ${entryPath}`);
  }
  const parts = archivePath.split("/");
  if (parts.includes("..")) throw new Error(`Path traversal bloqueado: ${entryPath}`);
  const normalized = path.posix.normalize(archivePath);
  if (parts[0] !== "backup-manifest.json" && !RESTORABLE_ROOTS.has(parts[0])) {
    throw new Error(`Entrada nao permitida no backup: ${entryPath}`);
  }
  const normalizedFolded = normalized.replace(/\/+$/, "").toLowerCase();
  if (normalizedFolded === "data/.rootark-quarantine-restore-journal.json"
    || normalizedFolded.startsWith("data/.rootark-quarantine-restore-metadata-")
    || (normalizedFolded === "data/quarantine.json" && normalized !== "data/quarantine.json")) {
    throw new Error(`Entrada de controle bloqueada no backup: ${entryPath}`);
  }
  const sensitiveName = path.posix.basename(normalized).toLowerCase();
  if (normalized.includes("data/backups/") || sensitiveName === "server-master.key"
    || sensitiveName === ".env" || sensitiveName.startsWith(".env.")) {
    throw new Error(`Entrada sensivel bloqueada no backup: ${entryPath}`);
  }
  return normalized;
}

async function readManifest(archivePath) {
  const zip = await unzipper.Open.file(archivePath);
  const manifestEntry = zip.files.find((entry) => entry.path === "backup-manifest.json");
  if (!manifestEntry) throw new Error("Manifest ausente no backup");
  const raw = await manifestEntry.buffer();
  const manifest = JSON.parse(raw.toString("utf-8"));
  return { zip, manifest };
}

async function validateBackupArchive(backup, archivePath) {
  if (backup.checksum) {
    const checksum = await backupService.calculateFileHash(archivePath);
    if (checksum !== backup.checksum) {
      throw new Error("Checksum do backup nao confere");
    }
  }

  const { zip, manifest } = await readManifest(archivePath);
  const destinations = new Set();
  for (const entry of zip.files) {
    if (isZipSymlink(entry)) throw new Error(`Symlink bloqueado no backup: ${entry.path}`);
    const safePath = assertSafeZipPath(entry.path);
    const destinationKey = safePath.replace(/\/+$/, "").toLowerCase();
    if (destinations.has(destinationKey)) throw new Error(`Entrada duplicada no backup: ${entry.path}`);
    destinations.add(destinationKey);
  }
  if (!manifest.backup_id) throw new Error("Manifest invalido");
  await attestCiphertextOnlyArchive(zip);
  return { zip, manifest };
}

async function extractArchive(zip, targetDir) {
  fs.rmSync(targetDir, { recursive: true, force: true });
  fs.mkdirSync(targetDir, { recursive: true });

  for (const entry of zip.files) {
    const safePath = assertSafeZipPath(entry.path);
    if (safePath === "backup-manifest.json") continue;
    if (entry.type === "Directory") continue;
    if (isZipSymlink(entry)) throw new Error(`Symlink bloqueado no backup: ${entry.path}`);

    const root = path.resolve(targetDir);
    const destination = path.resolve(root, safePath);
    const relative = path.relative(root, destination);
    if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
      throw new Error(`Path traversal bloqueado: ${entry.path}`);
    }
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, await entry.buffer());
  }
}

function isPathWithin(basePath, targetPath) {
  const base = path.resolve(basePath);
  const target = path.resolve(targetPath);
  const comparableBase = process.platform === "win32" ? base.toLowerCase() : base;
  const comparableTarget = process.platform === "win32" ? target.toLowerCase() : target;
  const relative = path.relative(comparableBase, comparableTarget);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function pathVariants(value) {
  const resolved = path.resolve(value);
  const variants = new Map();
  const add = (candidate) => {
    const normalized = path.resolve(candidate);
    const key = process.platform === "win32" ? normalized.toLowerCase() : normalized;
    if (!variants.has(key)) variants.set(key, normalized);
  };
  add(resolved);
  try { add(fs.realpathSync.native ? fs.realpathSync.native(resolved) : fs.realpathSync(resolved)); } catch {}
  return [...variants.values()];
}

function isPathWithinAliases(basePath, targetPath) {
  return pathVariants(basePath).some((base) => pathVariants(targetPath).some((target) => isPathWithin(base, target)));
}

function nestedPathDepth(basePath, targetPath) {
  const base = path.resolve(basePath);
  const target = path.resolve(targetPath);
  const comparableBase = process.platform === "win32" ? base.toLowerCase() : base;
  const comparableTarget = process.platform === "win32" ? target.toLowerCase() : target;
  if (!isPathWithin(comparableBase, comparableTarget) || isPathWithin(comparableTarget, comparableBase)) return 0;
  return path.relative(base, target).split(path.sep).filter(Boolean).length;
}

function assertSafeQuarantineRestoreLocation() {
  const uploads = resolveRuntimePath("uploads");
  const quarantine = getUploadQuarantineDir();
  if (quarantineDirContainsUploads(uploads, quarantine)) {
    throw new Error("Restore is not supported when the quarantine directory equals or contains uploads");
  }
  if (nestedPathDepth(uploads, quarantine) > 1) {
    throw new Error("Restore is not supported when the quarantine directory is nested below an uploads subdirectory; configure it outside uploads or as a direct child of uploads");
  }
}

function samePathComponent(left, right) {
  return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function hasSymlinkInPath(pathname) {
  const absolute = path.resolve(pathname);
  const root = path.parse(absolute).root;
  let current = root;
  for (const component of absolute.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, component);
    let stat;
    try { stat = fs.lstatSync(current); } catch (error) {
      if (error.code === "ENOENT") return false;
      throw error;
    }
    if (stat.isSymbolicLink()) return true;
  }
  return false;
}

function clearDirectoryPreservingQuarantine(destination, quarantinePath) {
  let rootStat;
  try { rootStat = fs.lstatSync(destination); } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) return;

  let relative = null;
  try {
    const destinationReal = fs.realpathSync.native ? fs.realpathSync.native(destination) : fs.realpathSync(destination);
    const quarantineReal = fs.realpathSync.native ? fs.realpathSync.native(quarantinePath) : fs.realpathSync(quarantinePath);
    if (isPathWithin(destinationReal, quarantineReal)) relative = path.relative(destinationReal, quarantineReal);
  } catch {}
  if (relative === null) {
    for (const destinationPath of pathVariants(destination)) {
      const nestedVariant = pathVariants(quarantinePath).find((variant) => isPathWithin(destinationPath, variant));
      if (nestedVariant) {
        const base = process.platform === "win32" ? destinationPath.toLowerCase() : destinationPath;
        const target = process.platform === "win32" ? nestedVariant.toLowerCase() : nestedVariant;
        relative = path.relative(base, target);
        break;
      }
    }
  }
  if (relative === null) relative = path.relative(path.resolve(destination), path.resolve(quarantinePath));
  const remaining = relative.split(path.sep).filter(Boolean);
  if (!remaining.length) return;
  const clear = (currentDirectory, components) => {
    for (const entry of fs.readdirSync(currentDirectory, { withFileTypes: true })) {
      const entryPath = path.join(currentDirectory, entry.name);
      if (components.length && samePathComponent(entry.name, components[0])) {
        if (components.length === 1 || entry.isSymbolicLink() || !entry.isDirectory()) continue;
        clear(entryPath, components.slice(1));
        continue;
      }
      fs.rmSync(entryPath, { recursive: true, force: true });
    }
  };
  clear(destination, remaining);
}

function copyDirectoryContents(source, destination, protectedPath = null) {
  if (!fs.existsSync(source)) return;
  fs.mkdirSync(destination, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const sourcePath = path.join(source, entry.name);
    const destinationPath = path.join(destination, entry.name);
    if (protectedPath && isPathWithinAliases(protectedPath, destinationPath)) continue;
    if (protectedPath && isPathWithinAliases(destinationPath, protectedPath)) {
      if (entry.isDirectory() && !hasSymlinkInPath(destinationPath)) {
        fs.mkdirSync(destinationPath, { recursive: true });
        copyDirectoryContents(sourcePath, destinationPath, protectedPath);
      }
      continue;
    }
    if (entry.isDirectory()) {
      fs.rmSync(destinationPath, { recursive: true, force: true });
      copyDirectoryContents(sourcePath, destinationPath, protectedPath);
    } else if (entry.isFile()) {
      fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
      fs.copyFileSync(sourcePath, destinationPath);
    }
  }
}

function restoreDataFiles(extractedRoot) {
  const extractedData = path.join(extractedRoot, "data");
  if (!fs.existsSync(extractedData)) return;

  closeDb();
  fs.mkdirSync(resolveRuntimePath("data"), { recursive: true });
  for (const name of fs.readdirSync(extractedData)) {
    const foldedName = name.toLowerCase();
    if (foldedName === "backups" || foldedName === "quarantine.json" || foldedName === ".rootark-quarantine-restore-journal.json" || foldedName.startsWith(".rootark-quarantine-restore-metadata-") || foldedName === "server-master.key" || foldedName.endsWith(".key") || foldedName.startsWith("rootark.sqlite")) continue;
    const sourcePath = path.join(extractedData, name);
    const destinationPath = resolveRuntimePath("data", name);
    if (fs.statSync(sourcePath).isFile()) {
      fs.copyFileSync(sourcePath, destinationPath);
    }
  }
}

function restoreUploads(extractedRoot) {
  const extractedUploads = path.join(extractedRoot, "uploads");
  if (!fs.existsSync(extractedUploads)) return;

  const destinationUploads = resolveRuntimePath("uploads");
  const quarantineDir = path.resolve(getUploadQuarantineDir());
  const uploadsContainQuarantine = isPathWithinAliases(destinationUploads, quarantineDir);
  const quarantineContainsUploads = isPathWithinAliases(quarantineDir, destinationUploads);
  if (uploadsContainQuarantine && !quarantineContainsUploads) {
    clearDirectoryPreservingQuarantine(destinationUploads, quarantineDir);
    const uploadsStat = (() => { try { return fs.lstatSync(destinationUploads); } catch { return null; } })();
    if (uploadsStat?.isSymbolicLink()) return;
    copyDirectoryContents(extractedUploads, destinationUploads, quarantineDir);
    return;
  }
  if (quarantineContainsUploads) return;

  fs.rmSync(destinationUploads, { recursive: true, force: true });
  copyDirectoryContents(extractedUploads, destinationUploads);
}

function validateQuarantineArchive(extractedRoot, manifest) {
  if (manifest?.quarantine_format_version !== undefined && manifest.quarantine_format_version !== 1) {
    throw new Error("Quarantine archive format is not supported");
  }
  const hasQuarantineFormat = manifest?.quarantine_format_version === 1;
  const metadataPath = path.join(extractedRoot, "data", "quarantine.json");
  const metadata = readQuarantineMetadata(metadataPath);
  if (!metadata) {
    if (hasQuarantineFormat) throw new Error("Quarantine metadata is missing");
    return false;
  }
  const payloadRoot = path.join(extractedRoot, "data", "quarantine");
  if (!hasQuarantineFormat && metadata.items.length > 0 && !pathExists(payloadRoot)) {
    throw new Error("Quarantine archive payloads are missing");
  }
  validateQuarantinePayloads(metadata.items, payloadRoot);
  return true;
}

function pathExists(pathname) {
  try { fs.lstatSync(pathname); return true; }
  catch (error) { if (error.code === "ENOENT") return false; throw error; }
}

function sameRuntimeRoot(left, right) {
  const a = path.normalize(String(left || ""));
  const b = path.normalize(String(right || ""));
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function validateQuarantineDestination(destination) {
  const resolved = path.resolve(destination);
  const root = path.parse(resolved).root;
  if (resolved === root) throw new Error("Quarantine directory cannot be a filesystem root");
  if (pathExists(resolved)) {
    if (!fs.statSync(resolved).isDirectory()) throw new Error("Quarantine destination is not a directory");
    const actual = fs.realpathSync(resolved);
    if (actual === path.parse(actual).root) throw new Error("Quarantine directory cannot be a filesystem root");
  }
  return resolved;
}

function prepareQuarantineRestore(extractedRoot) {
  const metadataPath = path.join(extractedRoot, "data", "quarantine.json");
  const metadata = readQuarantineMetadata(metadataPath);
  if (!metadata) return null;

  const destination = validateQuarantineDestination(getUploadQuarantineDir());
  const metadataDestination = resolveRuntimePath("data", "quarantine.json");
  const dataStat = fs.lstatSync(path.dirname(metadataDestination));
  if (!dataStat.isDirectory() || dataStat.isSymbolicLink()) throw new Error("Quarantine metadata directory is unsafe");
  const archivedPayloads = validateQuarantinePayloads(metadata.items, path.join(extractedRoot, "data", "quarantine"));
  const currentMetadata = readQuarantineMetadata(metadataDestination);
  const currentPayloads = currentMetadata ? validateQuarantinePayloads(currentMetadata.items, destination) : [];
  const preservedSensitiveItems = (currentMetadata?.items || []).filter((item) => isSensitiveQuarantineItem(item));
  const preservedNames = new Set(preservedSensitiveItems.map((item) => item.storedQuarantineFilename.toLowerCase()));
  const preservedIds = new Set(preservedSensitiveItems.map((item) => item.id).filter(Boolean));
  const archivedItems = metadata.items.filter((item) => !isSensitiveQuarantineItem(item)
    && !preservedNames.has(item.storedQuarantineFilename.toLowerCase())
    && !(item.id && preservedIds.has(item.id)));
  const archivedNames = new Set(archivedItems.map((item) => item.storedQuarantineFilename.toLowerCase()));
  const extractedPayloads = archivedPayloads.filter((payload) => archivedNames.has(payload.filename.toLowerCase()));
  const restoredPayloads = [
    ...extractedPayloads,
    ...currentPayloads.filter((payload) => preservedNames.has(payload.filename.toLowerCase())),
  ];
  const currentFilenames = new Set(currentPayloads.map((payload) => payload.filename.toLowerCase()));
  for (const payload of restoredPayloads) {
    let targetExists = false;
    try { fs.lstatSync(path.join(destination, payload.filename)); targetExists = true; }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    if (targetExists && !currentFilenames.has(payload.filename.toLowerCase())) {
      throw new Error("Quarantine payload destination already exists");
    }
  }

  return {
    destination,
    extractedPayloads,
    restoredPayloads,
    metadataContents: Buffer.from(JSON.stringify({ ...metadata, items: [...archivedItems, ...preservedSensitiveItems] })),
    metadataDestination,
    oldMetadataExists: Boolean(currentMetadata),
    currentPayloads,
  };
}

function quarantineJournalPath() {
  return resolveRuntimePath("data", ".rootark-quarantine-restore-journal.json");
}

function quarantineMetadataStagePath(transactionId, kind) {
  if (!/^[a-f0-9-]{36}$/i.test(transactionId || "") || !["old", "new"].includes(kind)) {
    throw new Error("Quarantine metadata staging path is invalid");
  }
  return resolveRuntimePath("data", `.rootark-quarantine-restore-metadata-${transactionId}-${kind}.tmp`);
}

function hasPendingQuarantineRestore() {
  return pathExists(quarantineJournalPath());
}

function quarantineStagePath(destination, transactionId) {
  const root = path.resolve(destination);
  const stage = path.resolve(root, `.rootark-quarantine-restore-${transactionId}`);
  if (!stage.startsWith(`${root}${path.sep}`)) throw new Error("Quarantine restore staging escaped its boundary");
  return stage;
}

function validQuarantineRestoreJournal(value) {
  if (!value || value.version !== 1 || !/^[a-f0-9-]{36}$/i.test(value.transactionId || "")) return false;
  if (typeof value.destination !== "string" || !sameRuntimeRoot(value.destination, getUploadQuarantineDir())) return false;
  if (typeof value.oldMetadataExists !== "boolean" || !/^[a-f0-9]{64}$/.test(value.metadataHash || "")) return false;
  if (!Array.isArray(value.oldPayloads) || !Array.isArray(value.newPayloads)) return false;
  const oldNames = new Set();
  for (const filename of value.oldPayloads) {
    if (!isSafeQuarantineFilename(filename) || oldNames.has(filename)) return false;
    oldNames.add(filename);
  }
  const newNames = new Set();
  for (const payload of value.newPayloads) {
    if (!payload || !isSafeQuarantineFilename(payload.filename) || !/^[a-f0-9]{64}$/.test(payload.sha256 || "") || newNames.has(payload.filename)) return false;
    newNames.add(payload.filename);
  }
  return true;
}

function isSafeQuarantineFilename(filename) {
  return typeof filename === "string" && Boolean(filename) && filename !== "." && filename !== ".."
    && path.basename(filename) === filename && !/[\\/<>:"|?*\u0000-\u001f]/.test(filename) && !/[. ]$/.test(filename)
    && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(filename);
}

function writeQuarantineJournal(journalPath, journal) {
  const temporary = `${journalPath}.${journal.transactionId}.tmp`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(journal)}\n`, { encoding: "utf8", flag: "wx" });
    fsyncFile(temporary);
    fs.renameSync(temporary, journalPath);
    fsyncDirectory(path.dirname(journalPath));
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
}

function readQuarantineJournal(journalPath) {
  let journal;
  let contents;
  try { contents = readQuarantineRegularFile(journalPath, "utf8"); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    throw new Error("Quarantine restore journal is invalid");
  }
  try { journal = JSON.parse(contents); }
  catch { throw new Error("Quarantine restore journal is invalid"); }
  if (!validQuarantineRestoreJournal(journal)) throw new Error("Quarantine restore journal is invalid");
  return journal;
}

function quarantineJournalStage(journal) {
  const destination = validateQuarantineDestination(journal.destination);
  const stage = quarantineStagePath(destination, journal.transactionId);
  const stat = fs.lstatSync(stage);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Quarantine restore staging is invalid");
  return stage;
}

function expectedFileHash(pathname, expectedHash) {
  if (!pathExists(pathname)) return false;
  const stat = fs.lstatSync(pathname);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error("Quarantine restore found an unexpected file");
  return fileSha256(pathname) === expectedHash;
}

function rollbackQuarantineRestore(journal, stage) {
  const destination = journal.destination;
  for (let index = 0; index < journal.newPayloads.length; index += 1) {
    const payload = journal.newPayloads[index];
    const stagedNew = path.join(stage, `new-${index}`);
    if (pathExists(stagedNew)) continue;
    const target = path.join(destination, payload.filename);
    if (pathExists(target)) {
      if (!expectedFileHash(target, payload.sha256)) throw new Error("Quarantine rollback found a changed destination payload");
      fs.rmSync(target, { force: false });
    }
  }
  for (let index = journal.oldPayloads.length - 1; index >= 0; index -= 1) {
    const filename = journal.oldPayloads[index];
    const stagedOld = path.join(stage, `old-${index}`);
    if (!pathExists(stagedOld)) continue;
    const target = path.join(destination, filename);
    if (pathExists(target)) {
      const newPayload = journal.newPayloads.find((payload) => payload.filename === filename);
      if (!newPayload || !expectedFileHash(target, newPayload.sha256)) throw new Error("Quarantine rollback found a changed destination payload");
      fs.rmSync(target, { force: false });
    }
    fs.renameSync(stagedOld, target);
  }

  const metadataDestination = resolveRuntimePath("data", "quarantine.json");
  const stagedOldMetadata = quarantineMetadataStagePath(journal.transactionId, "old");
  const stagedNewMetadata = quarantineMetadataStagePath(journal.transactionId, "new");
  if (pathExists(stagedOldMetadata)) {
    if (pathExists(metadataDestination)) {
      if (!expectedFileHash(metadataDestination, journal.metadataHash)) throw new Error("Quarantine rollback found changed metadata");
      fs.rmSync(metadataDestination, { force: false });
    }
    fs.renameSync(stagedOldMetadata, metadataDestination);
  } else if (!journal.oldMetadataExists && pathExists(metadataDestination)) {
    if (!expectedFileHash(metadataDestination, journal.metadataHash)) throw new Error("Quarantine rollback found changed metadata");
    fs.rmSync(metadataDestination, { force: false });
  } else if (journal.oldMetadataExists && !pathExists(metadataDestination)) {
    throw new Error("Quarantine rollback could not find prior metadata");
  }
  if (pathExists(stagedNewMetadata)) fs.rmSync(stagedNewMetadata, { force: false });
  fsyncDirectory(destination);
  fsyncDirectory(path.dirname(metadataDestination));
}

function cleanupOrphanQuarantineStages(destination) {
  if (!pathExists(destination)) return;
  for (const entry of fs.readdirSync(destination, { withFileTypes: true })) {
    if (!/^\.rootark-quarantine-restore-[a-f0-9-]{36}$/i.test(entry.name) || !entry.isDirectory() || entry.isSymbolicLink()) continue;
    fs.rmSync(path.join(destination, entry.name), { recursive: true, force: true });
  }
}

function cleanupQuarantineMetadataStages(transactionId) {
  fs.rmSync(quarantineMetadataStagePath(transactionId, "old"), { force: true });
  fs.rmSync(quarantineMetadataStagePath(transactionId, "new"), { force: true });
  fsyncDirectory(path.dirname(quarantineJournalPath()));
}

function cleanupOrphanQuarantineMetadataStages(dataDirectory) {
  if (!pathExists(dataDirectory)) return;
  for (const name of fs.readdirSync(dataDirectory)) {
    if (!/^\.rootark-quarantine-restore-metadata-[a-f0-9-]{36}-(?:old|new)\.tmp$/i.test(name)) continue;
    const stagedPath = path.join(dataDirectory, name);
    const stat = fs.lstatSync(stagedPath);
    if (stat.isFile() && !stat.isSymbolicLink()) fs.rmSync(stagedPath, { force: false });
  }
  fsyncDirectory(dataDirectory);
}

function recoverQuarantineRestore() {
  if (!fs.existsSync(backupService.BACKUPS_DIR)) {
    if (hasPendingQuarantineRestore()) throw new Error("Quarantine recovery cannot acquire its backup lock");
    return false;
  }
  const release = backupService.acquireLock("restore");
  try {
    const destination = validateQuarantineDestination(getUploadQuarantineDir());
    const journalPath = quarantineJournalPath();
    const journal = readQuarantineJournal(journalPath);
    if (!journal) {
      cleanupOrphanQuarantineStages(destination);
      cleanupOrphanQuarantineMetadataStages(path.dirname(journalPath));
      return false;
    }
    const stage = quarantineJournalStage(journal);
    const commitMarker = path.join(stage, "committed");
    if (pathExists(commitMarker)) {
      const marker = fs.readFileSync(commitMarker, "utf8");
      if (marker !== journal.transactionId) throw new Error("Quarantine restore commit marker is invalid");
      cleanupQuarantineMetadataStages(journal.transactionId);
      fs.rmSync(journalPath, { force: false });
      fsyncDirectory(path.dirname(journalPath));
      fs.rmSync(stage, { recursive: true, force: true });
      return true;
    }
    rollbackQuarantineRestore(journal, stage);
    cleanupQuarantineMetadataStages(journal.transactionId);
    fs.rmSync(journalPath, { force: false });
    fsyncDirectory(path.dirname(journalPath));
    fs.rmSync(stage, { recursive: true, force: true });
    return true;
  } finally {
    release();
  }
}

function restoreQuarantine(plan) {
  if (!plan) return;
  const destination = validateQuarantineDestination(plan.destination);
  fs.mkdirSync(destination, { recursive: true });
  validateQuarantineDestination(destination);
  const transactionId = crypto.randomUUID();
  const stagingDirectory = quarantineStagePath(destination, transactionId);
  const journalPath = quarantineJournalPath();
  const stagedOldMetadata = quarantineMetadataStagePath(transactionId, "old");
  const stagedNewMetadata = quarantineMetadataStagePath(transactionId, "new");
  const journal = {
    version: 1,
    transactionId,
    destination,
    oldMetadataExists: plan.oldMetadataExists,
    metadataHash: crypto.createHash("sha256").update(plan.metadataContents).digest("hex"),
    oldPayloads: plan.currentPayloads.map((payload) => payload.filename),
    newPayloads: plan.restoredPayloads.map((payload) => ({ filename: payload.filename, sha256: fileSha256(payload.absolutePath) })),
  };
  let journalWritten = false;
  try {
    if (pathExists(journalPath)) throw new Error("A quarantine restore recovery is pending");
    fs.mkdirSync(stagingDirectory);
    plan.restoredPayloads.forEach((payload, index) => {
      const stagedPath = path.join(stagingDirectory, `new-${index}`);
      fs.copyFileSync(payload.absolutePath, stagedPath, fs.constants.COPYFILE_EXCL);
      fsyncFile(stagedPath);
    });
    fsyncDirectory(stagingDirectory);
    fsyncDirectory(destination);
    writeQuarantineJournal(journalPath, journal);
    journalWritten = true;

    fs.writeFileSync(stagedNewMetadata, plan.metadataContents, { flag: "wx" });
    fsyncFile(stagedNewMetadata);
    fsyncDirectory(path.dirname(plan.metadataDestination));
    plan.currentPayloads.forEach((payload, index) => {
      const stagedOldPath = path.join(stagingDirectory, `old-${index}`);
      fsyncFile(payload.absolutePath);
      fs.renameSync(payload.absolutePath, stagedOldPath);
    });
    fsyncDirectory(destination);
    fsyncDirectory(stagingDirectory);
    for (let index = 0; index < plan.restoredPayloads.length; index += 1) {
      const payload = plan.restoredPayloads[index];
      const targetPath = path.join(destination, payload.filename);
      fs.renameSync(path.join(stagingDirectory, `new-${index}`), targetPath);
    }
    fsyncDirectory(destination);
    fsyncDirectory(stagingDirectory);
    if (plan.oldMetadataExists) {
      fsyncFile(plan.metadataDestination);
      fs.renameSync(plan.metadataDestination, stagedOldMetadata);
      fsyncDirectory(path.dirname(plan.metadataDestination));
    }
    fs.renameSync(stagedNewMetadata, plan.metadataDestination);
    fsyncDirectory(path.dirname(plan.metadataDestination));
    const markerTemporary = path.join(stagingDirectory, "committed.tmp");
    fs.writeFileSync(markerTemporary, transactionId, { flag: "wx" });
    fsyncFile(markerTemporary);
    fs.renameSync(markerTemporary, path.join(stagingDirectory, "committed"));
    fsyncDirectory(stagingDirectory);
  } catch (error) {
    if (journalWritten) {
      try {
        const activeJournal = readQuarantineJournal(journalPath);
        if (activeJournal) {
          const stage = quarantineJournalStage(activeJournal);
          if (pathExists(path.join(stage, "committed"))) {
            const marker = fs.readFileSync(path.join(stage, "committed"), "utf8");
            if (marker !== activeJournal.transactionId) throw new Error("Quarantine restore commit marker is invalid");
            fs.rmSync(path.join(stage, "committed"), { force: false });
            fsyncDirectory(stage);
          }
          rollbackQuarantineRestore(activeJournal, stage);
          cleanupQuarantineMetadataStages(activeJournal.transactionId);
        }
        fs.rmSync(journalPath, { force: true });
        fsyncDirectory(path.dirname(journalPath));
        fs.rmSync(stagingDirectory, { recursive: true, force: true });
      } catch (recoveryError) {
        error.recoveryError = recoveryError;
      }
    } else {
      fs.rmSync(stagingDirectory, { recursive: true, force: true });
    }
    throw error;
  }
  try {
    cleanupQuarantineMetadataStages(transactionId);
    fs.rmSync(journalPath, { force: false });
    fsyncDirectory(path.dirname(journalPath));
    fs.rmSync(stagingDirectory, { recursive: true, force: true });
  } catch {
    console.error("[restore] QUARANTINE_RESTORE_CLEANUP_FAILED");
  }
}

function validateDatabase(pathname) {
  const database = new Database(pathname, { readonly: true, fileMustExist: true });
  try {
    if (database.pragma("integrity_check", { simple: true }) !== "ok") throw new Error("Integridade SQLite invalida");
    if (database.pragma("foreign_key_check", { simple: true }) !== undefined) throw new Error("Chaves estrangeiras SQLite invalidas");
  } finally {
    database.close();
  }
}

const SQLITE_SUFFIXES = ["", "-wal", "-shm"];
const RESTORE_JOURNAL_VERSION = 1;

function databaseJournalPath(destinationPath) {
  return `${destinationPath}.restore-journal.json`;
}

function artifactPath(prefix, suffix) {
  return `${prefix}${suffix}`;
}

function fileSha256(pathname) {
  if (!fs.existsSync(pathname)) return null;
  return crypto.createHash("sha256").update(fs.readFileSync(pathname)).digest("hex");
}

function fsyncFile(pathname) {
  const fd = fs.openSync(pathname, "r");
  try {
    try { fs.fsyncSync(fd); } catch (error) {
      if (!(["EPERM", "ENOTSUP", "EINVAL"].includes(error.code) && process.platform === "win32")) throw error;
    }
  } finally { fs.closeSync(fd); }
}

function fsyncDirectory(dirname) {
  if (process.platform === "win32") return;
  try {
    const fd = fs.openSync(dirname, "r");
    try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  } catch {}
}

function writeRestoreJournal(journal) {
  const pathname = journal.journalPath;
  const temporary = `${pathname}.${journal.transactionId}.tmp`;
  fs.mkdirSync(path.dirname(pathname), { recursive: true });
  fs.writeFileSync(temporary, `${JSON.stringify(journal, null, 2)}\n`, { flag: "w" });
  fsyncFile(temporary);
  fs.renameSync(temporary, pathname);
  fsyncDirectory(path.dirname(pathname));
}

function readRestoreJournal(destinationPath) {
  const pathname = databaseJournalPath(destinationPath);
  if (!fs.existsSync(pathname)) return null;
  let journal;
  try {
    journal = JSON.parse(fs.readFileSync(pathname, "utf8"));
  } catch (error) {
    throw new Error(`Journal SQLite invalido; recuperacao interrompida: ${error.message}`);
  }
  const expectedDestination = path.resolve(destinationPath);
  if (journal.version !== RESTORE_JOURNAL_VERSION ||
      journal.destination !== expectedDestination ||
      !/^[a-f0-9-]{36}$/i.test(String(journal.transactionId || "")) ||
      !journal.stagePrefix || !journal.rollbackPrefix ||
      journal.journalPath !== pathname ||
      path.resolve(journal.stagePrefix) !== `${expectedDestination}.restore-stage-${journal.transactionId}` ||
      path.resolve(journal.rollbackPrefix) !== `${expectedDestination}.restore-rollback-${journal.transactionId}` ||
      !Array.isArray(journal.completedOperations)) {
    throw new Error("Journal SQLite ambiguo; recuperacao interrompida");
  }
  return journal;
}

function failureHook(options = {}) {
  const requested = options.failAfter ?? options.failureAfter ?? options.failAt ?? process.env.ROOTARK_SQLITE_FAIL_AFTER;
  let count = 0;
  return (name, journal) => {
    count += 1;
    if (typeof options.failureInjector === "function") options.failureInjector(name, { ...journal, step: name, stepNumber: count });
    if (requested !== undefined && (String(requested) === name || Number(requested) === count)) {
      const error = new Error(`Falha injetada no passo SQLite: ${name}`);
      error.code = "SQLITE_RESTORE_INJECTED_FAILURE";
      error.step = name;
      throw error;
    }
  };
}

function journalHas(journal, operation) {
  return journal.completedOperations.includes(operation);
}

function updateJournal(journal, phase) {
  journal.phase = phase;
  journal.updatedAt = new Date().toISOString();
  writeRestoreJournal(journal);
}

function recordOperation(journal, operation) {
  if (!journalHas(journal, operation)) journal.completedOperations.push(operation);
  journal.updatedAt = new Date().toISOString();
  writeRestoreJournal(journal);
}

function validateJournalArtifacts(journal) {
  const expected = new Set(SQLITE_SUFFIXES);
  for (const suffix of Object.keys(journal.originalPresent || {})) {
    if (!expected.has(suffix)) throw new Error("Journal SQLite contem sidecar desconhecido");
  }
  for (const suffix of SQLITE_SUFFIXES) {
    if (typeof journal.originalPresent?.[suffix] !== "boolean" || typeof journal.stagedPresent?.[suffix] !== "boolean") {
      throw new Error("Journal SQLite incompleto; recuperacao interrompida");
    }
  }
}

function rollbackRestoreJournal(journal, options = {}) {
  validateJournalArtifacts(journal);
  const hook = failureHook(options);
  updateJournal(journal, "rolling_back");

  for (const suffix of SQLITE_SUFFIXES) {
    const destination = artifactPath(journal.destination, suffix);
    const rollback = artifactPath(journal.rollbackPrefix, suffix);
    const stage = artifactPath(journal.stagePrefix, suffix);
    const originalMove = `original.move${suffix || ".primary"}`;
    const replacementMove = `replacement.move${suffix || ".primary"}`;
    const rollbackMove = `rollback.restore${suffix || ".primary"}`;

    if (journal.originalPresent[suffix]) {
      if (fs.existsSync(rollback)) {
        if (fs.existsSync(destination)) {
          fs.rmSync(destination, { force: true });
          recordOperation(journal, `rollback.remove-replacement${suffix || ".primary"}`);
          hook(`rollback.remove-replacement${suffix || ".primary"}`, journal);
        }
        fs.renameSync(rollback, destination);
        recordOperation(journal, rollbackMove);
        hook(rollbackMove, journal);
      } else if (!journalHas(journal, originalMove) && !journalHas(journal, rollbackMove)) {
        // The original was not moved. Leave it untouched.
      } else if (!fs.existsSync(destination)) {
        throw new Error(`Journal SQLite perdeu o original ${suffix || "principal"}`);
      }
    } else if (fs.existsSync(destination) && (journalHas(journal, replacementMove) || journal.phase !== "staged")) {
      fs.rmSync(destination, { force: true });
      recordOperation(journal, `rollback.remove-new${suffix || ".primary"}`);
      hook(`rollback.remove-new${suffix || ".primary"}`, journal);
    }
    fs.rmSync(stage, { force: true });
  }

  updateJournal(journal, "rolled_back");
  fs.rmSync(journal.journalPath, { force: true });
  fsyncDirectory(path.dirname(journal.journalPath));
}

function recoverDatabaseRestore(destinationPath, options = {}) {
  const resolvedDestination = path.resolve(destinationPath);
  const journal = readRestoreJournal(resolvedDestination);
  if (!journal) return { recovered: false, reason: "no_journal" };

  if (!["staged", "validated", "originals_moving", "originals_preserved", "replacement_moving", "replacement_installed", "reopened_verified", "rolling_back", "rolled_back", "committed"].includes(journal.phase)) {
    throw new Error("Journal SQLite contem fase desconhecida; recuperacao interrompida");
  }

  if (journal.phase === "committed") {
    validateJournalArtifacts(journal);
    for (const suffix of SQLITE_SUFFIXES) {
      fs.rmSync(artifactPath(journal.stagePrefix, suffix), { force: true });
      fs.rmSync(artifactPath(journal.rollbackPrefix, suffix), { force: true });
    }
    fs.rmSync(journal.journalPath, { force: true });
    fsyncDirectory(path.dirname(journal.journalPath));
    return { recovered: true, phase: "committed" };
  }

  rollbackRestoreJournal(journal, options);
  return { recovered: true, phase: "rolled_back" };
}

function recoverDatabaseRollback(destinationPath) {
  const journalResult = recoverDatabaseRestore(destinationPath);
  if (journalResult.recovered) return journalResult;
  if (fs.existsSync(destinationPath)) return { recovered: false, reason: "destination_exists" };
  const prefix = `${path.basename(destinationPath)}.restore-rollback-`;
  const candidates = fs.readdirSync(path.dirname(destinationPath)).filter((name) => name.startsWith(prefix) && !name.endsWith("-wal") && !name.endsWith("-shm"));
  if (candidates.length > 1) throw new Error("Rollbacks SQLite ambiguos; recuperacao interrompida");
  if (!candidates.length) return { recovered: false, reason: "no_rollback" };
  const rollbackPath = path.join(path.dirname(destinationPath), candidates[0]);
  fs.renameSync(rollbackPath, destinationPath);
  for (const suffix of ["-wal", "-shm"]) {
    const sidecar = `${rollbackPath}${suffix}`;
    if (fs.existsSync(sidecar)) fs.renameSync(sidecar, `${destinationPath}${suffix}`);
  }
  return { recovered: true, phase: "legacy_rollback" };
}

function restoreDatabaseFiles(extractedRoot, options = {}) {
  if (!isDbEnabled()) return false;
  const sourcePath = path.join(extractedRoot, "data", "rootark.sqlite");
  if (!fs.existsSync(sourcePath)) return false;

  const destinationPath = getDatabasePath();
  closeDb();
  fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
  recoverDatabaseRollback(destinationPath);
  const token = crypto.randomUUID();
  const stagePath = `${destinationPath}.restore-stage-${token}`;
  const rollbackPath = `${destinationPath}.restore-rollback-${token}`;
  const journal = {
    version: RESTORE_JOURNAL_VERSION,
    transactionId: token,
    destination: path.resolve(destinationPath),
    journalPath: databaseJournalPath(destinationPath),
    stagePrefix: stagePath,
    rollbackPrefix: rollbackPath,
    phase: "staged",
    startedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    completedOperations: [],
    originalPresent: Object.fromEntries(SQLITE_SUFFIXES.map((suffix) => [suffix, fs.existsSync(artifactPath(destinationPath, suffix))])),
    stagedPresent: Object.fromEntries(SQLITE_SUFFIXES.map((suffix) => [suffix, fs.existsSync(artifactPath(sourcePath, suffix))])),
    originalSha256: Object.fromEntries(SQLITE_SUFFIXES.map((suffix) => [suffix, fileSha256(artifactPath(destinationPath, suffix))])),
  };
  validateJournalArtifacts(journal);
  writeRestoreJournal(journal);
  const hook = failureHook(options);

  try {
  for (const suffix of SQLITE_SUFFIXES) {
    const source = artifactPath(sourcePath, suffix);
    if (fs.existsSync(source)) {
      fs.copyFileSync(source, artifactPath(stagePath, suffix));
      fsyncFile(artifactPath(stagePath, suffix));
      recordOperation(journal, `stage.copy${suffix || ".primary"}`);
      hook(`stage.copy${suffix || ".primary"}`, journal);
    }
  }
    validateDatabase(stagePath);
    recordOperation(journal, "stage.validate");
    hook("stage.validate", journal);
    updateJournal(journal, "staged");

    updateJournal(journal, "originals_moving");
    for (const suffix of SQLITE_SUFFIXES) {
      const destination = artifactPath(destinationPath, suffix);
      if (fs.existsSync(destination)) {
        fs.renameSync(destination, artifactPath(rollbackPath, suffix));
        recordOperation(journal, `original.move${suffix || ".primary"}`);
        hook(`original.move${suffix || ".primary"}`, journal);
      }
    }
    updateJournal(journal, "originals_preserved");
    updateJournal(journal, "replacement_moving");
    for (const suffix of SQLITE_SUFFIXES) {
      const staged = artifactPath(stagePath, suffix);
      if (fs.existsSync(staged)) {
        fs.renameSync(staged, artifactPath(destinationPath, suffix));
        recordOperation(journal, `replacement.move${suffix || ".primary"}`);
        hook(`replacement.move${suffix || ".primary"}`, journal);
      }
    }
    updateJournal(journal, "replacement_installed");
    validateDatabase(destinationPath);
    recordOperation(journal, "replacement.reopen-validate");
    hook("replacement.reopen-validate", journal);
    updateJournal(journal, "reopened_verified");
    updateJournal(journal, "committed");
    for (const suffix of SQLITE_SUFFIXES) {
      fs.rmSync(artifactPath(rollbackPath, suffix), { force: true });
      fs.rmSync(artifactPath(stagePath, suffix), { force: true });
    }
    fs.rmSync(journal.journalPath, { force: true });
    fsyncDirectory(path.dirname(destinationPath));
  } catch (error) {
    if (!options.simulateCrash && !options.leaveJournalOnFailure) {
      try { recoverDatabaseRestore(destinationPath); } catch (recoveryError) { error.recoveryError = recoveryError; }
    }
    throw error;
  }
  return true;
}

async function restoreBackup(id, options = {}) {
  if (String(options.confirmation || "") !== "RESTORE") {
    throw new Error("Confirmacao invalida. Digite RESTORE para restaurar.");
  }

  assertSafeQuarantineRestoreLocation();

  const preRestore = await backupService.createBackup({
    type: "pre-restore",
    createdBy: options.username || null,
    notes: `Backup automatico antes de restaurar ${id}`,
  });

  const release = backupService.acquireLock("restore");
  const restoreDir = path.join(RESTORE_TMP_DIR, String(id));
  try {
    const { backup, archivePath } = backupService.getBackupOrThrow(id);
    const { zip, manifest } = await validateBackupArchive(backup, archivePath);
    await extractArchive(zip, restoreDir);
    const hasQuarantineState = validateQuarantineArchive(restoreDir, manifest);
    const quarantinePlan = hasQuarantineState ? prepareQuarantineRestore(restoreDir) : null;
    restoreQuarantine(quarantinePlan);
    restoreDataFiles(restoreDir);
    restoreUploads(restoreDir);
    const restoredDatabase = restoreDatabaseFiles(restoreDir);
    const cloudSync = cloudStorage?.enabled() && manifest.cloud_complete
      ? createRestoreSync(manifest)
      : { state: "not_required" };
    if (cloudSync.state === "pending") {
      backupRepository.saveBackup({ ...backup, metadata: { ...backup.metadata, restoreSync: cloudSync } });
    }
    return {
      backup,
      manifest,
      preRestore,
      restartRecommended: restoredDatabase,
      cloudSync,
    };
  } finally {
    fs.rmSync(restoreDir, { recursive: true, force: true });
    fs.rmSync(RESTORE_TMP_DIR, { recursive: true, force: true });
    release();
  }
}

async function getBackupManifest(id) {
  const { backup, archivePath } = backupService.getBackupOrThrow(id);
  const { manifest } = await validateBackupArchive(backup, archivePath);
  return manifest;
}

module.exports = {
  cancelRestoreSync,
  createRestoreSync,
  getBackupManifest,
  hasPendingQuarantineRestore,
  prepareQuarantineRestore,
  processRestoreSync,
  recoverQuarantineRestore,
  restoreBackup,
  setCloudStorage,
  validateBackupArchive,
  validateDatabase,
  recoverDatabaseRollback,
  recoverDatabaseRestore,
  restoreDatabaseFiles,
  databaseJournalPath,
  SQLITE_SUFFIXES,
};
