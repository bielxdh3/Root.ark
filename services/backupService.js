const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Readable } = require("stream");
const Database = require("better-sqlite3");
const { ZipArchive } = require("archiver");
const backupRepository = require("../repositories/backupRepository");
const { getDatabasePath, getDb, isDbEnabled } = require("../db");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { attestCiphertextOnlyFile } = require("../src/services/deploymentResilience");
const { getUploadQuarantineDir, isSensitiveQuarantineItem, readQuarantineMetadata, validateQuarantinePayloads } = require("../src/quarantine-paths");

const BACKUPS_DIR = resolveRuntimePath("data", "backups");
const LOCK_FILE = path.join(BACKUPS_DIR, ".backup.lock");
const LOCK_TAKEOVER_DIR = `${LOCK_FILE}.takeover`;
const LOCK_TAKEOVER_META = path.join(LOCK_TAKEOVER_DIR, "authority.json");
const LOCK_TAKEOVER_EVIDENCE = path.join(LOCK_TAKEOVER_DIR, "evidence");
const RETENTION_TRANSACTIONS_DIR = path.join(BACKUPS_DIR, ".retention-transactions");
const OPERATION_LOCK_FORMAT_VERSION = 1;
const MALFORMED_LOCK_TTL_MS = 60 * 1000;
const MALFORMED_TAKEOVER_TTL_MS = 60 * 1000;
const MAX_LOCK_TTL_MS = 24 * 60 * 60 * 1000;
let operationLock = null;
let cloudStorage = null;

function boundedLockDuration(name, fallback) {
  const value = Number(process.env[name]);
  if (!Number.isFinite(value)) return fallback;
  return Math.max(1000, Math.min(MAX_LOCK_TTL_MS, value));
}

function processStartIdentity(pid) {
  if (process.platform !== "linux") return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 1).trim().split(/\s+/)[19] || null;
  } catch {
    return null;
  }
}

const CURRENT_PROCESS_START_IDENTITY = processStartIdentity(process.pid);

function setCloudStorage(storage) {
  cloudStorage = storage || null;
}
const RETENTION_TOMBSTONE_SUFFIX = ".retention-tombstone";

function envBool(name, fallback) {
  const value = process.env[name];
  if (value === undefined) return fallback;
  return String(value).toLowerCase() === "true";
}

function envNumber(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) ? value : fallback;
}

function timestampForName() {
  const date = new Date();
  const pad = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}-${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}-${String(date.getMilliseconds()).padStart(3, "0")}-${crypto.randomUUID().slice(0, 8)}`;
}

function normalizeEntryPath(value) {
  return String(value || "").replace(/\\/g, "/").replace(/^\/+/, "");
}

function collisionKey(value) {
  return normalizeEntryPath(value).toLowerCase();
}

function isSensitivePath(relativePath) {
  const normalized = normalizeEntryPath(relativePath);
  const base = path.basename(normalized).toLowerCase();
  if (!normalized) return true;
  if (normalized.startsWith(".git/") || normalized === ".git") return true;
  if (normalized.startsWith("node_modules/") || normalized === "node_modules") return true;
  if (normalized.startsWith("data/backups/") || normalized === "data/backups") return true;
  if (normalized.startsWith("temp/.chunks/") || normalized.startsWith("temp/.incoming/")) return true;
  if (base === ".env" || base.startsWith(".env.") || base.endsWith(".env")) return true;
  if (base.includes("credentials") || base.includes("service-account")) return true;
  if (base.endsWith(".key") || base.endsWith(".pem") || base.endsWith(".p12")) return true;
  if (base === "server-master.key") return true;
  if (base === ".rootark-quarantine-restore-journal.json" || base.startsWith(".rootark-quarantine-restore-metadata-")) return true;
  return false;
}

function isPathWithin(basePath, targetPath) {
  const base = path.resolve(basePath);
  const target = path.resolve(targetPath);
  const comparableBase = process.platform === "win32" ? base.toLowerCase() : base;
  const comparableTarget = process.platform === "win32" ? target.toLowerCase() : target;
  const relative = path.relative(comparableBase, comparableTarget);
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function pathIdentityKey(value) {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function fileIdentity(stat) {
  return stat?.isFile?.() && Number(stat.ino) ? `${stat.dev}:${stat.ino}` : null;
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.ino !== 0n;
}

function sameFileSnapshot(left, right) {
  return sameFileIdentity(left, right) && left.size === right.size && left.mode === right.mode
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs && left.birthtimeNs === right.birthtimeNs;
}

function samePath(left, right) {
  const a = path.normalize(left);
  const b = path.normalize(right);
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function archiveRootInfo(rootPath, { allowRootSymlink = false } = {}) {
  const absolutePath = path.resolve(rootPath);
  const pathStat = fs.lstatSync(absolutePath, { bigint: true });
  const rootSymlink = pathStat.isSymbolicLink();
  if (rootSymlink && !allowRootSymlink) throw new Error("Backup source root cannot be a symbolic link");
  if (!rootSymlink && !pathStat.isDirectory()) throw new Error("Backup source root is not a directory");
  const realPath = fs.realpathSync.native(absolutePath);
  const realStat = fs.statSync(realPath, { bigint: true });
  if (!realStat.isDirectory() || realStat.ino === 0n) throw new Error("Backup source root has no stable directory identity");
  return { absolutePath, realPath, pathStat, realStat, rootSymlink };
}

function assertArchiveRootUnchanged(root) {
  const currentPathStat = fs.lstatSync(root.absolutePath, { bigint: true });
  if (currentPathStat.isSymbolicLink() !== root.rootSymlink || !sameFileIdentity(root.pathStat, currentPathStat)) {
    throw new Error("Backup source root changed during archive creation");
  }
  const realPath = fs.realpathSync.native(root.absolutePath);
  if (!samePath(realPath, root.realPath)) throw new Error("Backup source root changed during archive creation");
  const realStat = fs.statSync(realPath, { bigint: true });
  if (!realStat.isDirectory() || !sameFileIdentity(root.realStat, realStat)) {
    throw new Error("Backup source root changed during archive creation");
  }
}

function assertArchiveSourcePath(root, absolutePath) {
  if (!isPathWithin(root.absolutePath, absolutePath) || path.resolve(root.absolutePath) === path.resolve(absolutePath)) {
    throw new Error("Backup source escaped its collected root");
  }
  const segments = path.relative(root.absolutePath, absolutePath).split(path.sep).filter(Boolean);
  let current = root.absolutePath;
  for (let index = 0; index < segments.length; index += 1) {
    current = path.join(current, segments[index]);
    const stat = fs.lstatSync(current, { bigint: true });
    if (stat.isSymbolicLink()) throw new Error("Backup source cannot be a symbolic link");
    if (index < segments.length - 1 && !stat.isDirectory()) throw new Error("Backup source parent is not a directory");
    if (index === segments.length - 1 && !stat.isFile()) throw new Error("Backup source is not a regular file");
  }
  return fs.lstatSync(absolutePath, { bigint: true });
}

function archiveSourceMetadata(file) {
  const absolutePath = path.resolve(file.absolutePath);
  let root = file.archiveRoot;
  let sourceStat = file.sourceStat;
  if (!root && !sourceStat) {
    sourceStat = fs.lstatSync(absolutePath, { bigint: true });
    if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) throw new Error("Backup source is not a regular file");
    root = archiveRootInfo(path.dirname(absolutePath));
  }
  if (!root || !sourceStat) throw new Error("Backup source verification metadata is missing");
  return { ...file, absolutePath, archiveRoot: root, sourceStat };
}

function createVerifiedArchiveStream(file) {
  return Readable.from((async function* readVerifiedArchiveSource() {
    const { absolutePath, archiveRoot: root, sourceStat } = file;
    assertArchiveRootUnchanged(root);
    const pathStat = assertArchiveSourcePath(root, absolutePath);
    if (!sameFileSnapshot(sourceStat, pathStat) || pathStat.nlink !== 1n) {
      throw new Error("Backup source changed or is aliased during archive creation");
    }

    let fd;
    let source;
    try {
      fd = fs.openSync(absolutePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      const openedStat = fs.fstatSync(fd, { bigint: true });
      if (!openedStat.isFile() || openedStat.nlink !== 1n || !sameFileSnapshot(sourceStat, openedStat)) {
        throw new Error("Backup source changed or is aliased during archive creation");
      }
      assertArchiveRootUnchanged(root);
      const finalPathStat = assertArchiveSourcePath(root, absolutePath);
      const realPath = fs.realpathSync.native(absolutePath);
      if (!isPathWithin(root.realPath, realPath) || !sameFileSnapshot(openedStat, finalPathStat)) {
        throw new Error("Backup source escaped its collected root");
      }
      source = fs.createReadStream(null, { fd, autoClose: true });
      fd = undefined;
      for await (const chunk of source) yield chunk;
    } finally {
      if (source) source.destroy();
      if (fd !== undefined) fs.closeSync(fd);
    }
  })());
}

function collectFilesRecursive(rootPath, entryPrefix, options = {}) {
  if (!fs.existsSync(rootPath)) return [];
  const rootAbsolute = path.resolve(rootPath);
  if (fs.lstatSync(rootAbsolute).isSymbolicLink()) return [];
  const archiveRoot = archiveRootInfo(rootAbsolute);
  const excludedPaths = (options.excludePaths || []).filter(Boolean).map((excludedPath) => {
    const absolute = path.resolve(excludedPath);
    return { absolute, real: fs.existsSync(absolute) ? fs.realpathSync(absolute) : null };
  });
  const isExcluded = (candidatePath) => {
    if (!excludedPaths.length) return false;
    const absolute = path.resolve(candidatePath);
    if (excludedPaths.some((excluded) => isPathWithin(excluded.absolute, absolute))) return true;
    if (!excludedPaths.some((excluded) => excluded.real)) return false;
    let real;
    try { real = fs.realpathSync(absolute); } catch { return false; }
    return excludedPaths.some((excluded) => excluded.real && isPathWithin(excluded.real, real));
  };
  if (isExcluded(rootAbsolute)) return [];
  const files = [];
  const stack = [{ absolutePath: rootAbsolute, entryPath: entryPrefix }];
  while (stack.length) {
    const current = stack.pop();
    if (isExcluded(current.absolutePath)) continue;
    const stat = fs.lstatSync(current.absolutePath, { bigint: true });
    if (stat.isSymbolicLink()) continue;
    if (stat.isDirectory()) {
      for (const name of fs.readdirSync(current.absolutePath)) {
        const absolutePath = path.join(current.absolutePath, name);
        if (isExcluded(absolutePath)) continue;
        const entryPath = normalizeEntryPath(path.posix.join(current.entryPath, name));
        if (isSensitivePath(entryPath)) continue;
        stack.push({ absolutePath, entryPath });
      }
      continue;
    }
    if (!stat.isFile()) continue;
    const identity = fileIdentity(stat);
    if (identity && options.excludeFileIdentities?.has(identity)) continue;
    if (options.maxBytes && stat.size > options.maxBytes) continue;
    files.push({ absolutePath: current.absolutePath, entryPath: normalizeEntryPath(current.entryPath), size: Number(stat.size), archiveRoot, sourceStat: stat });
  }
  return files;
}

async function collectBackupFiles(options = {}) {
  const files = [];
  const dataDir = resolveRuntimePath("data");
  let dataRootInfo = null;
  try {
    const dataStat = fs.lstatSync(dataDir, { bigint: true });
    if (dataStat.isSymbolicLink()) throw new Error("Backup data directory cannot be a symbolic link");
    dataRootInfo = archiveRootInfo(dataDir);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const includeUploads = envBool("BACKUP_INCLUDE_UPLOADS", true);
  const includeTemp = envBool("BACKUP_INCLUDE_TEMP", false);
  const includePending = envBool("BACKUP_INCLUDE_PENDING", false);
  const quarantineDir = getUploadQuarantineDir();
  const quarantineMetadata = readQuarantineMetadata(resolveRuntimePath("data", "quarantine.json"));
  const quarantinePayloads = quarantineMetadata ? validateQuarantinePayloads(quarantineMetadata.items, quarantineDir) : [];
  const quarantineRootInfo = quarantinePayloads.length ? archiveRootInfo(quarantineDir, { allowRootSymlink: true }) : null;
  const quarantinePathIdentities = new Set();
  const quarantineFileIdentities = new Set();
  for (const payload of quarantinePayloads) {
    quarantinePathIdentities.add(pathIdentityKey(payload.absolutePath));
    try { quarantinePathIdentities.add(pathIdentityKey(fs.realpathSync(payload.absolutePath))); } catch {}
    const identity = fileIdentity(fs.lstatSync(payload.absolutePath));
    if (identity) quarantineFileIdentities.add(identity);
  }
  const isQuarantinePayloadPath = (candidatePath, stat) => {
    const identity = fileIdentity(stat);
    if (identity && quarantineFileIdentities.has(identity)) return true;
    if (quarantinePathIdentities.has(pathIdentityKey(candidatePath))) return true;
    try { return quarantinePathIdentities.has(pathIdentityKey(fs.realpathSync(candidatePath))); } catch { return false; }
  };

  for (const name of fs.existsSync(dataDir) ? fs.readdirSync(dataDir) : []) {
    if (name.toLowerCase() === "quarantine.json") continue;
    const absolutePath = path.join(dataDir, name);
    const entryPath = normalizeEntryPath(path.posix.join("data", name));
    if (isSensitivePath(entryPath)) continue;
    const stat = fs.lstatSync(absolutePath, { bigint: true });
    if (stat.isSymbolicLink()) continue;
    if (stat.isFile() && (
      name.endsWith(".json") ||
      name === "README.md"
    ) && !isQuarantinePayloadPath(absolutePath, stat)) {
      files.push({ absolutePath, entryPath, size: Number(stat.size), archiveRoot: dataRootInfo, sourceStat: stat });
    }
  }

  if (quarantineMetadata) {
    const safeItems = quarantineMetadata.items.filter((item) => {
      const storedPath = path.posix.join("data", "quarantine", item.storedQuarantineFilename);
      return !isSensitivePath(storedPath) && !isSensitiveQuarantineItem(item);
    });
    const safeNames = new Set(safeItems.map((item) => item.storedQuarantineFilename));
    const metadataContents = Buffer.from(JSON.stringify({ ...quarantineMetadata, items: safeItems }));
    files.push({ contents: metadataContents, entryPath: "data/quarantine.json", size: metadataContents.length });
    files.push(...quarantinePayloads.filter((payload) => safeNames.has(payload.filename)).map((payload) => {
      const sourceStat = fs.lstatSync(payload.absolutePath, { bigint: true });
      if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) throw new Error("Quarantine payload is not a regular file");
      return {
        absolutePath: payload.absolutePath,
        entryPath: normalizeEntryPath(path.posix.join("data", "quarantine", payload.filename)),
        size: Number(sourceStat.size),
        archiveRoot: quarantineRootInfo,
        sourceStat,
      };
    }));
  }

  if (isDbEnabled()) {
    const snapshotPath = options.sqliteSnapshotPath;
    if (snapshotPath && fs.existsSync(snapshotPath)) {
      const sourceStat = fs.lstatSync(snapshotPath, { bigint: true });
      if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) throw new Error("SQLite backup snapshot is not a regular file");
      files.push({ absolutePath: snapshotPath, entryPath: "data/rootark.sqlite", size: Number(sourceStat.size), archiveRoot: dataRootInfo, sourceStat });
    }
  }

  if (includeUploads) {
    files.push(...collectFilesRecursive(resolveRuntimePath("uploads"), "uploads", { excludePaths: [quarantineDir], excludeFileIdentities: quarantineFileIdentities }));
  }

  if (includeTemp || includePending) {
    files.push(...collectFilesRecursive(resolveRuntimePath("temp"), "temp", { excludePaths: [quarantineDir], excludeFileIdentities: quarantineFileIdentities }));
  }

  const syncFile = files.find((file) => file.entryPath === "data/sync-objects.json");
  if (syncFile) attestCiphertextOnlyFile(syncFile.absolutePath);

  if (!cloudStorage?.enabled()) return files.sort((a, b) => a.entryPath.localeCompare(b.entryPath));

  const stageDir = options.stageDir;
  if (!stageDir) throw new Error("Cloud backup staging is required");
  const known = new Map();
  const collisions = new Map();
  for (const file of files) {
    const key = collisionKey(file.entryPath);
    if (collisions.has(key) && collisions.get(key) !== file.entryPath) throw new Error("Backup entry collision");
    collisions.set(key, file.entryPath);
    known.set(file.entryPath, file);
  }
  const areas = ["uploads", ...(includeTemp || includePending ? ["temp"] : [])];
  const remoteIdentities = new Set();
  let stageRootInfo = null;
  if (typeof cloudStorage.inventory !== "function") throw new Error("Authoritative cloud inventory is required");
  const remotes = await cloudStorage.inventory();
  for (const remote of remotes) {
    if (!areas.includes(remote.area)) continue;
    const folderId = String(remote.folderId || "");
    const name = String(remote.name || "");
    const identity = `${remote.provider || "cloud"}:${remote.providerIdentity || remote.id || remote.key || `${remote.area}/${folderId}/${name}`}`;
    if (remoteIdentities.has(identity)) throw new Error("Cloud backup inventory contains a duplicate provider identity");
    remoteIdentities.add(identity);
    if (!folderId || folderId === "." || folderId === ".." || /[\\\\/]/.test(folderId)) throw new Error("Cloud backup inventory contains an unsafe folder");
    if (!name || name !== path.basename(name) || /[\\/]/.test(name) || isSensitivePath(`${remote.area}/${folderId}/${name}`)) throw new Error("Cloud backup inventory contains an unsafe path");
    const entryPath = normalizeEntryPath(path.posix.join(remote.area, folderId === "root" ? "" : folderId, name));
    const key = collisionKey(entryPath);
    if (collisions.has(key) && collisions.get(key) !== entryPath) throw new Error("Backup entry collision");
    collisions.set(key, entryPath);
    const staged = path.resolve(stageDir, entryPath);
    if (!staged.startsWith(`${path.resolve(stageDir)}${path.sep}`)) throw new Error("Cloud backup staging escaped its boundary");
    fs.mkdirSync(path.dirname(staged), { recursive: true });
    if (!await cloudStorage.download(folderId, name, staged, remote.area)) throw new Error("Cloud backup object is unavailable");
    const local = known.get(entryPath);
    if (local) {
      if (await calculateBackupEntryHash(local) !== await calculateFileHash(staged)) throw new Error("Cloud and local backup objects differ");
      fs.rmSync(staged, { force: true });
    } else {
      const sourceStat = fs.lstatSync(staged, { bigint: true });
      if (!sourceStat.isFile() || sourceStat.isSymbolicLink()) throw new Error("Cloud backup staging file is not a regular file");
      stageRootInfo ||= archiveRootInfo(stageDir);
      known.set(entryPath, { absolutePath: staged, entryPath, size: Number(sourceStat.size), cloudOnly: true, archiveRoot: stageRootInfo, sourceStat });
    }
  }
  options.cloudComplete = true;
  return [...known.values()].sort((a, b) => a.entryPath.localeCompare(b.entryPath));
}

async function createSqliteSnapshot() {
  if (!isDbEnabled() || !fs.existsSync(getDatabasePath())) return null;
  const stageDir = resolveRuntimePath("data", `.sqlite-backup-${crypto.randomUUID()}`);
  const snapshotPath = path.join(stageDir, "rootark.sqlite");
  fs.mkdirSync(stageDir, { recursive: true });
  try {
    await getDb().backup(snapshotPath);
    const snapshot = new Database(snapshotPath, { readonly: true, fileMustExist: true });
    try {
      if (snapshot.pragma("integrity_check", { simple: true }) !== "ok") throw new Error("SQLite snapshot integrity check failed");
    } finally { snapshot.close(); }
    return { stageDir, snapshotPath };
  } catch (error) {
    try { fs.rmSync(stageDir, { recursive: true, force: true }); } catch {}
    throw error;
  }
}

function calculateFileHash(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const input = fs.createReadStream(filePath);
    input.on("data", (chunk) => hash.update(chunk));
    input.on("error", reject);
    input.on("end", () => resolve(hash.digest("hex")));
  });
}

function calculateBackupEntryHash(file) {
  if (Buffer.isBuffer(file.contents)) {
    return Promise.resolve(crypto.createHash("sha256").update(file.contents).digest("hex"));
  }
  return calculateFileHash(file.absolutePath);
}

function runtimeRootIdentity() {
  try { return fs.realpathSync(resolveRuntimePath(".")); } catch { return path.resolve(resolveRuntimePath(".")); }
}

function sameRuntimeRoot(left, right) {
  const a = path.normalize(String(left || ""));
  const b = path.normalize(String(right || ""));
  return process.platform === "win32" ? a.toLowerCase() === b.toLowerCase() : a === b;
}

function ownerIsLive(record) {
  if (!Number.isInteger(record?.pid) || record.pid <= 0) return false;
  try { process.kill(record.pid, 0); } catch (error) { return error.code === "EPERM"; }
  if (record.processStartIdentity && processStartIdentity(record.pid)) {
    return record.processStartIdentity === processStartIdentity(record.pid);
  }
  return true;
}

function validLockRecord(record) {
  if (!record || typeof record !== "object") return false;
  if (!Number.isInteger(record.pid) || record.pid <= 0) return false;
  if (record.formatVersion === OPERATION_LOCK_FORMAT_VERSION) {
    return typeof record.token === "string" && Boolean(record.token) && typeof record.operation === "string" && Boolean(record.operation) && typeof record.startedAt === "string" && Number.isFinite(Date.parse(record.startedAt)) && typeof record.runtimeRoot === "string" && Boolean(record.runtimeRoot);
  }
  return true;
}

function lockError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function readLockState() {
  let stat;
  try { stat = fs.statSync(LOCK_FILE); } catch (error) {
    if (error.code === "ENOENT") return { kind: "missing" };
    throw error;
  }
  let contents = "";
  try {
    contents = fs.readFileSync(LOCK_FILE, "utf8");
    const record = JSON.parse(contents);
    if (!validLockRecord(record)) return { kind: "malformed", mtimeMs: stat.mtimeMs, contents, stat };
    if (record.runtimeRoot && !sameRuntimeRoot(record.runtimeRoot, runtimeRootIdentity())) return { kind: "mismatch", record };
    const createdAtMs = Date.parse(record.startedAt || "");
    const ageMs = Math.max(Date.now() - stat.mtimeMs, Number.isFinite(createdAtMs) ? Date.now() - createdAtMs : 0);
    const live = ownerIsLive(record);
    const staleMs = boundedLockDuration("BACKUP_LOCK_STALE_MS", 6 * 60 * 60 * 1000);
    return { kind: "valid", record, contents, stat, ageMs, live, stale: !live && (record.formatVersion === OPERATION_LOCK_FORMAT_VERSION || ageMs >= staleMs) };
  } catch {
    return { kind: "malformed", mtimeMs: stat.mtimeMs, contents, stat };
  }
}

function statIdentity(stat) {
  return stat ? {
    dev: stat.dev,
    ino: stat.ino,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    ctimeMs: stat.ctimeMs,
    birthtimeMs: stat.birthtimeMs,
  } : null;
}

function sameStatIdentity(left, right) {
  if (!left || !right) return false;
  return ["dev", "ino", "size", "mtimeMs", "ctimeMs", "birthtimeMs"].every((key) => left[key] === right[key]);
}

function sameRenamedFileIdentity(left, right) {
  if (!left || !right) return false;
  return ["dev", "ino", "size", "mtimeMs", "birthtimeMs"].every((key) => left[key] === right[key]);
}

function lockObservation(state) {
  return { contents: state.contents, stat: state.stat };
}

function sameLockObservation(observed, current) {
  return Boolean(observed && current?.contents !== undefined && observed.contents === current.contents && sameStatIdentity(statIdentity(observed.stat), statIdentity(current.stat)));
}

function takeoverObservation(observed) {
  return {
    sha256: crypto.createHash("sha256").update(observed.contents).digest("hex"),
    size: Buffer.byteLength(observed.contents),
    stat: statIdentity(observed.stat),
  };
}

function authorityPathIsSafe(target) {
  return path.dirname(path.resolve(target)) === path.resolve(BACKUPS_DIR) && path.basename(target) === path.basename(LOCK_TAKEOVER_DIR);
}

function validTakeoverAuthority(record) {
  return record && record.version === OPERATION_LOCK_FORMAT_VERSION && typeof record.token === "string" && record.token && Number.isInteger(record.pid) && record.pid > 0 && typeof record.claimedAt === "string" && Number.isFinite(Date.parse(record.claimedAt)) && typeof record.runtimeRoot === "string" && sameRuntimeRoot(record.runtimeRoot, runtimeRootIdentity()) && record.lockPath === LOCK_FILE && record.evidencePath === LOCK_TAKEOVER_EVIDENCE && record.observed && typeof record.observed.sha256 === "string" && Number.isInteger(record.observed.size) && record.observed.stat;
}

function readTakeoverAuthority() {
  let stat;
  try {
    const link = fs.lstatSync(LOCK_TAKEOVER_DIR);
    if (!link.isDirectory() || link.isSymbolicLink() || !authorityPathIsSafe(LOCK_TAKEOVER_DIR)) return { kind: "ambiguous" };
    stat = link;
  } catch (error) {
    if (error.code === "ENOENT") return { kind: "missing" };
    throw error;
  }
  let record;
  try { record = JSON.parse(fs.readFileSync(LOCK_TAKEOVER_META, "utf8")); } catch { return { kind: "malformed", mtimeMs: stat.mtimeMs }; }
  if (!validTakeoverAuthority(record)) return { kind: "mismatch", record };
  const ageMs = Math.max(Date.now() - stat.mtimeMs, Date.now() - Date.parse(record.claimedAt));
  return { kind: "valid", record, live: ownerIsLive(record), stale: ageMs > MAX_LOCK_TTL_MS };
}

function evidenceMatchesAuthority(record) {
  let stat;
  let bytes;
  try {
    const link = fs.lstatSync(LOCK_TAKEOVER_EVIDENCE);
    if (!link.isFile() || link.isSymbolicLink()) return false;
    stat = link;
    bytes = fs.readFileSync(LOCK_TAKEOVER_EVIDENCE);
  } catch (error) {
    return error.code === "ENOENT";
  }
  return crypto.createHash("sha256").update(bytes).digest("hex") === record.observed.sha256 && bytes.length === record.observed.size && sameRenamedFileIdentity(statIdentity(stat), record.observed.stat);
}

function removeTakeoverAuthority(token) {
  const state = readTakeoverAuthority();
  if (state.kind === "missing") return;
  if (state.kind !== "valid" || state.record.token !== token) throw lockError("BACKUP_LOCKED", "Evidence de takeover de lock ambigua");
  if (!evidenceMatchesAuthority(state.record)) throw lockError("BACKUP_LOCKED", "Evidence de takeover de lock ambigua");
  try { fs.rmSync(LOCK_TAKEOVER_EVIDENCE, { force: false }); } catch (error) { if (error.code !== "ENOENT") throw error; }
  try { fs.rmSync(LOCK_TAKEOVER_META, { force: false }); } catch (error) { if (error.code !== "ENOENT") throw error; }
  try { fs.rmdirSync(LOCK_TAKEOVER_DIR); } catch (error) { if (error.code !== "ENOENT") throw error; }
}

function recoverTakeoverAuthority() {
  const state = readTakeoverAuthority();
  if (state.kind === "missing") return;
  if (state.kind === "valid" && state.live) throw lockError("BACKUP_LOCKED", "Reivindicacao de takeover de lock de backup em andamento");
  if (state.kind === "malformed") {
    if (Date.now() - state.mtimeMs <= boundedLockDuration("BACKUP_LOCK_MALFORMED_TTL_MS", MALFORMED_TAKEOVER_TTL_MS)) throw lockError("BACKUP_LOCKED", "Autoridade de takeover de lock recente e invalida");
    const entries = fs.readdirSync(LOCK_TAKEOVER_DIR);
    if (entries.length) throw lockError("BACKUP_LOCKED", "Autoridade de takeover de lock ambigua");
    fs.rmdirSync(LOCK_TAKEOVER_DIR);
    return;
  }
  if (state.kind !== "valid") throw lockError("BACKUP_LOCKED", "Autoridade de takeover de lock ambigua");
  removeTakeoverAuthority(state.record.token);
}

function acquireTakeoverAuthority(observed, operation) {
  recoverTakeoverAuthority();
  const token = crypto.randomUUID();
  const authority = {
    version: OPERATION_LOCK_FORMAT_VERSION,
    token,
    operation,
    pid: process.pid,
    processStartIdentity: CURRENT_PROCESS_START_IDENTITY,
    claimedAt: new Date().toISOString(),
    runtimeRoot: runtimeRootIdentity(),
    lockPath: LOCK_FILE,
    evidencePath: LOCK_TAKEOVER_EVIDENCE,
    observed: takeoverObservation(observed),
  };
  try { fs.mkdirSync(LOCK_TAKEOVER_DIR, { recursive: false }); } catch (error) {
    if (error.code !== "EEXIST") throw error;
    recoverTakeoverAuthority();
    fs.mkdirSync(LOCK_TAKEOVER_DIR, { recursive: false });
  }
  try {
    writeDurableFile(LOCK_TAKEOVER_META, JSON.stringify(authority));
    const current = readLockState();
    if (!sameLockObservation(observed, current)) {
      removeTakeoverAuthority(token);
      return null;
    }
    fs.renameSync(LOCK_FILE, LOCK_TAKEOVER_EVIDENCE);
    const evidence = fs.readFileSync(LOCK_TAKEOVER_EVIDENCE);
    if (crypto.createHash("sha256").update(evidence).digest("hex") !== authority.observed.sha256 || evidence.length !== authority.observed.size) throw new Error("Backup lock evidence changed during takeover");
    return { authorityToken: token, evidencePath: LOCK_TAKEOVER_EVIDENCE };
  } catch (error) {
    try { removeTakeoverAuthority(token); } catch {}
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function writeDurableFile(filePath, contents) {
  const temporary = `${filePath}.${crypto.randomUUID()}.tmp`;
  let fd;
  try {
    fd = fs.openSync(temporary, "wx");
    const bytes = Buffer.from(contents);
    let offset = 0;
    while (offset < bytes.length) {
      const written = fs.writeSync(fd, bytes, offset, bytes.length - offset);
      if (!written) throw new Error("Durable file write made no progress");
      offset += written;
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temporary, filePath);
  } catch (error) {
    try { if (fd !== undefined) fs.closeSync(fd); } catch {}
    try { fs.rmSync(temporary, { force: true }); } catch {}
    throw error;
  }
}

function lockRecord(operation, token, claimToken = null) {
  return {
    formatVersion: OPERATION_LOCK_FORMAT_VERSION,
    token,
    operation,
    pid: process.pid,
    processStartIdentity: CURRENT_PROCESS_START_IDENTITY,
    startedAt: new Date().toISOString(),
    runtimeRoot: runtimeRootIdentity(),
    takeoverClaimToken: claimToken,
  };
}

function cleanupOwnedIncompleteLock(descriptorStat, token) {
  try {
    const currentStat = fs.statSync(LOCK_FILE);
    const contents = fs.readFileSync(LOCK_FILE, "utf8");
    const sameFile = descriptorStat && currentStat.dev === descriptorStat.dev && currentStat.ino === descriptorStat.ino && (currentStat.birthtimeMs === descriptorStat.birthtimeMs || currentStat.ctimeMs === descriptorStat.ctimeMs);
    if (sameFile && contents.includes(`"token":"${token}"`)) fs.rmSync(LOCK_FILE, { force: false });
  } catch {}
}

function writeLock(operation, token = crypto.randomUUID(), claimToken = null) {
  const record = lockRecord(operation, token, claimToken);
  let fd;
  let descriptorStat;
  try {
    fd = fs.openSync(LOCK_FILE, "wx");
    descriptorStat = fs.fstatSync(fd);
    const contents = Buffer.from(JSON.stringify(record));
    let offset = 0;
    while (offset < contents.length) {
      const written = fs.writeSync(fd, contents, offset, contents.length - offset);
      if (!written) throw new Error("Backup lock write made no progress");
      offset += written;
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    return token;
  } catch (error) {
    try { if (fd !== undefined) fs.closeSync(fd); } catch {}
    cleanupOwnedIncompleteLock(descriptorStat, token);
    throw error;
  }
}

function claimStaleLock(observed, operation) {
  const authority = acquireTakeoverAuthority(observed, operation);
  if (!authority) return null;
  const token = authority.authorityToken;
  try {
    writeLock(operation, token, token);
    const current = readLockState();
    if (current.kind !== "valid" || current.record.token !== token) throw lockError("BACKUP_LOCKED", "Lock de backup nao confirmou a posse");
    removeTakeoverAuthority(token);
    return token;
  } catch (error) {
    try { removeTakeoverAuthority(token); } catch {}
    throw error;
  }
}

function acquireLock(operation) {
  fs.mkdirSync(BACKUPS_DIR, { recursive: true });
  if (operationLock) throw lockError("BACKUP_LOCKED", `Operacao de ${operationLock.operation} em andamento`);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    recoverTakeoverAuthority();
    const state = readLockState();
    if (state.kind === "mismatch") throw lockError("BACKUP_LOCKED", "Lock de backup pertence a outra raiz de runtime");
    if (state.kind === "valid" && !state.stale) throw lockError("BACKUP_LOCKED", "Outra operacao de backup/restauracao esta em andamento");
    if (state.kind === "malformed" && Date.now() - state.mtimeMs <= boundedLockDuration("BACKUP_LOCK_MALFORMED_TTL_MS", MALFORMED_LOCK_TTL_MS)) throw lockError("BACKUP_LOCKED", "Lock de backup recente e invalido");

    if (state.kind === "missing") {
      try {
        const token = writeLock(operation);
        operationLock = { operation, token };
        return createLockRelease(operation, token);
      } catch (error) {
        if (error.code === "EEXIST") continue;
        throw lockError("BACKUP_LOCK_WRITE_FAILED", "Falha ao gravar lock de backup");
      }
    }

    const observed = lockObservation(state);
    let claim;
    try { claim = claimStaleLock(observed, operation); } catch (error) {
      if (error.code === "ENOENT") continue;
      throw lockError("BACKUP_LOCKED", "Nao foi possivel reivindicar o lock de backup");
    }
    if (!claim) continue;
    operationLock = { operation, token: claim };
    return createLockRelease(operation, claim);
  }
  throw lockError("BACKUP_LOCKED", "Aquisicao concorrente do lock de backup nao foi resolvida");
}

function createLockRelease(operation, token) {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    if (operationLock?.token === token) operationLock = null;
    try {
      const current = JSON.parse(fs.readFileSync(LOCK_FILE, "utf8"));
      if (current.token === token) fs.rmSync(LOCK_FILE, { force: false });
    } catch {
      // The lock is already gone or malformed; never delete another operation's lock.
    }
  };
}

async function createZipArchive(archivePath, manifest, files) {
  const closeTimeoutMs = Math.max(50, Math.min(5000, envNumber("BACKUP_OUTPUT_CLOSE_TIMEOUT_MS", 1000)));
  const cleanupRetries = 2;
  const cleanupDelayMs = 25;
  await new Promise((resolve, reject) => {
    let settled = false;
    let owned = false;
    let outputClosed = false;
    let finalized = false;
    let archive;
    let output;
    let fd;

    const closeOutput = () => {
      if (!output || outputClosed || output.destroyed) return;
      try { output.destroy(); } catch {}
    };

    const waitForOutputClose = () => {
      if (!output || outputClosed || output.closed) return Promise.resolve();
      return new Promise((done) => {
        let timer;
        const finishWait = () => {
          if (timer) clearTimeout(timer);
          output.removeListener("close", finishWait);
          done();
        };
        timer = setTimeout(finishWait, closeTimeoutMs);
        output.once("close", finishWait);
      });
    };

    const removeOwnedArchive = async () => {
      if (!owned) return;
      let lastError;
      for (let attempt = 0; attempt <= cleanupRetries; attempt += 1) {
        try {
          fs.rmSync(archivePath, { force: false });
          return;
        } catch (error) {
          if (error.code === "ENOENT") return;
          lastError = error;
          if (attempt < cleanupRetries) await new Promise((done) => setTimeout(done, cleanupDelayMs));
        }
      }
      throw lastError;
    };

    const stopArchive = () => {
      try {
        if (archive && typeof archive.abort === "function") archive.abort();
        else if (archive && typeof archive.destroy === "function") archive.destroy();
      } catch {}
      closeOutput();
    };

    const finish = async (error) => {
      if (settled) return;
      if (error) {
        settled = true;
        stopArchive();
        await waitForOutputClose();
        try { await removeOwnedArchive(); } catch (cleanupError) { error.cleanupError = cleanupError; }
        reject(error);
        return;
      }
      if (!finalized || !outputClosed) return;
      settled = true;
      resolve();
    };

    const onArchiveError = (error) => { void finish(error); };
    const onOutputError = (error) => { void finish(error); };

    try {
      fd = fs.openSync(archivePath, "wx");
      owned = true;
      output = fs.createWriteStream(archivePath, { fd, autoClose: true });
      archive = new ZipArchive({ zlib: { level: 9 } });
      output.on("close", () => { outputClosed = true; void finish(); });
      output.on("error", onOutputError);
      archive.on("error", onArchiveError);
      archive.pipe(output);
      archive.append(JSON.stringify(manifest, null, 2), { name: "backup-manifest.json" });
      for (const file of files) {
        if (Buffer.isBuffer(file.contents)) archive.append(file.contents, { name: file.entryPath });
        else {
          const source = archiveSourceMetadata(file);
          const sourceStream = createVerifiedArchiveStream(source);
          sourceStream.on("error", onArchiveError);
          archive.append(sourceStream, {
            name: file.entryPath,
            date: source.sourceStat.mtime,
            mode: Number(source.sourceStat.mode),
          });
        }
      }
      Promise.resolve(archive.finalize()).then(() => { finalized = true; void finish(); }, onArchiveError);
    } catch (error) {
      if (fd !== undefined && !output) { try { fs.closeSync(fd); } catch {} }
      void finish(error);
    }
  });
}

function getArchivePath(filename) {
  const safeName = path.basename(filename || "");
  if (!/^rootark-(backup|pre-restore)-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}(?:-\d{3}-[a-f0-9]{8})?\.zip$/.test(safeName)) {
    return null;
  }
  const archivePath = path.resolve(BACKUPS_DIR, safeName);
  const root = path.resolve(BACKUPS_DIR);
  return archivePath === root || archivePath.startsWith(`${root}${path.sep}`) ? archivePath : null;
}

function retentionTombstone(archivePath) {
  const root = path.resolve(BACKUPS_DIR);
  const target = path.resolve(`${archivePath}${RETENTION_TOMBSTONE_SUFFIX}`);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error("Retention tombstone escaped backup root");
  return target;
}

function retentionTombstoneMetadata(tombstone) {
  const root = path.resolve(BACKUPS_DIR);
  const metadata = path.resolve(`${tombstone}.json`);
  if (!metadata.startsWith(`${root}${path.sep}`)) throw new Error("Retention metadata escaped backup root");
  return metadata;
}

function writeRetentionMetadata(tombstone, backup) {
  const metadataPath = retentionTombstoneMetadata(tombstone);
  const temporary = `${metadataPath}.${crypto.randomUUID()}.tmp`;
  const value = JSON.stringify({ backupId: backup.id, filename: backup.filename, checksum: backup.checksum || null });
  try {
    fs.writeFileSync(temporary, value, { encoding: "utf8", flag: "wx" });
    fs.renameSync(temporary, metadataPath);
  } catch (error) {
    fs.rmSync(temporary, { force: true });
    throw error;
  }
  return metadataPath;
}

function retentionTransactionPath(transactionId) {
  const directory = path.resolve(RETENTION_TRANSACTIONS_DIR, `tx-${transactionId}`);
  const root = path.resolve(RETENTION_TRANSACTIONS_DIR);
  if (!directory.startsWith(`${root}${path.sep}`)) throw new Error("Retention transaction escaped backup root");
  return path.join(directory, "transaction.json");
}

function validRetentionTransaction(transaction) {
  if (!transaction || transaction.version !== 1 || typeof transaction.transactionId !== "string" || !transaction.transactionId || !["prepared", "archive_moved", "history_removed", "cleanup_committed"].includes(transaction.phase)) return false;
  if (typeof transaction.backupId !== "string" || !transaction.backupId || typeof transaction.filename !== "string" || !getArchivePath(transaction.filename)) return false;
  if (typeof transaction.checksum !== "string" || !/^[a-f0-9]{64}$/i.test(transaction.checksum)) return false;
  return transaction.archivePath === getArchivePath(transaction.filename) && transaction.tombstonePath === retentionTombstone(transaction.archivePath);
}

function persistRetentionTransaction(transaction) {
  const transactionPath = retentionTransactionPath(transaction.transactionId);
  fs.mkdirSync(path.dirname(transactionPath), { recursive: true });
  writeDurableFile(transactionPath, JSON.stringify(transaction));
  return transactionPath;
}

function listRetentionTransactions() {
  if (!fs.existsSync(RETENTION_TRANSACTIONS_DIR)) return [];
  const records = [];
  for (const name of fs.readdirSync(RETENTION_TRANSACTIONS_DIR)) {
    const directory = path.join(RETENTION_TRANSACTIONS_DIR, name);
    if (!name.startsWith("tx-") || !fs.statSync(directory).isDirectory()) throw new Error("Malformed retention transaction directory");
    const transactionPath = path.join(directory, "transaction.json");
    if (!fs.existsSync(transactionPath)) {
      if (fs.readdirSync(directory).length === 0) { fs.rmSync(directory, { recursive: true, force: false }); continue; }
      throw new Error("Retention transaction metadata is missing");
    }
    let transaction;
    try { transaction = JSON.parse(fs.readFileSync(transactionPath, "utf8")); } catch { throw new Error("Malformed retention transaction metadata"); }
    if (!validRetentionTransaction(transaction)) throw new Error("Invalid retention transaction identity");
    records.push({ transaction, transactionPath, directory });
  }
  const claims = new Set();
  for (const { transaction } of records) {
    for (const claim of [String(transaction.backupId), `filename:${transaction.filename}`]) {
      if (claims.has(claim)) throw new Error("Multiple retention transactions claim one backup");
      claims.add(claim);
    }
  }
  return records;
}

function removeRetentionTransaction(record) {
  fs.rmSync(record.transactionPath, { force: false });
  fs.rmSync(record.directory, { recursive: true, force: false });
}

function sameArchiveBytes(left, right) {
  return fs.existsSync(left) && fs.existsSync(right) && fs.readFileSync(left).equals(fs.readFileSync(right));
}

function retentionHistoryMatches(transaction) {
  return backupRepository.listBackups().filter((backup) => backup.id === transaction.backupId || backup.filename === transaction.filename);
}

function recoverRetentionTransactions() {
  for (const record of listRetentionTransactions()) {
    const transaction = record.transaction;
    const original = transaction.archivePath;
    const tombstone = transaction.tombstonePath;
    const originalExists = fs.existsSync(original);
    const tombstoneExists = fs.existsSync(tombstone);
    if ((originalExists && !awaitableChecksum(original, transaction.checksum)) || (tombstoneExists && !awaitableChecksum(tombstone, transaction.checksum))) throw new Error("Retention archive checksum mismatch");
    const history = retentionHistoryMatches(transaction);
    if (history.length > 1) throw new Error("Ambiguous retention transaction history");
    if (originalExists && tombstoneExists && !sameArchiveBytes(original, tombstone)) throw new Error("Conflicting retention archive bytes");

    if (transaction.phase === "prepared" || transaction.phase === "archive_moved") {
      if (history.length === 1) {
        if (originalExists && tombstoneExists) fs.rmSync(tombstone, { force: false });
        else if (!originalExists && tombstoneExists) fs.renameSync(tombstone, original);
        else if (!originalExists) throw new Error("Retention history points to a missing archive");
        if (awaitableChecksum(original, transaction.checksum) === false) throw new Error("Retention archive checksum mismatch");
        removeRetentionTransaction(record);
        continue;
      }
      if (transaction.phase === "prepared") throw new Error("Prepared retention transaction lost repository history");
      if (originalExists && tombstoneExists) { fs.rmSync(original, { force: false }); fs.rmSync(tombstone, { force: false }); }
      else if (tombstoneExists) fs.rmSync(tombstone, { force: false });
      else if (originalExists) throw new Error("Retention cleanup found an unowned archive");
      removeRetentionTransaction(record);
      continue;
    }

    if (history.length > 0) throw new Error("Retention history survived repository-delete phase");
    if (originalExists && tombstoneExists) { fs.rmSync(original, { force: false }); fs.rmSync(tombstone, { force: false }); }
    else if (tombstoneExists) fs.rmSync(tombstone, { force: false });
    else if (originalExists) throw new Error("Retention cleanup found an unowned archive");
    removeRetentionTransaction(record);
  }
}

function awaitableChecksum(filePath, expected) {
  if (!fs.existsSync(filePath)) return false;
  const hash = crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  return hash === expected;
}

function recoverLegacyRetentionTombstones() {
  if (!fs.existsSync(BACKUPS_DIR)) return;
  const names = fs.readdirSync(BACKUPS_DIR);
  const tombstoneNames = names.filter((name) => name.endsWith(RETENTION_TOMBSTONE_SUFFIX));
  for (const name of names.filter((value) => value.endsWith(`${RETENTION_TOMBSTONE_SUFFIX}.json`))) {
    const tombstone = name.slice(0, -5);
    if (!tombstoneNames.includes(tombstone)) throw new Error("Retention metadata without tombstone");
  }
  const claims = new Map();
  const records = [];
  for (const name of tombstoneNames) {
    const original = getArchivePath(name.slice(0, -RETENTION_TOMBSTONE_SUFFIX.length));
    const tombstone = path.resolve(BACKUPS_DIR, name);
    if (!original || !tombstone.startsWith(`${path.resolve(BACKUPS_DIR)}${path.sep}`)) throw new Error("Invalid retention tombstone path");
    const metadataPath = retentionTombstoneMetadata(tombstone);
    let metadata;
    try { metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8")); } catch { throw new Error("Malformed retention tombstone metadata"); }
    if (metadata.filename !== path.basename(original) || !metadata.backupId) throw new Error("Retention tombstone identity mismatch");
    for (const claim of [String(metadata.backupId), `filename:${metadata.filename}`]) {
      if (claims.has(claim)) throw new Error("Multiple retention tombstones claim one backup");
      claims.set(claim, name);
    }
    records.push({ original, tombstone, metadata, metadataPath });
  }
  const history = backupRepository.listBackups();
  for (const { original, tombstone, metadata, metadataPath } of records) {
    const matches = history.filter((backup) => backup.id === metadata.backupId || backup.filename === metadata.filename);
    if (matches.length > 1) throw new Error("Ambiguous retention tombstone history");
    if (fs.existsSync(original)) {
      if (matches.length === 0 || (matches[0].checksum && matches[0].checksum !== metadata.checksum) || (metadata.checksum && matches[0].checksum !== metadata.checksum)) throw new Error("Conflicting retention archive evidence");
      if (sameArchiveBytes(original, tombstone)) { fs.rmSync(tombstone, { force: false }); fs.rmSync(metadataPath, { force: false }); }
      else throw new Error("Conflicting retention archive bytes");
    } else if (matches.length === 1) {
      if (metadata.checksum !== null && metadata.checksum !== undefined && matches[0].checksum !== metadata.checksum) throw new Error("Retention checksum mismatch");
      if (matches[0].checksum && !metadata.checksum) throw new Error("Retention checksum evidence missing");
      fs.renameSync(tombstone, original);
      fs.rmSync(metadataPath, { force: false });
    } else {
      fs.rmSync(tombstone, { force: false });
      fs.rmSync(metadataPath, { force: false });
    }
  }
}

function recoverRetentionTombstones() {
  recoverRetentionTransactions();
  recoverLegacyRetentionTombstones();
}

async function cleanupRetention(options = {}) {
  const release = options.lockHeld ? null : acquireLock("backup");
  try {
  const count = Math.max(0, Math.floor(envNumber("BACKUP_RETENTION_COUNT", 10)));
  const days = Math.max(0, Math.floor(envNumber("BACKUP_RETENTION_DAYS", 30)));
  const cutoff = days ? Date.now() - days * 24 * 60 * 60 * 1000 : null;
  recoverRetentionTombstones();
  const backups = backupRepository.listBackups()
    .filter((item) => item.status === "success" && item.type !== "pre-restore")
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt) || String(b.id).localeCompare(String(a.id)));

  const toDelete = backups.filter((item, index) => (count > 0 && index >= count) || (cutoff && new Date(item.createdAt).getTime() < cutoff));
  for (const backup of toDelete) {
    const archivePath = getArchivePath(backup.filename);
    if (!archivePath || !fs.existsSync(archivePath)) continue;
    const transactionId = crypto.randomUUID();
    const tombstone = retentionTombstone(archivePath);
    const transaction = { version: 1, transactionId, phase: "prepared", backupId: String(backup.id), filename: path.basename(archivePath), archivePath, tombstonePath: tombstone, checksum: await calculateFileHash(archivePath), createdAt: new Date().toISOString() };
    const record = { transaction, transactionPath: persistRetentionTransaction(transaction), directory: path.dirname(retentionTransactionPath(transactionId)) };
    try {
      fs.renameSync(archivePath, tombstone);
      transaction.phase = "archive_moved";
      persistRetentionTransaction(transaction);
      backupRepository.deleteBackup(backup.id);
      transaction.phase = "history_removed";
      persistRetentionTransaction(transaction);
      fs.rmSync(tombstone, { force: false });
      transaction.phase = "cleanup_committed";
      persistRetentionTransaction(transaction);
      removeRetentionTransaction(record);
    } catch (error) {
      if (fs.existsSync(tombstone) && !fs.existsSync(archivePath) && backupRepository.getBackup(backup.id)) {
        try { fs.renameSync(tombstone, archivePath); transaction.phase = "prepared"; persistRetentionTransaction(transaction); removeRetentionTransaction(record); } catch (rollbackError) { error.rollbackError = rollbackError; }
      }
      throw error;
    }
  }
  } finally {
    if (release) release();
  }
}

async function createBackup(options = {}) {
  if (!envBool("BACKUP_ENABLED", true)) {
    throw new Error("Backups desativados por BACKUP_ENABLED=false");
  }

  const release = acquireLock("backup");
  const startedAt = Date.now();
  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const backupType = options.type || "manual";
  const filenameBase = `rootark-${backupType === "pre-restore" ? "pre-restore" : "backup"}-${timestampForName()}`;
  const maxArchiveAttempts = Math.max(1, Math.min(20, Math.floor(envNumber("BACKUP_ARCHIVE_COLLISION_RETRIES", 5))));
  let filename = `${filenameBase}.zip`;
  let archivePath = path.join(BACKUPS_DIR, filename);
  let archiveCreated = false;
  const stageDir = path.join(BACKUPS_DIR, ".cloud-stage", id);
  const baseEntry = {
    id,
    filename,
    type: backupType,
    status: "failed",
    createdBy: options.createdBy || null,
    createdAt,
    finishedAt: null,
    sizeBytes: 0,
    checksum: null,
    errorMessage: null,
    metadata: { notes: options.notes || "" },
  };
  let sqliteSnapshot = null;
  let saved = null;
  let outcomeError = null;

  try {
    sqliteSnapshot = await createSqliteSnapshot();
    const collectionOptions = { stageDir, sqliteSnapshotPath: sqliteSnapshot?.snapshotPath };
    const files = await collectBackupFiles(collectionOptions);
    const totalSize = files.reduce((sum, file) => sum + file.size, 0);
    const manifest = {
      backup_id: id,
      created_at: createdAt,
      type: backupType,
      created_by: options.createdBy || null,
      total_size: totalSize,
      included_files: files.map((file) => ({ path: file.entryPath, size: file.size })),
      archive_sha256: null,
      app_version: process.env.npm_package_version || "1.0.0",
      ...(files.some((file) => file.entryPath === "data/quarantine.json") ? { quarantine_format_version: 1 } : {}),
      status: "success",
      error_message: null,
      duration_ms: null,
      notes: options.notes || "",
      cloud_complete: Boolean(collectionOptions.cloudComplete),
    };

    let created = false;
    for (let attempt = 0; attempt < maxArchiveAttempts; attempt += 1) {
      filename = attempt === 0 ? `${filenameBase}.zip` : `${filenameBase}-${String(attempt).padStart(3, "0")}.zip`;
      archivePath = path.join(BACKUPS_DIR, filename);
      try {
        await createZipArchive(archivePath, manifest, files);
        created = true;
        archiveCreated = true;
        break;
      } catch (error) {
        if (error.code !== "EEXIST" || attempt === maxArchiveAttempts - 1) {
          if (error.code === "EEXIST") error.code = "BACKUP_ARCHIVE_COLLISION_LIMIT";
          throw error;
        }
      }
    }
    if (!created) throw new Error("Backup archive was not created");
    baseEntry.filename = filename;
    const checksum = await calculateFileHash(archivePath);
    const finishedAt = new Date().toISOString();
    const durationMs = Date.now() - startedAt;
    const sizeBytes = fs.statSync(archivePath).size;

    saved = backupRepository.saveBackup({
      ...baseEntry,
      status: "success",
      finishedAt,
      sizeBytes,
      checksum,
      metadata: {
        ...baseEntry.metadata,
        manifest: { ...manifest, duration_ms: durationMs },
        includedFiles: files.length,
        cloudComplete: Boolean(collectionOptions.cloudComplete),
      },
    });

    await cleanupRetention({ lockHeld: true });
    return saved;
  } catch (error) {
    outcomeError = error;
    let cleanupError = null;
    if (archiveCreated) {
      try { fs.rmSync(archivePath, { force: false }); } catch (cleanupFailure) { cleanupError = cleanupFailure; }
    }
    let failed;
    try {
      failed = backupRepository.saveBackup({
        ...baseEntry,
        finishedAt: new Date().toISOString(),
        errorMessage: error.message,
        metadata: { ...baseEntry.metadata, durationMs: Date.now() - startedAt },
      });
    } catch (historyError) {
      historyError.archiveCleanupError = cleanupError;
      throw historyError;
    }
    if (cleanupError) error.archiveCleanupError = cleanupError;
    throw Object.assign(error, { backup: failed });
  } finally {
    fs.rmSync(stageDir, { recursive: true, force: true });
    try { fs.rmdirSync(path.dirname(stageDir)); } catch {}
    if (sqliteSnapshot?.stageDir) {
      try { fs.rmSync(sqliteSnapshot.stageDir, { recursive: true, force: true }); }
      catch (error) {
        const evidence = { code: "SQLITE_STAGE_CLEANUP_FAILED", message: "SQLite staging cleanup failed" };
        if (outcomeError) outcomeError.sqliteStageCleanupFailure = evidence;
        if (saved?.status === "success") {
          saved.metadata = { ...saved.metadata, sqliteStageCleanup: evidence };
          try { backupRepository.saveBackup(saved); } catch (persistError) { outcomeError = outcomeError || persistError; }
        }
        console.error(`[backup] ${evidence.code}`);
      }
    }
    release();
  }
}

function listBackups() {
  return backupRepository.listBackups().map((backup) => ({
    ...backup,
    exists: Boolean(getArchivePath(backup.filename) && fs.existsSync(getArchivePath(backup.filename))),
  }));
}

function getBackupOrThrow(id) {
  if (!/^[a-f0-9-]{36}$/i.test(String(id || ""))) throw new Error("Backup invalido");
  const backup = backupRepository.getBackup(id);
  if (!backup) throw new Error("Backup nao encontrado");
  const archivePath = getArchivePath(backup.filename);
  if (!archivePath || !fs.existsSync(archivePath)) throw new Error("Arquivo de backup nao encontrado");
  return { backup, archivePath };
}

function deleteBackup(id) {
  const release = acquireLock("delete");
  try {
    const { backup, archivePath } = getBackupOrThrow(id);
    fs.rmSync(archivePath, { force: true });
    backupRepository.deleteBackup(backup.id);
    return backup;
  } finally {
    release();
  }
}

function latestStatus() {
  return backupRepository.latestStatus();
}

module.exports = {
  BACKUPS_DIR,
  LOCK_FILE,
  LOCK_TAKEOVER_DIR,
  RETENTION_TRANSACTIONS_DIR,
  acquireLock,
  calculateFileHash,
  cleanupRetention,
  createBackup,
  createZipArchive,
  deleteBackup,
  getArchivePath,
  getBackupOrThrow,
  latestStatus,
  listBackups,
  setCloudStorage,
  recoverRetentionTombstones,
};
