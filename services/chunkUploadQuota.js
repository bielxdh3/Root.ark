const cluster = require("node:cluster");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree } = require("./chunkUploadWindowsAcl");

const MAX_SAFE_BYTES = Number.MAX_SAFE_INTEGER;
const DATABASE_NAME = ".quota.sqlite";
const BUSY_TIMEOUT_MS = 3000;
const REQUIRED_TOPOLOGY_ACK = "single-host-local-volume";
const KNOWN_REMOTE_LINUX_FILESYSTEM_TYPES = new Set([
  0x6969, // NFS
  0x517b, // SMB
  0xff534d42, // CIFS / SMB
  0xfe534d42, // SMB2
  0x65735546, // FUSE (including common network mounts such as SSHFS)
  0x01021997, // 9p
  0x00c36400, // Ceph
  0x5346414f, // AFS
  0x6b414653, // AFS (alternate magic)
  0x564c, // NCP
]);
const activeQuotaInstances = new Set();
const STATES = new Set([
  "reserved", "writing", "staged", "promoting", "part_committed", "assembling",
  "assembled", "encrypting", "handoff_pending", "handoff_published", "handed_off", "cleanup_pending",
]);

// The per-account chunk limiter and session locks are process-local, so chunk uploads
// fail closed when this process is a cluster worker or a non-primary PM2 instance.
function detectMultiProcessRuntime(env = process.env, { isWorker = cluster.isWorker } = {}) {
  if (isWorker) return true;
  const instance = env.NODE_APP_INSTANCE;
  return typeof instance === "string" && instance !== "" && instance !== "0";
}

function parseChunkUploadQuotaConfig(env = process.env, runtime = {}) {
  const perAccountText = env.CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES;
  const systemText = env.CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES;
  const perAccountEntriesText = env.CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_ENTRIES;
  const systemEntriesText = env.CHUNK_UPLOAD_QUOTA_SYSTEM_ENTRIES;
  const parse = (value) => {
    if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  };
  const perAccountBytes = parse(perAccountText);
  const systemBytes = parse(systemText);
  const perAccountEntries = parse(perAccountEntriesText);
  const systemEntries = parse(systemEntriesText);
  if (perAccountBytes === null || systemBytes === null || perAccountBytes > systemBytes ||
      perAccountEntries === null || systemEntries === null || perAccountEntries > systemEntries) {
    return { enabled: false, reason: "invalid_configuration" };
  }
  if (env.CHUNK_UPLOAD_STORAGE_TOPOLOGY !== REQUIRED_TOPOLOGY_ACK) {
    return { enabled: false, reason: "topology_not_acknowledged" };
  }
  if (detectMultiProcessRuntime(env, runtime)) {
    return { enabled: false, reason: "multi_process_runtime" };
  }
  return { enabled: true, perAccountBytes, systemBytes, perAccountEntries, systemEntries };
}

function assertSafeChunkUploadAncestors(directory, { platform = process.platform, uid = process.getuid?.() } = {}) {
  if (platform === "win32") return;
  if (!Number.isInteger(uid)) throw new Error("Unable to verify chunk-upload storage owner");

  const resolved = path.resolve(directory);
  const pathRoot = path.parse(resolved).root;
  const segments = resolved.slice(pathRoot.length).split(path.sep).filter(Boolean);
  let current = pathRoot;
  for (let index = 0; index < segments.length; index += 1) {
    current = path.join(current, segments[index]);
    let stats;
    try {
      stats = fs.lstatSync(current);
    } catch (error) {
      if (error.code === "ENOENT" && index === segments.length - 1) return;
      throw error;
    }
    if (stats.isSymbolicLink() || !stats.isDirectory()) throw new Error("Unsafe chunk-upload storage ancestor");
    if (stats.uid !== 0 && stats.uid !== uid) throw new Error("Untrusted chunk-upload storage ancestor owner");
    const writableByGroupOrOther = (stats.mode & 0o022) !== 0;
    const sticky = (stats.mode & 0o1000) !== 0;
    const isTargetDirectory = index === segments.length - 1;
    if (writableByGroupOrOther && (!sticky || isTargetDirectory)) throw new Error("Writable chunk-upload storage ancestor");
  }
}

function assertSupportedChunkUploadFilesystem(rootDir, { platform = process.platform, statfs = fs.statfsSync } = {}) {
  if (platform === "win32") {
    if (/^(?:\\\\|\/\/)/.test(rootDir)) throw new Error("Unsupported network filesystem for chunk uploads");
    return;
  }
  if (platform !== "linux") return;
  if (typeof statfs !== "function") throw new Error("Unable to verify chunk-upload filesystem type");
  let type;
  try {
    const rawType = statfs(rootDir).type;
    if (typeof rawType !== "number" || !Number.isSafeInteger(rawType)) throw new Error("Filesystem type is unavailable");
    type = rawType >>> 0;
  } catch {
    throw new Error("Unable to verify chunk-upload filesystem type");
  }
  if (KNOWN_REMOTE_LINUX_FILESYSTEM_TYPES.has(type)) throw new Error("Unsupported remote filesystem for chunk uploads");
}

function canonicalAccountKey(username) {
  if (typeof username !== "string" || !username.trim()) throw new TypeError("Invalid chunk quota account identity");
  return username.trim().toLowerCase();
}

function validateRelativePath(relativePath) {
  if (typeof relativePath !== "string" || !relativePath || path.isAbsolute(relativePath)) {
    throw new TypeError("Invalid chunk quota relative path");
  }
  const segments = relativePath.split(/[\\/]/);
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw new TypeError("Invalid chunk quota relative path");
  }
  return segments.join(path.sep);
}

function safeByteCount(value) {
  const bytes = Number(value);
  if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Error("Invalid chunk quota accounting total");
  return bytes;
}

function normalizeProcessIdentity(identity) {
  if (!identity || typeof identity !== "object" || identity.version !== 1 || typeof identity.platform !== "string") return null;
  const stringOrNull = (value) => typeof value === "string" && value.length > 0 ? value : null;
  const normalized = {
    version: 1,
    platform: identity.platform,
    hostId: stringOrNull(identity.hostId),
    bootId: stringOrNull(identity.bootId),
    pidNamespace: stringOrNull(identity.pidNamespace),
    processStartTime: stringOrNull(identity.processStartTime),
  };
  if (normalized.platform === "linux" &&
      (!/^[a-f0-9]{64}$/.test(normalized.hostId || "") ||
       !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(normalized.bootId || "") ||
       !/^pid:\[\d+\]$/.test(normalized.pidNamespace || "") ||
       !/^\d+$/.test(normalized.processStartTime || ""))) return null;
  return normalized;
}

function serializeProcessIdentity(identity) {
  const normalized = normalizeProcessIdentity(identity);
  return normalized ? JSON.stringify(normalized) : null;
}

function parseProcessIdentity(value) {
  if (typeof value !== "string" || !value || value.length > 1024) return null;
  try { return normalizeProcessIdentity(JSON.parse(value)); }
  catch { return null; }
}

function readLinuxProcessStartTime(pid) {
  const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  const commandEnd = stat.lastIndexOf(")");
  if (commandEnd < 0) throw new Error("Malformed Linux process stat");
  const fields = stat.slice(commandEnd + 1).trim().split(/\s+/);
  const startTime = fields[19]; // Field 22; the suffix begins at field 3.
  if (!/^\d+$/.test(startTime || "")) throw new Error("Malformed Linux process start time");
  return startTime;
}

function linuxProcfsMatchesPidNamespace(pidNamespace, readlinkSync = fs.readlinkSync, readFileSync = fs.readFileSync, currentPid = process.pid) {
  try {
    // PID 1's namespace link may be hidden from unprivileged services; validate procfs through self and its visible PID instead.
    if (readlinkSync("/proc/self/ns/pid") !== pidNamespace) return false;
    const stat = readFileSync("/proc/self/stat", "utf8");
    const pidSeparator = stat.indexOf(" ");
    if (pidSeparator <= 0) return false;
    const visiblePid = Number(stat.slice(0, pidSeparator));
    return Number.isSafeInteger(visiblePid) && visiblePid === currentPid;
  } catch {
    return false;
  }
}

function getCurrentProcessIdentity(pid = process.pid) {
  if (pid !== process.pid) return null;
  if (process.platform !== "linux") {
    return normalizeProcessIdentity({ version: 1, platform: process.platform });
  }
  try {
    const machineId = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
      .map((filePath) => {
        try { return fs.readFileSync(filePath, "utf8").trim(); }
        catch { return ""; }
      })
      .find(Boolean);
    const bootId = fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    const pidNamespace = fs.readlinkSync("/proc/self/ns/pid");
    if (!linuxProcfsMatchesPidNamespace(pidNamespace, fs.readlinkSync, fs.readFileSync, pid)) return null;
    const processStartTime = readLinuxProcessStartTime(pid);
    if (!machineId || !bootId || !pidNamespace || !processStartTime) return null;
    const hostId = crypto.createHash("sha256").update(`rootark-chunk-quota-host\0${machineId}`).digest("hex");
    return normalizeProcessIdentity({ version: 1, platform: "linux", hostId, bootId, pidNamespace, processStartTime });
  } catch {
    return null;
  }
}

function classifyProcessOwner(ownerPid, ownerIdentity, currentIdentity, { platform = process.platform, kill = process.kill, readlinkSync = fs.readlinkSync, readFileSync = fs.readFileSync } = {}) {
  if (!Number.isSafeInteger(ownerPid) || ownerPid <= 0) return "unknown";
  const owner = typeof ownerIdentity === "string" ? parseProcessIdentity(ownerIdentity) : normalizeProcessIdentity(ownerIdentity);
  const current = typeof currentIdentity === "string" ? parseProcessIdentity(currentIdentity) : normalizeProcessIdentity(currentIdentity);
  if (!owner || !current || owner.platform !== platform || current.platform !== platform) return "unknown";

  if (platform === "linux") {
    if (owner.hostId !== current.hostId || owner.bootId !== current.bootId || owner.pidNamespace !== current.pidNamespace) return "unknown";
    if (!linuxProcfsMatchesPidNamespace(current.pidNamespace, readlinkSync, readFileSync, process.pid)) return "unknown";
    try {
      const namespace = readlinkSync(`/proc/${ownerPid}/ns/pid`);
      if (namespace !== owner.pidNamespace) return "unknown";
      return readLinuxProcessStartTime(ownerPid) === owner.processStartTime ? "live" : "dead";
    } catch (error) {
      if (error.code === "ENOENT" || error.code === "ESRCH") return "dead";
      return "unknown";
    }
  }

  // Other platforms lack a portable process-start identity here. A present PID is
  // therefore treated as live, including a potentially reused PID.
  try {
    kill(ownerPid, 0);
    return "live";
  } catch (error) {
    return error.code === "ESRCH" ? "dead" : "unknown";
  }
}

function ensureSafeDatabaseFile(databasePath) {
  let stats;
  try {
    stats = fs.lstatSync(databasePath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    try {
      const descriptor = fs.openSync(databasePath, "wx", 0o600);
      fs.closeSync(descriptor);
    } catch (createError) {
      if (createError.code !== "EEXIST") throw createError;
    }
    stats = fs.lstatSync(databasePath);
  }
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) {
    throw new Error("Unsafe chunk quota database file");
  }
  if (process.platform !== "win32" && (stats.mode & 0o077) !== 0) {
    fs.chmodSync(databasePath, 0o600);
  }
}

function enableChunkQuotaWal(database) {
  const deadline = Date.now() + BUSY_TIMEOUT_MS;
  const waitCell = new Int32Array(new SharedArrayBuffer(4));
  while (true) {
    try {
      const journalMode = database.pragma("journal_mode = WAL", { simple: true });
      if (typeof journalMode !== "string" || journalMode.toLowerCase() !== "wal") {
        throw new Error("Chunk quota database did not enter WAL mode");
      }
      return;
    } catch (error) {
      if (error.code !== "SQLITE_BUSY" || Date.now() >= deadline) throw error;
      Atomics.wait(waitCell, 0, 0, 10);
    }
  }
}

function ensureSafeSidecarFile(filePath) {
  let stats;
  try {
    stats = fs.lstatSync(filePath);
  } catch (error) {
    if (error.code === "ENOENT") return;
    throw error;
  }
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) throw new Error("Unsafe chunk quota SQLite sidecar");
  if (process.platform !== "win32" && (stats.mode & 0o077) !== 0) fs.chmodSync(filePath, 0o600);
}

function createChunkUploadQuota({ rootDir, perAccountBytes, systemBytes, perAccountEntries, systemEntries, processInstanceId = crypto.randomUUID(), processId = process.pid, processIdentity = undefined, classifyOwner = classifyProcessOwner }) {
  if (!Number.isSafeInteger(perAccountBytes) || perAccountBytes <= 0 || !Number.isSafeInteger(systemBytes) || systemBytes <= 0 || perAccountBytes > systemBytes ||
      !Number.isSafeInteger(perAccountEntries) || perAccountEntries <= 0 || !Number.isSafeInteger(systemEntries) || systemEntries <= 0 || perAccountEntries > systemEntries) {
    throw new TypeError("Invalid chunk upload quota limits");
  }
  if (typeof classifyOwner !== "function") throw new TypeError("Invalid chunk process owner classifier");
  const ownerProcessIdentity = serializeProcessIdentity(processIdentity === undefined ? getCurrentProcessIdentity() : processIdentity);
  const resolvedRoot = path.resolve(rootDir);
  assertSafeChunkUploadAncestors(resolvedRoot);
  assertSupportedChunkUploadFilesystem(resolvedRoot);
  ensureWindowsChunkUploadRoot(resolvedRoot);
  verifyWindowsChunkUploadTree(resolvedRoot);
  const rootStats = fs.lstatSync(resolvedRoot);
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory() || path.resolve(fs.realpathSync.native(resolvedRoot)) !== resolvedRoot) {
    throw new Error("Unsafe chunk quota root");
  }
  const databasePath = path.join(resolvedRoot, DATABASE_NAME);
  ensureSafeDatabaseFile(databasePath);
  for (const suffix of ["-journal", "-wal", "-shm"]) ensureSafeSidecarFile(`${databasePath}${suffix}`);
  const database = new Database(databasePath, { timeout: BUSY_TIMEOUT_MS });
  try {
    database.pragma(`busy_timeout = ${BUSY_TIMEOUT_MS}`);
    enableChunkQuotaWal(database);
    database.pragma("synchronous = FULL");
    database.pragma("foreign_keys = ON");
    const integrity = database.pragma("integrity_check", { simple: true });
    if (integrity !== "ok") throw new Error("Chunk quota database integrity check failed");
    database.transaction(() => {
      database.exec(`
      CREATE TABLE IF NOT EXISTS quota_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS quota_operations (
        operation_id TEXT PRIMARY KEY,
        account_key TEXT NOT NULL,
        session_key TEXT,
        relative_path TEXT NOT NULL,
        state TEXT NOT NULL,
        charge_bytes INTEGER NOT NULL CHECK (charge_bytes >= 0),
        owner_instance_id TEXT NOT NULL,
        owner_pid INTEGER NOT NULL,
        owner_process_identity TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS quota_operations_account ON quota_operations(account_key);
      CREATE INDEX IF NOT EXISTS quota_operations_path ON quota_operations(relative_path);
      CREATE INDEX IF NOT EXISTS quota_operations_session_state ON quota_operations(session_key, state);
      CREATE TABLE IF NOT EXISTS quota_session_locks (
        session_key TEXT PRIMARY KEY,
        owner_instance_id TEXT NOT NULL,
        owner_pid INTEGER NOT NULL,
        owner_process_identity TEXT,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS quota_usage (
        account_key TEXT PRIMARY KEY,
        charge_bytes INTEGER NOT NULL CHECK (charge_bytes >= 0)
      );
      CREATE TABLE IF NOT EXISTS quota_sessions (
        session_key TEXT PRIMARY KEY,
        account_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS quota_sessions_account ON quota_sessions(account_key);
      `);
      const operationColumns = new Set(database.pragma("table_info(quota_operations)").map((column) => column.name));
      const lockColumns = new Set(database.pragma("table_info(quota_session_locks)").map((column) => column.name));
      if (!operationColumns.has("owner_process_identity")) database.exec("ALTER TABLE quota_operations ADD COLUMN owner_process_identity TEXT");
      if (!lockColumns.has("owner_process_identity")) database.exec("ALTER TABLE quota_session_locks ADD COLUMN owner_process_identity TEXT");
    }).immediate();
    const insert = database.prepare(`
      INSERT INTO quota_operations (
        operation_id, account_key, session_key, relative_path, state, charge_bytes,
        owner_instance_id, owner_pid, owner_process_identity, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const selectOperation = database.prepare("SELECT * FROM quota_operations WHERE operation_id = ?");
    const selectOperationByPath = database.prepare("SELECT * FROM quota_operations WHERE relative_path = ?");
    const selectAllOperations = database.prepare("SELECT * FROM quota_operations ORDER BY operation_id");
    const selectSessionOperations = database.prepare("SELECT * FROM quota_operations WHERE session_key = ?");
    const selectQuotaSession = database.prepare("SELECT * FROM quota_sessions WHERE session_key = ?");
    const selectAllQuotaSessions = database.prepare("SELECT * FROM quota_sessions ORDER BY session_key");
    const selectActiveHandoff = database.prepare("SELECT 1 FROM quota_operations WHERE session_key = ? AND state IN ('handoff_pending', 'handoff_published', 'handed_off') LIMIT 1");
    const selectSystemUsage = database.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'");
    const selectAccountUsage = database.prepare("SELECT charge_bytes FROM quota_usage WHERE account_key = ?");
    const selectAllUsage = database.prepare("SELECT account_key, charge_bytes FROM quota_usage ORDER BY account_key");
    const selectAccountUsageTotals = database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations GROUP BY account_key ORDER BY account_key");
    const selectSessionUsageTotals = database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations WHERE session_key = ? GROUP BY account_key ORDER BY account_key");
    const selectAccountHasOperations = database.prepare("SELECT 1 FROM quota_operations WHERE account_key = ? LIMIT 1");
    const updateOwner = database.prepare("UPDATE quota_operations SET owner_instance_id = ?, owner_pid = ?, owner_process_identity = ?, updated_at = ? WHERE operation_id = ? AND owner_instance_id = ? AND owner_pid = ? AND owner_process_identity IS ?");
    const selectSessionLock = database.prepare("SELECT * FROM quota_session_locks WHERE session_key = ?");
    const insertSessionLock = database.prepare("INSERT INTO quota_session_locks(session_key, owner_instance_id, owner_pid, owner_process_identity, created_at) VALUES (?, ?, ?, ?, ?)");
    const deleteSessionLock = database.prepare("DELETE FROM quota_session_locks WHERE session_key = ? AND owner_instance_id = ? AND owner_pid = ? AND owner_process_identity IS ?");
    const updateOperation = database.prepare(`
      UPDATE quota_operations
      SET session_key = ?, relative_path = ?, state = ?, charge_bytes = ?, updated_at = ?
      WHERE operation_id = ?
    `);
    const deleteOperation = database.prepare("DELETE FROM quota_operations WHERE operation_id = ?");
    const deleteSessionOperations = database.prepare("DELETE FROM quota_operations WHERE session_key = ?");
    const insertQuotaSession = database.prepare("INSERT INTO quota_sessions(session_key, account_key, created_at, updated_at) VALUES (?, ?, ?, ?)");
    const deleteQuotaSession = database.prepare("DELETE FROM quota_sessions WHERE session_key = ?");
    const countSystemEntries = database.prepare("SELECT (SELECT COUNT(*) FROM quota_operations) + (SELECT COUNT(*) FROM quota_sessions) AS entries");
    const countAccountEntries = database.prepare("SELECT (SELECT COUNT(*) FROM quota_operations WHERE account_key = ?) + (SELECT COUNT(*) FROM quota_sessions WHERE account_key = ?) AS entries");
    const selectAccountEntryTotals = database.prepare("SELECT account_key, COUNT(*) AS entries FROM (SELECT account_key FROM quota_operations UNION ALL SELECT account_key FROM quota_sessions) GROUP BY account_key ORDER BY account_key");
    const deleteAllUsage = database.prepare("DELETE FROM quota_usage");
    const deleteAccountUsage = database.prepare("DELETE FROM quota_usage WHERE account_key = ?");
    const setQuotaMetaValue = database.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    const setAccountUsage = database.prepare("INSERT INTO quota_usage(account_key, charge_bytes) VALUES (?, ?) ON CONFLICT(account_key) DO UPDATE SET charge_bytes = excluded.charge_bytes");
    const totalSystem = database.prepare("SELECT COALESCE(SUM(charge_bytes), 0) AS bytes FROM quota_operations");
    const totalAccount = database.prepare("SELECT COALESCE(SUM(charge_bytes), 0) AS bytes FROM quota_operations WHERE account_key = ?");

    const normalizeSessionKey = (sessionKey) => {
      if (typeof sessionKey !== "string") throw new TypeError("Invalid chunk quota session identity");
      const parts = sessionKey.split(/[\\/]/);
      if (parts.length !== 2 || parts.some((part) => !/^[a-zA-Z0-9_-]{1,80}$/.test(part))) throw new TypeError("Invalid chunk quota session identity");
      return parts.join("/");
    };
    const getSystemEntries = () => safeByteCount(countSystemEntries.get().entries);
    const getAccountEntries = (accountKey) => safeByteCount(countAccountEntries.get(accountKey, accountKey).entries);
    const throwEntryQuotaExceeded = () => {
      const error = new Error("Chunk upload entry quota exceeded");
      error.code = "CHUNK_QUOTA_EXCEEDED";
      throw error;
    };
    const registerSessionInTransaction = (sessionKey, accountKey) => {
      const normalizedSession = normalizeSessionKey(sessionKey);
      const existing = selectQuotaSession.get(normalizedSession);
      if (existing) {
        if (existing.account_key !== accountKey) {
          const error = new Error("Chunk quota session has conflicting owners");
          error.code = "CHUNK_QUOTA_SESSION_OWNER_MISMATCH";
          throw error;
        }
        return false;
      }
      if (getSystemEntries() >= systemEntries || getAccountEntries(accountKey) >= perAccountEntries) throwEntryQuotaExceeded();
      const now = Date.now();
      insertQuotaSession.run(normalizedSession, accountKey, now, now);
      return true;
    };
    const entryCapacityExceeded = () => getSystemEntries() > systemEntries ||
      selectAccountEntryTotals.all().some((row) => safeByteCount(row.entries) > perAccountEntries);

    const readUsageNumber = (value, label) => {
      if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`Invalid chunk quota ${label}`);
      return safeByteCount(value);
    };
    const getSystemUsage = () => {
      const row = selectSystemUsage.get();
      if (!row) throw new Error("Chunk quota system usage is missing");
      return readUsageNumber(row.value, "system usage");
    };
    const getAccountUsage = (accountKey) => {
      const row = selectAccountUsage.get(accountKey);
      return row ? safeByteCount(row.charge_bytes) : 0;
    };
    const adjustUsage = (accountKey, delta, { removeIfUnused = false } = {}) => {
      const nextSystemBytes = getSystemUsage() + delta;
      const nextAccountBytes = getAccountUsage(accountKey) + delta;
      if (!Number.isSafeInteger(nextSystemBytes) || nextSystemBytes < 0 || !Number.isSafeInteger(nextAccountBytes) || nextAccountBytes < 0) {
        throw new Error("Chunk quota usage counters are inconsistent");
      }
      setQuotaMetaValue.run("system_charge_bytes", String(nextSystemBytes));
      if (removeIfUnused && nextAccountBytes === 0 && !selectAccountHasOperations.get(accountKey)) deleteAccountUsage.run(accountKey);
      else setAccountUsage.run(accountKey, nextAccountBytes);
    };

    const reserveTransaction = database.transaction((operation) => {
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (ready?.value !== "1") throw new Error("Chunk quota ledger is not ready");
      if (operation.sessionKey) registerSessionInTransaction(operation.sessionKey, operation.accountKey);
      if (getSystemEntries() >= systemEntries || getAccountEntries(operation.accountKey) >= perAccountEntries) throwEntryQuotaExceeded();
      const systemTotal = getSystemUsage();
      const accountTotal = getAccountUsage(operation.accountKey);
      if (operation.chargeBytes > systemBytes - systemTotal || operation.chargeBytes > perAccountBytes - accountTotal) {
        const error = new Error("Chunk upload storage quota exceeded");
        error.code = "CHUNK_QUOTA_EXCEEDED";
        throw error;
      }
      const now = Date.now();
      insert.run(
        operation.operationId, operation.accountKey, operation.sessionKey, operation.relativePath,
        operation.state, operation.chargeBytes, processInstanceId, processId, ownerProcessIdentity, now, now,
      );
      adjustUsage(operation.accountKey, operation.chargeBytes);
    });

    const transitionTransaction = database.transaction((operation) => {
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (ready?.value !== "1") throw new Error("Chunk quota ledger is not ready");
      const previous = selectOperation.get(operation.operationId);
      if (!previous) throw new Error("Unknown chunk quota operation");
      const nextSessionKey = operation.sessionKey === undefined
        ? previous.session_key
        : normalizeSessionKey(operation.sessionKey);
      if (previous.session_key && nextSessionKey !== previous.session_key) throw new Error("Chunk quota operation cannot change sessions");
      if (nextSessionKey) registerSessionInTransaction(nextSessionKey, previous.account_key);
      const previousCharge = safeByteCount(previous.charge_bytes);
      const systemTotal = getSystemUsage();
      const accountTotal = getAccountUsage(previous.account_key);
      if (systemTotal < previousCharge || accountTotal < previousCharge) throw new Error("Chunk quota usage counters are inconsistent");
      const systemOther = systemTotal - previousCharge;
      const accountOther = accountTotal - previousCharge;
      if (operation.chargeBytes > systemBytes - systemOther || operation.chargeBytes > perAccountBytes - accountOther) {
        const error = new Error("Chunk upload storage quota exceeded");
        error.code = "CHUNK_QUOTA_EXCEEDED";
        throw error;
      }
      updateOperation.run(
        nextSessionKey,
        operation.relativePath ?? previous.relative_path,
        operation.state,
        operation.chargeBytes,
        Date.now(),
        operation.operationId,
      );
      adjustUsage(previous.account_key, operation.chargeBytes - previousCharge);
    });

    const releaseTransaction = database.transaction((operationId) => {
      const previous = selectOperation.get(operationId);
      if (!previous) return false;
      const deleted = deleteOperation.run(operationId).changes === 1;
      if (!deleted) return false;
      adjustUsage(previous.account_key, -safeByteCount(previous.charge_bytes), { removeIfUnused: true });
      return true;
    });
    const releaseSessionTransaction = database.transaction((sessionKey) => {
      const accountTotals = selectSessionUsageTotals.all(sessionKey);
      const deleted = deleteSessionOperations.run(sessionKey).changes;
      for (const row of accountTotals) adjustUsage(row.account_key, -safeByteCount(row.bytes), { removeIfUnused: true });
      deleteQuotaSession.run(sessionKey);
      return deleted;
    });
    const releaseSessionOperationsTransaction = database.transaction((sessionKey) => {
      const accountTotals = selectSessionUsageTotals.all(sessionKey);
      const deleted = deleteSessionOperations.run(sessionKey).changes;
      for (const row of accountTotals) adjustUsage(row.account_key, -safeByteCount(row.bytes), { removeIfUnused: true });
      return deleted;
    });
    const registerSessionsTransaction = database.transaction((sessions) => {
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (ready?.value !== "1") throw new Error("Chunk quota ledger is not ready");
      for (const session of sessions) {
        if (!session || typeof session !== "object") throw new TypeError("Invalid chunk quota session import");
        registerSessionInTransaction(session.sessionKey, canonicalAccountKey(session.accountKey));
      }
      return sessions.length;
    });
    const totalsTransaction = database.transaction(() => {
      const systemBytes = safeByteCount(totalSystem.get().bytes);
      const accounts = Object.fromEntries(database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations GROUP BY account_key ORDER BY account_key").all().map((row) => [row.account_key, safeByteCount(row.bytes)]));
      return { systemBytes, accounts };
    });
    const entryTotalsTransaction = database.transaction(() => {
      const systemEntries = getSystemEntries();
      const accounts = Object.fromEntries(selectAccountEntryTotals.all().map((row) => [row.account_key, safeByteCount(row.entries)]));
      return { systemEntries, accounts };
    });
    const migrateUsageTransaction = database.transaction(() => {
      const operationColumns = new Set(database.pragma("table_info(quota_operations)").map((column) => column.name));
      const lockColumns = new Set(database.pragma("table_info(quota_session_locks)").map((column) => column.name));
      if (!operationColumns.has("owner_process_identity")) database.exec("ALTER TABLE quota_operations ADD COLUMN owner_process_identity TEXT");
      if (!lockColumns.has("owner_process_identity")) database.exec("ALTER TABLE quota_session_locks ADD COLUMN owner_process_identity TEXT");
      const version = database.prepare("SELECT value FROM quota_meta WHERE key = 'schema_version'").get();
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (!version) {
        if (ready?.value === "1") throw new Error("Chunk quota schema version is missing");
        return false;
      }
      if (!["1", "2", "3", "4"].includes(version.value)) throw new Error("Unsupported chunk quota schema version");
      if (ready && !["0", "1"].includes(ready.value)) throw new Error("Invalid chunk quota readiness marker");

      let schemaVersion = version.value;
      if (schemaVersion === "1") {
        if (ready?.value === "1") {
          deleteAllUsage.run();
          for (const row of selectAccountUsageTotals.all()) setAccountUsage.run(row.account_key, safeByteCount(row.bytes));
          setQuotaMetaValue.run("system_charge_bytes", String(safeByteCount(totalSystem.get().bytes)));
          setQuotaMetaValue.run("usage_version", "1");
        }
        setQuotaMetaValue.run("schema_version", "2");
        schemaVersion = "2";
      }

      if (ready?.value === "1") {
        const usageVersion = database.prepare("SELECT value FROM quota_meta WHERE key = 'usage_version'").get();
        if (usageVersion?.value !== "1") throw new Error("Chunk quota usage version is missing");
        if (getSystemUsage() !== safeByteCount(totalSystem.get().bytes)) throw new Error("Chunk quota system usage does not match its ledger");
        const expected = selectAccountUsageTotals.all().map((row) => [row.account_key, safeByteCount(row.bytes)]);
        const actual = selectAllUsage.all().map((row) => [row.account_key, safeByteCount(row.charge_bytes)]);
        if (JSON.stringify(expected) !== JSON.stringify(actual)) throw new Error("Chunk quota account usage does not match its ledger");
      }

      if (schemaVersion === "2") {
        const sessions = database.prepare(`
          SELECT session_key, MIN(account_key) AS account_key, COUNT(DISTINCT account_key) AS account_count
          FROM quota_operations
          WHERE session_key IS NOT NULL
          GROUP BY session_key
          ORDER BY session_key
        `).all();
        for (const session of sessions) {
          if (safeByteCount(session.account_count) !== 1) throw new Error("Chunk quota session has conflicting owners");
          const existing = selectQuotaSession.get(session.session_key);
          if (existing && existing.account_key !== session.account_key) throw new Error("Chunk quota session has conflicting owners");
          if (!existing) insertQuotaSession.run(session.session_key, session.account_key, Date.now(), Date.now());
        }
        setQuotaMetaValue.run("schema_version", "3");
        schemaVersion = "3";
      }

      if (schemaVersion === "3") {
        const missingSession = database.prepare(`
          SELECT 1 FROM quota_operations operations
          LEFT JOIN quota_sessions sessions ON sessions.session_key = operations.session_key
          WHERE operations.session_key IS NOT NULL AND (sessions.session_key IS NULL OR sessions.account_key <> operations.account_key)
          LIMIT 1
        `).get();
        if (missingSession) throw new Error("Chunk quota session entries do not match the operation ledger");
        setQuotaMetaValue.run("schema_version", "4");
        schemaVersion = "4";
      }
      if (schemaVersion === "4") {
        return entryCapacityExceeded();
      }
      return false;
    });
    const initializeTransaction = database.transaction((importOperations = [], importSessions = []) => {
      const version = database.prepare("SELECT value FROM quota_meta WHERE key = 'schema_version'").get();
      if (version && version.value !== "4") throw new Error("Unsupported chunk quota schema version");
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (ready?.value === "1") return { alreadyReady: true, entryCapacityExceeded: entryCapacityExceeded() };
      if (ready && ready.value !== "0") throw new Error("Invalid chunk quota readiness marker");
      setQuotaMetaValue.run("schema_version", "4");
      setQuotaMetaValue.run("ready", "0");
      setQuotaMetaValue.run("system_charge_bytes", "0");
      deleteAllUsage.run();
      const importedSessions = new Map();
      for (const session of importSessions) {
        if (!session || typeof session !== "object") throw new TypeError("Invalid chunk quota session import");
        const sessionKey = normalizeSessionKey(session.sessionKey);
        const accountKey = canonicalAccountKey(session.accountKey);
        const previous = importedSessions.get(sessionKey);
        if (previous && previous !== accountKey) throw new Error("Chunk quota session has conflicting owners");
        importedSessions.set(sessionKey, accountKey);
      }
      for (const operation of importOperations) {
        const normalized = {
          operationId: operation.operationId,
          accountKey: canonicalAccountKey(operation.accountKey),
          sessionKey: operation.sessionKey == null ? null : normalizeSessionKey(operation.sessionKey),
          relativePath: validateRelativePath(operation.relativePath),
          state: operation.state,
          chargeBytes: safeByteCount(operation.chargeBytes),
        };
        if (!/^[a-zA-Z0-9_-]{1,120}$/.test(normalized.operationId) || !STATES.has(normalized.state)) throw new Error("Invalid imported chunk quota operation");
        if (normalized.sessionKey) {
          const previous = importedSessions.get(normalized.sessionKey);
          if (previous && previous !== normalized.accountKey) throw new Error("Chunk quota session has conflicting owners");
          importedSessions.set(normalized.sessionKey, normalized.accountKey);
        }
        const now = Date.now();
        insert.run(normalized.operationId, normalized.accountKey, normalized.sessionKey, normalized.relativePath, normalized.state, normalized.chargeBytes, processInstanceId, processId, ownerProcessIdentity, now, now);
      }
      for (const [sessionKey, accountKey] of importedSessions) registerSessionInTransaction(sessionKey, accountKey);
      const importedSystemBytes = safeByteCount(totalSystem.get().bytes);
      const importedAccounts = database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations GROUP BY account_key").all();
      if (importedSystemBytes > systemBytes || importedAccounts.some((row) => safeByteCount(row.bytes) > perAccountBytes)) {
        throw new Error("Existing chunk staging exceeds configured quota");
      }
      for (const row of importedAccounts) setAccountUsage.run(row.account_key, safeByteCount(row.bytes));
      setQuotaMetaValue.run("system_charge_bytes", String(importedSystemBytes));
      setQuotaMetaValue.run("usage_version", "1");
      const hasEntryCapacityExceeded = entryCapacityExceeded();
      setQuotaMetaValue.run("ready", "1");
      return { alreadyReady: false, entryCapacityExceeded: hasEntryCapacityExceeded };
    });
    const initializeAndMigrateTransaction = database.transaction((importOperations, importSessions) => {
      const migrationEntryCapacityExceeded = migrateUsageTransaction();
      const result = initializeTransaction(importOperations, importSessions);
      return { ...result, entryCapacityExceeded: result.entryCapacityExceeded || migrationEntryCapacityExceeded };
    });

    const service = {
      initialize(importOperations = [], importSessions = []) {
        if (!Array.isArray(importOperations) || !Array.isArray(importSessions)) throw new TypeError("Invalid chunk quota import");
        return initializeAndMigrateTransaction.immediate(importOperations, importSessions);
      },
      isReady() {
        const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
        return ready?.value === "1";
      },
      operations() {
        return selectAllOperations.all().map((row) => ({
          operationId: row.operation_id,
          accountKey: row.account_key,
          sessionKey: row.session_key,
          relativePath: row.relative_path,
          state: row.state,
          chargeBytes: Number(row.charge_bytes),
          ownerInstanceId: row.owner_instance_id,
          ownerPid: Number(row.owner_pid),
          ownerProcessIdentity: row.owner_process_identity,
          createdAt: Number(row.created_at),
          updatedAt: Number(row.updated_at),
        }));
      },
      operationsForSession(sessionKey) {
        const normalizedSessionKey = normalizeSessionKey(sessionKey);
        return selectSessionOperations.all(normalizedSessionKey).map((row) => ({
          operationId: row.operation_id,
          accountKey: row.account_key,
          sessionKey: row.session_key,
          relativePath: row.relative_path,
          state: row.state,
          chargeBytes: Number(row.charge_bytes),
          ownerInstanceId: row.owner_instance_id,
          ownerPid: Number(row.owner_pid),
          ownerProcessIdentity: row.owner_process_identity,
          createdAt: Number(row.created_at),
          updatedAt: Number(row.updated_at),
        }));
      },
      hasActiveHandoff(sessionKey) {
        return Boolean(selectActiveHandoff.get(normalizeSessionKey(sessionKey)));
      },
      isCurrentOwner(operation) {
        return Boolean(operation && operation.ownerPid === processId && operation.ownerInstanceId === processInstanceId);
      },
      ownerStatus(operation) {
        if (!operation || !Number.isSafeInteger(operation.ownerPid) || typeof operation.ownerInstanceId !== "string") return "unknown";
        if (service.isCurrentOwner(operation)) return "current";
        if (activeQuotaInstances.has(`${operation.ownerPid}\u0000${operation.ownerInstanceId}`)) return "live";
        return classifyOwner(operation.ownerPid, operation.ownerProcessIdentity, ownerProcessIdentity);
      },
      claim(operation) {
        if (!operation || typeof operation.operationId !== "string" || typeof operation.ownerInstanceId !== "string" || !Number.isSafeInteger(operation.ownerPid)) throw new TypeError("Invalid chunk quota claim");
        if (service.ownerStatus(operation) !== "dead") return false;
        return database.transaction(() => updateOwner.run(processInstanceId, processId, ownerProcessIdentity, Date.now(), operation.operationId, operation.ownerInstanceId, operation.ownerPid, operation.ownerProcessIdentity ?? null).changes === 1).immediate();
      },
      restoreOwner(operation) {
        if (!operation || typeof operation.operationId !== "string" || typeof operation.ownerInstanceId !== "string" || !Number.isSafeInteger(operation.ownerPid)) throw new TypeError("Invalid chunk quota owner restoration");
        return database.transaction(() => updateOwner.run(operation.ownerInstanceId, operation.ownerPid, operation.ownerProcessIdentity ?? null, Date.now(), operation.operationId, processInstanceId, processId, ownerProcessIdentity).changes === 1).immediate();
      },
      async withSessionLock(sessionKey, callback, { waitMs = 30_000 } = {}) {
        if (typeof sessionKey !== "string" || !sessionKey || typeof callback !== "function" || !Number.isSafeInteger(waitMs) || waitMs < 0) throw new TypeError("Invalid chunk session lock request");
        const deadline = Date.now() + waitMs;
        while (true) {
          const acquired = database.transaction(() => {
            const current = selectSessionLock.get(sessionKey);
            if (current) {
              const status = service.ownerStatus({
                ownerInstanceId: current.owner_instance_id,
                ownerPid: Number(current.owner_pid),
                ownerProcessIdentity: current.owner_process_identity,
              });
              if (status !== "dead") return false;
              deleteSessionLock.run(sessionKey, current.owner_instance_id, current.owner_pid, current.owner_process_identity ?? null);
            }
            insertSessionLock.run(sessionKey, processInstanceId, processId, ownerProcessIdentity, Date.now());
            return true;
          }).immediate();
          if (acquired) break;
          if (Date.now() >= deadline) {
            const error = new Error("Chunk session lock is busy");
            error.code = "CHUNK_SESSION_LOCK_BUSY";
            throw error;
          }
          await new Promise((resolve) => setTimeout(resolve, Math.min(50, Math.max(1, deadline - Date.now()))));
        }
        try {
          return await callback();
        } finally {
          database.transaction(() => deleteSessionLock.run(sessionKey, processInstanceId, processId, ownerProcessIdentity)).immediate();
        }
      },
      reserve({ operationId = crypto.randomUUID(), accountKey, sessionKey = null, relativePath, reservedBytes, allowZeroBytes = false }) {
        const normalizedAccount = canonicalAccountKey(accountKey);
        const normalizedSession = sessionKey == null ? null : normalizeSessionKey(sessionKey);
        if (typeof operationId !== "string" || !operationId || !Number.isSafeInteger(reservedBytes) || reservedBytes < 0 || (reservedBytes === 0 && allowZeroBytes !== true)) {
          throw new TypeError("Invalid chunk quota reservation");
        }
        reserveTransaction.immediate({ operationId, accountKey: normalizedAccount, sessionKey: normalizedSession, relativePath: validateRelativePath(relativePath), state: "reserved", chargeBytes: reservedBytes });
        return operationId;
      },
      transition({ operationId, state, chargeBytes, sessionKey, relativePath }) {
        if (!STATES.has(state) || !Number.isSafeInteger(chargeBytes) || chargeBytes < 0) throw new TypeError("Invalid chunk quota transition");
        transitionTransaction.immediate({ operationId, state, chargeBytes, sessionKey: sessionKey === undefined ? undefined : normalizeSessionKey(sessionKey), relativePath: relativePath === undefined ? undefined : validateRelativePath(relativePath) });
      },
      operationForPath(relativePath) {
        const rows = selectOperationByPath.all(validateRelativePath(relativePath));
        if (rows.length > 1) throw new Error("Ambiguous chunk quota path");
        const row = rows[0];
        return row ? { operationId: row.operation_id, accountKey: row.account_key, chargeBytes: Number(row.charge_bytes), state: row.state } : null;
      },
      release(operationId) {
        return releaseTransaction.immediate(operationId);
      },
      releaseSession(sessionKey) {
        return releaseSessionTransaction.immediate(normalizeSessionKey(sessionKey));
      },
      releaseSessionOperations(sessionKey) {
        return releaseSessionOperationsTransaction.immediate(normalizeSessionKey(sessionKey));
      },
      registerSession({ sessionKey, accountKey }) {
        return registerSessionsTransaction.immediate([{ sessionKey, accountKey }]);
      },
      registerSessions(sessions) {
        if (!Array.isArray(sessions)) throw new TypeError("Invalid chunk quota session import");
        return registerSessionsTransaction.immediate(sessions);
      },
      sessions() {
        return selectAllQuotaSessions.all().map((row) => ({
          sessionKey: row.session_key,
          accountKey: row.account_key,
          createdAt: Number(row.created_at),
          updatedAt: Number(row.updated_at),
        }));
      },
      totals() {
        return totalsTransaction.immediate();
      },
      entryTotals() {
        return entryTotalsTransaction.immediate();
      },
      close() {
        database.close();
        if (processId === process.pid) activeQuotaInstances.delete(`${processId}\u0000${processInstanceId}`);
      },
    };
    if (processId === process.pid) activeQuotaInstances.add(`${processId}\u0000${processInstanceId}`);
    return service;
  } catch (error) {
    database.close();
    throw error;
  }
}

module.exports = {
  assertSafeChunkUploadAncestors,
  assertSupportedChunkUploadFilesystem,
  canonicalAccountKey,
  classifyProcessOwner,
  createChunkUploadQuota,
  getCurrentProcessIdentity,
  detectMultiProcessRuntime,
  parseChunkUploadQuotaConfig,
};
