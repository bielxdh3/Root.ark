const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree } = require("./chunkUploadWindowsAcl");

const MAX_SAFE_BYTES = Number.MAX_SAFE_INTEGER;
const DATABASE_NAME = ".quota.sqlite";
const BUSY_TIMEOUT_MS = 3000;
const activeQuotaInstances = new Set();
const STATES = new Set([
  "reserved", "writing", "staged", "promoting", "part_committed", "assembling",
  "assembled", "encrypting", "handoff_pending", "handoff_published", "handed_off", "cleanup_pending",
]);

function parseChunkUploadQuotaConfig(env = process.env) {
  const perAccountText = env.CHUNK_UPLOAD_QUOTA_PER_ACCOUNT_BYTES;
  const systemText = env.CHUNK_UPLOAD_QUOTA_SYSTEM_BYTES;
  const parse = (value) => {
    if (typeof value !== "string" || !/^[1-9][0-9]*$/.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : null;
  };
  const perAccountBytes = parse(perAccountText);
  const systemBytes = parse(systemText);
  if (perAccountBytes === null || systemBytes === null || perAccountBytes > systemBytes) {
    return { enabled: false, reason: "invalid_configuration" };
  }
  return { enabled: true, perAccountBytes, systemBytes };
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

function ensureSafeDatabaseFile(databasePath) {
  let stats;
  try {
    stats = fs.lstatSync(databasePath);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    const descriptor = fs.openSync(databasePath, "wx", 0o600);
    fs.closeSync(descriptor);
    stats = fs.lstatSync(databasePath);
  }
  if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1) {
    throw new Error("Unsafe chunk quota database file");
  }
  if (process.platform !== "win32" && (stats.mode & 0o077) !== 0) {
    fs.chmodSync(databasePath, 0o600);
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

function createChunkUploadQuota({ rootDir, perAccountBytes, systemBytes, processInstanceId = crypto.randomUUID(), processId = process.pid }) {
  if (!Number.isSafeInteger(perAccountBytes) || perAccountBytes <= 0 || !Number.isSafeInteger(systemBytes) || systemBytes <= 0 || perAccountBytes > systemBytes) {
    throw new TypeError("Invalid chunk upload quota limits");
  }
  const resolvedRoot = path.resolve(rootDir);
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
    database.pragma("journal_mode = WAL");
    database.pragma("synchronous = FULL");
    database.pragma("foreign_keys = ON");
    const integrity = database.pragma("integrity_check", { simple: true });
    if (integrity !== "ok") throw new Error("Chunk quota database integrity check failed");
    database.transaction(() => database.exec(`
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
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS quota_usage (
        account_key TEXT PRIMARY KEY,
        charge_bytes INTEGER NOT NULL CHECK (charge_bytes >= 0)
      );
    `)).immediate();
    const insert = database.prepare(`
      INSERT INTO quota_operations (
        operation_id, account_key, session_key, relative_path, state, charge_bytes,
        owner_instance_id, owner_pid, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const selectOperation = database.prepare("SELECT * FROM quota_operations WHERE operation_id = ?");
    const selectOperationByPath = database.prepare("SELECT * FROM quota_operations WHERE relative_path = ?");
    const selectAllOperations = database.prepare("SELECT * FROM quota_operations ORDER BY operation_id");
    const selectSessionOperations = database.prepare("SELECT * FROM quota_operations WHERE session_key = ?");
    const selectActiveHandoff = database.prepare("SELECT 1 FROM quota_operations WHERE session_key = ? AND state IN ('handoff_pending', 'handoff_published', 'handed_off') LIMIT 1");
    const selectSystemUsage = database.prepare("SELECT value FROM quota_meta WHERE key = 'system_charge_bytes'");
    const selectAccountUsage = database.prepare("SELECT charge_bytes FROM quota_usage WHERE account_key = ?");
    const selectAllUsage = database.prepare("SELECT account_key, charge_bytes FROM quota_usage ORDER BY account_key");
    const selectAccountUsageTotals = database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations GROUP BY account_key ORDER BY account_key");
    const selectSessionUsageTotals = database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations WHERE session_key = ? GROUP BY account_key ORDER BY account_key");
    const selectAccountHasOperations = database.prepare("SELECT 1 FROM quota_operations WHERE account_key = ? LIMIT 1");
    const updateOwner = database.prepare("UPDATE quota_operations SET owner_instance_id = ?, owner_pid = ?, updated_at = ? WHERE operation_id = ? AND owner_instance_id = ? AND owner_pid = ?");
    const selectSessionLock = database.prepare("SELECT * FROM quota_session_locks WHERE session_key = ?");
    const insertSessionLock = database.prepare("INSERT INTO quota_session_locks(session_key, owner_instance_id, owner_pid, created_at) VALUES (?, ?, ?, ?)");
    const deleteSessionLock = database.prepare("DELETE FROM quota_session_locks WHERE session_key = ? AND owner_instance_id = ? AND owner_pid = ?");
    const updateOperation = database.prepare(`
      UPDATE quota_operations
      SET session_key = ?, relative_path = ?, state = ?, charge_bytes = ?, updated_at = ?
      WHERE operation_id = ?
    `);
    const deleteOperation = database.prepare("DELETE FROM quota_operations WHERE operation_id = ?");
    const deleteSessionOperations = database.prepare("DELETE FROM quota_operations WHERE session_key = ?");
    const deleteAllUsage = database.prepare("DELETE FROM quota_usage");
    const deleteAccountUsage = database.prepare("DELETE FROM quota_usage WHERE account_key = ?");
    const setQuotaMetaValue = database.prepare("INSERT INTO quota_meta(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
    const setAccountUsage = database.prepare("INSERT INTO quota_usage(account_key, charge_bytes) VALUES (?, ?) ON CONFLICT(account_key) DO UPDATE SET charge_bytes = excluded.charge_bytes");
    const totalSystem = database.prepare("SELECT COALESCE(SUM(charge_bytes), 0) AS bytes FROM quota_operations");
    const totalAccount = database.prepare("SELECT COALESCE(SUM(charge_bytes), 0) AS bytes FROM quota_operations WHERE account_key = ?");

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
        operation.state, operation.chargeBytes, processInstanceId, processId, now, now,
      );
      adjustUsage(operation.accountKey, operation.chargeBytes);
    });

    const transitionTransaction = database.transaction((operation) => {
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (ready?.value !== "1") throw new Error("Chunk quota ledger is not ready");
      const previous = selectOperation.get(operation.operationId);
      if (!previous) throw new Error("Unknown chunk quota operation");
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
        operation.sessionKey ?? previous.session_key,
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
      return deleted;
    });
    const totalsTransaction = database.transaction(() => {
      const systemBytes = safeByteCount(totalSystem.get().bytes);
      const accounts = Object.fromEntries(database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations GROUP BY account_key ORDER BY account_key").all().map((row) => [row.account_key, safeByteCount(row.bytes)]));
      return { systemBytes, accounts };
    });
    const migrateUsageTransaction = database.transaction(() => {
      const version = database.prepare("SELECT value FROM quota_meta WHERE key = 'schema_version'").get();
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (!version) {
        if (ready?.value === "1") throw new Error("Chunk quota schema version is missing");
        return;
      }
      if (!["1", "2"].includes(version.value)) throw new Error("Unsupported chunk quota schema version");
      if (ready && !["0", "1"].includes(ready.value)) throw new Error("Invalid chunk quota readiness marker");

      if (version.value === "1") {
        if (ready?.value === "1") {
          deleteAllUsage.run();
          for (const row of selectAccountUsageTotals.all()) setAccountUsage.run(row.account_key, safeByteCount(row.bytes));
          setQuotaMetaValue.run("system_charge_bytes", String(safeByteCount(totalSystem.get().bytes)));
          setQuotaMetaValue.run("usage_version", "1");
        }
        setQuotaMetaValue.run("schema_version", "2");
        return;
      }

      if (ready?.value === "1") {
        const usageVersion = database.prepare("SELECT value FROM quota_meta WHERE key = 'usage_version'").get();
        if (usageVersion?.value !== "1") throw new Error("Chunk quota usage version is missing");
        if (getSystemUsage() !== safeByteCount(totalSystem.get().bytes)) throw new Error("Chunk quota system usage does not match its ledger");
        const expected = selectAccountUsageTotals.all().map((row) => [row.account_key, safeByteCount(row.bytes)]);
        const actual = selectAllUsage.all().map((row) => [row.account_key, safeByteCount(row.charge_bytes)]);
        if (JSON.stringify(expected) !== JSON.stringify(actual)) throw new Error("Chunk quota account usage does not match its ledger");
      }
    });
    const initializeTransaction = database.transaction((importOperations = []) => {
      const version = database.prepare("SELECT value FROM quota_meta WHERE key = 'schema_version'").get();
      if (version && version.value !== "2") throw new Error("Unsupported chunk quota schema version");
      const ready = database.prepare("SELECT value FROM quota_meta WHERE key = 'ready'").get();
      if (ready?.value === "1") return { alreadyReady: true };
      if (ready && ready.value !== "0") throw new Error("Invalid chunk quota readiness marker");
      setQuotaMetaValue.run("schema_version", "2");
      setQuotaMetaValue.run("ready", "0");
      setQuotaMetaValue.run("system_charge_bytes", "0");
      deleteAllUsage.run();
      for (const operation of importOperations) {
        const normalized = {
          operationId: operation.operationId,
          accountKey: canonicalAccountKey(operation.accountKey),
          sessionKey: operation.sessionKey ?? null,
          relativePath: validateRelativePath(operation.relativePath),
          state: operation.state,
          chargeBytes: safeByteCount(operation.chargeBytes),
        };
        if (!/^[a-zA-Z0-9_-]{1,120}$/.test(normalized.operationId) || !STATES.has(normalized.state)) throw new Error("Invalid imported chunk quota operation");
        const now = Date.now();
        insert.run(normalized.operationId, normalized.accountKey, normalized.sessionKey, normalized.relativePath, normalized.state, normalized.chargeBytes, processInstanceId, processId, now, now);
      }
      const importedSystemBytes = safeByteCount(totalSystem.get().bytes);
      const importedAccounts = database.prepare("SELECT account_key, SUM(charge_bytes) AS bytes FROM quota_operations GROUP BY account_key").all();
      if (importedSystemBytes > systemBytes || importedAccounts.some((row) => safeByteCount(row.bytes) > perAccountBytes)) {
        throw new Error("Existing chunk staging exceeds configured quota");
      }
      for (const row of importedAccounts) setAccountUsage.run(row.account_key, safeByteCount(row.bytes));
      setQuotaMetaValue.run("system_charge_bytes", String(importedSystemBytes));
      setQuotaMetaValue.run("usage_version", "1");
      setQuotaMetaValue.run("ready", "1");
      return { alreadyReady: false };
    });

    const service = {
      initialize(importOperations = []) {
        if (!Array.isArray(importOperations)) throw new TypeError("Invalid chunk quota import");
        migrateUsageTransaction.immediate();
        return initializeTransaction.immediate(importOperations);
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
          createdAt: Number(row.created_at),
          updatedAt: Number(row.updated_at),
        }));
      },
      operationsForSession(sessionKey) {
        if (typeof sessionKey !== "string" || !sessionKey) throw new TypeError("Invalid chunk quota session identity");
        return selectSessionOperations.all(sessionKey).map((row) => ({
          operationId: row.operation_id,
          accountKey: row.account_key,
          sessionKey: row.session_key,
          relativePath: row.relative_path,
          state: row.state,
          chargeBytes: Number(row.charge_bytes),
          ownerInstanceId: row.owner_instance_id,
          ownerPid: Number(row.owner_pid),
          createdAt: Number(row.created_at),
          updatedAt: Number(row.updated_at),
        }));
      },
      hasActiveHandoff(sessionKey) {
        if (typeof sessionKey !== "string" || !sessionKey) throw new TypeError("Invalid chunk quota session identity");
        return Boolean(selectActiveHandoff.get(sessionKey));
      },
      isCurrentOwner(operation) {
        return Boolean(operation && operation.ownerPid === processId && operation.ownerInstanceId === processInstanceId);
      },
      claim(operation) {
        if (!operation || typeof operation.operationId !== "string" || typeof operation.ownerInstanceId !== "string" || !Number.isSafeInteger(operation.ownerPid)) throw new TypeError("Invalid chunk quota claim");
        return database.transaction(() => updateOwner.run(processInstanceId, processId, Date.now(), operation.operationId, operation.ownerInstanceId, operation.ownerPid).changes === 1).immediate();
      },
      async withSessionLock(sessionKey, callback, { waitMs = 30_000 } = {}) {
        if (typeof sessionKey !== "string" || !sessionKey || typeof callback !== "function" || !Number.isSafeInteger(waitMs) || waitMs < 0) throw new TypeError("Invalid chunk session lock request");
        const deadline = Date.now() + waitMs;
        while (true) {
          const acquired = database.transaction(() => {
            const current = selectSessionLock.get(sessionKey);
            if (current) {
              const sameProcess = Number(current.owner_pid) === processId;
              if (activeQuotaInstances.has(`${current.owner_pid}\u0000${current.owner_instance_id}`)) return false;
              if (!sameProcess) {
                let alive = true;
                try { process.kill(Number(current.owner_pid), 0); }
                catch (error) { alive = error.code !== "ESRCH"; }
                if (alive) return false;
              }
              deleteSessionLock.run(sessionKey, current.owner_instance_id, current.owner_pid);
            }
            insertSessionLock.run(sessionKey, processInstanceId, processId, Date.now());
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
          database.transaction(() => deleteSessionLock.run(sessionKey, processInstanceId, processId)).immediate();
        }
      },
      reserve({ operationId = crypto.randomUUID(), accountKey, sessionKey = null, relativePath, reservedBytes, allowZeroBytes = false }) {
        const normalizedAccount = canonicalAccountKey(accountKey);
        if (typeof operationId !== "string" || !operationId || !Number.isSafeInteger(reservedBytes) || reservedBytes < 0 || (reservedBytes === 0 && allowZeroBytes !== true)) {
          throw new TypeError("Invalid chunk quota reservation");
        }
        reserveTransaction.immediate({ operationId, accountKey: normalizedAccount, sessionKey, relativePath: validateRelativePath(relativePath), state: "reserved", chargeBytes: reservedBytes });
        return operationId;
      },
      transition({ operationId, state, chargeBytes, sessionKey, relativePath }) {
        if (!STATES.has(state) || !Number.isSafeInteger(chargeBytes) || chargeBytes < 0) throw new TypeError("Invalid chunk quota transition");
        transitionTransaction.immediate({ operationId, state, chargeBytes, sessionKey, relativePath: relativePath === undefined ? undefined : validateRelativePath(relativePath) });
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
        if (typeof sessionKey !== "string" || !sessionKey) throw new TypeError("Invalid chunk quota session identity");
        return releaseSessionTransaction.immediate(sessionKey);
      },
      totals() {
        return totalsTransaction.immediate();
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

module.exports = { canonicalAccountKey, createChunkUploadQuota, parseChunkUploadQuotaConfig };
