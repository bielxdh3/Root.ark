const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { getDb, getDatabasePath, isStrictSyncModeObserved } = require("../db");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { verifyWindowsChunkUploadTree } = require("../services/chunkUploadWindowsAcl");
const { assertNoLocalStrictSyncWriter, isStrictSyncAccountFenceConfigured } =
  require("../src/services/syncSqliteAccountWriteFence");
const { assertPrivateSqliteDirectory } = require("../src/services/zk1PrivateSqlitePath");
const { jsonStringify, runWrite, safeJsonParse } = require("./repositoryUtils");
const MAX_DEFERRED_AUDITS = 4096;
// The archival record is deliberately retained, but its capacity is finite.
// Never silently evict audit evidence to recover space: reject archiving and
// require operator intervention before any configured hard limit is exceeded.
const MAX_ARCHIVED_AUDITS = 100000;
const MAX_ARCHIVED_BYTES = 512 * 1024 * 1024;
const preparedJournals = new Set();

function auditJournalPath() {
  return path.join(`${getDatabasePath()}.audit-private`, "pending.sqlite");
}

function preparePendingAuditJournal() {
  const filename = auditJournalPath();
  // This check MUST precede preparedJournals caching, mkdir and Windows ACL
  // creator. The strict marker is read from the main SQLite on bootstrap;
  // its presence makes a missing sidecar a potential irreversible audit loss,
  // never an invitation to construct a fresh empty authority.
  if (isStrictSyncModeObserved()
    && (!fs.existsSync(path.dirname(filename)) || !fs.existsSync(filename))) {
    throw Object.assign(new Error("Previously enrolled strict audit journal missing"), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
  if (preparedJournals.has(filename)) return filename;
  const dir = path.dirname(filename);
  // Initial setup runs at strict Sync route registration, BEFORE requests.
  // Never create sensitive audit content in an untrusted inherited-ACL file.
  if (process.platform === "win32") {
    ensureWindowsChunkUploadRoot(dir);
    // "create" checks ancestors but does NOT verify an existing directory
    // DACL or its SQLite/WAL/SHM children. A hostile preexisting tree must
    // fail closed at strict-mode startup.
    verifyWindowsChunkUploadTree(dir);
  } else {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const info = fs.lstatSync(dir);
    if (!info.isDirectory() || info.isSymbolicLink()
      || (info.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && info.uid !== process.getuid())) {
      throw new Error("Private audit journal directory is not owner-only");
    }
    assertPrivateSqliteDirectory(filename);
  }
  preparedJournals.add(filename);
  return filename;
}

function assertSafePendingFiles(filename) {
  for (const candidate of [filename, `${filename}-wal`, `${filename}-shm`]) {
    const info = fs.lstatSync(candidate, { throwIfNoEntry: false });
    if (!info) continue;
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) {
      throw new Error("Unsafe pending audit database / WAL / SHM inode");
    }
    if (process.platform !== "win32") {
      if ((typeof process.getuid === "function" && info.uid !== process.getuid())
        || (info.mode & 0o077) !== 0) {
        throw new Error("Unsafe pending audit file owner or mode");
      }
    }
  }
}

// Separate, FULL-durable SQLite sidecar: when strict Sync holds the MAIN SQLite
// writer reservation across fsync, audit events still need a crash-safe home.
// The sidecar never bypasses the main account authorization transaction.
function withPendingAuditDb(callback) {
  const filename = preparePendingAuditJournal();
  assertSafePendingFiles(filename);
  if (isStrictSyncModeObserved() && !fs.existsSync(filename)) {
    throw Object.assign(new Error("Previously enrolled strict audit journal missing"), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
  const db = new Database(filename, { timeout: 100 });
  try {
    // Sidecar is a separate SQLite file, NOT the locked account authority.
    // A small bounded writer wait serializes peers without a five-second
    // event-loop stall. Exhaustion is explicit fail-closed, never lost log.
    db.pragma("busy_timeout = 100");
    db.pragma("journal_mode = WAL");
    db.pragma("synchronous = FULL");
    if (db.pragma("synchronous", { simple: true }) !== 2) throw new Error("Pending audit journal must be durable");
    // On POSIX, SQLite uses the process umask and may otherwise expose new
    // database/WAL files to other users. Restrict the sidecar and companions.
    if (process.platform !== "win32") {
      for (const candidate of [filename, `${filename}-wal`, `${filename}-shm`]) {
        if (fs.existsSync(candidate)) fs.chmodSync(candidate, 0o600);
      }
    }
    db.exec("CREATE TABLE IF NOT EXISTS pending_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)");
    // The archive is a separate, FULL-durable tombstone ledger. A stale
    // snapshot can never resurrect an archived ID, even after another process
    // drops its staged pending copy.
    db.exec("CREATE TABLE IF NOT EXISTS archived_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)");
    return callback(db);
  } finally {
    db.close();
  }
}

function ensurePendingAuditDatabase() {
  // Called BEFORE durable strict marker enrollment. Once enrolled, missing
  // journal is tamper/corruption, not permission to create a fresh empty one.
  withPendingAuditDb(() => {});
}

function archiveAuditLogs(logs) {
  if (!Array.isArray(logs) || !logs.length) return;
  try {
    withPendingAuditDb((db) => {
      const insert = db.prepare("INSERT INTO archived_audit(id,event) VALUES (?,?) ON CONFLICT(id) DO NOTHING");
      const clear = db.prepare("DELETE FROM pending_audit WHERE id=?");
      db.transaction(() => {
        const size = db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(event)),0) AS bytes FROM archived_audit").get();
        let count = size.n;
        let bytes = size.bytes;
        const exists = db.prepare("SELECT 1 FROM archived_audit WHERE id=?");
        for (const log of logs) {
          if (typeof log?.id !== "string" || !log.id || log.id.length > 128) {
            throw new TypeError("Invalid archived audit ID");
          }
          const serialized = JSON.stringify(log);
          if (Buffer.byteLength(serialized) > 64 * 1024) throw new Error("Archived audit too large");
          if (!exists.get(log.id)) {
            if (++count > MAX_ARCHIVED_AUDITS || (bytes += Buffer.byteLength(serialized)) > MAX_ARCHIVED_BYTES) {
              throw Object.assign(new Error("Durable audit archive capacity reached: operator action required"), {
                code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
              });
            }
          }
          insert.run(log.id, serialized);
          clear.run(log.id);
        }
      })();
    });
    pruneArchivedAuditRows(logs);
  } catch (error) {
    if (["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_BUSY_SNAPSHOT"].includes(error?.code)) {
      throw Object.assign(new Error("Durable audit archive busy", { cause: error }), {
        code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
      });
    }
    throw error;
  }
}

function pruneArchivedAuditRows(logs) {
  // Archived payload first becomes durable in the FULL sidecar. Physical
  // deletion from the active main database is a non-destructive optimization,
  // retried by later audit writes; a busy main writer does not roll back an
  // already acknowledged archive.
  if (!isStrictSyncModeObserved()) return;
  const ids = [...new Set(logs.map(({ id }) => id))];
  if (!ids.length) return;
  try {
    assertNoLocalStrictSyncWriter();
    const main = getDb();
    main.transaction(() => {
      const remove = main.prepare("DELETE FROM audit_logs WHERE id=?");
      for (const id of ids) remove.run(id);
    })();
  } catch (error) {
    if (error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE"
      || ["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_BUSY_SNAPSHOT"].includes(error?.code)) {
      console.warn("Archived audit cleanup deferred while main SQLite writer is busy");
      return;
    }
    throw error;
  }
}

function loadArchivedAuditLogs() {
  if (!fs.existsSync(auditJournalPath())) {
    if (isStrictSyncModeObserved()) throw Object.assign(
      new Error("Enrolled strict audit archive unavailable"), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    return { logs: [] };
  }
  return { logs: withPendingAuditDb((db) =>
    db.prepare("SELECT id,event FROM archived_audit ORDER BY rowid").all().map(({ id, event }) => {
      const entry = JSON.parse(event);
      if (entry.id !== id) throw new Error("Archive audit ID mismatch");
      return entry;
    })) };
}

function archivedAuditIds(candidates) {
  if (!fs.existsSync(auditJournalPath())) {
    if (isStrictSyncModeObserved()) throw Object.assign(
      new Error("Strict audit sidecar missing"), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    return new Set();
  }
  return new Set(withPendingAuditDb((db) => {
    if (!candidates) return db.prepare("SELECT id FROM archived_audit").all().map(({ id }) => id);
    const selected = [];
    const find = db.prepare("SELECT id FROM archived_audit WHERE id=?");
    for (const id of new Set(candidates)) {
      if (typeof id === "string" && find.get(id)) selected.push(id);
    }
    return selected;
  }));
}

function pendingAudits() {
  // Reads must include the durable sidecar across restarts, before the next
  // normal audit triggers consolidation. Do not fabricate a journal on read.
  if (!fs.existsSync(auditJournalPath())) {
    if (isStrictSyncModeObserved()) throw Object.assign(
      new Error("Strict pending audit journal missing"), { code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" });
    return [];
  }
  try {
    return withPendingAuditDb((db) => db.prepare("SELECT id, event FROM pending_audit ORDER BY rowid").all()
      .map(({ id, event }) => {
        const log = JSON.parse(event);
        if (!log || log.id !== id || typeof log.eventType !== "string") {
          throw new Error("Pending audit journal entry failed integrity validation");
        }
        return log;
      }));
  } catch (error) {
    throw Object.assign(new Error("Durable pending audit journal unreadable", { cause: error }), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
}

function deferAuditLog(log) {
  if (!log?.id || typeof log.id !== "string" || log.id.length > 128) throw new TypeError("valid audit id required");
  const serialized = JSON.stringify(log);
  if (Buffer.byteLength(serialized) > 64 * 1024) {
    throw Object.assign(new Error("Pending audit entry too large"), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
  // Commit+fsync completes before auditLog reports success. No in-memory
  // queue, no timer-dependent guarantee and no swallowed errors.
  try {
    withPendingAuditDb((db) => {
      db.transaction(() => {
        const exists = db.prepare("SELECT 1 FROM pending_audit WHERE id=?").get(log.id);
        if (!exists && db.prepare("SELECT COUNT(*) AS n FROM pending_audit").get().n >= MAX_DEFERRED_AUDITS) {
          throw Object.assign(new Error("Durable pending audit capacity exhausted"), {
            code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
          });
        }
        db.prepare("INSERT INTO pending_audit (id,event) VALUES (?,?) ON CONFLICT(id) DO NOTHING")
          .run(log.id, serialized);
      })();
    });
  } catch (error) {
    if (["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_BUSY_SNAPSHOT"].includes(error?.code)) {
      throw Object.assign(new Error("Durable pending audit journal busy", { cause: error }), {
        code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
      });
    }
    throw error;
  }
}

function deferIfStrictSyncWriter(log) {
  try {
    assertNoLocalStrictSyncWriter();
    return false;
  } catch (error) {
    if (error?.code !== "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE") throw error;
    deferAuditLog(log);
    return true;
  }
}

function rowToLog(row) {
  const details = safeJsonParse(row.details_json, {});
  return {
    id: row.id,
    timestamp: row.timestamp,
    eventType: row.event_type,
    severity: row.severity,
    actor: {
      username: row.actor_username || "system",
      role: details.actorRole || null,
      ip: row.actor_ip || null,
      userAgent: details.userAgent || null,
    },
    target: row.target_type || row.target_id
      ? {
          type: row.target_type || null,
          id: row.target_id || null,
          metadata: details.targetMetadata || undefined,
        }
      : null,
    action: row.action,
    result: row.result,
    details: details.details || details,
  };
}

function logToRow(log) {
  const details = {
    details: log.details || {},
    actorRole: log.actor?.role || null,
    userAgent: log.actor?.userAgent || null,
    targetMetadata: log.target?.metadata || null,
  };
  return {
    id: log.id,
    eventType: log.eventType || log.event_type || "system.unknown",
    severity: log.severity || "info",
    actorUsername: log.actor?.username || log.actor_username || "system",
    actorIp: log.actor?.ip || log.actor_ip || null,
    targetType: log.target?.type || log.target_type || null,
    targetId: log.target?.id || log.target_id || null,
    action: log.action || "",
    result: log.result || "success",
    timestamp: log.timestamp || new Date().toISOString(),
    detailsJson: jsonStringify(details),
  };
}

function loadAuditLogs() {
  const rows = getDb().prepare(`
    SELECT id, event_type, severity, actor_username, actor_ip, target_type, target_id, action, result, timestamp, details_json
    FROM audit_logs
    ORDER BY timestamp ASC
  `).all();
  const logs = rows.map(rowToLog);
  const seen = new Set(logs.map(({ id }) => id));
  for (const log of pendingAudits()) {
    if (!seen.has(log.id)) { seen.add(log.id); logs.push(log); }
  }
  const archived = archivedAuditIds(logs.map(({ id }) => id));
  const activeLogs = logs.filter(({ id }) => !archived.has(id));
  activeLogs.sort((a, b) => String(a.timestamp || "").localeCompare(String(b.timestamp || "")));
  return { logs: activeLogs };
}

function saveAuditLogs(entries = {}) {
  assertNoLocalStrictSyncWriter();
  const db = getDb();
  const logs = Array.isArray(entries?.logs) ? entries.logs : [];
  const protectedAudit = isStrictSyncModeObserved();
  if (protectedAudit && !fs.existsSync(auditJournalPath())) {
    throw Object.assign(new Error("Enrolled strict audit journal missing"), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
  // Probe only IDs relevant to the current main table/snapshot. Avoid
  // scanning 100k archive tombstones and issuing 100k DELETEs per request.
  const candidates = protectedAudit
    ? [...db.prepare("SELECT id FROM audit_logs").all().map(({ id }) => id),
      ...logs.map(({ id }) => id)]
    : [];
  const archived = protectedAudit ? archivedAuditIds(candidates) : new Set();
  runWrite(db, () => {
    if (!protectedAudit) db.prepare("DELETE FROM audit_logs").run();
    // Physical retention: every archive ID is already durably held on the
    // separate FULL journal, so the primary table need not grow forever.
    if (archived.size) {
      const remove = db.prepare("DELETE FROM audit_logs WHERE id=?");
      for (const id of archived) remove.run(id);
    }
    // Audit is monotonic: callers often supply whole-table snapshots read
    // BEFORE another process committed a newer event. Blind DELETE+replace
    // makes a late stale snapshot irreversibly erase that event after its
    // sidecar has been acknowledged and cleared. Idempotent UPSERT retains
    // concurrently committed IDs even when absent from the passed snapshot.
    const insert = db.prepare(`
      INSERT INTO audit_logs (id, event_type, severity, actor_username, actor_ip, target_type, target_id, action, result, timestamp, details_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO NOTHING
    `);

    for (const log of logs) {
      if (archived.has(log.id)) continue;
      const row = logToRow(log);
      insert.run(
        row.id,
        row.eventType,
        row.severity,
        row.actorUsername,
        row.actorIp,
        row.targetType,
        row.targetId,
        row.action,
        row.result,
        row.timestamp,
        row.detailsJson
      );
    }
  });
  // A crash after main commit but before sidecar removal is safe: load
  // deduplicates by id, and the next successful save can retry deletion.
  if (fs.existsSync(auditJournalPath())) {
    const committedIds = new Set(logs.map(({ id }) => id));
    try {
      withPendingAuditDb((pending) => {
        const remove = pending.prepare("DELETE FROM pending_audit WHERE id=?");
        pending.transaction(() => {
          for (const { id } of pending.prepare("SELECT id FROM pending_audit").all()) {
            if (committedIds.has(id)) remove.run(id);
          }
        })();
      });
    } catch (error) {
      if (["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_BUSY_SNAPSHOT"].includes(error?.code)) {
        // Main audit event is already committed and durable. Cleanup is
        // idempotent: retaining the pending record is safer than throwing an
        // ambiguous HTTP 500 AFTER acknowledging the primary write.
        console.warn("Deferred non-destructive audit journal cleanup after SQLite contention");
      } else {
        throw error;
      }
    }
  }
}

module.exports = { loadAuditLogs, saveAuditLogs, deferAuditLog, deferIfStrictSyncWriter,
  preparePendingAuditJournal, ensurePendingAuditDatabase, archiveAuditLogs, loadArchivedAuditLogs };
