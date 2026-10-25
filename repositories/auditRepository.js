const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { getDb, getDatabasePath } = require("../db");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { assertNoLocalStrictSyncWriter } = require("../src/services/syncSqliteAccountWriteFence");
const { jsonStringify, runWrite, safeJsonParse } = require("./repositoryUtils");
const MAX_DEFERRED_AUDITS = 4096;
const preparedJournals = new Set();

function auditJournalPath() {
  return path.join(`${getDatabasePath()}.audit-private`, "pending.sqlite");
}

function preparePendingAuditJournal() {
  const filename = auditJournalPath();
  if (preparedJournals.has(filename)) return filename;
  const dir = path.dirname(filename);
  // Initial setup runs at strict Sync route registration, BEFORE requests.
  // Never create sensitive audit content in an untrusted inherited-ACL file.
  if (process.platform === "win32") {
    ensureWindowsChunkUploadRoot(dir);
  } else {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const info = fs.lstatSync(dir);
    if (!info.isDirectory() || info.isSymbolicLink()
      || (info.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && info.uid !== process.getuid())) {
      throw new Error("Private audit journal directory is not owner-only");
    }
  }
  preparedJournals.add(filename);
  return filename;
}

// Separate, FULL-durable SQLite sidecar: when strict Sync holds the MAIN SQLite
// writer reservation across fsync, audit events still need a crash-safe home.
// The sidecar never bypasses the main account authorization transaction.
function withPendingAuditDb(callback) {
  const filename = preparePendingAuditJournal();
  const db = new Database(filename, { timeout: 0 });
  try {
    db.pragma("busy_timeout = 0");
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
    return callback(db);
  } finally {
    db.close();
  }
}

function pendingAudits() {
  // Reads must include the durable sidecar across restarts, before the next
  // normal audit triggers consolidation. Do not fabricate a journal on read.
  if (!fs.existsSync(auditJournalPath())) return [];
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
  logs.sort((a, b) => String(a.timestamp || "").localeCompare(String(b.timestamp || "")));
  return { logs };
}

function saveAuditLogs(entries = {}) {
  assertNoLocalStrictSyncWriter();
  const db = getDb();
  const logs = Array.isArray(entries?.logs) ? entries.logs : [];
  runWrite(db, () => {
    db.prepare("DELETE FROM audit_logs").run();
    const insert = db.prepare(`
      INSERT INTO audit_logs (id, event_type, severity, actor_username, actor_ip, target_type, target_id, action, result, timestamp, details_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        event_type = excluded.event_type,
        severity = excluded.severity,
        actor_username = excluded.actor_username,
        actor_ip = excluded.actor_ip,
        target_type = excluded.target_type,
        target_id = excluded.target_id,
        action = excluded.action,
        result = excluded.result,
        timestamp = excluded.timestamp,
        details_json = excluded.details_json
    `);

    for (const log of logs) {
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
    withPendingAuditDb((pending) => {
      const remove = pending.prepare("DELETE FROM pending_audit WHERE id=?");
      pending.transaction(() => {
        for (const { id } of pending.prepare("SELECT id FROM pending_audit").all()) {
          if (committedIds.has(id)) remove.run(id);
        }
      })();
    });
  }
}

module.exports = { loadAuditLogs, saveAuditLogs, deferAuditLog, deferIfStrictSyncWriter, preparePendingAuditJournal };
