const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { getDb, getDatabasePath, isDbEnabled, isStrictSyncModeObserved } = require("../db");
const { ensureWindowsChunkUploadRoot } = require("../services/chunkUploadWindowsAcl");
const { verifyWindowsChunkUploadTree } = require("../services/chunkUploadWindowsAcl");
const { assertNoLocalStrictSyncWriter, isStrictSyncAccountFenceConfigured } =
  require("../src/services/syncSqliteAccountWriteFence");
const { assertPrivateSqliteDirectory } = require("../src/services/zk1PrivateSqlitePath");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { renameSyncWithWindowsEpermRetry } = require("../src/fs-atomic-rename");
const { jsonStringify, runWrite, safeJsonParse } = require("./repositoryUtils");
const MAX_DEFERRED_AUDITS = 4096;
// The archival record is deliberately retained, but its capacity is finite.
// Never silently evict audit evidence to recover space: reject archiving and
// require operator intervention before any configured hard limit is exceeded.
const MAX_ARCHIVED_AUDITS = 100000;
const MAX_ARCHIVED_BYTES = 512 * 1024 * 1024;
const preparedJournals = new Set();

function assertNoStrictAuditRestore() {
  // A durable whole-restore coordinator is written before the pre-restore
  // backup. Refuse any NEW audit mutation until the restart/rollback barrier
  // clears, including other Node processes sharing this runtime. Reads remain
  // possible so the restore can preserve the full acknowledged evidence set.
  const coordinator = resolveRuntimePath("data", ".rootark-restore-coordinator.json");
  let status;
  try { status = fs.lstatSync(coordinator); }
  catch (error) {
    if (error?.code === "ENOENT") return;
    throw Object.assign(new Error("Strict audit restore barrier unavailable", { cause: error }), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
  if (status) {
    throw Object.assign(new Error("Strict audit writes blocked during whole restore"), {
      code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
    });
  }
}

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

function sidecarUnavailable(error) {
  if (error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE") return error;
  return Object.assign(new Error("Durable strict audit journal unavailable or corrupt", { cause: error }), {
    code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
  });
}

function assertAuditTableSchema(db, name) {
  const type = db.prepare("SELECT type FROM sqlite_master WHERE name = ?").get(name);
  if (type?.type !== "table") throw new Error("Invalid durable audit table type");
  const columns = db.pragma(`table_info(${name})`);
  if (columns.length !== 2
    || columns[0].name !== "id" || columns[0].type.toUpperCase() !== "TEXT"
    || columns[0].notnull !== 1 || columns[0].pk !== 1
    || columns[1].name !== "event" || columns[1].type.toUpperCase() !== "TEXT"
    || columns[1].notnull !== 1 || columns[1].pk !== 0) {
    throw new Error("Invalid durable audit table schema");
  }
}

// Separate, FULL-durable SQLite sidecar: when strict Sync holds the MAIN SQLite
// writer reservation across fsync, audit events still need a crash-safe home.
// The sidecar never bypasses the main account authorization transaction.
function withPendingAuditDb(callback) {
  let db;
  try {
    const filename = preparePendingAuditJournal();
    assertSafePendingFiles(filename);
    const strict = isStrictSyncModeObserved();
    if (strict && !fs.existsSync(filename)) {
      throw Object.assign(new Error("Previously enrolled strict audit journal missing"), {
        code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
      });
    }
    db = new Database(filename, { timeout: 100, fileMustExist: strict });
    // Sidecar is a separate SQLite file, NOT the locked account authority.
    // A small bounded writer wait serializes peers without a five-second
    // event-loop stall. Exhaustion is explicit fail-closed, never lost log.
    db.pragma("busy_timeout = 100");
    if (strict) {
      // A WAL read may overlap another process's BEGIN IMMEDIATE. Setting
      // journal_mode=WAL again can require a writer lock and turn a harmless
      // read into SQLITE_BUSY before main audit commit. Never mutate an
      // enrolled journal's mode: verify and reject a downgrade instead.
      if (String(db.pragma("journal_mode", { simple: true })).toLowerCase() !== "wal") {
        throw new Error("Durable strict audit journal is not WAL");
      }
    } else {
      db.pragma("journal_mode = WAL");
    }
    db.pragma("synchronous = FULL");
    if (db.pragma("synchronous", { simple: true }) !== 2) throw new Error("Pending audit journal must be durable");
    // On POSIX, SQLite uses the process umask and may otherwise expose new
    // database/WAL files to other users. Restrict the sidecar and companions.
    if (process.platform !== "win32") {
      for (const candidate of [filename, `${filename}-wal`, `${filename}-shm`]) {
        if (fs.existsSync(candidate)) fs.chmodSync(candidate, 0o600);
      }
    }
    // Only initial, unmarked enrollment may initialize schema. Once the main
    // SQLite has durably enrolled strict mode, missing/malformed tables are
    // evidence of loss or tampering, NEVER grounds for recreating empty logs.
    if (!strict) {
      db.exec("CREATE TABLE IF NOT EXISTS pending_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)");
      db.exec("CREATE TABLE IF NOT EXISTS archived_audit (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)");
    }
    assertAuditTableSchema(db, "pending_audit");
    assertAuditTableSchema(db, "archived_audit");
    return callback(db);
  } catch (error) {
    // A strict sidecar SQL error, malformed schema, WAL contention, integrity
    // error or unreadable path MUST propagate as 503; returning a fabricated
    // empty audit list would hide an already acknowledged security event.
    if (isStrictSyncModeObserved()) throw sidecarUnavailable(error);
    throw error;
  } finally {
    if (db) {
      try { db.close(); } catch (error) {
        if (isStrictSyncModeObserved()) throw sidecarUnavailable(error);
        throw error;
      }
    }
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
    assertNoStrictAuditRestore();
    // Reject a conflicting main-table ID BEFORE making the candidate archive
    // event durable in the independent sidecar. The post-archive prune repeats
    // this check against any concurrent main-table changes.
    if (isStrictSyncModeObserved()) {
      const primary = getDb();
      const existing = primary.prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
        target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`);
      for (const log of logs) {
        const main = existing.get(log?.id);
        if (main && !sameAuditEvidence(rowToLog(main), log, true)) {
          throw Error("Strict audit collision has divergent evidence");
        }
      }
    }
    withPendingAuditDb((db) => {
      const insert = db.prepare("INSERT INTO archived_audit(id,event) VALUES (?,?) ON CONFLICT(id) DO NOTHING");
      const clear = db.prepare("DELETE FROM pending_audit WHERE id=?");
      db.transaction(() => {
        assertNoStrictAuditRestore();
        const size = db.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(CAST(event AS BLOB))),0) AS bytes FROM archived_audit").get();
        let count = size.n;
        let bytes = size.bytes;
        const exists = db.prepare("SELECT event FROM archived_audit WHERE id=?");
        const pending = db.prepare("SELECT event FROM pending_audit WHERE id=?");
        for (const log of logs) {
          if (typeof log?.id !== "string" || !log.id || log.id.length > 128) {
            throw new TypeError("Invalid archived audit ID");
          }
          const serialized = JSON.stringify(log);
          if (Buffer.byteLength(serialized) > 64 * 1024) throw new Error("Archived audit too large");
          const archivedEvent = exists.get(log.id);
          const pendingEvent = pending.get(log.id);
          if ((archivedEvent && !sameAuditEvidence(JSON.parse(archivedEvent.event), log))
            || (pendingEvent && !sameAuditEvidence(JSON.parse(pendingEvent.event), log))) {
            throw Error("Strict audit collision has divergent evidence");
          }
          if (!archivedEvent) {
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
    if (isStrictSyncModeObserved()) throw sidecarUnavailable(error);
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
      assertNoStrictAuditRestore();
      const findMain = main.prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
        target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`);
      for (const log of logs) {
        const existing = findMain.get(log.id);
        if (existing && !sameAuditEvidence(rowToLog(existing), log, true)) {
          throw Error("Strict audit collision has divergent evidence");
        }
      }
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
    assertNoStrictAuditRestore();
    withPendingAuditDb((db) => {
      db.transaction(() => {
        assertNoStrictAuditRestore();
        const exists = db.prepare("SELECT event FROM pending_audit WHERE id=?").get(log.id);
        if (exists && !sameAuditEvidence(JSON.parse(exists.event), log)) {
          throw Error("Strict audit collision has divergent evidence");
        }
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

// JSON deployments have no SQLite sidecar. After rollback, preserve the
// restored JSON audit authority and append the coordinator's deterministic
// terminal outcome atomically while ordinary restore writes remain fenced.
function persistJsonTerminalRestoreAudit(log, coordinatorPath, coordinatorBytes) {
  const mainPath = resolveRuntimePath("data", "audit-logs.json");
  const archivePath = resolveRuntimePath("data", "audit-logs-archive.json");
  const read = (filename) => {
    // Re-open through a verified descriptor, never through a pathname that
    // can be replaced after the initial check. An absent historical JSON
    // audit archive is valid; an unsafe existing inode must fail closed.
    let bytes;
    try { bytes = readPinnedRestoreAuditFile(filename, MAX_ARCHIVED_BYTES); }
    catch (error) {
      if (error?.code === "ENOENT") return { logs: [] };
      throw error;
    }
    const parsed = JSON.parse(bytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || !Array.isArray(parsed.logs)) {
      throw new Error("Invalid JSON restore audit history");
    }
    return parsed;
  };
  const main = read(mainPath);
  const archive = read(archivePath);
  const previous = [...main.logs, ...archive.logs].filter((entry) => entry?.id === log.id);
  if (previous.length > 1 || (previous.length === 1 && !sameAuditEvidence(previous[0], log))) {
    throw new Error("JSON restore audit identity collision");
  }
  const latest = readPinnedRestoreAuditFile(coordinatorPath);
  if (!latest.equals(coordinatorBytes)) {
    throw new Error("JSON restore audit coordinator changed during persistence");
  }
  const syncParent = () => {
    if (process.platform === "win32") return;
    const directory = fs.openSync(path.dirname(mainPath), "r");
    try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
  };
  if (previous.length === 1) {
    // If the previous attempt committed the rename but its directory fsync
    // failed, retry durability before allowing coordinator removal.
    syncParent();
    return log.id;
  }
  const temporary = `${mainPath}.${crypto.randomUUID()}.tmp`;
  let published = false;
  try {
    const fd = fs.openSync(temporary, "wx", 0o600);
    try {
      fs.writeFileSync(fd, `${JSON.stringify({ ...main, logs: [...main.logs, log] }, null, 2)}\n`);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    // Do not remove or truncate the original audit history on rename failure.
    renameSyncWithWindowsEpermRetry(temporary, mainPath);
    published = true;
    syncParent();
  } finally {
    if (!published) fs.rmSync(temporary, { force: true });
  }
  return log.id;
}

// The whole-restore coordinator is the only authority that may produce its
// terminal audit event while ordinary audit writers are fenced. A successful
// restore has committed its data; rollback has restored its pre-images.
// Persist the deterministic event in FULL/WAL SQLite or restored JSON audit
// history before the coordinator is removed.
function readPinnedRestoreAuditFile(filename, maxBytes = 256 * 1024) {
  // Open FIRST; all security checks apply to the open descriptor instead of
  // checking a pathname and then opening it in a separate resolution. POSIX
  // O_NOFOLLOW refuses symlinks; Windows verifies the descriptor's file ID
  // against the still-present, non-symlinked directory entry.
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd);
    let entry;
    try { entry = fs.lstatSync(filename); }
    catch (error) {
      // A file removed AFTER successful open is not an absent legacy audit
      // file: it is a failed inode-consistency check, not an empty history.
      throw new Error("Strict restore audit file disappeared after open", { cause: error });
    }
    if (!opened.isFile() || opened.nlink !== 1 || opened.size < 1
      || opened.size > maxBytes || !entry.isFile() || entry.isSymbolicLink()
      || entry.nlink !== 1 || entry.size !== opened.size
      || entry.dev !== opened.dev || entry.ino !== opened.ino) {
      throw new Error("Strict restore audit coordinator changed during open");
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (bytes.length !== opened.size || after.size !== opened.size
      || after.mtimeMs !== opened.mtimeMs) {
      throw new Error("Strict restore audit coordinator changed during read");
    }
    return bytes;
  } finally { fs.closeSync(fd); }
}

function persistTerminalRestoreAudit(coordinator) {
  const filename = resolveRuntimePath("data", ".rootark-restore-coordinator.json");
  const original = readPinnedRestoreAuditFile(filename);
  const current = JSON.parse(original.toString("utf8"));
  const phase = current.phase;
  if (!coordinator || current.transactionId !== coordinator.transactionId
    || current.phase !== coordinator.phase || current.backupId !== coordinator.backupId
    || !["restart_required", "rollback_complete", "cancelled"].includes(phase)
    || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(current.transactionId || "")
    || typeof current.backupId !== "string" || !current.backupId || current.backupId.length > 128
    || !current.restoreAudit || typeof current.restoreAudit !== "object"
    || typeof current.restoreAudit.requestedAt !== "string"
    || !Number.isFinite(Date.parse(current.restoreAudit.requestedAt))) {
    throw new Error("Invalid strict restore audit coordinator state");
  }
  const actor = current.restoreAudit.actor;
  if (!actor || typeof actor.username !== "string" || !actor.username || actor.username.length > 128
    || !["string", "object"].includes(typeof actor.role)
    || typeof actor.ip !== "object" && typeof actor.ip !== "string"
    || typeof actor.userAgent !== "object" && typeof actor.userAgent !== "string") {
    throw new Error("Invalid strict restore audit actor");
  }
  const completed = phase === "restart_required";
  const log = {
    id: `restore-outcome-${current.transactionId}`,
    timestamp: completed ? current.completedAt : current.restoreAudit.requestedAt,
    eventType: completed ? "backup.restore.completed" : "backup.restore.failed",
    severity: completed ? "critical" : "error",
    actor,
    target: { type: "backup", id: current.backupId },
    action: "restore",
    result: completed ? "success" : "failure",
    details: completed
      ? { preRestoreBackupId: current.preRestoreBackupId, restartRecommended: true }
      : { error: "restore_not_committed", phase },
  };
  if (!Number.isFinite(Date.parse(log.timestamp || ""))) throw new Error("Invalid strict restore audit timestamp");
  const serialized = JSON.stringify(log);
  if (Buffer.byteLength(serialized) > 64 * 1024) throw new Error("Strict restore audit entry too large");
  if (!isDbEnabled()) {
    return persistJsonTerminalRestoreAudit(log, filename, original);
  }
  // Verify the authoritative main table before accepting an ID into the
  // sidecar. Never loosen the main SQLite write reservation for this event.
  const main = getDb().prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
    target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`).get(log.id);
  if (main && !sameAuditEvidence(rowToLog(main), log, true)) {
    throw new Error("Strict restore audit identity collision");
  }
  return withPendingAuditDb((db) => db.transaction(() => {
    // The same exact coordinator bytes must still be present at commit time:
    // neither a forged actor nor a different restore transaction can race in.
    const latest = readPinnedRestoreAuditFile(filename);
    if (!latest.equals(original)) {
      throw new Error("Strict restore audit coordinator changed during persistence");
    }
    const pending = db.prepare("SELECT event FROM pending_audit WHERE id=?").get(log.id);
    const archived = db.prepare("SELECT event FROM archived_audit WHERE id=?").get(log.id);
    for (const prior of [pending, archived]) {
      if (prior && !sameAuditEvidence(JSON.parse(prior.event), log)) {
        throw new Error("Strict restore audit identity collision");
      }
    }
    if (pending || archived || main) return log.id;
    if (db.prepare("SELECT COUNT(*) AS count FROM pending_audit").get().count >= MAX_DEFERRED_AUDITS) {
      throw new Error("Strict restore outcome journal capacity exhausted");
    }
    db.prepare("INSERT INTO pending_audit (id,event) VALUES (?,?)").run(log.id, serialized);
    return log.id;
  })());
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

// Match the canonical representation of an event stored in the legacy
// structured main table; raw sidecar JSON retains its complete evidence.
function normalizeMainAuditLog(log) {
  const value = logToRow(log);
  return rowToLog({
    id: value.id,
    event_type: value.eventType,
    severity: value.severity,
    actor_username: value.actorUsername,
    actor_ip: value.actorIp,
    target_type: value.targetType,
    target_id: value.targetId,
    action: value.action,
    result: value.result,
    timestamp: value.timestamp,
    details_json: value.detailsJson,
  });
}

function stableAuditValue(value) {
  if (Array.isArray(value)) return value.map(stableAuditValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableAuditValue(value[key])]));
  }
  return value;
}

function sameAuditEvidence(left, right, structuredMain = false) {
  const a = structuredMain ? normalizeMainAuditLog(left) : left;
  const b = structuredMain ? normalizeMainAuditLog(right) : right;
  return JSON.stringify(stableAuditValue(a)) === JSON.stringify(stableAuditValue(b));
}

function loadAllAuditEvidenceForRestore() {
  // Unlike loadAuditLogs(), do NOT suppress pending/main rows that share an
  // archived ID. A divergent hidden row must abort restore, not be discarded.
  const primary = getDb().prepare(`
    SELECT id, event_type, severity, actor_username, actor_ip, target_type,
      target_id, action, result, timestamp, details_json FROM audit_logs
  `).all().map((row) => ({ source: "main", log: rowToLog(row) }));
  const pending = pendingAudits().map((log) => ({ source: "pending", log }));
  const archived = loadArchivedAuditLogs().logs.map((log) => ({ source: "archived", log }));
  return [...primary, ...pending, ...archived];
}

function loadAuditLogs() {
  try {
    const rows = getDb().prepare(`
    SELECT id, event_type, severity, actor_username, actor_ip, target_type, target_id, action, result, timestamp, details_json
    FROM audit_logs
    ORDER BY timestamp ASC
  `).all();
    const logs = rows.map(rowToLog);
    const seen = new Map(logs.map((log) => [log.id, { log, main: true }]));
    for (const log of pendingAudits()) {
      const older = seen.get(log.id);
      if (older && !sameAuditEvidence(older.log, log, older.main)) {
        throw Error("Strict audit collision has divergent evidence");
      }
      if (!older) { seen.set(log.id, { log, main: false }); logs.push(log); }
    }
    const archived = archivedAuditIds(logs.map(({ id }) => id));
    if (archived.size) withPendingAuditDb((sidecar) => {
      const find = sidecar.prepare("SELECT event FROM archived_audit WHERE id=?");
      for (const id of archived) {
        const row = find.get(id);
        const prior = seen.get(id);
        if (row && prior && !sameAuditEvidence(prior.log, JSON.parse(row.event), prior.main)) {
          throw Error("Strict audit collision has divergent evidence");
        }
      }
    });
    const activeLogs = logs.filter(({ id }) => !archived.has(id));
    activeLogs.sort((a, b) => String(a.timestamp || "").localeCompare(String(b.timestamp || "")));
    return { logs: activeLogs };
  } catch (error) {
    if (isStrictSyncModeObserved()) throw sidecarUnavailable(error);
    throw error;
  }
}

function saveAuditLogsImpl(entries = {}) {
  assertNoStrictAuditRestore();
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
    assertNoStrictAuditRestore();
    if (!protectedAudit) db.prepare("DELETE FROM audit_logs").run();
    // Physical retention: every archive ID is already durably held on the
    // separate FULL journal, so the primary table need not grow forever.
    const archivedEvents = archived.size
      ? new Map(withPendingAuditDb((sidecar) => {
        const get = sidecar.prepare("SELECT event FROM archived_audit WHERE id=?");
        return [...archived].map((id) => [id, get.get(id)?.event]);
      }))
      : new Map();
    if (archived.size) {
      const find = db.prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
        target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`);
      for (const id of archived) {
        const active = find.get(id);
        if (active && (!archivedEvents.get(id)
          || !sameAuditEvidence(rowToLog(active), JSON.parse(archivedEvents.get(id)), true))) {
          throw Error("Strict audit collision has divergent evidence");
        }
      }
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
      if (archived.has(log.id)) {
        const archivedEvent = archivedEvents.get(log.id);
        if (!archivedEvent || !sameAuditEvidence(JSON.parse(archivedEvent), log)) {
          throw Error("Strict audit collision has divergent evidence");
        }
        continue;
      }
      const row = logToRow(log);
      const existing = db.prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
        target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`).get(row.id);
      if (existing && !sameAuditEvidence(rowToLog(existing), log, true)) {
        throw Error("Strict audit collision has divergent evidence");
      }
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
          assertNoStrictAuditRestore();
          const getMain = db.prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
            target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`);
          const getArchived = pending.prepare("SELECT event FROM archived_audit WHERE id=?");
          const getPending = pending.prepare("SELECT event FROM pending_audit WHERE id=?");
          for (const { id } of pending.prepare("SELECT id FROM pending_audit").all()) {
            if (!committedIds.has(id)) continue;
            const pendingLog = JSON.parse(getPending.get(id).event);
            const mainRow = getMain.get(id);
            const archivedRow = getArchived.get(id);
            if ((mainRow && !sameAuditEvidence(rowToLog(mainRow), pendingLog, true))
              || (archivedRow && !sameAuditEvidence(JSON.parse(archivedRow.event), pendingLog))) {
              throw Error("Strict audit collision has divergent evidence");
            }
            if (mainRow || archivedRow) remove.run(id);
          }
        })();
      });
    } catch (error) {
      const sqliteBusy = (value) => ["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_BUSY_SNAPSHOT"].includes(value);
      if (sqliteBusy(error?.code)
        || (error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE" && sqliteBusy(error?.cause?.code))) {
        // Main audit event is already committed and durable. Cleanup is
        // idempotent: ONLY transient SQLite writer contention is deferrable.
        // A malformed schema or integrity error must never be suppressed.
        console.warn("Deferred non-destructive audit journal cleanup after SQLite contention");
      } else {
        throw error;
      }
    }
  }
}

function saveAuditLogs(entries = {}) {
  try {
    return saveAuditLogsImpl(entries);
  } catch (error) {
    if (isStrictSyncModeObserved()) throw sidecarUnavailable(error);
    throw error;
  }
}

module.exports = { loadAuditLogs, saveAuditLogs, deferAuditLog, deferIfStrictSyncWriter,
  preparePendingAuditJournal, ensurePendingAuditDatabase, archiveAuditLogs, loadArchivedAuditLogs,
  normalizeMainAuditLog, loadAllAuditEvidenceForRestore, persistTerminalRestoreAudit, rowToLog };
