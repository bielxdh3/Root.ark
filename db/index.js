const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const ROOT_DIR = path.resolve(__dirname, "..");
const DEFAULT_DATABASE_PATH = path.join(ROOT_DIR, "data", "rootark.sqlite");

let dbInstance = null;
let observedPath = null;
let strictSyncModeObserved = false;
const STRICT_SYNC_MARKER = "rootark_strict_sync_audit_mode";
const STRICT_SYNC_BUSY_TIMEOUT_MS = 25;

function strictSyncUnavailable(cause) {
  return Object.assign(new Error("Durable SQLite strict Sync audit authority unavailable", { cause }), {
    code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
  });
}

function normalizeStrictSyncSqliteError(error) {
  if (strictSyncModeObserved && ["SQLITE_BUSY", "SQLITE_BUSY_SNAPSHOT", "SQLITE_LOCKED"].includes(error?.code)) {
    return strictSyncUnavailable(error);
  }
  return error;
}

// The marker is in the SAME durable WAL/FULL database as the audit table.
// Its existence is authoritative across Node processes and unaffected by a
// deleted/renamed auxiliary audit journal. No marker => legacy semantics.
function refreshStrictSyncMode(database) {
  database.pragma("busy_timeout = 0");
  let marked = false;
  try {
    const type = database.prepare("SELECT type FROM sqlite_master WHERE name=?").get(STRICT_SYNC_MARKER);
    if (type) {
      if (type.type !== "table") throw strictSyncUnavailable();
      const records = database.prepare(`SELECT id,mode FROM ${STRICT_SYNC_MARKER}`).all();
      if (records.length !== 1 || records[0].id !== 1 || records[0].mode !== "append_only") {
        throw strictSyncUnavailable();
      }
      marked = true;
    }
    if (strictSyncModeObserved && !marked) throw strictSyncUnavailable();
    if (marked) strictSyncModeObserved = true;
  } catch (error) {
    if (["SQLITE_BUSY", "SQLITE_BUSY_SNAPSHOT", "SQLITE_LOCKED"].includes(error?.code)) {
      throw strictSyncUnavailable(error);
    }
    throw normalizeStrictSyncSqliteError(error);
  } finally {
    database.pragma(`busy_timeout = ${marked || strictSyncModeObserved ? STRICT_SYNC_BUSY_TIMEOUT_MS : 5000}`);
  }
  return marked;
}

function isStrictSyncModeObserved() { return strictSyncModeObserved; }

function isDbEnabled() {
  return String(process.env.DB_ENABLED || "false").toLowerCase() === "true";
}

function isJsonReadFallbackEnabled() {
  return String(process.env.DB_READ_FALLBACK_JSON || "false").toLowerCase() === "true";
}

function isLegacyJsonWriteEnabled() {
  return String(process.env.DB_WRITE_LEGACY_JSON || "false").toLowerCase() === "true";
}

function getDatabasePath() {
  const configured = process.env.DATABASE_URL || DEFAULT_DATABASE_PATH;
  return path.resolve(ROOT_DIR, configured);
}

function getDb() {
  if (dbInstance) {
    refreshStrictSyncMode(dbInstance);
    return dbInstance;
  }

  const databasePath = getDatabasePath();
  if (observedPath !== databasePath) {
    observedPath = databasePath;
    strictSyncModeObserved = false;
  }
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });

  const database = new Database(databasePath, { timeout: 0 });
  try {
    // Configure the required crash durability first. Even a disposable
    // initialization failure must close the connection before any marker
    // lookup; legacy failure-injection tests exercise this ordering.
    database.pragma("busy_timeout = 0");
    database.pragma("journal_mode = WAL");
    // A successful recovery-code spend must survive a system crash before we
    // acknowledge it. WAL's NORMAL mode does not sync each committed write.
    database.pragma("synchronous = FULL");
    refreshStrictSyncMode(database);
    database.pragma("foreign_keys = ON");
    if (String(database.pragma("journal_mode", { simple: true })).toLowerCase() !== "wal"
      || database.pragma("synchronous", { simple: true }) !== 2) {
      throw new Error("SQLite recovery store requires durable WAL/FULL");
    }
    dbInstance = database;
    return dbInstance;
  } catch (error) {
    database.close();
    throw normalizeStrictSyncSqliteError(error);
  }
}

function closeDb() {
  if (!dbInstance) return;
  dbInstance.close();
  dbInstance = null;
}

function safeJsonParse(value, fallback) {
  if (value === null || value === undefined || value === "") return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function jsonStringify(value) {
  return JSON.stringify(value === undefined ? null : value);
}

function nowIso() {
  return new Date().toISOString();
}

function splitStorageKey(key, defaultFolderId = "root") {
  const value = String(key || "");
  const slashIndex = value.indexOf("/");
  if (slashIndex === -1) {
    return { folderId: defaultFolderId, fileName: path.basename(value) };
  }

  return {
    folderId: value.slice(0, slashIndex) || defaultFolderId,
    fileName: path.basename(value.slice(slashIndex + 1)),
  };
}

module.exports = {
  ROOT_DIR,
  DEFAULT_DATABASE_PATH,
  closeDb,
  getDatabasePath,
  getDb,
  isDbEnabled,
  isJsonReadFallbackEnabled,
  isLegacyJsonWriteEnabled,
  isStrictSyncModeObserved,
  normalizeStrictSyncSqliteError,
  jsonStringify,
  nowIso,
  safeJsonParse,
  splitStorageKey,
};
