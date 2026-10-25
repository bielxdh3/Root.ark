"use strict";

const Database = require("better-sqlite3");
const { getDatabasePath, isDbEnabled, isLegacyJsonWriteEnabled } = require("../../db");

function rejected() {
  return Object.assign(new Error("Sync account authorization revoked"), {
    code: "SYNC_ATOMIC_ACCOUNT_AUTH_REJECTED",
  });
}

function unavailable() {
  return Object.assign(new Error("Durable SQLite sync account authority unavailable"), {
    code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
  });
}

function createSyncSqliteAccountWriteFence() {
  // Every administrative permission, disable, session and deletion mutation
  // must use this authoritative SQLite users table. JSON mirror writes cannot
  // be considered a revocation authority for strict protected Sync.
  if (!isDbEnabled() || isLegacyJsonWriteEnabled()) {
    throw Object.assign(new Error("Strict Sync requires authoritative SQLite accounts without JSON writes"), {
      code: "SYNC_ATOMIC_DEVICE_CONFIGURATION",
    });
  }
  const dbPath = getDatabasePath();

  return async function persistUnderAccountFence(user, operation, persist) {
    if (!user || typeof user.username !== "string" || !user.username
      || !Number.isSafeInteger(user.sessionVersion) || user.sessionVersion < 0
      || typeof persist !== "function") throw rejected();

    let db;
    let insidePersistence = false;
    try {
      // Use an independent connection: a transaction kept open across
      // asynchronous JSON fsync must never expose its SQLite transaction to
      // unrelated requests sharing the application's singleton connection.
      db = new Database(dbPath, { fileMustExist: true, timeout: 30000 });
      db.pragma("busy_timeout = 30000");
      db.pragma("synchronous = FULL");
      if (String(db.pragma("journal_mode", { simple: true })).toLowerCase() !== "wal"
        || db.pragma("synchronous", { simple: true }) !== 2) throw unavailable();

      // Acquires SQLite's interprocess writer reservation BEFORE reading the
      // account. Admin updates in other processes must serialize before or
      // after the entire JSON store lock + durable rename/fsync.
      db.exec("BEGIN IMMEDIATE");
      const row = db.prepare(`SELECT role, permissions_json, session_version, disabled
        FROM users WHERE username = ? AND deleted_at IS NULL`).get(user.username);
      let permissions;
      try { permissions = JSON.parse(row?.permissions_json); } catch { throw unavailable(); }
      if (!row || row.disabled !== 0 || row.session_version !== user.sessionVersion
        || !permissions || typeof permissions !== "object" || Array.isArray(permissions)) throw rejected();
      const can = (name) => row.role === "admin"
        || (Object.hasOwn(permissions, name) && permissions[name] === true);
      if (!can("upload") || (operation.operation === "delete" && !can("delete"))) throw rejected();

      // The SQLite write lock remains held across every await in put(), its
      // device signature verification, JSON writer lock and final fsync.
      // Permission revocation cannot commit between this read and that fsync.
      insidePersistence = true;
      return await persist();
    } catch (error) {
      // Preserve existing Sync signature, replay, lock and indeterminate
      // commit semantics. Only SQLite authority failures map to 503.
      if (insidePersistence) throw error;
      if (error?.code === "SYNC_ATOMIC_ACCOUNT_AUTH_REJECTED") throw error;
      if (error?.code === "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE") throw error;
      throw unavailable();
    } finally {
      if (db) {
        try {
          // No SQLite data changed. Release only after the JSON commit/abort
          // has completed, preserving the exact ordering of admin revocation.
          if (db.inTransaction) db.exec("ROLLBACK");
        } finally {
          db.close();
        }
      }
    }
  };
}

module.exports = { createSyncSqliteAccountWriteFence };
