"use strict";

const Database = require("better-sqlite3");
const { performance } = require("node:perf_hooks");
const { getDatabasePath, isDbEnabled, isLegacyJsonWriteEnabled } = require("../../db");

const localAccountWriters = new Map();
const MAX_LOCAL_WAITERS = 64;
const ACCOUNT_FENCE_WAIT_MS = 30000;
const SQLITE_RETRY_MS = 25;

function assertNoLocalStrictSyncWriter(dbPath = getDatabasePath()) {
  // Existing administrative account writes use a synchronous SQLite
  // connection with a 5s busy_timeout. Never enter that blocking wait on the
  // same Node event loop while a protected Sync owns the SQLite writer lock.
  // The admin write is rejected for a retry; it does not commit stale state.
  if (localAccountWriters.get(dbPath)?.held) throw unavailable();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Process-wide across registerSyncRoutes instances, not a queue per route.
// Only one async Sync writer at a time may enter SQLite's synchronous writer
// reservation on this event loop. A bounded FIFO with timed removal prevents
// overlapping BEGIN IMMEDIATE calls and unbounded request accumulation.
function acquireLocalWriter(dbPath) {
  let gate = localAccountWriters.get(dbPath);
  if (!gate) {
    gate = { held: false, waiters: [] };
    localAccountWriters.set(dbPath, gate);
  }
  const release = () => {
    const next = gate.waiters.shift();
    if (next) {
      clearTimeout(next.timer);
      next.resolve(release);
    } else {
      gate.held = false;
      localAccountWriters.delete(dbPath);
    }
  };
  if (!gate.held) {
    gate.held = true;
    return Promise.resolve(release);
  }
  if (gate.waiters.length >= MAX_LOCAL_WAITERS) return Promise.reject(unavailable());
  return new Promise((resolve, reject) => {
    const waiter = { resolve, reject, timer: null };
    waiter.timer = setTimeout(() => {
      const index = gate.waiters.indexOf(waiter);
      if (index === -1) return;
      gate.waiters.splice(index, 1);
      reject(unavailable());
    }, ACCOUNT_FENCE_WAIT_MS);
    gate.waiters.push(waiter);
  });
}

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
  // Validate a separate private, crash-durable audit journal before accepting
  // strict requests. Without it, access-denial auditing would block SQLite
  // during the cross-process authorization reservation.
  require("../../repositories/auditRepository").preparePendingAuditJournal();

  return async function persistUnderAccountFence(user, operation, persist) {
    if (!user || typeof user.username !== "string" || !user.username
      || !Number.isSafeInteger(user.sessionVersion) || user.sessionVersion < 0
      || typeof persist !== "function") throw rejected();

    // Acquire the local FIFO before any synchronous SQLite statement. The
    // database busy timeout is zero: if ANOTHER process has the writer lock,
    // retry with an async timer so local pending fsyncs and admin handlers run.
    const releaseLocalWriter = await acquireLocalWriter(dbPath);
    let db;
    let insidePersistence = false;
    try {
      // Use an independent connection: a transaction kept open across
      // asynchronous JSON fsync must never expose its SQLite transaction to
      // unrelated requests sharing the application's singleton connection.
      db = new Database(dbPath, { fileMustExist: true, timeout: 0 });
      db.pragma("busy_timeout = 0");
      db.pragma("synchronous = FULL");
      if (String(db.pragma("journal_mode", { simple: true })).toLowerCase() !== "wal"
        || db.pragma("synchronous", { simple: true }) !== 2) throw unavailable();

      // Acquires SQLite's interprocess writer reservation BEFORE reading the
      // account. Admin updates in other processes must serialize before or
      // after the entire JSON store lock + durable rename/fsync.
      const deadline = performance.now() + ACCOUNT_FENCE_WAIT_MS;
      for (;;) {
        try {
          db.exec("BEGIN IMMEDIATE");
          break;
        } catch (error) {
          if (error?.code !== "SQLITE_BUSY" && error?.code !== "SQLITE_LOCKED") throw error;
          if (performance.now() >= deadline) throw unavailable();
          await sleep(Math.min(SQLITE_RETRY_MS, Math.max(1, deadline - performance.now())));
        }
      }
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
      try {
        if (db) {
          try {
            // No SQLite data changed. Release only after the JSON commit/abort
            // has completed, preserving the exact ordering of admin revocation.
            if (db.inTransaction) db.exec("ROLLBACK");
          } finally {
            db.close();
          }
        }
      } finally {
        releaseLocalWriter();
      }
    }
  };
}

module.exports = { createSyncSqliteAccountWriteFence, assertNoLocalStrictSyncWriter };
