"use strict";

const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree } =
  require("../services/chunkUploadWindowsAcl");

// Separate from the backup metadata lease: whole-restore recovery can already
// hold that lease when its trusted terminal audit must be committed.
const JSON_AUDIT_COORDINATION_FILE = resolveRuntimePath("data", ".rootark-json-audit-private", "coordination.sqlite");
const COORDINATOR = resolveRuntimePath("data", ".rootark-restore-coordinator.json");
let privateDirectoryVerified = false;

function withJsonAuditLock(callback, { allowCoordinator = false } = {}) {
  const directory = path.dirname(JSON_AUDIT_COORDINATION_FILE);
  if (process.platform === "win32") {
    if (!privateDirectoryVerified) {
      ensureWindowsChunkUploadRoot(directory);
      verifyWindowsChunkUploadTree(directory);
      privateDirectoryVerified = true;
    }
  } else {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const dir = fs.lstatSync(directory);
    if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && dir.uid !== process.getuid())) {
      throw new Error("Unsafe private JSON audit lock directory");
    }
  }
  try {
    const fd = fs.openSync(JSON_AUDIT_COORDINATION_FILE, "wx", 0o600);
    fs.closeSync(fd);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  const stat = fs.lstatSync(JSON_AUDIT_COORDINATION_FILE);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && stat.uid !== process.getuid())))) {
    throw new Error("Unsafe JSON audit coordination file");
  }
  let db;
  try {
    db = new Database(JSON_AUDIT_COORDINATION_FILE, { fileMustExist: true, timeout: 5000 });
    db.pragma("busy_timeout = 5000");
    db.exec("BEGIN IMMEDIATE");
    try {
      if (!allowCoordinator) {
        try {
          fs.lstatSync(COORDINATOR);
          throw Object.assign(new Error("JSON audit writes blocked during whole restore"), {
            code: "SYNC_ATOMIC_ACCOUNT_UNAVAILABLE",
          });
        } catch (error) {
          if (error.code !== "ENOENT") throw error;
        }
      }
      const result = callback();
      if (result && typeof result.then === "function") {
        throw new TypeError("JSON audit lock callback must be synchronous");
      }
      return result;
    } finally {
      db.exec("ROLLBACK");
    }
  } catch (error) {
    if (["SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_BUSY_SNAPSHOT"].includes(error.code)) {
      throw Object.assign(new Error("JSON audit writer lock busy", { cause: error }), {
        code: "JSON_AUDIT_LOCK_BUSY",
      });
    }
    throw error;
  } finally {
    if (db) {
      try { if (db.inTransaction) db.exec("ROLLBACK"); } finally { db.close(); }
    }
  }
}

module.exports = { JSON_AUDIT_COORDINATION_FILE, withJsonAuditLock };
