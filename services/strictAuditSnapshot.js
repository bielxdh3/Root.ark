"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { performance } = require("node:perf_hooks");

const ARCHIVE_ENTRY = "data/rootark.sqlite.audit-private/pending.sqlite";
const SNAPSHOT_NAME = "audit-pending.sqlite";
const MAX_AUDIT_RECORDS = 100_000;
const MAX_ARCHIVED_BYTES = 512 * 1024 * 1024;
const MAX_PENDING_RECORDS = 4_096;

function journalPath(dbPath) {
  return path.join(`${path.resolve(dbPath)}.audit-private`, "pending.sqlite");
}

function sha256(filename) {
  const digest = crypto.createHash("sha256");
  const descriptor = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const buffer = Buffer.allocUnsafe(64 * 1024);
    for (;;) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (!count) break;
      digest.update(buffer.subarray(0, count));
    }
    return digest.digest("hex");
  } finally { fs.closeSync(descriptor); }
}

function assertRegular(filename, maxBytes = Number.POSITIVE_INFINITY) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || stat.size <= 0 || stat.size > maxBytes) {
    throw Error("Unsafe or oversized strict audit SQLite file");
  }
  return stat;
}

function strictMarker(database) {
  const entry = database.prepare("SELECT type FROM sqlite_master WHERE name='rootark_strict_sync_audit_mode'").get();
  if (!entry) return false;
  if (entry.type !== "table") throw Error("Invalid strict audit marker type");
  const rows = database.prepare("SELECT id,mode FROM rootark_strict_sync_audit_mode").all();
  if (rows.length !== 1 || rows[0].id !== 1 || rows[0].mode !== "append_only") {
    throw Error("Invalid strict audit marker");
  }
  return true;
}

function inspectPrimary(filename) {
  assertRegular(filename);
  const db = new Database(filename, { readonly: true, fileMustExist: true });
  try {
    if (db.pragma("integrity_check", { simple: true }) !== "ok") throw Error("Primary SQLite backup failed integrity");
    return strictMarker(db);
  } finally { db.close(); }
}

function verifyAuditSchema(db, name) {
  if (db.prepare("SELECT type FROM sqlite_master WHERE name=?").get(name)?.type !== "table") throw Error("Missing strict audit table");
  const columns = db.pragma(`table_info(${name})`);
  if (columns.length !== 2 || columns[0].name !== "id" || columns[0].type.toUpperCase() !== "TEXT"
    || columns[0].notnull !== 1 || columns[0].pk !== 1
    || columns[1].name !== "event" || columns[1].type.toUpperCase() !== "TEXT"
    || columns[1].notnull !== 1 || columns[1].pk !== 0) throw Error("Invalid strict audit table schema");
}

function verifyAuditDatabase(filename, { requireWal = false } = {}) {
  assertRegular(filename, MAX_ARCHIVED_BYTES + 32 * 1024 * 1024);
  const db = new Database(filename, { readonly: true, fileMustExist: true });
  try {
    if (db.pragma("integrity_check", { simple: true }) !== "ok") throw Error("Strict audit SQLite integrity failure");
    if (requireWal && String(db.pragma("journal_mode", { simple: true })).toLowerCase() !== "wal") {
      throw Error("Strict audit sidecar must use WAL");
    }
    for (const name of ["pending_audit", "archived_audit"]) verifyAuditSchema(db, name);
    const pending = db.prepare("SELECT id,event FROM pending_audit").all();
    const archived = db.prepare("SELECT id,event FROM archived_audit").all();
    if (pending.length > MAX_PENDING_RECORDS || archived.length > MAX_AUDIT_RECORDS) throw Error("Strict audit capacity invalid");
    let bytes = 0;
    for (const row of [...pending, ...archived]) {
      if (typeof row.id !== "string" || !row.id || row.id.length > 128 || typeof row.event !== "string") throw Error("Invalid audit row");
      const entry = JSON.parse(row.event);
      if (!entry || entry.id !== row.id || typeof entry.eventType !== "string") throw Error("Strict audit row mismatches its ID");
      if ((bytes += Buffer.byteLength(row.event)) > MAX_ARCHIVED_BYTES) throw Error("Strict audit byte capacity exceeded");
    }
    return { pending: pending.length, archived: archived.length };
  } finally { db.close(); }
}

// Hold the main SQLite writer reservation while BOTH online snapshots are made.
// Pending audit entries can still append to the independent sidecar; its copy
// is taken LAST. A pending->main transfer cannot cross the two snapshots.
async function createCoordinatedSnapshots(main, mainPath, stageDir) {
  const authoritativePath = path.resolve(mainPath);
  const lock = new Database(authoritativePath, { timeout: 0, fileMustExist: true });
  const mainSnapshot = path.join(stageDir, "rootark.sqlite");
  const auditSnapshot = path.join(stageDir, SNAPSHOT_NAME);
  let sidecar;
  let inTransaction = false;
  try {
    lock.pragma("busy_timeout = 0");
    const deadline = performance.now() + 15_000;
    for (;;) {
      try { lock.exec("BEGIN IMMEDIATE"); inTransaction = true; break; }
      catch (error) {
        if (!["SQLITE_BUSY", "SQLITE_LOCKED"].includes(error?.code) || performance.now() >= deadline) {
          throw Error("Cannot obtain coordinated strict audit backup fence", { cause: error });
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
    const strict = strictMarker(lock);
    const sourcePath = journalPath(authoritativePath);
    const sourceExists = fs.existsSync(sourcePath);
    if (strict && !sourceExists) throw Error("Strict audit journal missing: refusing incomplete backup");
    if (sourceExists) {
      assertRegular(sourcePath, MAX_ARCHIVED_BYTES + 32 * 1024 * 1024);
      verifyAuditDatabase(sourcePath, { requireWal: strict });
      sidecar = new Database(sourcePath, { readonly: true, fileMustExist: true });
    }
    await main.backup(mainSnapshot);
    if (sidecar) {
      await sidecar.backup(auditSnapshot);
      verifyAuditDatabase(auditSnapshot);
    }
    if (inspectPrimary(mainSnapshot) !== strict) throw Error("Strict audit marker changed across backup snapshot");
    return { snapshotPath: mainSnapshot, auditSnapshotPath: sidecar ? auditSnapshot : null,
      auditSha256: sidecar ? sha256(auditSnapshot) : null, strict };
  } finally {
    try { sidecar?.close(); } finally {
      try { if (inTransaction) lock.exec("ROLLBACK"); } finally { lock.close(); }
    }
  }
}

// The whole-restore coordinator has already been durably written. Every
// compliant audit writer checks that gate again INSIDE its SQLite write
// transaction. Acquiring the two writer locks in fixed main->sidecar order
// drains pre-gate transactions. Release all file handles before Windows moves.
async function drainAuditWriters(mainPath) {
  const deadline = performance.now() + 15_000;
  const main = new Database(path.resolve(mainPath), { timeout: 0, fileMustExist: true });
  let sidecar;
  async function begin(db) {
    db.pragma("busy_timeout = 0");
    for (;;) {
      try { db.exec("BEGIN IMMEDIATE"); return; }
      catch (error) {
        if (!["SQLITE_BUSY", "SQLITE_LOCKED"].includes(error?.code) || performance.now() >= deadline) {
          throw Error("Strict audit restore could not drain concurrent writers", { cause: error });
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
  }
  try {
    await begin(main);
    const livePath = journalPath(mainPath);
    if (strictMarker(main) && !fs.existsSync(livePath)) {
      throw Error("Strict audit restore cannot drain a missing journal");
    }
    if (fs.existsSync(livePath)) {
      sidecar = new Database(livePath, { timeout: 0, fileMustExist: true });
      await begin(sidecar);
      verifyAuditDatabase(livePath);
    }
  } finally {
    try { if (sidecar?.inTransaction) sidecar.exec("ROLLBACK"); } finally {
      sidecar?.close();
      try { if (main.inTransaction) main.exec("ROLLBACK"); } finally { main.close(); }
    }
  }
}

module.exports = { ARCHIVE_ENTRY, SNAPSHOT_NAME, journalPath, sha256,
  inspectPrimary, verifyAuditDatabase, createCoordinatedSnapshots, drainAuditWriters, MAX_AUDIT_RECORDS,
  MAX_ARCHIVED_BYTES };
