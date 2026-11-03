"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const Database = require("better-sqlite3");
const { resolveRuntimePath } = require("../src/runtime-paths");
const { renameSyncWithWindowsEpermRetry } = require("../src/fs-atomic-rename");
const { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree } =
  require("../services/chunkUploadWindowsAcl");
const { findArchivedRestoreAuditMatches } = require("./jsonAuditArchiveScanner");
const { JSON_AUDIT_COORDINATION_FILE, withJsonAuditLock } = require("./jsonAuditLock");

// The legacy JSON archive remains immutable during ordinary audit writes.
// New events are committed to a FULL/WAL SQLite delta, and a canonical JSON
// representation is materialized only when taking a backup. This avoids a
// synchronous O(total-archive-size) rewrite on every audited HTTP request.
const LEGACY = resolveRuntimePath("data", "audit-logs-archive.json");
const STORE = path.join(path.dirname(JSON_AUDIT_COORDINATION_FILE), "archive.sqlite");
const ENROLLMENT = resolveRuntimePath("data", ".rootark-json-audit-enrollment.json");
const MAX_ID_BYTES = 512;
const MAX_EVENT_BYTES = 64 * 1024;
let windowsDirectoryVerified = false;

function syncDirectory(directory) {
  if (process.platform === "win32") return;
  const fd = fs.openSync(directory, "r");
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

function readEnrollment() {
  let info;
  try { info = fs.lstatSync(ENROLLMENT); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
  const fd = fs.openSync(ENROLLMENT, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd);
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > 4096
      || opened.size !== info.size || opened.ino !== info.ino || opened.dev !== info.dev
      || (process.platform !== "win32" && ((info.mode & 0o077) !== 0
        || (typeof process.getuid === "function" && info.uid !== process.getuid())))) {
      throw new Error("Unsafe JSON audit archive enrollment marker");
    }
    const value = JSON.parse(fs.readFileSync(fd, "utf8"));
    if (value?.version !== 1 || !/^[a-f0-9-]{36}$/i.test(value.storeId || "")) {
      throw new Error("Invalid JSON audit archive enrollment marker");
    }
    return value.storeId;
  } finally { fs.closeSync(fd); }
}

function publishEnrollment(storeId) {
  const prior = readEnrollment();
  if (prior) {
    if (prior !== storeId) throw new Error("JSON audit archive enrollment identity changed");
    return;
  }
  const temporary = `${ENROLLMENT}.${crypto.randomUUID()}.tmp`;
  let published = false;
  try {
    const fd = fs.openSync(temporary, "wx", 0o600);
    try {
      fs.writeFileSync(fd, `${JSON.stringify({ version: 1, storeId })}\n`);
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    if (fs.existsSync(ENROLLMENT)) throw new Error("JSON audit enrollment raced another writer");
    renameSyncWithWindowsEpermRetry(temporary, ENROLLMENT);
    published = true;
    syncDirectory(path.dirname(ENROLLMENT));
  } finally { if (!published) fs.rmSync(temporary, { force: true }); }
}

function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable(value[key])]));
  }
  return value;
}

function sameEvidence(left, right) {
  return JSON.stringify(stable(left)) === JSON.stringify(stable(right));
}

function assertSafeFile(filename) {
  for (const candidate of [filename, `${filename}-wal`, `${filename}-shm`]) {
    const stat = fs.lstatSync(candidate, { throwIfNoEntry: false });
    if (!stat) continue;
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || (process.platform !== "win32" && ((stat.mode & 0o077) !== 0
        || (typeof process.getuid === "function" && stat.uid !== process.getuid())))) {
      throw new Error("Unsafe private JSON audit archive inode");
    }
  }
}

function privateDirectory() {
  const directory = path.dirname(STORE);
  if (process.platform === "win32") {
    // The admission path already holds the cross-process JSON audit lease.
    // Re-running icacls on every archived audit event would itself become an
    // unbounded synchronous request-path cost.
    if (!windowsDirectoryVerified) {
      ensureWindowsChunkUploadRoot(directory);
      verifyWindowsChunkUploadTree(directory);
      windowsDirectoryVerified = true;
    }
  } else {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const stat = fs.lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || (stat.mode & 0o077) !== 0
      || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error("Unsafe private JSON audit archive directory");
    }
  }
}

function openStore(create = true) {
  const expectedStoreId = readEnrollment();
  if (!fs.existsSync(STORE)) {
    if (expectedStoreId) {
      // The immutable legacy JSON cannot prove which committed delta records
      // were removed. Missing previously enrolled sidecar is a hard failure.
      throw new Error("Enrolled JSON audit archive journal missing");
    }
    if (!create) return null;
  }
  privateDirectory();
  assertSafeFile(STORE);
  if (create && !fs.existsSync(STORE)) {
    // Never publish an empty, half-initialized archive authority. Initialize
    // tables and WAL in a private temporary database, then publish by rename
    // only after closing, syncing its bytes, and verifying the destination is
    // absent. A crash before rename leaves only a removable orphan temp; a
    // crashed acknowledged archive is never mistaken for fresh enrollment.
    const temporary = `${STORE}.${crypto.randomUUID()}.tmp`;
    let initialized = false;
    let db;
    try {
      const fd = fs.openSync(temporary, "wx", 0o600);
      fs.closeSync(fd);
      db = new Database(temporary, { fileMustExist: true });
      db.pragma("journal_mode = WAL");
      db.pragma("synchronous = FULL");
      db.exec("CREATE TABLE legacy_ids (id TEXT PRIMARY KEY NOT NULL);"
        + "CREATE TABLE delta (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL);"
        + "CREATE TABLE metadata (name TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL)");
      db.prepare("INSERT INTO metadata(name,value) VALUES ('store-id',?)").run(crypto.randomUUID());
      db.close();
      db = null;
      // Windows FlushFileBuffers requires a descriptor opened for write.
      const opened = fs.openSync(temporary, "r+");
      try { fs.fsyncSync(opened); } finally { fs.closeSync(opened); }
      if (fs.existsSync(STORE)) throw new Error("JSON audit archive enrollment raced another writer");
      renameSyncWithWindowsEpermRetry(temporary, STORE);
      initialized = true;
      syncDirectory(path.dirname(STORE));
    } finally {
      db?.close();
      if (!initialized) fs.rmSync(temporary, { force: true });
    }
  }
  assertSafeFile(STORE);
  const db = new Database(STORE, { fileMustExist: true, timeout: 5000 });
  try {
    db.pragma("busy_timeout = 5000");
    if (String(db.pragma("journal_mode", { simple: true })).toLowerCase() !== "wal") {
      throw new Error("Private JSON audit archive is not WAL");
    }
    db.pragma("synchronous = FULL");
    if (db.pragma("synchronous", { simple: true }) !== 2) throw new Error("Private JSON archive must be durable");
    for (const [table, columns] of [["legacy_ids", ["id"]], ["delta", ["id", "event"]],
      ["metadata", ["name", "value"]]]) {
      if (db.prepare("SELECT type FROM sqlite_master WHERE name=?").get(table)?.type !== "table"
        || db.pragma(`table_info(${table})`).map(({ name }) => name).join(",") !== columns.join(",")) {
        throw new Error("Invalid private JSON audit archive schema");
      }
    }
    const storedId = db.prepare("SELECT value FROM metadata WHERE name='store-id'").get()?.value;
    if (!/^[a-f0-9-]{36}$/i.test(storedId || "")) throw new Error("JSON archive store ID missing");
    if (expectedStoreId) {
      if (expectedStoreId !== storedId) throw new Error("JSON audit archive authority changed");
    } else {
      // Crash recovery may finish a *fresh* initialized store's enrollment,
      // but must never legitimize an existing data-bearing unmarked database.
      if (db.prepare("SELECT COUNT(*) AS n FROM delta").get().n !== 0) {
        throw new Error("Unenrolled JSON audit archive contains committed evidence");
      }
      publishEnrollment(storedId);
    }
    assertSafeFile(STORE);
    return db;
  } catch (error) {
    db.close();
    throw error;
  }
}

function legacyIdentity() {
  const stat = fs.lstatSync(LEGACY, { throwIfNoEntry: false });
  if (!stat) return "missing";
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size < 1) {
    throw new Error("Unsafe JSON audit archive history");
  }
  return JSON.stringify([stat.dev, stat.ino, stat.size, stat.mtimeMs, stat.ctimeMs]);
}

function withPinnedJson(filename, read) {
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const before = fs.fstatSync(fd);
    const entry = fs.lstatSync(filename);
    if (!before.isFile() || before.size < 1 || before.nlink !== 1
      || !entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1
      || entry.dev !== before.dev || entry.ino !== before.ino || entry.size !== before.size) {
      throw new Error("JSON audit archive inode changed during open");
    }
    const result = read(fd);
    const after = fs.fstatSync(fd);
    const latest = fs.lstatSync(filename);
    if (result.bytesRead !== before.size || after.size !== before.size
      || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs
      || !latest.isFile() || latest.isSymbolicLink() || latest.nlink !== 1
      || latest.dev !== before.dev || latest.ino !== before.ino
      || latest.size !== before.size || latest.mtimeMs !== before.mtimeMs
      || latest.ctimeMs !== before.ctimeMs) {
      throw new Error("JSON audit archive changed during pinned scan");
    }
    return result.value;
  } finally { fs.closeSync(fd); }
}

function withPinnedLegacy(read) {
  return withPinnedJson(LEGACY, read);
}

// A single one-time migration indexes IDs from the immutable legacy archive.
// A restore changes its inode/fingerprint, so rebuild the index and reconcile
// same-ID records already present in the durable delta before any new writes.
function ensureLegacyIndex(db) {
  const identity = legacyIdentity();
  const old = db.prepare("SELECT value FROM metadata WHERE name='legacy-identity'").get()?.value;
  if (old === identity) return;
  const insert = db.prepare("INSERT INTO legacy_ids(id) VALUES (?)");
  const delta = db.prepare("SELECT event FROM delta WHERE id=?");
  db.transaction(() => {
    db.prepare("DELETE FROM legacy_ids").run();
    if (identity !== "missing") {
      // The scanner invokes `onMatch` immediately. Keeping a Set of every ID
      // in a multi-gigabyte archive would recreate the memory exhaustion.
      const deltaIds = new Set();
      deltaIds.has = (id) => typeof id === "string" && Boolean(delta.get(id));
      withPinnedLegacy((fd) => {
        const result = findArchivedRestoreAuditMatches(fd, deltaIds, {
          onId(id) {
            if (typeof id !== "string" || !id || Buffer.byteLength(id) > MAX_ID_BYTES) {
              throw new Error("Invalid legacy JSON audit archive identity");
            }
            insert.run(id); // UNIQUE fails closed for every duplicate historical ID.
          },
          onMatch(event) {
            const previous = delta.get(event.id);
            if (!previous || !sameEvidence(JSON.parse(previous.event), event)) {
              throw new Error("JSON restore audit identity collision");
            }
            // Retain the durable delta copy even if a restored JSON base now
            // contains the same event. A failed subsequent restore may roll
            // back that base; deleting the shadow would lose acknowledged
            // evidence. Backup export de-duplicates against legacy_ids.
          },
        });
        return { value: null, bytesRead: result.bytesRead };
      });
    }
    if (legacyIdentity() !== identity) throw new Error("JSON audit archive changed during indexing");
    db.prepare("INSERT INTO metadata(name,value) VALUES ('legacy-identity',?) "
      + "ON CONFLICT(name) DO UPDATE SET value=excluded.value").run(identity);
  })();
  syncDirectory(path.dirname(STORE));
}

function assertLog(log) {
  if (!log || typeof log !== "object" || Array.isArray(log)
    || typeof log.id !== "string" || !log.id || Buffer.byteLength(log.id) > MAX_ID_BYTES) {
    throw new Error("Invalid JSON audit archive identity");
  }
  const serialized = JSON.stringify(log);
  if (!serialized || Buffer.byteLength(serialized) > MAX_EVENT_BYTES) {
    throw new Error("JSON audit archive event exceeds safe append budget");
  }
  return serialized;
}

function appendJsonArchiveLogs(logs) {
  if (!Array.isArray(logs)) throw new TypeError("Invalid JSON audit archive entries");
  if (!logs.length) return;
  const additions = new Map();
  for (const log of logs) {
    const serialized = assertLog(log);
    const prior = additions.get(log.id);
    if (prior && !sameEvidence(JSON.parse(prior), log)) throw new Error("JSON restore audit identity collision");
    additions.set(log.id, serialized);
  }
  const db = openStore();
  try {
    ensureLegacyIndex(db);
    const inLegacy = db.prepare("SELECT id FROM legacy_ids WHERE id=?");
    const collide = new Set([...additions.keys()].filter((id) => inLegacy.get(id)));
    if (collide.size) {
      const matches = withPinnedLegacy((fd) => {
        const result = findArchivedRestoreAuditMatches(fd, collide);
        return { value: result.matches, bytesRead: result.bytesRead };
      });
      if (matches.length !== collide.size) throw new Error("JSON archive legacy index mismatch");
      for (const previous of matches) {
        if (!sameEvidence(previous, JSON.parse(additions.get(previous.id)))) {
          throw new Error("JSON restore audit identity collision");
        }
        additions.delete(previous.id);
      }
    }
    const identity = legacyIdentity();
    const findDelta = db.prepare("SELECT event FROM delta WHERE id=?");
    const insert = db.prepare("INSERT INTO delta(id,event) VALUES (?,?)");
    db.transaction(() => {
      for (const [id, event] of additions) {
        const previous = findDelta.get(id);
        if (previous) {
          if (!sameEvidence(JSON.parse(previous.event), JSON.parse(event))) {
            throw new Error("JSON restore audit identity collision");
          }
        } else insert.run(id, event);
      }
      if (identity !== legacyIdentity()) throw new Error("JSON audit archive changed during delta append");
    })();
    syncDirectory(path.dirname(STORE));
  } finally { db.close(); }
}

function findDeltaAuditMatches(id) {
  if (typeof id !== "string") throw new TypeError("Invalid JSON archive audit ID");
  const db = openStore(false);
  if (!db) return [];
  try {
    const row = db.prepare("SELECT event FROM delta WHERE id=?").get(id);
    if (!row) return [];
    const event = JSON.parse(row.event);
    if (event?.id !== id) throw new Error("Private JSON audit archive identity mismatch");
    return [event];
  } finally { db.close(); }
}

function assertJsonRestoreCompatible(extractedRoot) {
  const db = openStore(false);
  if (!db) return;
  try {
    const find = db.prepare("SELECT event FROM delta WHERE id=?");
    const testCollision = (entry) => {
      if (typeof entry?.id !== "string" || !entry.id || Buffer.byteLength(entry.id) > MAX_ID_BYTES) {
        throw new Error("Invalid restored JSON audit identity");
      }
      const delta = find.get(entry.id);
      if (delta && !sameEvidence(JSON.parse(delta.event), entry)) {
        throw new Error("JSON restore audit identity collision");
      }
    };
    // The selected main JSON is bounded by the existing active-audit limit.
    // Capture its IDs before scanning the potentially unbounded archive, so
    // only incoming archive entries that intersect main or delta are parsed.
    const mainEvents = new Map();
    const candidateMain = path.join(extractedRoot, "data", "audit-logs.json");
    if (fs.existsSync(candidateMain)) {
      withPinnedJson(candidateMain, (fd) => {
        const fileSize = fs.fstatSync(fd).size;
        if (fileSize > 512 * 1024 * 1024) throw new Error("Restored active JSON audit history too large");
        const bytes = fs.readFileSync(fd);
        const entries = JSON.parse(bytes.toString("utf8"));
        if (!entries || !Array.isArray(entries.logs)) throw new Error("Invalid restored active JSON audit history");
        for (const entry of entries.logs) {
          testCollision(entry);
          const previous = mainEvents.get(entry.id);
          if (previous && !sameEvidence(previous, entry)) {
            throw new Error("Restored active JSON audit identity collision");
          }
          mainEvents.set(entry.id, entry);
        }
        return { value: null, bytesRead: bytes.length };
      });
    }
    const candidateArchive = path.join(extractedRoot, "data", "audit-logs-archive.json");
    if (fs.existsSync(candidateArchive)) {
      db.exec("CREATE TEMP TABLE restored_archive_ids (id TEXT PRIMARY KEY NOT NULL)");
      const insert = db.prepare("INSERT INTO restored_archive_ids(id) VALUES (?)");
      const wantedIds = new Set();
      wantedIds.has = (id) => typeof id === "string" && (mainEvents.has(id) || Boolean(find.get(id)));
      withPinnedJson(candidateArchive, (fd) => {
        const result = findArchivedRestoreAuditMatches(fd, wantedIds, {
          onId(id) {
            if (typeof id !== "string" || !id || Buffer.byteLength(id) > MAX_ID_BYTES) {
              throw new Error("Invalid restored JSON archive audit identity");
            }
            insert.run(id); // any duplicate in the incoming archive is invalid
          },
          onMatch(event) {
            testCollision(event);
            const active = mainEvents.get(event.id);
            if (active && !sameEvidence(active, event)) {
              throw new Error("Restored JSON main/archive audit identity collision");
            }
          },
        });
        return { value: null, bytesRead: result.bytesRead };
      });
    }
  } finally { db.close(); }
}

function writeAll(fd, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const count = fs.writeSync(fd, buffer, offset, buffer.length - offset);
    if (count < 1) throw new Error("JSON archive snapshot write failed");
    offset += count;
  }
}

function copyRange(source, target, from, until) {
  const buffer = Buffer.allocUnsafe(64 * 1024);
  while (from < until) {
    const count = fs.readSync(source, buffer, 0, Math.min(buffer.length, until - from), from);
    if (count < 1) throw new Error("JSON archive snapshot source truncated");
    writeAll(target, buffer.subarray(0, count));
    from += count;
  }
}

function captureMainAuditSnapshot(destination) {
  const filename = resolveRuntimePath("data", "audit-logs.json");
  if (!fs.existsSync(filename)) return null;
  const temporary = `${destination}.${crypto.randomUUID()}.tmp`;
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  let published = false;
  try {
    withPinnedJson(filename, (source) => {
      const length = fs.fstatSync(source).size;
      const target = fs.openSync(temporary, "wx", 0o600);
      try {
        copyRange(source, target, 0, length);
        fs.fsyncSync(target);
      } finally { fs.closeSync(target); }
      return { value: null, bytesRead: length };
    });
    renameSyncWithWindowsEpermRetry(temporary, destination);
    published = true;
    syncDirectory(path.dirname(destination));
    return destination;
  } finally { if (!published) fs.rmSync(temporary, { force: true }); }
}

function reconcileActiveAuditSnapshot(filename, archiveSnapshot) {
  if (!filename) return;
  // The active snapshot is captured at t0 under the writer lease, and the
  // delta SQLite snapshot is taken after t0. If an event moves from active
  // to archived in between, it exists in both snapshots. Keep it only in
  // archive after verifying the evidence is byte-semantically equivalent.
  const main = JSON.parse(fs.readFileSync(filename, "utf8"));
  if (!main || typeof main !== "object" || Array.isArray(main) || !Array.isArray(main.logs)) {
    throw new Error("Invalid captured JSON audit history");
  }
  const db = new Database(archiveSnapshot, { readonly: true, fileMustExist: true });
  let revised = [];
  try {
    const find = db.prepare("SELECT event FROM delta WHERE id=?");
    revised = main.logs.filter((entry) => {
      if (!entry || typeof entry.id !== "string") throw new Error("Invalid captured JSON audit identity");
      const delta = find.get(entry.id);
      if (!delta) return true;
      if (!sameEvidence(entry, JSON.parse(delta.event))) {
        throw new Error("Active/archived JSON audit identity collision during backup");
      }
      return false;
    });
  } finally { db.close(); }
  if (revised.length === main.logs.length) return;
  const temporary = `${filename}.${crypto.randomUUID()}.tmp`;
  let published = false;
  try {
    const fd = fs.openSync(temporary, "wx", 0o600);
    try {
      writeAll(fd, Buffer.from(`${JSON.stringify({ ...main, logs: revised }, null, 2)}\n`));
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    renameSyncWithWindowsEpermRetry(temporary, filename);
    published = true;
    syncDirectory(path.dirname(filename));
  } finally { if (!published) fs.rmSync(temporary, { force: true }); }
}

async function writeJsonArchiveBackupSnapshot(destination, mainDestination = null) {
  // Always check durable enrollment, even when the append store is currently
  // absent: a missing previously enrolled sidecar must never yield a
  // plausible but incomplete backup of the legacy archive alone.
  const expectedStoreId = readEnrollment();
  if (expectedStoreId && !fs.existsSync(STORE)) throw new Error("Enrolled JSON audit archive journal missing");
  // Read the current legacy archive version only while holding the same
  // cross-process gate as ordinary archive and restore writes. Capture the
  // bounded active history under the same gate BEFORE the delta snapshot;
  // this prevents a concurrently evicted record disappearing from both ZIP
  // members. A pre-restore backup may hold the coordinator barrier.
  const mainSnapshotPath = withJsonAuditLock(() => {
    const db = openStore(false);
    try { if (db) ensureLegacyIndex(db); } finally { db?.close(); }
    return mainDestination ? captureMainAuditSnapshot(mainDestination) : null;
  }, { allowCoordinator: true });
  if (!fs.existsSync(STORE)) return mainDestination ? { archiveSnapshotPath: null, mainSnapshotPath } : null;
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
  const snapshotDb = `${destination}.${crypto.randomUUID()}.sqlite`;
  const temporary = `${destination}.${crypto.randomUUID()}.tmp`;
  let published = false;
  try {
    const sourceDb = openStore(false);
    try { await sourceDb.backup(snapshotDb); } finally { sourceDb.close(); }
    reconcileActiveAuditSnapshot(mainSnapshotPath, snapshotDb);
    const db = new Database(snapshotDb, { readonly: true, fileMustExist: true });
    try {
      if (db.prepare("SELECT value FROM metadata WHERE name='legacy-identity'").get()?.value !== legacyIdentity()) {
        throw new Error("JSON archive changed during backup snapshot");
      }
      const output = fs.openSync(temporary, "wx", 0o600);
      try {
        const emit = (existing) => {
          let comma = existing;
          for (const { id, event } of db.prepare("SELECT id,event FROM delta "
            + "WHERE id NOT IN (SELECT id FROM legacy_ids) ORDER BY rowid").iterate()) {
            if (JSON.parse(event)?.id !== id) throw new Error("JSON archive snapshot identity mismatch");
            if (comma) writeAll(output, Buffer.from(","));
            writeAll(output, Buffer.from(event));
            comma = true;
          }
        };
        if (legacyIdentity() === "missing") {
          writeAll(output, Buffer.from('{"logs":['));
          emit(false);
          writeAll(output, Buffer.from("]}\n"));
        } else {
          withPinnedLegacy((fd) => {
            const scan = findArchivedRestoreAuditMatches(fd, new Set());
            if (!Number.isSafeInteger(scan.arrayCloseOffset) || scan.arrayCloseOffset < 0) {
              throw new Error("Invalid JSON audit archive array boundary");
            }
            copyRange(fd, output, 0, scan.arrayCloseOffset);
            emit(scan.arrayHasEntries);
            copyRange(fd, output, scan.arrayCloseOffset, scan.bytesRead);
            return { value: null, bytesRead: scan.bytesRead };
          });
        }
        fs.fsyncSync(output);
      } finally { fs.closeSync(output); }
    } finally { db.close(); }
    renameSyncWithWindowsEpermRetry(temporary, destination);
    published = true;
    syncDirectory(path.dirname(destination));
    return mainDestination ? { archiveSnapshotPath: destination, mainSnapshotPath } : destination;
  } finally {
    if (!published) fs.rmSync(temporary, { force: true });
    fs.rmSync(snapshotDb, { force: true });
    fs.rmSync(`${snapshotDb}-wal`, { force: true });
    fs.rmSync(`${snapshotDb}-shm`, { force: true });
  }
}

module.exports = { STORE, LEGACY, appendJsonArchiveLogs, findDeltaAuditMatches,
  assertJsonRestoreCompatible, writeJsonArchiveBackupSnapshot };
