"use strict";

// Strict, read-only physical evidence for an *explicitly selected* legacy data
// directory. No cloud/provider enumeration, recovery, mutation or completeness
// attestation. This module never exports source paths or raw archive metadata.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const ARCHIVE = /^rootark-(?:backup|pre-restore)-\d{4}(?:-\d{2}){5}(?:-\d{3}-[a-f0-9]{8})?\.zip$/;
const TX = /^tx-([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/i;
const PHASES = new Set(["prepared", "archive_moved", "history_removed", "cleanup_committed"]);
const MAX_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const MAX_JSON = 256 * 1024;
const MAX_ENTRIES = 5000;

function deny() {
  const err = new Error("ZK_LIVE_LEGACY_BACKUP_EVIDENCE_UNAVAILABLE");
  err.code = err.message;
  throw err;
}
function keys(obj, required) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(obj))) deny();
  for (const field of required) if (!Object.hasOwn(obj, field)) deny();
}
function directory(dir) {
  let stat;
  try { stat = fs.lstatSync(dir, { bigint: true }); } catch (_) { deny(); }
  if (!stat.isDirectory() || stat.isSymbolicLink()) deny();
  // A directory junction/reparse alias must not redirect a selected data root.
  let actual;
  try { actual = fs.realpathSync.native(dir); } catch (_) { deny(); }
  const canonical = path.resolve(dir);
  if ((process.platform === "win32" ? actual.toLowerCase() : actual)
    !== (process.platform === "win32" ? canonical.toLowerCase() : canonical)) deny();
  return stat;
}
function stable(stat, later) {
  return stat.dev === later.dev && stat.ino === later.ino
    && stat.size === later.size && stat.mtimeNs === later.mtimeNs
    && stat.ctimeNs === later.ctimeNs && stat.nlink === later.nlink;
}
function regular(name, identities) {
  let stat;
  try { stat = fs.lstatSync(name, { bigint: true }); } catch (_) { deny(); }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) deny();
  const identity = stat.dev + ":" + stat.ino;
  if (identities.has(identity)) deny(); // No physical hardlink aliases.
  identities.add(identity);
  return stat;
}
function allEntries(dir) {
  let entries;
  try { entries = fs.readdirSync(dir); } catch (_) { deny(); }
  if (entries.length > MAX_ENTRIES || new Set(entries.map((n) => n.toLowerCase())).size !== entries.length) deny();
  return entries;
}
function existsOrAbsent(file) {
  try { fs.lstatSync(file); return true; }
  catch (error) { if (error?.code === "ENOENT") return false; deny(); }
}
function readFile(file, identities, snapshots, budget, max = MAX_BYTES) {
  const before = regular(file, identities);
  if (before.size > BigInt(max)) deny();
  budget.bytes += before.size;
  if (budget.bytes > BigInt(MAX_TOTAL_BYTES)) deny();
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!stable(before, opened)) deny();
    // Concurrent archive/JSON growth must never expand our read allocation.
    const content = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < content.length) {
      const count = fs.readSync(fd, content, offset,
        Math.min(64 * 1024, content.length - offset), offset);
      if (count <= 0 || count > content.length - offset) deny();
      offset += count;
    }
    if (BigInt(content.length) !== opened.size
      || !stable(before, fs.fstatSync(fd, { bigint: true }))
      || !stable(before, fs.lstatSync(file, { bigint: true }))) deny();
    snapshots.push([file, before]);
    return content;
  } catch (_) { deny(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function parseJson(bytes) {
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (_) { deny(); }
  return value;
}
function digest(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function hex64(value) { return typeof value === "string" && /^[a-f0-9]{64}$/i.test(value); }
function archiveName(name) { return typeof name === "string" && ARCHIVE.test(name); }

function inspectZk1LiveLegacyBackupEvidence({ dataDir, databasePath, db, runSecret,
  zipContentsOptIn = false }) {
  if (typeof dataDir !== "string" || !path.isAbsolute(dataDir)
    || typeof databasePath !== "string" || path.dirname(path.resolve(databasePath)) !== path.resolve(dataDir)
    || !db || !Buffer.isBuffer(runSecret) || runSecret.length !== 32
    || typeof zipContentsOptIn !== "boolean") deny();
  const baseStat = directory(dataDir);
  const backupDir = path.join(dataDir, "backups");
  const backupStat = directory(backupDir);
  const identities = new Set();
  const snapshots = [];
  const budget = { bytes: 0n };
  const rows = db.prepare("SELECT id,filename,status,checksum FROM backup_history ORDER BY id LIMIT ?")
    .all(MAX_ENTRIES + 1);
  if (rows.length > MAX_ENTRIES) deny();
  const history = new Map();
  const byName = new Map();
  for (const row of rows) {
    if (typeof row.id !== "string" || !row.id || !archiveName(row.filename)
      || typeof row.status !== "string" || row.status.length > 64
      || (row.checksum !== null && !hex64(row.checksum))
      || history.has(row.id) || byName.has(row.filename)) deny();
    history.set(row.id, row);
    byName.set(row.filename, row);
  }

  // Historical JSON can remain after disabling JSON fallback. If present, it
  // must match the SQL history; silently ignoring it hides backup aliases.
  let mirrorRows = null;
  const mirrorFile = path.join(dataDir, "backup-history.json");
  if (existsOrAbsent(mirrorFile)) {
    const mirror = parseJson(readFile(mirrorFile, identities, snapshots, budget, MAX_JSON));
    if (!Array.isArray(mirror) || mirror.length !== history.size || mirror.length > MAX_ENTRIES) deny();
    const seen = new Set();
    for (const entry of mirror) {
      keys(entry, ["id", "filename"]);
      const original = history.get(entry.id);
      if (!original || original.filename !== entry.filename
        || (entry.status !== undefined && entry.status !== original.status)
        || seen.has(entry.id)) deny();
      seen.add(entry.id);
    }
    mirrorRows = mirror.length;
  }

  const names = allEntries(backupDir);
  const archives = new Map(), tombstones = new Map(), metadata = new Map();
  let txDirectory = false;
  for (const name of names) {
    if (archiveName(name)) archives.set(name, name);
    else if (name.endsWith(".retention-tombstone.json")
      && archiveName(name.slice(0, -".retention-tombstone.json".length))) {
      metadata.set(name.slice(0, -".retention-tombstone.json".length), name);
    } else if (name.endsWith(".retention-tombstone")
      && archiveName(name.slice(0, -".retention-tombstone".length))) {
      tombstones.set(name.slice(0, -".retention-tombstone".length), name);
    } else if (name === ".retention-transactions" && !txDirectory) txDirectory = true;
    else deny(); // Unknown transient, archive alias or future retention kind.
  }
  const files = new Map();
  for (const [name] of archives) files.set(name,
    readFile(path.join(backupDir, name), identities, snapshots, budget));
  for (const [name, file] of tombstones) files.set(name + ":tombstone",
    readFile(path.join(backupDir, file), identities, snapshots, budget));

  for (const [name, file] of metadata) {
    if (!tombstones.has(name)) deny();
    const value = parseJson(readFile(path.join(backupDir, file),
      identities, snapshots, budget, MAX_JSON));
    keys(value, ["backupId", "filename", "checksum"]);
    const record = history.get(value.backupId);
    if (!record || value.filename !== name || record.filename !== name
      || (value.checksum !== null && !hex64(value.checksum))) deny();
    if (value.checksum !== record.checksum) deny();
  }
  for (const name of tombstones.keys()) if (!metadata.has(name)) deny();

  const claims = new Set();
  let transactions = 0;
  if (txDirectory) {
    const txRoot = path.join(backupDir, ".retention-transactions");
    const txStat = directory(txRoot);
    for (const name of allEntries(txRoot)) {
      const match = TX.exec(name);
      if (!match) deny();
      const folder = path.join(txRoot, name);
      const folderStat = directory(folder);
      const directoryEntries = allEntries(folder);
      if (directoryEntries.length !== 1 || directoryEntries[0] !== "transaction.json") deny();
      const value = parseJson(readFile(path.join(folder, "transaction.json"),
        identities, snapshots, budget, MAX_JSON));
      keys(value, ["version", "transactionId", "backupId", "filename", "archivePath",
        "tombstonePath", "checksum", "phase"]);
      const row = history.get(value.backupId);
      if (value.version !== 1 || value.transactionId.toLowerCase() !== match[1].toLowerCase()
        || !archiveName(value.filename) || !PHASES.has(value.phase) || !hex64(value.checksum)
        || value.archivePath !== path.join(backupDir, value.filename)
        || value.tombstonePath !== path.join(backupDir, value.filename + ".retention-tombstone")
        || claims.has(value.backupId) || claims.has("file:" + value.filename)
        || (row && row.filename !== value.filename)
        || (row && row.checksum !== null && row.checksum !== value.checksum)
        || (["prepared"].includes(value.phase) && !row)
        || (["history_removed", "cleanup_committed"].includes(value.phase) && row)) deny();
      claims.add(value.backupId);
      claims.add("file:" + value.filename);
      const bytes = filesForTransaction(value, archives, tombstones, files);
      if (bytes === null || (bytes.length > 0 && digest(bytes) !== value.checksum)) deny();
      transactions += 1;
      if (!stable(folderStat, directory(folder))) deny();
    }
    if (!stable(txStat, directory(txRoot))) deny();
  }

  let verifiedArchives = 0;
  for (const [name, bytes] of files) {
    const isTombstone = name.endsWith(":tombstone");
    const archive = isTombstone ? name.slice(0, -":tombstone".length) : name;
    const expected = byName.get(archive);
    if (!expected) deny();
    const actual = digest(bytes);
    if (expected.checksum && actual !== expected.checksum) deny();
    if (isTombstone && expected.checksum === null) deny();
    if (!isTombstone) verifiedArchives++;
  }
  const archiveContents = zipContentsOptIn
    ? require("./zk1LiveLegacyZipReferenceEvidence").inspectZk1LiveLegacyZipReferenceEvidence({
      archives: files, runSecret,
    }) : null;
  for (const row of rows) {
    // No silent 'success' for archive missing on all local paths. The report
    // remains partial even with every local archive present.
    if (row.status === "success" && !archives.has(row.filename)
      && !tombstones.has(row.filename) && !claims.has("file:" + row.filename)) deny();
  }
  for (const [file, pinned] of snapshots) {
    let current;
    try { current = fs.lstatSync(file, { bigint: true }); } catch (_) { deny(); }
    if (!current.isFile() || current.isSymbolicLink() || !stable(pinned, current)) deny();
  }
  if (!stable(baseStat, directory(dataDir)) || !stable(backupStat, directory(backupDir))) deny();

  const count = Object.freeze({ historyRows: rows.length, jsonHistoryRows: mirrorRows,
    archives: verifiedArchives, retentionTombstones: tombstones.size, retentionTransactions: transactions });
  const fingerprint = crypto.createHmac("sha256", runSecret)
    .update("legacy-backup-physical/v1\0")
    .update(JSON.stringify([...history.values()].map((r) => [r.id, r.filename, r.status, r.checksum])))
    .update(JSON.stringify([...files].map(([name, bytes]) => [name, digest(bytes)])))
    .update(JSON.stringify(count)).digest("base64url");
  return Object.freeze({ observation: "partial-local-backup-evidence-only",
    ...count, ephemeralFingerprint: fingerprint,
    ...(archiveContents ? { archiveContents } : {}),
    globallyComplete: false });
}

function filesForTransaction(tx, archives, tombstones, buffers) {
  if (archives.has(tx.filename)) return buffers.get(tx.filename);
  if (tombstones.has(tx.filename)) return buffers.get(tx.filename + ":tombstone");
  // For history_removed/cleanup_committed, both archive names may be absent.
  return ["history_removed", "cleanup_committed"].includes(tx.phase) ? Buffer.alloc(0) : null;
}

module.exports = { inspectZk1LiveLegacyBackupEvidence };
