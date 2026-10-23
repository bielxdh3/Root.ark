"use strict";

// Read-only, opt-in observation of recoverable legacy sources INSIDE physical
// backup archives. An archive is a historical branch of the corpus: archived
// uploads, derived temp payloads and trash can outlive all current SQL rows.
// Evidence stays opaque, cannot authorize deletion, restore or cutover.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const unzipper = require("unzipper");
const { DatabaseSync } = require("node:sqlite");
const { inspectZk1LiveLegacyReferencePreflight } =
  require("./zk1LiveLegacyReferencePreflight");

const MAX_ARCHIVES = 32;
const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_ENTRIES = 256;
const MAX_INFLATED_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_MS = 15000;
const NAME = /^rootark-(?:backup|pre-restore)-\d{4}(?:-\d{2}){5}(?:-\d{3}-[a-f0-9]{8})?\.zip$/;
const MODE = ["sqlite", "json"];

function refuse() { throw new Error("ZK_LEGACY_RECOVERABLE_GRAPH_UNVERIFIED"); }
function regular(file, maxBytes = MAX_ARCHIVE_BYTES) {
  const stat = fs.lstatSync(file, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
    || stat.size > BigInt(maxBytes)) refuse();
  return stat;
}
function same(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.nlink === b.nlink
    && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}
function readPinnedArchive(file, expected) {
  let fd;
  try {
    const before = regular(file);
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
    if (!same(before, fs.fstatSync(fd, { bigint: true }))) refuse();
    const buffer = fs.readFileSync(fd);
    if (buffer.length !== Number(before.size)
      || !same(before, fs.fstatSync(fd, { bigint: true }))
      || !same(before, regular(file))) refuse();
    const digest = crypto.createHash("sha256").update(buffer).digest("hex");
    // A missing checksum cannot independently bind a recovery archive.
    if (!/^[a-f0-9]{64}$/.test(expected) || digest !== expected) refuse();
    return buffer;
  } catch (_) { refuse(); }
  finally { if (fd !== undefined) fs.closeSync(fd); }
}
function memberName(name) {
  if (typeof name !== "string" || name.length > 1024
    || name.startsWith("/") || name.includes("\\") || name.includes("\0")
    || name.includes(":") || /[\x00-\x1f\x7f]/.test(name)) refuse();
  const parts = name.split("/");
  if (parts.length < 2 || parts.some((x) => !x || x === "." || x === "..")
    || parts.some((x) => x.endsWith(".") || x.endsWith(" "))) refuse();
  if (!["uploads", "temp", "data"].includes(parts[0])) refuse();
  if (parts[0] === "data" && parts[1] === "backups") refuse();
  return name;
}
function category(name) {
  if (name.startsWith("uploads/")) return "archivedUploads";
  if (name.startsWith("temp/")) return "archivedTempCandidates";
  if (name.startsWith("data/trash/")) return "archivedTrash";
  if (name.startsWith("data/")) return "archiveMetadataAndState";
  refuse();
}
function regularZipMember(entry) {
  const mode = Number(entry.externalFileAttributes) >>> 16;
  const unix = (Number(entry.versionMadeBy) >>> 8) === 3;
  if (entry.type !== "File" || (unix && (mode & 0o170000) === 0o120000)) refuse();
  if (!Number.isSafeInteger(entry.uncompressedSize) || entry.uncompressedSize < 0
    || entry.uncompressedSize > MAX_ENTRY_BYTES
    || !Number.isSafeInteger(entry.compressedSize) || entry.compressedSize < 0) refuse();
}
async function digestInflated(entry, limit) {
  if (entry.uncompressedSize > limit) refuse();
  const hash = crypto.createHash("sha256");
  const stream = entry.stream();
  const timer = setTimeout(() => stream.destroy(new Error("ZIP deadline")), MAX_MS);
  timer.unref?.();
  let size = 0;
  try {
    for await (const bytes of stream) {
      if (!Buffer.isBuffer(bytes) || bytes.length > limit - size) refuse();
      size += bytes.length;
      hash.update(bytes);
    }
    if (size !== entry.uncompressedSize) refuse();
    return { size, digest: hash.digest("hex") };
  } finally {
    clearTimeout(timer);
    if (!stream.destroyed) stream.destroy();
  }
}
async function inspectArchive(bytes, expected, secret) {
  let zip;
  try { zip = await unzipper.Open.buffer(bytes); } catch (_) { refuse(); }
  if (!Array.isArray(zip?.files) || zip.files.length < 1 || zip.files.length > MAX_ENTRIES + 1) refuse();
  const files = new Map();
  let manifestEntry;
  for (const entry of zip.files) {
    regularZipMember(entry);
    if (entry.path === "backup-manifest.json") {
      if (manifestEntry || entry.uncompressedSize > MAX_MANIFEST_BYTES) refuse();
      manifestEntry = entry;
      continue;
    }
    const name = memberName(entry.path);
    const key = name.toLowerCase();
    if (files.has(key)) refuse();
    files.set(key, { name, entry });
  }
  if (!manifestEntry || files.size > MAX_ENTRIES) refuse();
  const manifestStream = manifestEntry.stream();
  const chunks = [];
  let length = 0;
  const timer = setTimeout(() => manifestStream.destroy(new Error("Manifest deadline")), MAX_MS);
  timer.unref?.();
  try {
    for await (const chunk of manifestStream) {
      if (!Buffer.isBuffer(chunk) || length + chunk.length > MAX_MANIFEST_BYTES) refuse();
      chunks.push(chunk); length += chunk.length;
    }
  } catch (_) { refuse(); }
  finally { clearTimeout(timer); if (!manifestStream.destroyed) manifestStream.destroy(); }
  if (length !== manifestEntry.uncompressedSize) refuse();
  let manifest;
  try { manifest = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch (_) { refuse(); }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || manifest.backup_id !== expected.id
    || manifest.type !== expected.type || manifest.created_at !== expected.created_at
    || !MODE.includes(manifest.persistence_mode)
    || !Array.isArray(manifest.included_files) || manifest.included_files.length !== files.size
    || !Number.isSafeInteger(manifest.total_size) || manifest.total_size < 0
    || typeof manifest.cloud_complete !== "boolean"
    || manifest.status !== "success"
    || (manifest.persistence_mode === "sqlite" && !files.has("data/rootark.sqlite"))) refuse();
  const declared = new Set();
  let total = 0;
  for (const raw of manifest.included_files) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)
      || Object.keys(raw).length !== 2
      || typeof raw.path !== "string" || !Number.isSafeInteger(raw.size) || raw.size < 0) refuse();
    const name = memberName(raw.path);
    const key = name.toLowerCase(), saved = files.get(key);
    if (declared.has(key) || !saved || saved.name !== name
      || saved.entry.uncompressedSize !== raw.size) refuse();
    declared.add(key);
    total += raw.size;
    if (total > MAX_INFLATED_BYTES) refuse();
  }
  if (total !== manifest.total_size) refuse();
  const counts = { archivedUploads: 0, archivedTempCandidates: 0,
    archivedTrash: 0, archiveMetadataAndState: 0 };
  const mac = crypto.createHmac("sha256", secret)
    .update("rootark-zk1-recoverable-archive-graph/v1\0")
    .update(expected.id + "\0");
  for (const { name, entry } of files.values()) {
    const checked = await digestInflated(entry, MAX_ENTRY_BYTES);
    counts[category(name)]++;
    mac.update(JSON.stringify([name, checked.size, checked.digest]) + "\n");
  }
  // A backup may legitimately contain content no longer present in live FTS,
  // which remains a recovery candidate, not an authority for cutover.
  return { ...counts, members: files.size, cloudCompleteClaim: manifest.cloud_complete,
    ephemeralFingerprint: mac.digest("base64url"), globallyComplete: false };
}

async function inspectZk1LiveLegacyRecoverableArchiveGraph({
  optIn, databasePath, persistence, backupDataDir, localUploadsDir, localTempDir,
} = {}) {
  if (optIn !== true || typeof databasePath !== "string" || !path.isAbsolute(databasePath)
    || typeof backupDataDir !== "string" || !path.isAbsolute(backupDataDir)
    || path.dirname(path.resolve(databasePath)) !== path.resolve(backupDataDir)
    || persistence?.dbEnabled !== true || persistence?.jsonReadFallback !== false
    || persistence?.jsonWriteMirror !== false) refuse();
  let db;
  try {
    // The existing read-only inventory refuses unknown SQL tables, backup
    // paths, archive hardlinks and corrupt local retention state first.
    const preflight = inspectZk1LiveLegacyReferencePreflight({
      optIn: true, databasePath, persistence, backupDataDir,
      ...(localUploadsDir === undefined ? {} : { localUploadsDir }),
      sqlCoverageOptIn: true,
    });
    const dbBefore = regular(databasePath, 1024 * 1024 * 1024);
    db = new DatabaseSync(databasePath, { readOnly: true });
    db.exec("PRAGMA query_only=ON");
    db.exec("BEGIN");
    const rows = db.prepare("SELECT id, filename, type, created_at, status, checksum FROM backup_history ORDER BY id LIMIT ?")
      .all(MAX_ARCHIVES + 1);
    if (rows.length > MAX_ARCHIVES) refuse();
    const secret = crypto.randomBytes(32);
    const localDerived = localTempDir === undefined
      ? null : require("./zk1LiveLegacyDerivedLocalEvidence")
        .inspectZk1LiveLegacyDerivedLocalEvidence({ tempDir: localTempDir, runSecret: secret });
    const reports = [];
    let unresolvedBackupRows = 0;
    for (const row of rows) {
      if (typeof row.id !== "string" || !row.id || !NAME.test(row.filename)
        || typeof row.type !== "string" || !row.type
        || typeof row.created_at !== "string" || !row.created_at
        || typeof row.status !== "string") refuse();
      const archiveFile = path.join(backupDataDir, "backups", row.filename);
      if (!fs.existsSync(archiveFile)) {
        // Removed backup/tombstoned recovery paths are unknown, not recovered.
        unresolvedBackupRows++;
        continue;
      }
      if (row.status !== "success") refuse();
      const buffer = readPinnedArchive(archiveFile, row.checksum);
      reports.push(await inspectArchive(buffer, row, secret));
      // Prevent one physical file being swapped for another during ZIP work.
      if (crypto.createHash("sha256").update(readPinnedArchive(archiveFile, row.checksum))
        .digest("hex") !== row.checksum) refuse();
    }
    db.exec("COMMIT");
    if (!same(dbBefore, regular(databasePath, 1024 * 1024 * 1024))) refuse();
    const result = {
      observation: "bounded-readonly-legacy-recoverable-archive-members",
      inspectedArchives: reports.length,
      unresolvedBackupRows,
      archivedUploads: reports.reduce((s, x) => s + x.archivedUploads, 0),
      archivedTempCandidates: reports.reduce((s, x) => s + x.archivedTempCandidates, 0),
      derivedOutsideFtsVerified: false,
      archivedTrash: reports.reduce((s, x) => s + x.archivedTrash, 0),
      liveNonFtsDerived: localDerived ? localDerived.potentialDerivedReferences : null,
      liveNonFtsDerivedInspected: Boolean(localDerived),
      archiveMetadataAndState: reports.reduce((s, x) => s + x.archiveMetadataAndState, 0),
      archiveMembers: reports.reduce((s, x) => s + x.members, 0),
      cloudCompleteClaimCount: reports.filter((x) => x.cloudCompleteClaim).length,
      backupRetentionTombstones: preflight.legacy.backupEvidence.retentionTombstones,
      backupRetentionTransactions: preflight.legacy.backupEvidence.retentionTransactions,
      sourceReferencesGloballyJoined: false,
      protectedRecoveryVerified: false,
      wholeCorpusVerified: false,
      canDeleteLegacy: false,
      authorizesCutover: false,
      ephemeralFingerprint: crypto.createHmac("sha256", secret)
        .update(JSON.stringify(reports.map((x) => x.ephemeralFingerprint))).digest("base64url"),
    };
    return Object.freeze(result);
  } catch (_) { refuse(); }
  finally { try { db?.close(); } catch (_) { /* fail closed */ } }
}

module.exports = { inspectZk1LiveLegacyRecoverableArchiveGraph };
