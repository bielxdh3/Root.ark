"use strict";

// This only classifies references inside an already validated legacy ZIP.
// Archive SQL is an untrusted historic snapshot, not current authority.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const { assertPrivateSqliteDirectory } = require("./zk1PrivateSqlitePath");
const { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree } =
  require("../../services/chunkUploadWindowsAcl");

const MAX_ROWS = 5000;
const MAX_JSON = 256 * 1024;
const KNOWN_TABLES = new Set([
  "users", "folders", "pending_uploads", "public_links", "actions_history",
  "file_permissions", "file_expirations", "file_versions", "encrypted_files",
  "analytics_events", "audit_logs", "backup_history", "trash_items",
  "file_search_index", "schema_migrations", "sync_resume_factor_spend_grant", "sqlite_sequence",
  "sqlite_stat1", "sqlite_stat4", ...["data", "idx", "content", "docsize", "config"]
    .map((name) => "file_search_index_" + name),
]);
const KNOWN_REFERENCE_COLUMNS = Object.freeze({
  file_versions: "id folder_id file_name versions_json updated_at",
  file_search_index: "folder_id file_name",
  encrypted_files: "id folder_id file_name encryption_level metadata_json created_at updated_at",
  public_links: "token folder_id file_name created_by created_at expires_at max_views views password_hash metadata_json revoked_at permissions_json",
  file_permissions: "id folder_id file_name allowed_users_json created_at updated_at",
  file_expirations: "id folder_id file_name expires_at created_by created_at",
  trash_items: "id item_type original_folder_id original_folder_name original_file_name stored_file_name original_path trash_path deleted_by deleted_at size_bytes metadata_json restore_metadata_json status restored_by restored_at permanently_deleted_by permanently_deleted_at",
  sync_resume_factor_spend_grant: "username replay_digest code_mac device_id pause_fence committed_at",
});
function deny() { throw new Error("ZK_LEGACY_ARCHIVE_SQLITE_JOIN_UNVERIFIED"); }
function assertPosixTrustedTemporaryParent(folder) {
  // mkdtemp(0700) protects the new inode but not its directory entry: a
  // foreign UID with write access to a non-sticky ancestor can replace it
  // before SQLite's pathname open or our cleanup. Check BEFORE mkdir.
  let cursor = path.resolve(folder);
  const owner = BigInt(process.getuid());
  while (true) {
    const stat = fs.lstatSync(cursor, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()
      || fs.realpathSync.native(cursor) !== cursor
      || (stat.uid !== owner && stat.uid !== 0n)) deny();
    const writable = (stat.mode & 0o022n) !== 0n;
    const rootSticky = stat.uid === 0n && (stat.mode & 0o1000n) !== 0n;
    if (writable && !rootSticky) deny();
    const parent = path.dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
}
function safePart(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 255
    && value !== "." && value !== ".." && !/[\\/\x00-\x1f<>:"|?*]/.test(value)
    && !value.endsWith(".") && !value.endsWith(" ");
}
function safeFolder(value) {
  return value === "root" || (safePart(value) && /^[a-zA-Z0-9._-]{1,128}$/.test(value));
}
function rows(db, table, columns) {
  const metadata = db.prepare("SELECT type FROM sqlite_master WHERE name=?").get(table);
  if (!metadata || metadata.type !== "table") return null;
  const existing = db.prepare(`PRAGMA table_info("${table}")`).all();
  if (columns.some((name) => !existing.some((col) => col.name === name))) return null;
  const found = db.prepare(`SELECT ${columns.join(",")} FROM ${table} LIMIT ?`).all(MAX_ROWS + 1);
  if (found.length > MAX_ROWS) deny();
  return found;
}
function parseHistory(value) {
  if (typeof value !== "string" || Buffer.byteLength(value) > MAX_JSON) deny();
  let item;
  try { item = JSON.parse(value); } catch (_) { deny(); }
  if (!item || typeof item !== "object" || Array.isArray(item)
    || !Array.isArray(item.versions) || item.versions.length > MAX_ROWS) deny();
  return item.versions;
}
function key(folder, name) {
  if (!safeFolder(folder) || !safePart(name)) return null;
  return "uploads/" + (folder === "root" ? "" : folder + "/") + name;
}
function inspectZk1LiveLegacyArchivedSqliteJoin({ sqliteBytes, members }) {
  if (!Buffer.isBuffer(sqliteBytes) || sqliteBytes.length < 100
    || sqliteBytes.length > 32 * 1024 * 1024 || !members || !(members instanceof Map)) deny();
  let tmp, db;
  try {
    // Node 22/24 DatabaseSync has no deserialize(bytes) API. On Windows,
    // mkdtemp inherits TEMP's DACL, which can give unrelated local users READ
    // (archived user/link/trash metadata) or MODIFY (replace the SQLite image)
    // before the read-only DB is opened. Native CreateDirectoryW installs the
    // protected owner-only DACL AT CREATION and first rejects destructive ACEs
    // on any ancestor. Never adopt/delete a candidate until verified.
    if (process.platform === "win32") {
      const candidate = path.join(os.tmpdir(),
        "zk1-archive-sql-" + crypto.randomBytes(12).toString("hex"));
      ensureWindowsChunkUploadRoot(candidate);
      verifyWindowsChunkUploadTree(candidate);
      tmp = candidate;
    } else {
      assertPosixTrustedTemporaryParent(os.tmpdir());
      tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zk1-archive-sql-"));
      // A private leaf under an attacker-owned/writable parent can still be
      // swapped. Root-owned sticky /tmp and owner-only ancestors are allowed.
      assertPrivateSqliteDirectory(path.join(tmp, "archive.sqlite"));
    }
    const filename = path.join(tmp, "archive.sqlite");
    fs.writeFileSync(filename, sqliteBytes, { flag: "wx", mode: 0o600 });
    if (process.platform === "win32") verifyWindowsChunkUploadTree(tmp);
    else assertPrivateSqliteDirectory(filename);
    db = new DatabaseSync(filename, { readOnly: true });
    db.exec("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF");
    if (db.prepare("PRAGMA quick_check").get()?.quick_check !== "ok") deny();
    db.exec("BEGIN");
    const files = new Set([...members.keys()]);
    const attributed = new Set();
    const result = {
      versionReferences: 0, joinedVersionReferences: 0,
      derivedReferences: 0, joinedDerivedReferences: 0,
      trashReferences: 0, joinedTrashReferences: 0,
      retentionReferences: 0, joinedRetentionReferences: 0,
      linkedMetadataReferences: 0, joinedMetadataReferences: 0,
      orphanArchiveUploads: 0, orphanArchiveTrash: 0,
      unclassifiedArchiveTemp: 0, unknownReferences: 0,
    };
    const schema = db.prepare("SELECT type,name FROM sqlite_master WHERE type IN ('table','view','trigger') LIMIT 129").all();
    if (schema.length > 128) deny();
    for (const item of schema) if (item.type !== "table" || !KNOWN_TABLES.has(item.name))
      result.unknownReferences++;
    for (const [table, rawFields] of Object.entries(KNOWN_REFERENCE_COLUMNS)) {
      const columns = db.prepare(`PRAGMA table_info("${table}")`).all();
      if (columns.some((item) => !rawFields.split(" ").includes(item.name)))
        result.unknownReferences++;
    }
    const versionKeys = new Set();
    const versionRows = rows(db, "file_versions", ["folder_id", "file_name", "versions_json"]);
    if (versionRows === null) {
      // Missing historical schema cannot establish any trustworthy joins.
      result.unknownReferences++;
    } else {
      for (const row of versionRows) {
        const logical = key(row.folder_id, row.file_name);
        if (!logical) { result.unknownReferences++; continue; }
        const seen = new Set();
        const history = parseHistory(row.versions_json);
        let complete = history.length > 0;
        if (history.length === 0) { result.unknownReferences++; continue; }
        for (const version of history) {
          result.versionReferences++;
          if (!Number.isSafeInteger(version?.version) || version.version < 1
            || seen.has(version.version)) {
            complete = false; result.unknownReferences++; continue;
          }
          seen.add(version.version);
          const physical = key(row.folder_id, version.storedAs);
          if (!physical || !files.has(physical.toLowerCase())
            || !Number.isSafeInteger(version.size) || version.size < 0
            || version.size !== members.get(physical.toLowerCase())?.size) {
            complete = false;
            result.unknownReferences++;
            continue;
          }
          attributed.add(physical.toLowerCase());
          result.joinedVersionReferences++;
        }
        if (complete) versionKeys.add(logical);
      }
    }
    const references = [
      ["file_search_index", "derivedReferences", "joinedDerivedReferences", ["folder_id", "file_name"]],
      ["file_expirations", "retentionReferences", "joinedRetentionReferences", ["folder_id", "file_name"]],
      ["encrypted_files", "linkedMetadataReferences", "joinedMetadataReferences", ["folder_id", "file_name"]],
      ["public_links", "linkedMetadataReferences", "joinedMetadataReferences", ["folder_id", "file_name"]],
      ["file_permissions", "linkedMetadataReferences", "joinedMetadataReferences", ["folder_id", "file_name"]],
    ];
    for (const [table, count, joined, columns] of references) {
      const found = rows(db, table, columns);
      if (found === null) { result.unknownReferences++; continue; }
      for (const row of found) {
        result[count]++;
        const logical = key(row.folder_id, row.file_name);
        if (logical && versionKeys.has(logical)) result[joined]++;
        else result.unknownReferences++;
      }
    }
    const trashRows = rows(db, "trash_items", ["status", "item_type", "trash_path", "size_bytes"]);
    if (trashRows === null) result.unknownReferences++;
    else for (const row of trashRows) {
      result.trashReferences++;
      // Only a still-trashed physical file has a provable path identity;
      // folder bundles or restored/deleted generations are UNKNOWN.
      if (row.status !== "trashed" || row.item_type !== "file"
        || typeof row.trash_path !== "string"
        || !/^files\/[a-z0-9-]{1,128}\/[a-zA-Z0-9._ -]{1,255}$/i.test(row.trash_path)) {
        result.unknownReferences++; continue;
      }
      const physical = "data/trash/" + row.trash_path;
      if (!Number.isSafeInteger(row.size_bytes) || row.size_bytes < 0
        || !files.has(physical.toLowerCase())
        || members.get(physical.toLowerCase())?.size !== row.size_bytes) {
        result.unknownReferences++; continue;
      }
      attributed.add(physical.toLowerCase());
      result.joinedTrashReferences++;
    }
    // An in-flight upload, older backup record, or historical event may name
    // sources that live outside the current ZIP. None has a safe generic join.
    for (const table of ["pending_uploads", "backup_history", "actions_history",
      "analytics_events", "audit_logs"]) {
      const values = rows(db, table, ["id"]);
      // analytics_events/audit_logs may lack a stable id in older schemas:
      // that is itself unprovable, rather than evidence of an empty table.
      if (values === null) { result.unknownReferences++; continue; }
      result.unknownReferences += values.length;
    }
    for (const [name] of members) {
      if (name.startsWith("uploads/") && !attributed.has(name)) {
        result.orphanArchiveUploads++; result.unknownReferences++;
      } else if (name.startsWith("data/trash/") && !attributed.has(name)) {
        result.orphanArchiveTrash++; result.unknownReferences++;
      } else if (name.startsWith("temp/")) {
        result.unclassifiedArchiveTemp++; result.unknownReferences++;
      }
    }
    db.exec("COMMIT");
    return Object.freeze({ observation: "bounded-historical-sqlite-member-joins",
      ...result, status: result.unknownReferences > 0 ? "UNKNOWN" : "BOUNDED_JOINS_ONLY",
      independentlyAuthenticated: false, globallyComplete: false,
      canDeleteLegacy: false, authorizesCutover: false });
  } catch (_) { deny(); }
  finally {
    try { db?.close(); } catch (_) { /* only temporary read-only DB */ }
    if (tmp) { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) { /* best effort */ } }
  }
}
module.exports = { inspectZk1LiveLegacyArchivedSqliteJoin };
