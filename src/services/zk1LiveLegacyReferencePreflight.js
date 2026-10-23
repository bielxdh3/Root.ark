"use strict";

// Deliberate, opt-in READ-ONLY metadata inspection of the LIVE legacy SQLite
// store. This is NOT a complete legacy inventory, a ZK authority or an API route.
// No source filename, path, token or raw metadata crosses the returned boundary.
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const SCHEMA = "rootark-zk1-live-legacy-reference-preflight/v1";
const MAX_ROWS_PER_TABLE = 5000;
// These names/columns map to db/migrations.js, NOT to an asserted universe of
// live filesystem, cloud, WebDAV, JSON mirrors or encrypted provider objects.
const SOURCES = Object.freeze([
  { kind: "versions", table: "file_versions", columns: ["id", "folder_id", "file_name", "versions_json"], order: "id", json: ["versions_json"] },
  { kind: "backups", table: "backup_history", columns: ["id", "filename", "type", "status", "metadata_json"], order: "id", json: ["metadata_json"] },
  { kind: "trash", table: "trash_items", columns: ["id", "item_type", "status", "original_file_name", "trash_path", "metadata_json", "restore_metadata_json"], order: "id", json: ["metadata_json", "restore_metadata_json"] },
  { kind: "links", table: "public_links", columns: ["token", "folder_id", "file_name", "revoked_at", "metadata_json"], order: "token", json: ["metadata_json"] },
  { kind: "derived", table: "file_search_index", columns: ["folder_id", "file_name"], order: "folder_id, file_name", json: [] },
  { kind: "retention", table: "file_expirations", columns: ["id", "folder_id", "file_name", "expires_at"], order: "id", json: [] },
]);
const LIMITATIONS = Object.freeze([
  "live-legacy-sqlite-metadata-only",
  "missing-physical-file-and-remote-provider-inventory",
  "missing-json-mirror-and-external-backup-coverage",
  "missing-backup-archive-retention-tombstones-and-transactions",
  "missing-derived-artifacts-outside-search-index",
  "missing-owner-and-independent-inventory-authority",
  "missing-full-legacy-to-protected-reference-joins",
  "missing-protected-zk-catalog-and-version-proof",
  "missing-concurrent-writer-quiescence-and-cross-provider-fence",
]);

function refuse() {
  const error = new Error("ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE");
  error.code = error.message;
  throw error;
}
function fileIdentity(file) {
  try {
    const s = fs.lstatSync(file);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1) refuse();
    return s;
  } catch (_) { refuse(); }
}
function sameIdentity(a, b) { return a.dev === b.dev && a.ino === b.ino; }
function columnNames(db, table) {
  const known = db.prepare("SELECT type FROM sqlite_master WHERE name = ?").all(table);
  if (known.length !== 1 || known[0].type !== "table") refuse();
  const columns = db.prepare(`PRAGMA table_info("${table}")`).all();
  if (!columns.length) refuse();
  return new Set(columns.map((column) => column.name));
}
function boundedJson(value) {
  if (typeof value !== "string" || value.length > 256 * 1024) refuse();
  let parsed;
  try { parsed = JSON.parse(value); } catch (_) { refuse(); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) refuse();
}
function inspectTable(db, source, secret) {
  const columns = columnNames(db, source.table);
  if (source.columns.some((column) => !columns.has(column))) refuse();
  // Bound the scan. A truncated result MUST be rejected, not presented as an
  // authoritative inventory. This is a consistent SQLite read transaction.
  const rows = db.prepare(`SELECT ${source.columns.join(", ")}
    FROM ${source.table} ORDER BY ${source.order} LIMIT ?`).iterate(MAX_ROWS_PER_TABLE + 1);
  const mac = crypto.createHmac("sha256", secret).update(source.kind + "\0");
  let count = 0;
  for (const row of rows) {
    if (++count > MAX_ROWS_PER_TABLE) refuse();
    for (const column of source.columns) {
      const value = row[column];
      if (typeof value !== "string" && typeof value !== "number" && value !== null) refuse();
      if (typeof value === "string" && value.length > 256 * 1024) refuse();
    }
    for (const name of source.json) boundedJson(row[name]);
    mac.update(JSON.stringify(source.columns.map((name) => row[name])) + "\n");
  }
  return Object.freeze({
    kind: source.kind,
    observedRows: count,
    observation: "partial-sqlite-only",
    // Per-call random-key HMAC is intentionally unlinkable across calls.
    // Neither secret, paths nor the original SQL row identifiers are returned.
    ephemeralFingerprint: mac.digest("base64url"),
  });
}

function inspectZk1LiveLegacyReferencePreflight({
  optIn, databasePath, persistence = {},
} = {}) {
  if (optIn !== true || typeof databasePath !== "string" || !path.isAbsolute(databasePath)
    || persistence.dbEnabled !== true || persistence.jsonReadFallback !== false
    || persistence.jsonWriteMirror !== false) refuse();
  let db;
  try {
    const before = fileIdentity(databasePath);
    // Opening the file read-only is critical: unlike the application's getDb,
    // this never creates a missing SQLite file, changes WAL or runs migrations.
    // Lazy-load SQLite only after explicit opt-in; importing this module has no
    // DB side effects or experimental SQLite initialization.
    const { DatabaseSync } = require("node:sqlite");
    db = new DatabaseSync(databasePath, { readOnly: true });
    db.exec("PRAGMA query_only=ON");
    db.exec("BEGIN");
    const ephemeralKey = crypto.randomBytes(32);
    const observations = SOURCES.map((source) => inspectTable(db, source, ephemeralKey));
    db.exec("COMMIT");
    if (!sameIdentity(before, fileIdentity(databasePath))) refuse();
    return Object.freeze({
      schema: SCHEMA,
      optIn: true,
      readOnly: true,
      legacy: Object.freeze({
        domain: "legacy-server-visible-metadata",
        coverage: "partial",
        observations: Object.freeze(observations),
      }),
      protected: Object.freeze({
        domain: "zk-ciphertext-only",
        coverage: "uninspected",
        legacySqlRowsAreNotProtectedProof: true,
      }),
      snapshotOwnerSigned: false,
      authoritativeCorpusInventory: false,
      wholeCorpusVerified: false,
      canDeleteLegacy: false,
      authorizesCutover: false,
      blockers: [...LIMITATIONS],
    });
  } catch (_) { refuse(); }
  finally { try { db?.close(); } catch (_) { /* Already refusing / no resources to expose. */ } }
}

module.exports = { inspectZk1LiveLegacyReferencePreflight };
