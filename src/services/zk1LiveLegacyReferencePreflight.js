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
// Opt-in schema coverage for additional legacy references. Even a full scan of
// these registered SQL tables does not enumerate local files, cloud custody,
// external backups, derived previews, provider aliases or protected copies.
const EXTRA_SOURCES = Object.freeze([
  { kind: "folders", table: "folders", columns: ["id", "name", "allowed_users_json", "deleted_at", "expires_at"], order: "id", json: ["allowed_users_json"] },
  { kind: "pending-uploads", table: "pending_uploads", columns: ["id", "folder_id", "file_name", "metadata_json"], order: "id", json: ["metadata_json"] },
  { kind: "file-permissions", table: "file_permissions", columns: ["id", "folder_id", "file_name", "allowed_users_json"], order: "id", json: ["allowed_users_json"] },
  { kind: "encrypted-files", table: "encrypted_files", columns: ["id", "folder_id", "file_name", "encryption_level", "metadata_json"], order: "id", json: ["metadata_json"] },
  { kind: "actions-history", table: "actions_history", columns: ["id", "action_type", "folder_id", "file_name", "details_json"], order: "id", json: ["details_json"] },
  { kind: "analytics-events", table: "analytics_events", columns: ["id", "event_type", "folder_id", "file_name", "details_json"], order: "id", json: ["details_json"] },
  { kind: "audit-logs", table: "audit_logs", columns: ["id", "event_type", "target_type", "target_id", "details_json"], order: "id", json: ["details_json"] },
  { kind: "users", table: "users", columns: ["id", "username", "permissions_json", "deleted_at"], order: "id", json: ["permissions_json"] },
  { kind: "schema-migrations", table: "schema_migrations", columns: ["version", "name", "applied_at"], order: "version", json: [] },
  // Authentication replay grants are observed as bounded opaque metadata,
  // never treated as proof of file provenance or legacy cutover readiness.
  { kind: "sync-resume-grants", table: "sync_resume_factor_spend_grant", columns: ["username", "replay_digest", "code_mac", "device_id", "pause_fence", "committed_at"], order: "username, replay_digest", json: [] },
]);
const FTS_SHADOW = Object.freeze(["data", "idx", "content", "docsize", "config"]
  .map((suffix) => `file_search_index_${suffix}`));
const KNOWN_TABLES = new Set([...SOURCES, ...EXTRA_SOURCES].map((entry) => entry.table)
  .concat(FTS_SHADOW, ["sqlite_sequence", "sqlite_stat1", "sqlite_stat4"]));
// Column drift can hide a NEW plaintext/reference field inside a previously
// recognized table. Allow only fields from migrations 1-9, even if not all are
// selected into the opaque observation. Missing selected fields fail below.
const KNOWN_COLUMNS = Object.freeze({
  users: "id username password_hash role permissions_json created_at updated_at deleted_at session_version disabled totp_enabled totp_secret_json totp_pending_secret_json totp_recovery_hashes_json totp_last_used_step totp_enrolled_at storage_revision",
  folders: "id name created_by created_at updated_at allowed_users_json is_root expires_at deleted_at",
  pending_uploads: "id file_name original_name folder_id uploaded_by uploaded_at size metadata_json",
  public_links: "token folder_id file_name created_by created_at expires_at max_views views password_hash metadata_json revoked_at permissions_json",
  actions_history: "id action_type username folder_id file_name timestamp details_json",
  file_permissions: "id folder_id file_name allowed_users_json created_at updated_at",
  file_expirations: "id folder_id file_name expires_at created_by created_at",
  file_versions: "id folder_id file_name versions_json updated_at",
  encrypted_files: "id folder_id file_name encryption_level metadata_json created_at updated_at",
  analytics_events: "id event_type username folder_id folder_name file_name size timestamp details_json",
  audit_logs: "id event_type severity actor_username actor_ip target_type target_id action result timestamp details_json",
  backup_history: "id filename type status created_by created_at finished_at size_bytes checksum error_message metadata_json",
  trash_items: "id item_type original_folder_id original_folder_name original_file_name stored_file_name original_path trash_path deleted_by deleted_at size_bytes metadata_json restore_metadata_json status restored_by restored_at permanently_deleted_by permanently_deleted_at",
  file_search_index: "folder_id file_name",
  schema_migrations: "version name applied_at",
  sync_resume_factor_spend_grant: "username replay_digest code_mac device_id pause_fence committed_at",
});
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
    // NTFS (and other 64-bit filesystems) can expose different dev/ino values
    // which collide after conversion to Number. Never round file identity.
    const s = fs.lstatSync(file, { bigint: true });
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1n) refuse();
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
function boundedExtraJson(value) {
  if (typeof value !== "string" || value.length > 256 * 1024) refuse();
  let parsed;
  try { parsed = JSON.parse(value); } catch (_) { refuse(); }
  if (!parsed || typeof parsed !== "object") refuse();
}
function inspectTable(db, source, secret, extra = false) {
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
    for (const name of source.json) (extra ? boundedExtraJson : boundedJson)(row[name]);
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

function inspectRegisteredSqlCoverage(db, secret, originalObservations) {
  const schema = db.prepare("SELECT type, name, sql FROM sqlite_master WHERE type IN ('table','view','trigger') ORDER BY name")
    .all();
  if (schema.length > 128 || schema.some((entry) =>
    entry.type !== "table" || !KNOWN_TABLES.has(entry.name)
      || (typeof entry.sql !== "string" && !entry.name.startsWith("sqlite_")))) refuse();
  const found = new Set(schema.map((entry) => entry.name));
  if ([...SOURCES, ...EXTRA_SOURCES].some((source) => !found.has(source.table))
    || FTS_SHADOW.some((name) => !found.has(name))) refuse();
  for (const [table, spec] of Object.entries(KNOWN_COLUMNS)) {
    const known = new Set(spec.split(" "));
    const actual = db.prepare(`PRAGMA table_info("${table}")`).all();
    if (!actual.length || actual.some((column) => !known.has(column.name))) refuse();
  }
  const fts = schema.find((entry) => entry.name === "file_search_index");
  if (!/^CREATE VIRTUAL TABLE\s+file_search_index\s+USING\s+fts5\s*\(\s*folder_id\s+UNINDEXED\s*,\s*file_name\s*,\s*tokenize\s*=\s*'trigram case_sensitive 0'\s*\)$/i.test(fts.sql)) refuse();
  // Validate declared FKs even when the writer had foreign_keys=OFF. This
  // cannot establish the correctness of application references without FKs.
  if (db.prepare("PRAGMA foreign_key_check").get() !== undefined) refuse();
  const extras = EXTRA_SOURCES.map((source) => inspectTable(db, source, secret, true));
  const fingerprint = crypto.createHmac("sha256", secret)
    .update("rootark-zk1-live-legacy-registered-sql/v1\0")
    .update(JSON.stringify(schema.map((row) => [row.type, row.name, row.sql])))
    .update(JSON.stringify([...originalObservations, ...extras].map((row) =>
      [row.kind, row.observedRows, row.ephemeralFingerprint]))).digest("base64url");
  return Object.freeze({
    observation: "bounded-registered-sqlite-sources-only",
    sources: Object.freeze([...originalObservations, ...extras]),
    registeredTableNamesOnly: true,
    registeredColumnNamesOnly: true,
    unrecognizedTables: 0,
    ephemeralFingerprint: fingerprint,
    providerCustodyVerified: false,
    protectedReferenceJoinsVerified: false,
    globallyComplete: false,
  });
}

function inspectZk1LiveLegacyReferencePreflight({
  optIn, databasePath, persistence = {}, backupDataDir, sqlCoverageOptIn, localUploadsDir,
  strictSourceInventoryOptIn, zipContentsOptIn,
} = {}) {
  if (optIn !== true || typeof databasePath !== "string" || !path.isAbsolute(databasePath)
    || persistence.dbEnabled !== true || persistence.jsonReadFallback !== false
    || persistence.jsonWriteMirror !== false
    || (sqlCoverageOptIn !== undefined && typeof sqlCoverageOptIn !== "boolean")
    || (strictSourceInventoryOptIn !== undefined && typeof strictSourceInventoryOptIn !== "boolean")
    || (strictSourceInventoryOptIn === true && (sqlCoverageOptIn !== true
      || backupDataDir === undefined || localUploadsDir === undefined))
    || (zipContentsOptIn !== undefined && typeof zipContentsOptIn !== "boolean")
    || (zipContentsOptIn === true && backupDataDir === undefined)) refuse();
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
    const sqlCoverage = sqlCoverageOptIn === true
      ? inspectRegisteredSqlCoverage(db, ephemeralKey, observations) : null;
    const backupEvidence = backupDataDir === undefined
      ? Object.freeze({ observation: "uninspected", globallyComplete: false })
      : require("./zk1LiveLegacyBackupEvidence").inspectZk1LiveLegacyBackupEvidence({
        dataDir: backupDataDir, databasePath, db, runSecret: ephemeralKey,
        zipContentsOptIn: zipContentsOptIn === true,
      });
    const localReferenceEvidence = localUploadsDir === undefined
      ? Object.freeze({ observation: "uninspected", globallyComplete: false })
      : require("./zk1LiveLegacyLocalReferenceEvidence").inspectZk1LiveLegacyLocalReferenceEvidence({
        uploadsDir: localUploadsDir, db, runSecret: ephemeralKey,
        strictSourceReferences: strictSourceInventoryOptIn === true,
      });
    const sourceInventory = strictSourceInventoryOptIn === true
      ? Object.freeze({
        observation: "bounded-reconciled-local-source-types-only",
        local: localReferenceEvidence.strictSourceTypes,
        backupHistoryRows: backupEvidence.historyRows,
        archiveFiles: backupEvidence.archives,
        archiveTombstones: backupEvidence.retentionTombstones,
        archiveTransactions: backupEvidence.retentionTransactions,
        sqlTablesRecognized: sqlCoverage.unrecognizedTables === 0,
        externalReferencesVerified: false,
        derivedOutsideSearchIndexVerified: false,
        ownerSignedCorpusProofVerified: false,
        globallyComplete: false,
        authorizesCutover: false,
        canDeleteLegacy: false,
      }) : null;
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
        backupEvidence,
        localReferenceEvidence,
        ...(sourceInventory ? { sourceInventory } : {}),
        ...(sqlCoverage ? { sqlCoverage } : {}),
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
