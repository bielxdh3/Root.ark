const fs = require("fs");
const path = require("path");
const crypto = require("node:crypto");
const { ROOT_DIR, getDb, getDatabasePath, isStrictSyncModeObserved } = require("./index");
const Database = require("better-sqlite3");
const { runMigrations } = require("./migrations");
const usersRepository = require("../repositories/usersRepository");
const foldersRepository = require("../repositories/foldersRepository");
const pendingUploadsRepository = require("../repositories/pendingUploadsRepository");
const publicLinksRepository = require("../repositories/publicLinksRepository");
const filePermissionsRepository = require("../repositories/filePermissionsRepository");
const fileExpirationsRepository = require("../repositories/fileExpirationsRepository");
const fileVersionsRepository = require("../repositories/fileVersionsRepository");
const encryptedFilesRepository = require("../repositories/encryptedFilesRepository");
const analyticsRepository = require("../repositories/analyticsRepository");
const auditRepository = require("../repositories/auditRepository");
const jsonAuditArchiveStore = require("../repositories/jsonAuditArchiveStore");
const { withJsonAuditLock } = require("../repositories/jsonAuditLock");
const actionHistoryRepository = require("../repositories/actionHistoryRepository");
const trashRepository = require("../repositories/trashRepository");
const backupRepository = require("../repositories/backupRepository");

const DATA_DIR = path.join(ROOT_DIR, "data");
const IMPORT_MARKER = "legacy_json_sqlite_import";
const AUDIT_IMPORT_MARKER = "legacy_json_sqlite_audit_import";
const AUDIT_ARCHIVE_TABLE = "legacy_json_audit_archive";
const JSON_SOURCES = [
  "users.local.json", "users.json", "folders.json", "pending-uploads.json",
  "public-links.json", "file-permissions.json", "file-expirations.json",
  "file-versions.json", "encrypted-files.json", "analytics.json",
  "audit-logs.json", "actions-history.json", "trash-items.json", "backup-history.json",
];
const IMPORT_TABLES = [
  "users", "folders", "pending_uploads", "public_links", "file_permissions",
  "file_expirations", "file_versions", "encrypted_files", "analytics_events",
  "audit_logs", "actions_history", "trash_items", "backup_history",
  AUDIT_ARCHIVE_TABLE,
];

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

function sourceFingerprint() {
  const hash = crypto.createHash("sha256");
  for (const fileName of JSON_SOURCES) {
    hash.update(`${fileName}\0`);
    const source = path.join(DATA_DIR, fileName);
    if (!fs.existsSync(source)) {
      hash.update("missing\0");
      continue;
    }
    const bytes = fs.readFileSync(source);
    hash.update(`present:${bytes.length}\0`);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function archivedAuditFingerprint() {
  const hash = crypto.createHash("sha256");
  hash.update("archived-json-audit-evidence-v1\0");
  jsonAuditArchiveStore.forEachArchivedAuditForMigration((log) => {
    const event = Buffer.from(JSON.stringify(log));
    hash.update(`${event.length}:`);
    hash.update(event);
  });
  return hash.digest("hex");
}

function readImportMarker(db, markerName = IMPORT_MARKER) {
  const entity = db.prepare("SELECT type FROM sqlite_master WHERE name = ?").get(markerName);
  if (!entity) return null;
  if (entity.type !== "table") throw new Error("Invalid JSON migration import marker");
  const rows = db.prepare(`SELECT id, version, source_sha256 FROM ${markerName}`).all();
  if (rows.length !== 1 || rows[0].id !== 1 || rows[0].version !== 1
    || !/^[a-f0-9]{64}$/.test(rows[0].source_sha256)) {
    throw new Error("Invalid JSON migration import marker");
  }
  return rows[0].source_sha256;
}

function storeImportMarker(db, name, hash) {
  db.exec(`CREATE TABLE ${name} (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    version INTEGER NOT NULL CHECK(version = 1),
    source_sha256 TEXT NOT NULL CHECK(length(source_sha256) = 64)
  )`);
  db.prepare(`INSERT INTO ${name}(id,version,source_sha256) VALUES (1,1,?)`).run(hash);
}

function importArchivedAudit(db, { activeLogs = null } = {}) {
  if (auditRepository.hasMigratedJsonArchive(db)) {
    throw new Error("Unmarked migrated JSON audit archive authority; refusing to overwrite");
  }
  db.exec(`CREATE TABLE ${AUDIT_ARCHIVE_TABLE} (id TEXT PRIMARY KEY NOT NULL, event TEXT NOT NULL)`);
  const active = activeLogs && new Map();
  if (active) {
    for (const log of activeLogs) {
      if (typeof log?.id !== "string" || !log.id) throw Error("Invalid active JSON audit identity");
      const prior = active.get(log.id);
      if (prior && !sameEvidence(prior, log)) throw Error("Divergent active JSON audit identity");
      active.set(log.id, log);
    }
  }
  const findMain = db.prepare(`SELECT id, event_type, severity, actor_username, actor_ip,
    target_type, target_id, action, result, timestamp, details_json FROM audit_logs WHERE id=?`);
  const find = db.prepare(`SELECT event FROM ${AUDIT_ARCHIVE_TABLE} WHERE id=?`);
  const insert = db.prepare(`INSERT INTO ${AUDIT_ARCHIVE_TABLE}(id,event) VALUES (?,?)`);
  const sidecarPath = `${getDatabasePath()}.audit-private${path.sep}pending.sqlite`;
  if (isStrictSyncModeObserved() && !fs.existsSync(sidecarPath)) {
    throw new Error("Strict audit journal missing during JSON archive migration");
  }
  let journal;
  try {
    if (fs.existsSync(sidecarPath)) journal = new Database(sidecarPath, { readonly: true, fileMustExist: true });
    const pending = journal?.prepare("SELECT event FROM pending_audit WHERE id=?");
    const archived = journal?.prepare("SELECT event FROM archived_audit WHERE id=?");
    jsonAuditArchiveStore.forEachArchivedAuditForMigration((log) => {
      if (typeof log?.id !== "string" || !log.id || typeof log.eventType !== "string") {
        throw new Error("Invalid archived JSON audit evidence during migration");
      }
      const previousActive = active?.get(log.id);
      if (previousActive && !sameEvidence(previousActive, log)) {
        throw new Error("Active/archived JSON audit identity collision during migration");
      }
      const main = findMain.get(log.id);
      if (main && !sameEvidence(auditRepository.rowToLog(main), auditRepository.normalizeMainAuditLog(log))) {
        throw new Error("SQLite main/archived JSON audit identity collision during migration");
      }
      for (const match of [pending?.get(log.id), archived?.get(log.id)]) {
        if (match && !sameEvidence(JSON.parse(match.event), log)) {
          throw new Error("SQLite sidecar/archived JSON audit identity collision during migration");
        }
      }
      const prior = find.get(log.id);
      if (prior) {
        if (!sameEvidence(JSON.parse(prior.event), log)) {
          throw new Error("Archived JSON audit identity collision during migration");
        }
      } else insert.run(log.id, JSON.stringify(log));
    });
  } finally { journal?.close(); }
}

function assertMatchingImport(marker, sourceHash) {
  if (marker !== sourceHash) {
    throw new Error("JSON source changed after import; refusing to overwrite SQLite data");
  }
}

function assertEmptyImportTables(db) {
  const present = new Set(db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all().map((row) => row.name));
  for (const table of IMPORT_TABLES) {
    if (present.has(table) && db.prepare(`SELECT 1 FROM ${table} LIMIT 1`).get()) {
      throw new Error("Pre-existing SQLite data without an import marker; refusing to overwrite");
    }
  }
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function copyDirectory(source, target) {
  fs.mkdirSync(target, { recursive: true });
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    if (entry.name === "backups") continue;
    const sourcePath = path.join(source, entry.name);
    const targetPath = path.join(target, entry.name);
    if (entry.isDirectory()) {
      copyDirectory(sourcePath, targetPath);
    } else {
      fs.copyFileSync(sourcePath, targetPath);
    }
  }
}

function backupDataDirectory() {
  const backupsDir = path.join(DATA_DIR, "backups");
  const backupPath = path.join(backupsDir, `json-before-sqlite-${timestamp()}`);
  fs.mkdirSync(backupsDir, { recursive: true });
  copyDirectory(DATA_DIR, backupPath);
  return backupPath;
}

function readJson(fileName, fallback) {
  const filePath = path.join(DATA_DIR, fileName);
  if (!fs.existsSync(filePath)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf-8"));
  } catch (error) {
    throw new Error(`JSON invalido em ${fileName}: ${error.message}`);
  }
}

function ensureArray(value, name) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new Error(`${name} precisa ser array`);
  return value;
}

function ensureObject(value, name) {
  if (value === undefined || value === null) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${name} precisa ser objeto`);
  }
  return value;
}

function getUsersJson() {
  const localUsers = readJson("users.local.json", null);
  if (Array.isArray(localUsers) && localUsers.length) return localUsers;
  return ensureArray(readJson("users.json", []), "users.json");
}

function migrateLocked() {
  const sourceHash = sourceFingerprint();
  const archiveHash = archivedAuditFingerprint();
  const db = getDb();
  const previousImport = readImportMarker(db);
  const previousArchive = readImportMarker(db, AUDIT_IMPORT_MARKER);
  if (previousImport !== null) {
    assertMatchingImport(previousImport, sourceHash);
    if (previousArchive !== null) {
      assertMatchingImport(previousArchive, archiveHash);
      if (!auditRepository.hasMigratedJsonArchive(db)) {
        throw Error("Migrated JSON audit archive marker without its authority");
      }
    } else {
      // Upgrade a deployment migrated by the original v1 importer. Its import
      // marker fingerprints only the public JSON files; preserve that contract
      // and add private archived evidence without touching its live accounts.
      db.transaction(() => {
        if (readImportMarker(db, AUDIT_IMPORT_MARKER) !== null) {
          throw Error("JSON audit archive migration raced another importer");
        }
        if (sourceFingerprint() !== sourceHash || archivedAuditFingerprint() !== archiveHash) {
          throw Error("JSON archive source changed during import");
        }
        importArchivedAudit(db);
        storeImportMarker(db, AUDIT_IMPORT_MARKER, archiveHash);
      }).immediate();
    }
    console.log("Migracao JSON -> SQLite ja concluida; dados SQLite preservados.");
    return;
  }
  if (previousArchive !== null) throw Error("Pre-existing SQLite data without an import marker; refusing to overwrite");
  // Check before backups or schema changes as well as inside the write lock.
  assertEmptyImportTables(db);

  const backupPath = backupDataDirectory();
  console.log(`Backup da pasta data criado em: ${backupPath}`);

  runMigrations();

  const payload = {
    users: getUsersJson(),
    folders: ensureArray(readJson("folders.json", []), "folders.json"),
    pendingUploads: ensureObject(readJson("pending-uploads.json", {}), "pending-uploads.json"),
    publicLinks: ensureObject(readJson("public-links.json", {}), "public-links.json"),
    filePermissions: ensureObject(readJson("file-permissions.json", {}), "file-permissions.json"),
    fileExpirations: ensureObject(readJson("file-expirations.json", {}), "file-expirations.json"),
    fileVersions: ensureObject(readJson("file-versions.json", {}), "file-versions.json"),
    encryptedFiles: ensureObject(readJson("encrypted-files.json", {}), "encrypted-files.json"),
    analytics: ensureObject(readJson("analytics.json", {}), "analytics.json"),
    auditLogs: ensureObject(readJson("audit-logs.json", { logs: [] }), "audit-logs.json"),
    actionHistory: ensureArray(readJson("actions-history.json", []), "actions-history.json"),
    trashItems: ensureArray(readJson("trash-items.json", []), "trash-items.json"),
    backupHistory: ensureArray(readJson("backup-history.json", []), "backup-history.json"),
  };

  if (!payload.folders.some((folder) => folder.id === "root")) {
    payload.folders.unshift({
      id: "root",
      name: "Arquivos atuais",
      createdBy: "sistema",
      createdAt: new Date().toISOString(),
      allowedUsers: [],
      isRoot: true,
    });
  }

  const writeAll = db.transaction(() => {
    const concurrentImport = readImportMarker(db);
    if (concurrentImport !== null) {
      assertMatchingImport(concurrentImport, sourceHash);
      return false;
    }
    assertEmptyImportTables(db);
    if (sourceFingerprint() !== sourceHash) {
      throw new Error("JSON source changed during import; refusing to overwrite SQLite data");
    }
    if (archivedAuditFingerprint() !== archiveHash) {
      throw new Error("JSON archive source changed during import; refusing to overwrite SQLite data");
    }
    usersRepository.saveUsers(payload.users);
    foldersRepository.saveFolders(payload.folders);
    pendingUploadsRepository.savePendingUploads(payload.pendingUploads);
    publicLinksRepository.savePublicLinks(payload.publicLinks);
    filePermissionsRepository.saveFilePermissions(payload.filePermissions);
    fileExpirationsRepository.saveFileExpirations(payload.fileExpirations);
    fileVersionsRepository.saveFileVersions(payload.fileVersions);
    encryptedFilesRepository.saveEncryptedFiles(payload.encryptedFiles);
    analyticsRepository.saveAnalytics(payload.analytics);
    auditRepository.saveAuditLogs(payload.auditLogs);
    // Archived authority lives in the backed-up SQLite primary, without the
    // 512 MiB capacity restriction of the strict pending-audit sidecar.
    importArchivedAudit(db, { activeLogs: payload.auditLogs.logs || [] });
    actionHistoryRepository.saveActionHistory(payload.actionHistory);
    for (const item of payload.trashItems) {
      if (!trashRepository.getTrashItem(item.id)) trashRepository.saveTrashItem(item);
    }
    for (const backup of payload.backupHistory) {
      if (!backupRepository.getBackup(backup.id)) backupRepository.saveBackup(backup);
    }
    storeImportMarker(db, IMPORT_MARKER, sourceHash);
    storeImportMarker(db, AUDIT_IMPORT_MARKER, archiveHash);
    return true;
  });

  if (!writeAll.immediate()) {
    console.log("Migracao JSON -> SQLite ja concluida em outra execucao.");
    return;
  }

  const report = {
    users: payload.users.length,
    folders: payload.folders.length,
    pendingUploads: Object.keys(payload.pendingUploads).length,
    publicLinks: Object.keys(payload.publicLinks).length,
    filePermissions: Object.keys(payload.filePermissions).length,
    fileExpirations: Object.keys(payload.fileExpirations).length,
    fileVersions: Object.keys(payload.fileVersions).length,
    encryptedFiles: Object.keys(payload.encryptedFiles).length,
    analyticsEvents: Object.values(payload.analytics).reduce((sum, list) => sum + (Array.isArray(list) ? list.length : 0), 0),
    auditLogs: Array.isArray(payload.auditLogs.logs) ? payload.auditLogs.logs.length : 0,
    actionHistory: payload.actionHistory.length,
    trashItems: payload.trashItems.length,
    backupHistory: payload.backupHistory.length,
  };

  console.log("Migracao JSON -> SQLite concluida:");
  for (const [key, value] of Object.entries(report)) {
    console.log(`- ${key}: ${value}`);
  }
}

function migrate() {
  // Hold the same cross-process writer lease as JSON audit retention for the
  // fingerprint, source scan and durable SQLite import marker COMMIT.
  return withJsonAuditLock(migrateLocked);
}

if (require.main === module) {
  try {
    migrate();
  } catch (error) {
    console.error(`Falha na migracao: ${error.message}`);
    process.exit(1);
  }
}

module.exports = { migrate };
