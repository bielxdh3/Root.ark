const fs = require("fs");
const path = require("path");
const { ROOT_DIR, getDb } = require("./index");
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
const actionHistoryRepository = require("../repositories/actionHistoryRepository");
const trashRepository = require("../repositories/trashRepository");
const backupRepository = require("../repositories/backupRepository");

const DATA_DIR = path.join(ROOT_DIR, "data");

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

function migrate() {
  const backupPath = backupDataDirectory();
  console.log(`Backup da pasta data criado em: ${backupPath}`);

  runMigrations();
  const db = getDb();

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
    actionHistoryRepository.saveActionHistory(payload.actionHistory);
    for (const item of payload.trashItems) {
      if (!trashRepository.getTrashItem(item.id)) trashRepository.saveTrashItem(item);
    }
    for (const backup of payload.backupHistory) {
      if (!backupRepository.getBackup(backup.id)) backupRepository.saveBackup(backup);
    }
  });

  writeAll();

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

if (require.main === module) {
  try {
    migrate();
  } catch (error) {
    console.error(`Falha na migracao: ${error.message}`);
    process.exit(1);
  }
}

module.exports = { migrate };
