const { loadEnvFile } = require("node:process");

try {
  loadEnvFile();
} catch (error) {
  if (error?.code !== "ENOENT") throw error;
}
const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const zlib = require("zlib");
const net = require("net");
const { pipeline } = require("stream/promises");
const mammoth = require("mammoth");
const { previewText } = require("./services/documentPreviewService");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const QRCode = require("qrcode");
const http = require("http");
const WebSocket = require("ws");
const cron = require("node-cron");
const { Transform } = require("node:stream");
const { scheduleAutomaticBackups } = require("./services/backupScheduler");
const dbConfig = require("./db");
const { runMigrations } = require("./db/migrations");
const usersRepository = require("./repositories/usersRepository");
const foldersRepository = require("./repositories/foldersRepository");
const pendingUploadsRepository = require("./repositories/pendingUploadsRepository");
const publicLinksRepository = require("./repositories/publicLinksRepository");
const filePermissionsRepository = require("./repositories/filePermissionsRepository");
const fileExpirationsRepository = require("./repositories/fileExpirationsRepository");
const fileVersionsRepository = require("./repositories/fileVersionsRepository");
const encryptedFilesRepository = require("./repositories/encryptedFilesRepository");
const analyticsRepository = require("./repositories/analyticsRepository");
const auditRepository = require("./repositories/auditRepository");
const actionHistoryRepository = require("./repositories/actionHistoryRepository");
const backupService = require("./services/backupService");
const restoreService = require("./services/restoreService");
const trashRepository = require("./repositories/trashRepository");
const trashService = require("./services/trashService");
const { createCloudStorage } = require("./services/cloudStorage");
const registerAuthRoutes = require("./src/routes/auth");
const registerAnalyticsRoutes = require("./src/routes/analytics");
const registerAuditRoutes = require("./src/routes/audit");
const registerBackupRoutes = require("./src/routes/backups");
const registerTrashRoutes = require("./src/routes/trash");
const { registerSyncRoutes } = require("./src/routes/sync");
const { registerGroupRoutes } = require("./src/routes/groups");
const { createAuthenticate, createRealtimeAuthenticator, getExpectedOrigin, parseCookies } = require("./src/middlewares/auth");
const { createRequirePermission } = require("./src/middlewares/permissions");
const { validateTotpPolicy } = require("./src/services/totpPolicy");
const { getDeploymentReadiness, registerReadinessRoutes, sanitizeLogValue } = require("./src/services/deploymentResilience");

const app = express();
const server = http.createServer(app);
const syncJsonParser = express.json({ limit: "9mb" });
function parseBoundedNumber(name, fallback, minimum, maximum) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && Number.isInteger(value) && value >= minimum && value <= maximum ? value : fallback;
}

const REALTIME_MAX_PAYLOAD_BYTES = parseBoundedNumber("REALTIME_MAX_PAYLOAD_BYTES", 16 * 1024, 1024, 1024 * 1024);
const REALTIME_MAX_BUFFERED_BYTES = parseBoundedNumber("REALTIME_MAX_BUFFERED_BYTES", 64 * 1024, 1024, 16 * 1024 * 1024);
const REALTIME_MAX_MESSAGES_PER_WINDOW = parseBoundedNumber("REALTIME_MAX_MESSAGES_PER_WINDOW", 30, 1, 10_000);
const REALTIME_RATE_WINDOW_MS = parseBoundedNumber("REALTIME_RATE_WINDOW_MS", 10 * 1000, 1000, 10 * 60 * 1000);
const REALTIME_HEARTBEAT_MS = parseBoundedNumber("REALTIME_HEARTBEAT_MS", 30 * 1000, 1000, 10 * 60 * 1000);
const REALTIME_IDLE_TIMEOUT_MS = parseBoundedNumber("REALTIME_IDLE_TIMEOUT_MS", 2 * REALTIME_HEARTBEAT_MS, REALTIME_HEARTBEAT_MS, 60 * 60 * 1000);
const wss = new WebSocket.Server({ server, path: "/ws", maxPayload: REALTIME_MAX_PAYLOAD_BYTES, perMessageDeflate: false });
const realtimeHeartbeat = setInterval(() => {
  for (const socket of wss.clients) {
    if (socket.isAlive === false || Date.now() - socket.lastActivityAt > REALTIME_IDLE_TIMEOUT_MS) socket.terminate();
    else { socket.isAlive = false; socket.ping(); }
  }
}, REALTIME_HEARTBEAT_MS);
server.once("close", () => clearInterval(realtimeHeartbeat));
const JWT_SECRET = String(process.env.JWT_SECRET || "");
if (JWT_SECRET.length < 32 || JWT_SECRET === "rootark_secret_change_in_production") {
  throw new Error("JWT_SECRET deve ser definido explicitamente com pelo menos 32 caracteres seguros.");
}
validateTotpPolicy();
const PORT = Number(process.env.PORT || 3000);
const SESSION_COOKIE_OPTIONS = { httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production", path: "/" };
const USERS_SEED_FILE = "./data/users.json";
const USERS_FILE = "./data/users.local.json";
const USER_GENERATIONS_FILE = "./data/user-generations.local.json";
const PENDING_UPLOADS_FILE = "./data/pending-uploads.json";
const PUBLIC_LINKS_FILE = "./data/public-links.json";
const ACTION_HISTORY_FILE = "./data/actions-history.json";
const FOLDERS_FILE = "./data/folders.json";
const FILE_PERMISSIONS_FILE = "./data/file-permissions.json";
const FILE_EXPIRATIONS_FILE = "./data/file-expirations.json";
const FILE_VERSIONS_FILE = "./data/file-versions.json";
const ENCRYPTED_FILES_FILE = "./data/encrypted-files.json";
const SERVER_MASTER_KEY_FILE = "./data/server-master.key";
const ANALYTICS_FILE = "./data/analytics.json";
const AUDIT_LOGS_FILE = "./data/audit-logs.json";
const AUDIT_ARCHIVE_FILE = "./data/audit-logs-archive.json";
const QUARANTINE_FILE = "./data/quarantine.json";
const GROUPS_FILE = "./data/groups.json";
const CLOUD_STORAGE_PROVIDER = String(process.env.CLOUD_STORAGE_PROVIDER || "local").toLowerCase();
const CLOUD_STORAGE_PREFIX = String(process.env.CLOUD_STORAGE_PREFIX || "rootark").replace(/^\/+|\/+$/g, "") || "rootark";
const ROOT_FOLDER_ID = "root";
const MAX_FILE_NAME_LENGTH = 30;
const MAX_FILE_VERSIONS = 10;
const MAX_SHARE_EXPIRATION_MINUTES = 60 * 24 * 30;
const MAX_SHARE_VIEWS = 1000;
const MAX_SHARE_DOWNLOADS = 1000;
const SHARE_VIEW_SESSION_MS = 10 * 60 * 1000;
const MAX_TEMPORARY_EXPIRATION_MS = 1000 * 60 * 60 * 24 * 365;
const OPEN_FILE_TOKEN_TTL_MS = 10 * 60 * 1000;
const MAX_ACTION_HISTORY_ENTRIES = 500;
const ANALYTICS_RETENTION_MS = 1000 * 60 * 60 * 24 * 365;
const ANALYTICS_SUMMARY_CACHE_MS = 5 * 60 * 1000;
const MAX_AUDIT_LOGS = 10000;
const AUDIT_RETENTION_MS = 1000 * 60 * 60 * 24 * 365;
const MAX_TEXT_PREVIEW_BYTES = 1024 * 1024;
const CHUNK_UPLOAD_DIR = path.resolve("./temp/.chunks");
const SIMPLE_UPLOAD_INCOMING_DIR = path.resolve("./temp/.incoming");
const MAX_UPLOAD_CHUNKS = 2000;
const SINGLE_UPLOAD_MAX_BYTES = 8 * 1024 * 1024;
const UPLOAD_SCAN_ENABLED = parseEnvBoolean(process.env.UPLOAD_SCAN_ENABLED, true);
const UPLOAD_SCAN_PROVIDER = String(process.env.UPLOAD_SCAN_PROVIDER || "clamav").toLowerCase();
const CLAMAV_HOST = process.env.CLAMAV_HOST || "127.0.0.1";
const CLAMAV_PORT = Number(process.env.CLAMAV_PORT || 3310);
const UPLOAD_BLOCK_EXECUTABLES = parseEnvBoolean(process.env.UPLOAD_BLOCK_EXECUTABLES, true);
const UPLOAD_QUARANTINE_DIR = path.resolve(process.env.UPLOAD_QUARANTINE_DIR || "./data/quarantine");
const UPLOAD_FAIL_CLOSED = parseEnvBoolean(process.env.UPLOAD_FAIL_CLOSED, false);
const UPLOAD_SUSPICIOUS_EXTENSIONS = new Set(
  String(process.env.UPLOAD_SUSPICIOUS_EXTENSIONS || ".exe,.bat,.cmd,.scr,.msi,.ps1,.vbs,.jar,.com")
    .split(",")
    .map((extension) => extension.trim().toLowerCase())
    .filter(Boolean)
);
const WEBDAV_ENABLED = parseEnvBoolean(process.env.WEBDAV_ENABLED, false);
const WEBDAV_PATH = normalizeWebDavMountPath(process.env.WEBDAV_PATH || "/dav");
const WEBDAV_ALLOW_DELETE = parseEnvBoolean(process.env.WEBDAV_ALLOW_DELETE, false);
const WEBDAV_ALLOW_MOVE = parseEnvBoolean(process.env.WEBDAV_ALLOW_MOVE, false);
const WEBDAV_MOVE_JOURNAL_DIR = path.resolve("./temp/.incoming");
const WEBDAV_MOVE_METADATA_FILES = [PUBLIC_LINKS_FILE, FILE_PERMISSIONS_FILE, FILE_EXPIRATIONS_FILE, FILE_VERSIONS_FILE, ENCRYPTED_FILES_FILE];
const WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS = parseBoundedNumber("WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS", 60 * 1000, 1000, 60 * 60 * 1000);
const WEBDAV_MOVE_RECONCILIATION_MAX_ATTEMPTS = parseBoundedNumber("WEBDAV_MOVE_RECONCILIATION_MAX_ATTEMPTS", 5, 1, 100);
const WEBDAV_MOVE_RECONCILIATION_LEASE_MS = parseBoundedNumber("WEBDAV_MOVE_RECONCILIATION_LEASE_MS", 60 * 1000, 1000, 60 * 60 * 1000);
const WEBDAV_MOVE_RECONCILIATION_MAX_BACKOFF_MS = parseBoundedNumber("WEBDAV_MOVE_RECONCILIATION_MAX_BACKOFF_MS", 60 * 60 * 1000, 1000, 24 * 60 * 60 * 1000);
const WEBDAV_MOVE_REMOTE_INTENT_STATES = new Set([
  "claimed",
  "destination_upload_intent",
  "destination_upload_uncertain",
  "cloud_destination_upload_intent",
  "cloud_destination_upload_uncertain",
  "destination_uploaded",
  "source_delete_intent",
  "source_delete_uncertain",
  "cloud_source_delete_intent",
  "cloud_source_delete_uncertain",
  "retry_wait",
  "cloud_reconciliation_claimed",
  "cloud_destination_uploaded",
  "cloud_source_removal_pending",
  "uploaded",
  "delete-claimed",
  "delete-uncertain",
  "uncertain",
]);
let webDavReconciliationRunning = false;
let webDavReconciliationTimer = null;
const ENCRYPTION_ITERATIONS = 100000;
const openFileTokens = new Map();
let groupsStore = null;
let analyticsSummaryCache = null;
const cloudStorage = createCloudStorage({
  provider: CLOUD_STORAGE_PROVIDER,
  prefix: CLOUD_STORAGE_PREFIX,
  rootFolderId: ROOT_FOLDER_ID,
  s3: { bucket: process.env.AWS_S3_BUCKET, region: process.env.AWS_REGION, endpoint: process.env.AWS_ENDPOINT_URL, forcePathStyle: process.env.AWS_FORCE_PATH_STYLE === "true" },
  gdrive: { folderId: process.env.GOOGLE_DRIVE_FOLDER_ID, credentials: process.env.GOOGLE_SERVICE_ACCOUNT_JSON, credentialsPath: process.env.GOOGLE_APPLICATION_CREDENTIALS },
});
backupService.setCloudStorage(cloudStorage);
restoreService.setCloudStorage(cloudStorage);
registerReadinessRoutes(app, {
  getReadiness: () => getDeploymentReadiness({
    env: process.env,
    masterKeyFile: SERVER_MASTER_KEY_FILE,
    cloudStatus: cloudStorage.status(),
    validateTotp: validateTotpPolicy,
  }),
});

function shouldUseDatabase() {
  return dbConfig.isDbEnabled();
}

function shouldReadJsonFallback() {
  return dbConfig.isJsonReadFallbackEnabled();
}

function shouldWriteLegacyJson() {
  return !shouldUseDatabase() || dbConfig.isLegacyJsonWriteEnabled();
}

function parseEnvBoolean(value, fallback = false) {
  if (value === undefined || value === null || value === "") return fallback;
  return ["1", "true", "yes", "sim", "on"].includes(String(value).trim().toLowerCase());
}

function normalizeWebDavMountPath(value) {
  const normalized = `/${String(value || "/dav").trim().replace(/^\/+|\/+$/g, "")}`;
  return normalized === "/" ? "/dav" : normalized;
}

function isWebDavRequestPath(requestPath) {
  const cleanPath = String(requestPath || "");
  return cleanPath === WEBDAV_PATH || cleanPath.startsWith(`${WEBDAV_PATH}/`);
}

const ENCRYPTION_LEVELS = {
  none: { description: "Arquivo nao criptografado", icon: "open", requiresKey: false },
  "server-key": { description: "Criptografado com chave do servidor", icon: "server", requiresKey: false },
  "user-key": { description: "Criptografado com chave do usuario", icon: "private", requiresKey: false },
  password: { description: "Criptografado com senha", icon: "password", requiresKey: true },
  dual: { description: "Criptografia dupla", icon: "dual", requiresKey: true },
};

// Cloud provider operations live in services/cloudStorage. These thin adapters preserve route behavior.
function isCloudStorageEnabled() { return cloudStorage.enabled(); }
function getCloudStorageStatus() { return cloudStorage.status(); }
function getCloudKey(folderId = ROOT_FOLDER_ID, fileName = "", area = "uploads") { return cloudStorage.key(folderId, fileName, area); }
async function uploadFileToCloud(localPath, folderId, fileName, area = "uploads") { return cloudStorage.upload(localPath, folderId, fileName, area); }
async function downloadFileFromCloud(folderId, fileName, localPath, area = "uploads") { return cloudStorage.download(folderId, fileName, localPath, area); }
async function deleteFileFromCloud(folderId, fileName, area = "uploads") { return cloudStorage.remove(folderId, fileName, area); }
async function deleteCloudPrefix(prefix) { return cloudStorage.removePrefix(prefix); }
async function listCloudFiles(folderId, area = "uploads") { return cloudStorage.list(folderId, area); }

async function syncFolderCacheFromCloud(folderId, area = "uploads") {
  if (!isCloudStorageEnabled()) return;

  try {
    const files = await listCloudFiles(folderId, area);
    const baseDir = area === "temp" ? "./temp" : "./uploads";
    for (const file of files) {
      const fileName = path.basename(file.name || "");
      if (!fileName) continue;
      const localPath = path.join(getFolderStoragePath(baseDir, folderId), fileName);
      await ensureCloudFileCached(folderId, fileName, localPath, area);
    }
  } catch (error) {
    console.error("[cloud-storage] sync cache failed:", sanitizeLogValue(error.message));
  }
}

function syncCloudFireAndForget(promise, label) {
  if (!isCloudStorageEnabled()) return;
  Promise.resolve(promise).catch((error) => {
    console.error("[cloud-storage] operation failed:", sanitizeLogValue(error.message));
  });
}

function syncFileToCloud(folderId, fileName, area = "uploads") {
  const baseDir = area === "temp" ? "./temp" : "./uploads";
  const localPath = path.join(getFolderStoragePath(baseDir, folderId), path.basename(fileName));
  syncCloudFireAndForget(uploadFileToCloud(localPath, folderId, fileName, area), `sync ${area}/${folderId}/${fileName}`);
}

function deleteCloudFileLater(folderId, fileName, area = "uploads") {
  syncCloudFireAndForget(deleteFileFromCloud(folderId, fileName, area), `delete ${area}/${folderId}/${fileName}`);
}

function deleteCloudFolderLater(folderId) {
  syncCloudFireAndForget(deleteCloudPrefix(getCloudKey(folderId, "", "uploads")), `delete uploads folder ${folderId}`);
  syncCloudFireAndForget(deleteCloudPrefix(getCloudKey(folderId, "", "temp")), `delete temp folder ${folderId}`);
}

async function ensureCloudFileCached(folderId, fileName, localPath, area = "uploads") {
  if (isExistingFile(localPath)) return true;
  if (!isCloudStorageEnabled()) return false;

  try {
    return await downloadFileFromCloud(folderId, fileName, localPath, area);
  } catch (error) {
    console.error("[cloud-storage] restore cache failed:", sanitizeLogValue(error.message));
    return false;
  }
}

function refreshRealtimeUser(socket) {
  if (!Number.isFinite(socket.user?.expiresAt) || Date.now() >= socket.user.expiresAt) {
    socket.close(1008, "Sessao expirada");
    return false;
  }
  const user = loadCurrentUser(socket.user?.username);
  if (user && !user.disabled && (user.sessionVersion || 0) === socket.user?.sessionVersion) return true;
  socket.close(1008, "Sessao revogada");
  return false;
}

function sendRealtime(socket, event, payload = {}) {
  if (socket.readyState !== WebSocket.OPEN || !refreshRealtimeUser(socket)) return;
  if (socket.bufferedAmount > REALTIME_MAX_BUFFERED_BYTES) return socket.close(1013, "Cliente lento");
  socket.send(JSON.stringify({ event, payload, timestamp: new Date().toISOString() }));
}

function broadcastRealtime(event, payload = {}) {
  for (const socket of wss.clients) {
    sendRealtime(socket, event, payload);
  }
}

function broadcastDataChanged(source, payload = {}) {
  broadcastRealtime("data:changed", { source, ...payload });
}

function loadUsers() {
  if (shouldUseDatabase()) {
    try {
      const users = usersRepository.loadUsers();
      if (users.length || !shouldReadJsonFallback()) return users;
    } catch (error) {
      console.error("Falha ao ler usuarios do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return [];
    }
  }
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
}

function loadUserGenerations() {
  if (!fs.existsSync(USER_GENERATIONS_FILE)) return {};

  let generations;
  try {
    generations = JSON.parse(fs.readFileSync(USER_GENERATIONS_FILE, "utf-8"));
  } catch {
    throw new Error("Historico de geracoes de usuario invalido");
  }

  if (!generations || typeof generations !== "object" || Array.isArray(generations) || Object.values(generations).some((version) => !Number.isSafeInteger(version) || version < 0)) {
    throw new Error("Historico de geracoes de usuario invalido");
  }
  return generations;
}

function rememberUserGenerations(users) {
  const generations = loadUserGenerations();
  for (const user of users) {
    const username = String(user?.username || "").trim();
    const version = user?.sessionVersion || 0;
    if (username && Number.isSafeInteger(version) && version >= 0) {
      generations[username] = Math.max(generations[username] ?? 0, version);
    }
  }
  fs.writeFileSync(USER_GENERATIONS_FILE, JSON.stringify(generations, null, 2));
}

function getCreatedUserSessionVersion(username) {
  if (shouldUseDatabase()) return 0;
  const generations = loadUserGenerations();
  return Object.hasOwn(generations, username) ? generations[username] + 1 : 0;
}

function saveUsers(users) {
  if (shouldUseDatabase()) usersRepository.saveUsers(users);
  if (shouldWriteLegacyJson()) {
    rememberUserGenerations(users);
    const temporaryFile = `${USERS_FILE}.tmp-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
    try {
      fs.writeFileSync(temporaryFile, JSON.stringify(users, null, 2), { mode: 0o600 });
      fs.renameSync(temporaryFile, USERS_FILE);
    } catch (error) {
      fs.rmSync(temporaryFile, { force: true });
      throw error;
    }
  }
}

function getBasePermissions() {
  return {
    upload: false,
    approve: false,
    delete: false,
    listFiles: true,
    listPending: false,
    manageUsers: false,
    createFolders: false,
    viewAnalytics: false,
    viewAuditLogs: false,
    manageBackups: false,
    manageTrash: false,
  };
}

function normalizeUserPermissions(user = {}) {
  const permissions = {
    ...getBasePermissions(),
    ...(user.permissions || {}),
  };

  if (user.role === "admin") {
    return Object.fromEntries(Object.keys(permissions).map((key) => [key, true]));
  }

  return permissions;
}

function getDefaultUsers() {
  return [
    {
      username: "admin",
      password: bcrypt.hashSync("admin123", 10),
      role: "admin",
      permissions: normalizeUserPermissions({ role: "admin" }),
    },
    {
      username: "user",
      password: bcrypt.hashSync("user123", 10),
      role: "user",
      permissions: {
        ...getBasePermissions(),
        upload: true,
      },
    },
  ];
}

function loadSeedUsers() {
  if (!fs.existsSync(USERS_SEED_FILE)) return null;

  try {
    const users = JSON.parse(fs.readFileSync(USERS_SEED_FILE, "utf-8"));
    return Array.isArray(users) && users.length ? users : null;
  } catch {
    return null;
  }
}

function loadPendingUploads() {
  if (shouldUseDatabase()) {
    try {
      const entries = pendingUploadsRepository.loadPendingUploads();
      if (Object.keys(entries).length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler uploads pendentes do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return {};
    }
  }
  if (!fs.existsSync(PENDING_UPLOADS_FILE)) return {};
  return JSON.parse(fs.readFileSync(PENDING_UPLOADS_FILE, "utf-8"));
}

function savePendingUploads(entries) {
  if (shouldUseDatabase()) pendingUploadsRepository.savePendingUploads(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(PENDING_UPLOADS_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("pending");
}

function getDefaultQuarantine() {
  return { items: [] };
}

function loadQuarantine() {
  if (!fs.existsSync(QUARANTINE_FILE)) return getDefaultQuarantine();
  try {
    const entries = JSON.parse(fs.readFileSync(QUARANTINE_FILE, "utf-8"));
    return { items: Array.isArray(entries?.items) ? entries.items : [] };
  } catch (error) {
    console.error("Falha ao ler quarentena:", error.message);
    return getDefaultQuarantine();
  }
}

function saveQuarantine(entries) {
  const normalized = { items: Array.isArray(entries?.items) ? entries.items : [] };
  fs.writeFileSync(QUARANTINE_FILE, JSON.stringify(normalized, null, 2));
  broadcastDataChanged("quarantine");
}

function getDefaultFolders() {
  return [
    {
      id: ROOT_FOLDER_ID,
      name: "Arquivos atuais",
      createdBy: "sistema",
      createdAt: new Date().toISOString(),
      allowedUsers: [],
      isRoot: true,
    },
  ];
}

function loadFolders() {
  if (shouldUseDatabase()) {
    try {
      const folders = foldersRepository.loadFolders();
      const jsonHasFolders = fs.existsSync(FOLDERS_FILE) && shouldReadJsonFallback();
      if (folders.length > 1 || !jsonHasFolders) return folders;
    } catch (error) {
      console.error("Falha ao ler pastas do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return getDefaultFolders();
    }
  }
  if (!fs.existsSync(FOLDERS_FILE)) return getDefaultFolders();
  const folders = JSON.parse(fs.readFileSync(FOLDERS_FILE, "utf-8"));
  return Array.isArray(folders) ? folders : getDefaultFolders();
}

function saveFolders(folders) {
  if (shouldUseDatabase()) foldersRepository.saveFolders(folders);
  if (shouldWriteLegacyJson()) fs.writeFileSync(FOLDERS_FILE, JSON.stringify(folders, null, 2));
  broadcastDataChanged("folders");
}

function loadFilePermissions() {
  if (shouldUseDatabase()) {
    try {
      const entries = filePermissionsRepository.loadFilePermissions();
      if (Object.keys(entries).length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler permissoes do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return {};
    }
  }
  if (!fs.existsSync(FILE_PERMISSIONS_FILE)) return {};

  try {
    const entries = JSON.parse(fs.readFileSync(FILE_PERMISSIONS_FILE, "utf-8"));
    return entries && typeof entries === "object" && !Array.isArray(entries) ? entries : {};
  } catch (error) {
    console.error("Falha ao ler permissoes de arquivos:", error.message);
    return {};
  }
}

function saveFilePermissions(entries) {
  if (shouldUseDatabase()) filePermissionsRepository.saveFilePermissions(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(FILE_PERMISSIONS_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("permissions");
}

function loadFileExpirations() {
  if (shouldUseDatabase()) {
    try {
      const entries = fileExpirationsRepository.loadFileExpirations();
      if (Object.keys(entries).length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler expiracoes do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return {};
    }
  }
  if (!fs.existsSync(FILE_EXPIRATIONS_FILE)) return {};

  try {
    const entries = JSON.parse(fs.readFileSync(FILE_EXPIRATIONS_FILE, "utf-8"));
    return entries && typeof entries === "object" && !Array.isArray(entries) ? entries : {};
  } catch (error) {
    console.error("Falha ao ler expiracoes de arquivos:", error.message);
    return {};
  }
}

function saveFileExpirations(entries) {
  if (shouldUseDatabase()) fileExpirationsRepository.saveFileExpirations(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(FILE_EXPIRATIONS_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("expirations");
}

function loadFileVersions() {
  if (shouldUseDatabase()) {
    try {
      const entries = fileVersionsRepository.loadFileVersions();
      if (Object.keys(entries).length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler versoes do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return {};
    }
  }
  if (!fs.existsSync(FILE_VERSIONS_FILE)) return {};

  try {
    const entries = JSON.parse(fs.readFileSync(FILE_VERSIONS_FILE, "utf-8"));
    return entries && typeof entries === "object" && !Array.isArray(entries) ? entries : {};
  } catch (error) {
    console.error("Falha ao ler versoes de arquivos:", error.message);
    return {};
  }
}

function saveFileVersions(entries) {
  if (shouldUseDatabase()) fileVersionsRepository.saveFileVersions(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(FILE_VERSIONS_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("versions");
}

function loadEncryptedFiles() {
  if (shouldUseDatabase()) {
    try {
      const entries = encryptedFilesRepository.loadEncryptedFiles();
      if (Object.keys(entries).length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler criptografia do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return {};
    }
  }
  if (!fs.existsSync(ENCRYPTED_FILES_FILE)) return {};

  try {
    const entries = JSON.parse(fs.readFileSync(ENCRYPTED_FILES_FILE, "utf-8"));
    return entries && typeof entries === "object" && !Array.isArray(entries) ? entries : {};
  } catch (error) {
    console.error("Falha ao ler metadados de criptografia:", error.message);
    return {};
  }
}

function saveEncryptedFiles(entries) {
  if (shouldUseDatabase()) encryptedFilesRepository.saveEncryptedFiles(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(ENCRYPTED_FILES_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("encryption");
}

function getDefaultAnalytics() {
  return {
    uploads: [],
    downloads: [],
    logins: [],
    deletions: [],
    approvals: [],
    rejections: [],
    restores: [],
    versionDeletions: [],
  };
}

function normalizeAnalytics(entries = {}) {
  const defaults = getDefaultAnalytics();
  return Object.fromEntries(
    Object.keys(defaults).map((key) => [key, Array.isArray(entries[key]) ? entries[key] : []])
  );
}

function loadAnalytics() {
  if (shouldUseDatabase()) {
    try {
      const entries = analyticsRepository.loadAnalytics();
      const hasEvents = Object.values(entries).some((items) => Array.isArray(items) && items.length);
      if (hasEvents || !shouldReadJsonFallback()) return normalizeAnalytics(entries);
    } catch (error) {
      console.error("Falha ao ler analytics do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return getDefaultAnalytics();
    }
  }
  if (!fs.existsSync(ANALYTICS_FILE)) return getDefaultAnalytics();

  try {
    return normalizeAnalytics(JSON.parse(fs.readFileSync(ANALYTICS_FILE, "utf-8")));
  } catch (error) {
    console.error("Falha ao ler analytics:", error.message);
    return getDefaultAnalytics();
  }
}

function saveAnalytics(entries) {
  const normalized = normalizeAnalytics(entries);
  if (shouldUseDatabase()) analyticsRepository.saveAnalytics(normalized);
  if (shouldWriteLegacyJson()) fs.writeFileSync(ANALYTICS_FILE, JSON.stringify(normalized, null, 2));
  broadcastDataChanged("analytics");
}

function invalidateAnalyticsCache() {
  analyticsSummaryCache = null;
}

function cleanOldAnalytics(entries) {
  const cutoff = Date.now() - ANALYTICS_RETENTION_MS;
  let changed = false;
  const dateFields = {
    uploads: "uploadedAt",
    downloads: "downloadedAt",
    logins: "loginAt",
    deletions: "deletedAt",
    approvals: "approvedAt",
    rejections: "rejectedAt",
    restores: "restoredAt",
    versionDeletions: "deletedAt",
  };

  for (const [key, field] of Object.entries(dateFields)) {
    const current = entries[key] || [];
    const filtered = current.filter((item) => {
      const time = new Date(item?.[field]).getTime();
      return Number.isFinite(time) && time >= cutoff;
    });
    if (filtered.length !== current.length) {
      entries[key] = filtered;
      changed = true;
    }
  }

  return changed;
}

function logAnalyticsEvent(type, payload = {}) {
  try {
    const entries = loadAnalytics();
    const now = new Date().toISOString();

    if (type === "upload") {
      entries.uploads.push({
        filename: payload.filename,
        uploadedBy: payload.uploadedBy,
        uploadedAt: payload.uploadedAt || now,
        size: Number(payload.size) || 0,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
        approved: false,
      });
    } else if (type === "approval") {
      const target = [...entries.uploads].reverse().find((item) => (
        item.filename === payload.filename &&
        (item.folderId || ROOT_FOLDER_ID) === (payload.folderId || ROOT_FOLDER_ID) &&
        !item.approved
      ));
      if (target) {
        target.approved = true;
        target.approvedBy = payload.approvedBy;
        target.approvedAt = payload.approvedAt || now;
      }
      entries.approvals.push({
        filename: payload.filename,
        approvedBy: payload.approvedBy,
        approvedAt: payload.approvedAt || now,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
      });
    } else if (type === "rejection") {
      entries.rejections.push({
        filename: payload.filename,
        rejectedBy: payload.rejectedBy,
        rejectedAt: payload.rejectedAt || now,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
      });
    } else if (type === "download") {
      entries.downloads.push({
        filename: payload.filename,
        downloadedBy: payload.downloadedBy,
        downloadedAt: payload.downloadedAt || now,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
      });
    } else if (type === "login") {
      entries.logins.push({
        username: payload.username,
        loginAt: payload.loginAt || now,
        ip: payload.ip || "",
      });
    } else if (type === "deletion") {
      entries.deletions.push({
        filename: payload.filename,
        deletedBy: payload.deletedBy,
        deletedAt: payload.deletedAt || now,
        size: Number(payload.size) || 0,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
      });
    } else if (type === "restore") {
      entries.restores.push({
        filename: payload.filename,
        restoredBy: payload.restoredBy,
        restoredAt: payload.restoredAt || now,
        restoredVersion: payload.restoredVersion,
        newVersion: payload.newVersion,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
      });
    } else if (type === "versionDeletion") {
      entries.versionDeletions.push({
        filename: payload.filename,
        deletedBy: payload.deletedBy,
        deletedAt: payload.deletedAt || now,
        version: payload.version,
        folderId: payload.folderId || ROOT_FOLDER_ID,
        folderName: payload.folderName || "",
      });
    }

    cleanOldAnalytics(entries);
    saveAnalytics(entries);
    invalidateAnalyticsCache();
  } catch (error) {
    console.error("Falha ao registrar analytics:", error.message);
  }
}

function loadPublicLinks() {
  if (shouldUseDatabase()) {
    try {
      const entries = publicLinksRepository.loadPublicLinks();
      if (Object.keys(entries).length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler links publicos do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return {};
    }
  }
  if (!fs.existsSync(PUBLIC_LINKS_FILE)) return {};
  return JSON.parse(fs.readFileSync(PUBLIC_LINKS_FILE, "utf-8"));
}

function savePublicLinks(entries) {
  if (shouldUseDatabase()) publicLinksRepository.savePublicLinks(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(PUBLIC_LINKS_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("shares");
}

function incrementPublicLinkViews(shareToken, link, links) {
  if (shouldUseDatabase()) {
    const updatedViews = publicLinksRepository.incrementPublicLinkViews(shareToken, link);
    if (updatedViews !== null) {
      broadcastDataChanged("shares");
      if (shouldWriteLegacyJson() && links) {
        links[shareToken].views = updatedViews;
        fs.writeFileSync(PUBLIC_LINKS_FILE, JSON.stringify(links, null, 2));
      }
      return updatedViews;
    }
  }

  link.views = (Number(link.views) || 0) + 1;
  savePublicLinks(links);
  return link.views;
}

function loadActionHistory() {
  if (shouldUseDatabase()) {
    try {
      const entries = actionHistoryRepository.loadActionHistory();
      if (entries.length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler historico do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return [];
    }
  }
  if (!fs.existsSync(ACTION_HISTORY_FILE)) return [];

  try {
    const entries = JSON.parse(fs.readFileSync(ACTION_HISTORY_FILE, "utf-8"));
    return Array.isArray(entries) ? entries : [];
  } catch (error) {
    console.error("Falha ao ler historico de acoes:", error.message);
    return [];
  }
}

function saveActionHistory(entries) {
  if (shouldUseDatabase()) actionHistoryRepository.saveActionHistory(entries);
  if (shouldWriteLegacyJson()) fs.writeFileSync(ACTION_HISTORY_FILE, JSON.stringify(entries, null, 2));
  broadcastDataChanged("history");
}

const AUDIT_EVENTS = {
  "auth.login.success": { severity: "info" },
  "auth.login.failed": { severity: "warning" },
  "auth.login.blocked": { severity: "warning" },
  "auth.login.rate_limited": { severity: "warning" },
  "auth.token.invalid": { severity: "warning" },
  "file.upload": { severity: "info" },
  "upload.scan.clean": { severity: "info" },
  "upload.scan.failed": { severity: "warning" },
  "upload.scan.infected": { severity: "critical" },
  "upload.scan.suspicious": { severity: "warning" },
  "upload.quarantined": { severity: "warning" },
  "quarantine.deleted": { severity: "critical" },
  "file.download": { severity: "info" },
  "file.delete": { severity: "warning" },
  "file.approve": { severity: "info" },
  "file.reject": { severity: "info" },
  "file.rename": { severity: "info" },
  "file.move": { severity: "info" },
  "file.access.denied": { severity: "warning" },
  "file.version.restore": { severity: "warning" },
  "file.version.delete": { severity: "warning" },
  "share.created": { severity: "info" },
  "share.opened": { severity: "info" },
  "share.password.failed": { severity: "warning" },
  "share.downloaded": { severity: "info" },
  "share.expired": { severity: "info" },
  "share.limit_reached": { severity: "warning" },
  "user.created": { severity: "info" },
  "user.updated": { severity: "info" },
  "user.deleted": { severity: "critical" },
  "user.permission.changed": { severity: "critical" },
  "user.password.changed": { severity: "warning" },
  "folder.created": { severity: "info" },
  "folder.deleted": { severity: "warning" },
  "folder.access.changed": { severity: "critical" },
  "system.startup": { severity: "info" },
  "system.error": { severity: "error" },
  "system.anomaly.detected": { severity: "warning" },
  "backup.created": { severity: "info" },
  "backup.failed": { severity: "error" },
  "backup.deleted": { severity: "warning" },
  "backup.downloaded": { severity: "info" },
  "backup.restore.started": { severity: "critical" },
  "backup.restore.completed": { severity: "critical" },
  "backup.restore.failed": { severity: "error" },
  "trash.file.moved": { severity: "warning" },
  "trash.folder.moved": { severity: "warning" },
  "trash.file.restored": { severity: "info" },
  "trash.folder.restored": { severity: "info" },
  "trash.file.permanently_deleted": { severity: "critical" },
  "trash.folder.permanently_deleted": { severity: "critical" },
  "trash.emptied": { severity: "critical" },
  "trash.restore.failed": { severity: "error" },
  "trash.delete.failed": { severity: "error" },
};

function getDefaultAuditLogs() {
  return { logs: [] };
}

function sanitizeAuditValue(value, maxLength = 500) {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") return value.replace(/[\r\n\t]/g, " ").slice(0, maxLength);
  if (typeof value === "number" || typeof value === "boolean") return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => sanitizeAuditValue(item, maxLength));
  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => !/password|token|secret|authorization/i.test(key))
        .map(([key, item]) => [sanitizeAuditValue(key, 100), sanitizeAuditValue(item, maxLength)])
    );
  }
  return String(value).slice(0, maxLength);
}

function loadAuditLogs(file = AUDIT_LOGS_FILE) {
  if (shouldUseDatabase() && file === AUDIT_LOGS_FILE) {
    try {
      const entries = auditRepository.loadAuditLogs();
      if (entries.logs.length || !shouldReadJsonFallback()) return entries;
    } catch (error) {
      console.error("Falha ao ler auditoria do SQLite:", error.message);
      if (!shouldReadJsonFallback()) return getDefaultAuditLogs();
    }
  }
  if (!fs.existsSync(file)) return getDefaultAuditLogs();
  try {
    const entries = JSON.parse(fs.readFileSync(file, "utf-8"));
    return { logs: Array.isArray(entries?.logs) ? entries.logs : [] };
  } catch (error) {
    console.error("Falha ao ler audit logs:", error.message);
    return getDefaultAuditLogs();
  }
}

function saveAuditLogs(entries, file = AUDIT_LOGS_FILE) {
  const normalized = { logs: Array.isArray(entries?.logs) ? entries.logs : [] };
  if (shouldUseDatabase() && file === AUDIT_LOGS_FILE) auditRepository.saveAuditLogs(normalized);
  if (file !== AUDIT_LOGS_FILE || shouldWriteLegacyJson()) {
    fs.writeFileSync(file, JSON.stringify(normalized, null, 2));
  }
  if (file === AUDIT_LOGS_FILE) broadcastDataChanged("audit");
}

function getAuditActor(req, fallbackUsername = "system") {
  const forwardedFor = String(req?.headers?.["x-forwarded-for"] || "")
    .split(",")
    .map((ip) => ip.trim())
    .filter(Boolean);
  const rawIp =
    req?.headers?.["cf-connecting-ip"] ||
    req?.headers?.["x-real-ip"] ||
    forwardedFor[0] ||
    req?.ip ||
    req?.socket?.remoteAddress ||
    null;
  const ip = rawIp === "::1" || rawIp === "::ffff:127.0.0.1" ? "127.0.0.1" : rawIp;

  return {
    username: req?.user?.username || fallbackUsername || "system",
    role: req?.user?.role || null,
    ip,
    userAgent: req?.headers?.["user-agent"] || null,
  };
}

function getSafeWebDavAuditPath(req) {
  try {
    const pathname = new URL(req.originalUrl || req.url || WEBDAV_PATH, "http://localhost").pathname;
    return pathname.startsWith(WEBDAV_PATH) ? pathname : WEBDAV_PATH;
  } catch {
    return WEBDAV_PATH;
  }
}

function sendWebDavUnauthorized(req, res, reason = "invalid_credentials") {
  res.setHeader("WWW-Authenticate", 'Basic realm="Root.ark WebDAV", charset="UTF-8"');
  auditLog(
    "webdav.login.failed",
    getAuditActor(req, "anonymous"),
    { type: "webdav", id: WEBDAV_PATH },
    "authenticate",
    "failure",
    { reason, method: req.method, path: getSafeWebDavAuditPath(req) }
  );
  res.status(401).send("Authentication required");
  return false;
}

function authenticateWebDavRequest(req, res) {
  const header = String(req.headers.authorization || "");
  if (!header.toLowerCase().startsWith("basic ")) {
    return sendWebDavUnauthorized(req, res, "missing_basic_auth");
  }

  let username = "";
  let password = "";
  try {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf-8");
    const separator = decoded.indexOf(":");
    if (separator === -1) return sendWebDavUnauthorized(req, res, "malformed_basic_auth");
    username = decoded.slice(0, separator).trim();
    password = decoded.slice(separator + 1);
  } catch {
    return sendWebDavUnauthorized(req, res, "malformed_basic_auth");
  }

  const user = loadUsers().find((entry) => sameUsername(entry.username, username));
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return sendWebDavUnauthorized(req, res, "invalid_credentials");
  }

  req.user = {
    username: user.username,
    role: user.role,
    permissions: normalizeUserPermissions(user),
  };
  return true;
}

function parseWebDavSegments(req) {
  const pathname = new URL(req.originalUrl || req.url || WEBDAV_PATH, "http://localhost").pathname;
  if (!isWebDavRequestPath(pathname)) return null;

  const suffix = pathname.slice(WEBDAV_PATH.length).replace(/^\/+|\/+$/g, "");
  if (!suffix) return [];

  return suffix.split("/").map((segment) => {
    let decoded = segment;
    for (let index = 0; index < 3; index += 1) {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    }
    if (
      !decoded ||
      decoded === "." ||
      decoded === ".." ||
      decoded.includes("/") ||
      decoded.includes("\\") ||
      decoded.includes("\0")
    ) {
      throw new Error("Caminho WebDAV invalido");
    }
    return decoded;
  });
}

function archiveAuditLogs(logs) {
  if (!logs.length) return;
  const archive = loadAuditLogs(AUDIT_ARCHIVE_FILE);
  archive.logs.push(...logs);
  saveAuditLogs(archive, AUDIT_ARCHIVE_FILE);
}

function appendAuditLog(log) {
  const entries = loadAuditLogs();
  const cutoff = Date.now() - AUDIT_RETENTION_MS;
  const retained = entries.logs.filter((entry) => {
    const time = new Date(entry.timestamp).getTime();
    return Number.isFinite(time) && time >= cutoff;
  });

  retained.push(log);
  if (retained.length > MAX_AUDIT_LOGS) {
    archiveAuditLogs(retained.slice(0, retained.length - MAX_AUDIT_LOGS));
    entries.logs = retained.slice(-MAX_AUDIT_LOGS);
  } else {
    entries.logs = retained;
  }

  saveAuditLogs(entries);
}

function auditLog(eventType, actor, target, action, result, details = {}) {
  const log = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    eventType: sanitizeAuditValue(eventType, 120),
    severity: AUDIT_EVENTS[eventType]?.severity || "info",
    actor: sanitizeAuditValue({
      username: actor?.username || "system",
      role: actor?.role || null,
      ip: actor?.ip || null,
      userAgent: actor?.userAgent || null,
    }),
    target: target ? sanitizeAuditValue(target) : null,
    action: sanitizeAuditValue(action, 120),
    result: result === "failure" || result === "partial" ? result : "success",
    details: sanitizeAuditValue(details),
  };

  appendAuditLog(log);
  if (log.severity === "critical" || log.severity === "error") {
    console.error(`[AUDIT ${log.severity.toUpperCase()}]`, log);
  }
  return log.id;
}

function addActionHistory(action, fileName, actor, details = {}) {
  try {
    const entries = loadActionHistory();

    entries.unshift({
      id: crypto.randomUUID(),
      action,
      fileName,
      actor: actor || "sistema",
      timestamp: new Date().toISOString(),
      details,
    });

    saveActionHistory(entries.slice(0, MAX_ACTION_HISTORY_ENTRIES));
  } catch (error) {
    console.error("Falha ao registrar historico de acoes:", error.message);
  }
}

function cleanupExpiredPublicLinks(entries = loadPublicLinks()) {
  const now = Date.now();
  let changed = false;

  for (const [token, link] of Object.entries(entries)) {
    const expiresAt = new Date(link.expiresAt).getTime();
    const maxViews = Number(link.maxViews) || 0;
    const views = Number(link.views) || 0;
    const activeViewers = cleanupShareViewers(link, now);
    if (activeViewers.changed) changed = true;

    if (
      !Number.isFinite(expiresAt) ||
      expiresAt <= now ||
      (maxViews > 0 && views >= maxViews && Object.keys(activeViewers.viewers).length === 0)
    ) {
      delete entries[token];
      changed = true;
    }
  }

  if (changed) savePublicLinks(entries);
  return entries;
}

function removePublicLinksForFile(fileName, folderId = null) {
  const entries = loadPublicLinks();
  let changed = false;

  for (const [token, link] of Object.entries(entries)) {
    const sameFolder = !folderId || (link.folderId || ROOT_FOLDER_ID) === folderId;
    if (link.fileName === fileName && sameFolder) {
      delete entries[token];
      changed = true;
    }
  }

  if (changed) savePublicLinks(entries);
}

function renamePublicLinksForFile(oldName, newName, folderId = null) {
  const entries = loadPublicLinks();
  let changed = false;

  for (const link of Object.values(entries)) {
    const sameFolder = !folderId || (link.folderId || ROOT_FOLDER_ID) === folderId;
    if (link.fileName === oldName && sameFolder) {
      link.fileName = newName;
      changed = true;
    }
  }

  if (changed) savePublicLinks(entries);
}

function movePublicLinksForFile(oldName, newName, fromFolderId, toFolderId) {
  const entries = loadPublicLinks();
  let changed = false;

  for (const link of Object.values(entries)) {
    if (link.fileName === oldName && (link.folderId || ROOT_FOLDER_ID) === fromFolderId) {
      link.fileName = newName;
      link.folderId = toFolderId;
      changed = true;
    }
  }

  if (changed) savePublicLinks(entries);
}

function removePublicLinksForFolder(folderId) {
  const entries = loadPublicLinks();
  let changed = false;

  for (const [token, link] of Object.entries(entries)) {
    if ((link.folderId || ROOT_FOLDER_ID) === folderId) {
      delete entries[token];
      changed = true;
    }
  }

  if (changed) savePublicLinks(entries);
}

function getShareExpirationMinutes(rawValue) {
  const minutes = Number(rawValue);
  if (!Number.isFinite(minutes)) return null;

  const rounded = Math.floor(minutes);
  if (rounded < 1 || rounded > MAX_SHARE_EXPIRATION_MINUTES) return null;

  return rounded;
}

function getShareMaxViews(rawValue) {
  const views = Number(rawValue);
  if (!Number.isFinite(views)) return 0;

  const rounded = Math.floor(views);
  if (rounded < 0 || rounded > MAX_SHARE_VIEWS) return null;

  return rounded;
}

function getShareMaxDownloads(rawValue) {
  const downloads = Number(rawValue);
  if (!Number.isFinite(downloads)) return 0;

  const rounded = Math.floor(downloads);
  if (rounded < 0 || rounded > MAX_SHARE_DOWNLOADS) return null;

  return rounded;
}

function getSharePasswordHash(password) {
  const value = typeof password === "string" ? password.trim() : "";
  if (!value) return null;
  if (value.length < 4 || value.length > 128) return undefined;
  return bcrypt.hashSync(value, 10);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function hasSharePassword(link) {
  return Boolean(link?.passwordHash || link?.password_hash);
}

function getSharePasswordCookieName(token) {
  return `rootark_share_pwd_${token}`;
}

function setSharePasswordCookie(req, res, token) {
  res.cookie(getSharePasswordCookieName(token), "ok", {
    httpOnly: true,
    sameSite: "lax",
    secure: req.secure || req.get("x-forwarded-proto") === "https",
    maxAge: 1000 * 60 * 60,
  });
}

function hasValidSharePasswordSession(req, token, link) {
  if (!hasSharePassword(link)) return true;
  return getCookieValue(req, getSharePasswordCookieName(token)) === "ok";
}

function getShareFailurePage(message = "Este link nao esta disponivel.") {
  const safeMessage = escapeHtml(message);
  return `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <title>Root.ark - Link indisponivel</title>
    <style>
      body{min-height:100vh;margin:0;display:grid;place-items:center;background:#020202;color:#fff;font-family:Arial,sans-serif}
      .card{width:min(460px,calc(100% - 32px));padding:26px;border:1px solid #044879;border-radius:18px;background:#111012;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,.45)}
      h1{margin:0 0 10px;font-size:2rem} p{color:#b8b8b8;line-height:1.5}
    </style>
  </head>
  <body><main class="card"><h1>ROOT.ark</h1><p>${safeMessage}</p></main></body>
</html>`;
}

function getTemporaryExpiresAt(rawValue) {
  if (rawValue === null || rawValue === undefined || rawValue === "" || rawValue === false) {
    return null;
  }

  const date = new Date(rawValue);
  const timestamp = date.getTime();
  const now = Date.now();

  if (!Number.isFinite(timestamp) || timestamp <= now || timestamp - now > MAX_TEMPORARY_EXPIRATION_MS) {
    return undefined;
  }

  return date.toISOString();
}

function getTemporaryExpirationFromBody(body = {}) {
  if (body.temporary === false || body.expiresAt === null) return null;
  if (body.expiresAt !== undefined) return getTemporaryExpiresAt(body.expiresAt);

  const amount = Number(body.durationAmount);
  const unit = String(body.durationUnit || "").toLowerCase();
  if (body.durationAmount === undefined && body.durationUnit === undefined) return null;
  if (!Number.isFinite(amount) || amount <= 0) return undefined;

  const multiplier = unit.startsWith("day") || unit === "dias" || unit === "dia"
    ? 24 * 60 * 60 * 1000
    : 60 * 60 * 1000;
  const durationMs = Math.floor(amount) * multiplier;

  if (durationMs <= 0 || durationMs > MAX_TEMPORARY_EXPIRATION_MS) return undefined;
  return new Date(Date.now() + durationMs).toISOString();
}

function cleanupShareViewers(link, now = Date.now()) {
  const viewers = link.activeViewers && typeof link.activeViewers === "object" ? link.activeViewers : {};
  let changed = false;

  for (const [viewerId, viewer] of Object.entries(viewers)) {
    const expiresAt = new Date(viewer?.expiresAt).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt <= now) {
      delete viewers[viewerId];
      changed = true;
    }
  }

  link.activeViewers = viewers;
  return { viewers, changed };
}

function getCookieValue(req, name) {
  const cookies = String(req.headers.cookie || "").split(";");

  for (const cookie of cookies) {
    const [rawKey, ...rawValue] = cookie.trim().split("=");
    if (rawKey === name) {
      return decodeURIComponent(rawValue.join("="));
    }
  }

  return "";
}

function setShareViewerCookie(req, res, token, viewerId, expiresAt) {
  const maxAge = Math.max(1, Math.min(SHARE_VIEW_SESSION_MS, expiresAt - Date.now()));
  res.cookie(`rootark_share_${token}`, viewerId, {
    httpOnly: true,
    sameSite: "lax",
    secure: req.secure || req.get("x-forwarded-proto") === "https",
    maxAge,
  });
}

function renderPublicSharePage(token) {
  const safeToken = String(token).replace(/[^a-f0-9]/gi, "");

  return `<!doctype html>
<html lang="pt-BR">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex, nofollow, noarchive" />
    <meta property="og:title" content="Root.ark - Compartilhamento" />
    <meta property="og:description" content="Acesse um arquivo compartilhado com segurança pelo Root.ark." />
    <title>Root.ark - Compartilhamento</title>
    <style>
      :root {
        --blue: #044879;
        --blue-soft: #60a0ce;
        --panel: #111012;
        --muted: #b8b8b8;
      }

      * { box-sizing: border-box; }

      body {
        min-height: 100vh;
        margin: 0;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
        background: #020202;
        color: white;
        font-family: Arial, sans-serif;
      }

      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background:
          radial-gradient(circle at 50% 0%, rgba(4, 72, 121, 0.35), transparent 34%),
          linear-gradient(180deg, rgba(4, 72, 121, 0.18), transparent 44%),
          #020202;
        pointer-events: none;
      }

      .card {
        position: relative;
        z-index: 1;
        width: min(760px, 100%);
        padding: 26px;
        border: 1px solid var(--blue);
        border-radius: 20px;
        background: rgba(17, 16, 18, 0.94);
        box-shadow: 0 28px 90px rgba(0, 0, 0, 0.55);
      }

      .brand {
        text-align: center;
        margin-bottom: 22px;
      }

      .brand h1 {
        margin: 0;
        font-size: clamp(2.2rem, 8vw, 4rem);
        letter-spacing: -0.08em;
      }

      .brand span {
        display: inline-block;
        background: var(--blue);
        border-radius: 14px;
        padding: 0 8px;
        letter-spacing: -0.06em;
      }

      .file-box {
        border: 1px solid rgba(4, 72, 121, 0.8);
        border-radius: 16px;
        padding: 18px;
        background: rgba(2, 2, 2, 0.42);
      }

      h2 {
        margin: 0 0 8px;
        overflow-wrap: anywhere;
      }

      p {
        color: var(--muted);
        line-height: 1.5;
      }

      .meta {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin: 14px 0;
      }

      .pill {
        border: 1px solid rgba(96, 160, 206, 0.55);
        color: var(--blue-soft);
        border-radius: 999px;
        padding: 6px 10px;
        font-size: 0.85rem;
      }

      .actions {
        display: flex;
        flex-wrap: wrap;
        gap: 10px;
        margin-top: 18px;
      }

      button, a {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        min-height: 42px;
        padding: 10px 14px;
        border-radius: 10px;
        border: 1px solid var(--blue);
        background: transparent;
        color: var(--blue-soft);
        cursor: pointer;
        text-decoration: none;
        font-weight: 700;
      }

      .primary {
        background: var(--blue);
        color: white;
      }

      input {
        width: 100%;
        margin-top: 10px;
        padding: 12px;
        border-radius: 10px;
        border: 1px solid var(--blue);
        background: rgba(17, 16, 18, 0.9);
        color: white;
      }

      .hidden { display: none !important; }

      .preview {
        margin-top: 18px;
        border: 1px solid rgba(4, 72, 121, 0.7);
        border-radius: 14px;
        overflow: hidden;
        min-height: 220px;
        background: #050505;
      }

      .preview iframe,
      .preview video,
      .preview audio,
      .preview img {
        width: 100%;
        max-height: 520px;
        border: 0;
        display: block;
      }

      .preview audio { margin: 40px auto; width: calc(100% - 36px); }

      .qr {
        margin-top: 16px;
        display: grid;
        place-items: center;
      }

      .qr img {
        width: 172px;
        height: 172px;
        border-radius: 14px;
        background: white;
        padding: 8px;
      }

      .status {
        min-height: 22px;
      }

      button:disabled {
        opacity: .5;
        cursor: not-allowed;
      }

      @media (max-width: 560px) {
        body { padding: 14px; }
        .card { padding: 18px; }
        .actions { flex-direction: column; }
        button, a { width: 100%; }
      }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="brand">
        <h1>ROOT<span>.ark</span></h1>
        <p>Compartilhamento publico seguro</p>
      </div>
      <section class="file-box">
        <h2 id="fileName">Validando link...</h2>
        <p class="status" id="status">Aguarde um instante.</p>

        <div id="passwordBox" class="hidden">
          <p>Este link esta protegido. Digite a senha para continuar.</p>
          <input type="password" id="sharePassword" placeholder="Senha do link" autocomplete="current-password" />
          <div class="actions">
            <button type="button" class="primary" id="passwordButton">Acessar</button>
          </div>
        </div>

        <div id="contentBox" class="hidden">
          <div class="meta" id="meta"></div>
          <div class="actions">
            <a class="primary" id="downloadButton" href="/share/${safeToken}/download">Download</a>
            <button type="button" id="previewButton">Preview</button>
            <button type="button" id="copyButton">Copiar link</button>
            <button type="button" id="qrButton">QR Code</button>
          </div>
          <div class="preview hidden" id="previewBox"></div>
          <div class="qr hidden" id="qrBox"></div>
        </div>
      </section>
    </main>
    <script>
      const token = "${safeToken}";
      const fileName = document.getElementById("fileName");
      const status = document.getElementById("status");
      const passwordBox = document.getElementById("passwordBox");
      const contentBox = document.getElementById("contentBox");
      const passwordInput = document.getElementById("sharePassword");
      const passwordButton = document.getElementById("passwordButton");
      const meta = document.getElementById("meta");
      const previewButton = document.getElementById("previewButton");
      const previewBox = document.getElementById("previewBox");
      const qrButton = document.getElementById("qrButton");
      const qrBox = document.getElementById("qrBox");
      const copyButton = document.getElementById("copyButton");

      function formatSize(bytes) {
        const size = Number(bytes) || 0;
        if (size < 1024) return size + " B";
        if (size < 1024 * 1024) return Math.round(size / 1024) + " KB";
        if (size < 1024 * 1024 * 1024) return (size / 1024 / 1024).toFixed(1) + " MB";
        return (size / 1024 / 1024 / 1024).toFixed(1) + " GB";
      }

      function renderAccess(data) {
        passwordBox.classList.add("hidden");
        contentBox.classList.remove("hidden");
        fileName.textContent = data.fileName || "Arquivo compartilhado";
        status.textContent = "Link valido ate " + new Date(data.expiresAt).toLocaleString("pt-BR") + ".";
        meta.innerHTML = [
          data.fileType ? '<span class="pill">' + data.fileType + '</span>' : "",
          '<span class="pill">' + formatSize(data.size) + '</span>',
          data.remainingViews !== null ? '<span class="pill">' + data.remainingViews + ' visualizacoes restantes</span>' : '<span class="pill">Visualizacoes ilimitadas</span>',
          data.remainingDownloads !== null ? '<span class="pill">' + data.remainingDownloads + ' downloads restantes</span>' : '<span class="pill">Downloads ilimitados</span>'
        ].filter(Boolean).join("");
        previewButton.hidden = !data.canPreview;
      }

      async function accessShare(password = "") {
        status.textContent = "Validando link...";
        const response = await fetch("/share/" + token + "/password", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password })
        });
        const data = await response.json().catch(() => ({}));

        if (response.status === 401 && data.passwordRequired) {
          fileName.textContent = "Link protegido";
          status.textContent = "Informe a senha para continuar.";
          passwordBox.classList.remove("hidden");
          contentBox.classList.add("hidden");
          return;
        }

        if (!response.ok) {
          fileName.textContent = "Link indisponivel";
          status.textContent = data.error || "Nao foi possivel acessar este compartilhamento.";
          passwordBox.classList.add("hidden");
          contentBox.classList.add("hidden");
          return;
        }

        renderAccess(data);
      }

      passwordButton.addEventListener("click", () => accessShare(passwordInput.value));
      passwordInput.addEventListener("keydown", (event) => {
        if (event.key === "Enter") accessShare(passwordInput.value);
      });

      previewButton.addEventListener("click", () => {
        previewBox.classList.toggle("hidden");
        if (!previewBox.dataset.loaded) {
          previewBox.innerHTML = '<iframe src="/share/' + token + '/preview" title="Preview"></iframe>';
          previewBox.dataset.loaded = "1";
        }
      });

      qrButton.addEventListener("click", () => {
        qrBox.classList.toggle("hidden");
        if (!qrBox.dataset.loaded) {
          qrBox.innerHTML = '<img alt="QR Code do link" src="/share/' + token + '/qr" />';
          qrBox.dataset.loaded = "1";
        }
      });

      copyButton.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(window.location.href);
          status.textContent = "Link copiado.";
        } catch {
          status.textContent = "Nao foi possivel copiar automaticamente.";
        }
      });

      accessShare();
    </script>
  </body>
</html>`;
}
function buildPublicShareUrl(req, token) {
  return `${req.protocol}://${req.get("host")}/share/${token}`;
}

function getShareAuditActor(req) {
  return getAuditActor({ ...req, user: { username: "public", role: "public" } }, "public");
}

function logShareAudit(req, eventType, token, link, action, result, details = {}) {
  auditLog(
    eventType,
    getShareAuditActor(req),
    { type: "public_link", id: token },
    action,
    result,
    {
      fileName: link?.fileName || null,
      folderId: link?.folderId || ROOT_FOLDER_ID,
      ...details,
    }
  );
}

function getShareFileInfo(link) {
  const folderId = link.folderId || ROOT_FOLDER_ID;
  const fileName = path.basename(link.fileName || "");
  if (!fileName || fileName !== link.fileName) return null;

  const filePath = path.join(getFolderStoragePath("./uploads", folderId), fileName);
  return { folderId, fileName, filePath };
}

async function ensureShareFileAvailable(link) {
  const info = getShareFileInfo(link);
  if (!info) return null;
  if (isFileInTrash(info.folderId, info.fileName)) return null;
  await ensureCloudFileCached(info.folderId, info.fileName, info.filePath, "uploads");
  if (!isExistingFile(info.filePath)) return null;
  if (getEncryptedFileMetadata(info.folderId, info.fileName)) return null;
  return info;
}

function getPublicShareTypeLabel(fileName) {
  const extension = path.extname(fileName || "").replace(".", "").toUpperCase();
  return extension || "Arquivo";
}

function getPublicShareCanPreview(fileName) {
  return ["image", "pdf", "audio", "video"].includes(getPreviewKind(fileName));
}

function isShareViewerActive(req, token, link) {
  const { viewers } = cleanupShareViewers(link);
  const viewerId = getCookieValue(req, `rootark_share_${token}`);
  return Boolean(viewerId && viewers[viewerId]);
}

function createShareViewer(req, res, token, link, expiresAt) {
  const { viewers } = cleanupShareViewers(link);
  const viewerId = crypto.randomBytes(16).toString("hex");
  viewers[viewerId] = {
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Math.min(Date.now() + SHARE_VIEW_SESSION_MS, expiresAt)).toISOString(),
  };
  link.activeViewers = viewers;
  setShareViewerCookie(req, res, token, viewerId, expiresAt);
}

function getShareLimitState(link) {
  const maxViews = Number(link.maxViews) || 0;
  const views = Number(link.views) || 0;
  const maxDownloads = Number(link.maxDownloads) || 0;
  const downloads = Number(link.downloads) || 0;

  return {
    maxViews,
    views,
    maxDownloads,
    downloads,
    remainingViews: maxViews > 0 ? Math.max(0, maxViews - views) : null,
    remainingDownloads: maxDownloads > 0 ? Math.max(0, maxDownloads - downloads) : null,
  };
}

function validateShareToken(rawToken) {
  const token = String(rawToken || "");
  return /^[a-f0-9]{48}$/i.test(token) ? token : "";
}

function getShareAccessCookieRequired(link) {
  return hasSharePassword(link) || (Number(link.maxViews) || 0) > 0;
}

async function resolveShareAccess(req, res, token, options = {}) {
  const links = loadPublicLinks();
  const link = links[token];
  if (!link) return { status: 404, error: "Link indisponivel." };

  const expiresAt = new Date(link.expiresAt).getTime();
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    delete links[token];
    savePublicLinks(links);
    logShareAudit(req, "share.expired", token, link, "expired", "failure");
    return { status: 410, error: "Link indisponivel." };
  }

  const passwordHash = link.passwordHash || link.password_hash || null;
  if (passwordHash && !hasValidSharePasswordSession(req, token, link)) {
    if (!options.password) return { status: 401, error: "Senha obrigatoria.", passwordRequired: true };
    if (!bcrypt.compareSync(String(options.password), passwordHash)) {
      logShareAudit(req, "share.password.failed", token, link, "password", "failure");
      return { status: 401, error: "Nao foi possivel acessar este link.", passwordRequired: true };
    }
    setSharePasswordCookie(req, res, token);
  }

  const limits = getShareLimitState(link);
  const viewerAlreadyActive = isShareViewerActive(req, token, link);
  if (options.countView && !viewerAlreadyActive && limits.maxViews > 0 && limits.views >= limits.maxViews) {
    logShareAudit(req, "share.limit_reached", token, link, "view", "failure", { limit: "views" });
    return { status: 410, error: "Link indisponivel." };
  }

  if (options.requireViewer && getShareAccessCookieRequired(link) && !viewerAlreadyActive && !options.countView) {
    return { status: 403, error: "Abra a pagina do compartilhamento novamente." };
  }

  if (options.countDownload && limits.maxDownloads > 0 && limits.downloads >= limits.maxDownloads) {
    logShareAudit(req, "share.limit_reached", token, link, "download", "failure", { limit: "downloads" });
    return { status: 410, error: "Link indisponivel." };
  }

  const fileInfo = await ensureShareFileAvailable(link);
  if (!fileInfo) return { status: 404, error: "Link indisponivel." };

  if (options.countView && !viewerAlreadyActive) {
    createShareViewer(req, res, token, link, expiresAt);
    link.lastViewedAt = new Date().toISOString();
    link.views = incrementPublicLinkViews(token, link, links);
    logShareAudit(req, "share.opened", token, link, "opened", "success");
  } else {
    const cleaned = cleanupShareViewers(link);
    if (cleaned.changed) savePublicLinks(links);
  }

  if (options.countDownload) {
    link.downloads = (Number(link.downloads) || 0) + 1;
    link.lastDownloadedAt = new Date().toISOString();
    links[token] = link;
    savePublicLinks(links);
    logShareAudit(req, "share.downloaded", token, link, "downloaded", "success");
  }

  return { link, fileInfo, limits: getShareLimitState(link), expiresAt };
}

function getSharePublicPayload(link, fileInfo, limits) {
  const stats = fs.statSync(fileInfo.filePath);
  return {
    fileName: fileInfo.fileName,
    fileType: getPublicShareTypeLabel(fileInfo.fileName),
    size: stats.size,
    expiresAt: link.expiresAt,
    views: Number(link.views) || 0,
    maxViews: Number(link.maxViews) || 0,
    downloads: Number(link.downloads) || 0,
    maxDownloads: Number(link.maxDownloads) || 0,
    remainingViews: limits.remainingViews,
    remainingDownloads: limits.remainingDownloads,
    canPreview: getPublicShareCanPreview(fileInfo.fileName),
  };
}

function getFolderById(folderId = ROOT_FOLDER_ID) {
  return loadFolders().find((folder) => folder.id === folderId) || null;
}

function hasFolderAccess(req, folder) {
  if (!folder) return false;
  if (folder.isRoot || folder.id === ROOT_FOLDER_ID) return true;
  if (req.user?.role === "admin" || req.user?.permissions?.manageUsers) return true;
  if (folder.createdBy === req.user?.username) return true;
  if (groupsStore?.isMember(req.user?.username, folder.groupIds)) return true;
  const access = normalizeFolderAccessEntry(folder).users[req.user?.username];
  return Boolean(access?.read) || Boolean(access?.edit);
}

function canManageAccess(req) {
  return req.user?.role === "admin" || req.user?.permissions?.manageUsers;
}

function sameUsername(left, right) {
  return String(left || "").trim().toLowerCase() === String(right || "").trim().toLowerCase();
}

function canViewAnalytics(req) {
  return canManageAccess(req) || Boolean(req.user?.permissions?.viewAnalytics);
}

function canViewAuditLogs(req) {
  return canManageAccess(req) || Boolean(req.user?.permissions?.viewAuditLogs);
}

function canManageBackups(req) {
  return canManageAccess(req) || Boolean(req.user?.permissions?.manageBackups);
}

function canManageTrash(req) {
  return canManageAccess(req) || Boolean(req.user?.permissions?.manageTrash);
}

function canMoveToTrash(req) {
  return canManageAccess(req) || Boolean(req.user?.permissions?.delete);
}

function requireAnalyticsAccess(req, res, next) {
  if (!canViewAnalytics(req)) {
    return res.status(403).json({ error: "Permissao negada: viewAnalytics" });
  }

  next();
}

function requireAuditAccess(req, res, next) {
  if (!canViewAuditLogs(req)) {
    auditLog("file.access.denied", getAuditActor(req), { type: "audit", id: req.path }, "read", "failure", {
      reason: "missing_viewAuditLogs",
    });
    return res.status(403).json({ error: "Permissao negada: viewAuditLogs" });
  }

  next();
}

function requireBackupAccess(req, res, next) {
  if (!canManageBackups(req)) {
    return res.status(403).json({ error: "Permissao negada: manageBackups" });
  }
  next();
}

function requireTrashManageAccess(req, res, next) {
  if (!canManageTrash(req)) {
    return res.status(403).json({ error: "Permissao negada: manageTrash" });
  }
  next();
}

function canCreateFolders(req) {
  return canManageAccess(req) || Boolean(req.user?.permissions?.createFolders);
}

function hasFolderEditAccess(req, folder) {
  if (!folder || folder.isRoot || folder.id === ROOT_FOLDER_ID) return false;
  if (canManageAccess(req)) return true;
  if (folder.createdBy === req.user?.username) return true;
  return Boolean(normalizeFolderAccessEntry(folder).users[req.user?.username]?.edit);
}

function serializeFolderForUser(req, folder) {
  const access = normalizeFolderAccessEntry(folder);
  return {
    ...folder,
    owner: access.owner,
    users: access.users,
    allowedUsers: Object.entries(access.users)
      .filter(([, permission]) => permission.read || permission.edit)
      .map(([username]) => username),
    canEdit: hasFolderEditAccess(req, folder),
    canManageAccess: canManageAccess(req) || hasFolderEditAccess(req, folder),
  };
}

function normalizeAccessUsers(rawUsers = {}, legacyAllowedUsers = []) {
  const users = {};

  if (rawUsers && typeof rawUsers === "object" && !Array.isArray(rawUsers)) {
    for (const [username, access] of Object.entries(rawUsers)) {
      const cleanUsername = String(username || "").trim();
      if (!cleanUsername) continue;

      const canEdit = Boolean(access?.edit);
      const canRead = Boolean(access?.read) || canEdit;
      if (canRead || canEdit) {
        users[cleanUsername] = { read: canRead, edit: canEdit };
      }
    }
  }

  for (const username of legacyAllowedUsers) {
    users[username] = {
      read: true,
      edit: Boolean(users[username]?.edit),
    };
  }

  return users;
}

function normalizeFolderAccessEntry(folder = {}) {
  return {
    owner: folder.createdBy || "sistema",
    users: normalizeAccessUsers(folder.users, normalizeAllowedUsers(folder.allowedUsers)),
  };
}

function getFilePermissionKey(folderId, fileName) {
  return `${folderId || ROOT_FOLDER_ID}/${path.basename(fileName || "")}`;
}

function getFileExpirationKey(folderId, fileName) {
  return `${folderId || ROOT_FOLDER_ID}/${path.basename(fileName || "")}`;
}

function getFileExpirationEntry(folderId, fileName, entries = loadFileExpirations()) {
  return entries[getFileExpirationKey(folderId, fileName)] || null;
}

function getFileVersionKey(folderId, fileName) {
  return `${folderId || ROOT_FOLDER_ID}/${path.basename(fileName || "")}`;
}

function getEncryptedFileKey(folderId, fileName) {
  return `${folderId || ROOT_FOLDER_ID}/${path.basename(fileName || "")}`;
}

function getEncryptedFileMetadata(folderId, fileName, entries = loadEncryptedFiles()) {
  const name = path.basename(fileName || "");
  const key = getEncryptedFileKey(folderId, name);
  if (entries[key]) return entries[key];
  if (entries[name]) return entries[name];

  for (const [entryKey, entry] of Object.entries(entries || {})) {
    const entryName = path.basename(entry?.fileName || entry?.originalFilename || entryKey);
    const entryFolderId = entry?.folderId || (String(entryKey).includes("/") ? String(entryKey).split("/")[0] : ROOT_FOLDER_ID);
    if (entryName === name && entryFolderId === (folderId || ROOT_FOLDER_ID)) {
      return entry;
    }
  }

  return null;
}

function getStoredVersionName(fileName, version) {
  return `${path.basename(fileName || "")}.v${version}`;
}

function normalizeVersionHistory(entry) {
  const versions = Array.isArray(entry?.versions)
    ? entry.versions
        .map((version) => ({
          version: Number(version.version),
          storedAs: path.basename(version.storedAs || ""),
          uploadedBy: version.uploadedBy || "sistema",
          uploadedAt: version.uploadedAt || new Date().toISOString(),
          size: Number(version.size) || 0,
          comment: version.comment || "",
        }))
        .filter((version) => Number.isInteger(version.version) && version.version > 0 && version.storedAs)
    : [];
  const highestVersion = versions.reduce((max, version) => Math.max(max, version.version), 0);

  return {
    currentVersion: Number(entry?.currentVersion) || highestVersion || 0,
    versions,
  };
}

function getVersionHistory(folderId, fileName, entries = loadFileVersions()) {
  return normalizeVersionHistory(entries[getFileVersionKey(folderId, fileName)]);
}

function ensureVersionHistory(folder, fileName, uploadedBy = "sistema", comment = "Versao inicial") {
  const entries = loadFileVersions();
  const key = getFileVersionKey(folder.id, fileName);
  const history = normalizeVersionHistory(entries[key]);

  if (history.currentVersion && history.versions.length) {
    return { entries, key, history };
  }

  const currentPath = path.join(folder.uploadDir, fileName);
  if (!isExistingFile(currentPath)) {
    return { entries, key, history: { currentVersion: 0, versions: [] } };
  }

  const stats = fs.statSync(currentPath);
  const createdHistory = {
    currentVersion: 1,
    versions: [{
      version: 1,
      storedAs: fileName,
      uploadedBy,
      uploadedAt: stats.birthtime?.toISOString?.() || new Date().toISOString(),
      size: stats.size,
      comment,
    }],
  };

  entries[key] = createdHistory;
  saveFileVersions(entries);
  return { entries, key, history: createdHistory };
}

function pruneFileVersions(entries, key, folder) {
  const history = normalizeVersionHistory(entries[key]);
  let changed = false;

  while (history.versions.length > MAX_FILE_VERSIONS) {
    const removable = history.versions
      .filter((version) => version.version !== history.currentVersion)
      .sort((a, b) => a.version - b.version)[0];

    if (!removable) break;

    const storedPath = path.join(folder.uploadDir, removable.storedAs);
    if (removable.storedAs && removable.storedAs !== path.basename(key) && fs.existsSync(storedPath)) {
      fs.unlinkSync(storedPath);
    }
    if (removable.storedAs) deleteCloudFileLater(folder.id, removable.storedAs, "uploads");

    history.versions = history.versions.filter((version) => version.version !== removable.version);
    changed = true;
  }

  if (changed) entries[key] = history;
}

function recordApprovedFileVersion(folder, fileName, pendingPath, uploadedBy, comment = "") {
  const currentPath = path.join(folder.uploadDir, fileName);
  const exists = isExistingFile(currentPath);
  const initialComment = comment || "Versao inicial";

  if (!exists) {
    fs.renameSync(pendingPath, currentPath);
    ensureVersionHistory(folder, fileName, uploadedBy || "sistema", initialComment);
    return { currentVersion: 1, replaced: false };
  }

  const currentOwner = normalizeFilePermissionEntry(getFilePermissionEntry(folder.id, fileName)).owner;
  const { entries, key, history } = ensureVersionHistory(folder, fileName, currentOwner, "Versao inicial");
  const oldCurrentVersion = history.currentVersion || 1;
  const archivedName = getStoredVersionName(fileName, oldCurrentVersion);
  const archivedPath = path.join(folder.uploadDir, archivedName);

  fs.renameSync(currentPath, archivedPath);
  for (const version of history.versions) {
    if (version.version === oldCurrentVersion) {
      version.storedAs = archivedName;
      version.size = fs.statSync(archivedPath).size;
    }
  }

  fs.renameSync(pendingPath, currentPath);
  const stats = fs.statSync(currentPath);
  const newVersion = oldCurrentVersion + 1;
  history.currentVersion = newVersion;
  history.versions.push({
    version: newVersion,
    storedAs: fileName,
    uploadedBy: uploadedBy || "sistema",
    uploadedAt: new Date().toISOString(),
    size: stats.size,
    comment: comment || "",
  });

  entries[key] = history;
  pruneFileVersions(entries, key, folder);
  saveFileVersions(entries);
  return { currentVersion: newVersion, replaced: true };
}

function syncFileVersionsToCloud(folderId, fileName) {
  const folder = {
    id: folderId || ROOT_FOLDER_ID,
    uploadDir: getFolderStoragePath("./uploads", folderId || ROOT_FOLDER_ID),
  };
  const history = getVersionHistory(folder.id, fileName);
  const storedNames = new Set([
    path.basename(fileName || ""),
    ...history.versions.map((version) => path.basename(version.storedAs || "")).filter(Boolean),
  ]);

  for (const storedName of storedNames) {
    const storedPath = path.join(folder.uploadDir, storedName);
    if (isExistingFile(storedPath)) {
      syncCloudFireAndForget(uploadFileToCloud(storedPath, folder.id, storedName, "uploads"), `sync version ${folder.id}/${storedName}`);
    }
  }
}

function getVersionFilePath(folder, fileName, versionNumber) {
  const history = getVersionHistory(folder.id, fileName);
  const version = history.versions.find((item) => item.version === Number(versionNumber));
  if (!version) return null;

  return {
    history,
    version,
    filePath: path.join(folder.uploadDir, version.storedAs),
  };
}

function isStoredVersionFile(folderId, fileName, entries = loadFileVersions()) {
  const name = path.basename(fileName || "");

  for (const [key, value] of Object.entries(entries)) {
    if (!key.startsWith(`${folderId || ROOT_FOLDER_ID}/`)) continue;
    const primaryName = path.basename(key);
    if (name === primaryName) continue;

    const history = normalizeVersionHistory(value);
    if (history.versions.some((version) => version.storedAs === name && version.version !== history.currentVersion)) {
      return true;
    }
  }

  return false;
}

function removeFileVersions(folderId, fileName) {
  const entries = loadFileVersions();
  const key = getFileVersionKey(folderId, fileName);
  const history = normalizeVersionHistory(entries[key]);
  const uploadDir = getFolderStoragePath("./uploads", folderId);

  for (const version of history.versions) {
    if (version.storedAs && version.storedAs !== fileName) {
      fs.rmSync(path.join(uploadDir, version.storedAs), { force: true });
      deleteCloudFileLater(folderId, version.storedAs, "uploads");
    }
  }

  if (entries[key]) {
    delete entries[key];
    saveFileVersions(entries);
  }
}

function getActionHistoryForFile(folderId, fileName, limit = 80) {
  const targetFolderId = folderId || ROOT_FOLDER_ID;
  const targetName = path.basename(fileName || "");

  if (!targetName) return [];

  return loadActionHistory()
    .filter((entry) => {
      const details = entry.details || {};
      const entryFolderId = details.folderId || details.toFolderId || details.fromFolderId || ROOT_FOLDER_ID;
      const sameFolder = entryFolderId === targetFolderId ||
        details.toFolderId === targetFolderId ||
        details.fromFolderId === targetFolderId;
      const names = [
        entry.fileName,
        details.oldName,
        details.newName,
        details.originalName,
      ].filter(Boolean).map((name) => path.basename(String(name)));

      return sameFolder && names.includes(targetName);
    })
    .slice(0, limit);
}

function renameFileVersions(folderId, oldName, newName) {
  const entries = loadFileVersions();
  const oldKey = getFileVersionKey(folderId, oldName);
  const newKey = getFileVersionKey(folderId, newName);
  const history = normalizeVersionHistory(entries[oldKey]);
  if (!entries[oldKey]) return;

  const uploadDir = getFolderStoragePath("./uploads", folderId);
  for (const version of history.versions) {
    const nextStoredAs = version.version === history.currentVersion
      ? newName
      : getStoredVersionName(newName, version.version);

    if (version.storedAs !== oldName && version.storedAs !== nextStoredAs) {
      const oldVersionPath = path.join(uploadDir, version.storedAs);
      const newVersionPath = path.join(uploadDir, nextStoredAs);
      if (fs.existsSync(oldVersionPath)) fs.renameSync(oldVersionPath, newVersionPath);
    }

    version.storedAs = nextStoredAs;
  }

  entries[newKey] = history;
  delete entries[oldKey];
  saveFileVersions(entries);
}

function moveFileVersions(oldFolderId, oldName, newFolderId, newName) {
  const entries = loadFileVersions();
  const oldKey = getFileVersionKey(oldFolderId, oldName);
  const newKey = getFileVersionKey(newFolderId, newName);
  const history = normalizeVersionHistory(entries[oldKey]);
  if (!entries[oldKey]) return;

  const oldUploadDir = getFolderStoragePath("./uploads", oldFolderId);
  const newUploadDir = getFolderStoragePath("./uploads", newFolderId);
  if (!fs.existsSync(newUploadDir)) fs.mkdirSync(newUploadDir, { recursive: true });

  for (const version of history.versions) {
    const nextStoredAs = version.version === history.currentVersion
      ? newName
      : getStoredVersionName(newName, version.version);

    if (version.storedAs !== oldName) {
      const oldVersionPath = path.join(oldUploadDir, version.storedAs);
      const newVersionPath = path.join(newUploadDir, nextStoredAs);
      if (fs.existsSync(oldVersionPath)) fs.renameSync(oldVersionPath, newVersionPath);
    }

    version.storedAs = nextStoredAs;
  }

  entries[newKey] = history;
  delete entries[oldKey];
  saveFileVersions(entries);
}

function removeFileVersionsForFolder(folderId) {
  const entries = loadFileVersions();
  let changed = false;

  for (const key of Object.keys(entries)) {
    if (entries[key]?.folderId === folderId || key.startsWith(`${folderId}/`)) {
      delete entries[key];
      changed = true;
    }
  }

  if (changed) saveFileVersions(entries);
}

function cleanupOpenFileTokens() {
  const now = Date.now();

  for (const [token, entry] of openFileTokens.entries()) {
    if (!entry?.expiresAt || entry.expiresAt <= now) {
      openFileTokens.delete(token);
    }
  }
}

function createOpenFileToken(folderId, fileName, options = {}) {
  cleanupOpenFileTokens();
  const token = crypto.randomBytes(24).toString("hex");
  openFileTokens.set(token, {
    folderId,
    fileName,
    filePath: options.filePath || null,
    downloadName: options.downloadName || fileName,
    cloudFileName: options.cloudFileName || path.basename(options.filePath || fileName),
    expiresAt: Date.now() + OPEN_FILE_TOKEN_TTL_MS,
  });
  return token;
}

function getFileContentDisposition(fileName, dispositionType = "inline") {
  const fallbackName = path.basename(fileName || "arquivo")
    .replace(/[^\x20-\x7E]/g, "_")
    .replace(/["\\]/g, "_");
  const safeDisposition = dispositionType === "attachment" ? "attachment" : "inline";

  return `${safeDisposition}; filename="${fallbackName}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

function getMimeType(fileName) {
  const extension = path.extname(fileName || "").toLowerCase();
  const types = {
    ".txt": "text/plain; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".bmp": "image/bmp",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".m4v": "video/mp4",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".m4a": "audio/mp4",
    ".flac": "audio/flac",
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".cjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".htm": "text/html; charset=utf-8",
    ".md": "text/markdown; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".yml": "text/yaml; charset=utf-8",
    ".yaml": "text/yaml; charset=utf-8",
    ".zip": "application/zip",
    ".exe": "application/octet-stream",
    ".msi": "application/octet-stream",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  };

  return types[extension] || "application/octet-stream";
}

function getPreviewKind(fileName) {
  const extension = path.extname(fileName || "").toLowerCase();
  if ([".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp"].includes(extension)) return "image";
  if (extension === ".pdf") return "pdf";
  if ([".mp3", ".wav", ".ogg", ".oga", ".flac", ".m4a"].includes(extension)) return "audio";
  if ([".mp4", ".webm", ".mov", ".m4v"].includes(extension)) return "video";
  if ([".doc", ".docx"].includes(extension)) return "document";
  if ([
    ".txt", ".json", ".js", ".mjs", ".cjs", ".css", ".html", ".htm", ".md", ".csv",
    ".xml", ".yml", ".yaml", ".log", ".ini", ".env", ".sql", ".sh", ".bat", ".ps1",
    ".py", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".php", ".rb", ".go", ".rs",
    ".ts", ".tsx", ".jsx",
  ].includes(extension)) return "text";
  return "unsupported";
}

function isInlinePreviewFile(fileName) {
  return ["image", "pdf", "audio", "video"].includes(getPreviewKind(fileName));
}

function getServerMasterKey(options = {}) {
  const createIfMissing = options.createIfMissing !== false;
  const envKey = process.env.SERVER_MASTER_KEY;
  if (envKey) {
    const cleanKey = envKey.trim();
    if (/^[a-f0-9]{64}$/i.test(cleanKey)) return Buffer.from(cleanKey, "hex");
    const decoded = Buffer.from(cleanKey, "base64");
    if (decoded.length === 32) return decoded;
    throw new Error("SERVER_MASTER_KEY precisa ter 32 bytes em hex ou base64");
  }

  if (!fs.existsSync(SERVER_MASTER_KEY_FILE)) {
    if (!createIfMissing) throw new Error("SERVER_MASTER_KEY ausente");
    const masterKey = crypto.randomBytes(32);
    fs.writeFileSync(SERVER_MASTER_KEY_FILE, masterKey.toString("hex"), { mode: 0o600 });
    console.warn("[security] Nova chave mestra gerada em data/server-master.key. Faca backup seguro imediatamente.");
    return masterKey;
  }

  const fileKey = fs.readFileSync(SERVER_MASTER_KEY_FILE, "utf-8").trim();
  if (!/^[a-f0-9]{64}$/i.test(fileKey)) throw new Error("SERVER_MASTER_KEY invalida");
  return Buffer.from(fileKey, "hex");
}

function deriveKeyFromPassword(password, salt = null) {
  const effectiveSalt = salt || crypto.randomBytes(16);
  return {
    key: crypto.pbkdf2Sync(String(password || ""), effectiveSalt, ENCRYPTION_ITERATIONS, 32, "sha256"),
    salt: effectiveSalt,
  };
}

function getUserEncryptionKey(username) {
  const serverSecret = getServerMasterKey();
  const userSalt = crypto.createHash("sha256").update(`${username || "sistema"}:rootark-user-key`).digest();
  return crypto.pbkdf2Sync(serverSecret, userSalt, ENCRYPTION_ITERATIONS, 32, "sha256");
}

function encryptBuffer(buffer, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { encrypted, iv, authTag: cipher.getAuthTag() };
}

function decryptBuffer(buffer, key, iv, authTag) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(iv, "hex"));
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  return Buffer.concat([decipher.update(buffer), decipher.final()]);
}

function resolveEncryptionKeys(level, req, password, metadata = null) {
  const owner = metadata?.accessControl?.owner || metadata?.uploadedBy || req.user?.username;
  if (level === "server-key") return [{ key: getServerMasterKey(), type: "server" }];
  if (level === "user-key") return [{ key: getUserEncryptionKey(owner), type: "user" }];
  if (level === "password") {
    if (!password || String(password).length < 8) throw new Error("Senha obrigatoria com no minimo 8 caracteres");
    const salt = metadata?.salt ? Buffer.from(metadata.salt, "hex") : null;
    const derived = deriveKeyFromPassword(password, salt);
    return [{ key: derived.key, type: "password", salt: derived.salt }];
  }
  if (level === "dual") {
    if (!password || String(password).length < 8) throw new Error("Senha obrigatoria com no minimo 8 caracteres");
    const salt = metadata?.salt ? Buffer.from(metadata.salt, "hex") : null;
    const derived = deriveKeyFromPassword(password, salt);
    return [
      { key: getServerMasterKey(), type: "server" },
      { key: derived.key, type: "password", salt: derived.salt },
    ];
  }
  return [];
}

function encryptFileInPlace(filePath, options) {
  const level = options.encryptionLevel || "none";
  if (level === "none") return null;
  if (!ENCRYPTION_LEVELS[level]) throw new Error("Nivel de criptografia invalido");
  const expiresInDays = options.expiresInDays ? Number(options.expiresInDays) : null;
  if (options.expiresInDays && (!Number.isFinite(expiresInDays) || expiresInDays <= 0 || expiresInDays > 365)) {
    throw new Error("Expiracao criptografada invalida");
  }

  let buffer = fs.readFileSync(filePath);
  const layers = [];
  const keys = resolveEncryptionKeys(level, options.req, options.password);

  for (const layer of keys) {
    const encrypted = encryptBuffer(buffer, layer.key);
    buffer = encrypted.encrypted;
    layers.push({
      type: layer.type,
      iv: encrypted.iv.toString("hex"),
      authTag: encrypted.authTag.toString("hex"),
    });
    if (layer.salt) layers[layers.length - 1].salt = layer.salt.toString("hex");
  }

  fs.writeFileSync(filePath, buffer);
  return {
    originalFilename: options.originalName,
    fileName: options.fileName,
    folderId: options.folderId,
    uploadedBy: options.req.user.username,
    uploadedAt: new Date().toISOString(),
    size: options.originalSize,
    encryptedSize: buffer.length,
    encryptionLevel: level,
    algorithm: "aes-256-gcm",
    keyDerivation: level === "password" || level === "dual" ? "pbkdf2" : null,
    iterations: level === "password" || level === "dual" ? ENCRYPTION_ITERATIONS : null,
    salt: layers.find((layer) => layer.salt)?.salt || null,
    layers,
    accessControl: {
      owner: options.req.user.username,
      authorizedUsers: [options.req.user.username],
      requiresPassword: level === "password" || level === "dual",
      expiresAt: expiresInDays ? new Date(Date.now() + expiresInDays * 24 * 60 * 60 * 1000).toISOString() : null,
    },
    metadata: {
      mimeType: options.mimeType || getMimeType(options.originalName),
      isEncrypted: true,
      canPreview: false,
    },
  };
}

function decryptEncryptedFileBuffer(encryptedBuffer, metadata, req, password) {
  let buffer = encryptedBuffer;
  const layers = Array.isArray(metadata.layers) ? metadata.layers.slice().reverse() : [];

  for (const layer of layers) {
    let key;
    if (layer.type === "server") key = getServerMasterKey();
    if (layer.type === "user") key = getUserEncryptionKey(metadata.accessControl?.owner || metadata.uploadedBy);
    if (layer.type === "password") {
      if (!password) throw new Error("Senha obrigatoria");
      key = deriveKeyFromPassword(password, Buffer.from(layer.salt || metadata.salt, "hex")).key;
    }
    if (!key) throw new Error("Camada de criptografia invalida");
    buffer = decryptBuffer(buffer, key, layer.iv, layer.authTag);
  }

  return buffer;
}

function getEncryptedAuthorizedUsers(metadata) {
  const users = new Set(metadata?.accessControl?.authorizedUsers || []);
  const owner = metadata?.accessControl?.owner || metadata?.uploadedBy;
  if (owner) users.add(owner);
  return users;
}

function canAccessEncryptedFile(req, metadata) {
  if (!metadata) return true;
  if (req.user?.role === "admin") return true;

  const level = metadata.encryptionLevel || "server-key";
  if (level === "server-key" || level === "password") {
    return true;
  }

  if (level === "user-key" || level === "dual") {
    return Array.from(getEncryptedAuthorizedUsers(metadata)).some((username) => sameUsername(username, req.user?.username));
  }

  return false;
}

function saveEncryptedMetadata(folderId, fileName, metadata) {
  const entries = loadEncryptedFiles();
  entries[getEncryptedFileKey(folderId, fileName)] = metadata;
  saveEncryptedFiles(entries);
}

function promoteEncryptedMetadataAfterApproval(folderId, fileName, uploadedBy) {
  const entries = loadEncryptedFiles();
  const name = path.basename(fileName || "");
  const exactKey = getEncryptedFileKey(folderId, name);
  const legacyKeys = [exactKey, name];
  let metadata = null;

  for (const key of legacyKeys) {
    if (entries[key]) {
      metadata = entries[key];
      break;
    }
  }

  if (!metadata) {
    for (const [key, entry] of Object.entries(entries)) {
      const entryName = path.basename(entry?.fileName || entry?.originalFilename || key);
      const entryFolderId = entry?.folderId || (String(key).includes("/") ? String(key).split("/")[0] : ROOT_FOLDER_ID);
      if (entryName === name && entryFolderId === (folderId || ROOT_FOLDER_ID)) {
        metadata = entry;
        break;
      }
    }
  }

  if (!metadata) return null;

  const owner = metadata.accessControl?.owner || metadata.uploadedBy || uploadedBy || "sistema";
  const authorizedUsers = new Set(metadata.accessControl?.authorizedUsers || []);
  if (owner) authorizedUsers.add(owner);
  if (uploadedBy) authorizedUsers.add(uploadedBy);

  const promoted = {
    ...metadata,
    folderId: folderId || ROOT_FOLDER_ID,
    fileName: name,
    accessControl: {
      ...(metadata.accessControl || {}),
      owner,
      authorizedUsers: Array.from(authorizedUsers),
    },
    updatedAt: new Date().toISOString(),
  };

  for (const key of Object.keys(entries)) {
    const entry = entries[key];
    const entryName = path.basename(entry?.fileName || entry?.originalFilename || key);
    const entryFolderId = entry?.folderId || (String(key).includes("/") ? String(key).split("/")[0] : ROOT_FOLDER_ID);
    if ((key === name || key === exactKey || entryName === name) && entryFolderId === (folderId || ROOT_FOLDER_ID)) {
      delete entries[key];
    }
  }

  entries[exactKey] = promoted;
  saveEncryptedFiles(entries);
  return promoted;
}

function removeEncryptedMetadata(folderId, fileName) {
  const entries = loadEncryptedFiles();
  const key = getEncryptedFileKey(folderId, fileName);
  if (!entries[key]) return;
  delete entries[key];
  saveEncryptedFiles(entries);
}

function renameEncryptedMetadata(folderId, oldName, newName) {
  const entries = loadEncryptedFiles();
  const oldKey = getEncryptedFileKey(folderId, oldName);
  const newKey = getEncryptedFileKey(folderId, newName);
  if (!entries[oldKey]) return;
  entries[newKey] = { ...entries[oldKey], fileName: newName };
  delete entries[oldKey];
  saveEncryptedFiles(entries);
}

function moveEncryptedMetadata(oldFolderId, oldName, newFolderId, newName) {
  const entries = loadEncryptedFiles();
  const oldKey = getEncryptedFileKey(oldFolderId, oldName);
  const newKey = getEncryptedFileKey(newFolderId, newName);
  if (!entries[oldKey]) return;
  entries[newKey] = { ...entries[oldKey], folderId: newFolderId, fileName: newName };
  delete entries[oldKey];
  saveEncryptedFiles(entries);
}

function removeEncryptedMetadataForFolder(folderId) {
  const entries = loadEncryptedFiles();
  let changed = false;
  for (const key of Object.keys(entries)) {
    if (entries[key]?.folderId === folderId || key.startsWith(`${folderId}/`)) {
      delete entries[key];
      changed = true;
    }
  }
  if (changed) saveEncryptedFiles(entries);
}

function getPublicEncryptionMetadata(metadata) {
  if (!metadata) return null;
  return {
    isEncrypted: true,
    encryptionLevel: metadata.encryptionLevel,
    originalFilename: metadata.originalFilename,
    requiresPassword: Boolean(metadata.accessControl?.requiresPassword),
    expiresAt: metadata.accessControl?.expiresAt || null,
    canPreview: false,
    owner: metadata.accessControl?.owner || metadata.uploadedBy,
  };
}

function parseRangeHeader(rangeHeader, size) {
  if (!rangeHeader || !String(rangeHeader).startsWith("bytes=")) return null;

  const range = String(rangeHeader).replace("bytes=", "").split(",")[0].trim();
  const [rawStart, rawEnd] = range.split("-");
  let start;
  let end;

  if (rawStart === "") {
    const suffixLength = Number(rawEnd);
    if (!Number.isInteger(suffixLength) || suffixLength <= 0) return null;
    start = Math.max(size - suffixLength, 0);
    end = size - 1;
  } else {
    start = Number(rawStart);
    end = rawEnd ? Number(rawEnd) : size - 1;
  }

  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    end < start ||
    start >= size
  ) {
    return { invalid: true };
  }

  return {
    start,
    end: Math.min(end, size - 1),
  };
}

function sendOptimizedFile(req, res, filePath, downloadName, dispositionType = "inline", options = {}) {
  const stats = fs.statSync(filePath);
  const size = stats.size;
  const safeName = path.basename(downloadName || path.basename(filePath));
  const range = parseRangeHeader(req.headers.range, size);
  const cacheControl = options.cacheControl || "private, max-age=3600";
  const highWaterMark = Number(options.highWaterMark) || 1024 * 1024;

  if (range?.invalid) {
    res.writeHead(416, {
      "Content-Range": `bytes */${size}`,
      "Accept-Ranges": "bytes",
    });
    res.end();
    return;
  }

  const commonHeaders = {
    "Accept-Ranges": "bytes",
    "Cache-Control": cacheControl,
    "Content-Type": options.contentType || getMimeType(safeName),
    "Content-Disposition": getFileContentDisposition(safeName, dispositionType),
    "X-Content-Type-Options": "nosniff",
  };

  const streamOptions = { highWaterMark };
  let statusCode = 200;
  let headers = {
    ...commonHeaders,
    "Content-Length": size,
  };

  if (range) {
    statusCode = 206;
    streamOptions.start = range.start;
    streamOptions.end = range.end;
    headers = {
      ...commonHeaders,
      "Content-Range": `bytes ${range.start}-${range.end}/${size}`,
      "Content-Length": range.end - range.start + 1,
    };
  }

  res.writeHead(statusCode, headers);
  const stream = fs.createReadStream(filePath, streamOptions);

  stream.on("error", (error) => {
    console.error("Erro ao transmitir arquivo:", error.message);
    if (!res.headersSent) res.status(500).end("Erro ao transmitir arquivo");
    else res.destroy(error);
  });

  req.on("close", () => {
    if (!res.writableEnded) stream.destroy();
  });

  stream.pipe(res);
}

function removeFileExpiration(folderId, fileName) {
  const entries = loadFileExpirations();
  const key = getFileExpirationKey(folderId, fileName);
  if (!entries[key]) return;

  delete entries[key];
  saveFileExpirations(entries);
}

function renameFileExpiration(folderId, oldName, newName) {
  const entries = loadFileExpirations();
  const oldKey = getFileExpirationKey(folderId, oldName);
  const newKey = getFileExpirationKey(folderId, newName);
  if (!entries[oldKey]) return;

  entries[newKey] = {
    ...entries[oldKey],
    folderId,
    fileName: newName,
    updatedAt: new Date().toISOString(),
  };
  delete entries[oldKey];
  saveFileExpirations(entries);
}

function moveFileExpiration(oldFolderId, oldName, newFolderId, newName) {
  const entries = loadFileExpirations();
  const oldKey = getFileExpirationKey(oldFolderId, oldName);
  const newKey = getFileExpirationKey(newFolderId, newName);
  if (!entries[oldKey]) return;

  entries[newKey] = {
    ...entries[oldKey],
    folderId: newFolderId,
    fileName: newName,
    updatedAt: new Date().toISOString(),
  };
  delete entries[oldKey];
  saveFileExpirations(entries);
}

function removeFileExpirationsForFolder(folderId) {
  const entries = loadFileExpirations();
  let changed = false;

  for (const key of Object.keys(entries)) {
    if (entries[key]?.folderId === folderId || key.startsWith(`${folderId}/`)) {
      delete entries[key];
      changed = true;
    }
  }

  if (changed) saveFileExpirations(entries);
}

function getFilePermissionEntry(folderId, fileName, entries = loadFilePermissions()) {
  return entries[getFilePermissionKey(folderId, fileName)] || null;
}

function normalizeFilePermissionEntry(entry) {
  const legacyAllowedUsers = normalizeAllowedUsers(entry?.allowedUsers);
  const rawUsers = entry?.users && typeof entry.users === "object" ? entry.users : {};
  const users = {};

  for (const [username, access] of Object.entries(rawUsers)) {
    const cleanUsername = String(username || "").trim();
    if (!cleanUsername) continue;

    const canEdit = Boolean(access?.edit);
    const canRead = Boolean(access?.read) || canEdit;
    if (canRead || canEdit) {
      users[cleanUsername] = { read: canRead, edit: canEdit };
    }
  }

  for (const username of legacyAllowedUsers) {
    users[username] = { read: true, edit: Boolean(users[username]?.edit) };
  }

  return {
    public: entry ? Boolean(entry.public) : true,
    owner: entry?.owner || "sistema",
    users,
  };
}

function getFolderEligibleUsers(folder) {
  const users = loadUsers().map(({ password, ...user }) => user);

  if (folder.isRoot || folder.id === ROOT_FOLDER_ID) {
    return users;
  }

  const folderUsers = normalizeFolderAccessEntry(folder).users;

  return users.filter((user) => (
    user.role === "admin" ||
    user.permissions?.manageUsers ||
    folder.createdBy === user.username ||
    groupsStore?.isMember(user.username, folder.groupIds) ||
    Boolean(folderUsers[user.username]?.read) ||
    Boolean(folderUsers[user.username]?.edit)
  ));
}

function normalizeFolderGroupIds(value, allowMissing = true) {
  if (value === undefined && allowMissing) return undefined;
  if (!groupsStore) return null;
  return groupsStore?.validateIds(value);
}

function hasFileAccess(req, folder, fileName, entries = loadFilePermissions()) {
  if (!hasFolderAccess(req, folder)) return false;
  if (canManageAccess(req)) return true;

  const entry = getFilePermissionEntry(folder.id, fileName, entries);
  const permissions = normalizeFilePermissionEntry(entry);
  const userAccess = permissions.users[req.user?.username];

  return (
    permissions.public ||
    sameUsername(permissions.owner, req.user?.username) ||
    Boolean(userAccess?.read) ||
    Boolean(userAccess?.edit)
  );
}

function hasFileEditAccess(req, folder, fileName, entries = loadFilePermissions()) {
  if (!hasFolderAccess(req, folder)) return false;
  if (canManageAccess(req)) return true;

  const entry = getFilePermissionEntry(folder.id, fileName, entries);
  if (!entry) return Boolean(req.user?.permissions?.delete);

  const permissions = normalizeFilePermissionEntry(entry);
  if (sameUsername(permissions.owner, req.user?.username)) return true;
  if (permissions.public && Object.keys(permissions.users).length === 0) {
    return Boolean(req.user?.permissions?.delete);
  }

  return Boolean(permissions.users[req.user?.username]?.edit);
}

function hasReadableFolderAccess(req, folder) {
  return hasFolderAccess(req, folder);
}

function getReadableFolderOrRespond(req, res, rawFolderId = ROOT_FOLDER_ID) {
  const folderId = String(rawFolderId || ROOT_FOLDER_ID);
  const folder = getFolderById(folderId);

  if (!folder) {
    res.status(404).json({ error: "Pasta nao encontrada" });
    return null;
  }

  if (!hasReadableFolderAccess(req, folder)) {
    res.status(403).json({ error: "Acesso negado a esta pasta" });
    return null;
  }

  const paths = ensureFolderDirectories(folder.id);
  return { ...folder, ...paths };
}

function removeFilePermission(folderId, fileName) {
  const entries = loadFilePermissions();
  const key = getFilePermissionKey(folderId, fileName);
  if (!entries[key]) return;

  delete entries[key];
  saveFilePermissions(entries);
}

function renameFilePermission(folderId, oldName, newName) {
  const entries = loadFilePermissions();
  const oldKey = getFilePermissionKey(folderId, oldName);
  const newKey = getFilePermissionKey(folderId, newName);
  if (!entries[oldKey]) return;

  entries[newKey] = {
    ...entries[oldKey],
    folderId,
    fileName: newName,
    updatedAt: new Date().toISOString(),
  };
  delete entries[oldKey];
  saveFilePermissions(entries);
}

function moveFilePermission(oldFolderId, oldName, newFolderId, newName) {
  const entries = loadFilePermissions();
  const oldKey = getFilePermissionKey(oldFolderId, oldName);
  const newKey = getFilePermissionKey(newFolderId, newName);
  if (!entries[oldKey]) return;

  entries[newKey] = {
    ...entries[oldKey],
    folderId: newFolderId,
    fileName: newName,
    updatedAt: new Date().toISOString(),
  };
  delete entries[oldKey];
  saveFilePermissions(entries);
}

function setFileOwner(folderId, fileName, owner) {
  if (!owner) return;

  const entries = loadFilePermissions();
  const key = getFilePermissionKey(folderId, fileName);
  const current = normalizeFilePermissionEntry(entries[key]);

  entries[key] = {
    folderId,
    fileName,
    owner,
    public: current.public,
    users: current.users,
    updatedAt: new Date().toISOString(),
    updatedBy: "sistema",
  };

  saveFilePermissions(entries);
}

function removeFilePermissionsForFolder(folderId) {
  const entries = loadFilePermissions();
  let changed = false;

  for (const key of Object.keys(entries)) {
    if (entries[key]?.folderId === folderId || key.startsWith(`${folderId}/`)) {
      delete entries[key];
      changed = true;
    }
  }

  if (changed) saveFilePermissions(entries);
}

function removeUserFromFilePermissions(username) {
  const entries = loadFilePermissions();
  let changed = false;

  for (const entry of Object.values(entries)) {
    if (Array.isArray(entry.allowedUsers)) {
      const nextUsers = entry.allowedUsers.filter((user) => user !== username);
      if (nextUsers.length !== entry.allowedUsers.length) {
        entry.allowedUsers = nextUsers;
        changed = true;
      }
    }

    if (entry.users && typeof entry.users === "object" && entry.users[username]) {
      delete entry.users[username];
      entry.updatedAt = new Date().toISOString();
      changed = true;
    }
  }

  if (changed) saveFilePermissions(entries);
}

function removeUserFromFolderPermissions(username) {
  const folders = loadFolders();
  let changed = false;

  for (const folder of folders) {
    if (Array.isArray(folder.allowedUsers)) {
      const nextUsers = folder.allowedUsers.filter((user) => user !== username);
      if (nextUsers.length !== folder.allowedUsers.length) {
        folder.allowedUsers = nextUsers;
        changed = true;
      }
    }

    if (folder.users && typeof folder.users === "object" && folder.users[username]) {
      delete folder.users[username];
      folder.updatedAt = new Date().toISOString();
      changed = true;
    }
  }

  if (changed) saveFolders(folders);
}

function deleteFolderContents(folder) {
  const folderId = folder.id;
  const uploadDir = getFolderStoragePath("./uploads", folderId);
  const tempDir = getFolderStoragePath("./temp", folderId);

  if (!isSafeFolderChildPath("./uploads", uploadDir) || !isSafeFolderChildPath("./temp", tempDir)) {
    throw new Error("Caminho de pasta invalido");
  }

  removePendingEntriesForFolder(folderId);
  removePublicLinksForFolder(folderId);
  removeFilePermissionsForFolder(folderId);
  removeFileExpirationsForFolder(folderId);
  removeFileVersionsForFolder(folderId);
  removeEncryptedMetadataForFolder(folderId);
  fs.rmSync(uploadDir, { recursive: true, force: true });
  fs.rmSync(tempDir, { recursive: true, force: true });
  deleteCloudFolderLater(folderId);
}

function shouldAutoCleanupTrash() {
  return String(process.env.TRASH_AUTO_CLEANUP_ENABLED || "false").toLowerCase() === "true";
}

function isTrashEnabled() {
  return String(process.env.TRASH_ENABLED || "true").toLowerCase() !== "false";
}

function getTrashRetentionDays() {
  const days = Number(process.env.TRASH_RETENTION_DAYS || 30);
  return Number.isFinite(days) && days > 0 ? days : 30;
}

function cleanupExpiredTrashItems() {
  if (!isTrashEnabled()) return;
  if (!shouldAutoCleanupTrash()) return;

  const cutoff = Date.now() - getTrashRetentionDays() * 24 * 60 * 60 * 1000;
  const items = trashRepository.listTrashItems().filter((item) => {
    const deletedAt = new Date(item.deletedAt).getTime();
    return Number.isFinite(deletedAt) && deletedAt <= cutoff;
  });

  for (const item of items) {
    try {
      if (!isCloudStorageEnabled()) {
        trashService.permanentlyDelete({ item, deletedBy: "system", loaders: getTrashLoaders() });
      } else {
        const pending = trashService.queueRemoteDeletion({ item, deletedBy: "system", loaders: getTrashLoaders(), provider: getCloudStorageStatus().provider });
        auditLog("trash.remote_delete.queued", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "success", {});
        void trashService.processRemoteDeletion({ item: pending, provider: deleteCloudTrashItem })
          .then((result) => {
            const persisted = trashRepository.getTrashItem(item.id) || result;
            const state = persisted.metadata?.remoteDeletion?.state;
            if (state === "completed") auditLog("trash.remote_delete.completed", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "success", {});
            else if (state === "terminal_failure") auditLog("trash.remote_delete.failed", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "failure", { category: persisted.metadata?.remoteDeletion?.failureCategory });
          })
          .catch((error) => {
            auditLog("trash.remote_delete.operational_failure", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "failure", { category: error.code || "persistence_error" });
            console.error("[cloud-trash] remote deletion state could not be persisted:", error.code || "persistence_error");
          });
      }
      if (!isCloudStorageEnabled()) {
        auditLog(
          item.itemType === "file" ? "trash.file.permanently_deleted" : "trash.folder.permanently_deleted",
          { username: "system", role: "system" },
          { type: "trash", id: item.id },
          "auto_cleanup",
          "success",
          { retentionDays: getTrashRetentionDays(), itemType: item.itemType }
        );
      }
    } catch (error) {
      auditLog("trash.delete.failed", { username: "system", role: "system" }, { type: "trash", id: item.id }, "auto_cleanup", "failure", {
        error: error.message,
      });
    }
  }

  if (items.length) broadcastDataChanged("trash", { action: "auto_cleanup", count: items.length });
}

function cleanupExpiredTemporaryItems() {
  const now = Date.now();

  try {
    const folders = loadFolders();
    const remainingFolders = [];
    let foldersChanged = false;

    for (const folder of folders) {
      const expiresAt = folder.expiresAt ? new Date(folder.expiresAt).getTime() : null;
      if (
        folder.id !== ROOT_FOLDER_ID &&
        Number.isFinite(expiresAt) &&
        expiresAt <= now
      ) {
        deleteFolderContents(folder);
        addActionHistory("folder_expired", folder.name, "sistema", {
          folderId: folder.id,
          folderName: folder.name,
          expiresAt: folder.expiresAt,
        });
        foldersChanged = true;
        continue;
      }

      remainingFolders.push(folder);
    }

    if (foldersChanged) saveFolders(remainingFolders);
  } catch (error) {
    console.error("Falha ao limpar pastas temporarias:", error.message);
  }

  try {
    const expirations = loadFileExpirations();
    let filesChanged = false;

    for (const [key, entry] of Object.entries(expirations)) {
      const expiresAt = new Date(entry?.expiresAt).getTime();
      if (!Number.isFinite(expiresAt) || expiresAt > now) continue;

      const folderId = entry.folderId || ROOT_FOLDER_ID;
      const fileName = path.basename(entry.fileName || "");
      const filePath = path.join(getFolderStoragePath("./uploads", folderId), fileName);

      if (fileName && isExistingFile(filePath)) {
        fs.unlinkSync(filePath);
      }

      deleteCloudFileLater(folderId, fileName, "uploads");
      removePublicLinksForFile(fileName, folderId);
      removeFilePermission(folderId, fileName);
      removeFileVersions(folderId, fileName);
      delete expirations[key];
      addActionHistory("file_expired", fileName, "sistema", {
        folderId,
        expiresAt: entry.expiresAt,
      });
      filesChanged = true;
    }

    if (filesChanged) saveFileExpirations(expirations);
  } catch (error) {
    console.error("Falha ao limpar arquivos temporarios:", error.message);
  }
}

function sanitizeFolderName(name) {
  return String(name || "").trim().slice(0, 60);
}

function normalizeAllowedUsers(value) {
  if (Array.isArray(value)) {
    return [...new Set(value.map((user) => String(user).trim()).filter(Boolean))];
  }

  if (typeof value === "string") {
    return [...new Set(value.split(",").map((user) => user.trim()).filter(Boolean))];
  }

  return [];
}

function createFolderId() {
  return crypto.randomBytes(8).toString("hex");
}

function getFolderStoragePath(baseDir, folderId = ROOT_FOLDER_ID) {
  if (folderId === ROOT_FOLDER_ID) return path.resolve(baseDir);
  return path.resolve(baseDir, folderId);
}

function ensureFolderDirectories(folderId) {
  const uploadDir = getFolderStoragePath("./uploads", folderId);
  const tempDir = getFolderStoragePath("./temp", folderId);

  if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  return { uploadDir, tempDir };
}

function isSafeFolderChildPath(baseDir, targetPath) {
  const basePath = path.resolve(baseDir);
  const resolvedTarget = path.resolve(targetPath);
  return resolvedTarget.startsWith(`${basePath}${path.sep}`);
}

function isSafeChildPath(baseDir, targetPath) {
  const basePath = path.resolve(baseDir);
  const resolvedTarget = path.resolve(targetPath);
  return resolvedTarget === basePath || resolvedTarget.startsWith(`${basePath}${path.sep}`);
}

function sanitizeQuarantineFilename(name) {
  const base = path.basename(String(name || "upload.bin")).replace(/[<>:"/\\|?*\x00-\x1F]/g, "_").trim();
  return (base || "upload.bin").slice(0, 120);
}

function getClamAvPort() {
  return Number.isInteger(CLAMAV_PORT) && CLAMAV_PORT > 0 ? CLAMAV_PORT : 3310;
}

function scanFileWithClamAv(filePath) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: CLAMAV_HOST, port: getClamAvPort() });
    const chunks = [];
    let settled = false;

    function finish(error, result) {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else resolve(result);
    }

    socket.setTimeout(5000, () => finish(new Error("ClamAV indisponivel: timeout")));
    socket.on("error", (error) => finish(error));
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => {
      const response = Buffer.concat(chunks).toString("utf-8").trim();
      if (/FOUND$/i.test(response)) {
        const virus = response.replace(/^stream:\s*/i, "").replace(/\s+FOUND$/i, "");
        return finish(null, { status: "infected", provider: "clamav", virus, raw: response.slice(0, 300) });
      }
      if (/OK$/i.test(response)) {
        return finish(null, { status: "clean", provider: "clamav", raw: response.slice(0, 300) });
      }
      return finish(new Error(response || "Resposta invalida do ClamAV"));
    });

    socket.on("connect", () => {
      socket.write(Buffer.from("zINSTREAM\0"));
      const input = fs.createReadStream(filePath);
      input.on("data", (chunk) => {
        const size = Buffer.alloc(4);
        size.writeUInt32BE(chunk.length, 0);
        socket.write(size);
        socket.write(chunk);
      });
      input.on("end", () => socket.write(Buffer.alloc(4)));
      input.on("error", (error) => finish(error));
    });
  });
}

function quarantineUploadedFile(req, options) {
  const folderId = options.folderId || ROOT_FOLDER_ID;
  const originalFilename = path.basename(options.originalName || options.fileName || "upload.bin");
  const storedQuarantineFilename = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}-${sanitizeQuarantineFilename(originalFilename)}`;
  const destinationPath = path.join(UPLOAD_QUARANTINE_DIR, storedQuarantineFilename);

  fs.mkdirSync(UPLOAD_QUARANTINE_DIR, { recursive: true });
  if (!isSafeChildPath(UPLOAD_QUARANTINE_DIR, destinationPath)) {
    throw new Error("Caminho de quarentena invalido");
  }

  try {
    fs.renameSync(options.filePath, destinationPath);
  } catch (error) {
    fs.copyFileSync(options.filePath, destinationPath);
    fs.rmSync(options.filePath, { force: true });
  }

  const entries = loadQuarantine();
  const item = {
    id: crypto.randomUUID(),
    originalFilename,
    storedQuarantineFilename,
    uploader: req.user?.username || "anonymous",
    folderId,
    size: Number(options.size) || fs.statSync(destinationPath).size,
    reason: options.reason || "blocked",
    scanResult: options.scanResult || {},
    timestamp: new Date().toISOString(),
  };
  entries.items.unshift(item);
  saveQuarantine(entries);

  auditLog("upload.quarantined", getAuditActor(req), { type: "quarantine", id: item.id }, "quarantined", "success", {
    filename: originalFilename,
    folderId,
    reason: item.reason,
    result: item.scanResult?.status || "blocked",
  });

  return item;
}

async function scanUploadBeforePending(req, options) {
  if (!UPLOAD_SCAN_ENABLED) {
    return { allowed: true, scanResult: { status: "skipped", provider: "disabled" } };
  }

  const fileName = path.basename(options.fileName || options.originalName || "");
  const folderId = options.folderId || ROOT_FOLDER_ID;
  const extension = path.extname(fileName).toLowerCase();
  const auditTarget = { type: "file", id: fileName };

  if (UPLOAD_BLOCK_EXECUTABLES && UPLOAD_SUSPICIOUS_EXTENSIONS.has(extension)) {
    const scanResult = { status: "suspicious", provider: "extension-block", extension };
    auditLog("upload.scan.suspicious", getAuditActor(req), auditTarget, "scan", "failure", {
      filename: fileName,
      folderId,
      reason: "suspicious_extension",
      extension,
    });
    const quarantine = quarantineUploadedFile(req, {
      ...options,
      reason: "suspicious_extension",
      scanResult,
    });
    return {
      allowed: false,
      status: 415,
      error: "Upload bloqueado por politica de seguranca.",
      quarantine,
      scanResult,
    };
  }

  if (UPLOAD_SCAN_PROVIDER !== "clamav") {
    auditLog("upload.scan.clean", getAuditActor(req), auditTarget, "scan", "success", {
      filename: fileName,
      folderId,
      provider: UPLOAD_SCAN_PROVIDER,
      result: "skipped",
    });
    return { allowed: true, scanResult: { status: "skipped", provider: UPLOAD_SCAN_PROVIDER } };
  }

  try {
    const scanResult = await scanFileWithClamAv(options.filePath);
    if (scanResult.status === "infected") {
      auditLog("upload.scan.infected", getAuditActor(req), auditTarget, "scan", "failure", {
        filename: fileName,
        folderId,
        provider: "clamav",
        virus: scanResult.virus,
      });
      const quarantine = quarantineUploadedFile(req, {
        ...options,
        reason: "clamav_infected",
        scanResult,
      });
      return {
        allowed: false,
        status: 422,
        error: "Upload bloqueado pela verificacao de seguranca.",
        quarantine,
        scanResult,
      };
    }

    auditLog("upload.scan.clean", getAuditActor(req), auditTarget, "scan", "success", {
      filename: fileName,
      folderId,
      provider: "clamav",
      result: scanResult.status,
    });
    return { allowed: true, scanResult };
  } catch (error) {
    const scanResult = { status: "failed", provider: "clamav", error: error.message };
    auditLog("upload.scan.failed", getAuditActor(req), auditTarget, "scan", "failure", {
      filename: fileName,
      folderId,
      provider: "clamav",
      failClosed: UPLOAD_FAIL_CLOSED,
      error: error.message,
    });

    if (UPLOAD_FAIL_CLOSED) {
      const quarantine = quarantineUploadedFile(req, {
        ...options,
        reason: "scan_failed_fail_closed",
        scanResult,
      });
      return {
        allowed: false,
        status: 503,
        error: "Upload bloqueado: scanner indisponivel.",
        quarantine,
        scanResult,
      };
    }

    return { allowed: true, scanResult };
  }
}

function removePendingEntriesForFolder(folderId) {
  const entries = loadPendingUploads();
  let changed = false;

  for (const key of Object.keys(entries)) {
    if (key.startsWith(`${folderId}/`) || entries[key]?.folderId === folderId) {
      delete entries[key];
      changed = true;
    }
  }

  if (changed) savePendingUploads(entries);
}

function getAccessibleFolderOrRespond(req, res, rawFolderId = ROOT_FOLDER_ID) {
  const folderId = String(rawFolderId || ROOT_FOLDER_ID);
  const folder = getFolderById(folderId);

  if (!folder) {
    res.status(404).json({ error: "Pasta nao encontrada" });
    return null;
  }

  if (!hasFolderAccess(req, folder)) {
    res.status(403).json({ error: "Acesso negado a esta pasta" });
    return null;
  }

  const paths = ensureFolderDirectories(folder.id);
  return { ...folder, ...paths };
}

function getPendingKey(folderId, fileName) {
  return `${folderId || ROOT_FOLDER_ID}/${path.basename(fileName || "")}`;
}

function isValidFileNameLength(fileName) {
  return fileName.length <= MAX_FILE_NAME_LENGTH;
}

function shortenFileName(fileName) {
  const safeName = path.basename(fileName || "");
  if (safeName.length <= MAX_FILE_NAME_LENGTH) return safeName;

  const extension = path.extname(safeName);
  const baseName = path.basename(safeName, extension);
  const maxBaseLength = Math.max(1, MAX_FILE_NAME_LENGTH - extension.length);

  return `${baseName.slice(0, maxBaseLength)}${extension}`;
}

function getAvailableUploadFileName(originalName, folderId = ROOT_FOLDER_ID, allowExistingPublic = false) {
  const shortenedName = shortenFileName(originalName);
  const extension = path.extname(shortenedName);
  const baseName = path.basename(shortenedName, extension);
  let candidate = shortenedName;
  let counter = 1;
  const uploadDir = getFolderStoragePath("./uploads", folderId);
  const tempDir = getFolderStoragePath("./temp", folderId);

  while (
    fs.existsSync(path.join(tempDir, candidate)) ||
    (!allowExistingPublic && fs.existsSync(path.join(uploadDir, candidate)))
  ) {
    const suffix = `-${counter}`;
    const maxBaseLength = Math.max(1, MAX_FILE_NAME_LENGTH - extension.length - suffix.length);
    candidate = `${baseName.slice(0, maxBaseLength)}${suffix}${extension}`;
    counter += 1;
  }

  return candidate;
}

function isExistingFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
}

function isGzipFile(filePath) {
  try {
    const fd = fs.openSync(filePath, "r");
    const buffer = Buffer.alloc(2);
    fs.readSync(fd, buffer, 0, 2, 0);
    fs.closeSync(fd);
    return buffer[0] === 0x1f && buffer[1] === 0x8b;
  } catch {
    return false;
  }
}

async function decompressUploadedFileIfNeeded(req) {
  const compression = String(req.body?.rootarkCompression || req.query?.rootarkCompression || "").toLowerCase();
  if (!req.file?.path) return false;

  const extension = path.extname(req.file.originalname || req.file.filename || "").toLowerCase();
  const hasGzipHeader = isGzipFile(req.file.path);
  const shouldDecompress = compression === "gzip" || (hasGzipHeader && extension !== ".gz");
  if (!shouldDecompress) return false;

  if (!hasGzipHeader) {
    throw new Error("Upload marcado como compactado, mas o arquivo nao esta em gzip");
  }

  const compressedPath = req.file.path;
  const outputPath = `${compressedPath}.decompressed`;

  try {
    await pipeline(
      fs.createReadStream(compressedPath),
      zlib.createGunzip(),
      fs.createWriteStream(outputPath)
    );
    fs.rmSync(compressedPath, { force: true });
    fs.renameSync(outputPath, compressedPath);
    req.file.size = fs.statSync(compressedPath).size;
    return true;
  } catch (error) {
    fs.rmSync(outputPath, { force: true });
    throw new Error("Nao foi possivel descompactar o upload");
  }
}

async function repairCompressedTempUploads(directory = path.resolve("./temp")) {
  if (!fs.existsSync(directory)) return;

  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      await repairCompressedTempUploads(fullPath);
      continue;
    }

    if (!entry.isFile()) continue;
    if (path.extname(entry.name).toLowerCase() === ".gz") continue;
    if (!isGzipFile(fullPath)) continue;

    const outputPath = `${fullPath}.repair`;
    try {
      await pipeline(
        fs.createReadStream(fullPath),
        zlib.createGunzip(),
        fs.createWriteStream(outputPath)
      );
      fs.rmSync(fullPath, { force: true });
      fs.renameSync(outputPath, fullPath);
      console.log(`[upload-repair] Arquivo temporario descompactado: ${fullPath}`);
    } catch (error) {
      fs.rmSync(outputPath, { force: true });
      fs.rmSync(fullPath, { force: true });
      console.error(`[upload-repair] Falha ao recuperar ${fullPath}:`, error.message);
    }
  }
}

function cleanupOrphanTempUploads(directory = path.resolve("./temp")) {
  if (!fs.existsSync(directory)) return;

  const pendingUploads = loadPendingUploads();
  const pendingNames = new Set();
  for (const [key, entry] of Object.entries(pendingUploads)) {
    const folderId = entry?.folderId || (String(key).includes("/") ? String(key).split("/")[0] : ROOT_FOLDER_ID);
    const fileName = path.basename(entry?.fileName || key);
    pendingNames.add(path.join(getFolderStoragePath("./temp", folderId), fileName));
  }

  const now = Date.now();
  const walk = (currentDir) => {
    for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
      const fullPath = path.join(currentDir, entry.name);
      if (fullPath.startsWith(CHUNK_UPLOAD_DIR)) continue;
      if (fullPath.startsWith(SIMPLE_UPLOAD_INCOMING_DIR)) continue;

      if (entry.isDirectory()) {
        walk(fullPath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (pendingNames.has(path.resolve(fullPath))) continue;

      const stats = fs.statSync(fullPath);
      const internalTempFile = /\.(upload|part|repair|decompressed)$/i.test(entry.name);
      const maxAge = internalTempFile ? 5 * 60 * 1000 : 24 * 60 * 60 * 1000;
      if (now - stats.mtimeMs > maxAge) {
        fs.rmSync(fullPath, { force: true });
      }
    }
  };

  walk(directory);
}

function cleanupIncomingUploads() {
  for (const directory of [SIMPLE_UPLOAD_INCOMING_DIR, path.join(CHUNK_UPLOAD_DIR, "incoming")]) {
    if (!fs.existsSync(directory)) continue;

    const now = Date.now();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const fullPath = path.join(directory, entry.name);
      if (!entry.isFile()) continue;

      const stats = fs.statSync(fullPath);
      if (now - stats.mtimeMs > 5 * 60 * 1000) {
        fs.rmSync(fullPath, { force: true });
      }
    }
  }
}

function getPendingUploadEntry(folderId, fileName) {
  const entries = loadPendingUploads();
  return entries[getPendingKey(folderId, fileName)] || entries[fileName] || null;
}

function getPendingUploadOwner(folderId, fileName) {
  return getPendingUploadEntry(folderId, fileName)?.uploadedBy || null;
}

function getApprovalFolderById(folderId) {
  const folder = getFolderById(folderId || ROOT_FOLDER_ID);
  if (!folder) return null;
  return { ...folder, ...ensureFolderDirectories(folder.id) };
}

async function findPendingApprovalTarget(req, requestedFolder, fileName) {
  const name = path.basename(fileName || "");
  if (!name) return null;

  const candidates = [];
  const pushCandidate = (folderId) => {
    const folder = getApprovalFolderById(folderId);
    if (!folder) return;
    if (!canManageAccess(req) && !hasFolderAccess(req, folder)) return;
    if (candidates.some((candidate) => candidate.folder.id === folder.id)) return;
    candidates.push({
      folder,
      pendingPath: path.join(folder.tempDir, name),
    });
  };

  pushCandidate(requestedFolder?.id || ROOT_FOLDER_ID);

  const pendingUploads = loadPendingUploads();
  for (const [key, entry] of Object.entries(pendingUploads)) {
    const entryName = path.basename(entry?.fileName || key);
    if (entryName !== name) continue;
    const folderId = entry?.folderId || (String(key).includes("/") ? String(key).split("/")[0] : ROOT_FOLDER_ID);
    pushCandidate(folderId);
  }

  for (const folder of loadFolders()) {
    pushCandidate(folder.id);
  }

  for (const candidate of candidates) {
    await ensureCloudFileCached(candidate.folder.id, name, candidate.pendingPath, "temp");
    if (isExistingFile(candidate.pendingPath)) return candidate;
  }

  return null;
}

function canAccessPendingFile(req, folderId, fileName) {
  return (
    req.user?.permissions?.listPending ||
    getPendingUploadOwner(folderId, fileName) === req.user?.username ||
    !getPendingUploadOwner(folderId, fileName)
  );
}

function resolveScopedFile(scope, rawName, rawFolderId = ROOT_FOLDER_ID) {
  const name = path.basename(rawName || "");
  const folderId = String(rawFolderId || ROOT_FOLDER_ID);

  if (!name) {
    return null;
  }

  const folder = getFolderById(folderId);
  if (!folder) return null;

  if (scope === "public") {
    return {
      name,
      folder,
      folderId,
      filePath: path.join(getFolderStoragePath("./uploads", folderId), name),
      isPending: false,
    };
  }

  if (scope === "pending") {
    return {
      name,
      folder,
      folderId,
      filePath: path.join(getFolderStoragePath("./temp", folderId), name),
      isPending: true,
    };
  }

  return null;
}

async function ensurePreviewAccess(req, res, scope, rawName, rawFolderId = ROOT_FOLDER_ID) {
  const target = resolveScopedFile(scope, rawName, rawFolderId);
  if (!target) {
    res.status(400).json({ error: "Arquivo invalido" });
    return null;
  }

  if (target.isPending && !hasFolderAccess(req, target.folder)) {
    res.status(403).json({ error: "Acesso negado a esta pasta" });
    return null;
  }

  if (target.isPending) {
    if (!req.user?.permissions?.listPending && !req.user?.permissions?.upload) {
      res.status(403).json({ error: "Permissao negada: listPending" });
      return null;
    }

    if (!canAccessPendingFile(req, target.folderId, target.name)) {
      res.status(403).json({ error: "Permissao negada para esse arquivo" });
      return null;
    }
  } else if (!req.user?.permissions?.listFiles) {
    res.status(403).json({ error: "Permissao negada: listFiles" });
    return null;
  } else if (!hasFileAccess(req, target.folder, target.name)) {
    res.status(403).json({ error: "Acesso negado a este arquivo" });
    return null;
  } else if (isFileInTrash(target.folderId, target.name)) {
    res.status(410).json({ error: "Arquivo esta na lixeira" });
    return null;
  }

  if (getEncryptedFileMetadata(target.folderId, target.name)) {
    res.status(403).json({ error: "Preview indisponivel para arquivos criptografados" });
    return null;
  }

  await ensureCloudFileCached(target.folderId, target.name, target.filePath, target.isPending ? "temp" : "uploads");
  if (!fs.existsSync(target.filePath)) {
    res.status(404).json({ error: "Arquivo nao encontrado" });
    return null;
  }

  return target;
}

function listFilesWithDetails(directory, callback) {
  fs.readdir(directory, (readError, files) => {
    if (readError) {
      callback(readError);
      return;
    }

    const items = [];

    for (const name of files) {
      try {
        const filePath = path.join(directory, name);
        const stats = fs.statSync(filePath);

        if (stats.isFile()) {
          items.push({
            name,
            size: stats.size,
            uploadedAt: stats.birthtime.toISOString(),
            modifiedAt: stats.mtime.toISOString(),
          });
        }
      } catch (error) {
        // The file may be renamed or removed between readdir() and stat().
        if (error.code === "ENOENT") {
          continue;
        }

        callback(error);
        return;
      }
    }

    callback(null, items);
  });
}

function listFilesWithDetailsAsync(directory) {
  return new Promise((resolve, reject) => {
    listFilesWithDetails(directory, (error, files) => {
      if (error) reject(error);
      else resolve(files);
    });
  });
}

function getDirectorySize(directory) {
  if (!fs.existsSync(directory)) return 0;

  let total = 0;
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      total += getDirectorySize(fullPath);
    } else if (entry.isFile()) {
      total += fs.statSync(fullPath).size;
    }
  }

  return total;
}

function getMonthKey(date) {
  return date.toISOString().slice(0, 7);
}

function getDayKey(date) {
  return date.toISOString().slice(0, 10);
}

function getUploadsByMonth(months = 6) {
  const analytics = loadAnalytics();
  const count = Math.min(Math.max(Number(months) || 6, 1), 24);
  const result = [];
  const now = new Date();

  for (let index = count - 1; index >= 0; index -= 1) {
    const monthStart = new Date(now.getFullYear(), now.getMonth() - index, 1);
    const monthEnd = new Date(now.getFullYear(), now.getMonth() - index + 1, 1);
    const uploads = analytics.uploads.filter((upload) => {
      const date = new Date(upload.uploadedAt);
      return date >= monthStart && date < monthEnd;
    });

    result.push({
      month: getMonthKey(monthStart),
      count: uploads.length,
      totalSize: uploads.reduce((sum, upload) => sum + (Number(upload.size) || 0), 0),
    });
  }

  return result;
}

function getUploadsByUser(limit = 10) {
  const analytics = loadAnalytics();
  const totals = {};

  for (const upload of analytics.uploads) {
    const username = upload.uploadedBy || "desconhecido";
    if (!totals[username]) totals[username] = { username, count: 0, totalSize: 0 };
    totals[username].count += 1;
    totals[username].totalSize += Number(upload.size) || 0;
  }

  return Object.values(totals)
    .sort((a, b) => b.count - a.count || b.totalSize - a.totalSize)
    .slice(0, Math.min(Math.max(Number(limit) || 10, 1), 50));
}

function getActiveUsers(days = 30) {
  const analytics = loadAnalytics();
  const count = Math.min(Math.max(Number(days) || 30, 1), 365);
  const result = [];
  const byDay = {};

  for (let index = count - 1; index >= 0; index -= 1) {
    const day = new Date(Date.now() - index * 24 * 60 * 60 * 1000);
    byDay[getDayKey(day)] = new Set();
  }

  for (const login of analytics.logins) {
    const date = new Date(login.loginAt);
    const key = Number.isFinite(date.getTime()) ? getDayKey(date) : "";
    if (byDay[key]) byDay[key].add(login.username);
  }

  for (const [date, users] of Object.entries(byDay)) {
    result.push({ date, uniqueUsers: users.size });
  }

  return result;
}

function getFileTypes() {
  const analytics = loadAnalytics();
  const totals = {};

  for (const upload of analytics.uploads) {
    const extension = path.extname(upload.filename || "").toLowerCase() || "sem extensao";
    if (!totals[extension]) totals[extension] = { extension, count: 0, totalSize: 0 };
    totals[extension].count += 1;
    totals[extension].totalSize += Number(upload.size) || 0;
  }

  return Object.values(totals).sort((a, b) => b.count - a.count || b.totalSize - a.totalSize);
}

function getMostDownloadedFiles(limit = 10) {
  const analytics = loadAnalytics();
  const totals = {};

  for (const download of analytics.downloads) {
    const filename = download.filename || "arquivo";
    if (!totals[filename]) totals[filename] = { filename, downloads: 0 };
    totals[filename].downloads += 1;
  }

  return Object.values(totals)
    .sort((a, b) => b.downloads - a.downloads)
    .slice(0, Math.min(Math.max(Number(limit) || 10, 1), 50));
}

function getAnalyticsSummary() {
  if (analyticsSummaryCache && analyticsSummaryCache.expiresAt > Date.now()) {
    return analyticsSummaryCache.value;
  }

  const analytics = loadAnalytics();
  const today = getDayKey(new Date());
  const currentMonth = getMonthKey(new Date());
  const activeToday = new Set(
    analytics.logins
      .filter((login) => String(login.loginAt || "").startsWith(today))
      .map((login) => login.username)
  );
  const uploadsThisMonth = analytics.uploads.filter((upload) => String(upload.uploadedAt || "").startsWith(currentMonth));
  const topUser = getUploadsByUser(1)[0]?.username || "";
  const topDownload = getMostDownloadedFiles(1)[0]?.filename || "";
  const pendingUploads = loadPendingUploads();

  const summary = {
    totalUploads: analytics.uploads.length,
    totalDownloads: analytics.downloads.length,
    totalUsers: loadUsers().length,
    activeUsersToday: activeToday.size,
    storageUsed: getDirectorySize("./uploads"),
    pendingApprovals: Object.keys(pendingUploads).length,
    uploadsThisMonth: uploadsThisMonth.length,
    mostActiveUser: topUser,
    mostDownloadedFile: topDownload,
  };

  analyticsSummaryCache = {
    value: summary,
    expiresAt: Date.now() + ANALYTICS_SUMMARY_CACHE_MS,
  };
  return summary;
}

function getRecentAnalyticsEvents(limit = 20) {
  const analytics = loadAnalytics();
  const events = [
    ...analytics.uploads.map((item) => ({
      type: "upload",
      username: item.uploadedBy,
      filename: item.filename,
      timestamp: item.uploadedAt,
    })),
    ...analytics.downloads.map((item) => ({
      type: "download",
      username: item.downloadedBy,
      filename: item.filename,
      timestamp: item.downloadedAt,
    })),
    ...analytics.logins.map((item) => ({
      type: "login",
      username: item.username,
      filename: "",
      timestamp: item.loginAt,
    })),
    ...analytics.deletions.map((item) => ({
      type: "delete",
      username: item.deletedBy,
      filename: item.filename,
      timestamp: item.deletedAt,
    })),
    ...analytics.approvals.map((item) => ({
      type: "approval",
      username: item.approvedBy,
      filename: item.filename,
      timestamp: item.approvedAt,
    })),
    ...analytics.rejections.map((item) => ({
      type: "rejection",
      username: item.rejectedBy,
      filename: item.filename,
      timestamp: item.rejectedAt,
    })),
    ...analytics.restores.map((item) => ({
      type: "restore",
      username: item.restoredBy,
      filename: item.filename,
      timestamp: item.restoredAt,
    })),
    ...analytics.versionDeletions.map((item) => ({
      type: "versionDeletion",
      username: item.deletedBy,
      filename: item.filename,
      timestamp: item.deletedAt,
    })),
  ].filter((event) => Number.isFinite(new Date(event.timestamp).getTime()));

  return events
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, Math.min(Math.max(Number(limit) || 20, 1), 100));
}

function getNestedValue(item, key) {
  return String(key).split(".").reduce((value, part) => value?.[part], item);
}

function countBy(items, key) {
  return items.reduce((acc, item) => {
    const value = getNestedValue(item, key) || "desconhecido";
    acc[value] = (acc[value] || 0) + 1;
    return acc;
  }, {});
}

function findSuspiciousIPs(logs) {
  return Object.entries(countBy(logs.filter((log) => log.eventType === "auth.login.failed"), "actor.ip"))
    .filter(([, count]) => count >= 5)
    .map(([ip, failedAttempts]) => ({ ip, failedAttempts }));
}

function getFilteredAuditLogs(query = {}) {
  let logs = loadAuditLogs().logs;
  const { eventType, username, startDate, endDate, severity, result } = query;

  if (eventType) logs = logs.filter((log) => log.eventType === eventType);
  if (username) logs = logs.filter((log) => log.actor?.username === username);
  if (severity) logs = logs.filter((log) => log.severity === severity);
  if (result) logs = logs.filter((log) => log.result === result);
  if (startDate) logs = logs.filter((log) => new Date(log.timestamp) >= new Date(startDate));
  if (endDate) logs = logs.filter((log) => new Date(log.timestamp) <= new Date(`${endDate}T23:59:59.999Z`));

  return logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function convertAuditLogsToCSV(logs) {
  const headers = ["ID", "Timestamp", "Event Type", "Severity", "Username", "Role", "IP", "Action", "Result", "Target", "Details"];
  const rows = logs.map((log) => [
    log.id,
    log.timestamp,
    log.eventType,
    log.severity,
    log.actor?.username,
    log.actor?.role,
    log.actor?.ip,
    log.action,
    log.result,
    log.target ? `${log.target.type || ""}:${log.target.id || ""}` : "",
    JSON.stringify(log.details || {}),
  ].map(csvCell).join(","));

  return `${headers.map(csvCell).join(",")}\n${rows.join("\n")}`;
}

function checkAnomalies(req, username) {
  const logs = loadAuditLogs().logs;
  const since = Date.now() - 60 * 60 * 1000;
  const recent = logs.filter((log) => (
    log.actor?.username === username &&
    new Date(log.timestamp).getTime() >= since
  ));
  const ips = [...new Set(recent.map((log) => log.actor?.ip).filter(Boolean))];
  const failedAttempts = recent.filter((log) => log.eventType === "auth.login.failed").length;

  if (ips.length > 3) {
    auditLog("system.anomaly.detected", { username: "system" }, { type: "user", id: username }, "flagged", "partial", {
      reason: "multiple_ips",
      count: ips.length,
      ips,
    });
  }

  if (failedAttempts >= 3) {
    auditLog("system.anomaly.detected", { username: "system" }, { type: "user", id: username }, "flagged", "partial", {
      reason: "bruteforce_pattern",
      failedAttempts,
      ip: getAuditActor(req, username).ip,
    });
  }
}

function getTrashLoaders() {
  return {
    loadFolders,
    saveFolders,
    loadFilePermissions,
    saveFilePermissions,
    loadFileExpirations,
    saveFileExpirations,
    loadFileVersions,
    saveFileVersions,
    loadEncryptedFiles,
    saveEncryptedFiles,
    loadPublicLinks,
    savePublicLinks,
  };
}

function serializeTrashItemForUser(item) {
  const remote = item.metadata?.remoteDeletion;
  return {
    id: item.id,
    itemType: item.itemType,
    originalFolderId: item.originalFolderId,
    originalFolderName: item.originalFolderName,
    originalFileName: item.originalFileName,
    deletedBy: item.deletedBy,
    deletedAt: item.deletedAt,
    sizeBytes: item.sizeBytes,
    status: item.status,
    ...(remote ? {
      remoteDeletion: {
        state: remote.state,
        operationId: remote.operationId,
        provider: remote.provider,
        attempts: remote.attempts,
        maxAttempts: remote.maxAttempts,
        queuedAt: remote.queuedAt,
        lastAttemptAt: remote.lastAttemptAt,
        nextAttemptAt: remote.nextAttemptAt,
        completedAt: remote.completedAt,
        failureCategory: remote.failureCategory,
        cancellationReason: remote.cancellationReason,
      },
    } : {}),
  };
}

function canRestoreTrashItem(req, item) {
  if (canManageTrash(req)) return true;
  if (item.deletedBy !== req.user?.username) return false;
  if (item.itemType === "folder") return true;
  const folder = getFolderById(item.originalFolderId);
  return item.itemType === "file" && folder && hasFolderAccess(req, folder);
}

function isFileInTrash(folderId, fileName) {
  return trashRepository.isFileTrashed(folderId || ROOT_FOLDER_ID, path.basename(fileName || ""));
}

function hydrateFolderForWebDav(folder) {
  if (!folder) return null;
  return { ...folder, ...ensureFolderDirectories(folder.id) };
}

function findWebDavFolderByName(req, segment) {
  const target = String(segment || "").trim();
  return loadFolders()
    .filter((folder) => !folder.deletedAt && folder.id !== ROOT_FOLDER_ID && hasFolderAccess(req, folder))
    .find((folder) => folder.id === target || sameUsername(folder.name, target));
}

function getWebDavAccessibleFolders(req) {
  return loadFolders()
    .filter((folder) => !folder.deletedAt && folder.id !== ROOT_FOLDER_ID && hasFolderAccess(req, folder))
    .map(hydrateFolderForWebDav);
}

function getWebDavRootFolder() {
  return hydrateFolderForWebDav(getFolderById(ROOT_FOLDER_ID) || getDefaultFolders()[0]);
}

function isWebDavFileExpired(folderId, fileName) {
  const entry = getFileExpirationEntry(folderId, fileName);
  if (!entry?.expiresAt) return false;
  const expiresAt = new Date(entry.expiresAt).getTime();
  return Number.isFinite(expiresAt) && expiresAt <= Date.now();
}

function isWebDavEncryptedFile(folderId, fileName) {
  return Boolean(getEncryptedFileMetadata(folderId, fileName));
}

function isWebDavInternalStoredFile(folderId, fileName) {
  const name = path.basename(fileName || "");
  return isStoredVersionFile(folderId, name) || /\.v\d+$/i.test(name);
}

async function deleteCloudTrashItem(item) {
  if (!isCloudStorageEnabled()) return false;
  if (item.itemType === "folder") {
    await deleteCloudPrefix(getCloudKey(item.originalFolderId, "", "uploads"));
    await deleteCloudPrefix(getCloudKey(item.originalFolderId, "", "temp"));
    return true;
  }
  await deleteFileFromCloud(item.originalFolderId || ROOT_FOLDER_ID, item.originalFileName, "uploads");
  for (const version of item.restoreMetadata?.versions?.versions || []) {
    if (version.storedAs && version.storedAs !== item.originalFileName) {
      await deleteFileFromCloud(item.originalFolderId || ROOT_FOLDER_ID, version.storedAs, "uploads");
    }
  }
  return true;
}

async function processPendingCloudTrashItems() {
  if (!isCloudStorageEnabled()) return;
  try {
    for (const item of trashRepository.listTrashItems({ status: "remote_delete_pending" })) {
      try {
        const result = await trashService.processRemoteDeletion({ item, provider: deleteCloudTrashItem });
        const state = result.metadata?.remoteDeletion?.state;
        if (state === "completed") auditLog("trash.remote_delete.completed", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "success", {});
        else if (state === "terminal_failure") auditLog("trash.remote_delete.failed", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "failure", { category: result.metadata?.remoteDeletion?.failureCategory });
      } catch (error) {
        auditLog("trash.remote_delete.operational_failure", { username: "system", role: "system" }, { type: "trash", id: item.id }, "remote_delete", "failure", { category: error.code || "persistence_error" });
        console.error("[cloud-trash] pending remote deletion failed:", error.code || "persistence_error");
      }
    }
  } catch (error) {
    console.error("[cloud-trash] pending retry failed:", error.code || "persistence_error");
  }
}

function deleteCloudTrashItemLater(item) {
  if (!item) return;
  if (item.itemType === "folder") {
    deleteCloudFolderLater(item.originalFolderId);
    return;
  }

  if (item.itemType === "file" && item.originalFileName) {
    deleteCloudFileLater(item.originalFolderId || ROOT_FOLDER_ID, item.originalFileName, "uploads");
    const versions = item.restoreMetadata?.versions?.versions || [];
    for (const version of versions) {
      if (version.storedAs && version.storedAs !== item.originalFileName) {
        deleteCloudFileLater(item.originalFolderId || ROOT_FOLDER_ID, version.storedAs, "uploads");
      }
    }
  }
}

async function processPendingCloudRestoreSync() {
  if (!isCloudStorageEnabled()) return;
  for (const backup of backupService.listBackups()) {
    const state = backup.metadata?.restoreSync?.state;
    if (!["pending", "retry_wait"].includes(state)) continue;
    try {
      await restoreService.processRestoreSync({ backupId: backup.id });
    } catch {
      // The durable entry remains retryable; never create an unhandled rejection.
    }
  }
}

function initData() {
  if (!fs.existsSync("./data")) fs.mkdirSync("./data");
  if (!fs.existsSync("./data/trash")) fs.mkdirSync("./data/trash", { recursive: true });
  if (!fs.existsSync(UPLOAD_QUARANTINE_DIR)) fs.mkdirSync(UPLOAD_QUARANTINE_DIR, { recursive: true });
  if (!fs.existsSync("./temp")) fs.mkdirSync("./temp");
  if (!fs.existsSync(CHUNK_UPLOAD_DIR)) fs.mkdirSync(CHUNK_UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(SIMPLE_UPLOAD_INCOMING_DIR)) fs.mkdirSync(SIMPLE_UPLOAD_INCOMING_DIR, { recursive: true });
  if (!fs.existsSync("./uploads")) fs.mkdirSync("./uploads");

  if (shouldUseDatabase()) {
    runMigrations({ backup: String(process.env.DB_AUTO_BACKUP_ON_START || "false").toLowerCase() === "true" });
  }

  if (!shouldUseDatabase() || shouldWriteLegacyJson()) {
    if (!fs.existsSync(PENDING_UPLOADS_FILE)) savePendingUploads({});
    if (!fs.existsSync(PUBLIC_LINKS_FILE)) savePublicLinks({});
    if (!fs.existsSync(ACTION_HISTORY_FILE)) saveActionHistory([]);
    if (!fs.existsSync(FOLDERS_FILE)) saveFolders(getDefaultFolders());
    if (!fs.existsSync(FILE_PERMISSIONS_FILE)) saveFilePermissions({});
    if (!fs.existsSync(FILE_EXPIRATIONS_FILE)) saveFileExpirations({});
    if (!fs.existsSync(FILE_VERSIONS_FILE)) saveFileVersions({});
    if (!fs.existsSync(ENCRYPTED_FILES_FILE)) saveEncryptedFiles({});
    if (!fs.existsSync(ANALYTICS_FILE)) saveAnalytics(getDefaultAnalytics());
    if (!fs.existsSync(AUDIT_LOGS_FILE)) saveAuditLogs(getDefaultAuditLogs());
    if (!fs.existsSync(QUARANTINE_FILE)) saveQuarantine(getDefaultQuarantine());
  }

  if (!fs.existsSync(QUARANTINE_FILE)) saveQuarantine(getDefaultQuarantine());

  for (const folder of loadFolders()) {
    ensureFolderDirectories(folder.id);
  }

  const hasUsers = shouldUseDatabase()
    ? usersRepository.loadUsers().length > 0
    : fs.existsSync(USERS_FILE);

  if (!hasUsers) {
    const seedUsers = loadSeedUsers();
    const users = seedUsers || getDefaultUsers();

    saveUsers(users);
    console.log(
      seedUsers
        ? "Usuarios locais restaurados a partir de data/users.json"
        : "Usuarios padrao criados -> admin:admin123 / user:user123"
    );
  }
}

app.set("trust proxy", true);
app.use((req, res, next) => {
  if (WEBDAV_ENABLED && isWebDavRequestPath(req.path)) return next();
  if (req.path === "/sync/v1" || req.path.startsWith("/sync/v1/")) return syncJsonParser(req, res, next);
  return express.json()(req, res, next);
});
app.use((req, res, next) => {
  if (req.path === "/" || req.path.endsWith(".html")) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
  }
  next();
});
app.use(express.static("./public"));
app.use((req, res, next) => {
  cleanupExpiredTemporaryItems();
  next();
});

const loadCurrentUser = (username) => loadUsers().find((user) => user.username === username);
const authenticate = createAuthenticate({ jwt, jwtSecret: JWT_SECRET, loadUser: loadCurrentUser, normalizeUserPermissions });
const authenticateRealtimeToken = createRealtimeAuthenticator({ jwt, jwtSecret: JWT_SECRET, loadUser: loadCurrentUser, normalizeUserPermissions });

app.get("/auth/session.js", authenticate, (req, res) => {
  res.type("application/javascript").set("Cache-Control", "no-store");
  const identity = JSON.stringify({ username: req.user.username, role: req.user.role, permissions: req.user.permissions }).replace(/</g, "\\u003c");
  res.send(`window.ROOTARK_AUTH=${identity};`);
});

wss.on("connection", (socket, req) => {
  const origin = req.headers.origin;
  const expectedOrigin = getExpectedOrigin(req);
  const user = origin === expectedOrigin && authenticateRealtimeToken(parseCookies(req.headers.cookie).rootark_session);

  if (!user) {
    socket.close(1008, "Token invalido");
    return;
  }

  socket.user = user;
  socket.isAlive = true;
  socket.lastActivityAt = Date.now();
  socket.on("error", () => {});
  socket.on("pong", () => { socket.isAlive = true; socket.lastActivityAt = Date.now(); });
  socket.realtimeRate = { startedAt: Date.now(), count: 0 };
  sendRealtime(socket, "connected", { username: user.username });

  socket.on("message", (rawMessage, isBinary) => {
    socket.lastActivityAt = Date.now();
    if (!refreshRealtimeUser(socket)) return;
    if (isBinary) return socket.close(1003, "Quadro binario nao suportado");
    const now = Date.now();
    if (now - socket.realtimeRate.startedAt >= REALTIME_RATE_WINDOW_MS) socket.realtimeRate = { startedAt: now, count: 0 };
    socket.realtimeRate.count += 1;
    if (socket.realtimeRate.count > REALTIME_MAX_MESSAGES_PER_WINDOW) return socket.close(1008, "Limite de mensagens excedido");
    let message = {};
    try {
      message = JSON.parse(rawMessage.toString());
    } catch {
      return;
    }

    if (message.event === "ping") {
      sendRealtime(socket, "pong", {});
    }
  });
});

const requirePermission = createRequirePermission();

registerSyncRoutes({
  app,
  authenticate,
  requirePermission,
  storagePath: process.env.SYNC_OBJECTS_FILE || "./data/sync-objects.json",
  requireDeviceAuthorization: true,
  deviceRegistryPath: process.env.SYNC_DEVICE_REGISTRY || "",
});

groupsStore = registerGroupRoutes({
  app,
  authenticate,
  requirePermission,
  loadUsers,
  loadFolders,
  saveFolders,
  auditLog,
  getAuditActor,
  storagePath: process.env.GROUPS_FILE || GROUPS_FILE,
}).store;

if (WEBDAV_ENABLED) {
  registerWebDavRoutes();
}

app.get("/storage/status", authenticate, requirePermission("manageUsers"), (req, res) => {
  res.json(getCloudStorageStatus());
});

function requireQuarantineAccess(req, res, next) {
  if (!canManageAccess(req)) {
    return res.status(403).json({ error: "Permissao negada: manageUsers" });
  }
  next();
}

app.get("/quarantine", authenticate, requireQuarantineAccess, (req, res) => {
  const entries = loadQuarantine();
  res.json(entries.items.map((item) => ({
    id: item.id,
    originalFilename: item.originalFilename,
    uploader: item.uploader,
    folderId: item.folderId,
    size: item.size,
    reason: item.reason,
    scanResult: item.scanResult,
    timestamp: item.timestamp,
  })));
});

app.delete("/quarantine/:id", authenticate, requireQuarantineAccess, (req, res) => {
  const id = String(req.params.id || "").trim();
  const entries = loadQuarantine();
  const item = entries.items.find((entry) => entry.id === id);
  if (!item) return res.status(404).json({ error: "Arquivo em quarentena nao encontrado" });

  const quarantinePath = path.join(UPLOAD_QUARANTINE_DIR, path.basename(item.storedQuarantineFilename || ""));
  if (!isSafeChildPath(UPLOAD_QUARANTINE_DIR, quarantinePath)) {
    return res.status(400).json({ error: "Registro de quarentena invalido" });
  }

  fs.rmSync(quarantinePath, { force: true });
  saveQuarantine({ items: entries.items.filter((entry) => entry.id !== id) });
  auditLog("quarantine.deleted", getAuditActor(req), { type: "quarantine", id }, "deleted", "success", {
    filename: item.originalFilename,
    folderId: item.folderId,
    reason: item.reason,
  });
  res.json({ message: "Arquivo removido da quarentena" });
});

registerAuthRoutes(app, {
  authenticate,
  auditLog,
  bcrypt,
  checkAnomalies,
  getAuditActor,
  jwt,
  jwtSecret: JWT_SECRET,
  getTotpKey: () => getServerMasterKey({ createIfMissing: false }),
  qrcode: QRCode,
  sessionCookieOptions: SESSION_COOKIE_OPTIONS,
  loadUsers,
  saveUsers,
  logAnalyticsEvent,
  normalizeUserPermissions,
  requirePermission,
});

app.get("/users", authenticate, requirePermission("manageUsers"), (req, res) => {
  const users = loadUsers().map(({ password, totpSecret, totpPendingSecret, totpRecoveryHashes, totpLastUsedStep, ...rest }) => ({
    ...rest,
    permissions: normalizeUserPermissions(rest),
  }));
  res.json(users);
});

app.post("/users", authenticate, requirePermission("manageUsers"), (req, res) => {
  const { username, password, role, permissions } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "username e password obrigatorios" });
  }

  const users = loadUsers();
  if (users.find((u) => u.username === username)) {
    return res.status(409).json({ error: "Usuario ja existe" });
  }

  const base = {
    ...getBasePermissions(),
    ...permissions,
  };

  const finalPermissions =
    role === "admin"
      ? Object.fromEntries(Object.keys(base).map((key) => [key, true]))
      : base;

  users.push({
    username,
    password: bcrypt.hashSync(password, 10),
    role: role || "user",
    permissions: finalPermissions,
    sessionVersion: getCreatedUserSessionVersion(username),
  });

  saveUsers(users);
  auditLog("user.created", getAuditActor(req), { type: "user", id: username }, "created", "success", {
    role: role || "user",
    permissions: finalPermissions,
  });
  res.status(201).json({ message: "Usuario criado" });
});

app.put("/users/:username", authenticate, requirePermission("manageUsers"), (req, res) => {
  const users = loadUsers();
  const idx = users.findIndex((u) => u.username === req.params.username);
  if (idx === -1) return res.status(404).json({ error: "Usuario nao encontrado" });

  if (req.params.username === req.user.username && req.body.permissions?.manageUsers === false) {
    return res.status(400).json({ error: "Voce nao pode revogar sua propria permissao manageUsers" });
  }

  const before = JSON.parse(JSON.stringify(users[idx]));
  const { password, role, permissions } = req.body;
  const sessionChanged = Boolean(password || (role && role !== users[idx].role) || (permissions && Object.entries(permissions).some(([key, value]) => users[idx].permissions?.[key] !== value)) || req.body.disabled !== undefined && Boolean(req.body.disabled) !== Boolean(users[idx].disabled));
  if (password) users[idx].password = bcrypt.hashSync(password, 10);
  if (role) users[idx].role = role;
  if (permissions) users[idx].permissions = { ...users[idx].permissions, ...permissions };
  if (req.body.disabled !== undefined) users[idx].disabled = Boolean(req.body.disabled);
  if (sessionChanged) users[idx].sessionVersion = (users[idx].sessionVersion || 0) + 1;
  users[idx].permissions = normalizeUserPermissions(users[idx]);

  saveUsers(users);
  const changes = {};
  if (role && before.role !== users[idx].role) changes.role = { from: before.role, to: users[idx].role };
  if (password) changes.password = { from: "changed", to: "changed" };
  if (permissions) {
    for (const [key, value] of Object.entries(permissions)) {
      if (before.permissions?.[key] !== value) {
        changes[`permissions.${key}`] = { from: Boolean(before.permissions?.[key]), to: Boolean(value) };
      }
    }
  }
  auditLog(
    permissions ? "user.permission.changed" : password ? "user.password.changed" : "user.updated",
    getAuditActor(req),
    { type: "user", id: req.params.username },
    "modified",
    "success",
    { changes, modifiedBy: req.user.username }
  );

  const { password: _, totpSecret, totpPendingSecret, totpRecoveryHashes, totpLastUsedStep, ...updated } = users[idx];
  res.json({ message: "Usuario atualizado", user: updated });
});

app.delete("/users/:username", authenticate, requirePermission("manageUsers"), (req, res) => {
  if (req.params.username === req.user.username) {
    auditLog("user.deleted", getAuditActor(req), { type: "user", id: req.params.username }, "attempted", "failure", {
      reason: "cannot_delete_self",
    });
    return res.status(400).json({ error: "Voce nao pode excluir a si mesmo" });
  }

  const users = loadUsers();
  const filtered = users.filter((u) => u.username !== req.params.username);
  if (filtered.length === users.length) {
    return res.status(404).json({ error: "Usuario nao encontrado" });
  }

  if (shouldWriteLegacyJson()) rememberUserGenerations(users);
  saveUsers(filtered);
  removeUserFromFilePermissions(req.params.username);
  removeUserFromFolderPermissions(req.params.username);
  auditLog("user.deleted", getAuditActor(req), { type: "user", id: req.params.username }, "deleted", "success", {
    deletedBy: req.user.username,
  });
  res.json({ message: "Usuario excluido" });
});

app.get("/file-access", authenticate, (req, res) => {
  const rawName = typeof req.query.name === "string" ? req.query.name.trim() : "";
  const name = path.basename(rawName);
  const folder = getAccessibleFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  const filePath = path.join(folder.uploadDir, name);
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!canManageAccess(req) && !hasFileEditAccess(req, folder, name)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  const entry = getFilePermissionEntry(folder.id, name);
  const normalizedEntry = normalizeFilePermissionEntry(entry);
  res.json({
    folderId: folder.id,
    fileName: name,
    owner: normalizedEntry.owner,
    public: normalizedEntry.public,
    users: normalizedEntry.users,
    eligibleUsers: getFolderEligibleUsers(folder),
    allowedUsers: Object.entries(normalizedEntry.users)
      .filter(([, access]) => access.read || access.edit)
      .map(([username]) => username),
    inherited: !entry,
  });
});

app.put("/file-access", authenticate, (req, res) => {
  const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const name = path.basename(rawName);
  const folder = getAccessibleFolderOrRespond(req, res, req.body.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  const filePath = path.join(folder.uploadDir, name);
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!canManageAccess(req) && !hasFileEditAccess(req, folder, name)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  const eligibleUsers = getFolderEligibleUsers(folder);
  const validUsernames = new Set(eligibleUsers.map((user) => user.username));
  const publicAccess = Boolean(req.body.public);
  const requestedUsers = req.body.users && typeof req.body.users === "object"
    ? req.body.users
    : Object.fromEntries(normalizeAllowedUsers(req.body.allowedUsers).map((username) => [
        username,
        { read: true, edit: false },
      ]));
  const userAccess = {};
  const invalidUsers = [];

  for (const [username, access] of Object.entries(requestedUsers)) {
    const cleanUsername = String(username || "").trim();
    if (!cleanUsername) continue;

    if (!validUsernames.has(cleanUsername)) {
      invalidUsers.push(cleanUsername);
      continue;
    }

    const canEdit = Boolean(access?.edit);
    const canRead = Boolean(access?.read) || canEdit;
    if (canRead || canEdit) {
      userAccess[cleanUsername] = { read: canRead, edit: canEdit };
    }
  }

  if (invalidUsers.length) {
    return res.status(400).json({
      error: `Usuarios sem acesso a pasta ou invalidos: ${invalidUsers.join(", ")}`,
    });
  }

  const entries = loadFilePermissions();
  const key = getFilePermissionKey(folder.id, name);
  const hasSpecificUsers = Object.keys(userAccess).length > 0;

  if (publicAccess && !hasSpecificUsers) {
    delete entries[key];
  } else {
    const previous = normalizeFilePermissionEntry(entries[key]);
    entries[key] = {
      folderId: folder.id,
      fileName: name,
      owner: previous.owner,
      public: publicAccess,
      users: userAccess,
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.username,
    };
  }

  saveFilePermissions(entries);
  addActionHistory("file_access_updated", name, req.user.username, {
    folderId: folder.id,
    folderName: folder.name,
    public: publicAccess,
    users: userAccess,
    inherited: publicAccess && !hasSpecificUsers,
  });

  res.json({
    message: "Permissoes do arquivo atualizadas",
    folderId: folder.id,
    fileName: name,
    owner: entries[key]?.owner || "sistema",
    public: publicAccess,
    users: userAccess,
    eligibleUsers,
    allowedUsers: Object.keys(userAccess),
    inherited: publicAccess && !hasSpecificUsers,
  });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    fs.mkdirSync(SIMPLE_UPLOAD_INCOMING_DIR, { recursive: true });
    cb(null, SIMPLE_UPLOAD_INCOMING_DIR);
  },
  filename: (req, file, cb) => {
    try {
      req.uploadFinalFileName = getAvailableUploadFileName(file.originalname, req.uploadFolder?.id || ROOT_FOLDER_ID, true);
      cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}.upload`);
    } catch (error) {
      cb(error);
    }
  },
});

const upload = multer({
  storage,
  defParamCharset: "utf8",
  limits: { fileSize: SINGLE_UPLOAD_MAX_BYTES, files: 1, fields: 10, fieldNestingDepth: 0 },
});
const chunkUpload = multer({
  dest: path.join(CHUNK_UPLOAD_DIR, "incoming"),
  defParamCharset: "utf8",
  limits: { files: 1, fields: 10, fieldNestingDepth: 0 },
});

function rejectLargeSingleUpload(req, res, next) {
  const contentLength = Number(req.headers["content-length"]) || 0;
  if (contentLength > SINGLE_UPLOAD_MAX_BYTES + 1024 * 512) {
    return res.status(413).json({
      error: "Arquivo grande demais para upload simples. Recarregue a pagina para usar o upload em blocos.",
      useChunkedUpload: true,
      maxSingleUploadBytes: SINGLE_UPLOAD_MAX_BYTES,
    });
  }

  next();
}

function handleUploadSingle(req, res, next) {
  upload.single("file")(req, res, (error) => {
    if (!error) {
      next();
      return;
    }

    if (req.file?.path) {
      fs.rmSync(req.file.path, { force: true });
    }

    res.status(400).json({ error: error.message || "Upload nao concluido" });
  });
}

function handleChunkUploadSingle(req, res, next) {
  chunkUpload.single("chunk")(req, res, (error) => {
    if (!error) {
      next();
      return;
    }

    if (req.file?.path) {
      fs.rmSync(req.file.path, { force: true });
    }

    res.status(400).json({ error: error.message || "Upload do bloco nao concluido" });
  });
}

function prepareUploadFolder(req, res, next) {
  const folder = getAccessibleFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  req.uploadFolder = folder;
  next();
}

app.get("/folders", authenticate, (req, res) => {
  const folders = loadFolders()
    .filter((folder) => hasFolderAccess(req, folder))
    .map((folder) => serializeFolderForUser(req, folder));
  res.json(folders);
});

app.post("/folders", authenticate, (req, res) => {
  if (!canCreateFolders(req)) {
    return res.status(403).json({ error: "Permissao negada: createFolders" });
  }

  const name = sanitizeFolderName(req.body.name);
  const requestedUsers = req.body.users && typeof req.body.users === "object"
    ? req.body.users
    : Object.fromEntries(normalizeAllowedUsers(req.body.allowedUsers).map((username) => [
        username,
        { read: true, edit: false },
      ]));
  const validUsernames = new Set(loadUsers().map((user) => user.username));
  const folderUsers = {};
  const groupIds = normalizeFolderGroupIds(req.body.groupIds);
  const invalidUsers = [];
  const expiresAt = getTemporaryExpirationFromBody(req.body);

  if (!name) {
    return res.status(400).json({ error: "Nome da pasta e obrigatorio" });
  }

  if (expiresAt === undefined) {
    return res.status(400).json({ error: "Expiracao temporaria invalida" });
  }

  if (groupIds === null) {
    return res.status(400).json({ error: "Grupos invalidos" });
  }

  for (const [username, access] of Object.entries(requestedUsers)) {
    const cleanUsername = String(username || "").trim();
    if (!cleanUsername) continue;

    if (!validUsernames.has(cleanUsername)) {
      invalidUsers.push(cleanUsername);
      continue;
    }

    const canEdit = Boolean(access?.edit);
    const canRead = Boolean(access?.read) || canEdit;
    if (canRead || canEdit) {
      folderUsers[cleanUsername] = { read: canRead, edit: canEdit };
    }
  }

  if (invalidUsers.length) {
    return res.status(400).json({ error: `Usuarios invalidos: ${invalidUsers.join(", ")}` });
  }

  const folders = loadFolders();
  const folder = {
    id: createFolderId(),
    name,
    createdBy: req.user.username,
    createdAt: new Date().toISOString(),
    expiresAt,
    users: folderUsers,
    allowedUsers: Object.keys(folderUsers),
    groupIds: groupIds || [],
    isRoot: false,
  };

  folders.push(folder);
  saveFolders(folders);
  ensureFolderDirectories(folder.id);
  auditLog("folder.created", getAuditActor(req), { type: "folder", id: folder.id }, "created", "success", {
    name,
    users: folderUsers,
    expiresAt,
  });
  addActionHistory("folder_created", name, req.user.username, {
    folderId: folder.id,
    users: folderUsers,
    expiresAt,
  });
  res.status(201).json(serializeFolderForUser(req, folder));
});

app.get("/folders/:id/access", authenticate, (req, res) => {
  const folderId = String(req.params.id || "");
  const folder = getFolderById(folderId);

  if (!folder) return res.status(404).json({ error: "Pasta nao encontrada" });
  if (folderId === ROOT_FOLDER_ID || folder.isRoot) {
    return res.status(400).json({ error: "A pasta padrao nao pode ter acesso alterado" });
  }
  if (!hasFolderEditAccess(req, folder)) {
    return res.status(403).json({ error: "Permissao negada para editar esta pasta" });
  }

  const normalized = normalizeFolderAccessEntry(folder);
  res.json({
    folderId: folder.id,
    folderName: folder.name,
    owner: normalized.owner,
    users: normalized.users,
    eligibleUsers: loadUsers().map(({ password, ...user }) => user),
  });
});

app.put("/folders/:id/access", authenticate, (req, res) => {
  const folderId = String(req.params.id || "");

  if (folderId === ROOT_FOLDER_ID) {
    return res.status(400).json({ error: "A pasta padrao nao pode ter acesso alterado" });
  }

  const folders = loadFolders();
  const folder = folders.find((item) => item.id === folderId);
  if (!folder) return res.status(404).json({ error: "Pasta nao encontrada" });
  if (!hasFolderEditAccess(req, folder)) {
    return res.status(403).json({ error: "Permissao negada para editar esta pasta" });
  }

  const groupIds = normalizeFolderGroupIds(req.body.groupIds);
  if (groupIds === null) {
    return res.status(400).json({ error: "Grupos invalidos" });
  }

  const requestedUsers = req.body.users && typeof req.body.users === "object"
    ? req.body.users
    : Object.fromEntries(normalizeAllowedUsers(req.body.allowedUsers).map((username) => [
        username,
        { read: true, edit: false },
      ]));
  const validUsernames = new Set(loadUsers().map((user) => user.username));
  const folderUsers = {};
  const invalidUsers = [];

  for (const [username, access] of Object.entries(requestedUsers)) {
    const cleanUsername = String(username || "").trim();
    if (!cleanUsername) continue;

    if (!validUsernames.has(cleanUsername)) {
      invalidUsers.push(cleanUsername);
      continue;
    }

    const canEdit = Boolean(access?.edit);
    const canRead = Boolean(access?.read) || canEdit;
    if (canRead || canEdit) {
      folderUsers[cleanUsername] = { read: canRead, edit: canEdit };
    }
  }

  if (invalidUsers.length) {
    return res.status(400).json({ error: `Usuarios invalidos: ${invalidUsers.join(", ")}` });
  }

  folder.users = folderUsers;
  folder.allowedUsers = Object.keys(folderUsers);
  if (groupIds !== undefined) folder.groupIds = groupIds;
  folder.updatedAt = new Date().toISOString();
  saveFolders(folders);
  auditLog("folder.access.changed", getAuditActor(req), { type: "folder", id: folderId }, "modified", "success", {
    folderName: folder.name,
    users: folderUsers,
  });
  addActionHistory("folder_access_updated", folder.name, req.user.username, {
    folderId,
    users: folderUsers,
  });
  res.json(serializeFolderForUser(req, folder));
});

app.put("/folders/:id/name", authenticate, (req, res) => {
  const folderId = String(req.params.id || "");
  const name = sanitizeFolderName(req.body.name);

  if (!folderId || folderId === ROOT_FOLDER_ID) {
    return res.status(400).json({ error: "A pasta padrao nao pode ser renomeada" });
  }

  if (!name) {
    return res.status(400).json({ error: "Nome da pasta e obrigatorio" });
  }

  const folders = loadFolders();
  const folder = folders.find((item) => item.id === folderId);
  if (!folder) return res.status(404).json({ error: "Pasta nao encontrada" });
  if (!hasFolderEditAccess(req, folder)) {
    return res.status(403).json({ error: "Permissao negada para editar esta pasta" });
  }

  const oldName = folder.name;
  if (oldName === name) {
    return res.status(400).json({ error: "O novo nome precisa ser diferente do atual" });
  }

  folder.name = name;
  folder.updatedAt = new Date().toISOString();
  saveFolders(folders);
  addActionHistory("folder_renamed", name, req.user.username, {
    folderId,
    oldName,
    newName: name,
  });

  res.json(serializeFolderForUser(req, folder));
});

app.put("/folders/:id/temporary", authenticate, (req, res) => {
  const folderId = String(req.params.id || "");

  if (!folderId || folderId === ROOT_FOLDER_ID) {
    return res.status(400).json({ error: "A pasta padrao nao pode ser temporaria" });
  }

  const expiresAt = getTemporaryExpirationFromBody(req.body);
  if (expiresAt === undefined) {
    return res.status(400).json({ error: "Expiracao temporaria invalida" });
  }

  const folders = loadFolders();
  const folder = folders.find((item) => item.id === folderId);
  if (!folder) return res.status(404).json({ error: "Pasta nao encontrada" });
  if (!hasFolderEditAccess(req, folder)) {
    return res.status(403).json({ error: "Permissao negada para editar esta pasta" });
  }

  folder.expiresAt = expiresAt;
  folder.updatedAt = new Date().toISOString();
  saveFolders(folders);
  addActionHistory("folder_temporary_updated", folder.name, req.user.username, {
    folderId,
    folderName: folder.name,
    expiresAt,
    temporary: Boolean(expiresAt),
  });

  res.json(serializeFolderForUser(req, folder));
});

app.delete("/folders/:id", authenticate, (req, res) => {
  if (!isTrashEnabled()) return res.status(503).json({ error: "Lixeira desativada" });
  const folderId = String(req.params.id || "");

  if (!folderId || folderId === ROOT_FOLDER_ID) {
    return res.status(400).json({ error: "A pasta padrao nao pode ser excluida" });
  }

  const folders = loadFolders();
  const folder = folders.find((item) => item.id === folderId);
  if (!folder) return res.status(404).json({ error: "Pasta nao encontrada" });
  if (!canMoveToTrash(req)) {
    return res.status(403).json({ error: "Permissao negada: delete" });
  }
  if (!hasFolderEditAccess(req, folder)) {
    return res.status(403).json({ error: "Permissao negada para excluir esta pasta" });
  }

  try {
    const paths = ensureFolderDirectories(folder.id);
    const trashItem = trashService.moveFolderToTrash({
      folder: { ...folder, ...paths },
      deletedBy: req.user.username,
      loaders: getTrashLoaders(),
    });
    auditLog("trash.folder.moved", getAuditActor(req), { type: "trash", id: trashItem.id }, "moved", "success", {
      itemType: "folder",
      originalFolderId: folderId,
      folderName: folder.name,
    });
    addActionHistory("folder_deleted", folder.name, req.user.username, { folderId, trashId: trashItem.id });
    broadcastDataChanged("trash", { folderId, itemType: "folder" });
    return res.json({ message: "Pasta movida para lixeira", trashItem: serializeTrashItemForUser(trashItem) });
  } catch (error) {
    auditLog("trash.delete.failed", getAuditActor(req), { type: "folder", id: folderId }, "move_to_trash", "failure", {
      error: error.message,
    });
    return res.status(500).json({ error: "Erro ao mover pasta para lixeira" });
  }

});

app.get("/files/search", authenticate, requirePermission("listFiles"), handleFileSearch);

app.get("/files/:name", authenticate, requirePermission("listFiles"), async (req, res) => {
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  const name = path.basename(req.params.name);
  if (isFileInTrash(folder.id, name)) {
    return res.status(410).json({ error: "Arquivo esta na lixeira" });
  }
  const filePath = path.join(folder.uploadDir, name);
  await ensureCloudFileCached(folder.id, name, filePath, "uploads");
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!hasFileAccess(req, folder, name)) {
    auditLog("file.access.denied", getAuditActor(req), { type: "file", id: name }, "download", "failure", {
      folderId: folder.id,
      reason: "hasFileAccess_false",
    });
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  if (getEncryptedFileMetadata(folder.id, name)) {
    return res.status(403).json({ error: "Use a rota de download criptografado para este arquivo" });
  }

  logAnalyticsEvent("download", {
    filename: name,
    downloadedBy: req.user.username,
    folderId: folder.id,
    folderName: folder.name,
  });
  auditLog("file.download", getAuditActor(req), { type: "file", id: name }, "downloaded", "success", {
    folderId: folder.id,
    folderName: folder.name,
  });

  sendOptimizedFile(req, res, filePath, name, "attachment");
});

app.post("/file-open-token", authenticate, requirePermission("listFiles"), async (req, res) => {
  const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const name = path.basename(rawName);
  const folder = getReadableFolderOrRespond(req, res, req.body.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }
  if (isFileInTrash(folder.id, name)) {
    return res.status(410).json({ error: "Arquivo esta na lixeira" });
  }

  const filePath = path.join(folder.uploadDir, name);
  await ensureCloudFileCached(folder.id, name, filePath, "uploads");
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!hasFileAccess(req, folder, name)) {
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  if (getEncryptedFileMetadata(folder.id, name)) {
    return res.status(403).json({ error: "Arquivo criptografado. Use Download para informar a senha quando necessario." });
  }

  const openToken = createOpenFileToken(folder.id, name);
  if (req.body.download === true) {
    logAnalyticsEvent("download", {
      filename: name,
      downloadedBy: req.user.username,
      folderId: folder.id,
      folderName: folder.name,
    });
    auditLog("file.download", getAuditActor(req), { type: "file", id: name }, "downloaded", "success", {
      folderId: folder.id,
      folderName: folder.name,
      via: "file-open-token",
    });
  }

  res.json({
    url: `/open-file/${openToken}/${encodeURIComponent(name)}`,
    downloadUrl: `/open-file/${openToken}/${encodeURIComponent(name)}?download=1`,
    expiresAt: new Date(Date.now() + OPEN_FILE_TOKEN_TTL_MS).toISOString(),
  });
});

app.get("/open-file/:token/:name", async (req, res) => {
  cleanupOpenFileTokens();

  const openToken = String(req.params.token || "");
  const entry = openFileTokens.get(openToken);

  if (!entry) {
    return res.status(404).send("Link de abertura expirado ou invalido");
  }

  const name = path.basename(req.params.name || "");
  if (!name || name !== entry.fileName) {
    return res.status(400).send("Nome de arquivo invalido");
  }

  const filePath = entry.filePath || path.join(getFolderStoragePath("./uploads", entry.folderId), name);
  await ensureCloudFileCached(entry.folderId, entry.cloudFileName || entry.downloadName || name, filePath, "uploads");
  if (!isExistingFile(filePath)) {
    openFileTokens.delete(openToken);
    return res.status(404).send("Arquivo nao encontrado");
  }

  const dispositionType = req.query.download === "1" ? "attachment" : "inline";
  sendOptimizedFile(req, res, filePath, entry.downloadName || name, dispositionType, {
    cacheControl: "private, max-age=3600",
  });
});

app.get("/encrypted/:filename/metadata", authenticate, requirePermission("listFiles"), (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  const metadata = getEncryptedFileMetadata(folder.id, name);
  if (!metadata) return res.json({ isEncrypted: false });

  if (!hasFileAccess(req, folder, name) || !canAccessEncryptedFile(req, metadata)) {
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  res.json(getPublicEncryptionMetadata(metadata));
});

app.post("/encrypted-download/:filename", authenticate, requirePermission("listFiles"), express.json(), async (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  const metadata = getEncryptedFileMetadata(folder.id, name);
  if (!metadata) return res.status(404).json({ error: "Arquivo criptografado nao encontrado" });
  if (isFileInTrash(folder.id, name)) {
    return res.status(410).json({ error: "Arquivo esta na lixeira" });
  }

  if (!hasFileAccess(req, folder, name) || !canAccessEncryptedFile(req, metadata)) {
    auditLog("file.access.denied", getAuditActor(req), { type: "file", id: name }, "decrypt", "failure", {
      folderId: folder.id,
      reason: "encrypted_access_denied",
    });
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  if (metadata.accessControl?.expiresAt && new Date(metadata.accessControl.expiresAt).getTime() <= Date.now()) {
    return res.status(410).json({ error: "Arquivo criptografado expirado" });
  }

  if (metadata.accessControl?.requiresPassword && !req.body?.password) {
    return res.status(401).json({ error: "Senha obrigatoria para este arquivo" });
  }

  const filePath = path.join(folder.uploadDir, name);
  await ensureCloudFileCached(folder.id, name, filePath, "uploads");
  if (!isExistingFile(filePath)) return res.status(404).json({ error: "Arquivo nao encontrado" });

  try {
    const decrypted = decryptEncryptedFileBuffer(fs.readFileSync(filePath), metadata, req, req.body?.password || "");
    logAnalyticsEvent("download", {
      filename: name,
      downloadedBy: req.user.username,
      folderId: folder.id,
      folderName: folder.name,
    });
    auditLog("file.decrypt", getAuditActor(req), { type: "file", id: name }, "decrypted", "success", {
      folderId: folder.id,
      encryptionLevel: metadata.encryptionLevel,
    });
    res.setHeader("Content-Type", metadata.metadata?.mimeType || getMimeType(metadata.originalFilename));
    res.setHeader("Content-Disposition", getFileContentDisposition(metadata.originalFilename || name, "attachment"));
    res.setHeader("Cache-Control", "no-store");
    res.send(decrypted);
  } catch (error) {
    auditLog("file.decrypt.failed", getAuditActor(req), { type: "file", id: name }, "decrypt", "failure", {
      folderId: folder.id,
      reason: "bad_key_or_corrupt_file",
    });
    res.status(401).json({ error: "Falha na descriptografia: senha incorreta ou arquivo corrompido" });
  }
});

app.post("/encrypted/:filename/grant-access", authenticate, (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const folder = getAccessibleFolderOrRespond(req, res, req.body.folderId || req.query.folderId);
  if (!folder) return;
  const username = String(req.body.username || "").trim();
  const metadata = getEncryptedFileMetadata(folder.id, name);
  if (!metadata) return res.status(404).json({ error: "Arquivo criptografado nao encontrado" });
  if (metadata.accessControl?.owner !== req.user.username && req.user.role !== "admin") {
    return res.status(403).json({ error: "Apenas o dono ou admin pode conceder acesso" });
  }
  if (!loadUsers().some((user) => user.username === username)) {
    return res.status(404).json({ error: "Usuario nao encontrado" });
  }
  const entries = loadEncryptedFiles();
  const key = getEncryptedFileKey(folder.id, name);
  const users = new Set(entries[key].accessControl.authorizedUsers || []);
  users.add(username);
  entries[key].accessControl.authorizedUsers = [...users];
  saveEncryptedFiles(entries);
  auditLog("file.encryption.access.grant", getAuditActor(req), { type: "file", id: name }, "granted", "success", {
    folderId: folder.id,
    username,
  });
  res.json({ message: `Acesso concedido para ${username}` });
});

app.delete("/encrypted/:filename/revoke-access", authenticate, (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const folder = getAccessibleFolderOrRespond(req, res, req.body.folderId || req.query.folderId);
  if (!folder) return;
  const username = String(req.body.username || "").trim();
  const metadata = getEncryptedFileMetadata(folder.id, name);
  if (!metadata) return res.status(404).json({ error: "Arquivo criptografado nao encontrado" });
  if (metadata.accessControl?.owner !== req.user.username && req.user.role !== "admin") {
    return res.status(403).json({ error: "Apenas o dono ou admin pode revogar acesso" });
  }
  const entries = loadEncryptedFiles();
  const key = getEncryptedFileKey(folder.id, name);
  entries[key].accessControl.authorizedUsers = (entries[key].accessControl.authorizedUsers || [])
    .filter((item) => item !== username || item === entries[key].accessControl.owner);
  saveEncryptedFiles(entries);
  auditLog("file.encryption.access.revoke", getAuditActor(req), { type: "file", id: name }, "revoked", "success", {
    folderId: folder.id,
    username,
  });
  res.json({ message: `Acesso revogado para ${username}` });
});

function registerPendingUpload(req, options) {
  const folderId = req.uploadFolder?.id || ROOT_FOLDER_ID;
  const fileName = path.basename(options.fileName || "");
  const originalName = path.basename(options.originalName || fileName);
  const uploadedAt = new Date().toISOString();
  const versionComment = typeof options.versionComment === "string" ? options.versionComment.slice(0, 500) : "";
  const compressedUpload = Boolean(options.compressedUpload);
  const size = Number(options.size) || 0;
  const encryptionMetadata = options.encryptionMetadata || null;

  const pendingUploads = loadPendingUploads();
  pendingUploads[getPendingKey(folderId, fileName)] = {
    uploadedBy: req.user.username,
    uploadedAt,
    originalName: originalName !== fileName ? originalName : undefined,
    versionComment,
    compressedUpload,
    folderId,
  };
  savePendingUploads(pendingUploads);
  if (encryptionMetadata) saveEncryptedMetadata(folderId, fileName, encryptionMetadata);
  syncFileToCloud(folderId, fileName, "temp");
  logAnalyticsEvent("upload", {
    filename: fileName,
    uploadedBy: req.user.username,
    uploadedAt,
    size,
    folderId,
    folderName: req.uploadFolder?.name,
  });
  auditLog("file.upload", getAuditActor(req), {
    type: "file",
    id: fileName,
    metadata: { size, mimeType: options.mimeType || "" },
  }, "created", "success", {
    destination: "temp",
    requiresApproval: true,
    folderId,
    folderName: req.uploadFolder?.name,
    chunkedUpload: Boolean(options.chunkedUpload),
    encrypted: Boolean(encryptionMetadata),
    encryptionLevel: encryptionMetadata?.encryptionLevel || "none",
  });
  addActionHistory("upload_pending", fileName, req.user.username, {
    status: "pending",
    originalName: originalName !== fileName ? originalName : null,
    versionComment,
    compressedUpload,
    chunkedUpload: Boolean(options.chunkedUpload),
    folderId,
    folderName: req.uploadFolder?.name,
  });

  return {
    message: "Upload enviado para aprovacao",
    fileName,
    originalName,
    folderId,
    renamed: originalName !== fileName,
    compressedUpload,
    chunkedUpload: Boolean(options.chunkedUpload),
    encrypted: Boolean(encryptionMetadata),
    encryptionLevel: encryptionMetadata?.encryptionLevel || "none",
  };
}

function getChunkSessionDir(folderId, uploadId) {
  const safeFolderId = String(folderId || ROOT_FOLDER_ID).replace(/[^a-zA-Z0-9_-]/g, "_");
  const safeUploadId = String(uploadId || "").replace(/[^a-zA-Z0-9_-]/g, "");
  if (!safeUploadId || safeUploadId.length > 80) return null;

  const sessionDir = path.join(CHUNK_UPLOAD_DIR, safeFolderId, safeUploadId);
  if (!isSafeChildPath(CHUNK_UPLOAD_DIR, sessionDir)) return null;
  return sessionDir;
}

function loadChunkMetadata(sessionDir) {
  const metadataPath = path.join(sessionDir, "metadata.json");
  if (!isExistingFile(metadataPath)) return null;
  return JSON.parse(fs.readFileSync(metadataPath, "utf-8"));
}

function saveChunkMetadata(sessionDir, metadata) {
  fs.writeFileSync(path.join(sessionDir, "metadata.json"), JSON.stringify(metadata, null, 2));
}

function hasAllChunks(sessionDir, totalChunks) {
  for (let index = 0; index < totalChunks; index += 1) {
    if (!isExistingFile(path.join(sessionDir, `${index}.part`))) return false;
  }
  return true;
}

async function assembleChunkedUpload(sessionDir, destinationPath, totalChunks) {
  fs.mkdirSync(path.dirname(destinationPath), { recursive: true });
  const output = fs.createWriteStream(destinationPath);

  try {
    for (let index = 0; index < totalChunks; index += 1) {
      const chunkPath = path.join(sessionDir, `${index}.part`);
      await new Promise((resolve, reject) => {
        const input = fs.createReadStream(chunkPath);
        input.on("error", reject);
        input.on("end", resolve);
        input.pipe(output, { end: false });
      });
    }

    await new Promise((resolve, reject) => {
      output.on("finish", resolve);
      output.on("error", reject);
      output.end();
    });
  } catch (error) {
    output.destroy();
    fs.rmSync(destinationPath, { force: true });
    throw error;
  }
}

app.post("/upload-chunk", authenticate, requirePermission("upload"), prepareUploadFolder, handleChunkUploadSingle, async (req, res) => {
  const folderId = req.uploadFolder?.id || ROOT_FOLDER_ID;
  const uploadId = String(req.body.uploadId || "");
  const originalName = path.basename(String(req.body.originalName || ""));
  const chunkIndex = Number(req.body.chunkIndex);
  const totalChunks = Number(req.body.totalChunks);

  if (!req.file) {
    return res.status(400).json({ error: "Bloco obrigatorio" });
  }

  if (
    !originalName ||
    !Number.isInteger(chunkIndex) ||
    !Number.isInteger(totalChunks) ||
    chunkIndex < 0 ||
    totalChunks < 1 ||
    totalChunks > MAX_UPLOAD_CHUNKS ||
    chunkIndex >= totalChunks
  ) {
    fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Dados do upload em blocos invalidos" });
  }

  const sessionDir = getChunkSessionDir(folderId, uploadId);
  if (!sessionDir) {
    fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Sessao de upload invalida" });
  }

  try {
    fs.mkdirSync(sessionDir, { recursive: true });
    let metadata = loadChunkMetadata(sessionDir);

    if (!metadata) {
      const fileName = getAvailableUploadFileName(originalName, folderId, true);
      metadata = {
        uploadId,
        folderId,
        originalName,
        fileName,
        totalChunks,
        uploadedBy: req.user.username,
        versionComment: typeof req.body.versionComment === "string" ? req.body.versionComment.slice(0, 500) : "",
        encryptionLevel: typeof req.body.encryptionLevel === "string" ? req.body.encryptionLevel : "none",
        password: typeof req.body.password === "string" ? req.body.password : "",
        expiresInDays: typeof req.body.expiresInDays === "string" ? req.body.expiresInDays : "",
        createdAt: new Date().toISOString(),
      };
      saveChunkMetadata(sessionDir, metadata);
    }

    if (metadata.totalChunks !== totalChunks || metadata.originalName !== originalName) {
      fs.rmSync(req.file.path, { force: true });
      return res.status(409).json({ error: "Sessao de upload inconsistente" });
    }

    const chunkPath = path.join(sessionDir, `${chunkIndex}.part`);
    fs.rmSync(chunkPath, { force: true });
    fs.renameSync(req.file.path, chunkPath);

    if (!hasAllChunks(sessionDir, totalChunks)) {
      return res.json({
        complete: false,
        received: chunkIndex + 1,
        totalChunks,
        fileName: metadata.fileName,
      });
    }

    const finalPath = path.join(req.uploadFolder.tempDir, metadata.fileName);
    await assembleChunkedUpload(sessionDir, finalPath, totalChunks);
    const stats = fs.statSync(finalPath);
    const scan = await scanUploadBeforePending(req, {
      filePath: finalPath,
      fileName: metadata.fileName,
      originalName: metadata.originalName,
      folderId,
      size: stats.size,
    });
    if (!scan.allowed) {
      fs.rmSync(sessionDir, { recursive: true, force: true });
      return res.status(scan.status || 400).json({ error: scan.error || "Upload bloqueado por seguranca" });
    }

    let encryptionMetadata = null;
    try {
      encryptionMetadata = encryptFileInPlace(finalPath, {
        req,
        fileName: metadata.fileName,
        originalName: metadata.originalName,
        folderId,
        originalSize: stats.size,
        mimeType: req.file.mimetype,
        encryptionLevel: metadata.encryptionLevel || "none",
        password: metadata.password || "",
        expiresInDays: metadata.expiresInDays || "",
      });
    } catch (error) {
      fs.rmSync(finalPath, { force: true });
      fs.rmSync(sessionDir, { recursive: true, force: true });
      return res.status(400).json({ error: error.message || "Falha ao criptografar arquivo" });
    }
    fs.rmSync(sessionDir, { recursive: true, force: true });

    const payload = registerPendingUpload(req, {
      fileName: metadata.fileName,
      originalName: metadata.originalName,
      versionComment: metadata.versionComment,
      size: stats.size,
      mimeType: req.file.mimetype,
      chunkedUpload: true,
      encryptionMetadata,
    });

    res.json({ ...payload, complete: true, totalChunks });
  } catch (error) {
    fs.rmSync(req.file.path, { force: true });
    console.error("Erro no upload em blocos:", error.message);
    res.status(500).json({ error: "Upload em blocos nao concluido" });
  }
});

app.post("/upload", authenticate, requirePermission("upload"), prepareUploadFolder, rejectLargeSingleUpload, handleUploadSingle, async (req, res) => {
  const originalName = path.basename(req.file?.originalname || "");
  const fileName = path.basename(req.uploadFinalFileName || "");

  if (!req.file || !fileName) {
    if (req.file?.path) fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: "Arquivo obrigatorio" });
  }

  let uploadWasCompressed = false;
  try {
    uploadWasCompressed = await decompressUploadedFileIfNeeded(req);
  } catch (error) {
    fs.rmSync(req.file.path, { force: true });
    return res.status(400).json({ error: error.message || "Upload compactado invalido" });
  }

  const finalTempPath = path.join(req.uploadFolder.tempDir, fileName);
  try {
    fs.renameSync(req.file.path, finalTempPath);
    req.file.path = finalTempPath;
  } catch (error) {
    fs.rmSync(req.file.path, { force: true });
    return res.status(500).json({ error: "Nao foi possivel finalizar o upload" });
  }

  const scan = await scanUploadBeforePending(req, {
    filePath: finalTempPath,
    fileName,
    originalName,
    folderId: req.uploadFolder?.id || ROOT_FOLDER_ID,
    size: req.file.size,
  });
  if (!scan.allowed) {
    return res.status(scan.status || 400).json({ error: scan.error || "Upload bloqueado por seguranca" });
  }

  let encryptionMetadata = null;
  try {
    encryptionMetadata = encryptFileInPlace(finalTempPath, {
      req,
      fileName,
      originalName,
      folderId: req.uploadFolder?.id || ROOT_FOLDER_ID,
      originalSize: req.file.size,
      mimeType: req.file.mimetype,
      encryptionLevel: req.body.encryptionLevel || "none",
      password: req.body.password || "",
      expiresInDays: req.body.expiresInDays || "",
    });
  } catch (error) {
    fs.rmSync(finalTempPath, { force: true });
    return res.status(400).json({ error: error.message || "Falha ao criptografar arquivo" });
  }

  res.json(registerPendingUpload(req, {
    fileName,
    originalName,
    versionComment: req.body.versionComment,
    size: req.file.size,
    mimeType: req.file.mimetype,
    compressedUpload: uploadWasCompressed,
    encryptionMetadata,
  }));
});

app.put("/file-temporary", authenticate, (req, res) => {
  const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const name = path.basename(rawName);
  const folder = getAccessibleFolderOrRespond(req, res, req.body.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  if (!hasFileEditAccess(req, folder, name)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  const filePath = path.join(folder.uploadDir, name);
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  const expiresAt = getTemporaryExpirationFromBody(req.body);
  if (expiresAt === undefined) {
    return res.status(400).json({ error: "Expiracao temporaria invalida" });
  }

  const expirations = loadFileExpirations();
  const key = getFileExpirationKey(folder.id, name);

  if (!expiresAt) {
    delete expirations[key];
  } else {
    expirations[key] = {
      folderId: folder.id,
      fileName: name,
      expiresAt,
      updatedAt: new Date().toISOString(),
      updatedBy: req.user.username,
    };
  }

  saveFileExpirations(expirations);
  addActionHistory("file_temporary_updated", name, req.user.username, {
    folderId: folder.id,
    folderName: folder.name,
    expiresAt,
    temporary: Boolean(expiresAt),
  });

  res.json({
    message: "Temporariedade do arquivo atualizada",
    folderId: folder.id,
    fileName: name,
    expiresAt,
    temporary: Boolean(expiresAt),
  });
});

function getFileListCaches() {
  return {
    filePermissions: loadFilePermissions(),
    fileExpirations: loadFileExpirations(),
    fileVersions: loadFileVersions(),
    encryptedFiles: loadEncryptedFiles(),
    publicLinks: cleanupExpiredPublicLinks(),
  };
}

function hasPublicLinkForFile(folderId, fileName, publicLinks = {}) {
  return Object.values(publicLinks).some((link) => {
    if (!link || link.revokedAt) return false;
    return (link.folderId || ROOT_FOLDER_ID) === folderId && link.fileName === fileName;
  });
}

function buildVisibleFileEntry(req, folder, file, caches = getFileListCaches()) {
  if (isStoredVersionFile(folder.id, file.name, caches.fileVersions)) return null;
  if (isFileInTrash(folder.id, file.name)) return null;
  if (!hasFileAccess(req, folder, file.name, caches.filePermissions)) return null;

  const encryption = getEncryptedFileMetadata(folder.id, file.name, caches.encryptedFiles);
  if (!canAccessEncryptedFile(req, encryption)) return null;

  const entry = getFilePermissionEntry(folder.id, file.name, caches.filePermissions);
  const normalizedEntry = normalizeFilePermissionEntry(entry);
  const expiration = getFileExpirationEntry(folder.id, file.name, caches.fileExpirations);
  const versions = getVersionHistory(folder.id, file.name, caches.fileVersions);
  const shared = Boolean(normalizedEntry.public) || Object.keys(normalizedEntry.users || {}).length > 0 || hasPublicLinkForFile(folder.id, file.name, caches.publicLinks);

  return {
    ...file,
    folderId: folder.id,
    folderName: folder.name,
    uploadedBy: normalizedEntry.owner || null,
    owner: normalizedEntry.owner || null,
    isShared: shared,
    isEncrypted: Boolean(encryption),
    expiresAt: expiration?.expiresAt || null,
    temporary: Boolean(expiration?.expiresAt),
    access: {
      public: normalizedEntry.public,
      owner: normalizedEntry.owner,
      users: normalizedEntry.users,
    },
    currentVersion: versions.currentVersion || 0,
    versionCount: versions.versions.length,
    encryption: getPublicEncryptionMetadata(encryption),
    canEdit: hasFileEditAccess(req, folder, file.name, caches.filePermissions),
    canManageAccess: canManageAccess(req) || hasFileEditAccess(req, folder, file.name, caches.filePermissions),
  };
}

async function listVisibleFilesForFolder(req, folder, caches = getFileListCaches()) {
  await syncFolderCacheFromCloud(folder.id, "uploads");
  const files = await listFilesWithDetailsAsync(folder.uploadDir);
  return files
    .map((file) => buildVisibleFileEntry(req, folder, file, caches))
    .filter(Boolean);
}

async function getWebDavVisibleFiles(req, folder) {
  const visible = await listVisibleFilesForFolder(req, folder);
  return visible.filter((file) => !isWebDavEncryptedFile(folder.id, file.name) && !isWebDavInternalStoredFile(folder.id, file.name));
}

async function resolveWebDavFile(req, folder, fileName) {
  const name = path.basename(String(fileName || ""));
  if (!name || name !== fileName) return null;
  if (!folder || !hasFolderAccess(req, folder)) return null;
  if (isWebDavInternalStoredFile(folder.id, name)) return null;
  if (isFileInTrash(folder.id, name)) return null;
  if (isWebDavFileExpired(folder.id, name)) return null;
  if (isWebDavEncryptedFile(folder.id, name)) {
    return { blocked: true, status: 403, message: "Arquivos criptografados nao estao disponiveis via WebDAV neste MVP" };
  }
  if (!hasFileAccess(req, folder, name)) return null;

  const filePath = path.join(folder.uploadDir, name);
  await ensureCloudFileCached(folder.id, name, filePath, "uploads");
  if (!isExistingFile(filePath)) return null;

  return {
    type: "file",
    folder,
    name,
    filePath,
    stats: fs.statSync(filePath),
  };
}

async function resolveWebDavTarget(req, segments) {
  const rootFolder = getWebDavRootFolder();

  if (!segments.length) {
    return { type: "root", folder: rootFolder };
  }

  if (segments.length === 1) {
    const folder = findWebDavFolderByName(req, segments[0]);
    if (folder) return { type: "folder", folder: hydrateFolderForWebDav(folder) };
    return resolveWebDavFile(req, rootFolder, segments[0]);
  }

  if (segments.length === 2) {
    const folder = findWebDavFolderByName(req, segments[0]);
    if (!folder) return null;
    return resolveWebDavFile(req, hydrateFolderForWebDav(folder), segments[1]);
  }

  return null;
}

function getWebDavUploadTarget(req, segments) {
  if (!Array.isArray(segments) || !segments.length || segments.length > 2) return null;

  let folder = getWebDavRootFolder();
  let fileName = segments[0];

  if (segments.length === 2) {
    const matchedFolder = findWebDavFolderByName(req, segments[0]);
    if (!matchedFolder) return null;
    folder = hydrateFolderForWebDav(matchedFolder);
    fileName = segments[1];
  } else if (findWebDavFolderByName(req, segments[0])) {
    return null;
  }

  if (!folder || !hasFolderAccess(req, folder)) return null;
  const safeName = path.basename(fileName);
  if (!safeName || safeName !== fileName || safeName === "." || safeName === "..") return null;
  return { folder, fileName: safeName };
}

function escapeXml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function encodeWebDavHrefSegment(segment) {
  return encodeURIComponent(segment).replace(/%20/g, "%20");
}

function getWebDavHref(segments = [], isCollection = false) {
  const suffix = segments.map(encodeWebDavHrefSegment).join("/");
  return `${WEBDAV_PATH}${suffix ? `/${suffix}` : ""}${isCollection ? "/" : ""}`;
}

function buildWebDavPropResponse({ href, displayName, isCollection, size = 0, modifiedAt = new Date(), contentType = "application/octet-stream" }) {
  const resourcetype = isCollection ? "<D:collection/>" : "";
  const fileProps = isCollection
    ? ""
    : `
          <D:getcontentlength>${Number(size) || 0}</D:getcontentlength>
          <D:getcontenttype>${escapeXml(contentType)}</D:getcontenttype>`;

  return `
      <D:response>
        <D:href>${escapeXml(href)}</D:href>
        <D:propstat>
          <D:prop>
            <D:displayname>${escapeXml(displayName)}</D:displayname>
            <D:resourcetype>${resourcetype}</D:resourcetype>
            <D:getlastmodified>${new Date(modifiedAt).toUTCString()}</D:getlastmodified>${fileProps}
          </D:prop>
          <D:status>HTTP/1.1 200 OK</D:status>
        </D:propstat>
      </D:response>`;
}

function rejectNonEmptyWebDavBody(req) {
  return new Promise((resolve, reject) => {
    let bytes = 0;
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error); else resolve();
    };
    req.on("data", (chunk) => {
      bytes += chunk.length;
      if (bytes > 0) {
        const error = new Error("PROPFIND request body is not supported");
        error.code = "WEBDAV_BODY_UNSUPPORTED";
        finish(error);
        req.resume();
      }
    });
    req.once("end", () => finish(bytes > 0 ? Object.assign(new Error("PROPFIND request body is not supported"), { code: "WEBDAV_BODY_UNSUPPORTED" }) : null));
    req.once("aborted", () => finish(Object.assign(new Error("PROPFIND request aborted"), { code: "WEBDAV_BODY_ABORTED" })));
    req.once("error", (error) => finish(error));
  });
}

async function sendWebDavPropfind(req, res, segments) {
  try {
    await rejectNonEmptyWebDavBody(req);
  } catch (error) {
    return res.status(400).send(error.code === "WEBDAV_BODY_ABORTED" ? "Invalid WebDAV request body" : "Non-empty PROPFIND bodies are unsupported");
  }
  const depth = String(req.headers.depth || "1");
  if (!["0", "1"].includes(depth)) return res.status(400).send("Unsupported WebDAV depth");
  const target = await resolveWebDavTarget(req, segments);
  if (!target || target.blocked) return res.status(target?.status || 404).send(target?.message || "Not found");

  const responses = [];

  if (target.type === "root") {
    responses.push(buildWebDavPropResponse({
      href: getWebDavHref([], true),
      displayName: "Root.ark",
      isCollection: true,
      modifiedAt: new Date(),
    }));

    if (depth !== "0") {
      for (const folder of getWebDavAccessibleFolders(req)) {
        responses.push(buildWebDavPropResponse({
          href: getWebDavHref([folder.name], true),
          displayName: folder.name,
          isCollection: true,
          modifiedAt: folder.updatedAt || folder.createdAt || new Date(),
        }));
      }

      const files = await getWebDavVisibleFiles(req, target.folder);
      for (const file of files) {
        responses.push(buildWebDavPropResponse({
          href: getWebDavHref([file.name]),
          displayName: file.name,
          isCollection: false,
          size: file.size,
          modifiedAt: file.modifiedAt || file.uploadedAt || new Date(),
          contentType: getMimeType(file.name),
        }));
      }
    }
  } else if (target.type === "folder") {
    responses.push(buildWebDavPropResponse({
      href: getWebDavHref([target.folder.name], true),
      displayName: target.folder.name,
      isCollection: true,
      modifiedAt: target.folder.updatedAt || target.folder.createdAt || new Date(),
    }));

    if (depth !== "0") {
      const files = await getWebDavVisibleFiles(req, target.folder);
      for (const file of files) {
        responses.push(buildWebDavPropResponse({
          href: getWebDavHref([target.folder.name, file.name]),
          displayName: file.name,
          isCollection: false,
          size: file.size,
          modifiedAt: file.modifiedAt || file.uploadedAt || new Date(),
          contentType: getMimeType(file.name),
        }));
      }
    }
  } else if (target.type === "file") {
    const parent = target.folder.id === ROOT_FOLDER_ID ? [] : [target.folder.name];
    responses.push(buildWebDavPropResponse({
      href: getWebDavHref([...parent, target.name]),
      displayName: target.name,
      isCollection: false,
      size: target.stats.size,
      modifiedAt: target.stats.mtime,
      contentType: getMimeType(target.name),
    }));
  }

  auditLog("webdav.list", getAuditActor(req), { type: "webdav", id: getSafeWebDavAuditPath(req) }, "list", "success", {
    depth,
    path: getSafeWebDavAuditPath(req),
  });
  return res
    .status(207)
    .set("Content-Type", "application/xml; charset=utf-8")
    .send(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">${responses.join("")}</D:multistatus>`);
}

async function sendWebDavFile(req, res, segments, headOnly = false) {
  const target = await resolveWebDavTarget(req, segments);
  if (!target || target.type !== "file") return res.status(target?.status || 404).send(target?.message || "Not found");

  auditLog("webdav.download", getAuditActor(req), { type: "file", id: target.name }, "download", "success", {
    folderId: target.folder.id,
    method: req.method,
    path: getSafeWebDavAuditPath(req),
  });

  if (headOnly) {
    res.setHeader("Content-Type", getMimeType(target.name));
    res.setHeader("Content-Length", target.stats.size);
    res.setHeader("Last-Modified", target.stats.mtime.toUTCString());
    return res.status(200).end();
  }

  return sendOptimizedFile(req, res, target.filePath, target.name, "attachment", { logDownload: false });
}

async function handleWebDavPut(req, res, segments) {
  if (!req.user?.permissions?.upload) return res.status(403).send("Upload permission required");

  const target = getWebDavUploadTarget(req, segments);
  if (!target) return res.status(409).send("Invalid upload target");

  const rawContentLength = req.headers["content-length"];
  const hasContentLength = rawContentLength !== undefined;
  const contentLength = hasContentLength && /^\d+$/.test(String(rawContentLength)) ? Number(rawContentLength) : null;
  if (hasContentLength && contentLength === null) {
    return res.status(400).send("Invalid Content-Length");
  }
  if (contentLength !== null && contentLength > SINGLE_UPLOAD_MAX_BYTES) {
    return res.status(413).send("File too large for WebDAV MVP upload");
  }

  const incomingPath = path.join(SIMPLE_UPLOAD_INCOMING_DIR, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}.webdav`);
  fs.mkdirSync(SIMPLE_UPLOAD_INCOMING_DIR, { recursive: true });
  let finalPath = null;

  try {
    let receivedBytes = 0;
    const limiter = new Transform({
      transform(chunk, encoding, callback) {
        receivedBytes += chunk.length;
        if (receivedBytes > SINGLE_UPLOAD_MAX_BYTES) {
          const error = new Error("WebDAV upload exceeds the byte limit");
          error.code = "WEBDAV_UPLOAD_TOO_LARGE";
          callback(error);
          return;
        }
        callback(null, chunk);
      },
    });
    await pipeline(req, limiter, fs.createWriteStream(incomingPath));
    const written = fs.statSync(incomingPath).size;
    if (written > SINGLE_UPLOAD_MAX_BYTES || (contentLength !== null && written !== contentLength)) {
      fs.rmSync(incomingPath, { force: true });
      return res.status(written > SINGLE_UPLOAD_MAX_BYTES ? 413 : 400).send(written > SINGLE_UPLOAD_MAX_BYTES ? "File too large for WebDAV MVP upload" : "Content-Length mismatch");
    }

    const finalFileName = getAvailableUploadFileName(target.fileName, target.folder.id, true);
    finalPath = path.join(target.folder.tempDir, finalFileName);
    fs.mkdirSync(target.folder.tempDir, { recursive: true });
    fs.renameSync(incomingPath, finalPath);
    const scan = await scanUploadBeforePending(req, {
      filePath: finalPath,
      fileName: finalFileName,
      originalName: target.fileName,
      folderId: target.folder.id,
      size: written,
    });
    if (!scan.allowed) {
      fs.rmSync(finalPath, { force: true });
      return res.status(scan.status || 400).send(scan.error || "Upload bloqueado por seguranca");
    }

    req.uploadFolder = target.folder;
    registerPendingUpload(req, {
      fileName: finalFileName,
      originalName: target.fileName,
      size: written,
      mimeType: getMimeType(target.fileName),
    });

    auditLog("webdav.upload", getAuditActor(req), { type: "file", id: finalFileName }, "upload", "success", {
      folderId: target.folder.id,
      path: getSafeWebDavAuditPath(req),
      pendingApproval: true,
      originalName: target.fileName,
    });
    broadcastDataChanged("pending", { action: "webdav_upload", folderId: target.folder.id, fileName: finalFileName });
    return res.status(201).send("Created");
  } catch (error) {
    fs.rmSync(incomingPath, { force: true });
    if (typeof finalPath === "string") fs.rmSync(finalPath, { force: true });
    auditLog("webdav.error", getAuditActor(req), { type: "webdav", id: getSafeWebDavAuditPath(req) }, "upload", "failure", {
      error: error.message,
      path: getSafeWebDavAuditPath(req),
    });
    return res.status(error.code === "WEBDAV_UPLOAD_TOO_LARGE" ? 413 : error.code === "ABORT_ERR" ? 400 : 500).send(error.code === "WEBDAV_UPLOAD_TOO_LARGE" ? "File too large for WebDAV MVP upload" : "Upload failed");
  }
}

function handleWebDavMkcol(req, res, segments) {
  if (!canCreateFolders(req)) return res.status(403).send("Folder creation permission required");
  if (!Array.isArray(segments) || segments.length !== 1) return res.status(409).send("Nested WebDAV folders are not supported in this MVP");

  const name = sanitizeFolderName(segments[0]);
  if (!name || name !== segments[0]) return res.status(400).send("Invalid folder name");
  if (findWebDavFolderByName(req, name)) return res.status(405).send("Collection already exists");

  const folders = loadFolders();
  const folder = {
    id: createFolderId(),
    name,
    createdBy: req.user.username,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    users: {},
    allowedUsers: [],
    isRoot: false,
  };
  folders.push(folder);
  saveFolders(folders);
  ensureFolderDirectories(folder.id);
  auditLog("webdav.mkdir", getAuditActor(req), { type: "folder", id: folder.id }, "created", "success", {
    folderName: folder.name,
    path: getSafeWebDavAuditPath(req),
  });
  addActionHistory("folder_created_webdav", folder.name, req.user.username, { folderId: folder.id, folderName: folder.name });
  broadcastDataChanged("folders", { action: "webdav_mkdir", folderId: folder.id });
  return res.status(201).send("Created");
}

function getWebDavMoveDestination(req) {
  const destination = String(req.headers.destination || "");
  if (!destination) return null;
  let target;
  try {
    target = new URL(destination, getExpectedOrigin(req));
  } catch {
    return null;
  }
  if (target.origin !== getExpectedOrigin(req)) return null;
  return parseWebDavSegments({ originalUrl: target.pathname, url: target.pathname });
}

function snapshotWebDavMoveMetadata() {
  return Object.fromEntries(WEBDAV_MOVE_METADATA_FILES.map((file) => [file, fs.existsSync(file) ? fs.readFileSync(file) : null]));
}

function sha256Buffer(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function webDavMoveFileIdentity(filePath) {
  if (!fs.existsSync(filePath)) return { exists: false, size: 0, checksum: null };
  const contents = fs.readFileSync(filePath);
  return { exists: true, size: contents.length, checksum: sha256Buffer(contents) };
}

function beginWebDavMoveLocalIntent(journal, operation, phase) {
  journal.pendingOperation = operation;
  journal.phase = phase;
  writeWebDavMoveJournal(journal);
}

function webDavMoveIdentityMatches(filePath, identity) {
  if (!identity?.exists || !fs.existsSync(filePath)) return false;
  const current = webDavMoveFileIdentity(filePath);
  return current.size === identity.size && current.checksum === identity.checksum;
}

function writeWebDavMoveFileAtomically(filePath, contents) {
  const temporary = `${filePath}.${crypto.randomUUID()}.tmp`;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const descriptor = fs.openSync(temporary, "w");
  try {
    fs.writeFileSync(descriptor, contents);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, filePath);
}

function persistWebDavMoveMetadataSnapshot(transactionId, snapshot) {
  const directory = path.resolve(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${transactionId}`, "metadata");
  if (!isSafeChildPath(WEBDAV_MOVE_JOURNAL_DIR, directory)) throw new Error("Invalid WebDAV metadata snapshot path");
  fs.mkdirSync(directory, { recursive: true });
  const files = {};
  for (const [file, contents] of Object.entries(snapshot || {})) {
    const snapshotPath = path.resolve(directory, `${Object.keys(files).length}-${path.basename(file)}.snapshot`);
    if (!isSafeChildPath(directory, snapshotPath)) throw new Error("Invalid WebDAV metadata snapshot path");
    if (contents === null) {
      files[file] = { present: false, path: snapshotPath, checksum: null };
    } else {
      writeWebDavMoveFileAtomically(snapshotPath, contents);
      files[file] = { present: true, path: snapshotPath, checksum: sha256Buffer(contents) };
    }
  }
  return { directory, files };
}

function restoreWebDavMoveMetadata(snapshot) {
  const persisted = snapshot?.files ? snapshot : null;
  for (const [file, value] of Object.entries(persisted?.files || snapshot || {})) {
    const target = path.resolve(file);
    if (!WEBDAV_MOVE_METADATA_FILES.includes(file)) throw new Error("Unknown WebDAV metadata store");
    if (persisted) {
      const snapshotPath = path.resolve(String(value.path || ""));
      if (!isSafeChildPath(persisted.directory, snapshotPath)) throw new Error("Invalid WebDAV metadata snapshot path");
      if (!value.present) {
        fs.rmSync(target, { force: true });
        continue;
      }
      const contents = fs.readFileSync(snapshotPath);
      if (sha256Buffer(contents) !== value.checksum) throw new Error("WebDAV metadata snapshot checksum mismatch");
      writeWebDavMoveFileAtomically(target, contents);
      continue;
    }
    if (value === null) fs.rmSync(target, { force: true });
    else writeWebDavMoveFileAtomically(target, value);
  }
}

function writeWebDavMoveJournal(journal) {
  fs.mkdirSync(WEBDAV_MOVE_JOURNAL_DIR, { recursive: true });
  const temporary = `${journal.journalPath}.${journal.transactionId}.tmp`;
  const descriptor = fs.openSync(temporary, "w");
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(journal)}\n`);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  fs.renameSync(temporary, journal.journalPath);
}

function isSafeWebDavMoveJournal(journal) {
  if (!journal || journal.version !== 1 || !/^[a-f0-9-]{36}$/i.test(String(journal.transactionId || ""))) return false;
  const expectedJournal = path.resolve(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${journal.transactionId}.json`);
  if (path.resolve(journal.journalPath || "") !== expectedJournal) return false;
  if ([journal.sourcePath, journal.destinationPath, journal.stagePath, journal.destinationBackupPath].some((target) => typeof target !== "string" || !isSafeChildPath(path.resolve("."), target))) return false;
  const sourceDir = path.dirname(path.resolve(journal.sourcePath));
  if (!journal.metadata?.directory || !isSafeChildPath(WEBDAV_MOVE_JOURNAL_DIR, journal.metadata.directory)) return false;
  if (!journal.metadata?.files || Object.keys(journal.metadata.files).some((file) => !WEBDAV_MOVE_METADATA_FILES.includes(file))) return false;
  if (Object.values(journal.metadata.files).some((entry) => !entry || !isSafeChildPath(journal.metadata.directory, entry.path))) return false;
  return path.dirname(path.resolve(journal.destinationPath)) === sourceDir &&
    path.dirname(path.resolve(journal.stagePath)) === sourceDir &&
    path.dirname(path.resolve(journal.destinationBackupPath)) === sourceDir &&
    isSafeChildPath(path.resolve("./uploads"), sourceDir);
}

function rollbackWebDavMoveJournal(journal) {
  if (!isSafeWebDavMoveJournal(journal)) throw new Error("Journal WebDAV invalido");
  const sourcePath = path.resolve(journal.sourcePath);
  const destinationPath = path.resolve(journal.destinationPath);
  const stagePath = path.resolve(journal.stagePath);
  const destinationBackupPath = path.resolve(journal.destinationBackupPath);
  if (journal.pendingOperation === "source.stage" && fs.existsSync(sourcePath) && fs.existsSync(stagePath)) {
    throw new Error("Ambiguous MOVE source/stage evidence");
  }
  if (journal.pendingOperation === "destination.preserve" && fs.existsSync(destinationPath) && fs.existsSync(destinationBackupPath)) {
    throw new Error("Ambiguous MOVE destination/backup evidence");
  }
  if (journal.pendingOperation === "replacement.install" && !fs.existsSync(stagePath) && webDavMoveIdentityMatches(destinationPath, journal.sourceIdentity)) {
    journal.replacementInstalled = true;
  }
  if (fs.existsSync(destinationPath) && (journal.replacementInstalled || journal.pendingOperation === "replacement.install" || journal.completedOperations.includes("replacement.install"))) {
    if (journal.sourceIdentity && !webDavMoveIdentityMatches(destinationPath, journal.sourceIdentity)) throw new Error("Conflicting MOVE replacement bytes");
    fs.renameSync(destinationPath, stagePath);
  }
  if (fs.existsSync(destinationBackupPath)) {
    if (journal.destinationIdentity && !webDavMoveIdentityMatches(destinationBackupPath, journal.destinationIdentity)) throw new Error("Conflicting MOVE destination backup bytes");
    fs.renameSync(destinationBackupPath, destinationPath);
  }
  if (fs.existsSync(stagePath)) {
    if (journal.sourceIdentity && !webDavMoveIdentityMatches(stagePath, journal.sourceIdentity)) throw new Error("Conflicting MOVE source stage bytes");
    fs.renameSync(stagePath, sourcePath);
  }
  fs.rmSync(journal.journalPath, { force: true });
  fs.rmSync(journal.metadata.directory, { recursive: true, force: true });
  fs.rmSync(path.dirname(journal.metadata.directory), { recursive: true, force: true });
}

function isDurablyCompletedWebDavMove(journal) {
  return ["committed", "cloud_complete", "completed", "cleanup_intent", "cleanup_completed"].includes(journal.phase) || journal.cloud?.state === "completed";
}

function finalizeWebDavMoveJournal(journal) {
  if (!isSafeWebDavMoveJournal(journal)) throw new Error("Journal WebDAV invalido");
  journal.phase = "committed";
  writeWebDavMoveJournal(journal);
  const cleanup = (operation, target, options = {}) => {
    journal.pendingOperation = operation;
    journal.phase = "cleanup_intent";
    writeWebDavMoveJournal(journal);
    fs.rmSync(target, { force: true, ...options });
    journal.pendingOperation = null;
    journal.completedOperations.push(operation);
    journal.phase = "cleanup_completed";
    writeWebDavMoveJournal(journal);
  };
  cleanup("cleanup.destination_backup", journal.destinationBackupPath);
  cleanup("cleanup.stage", journal.stagePath);
  cleanup("cleanup.metadata", journal.metadata.directory, { recursive: true });
  cleanup("cleanup.metadata_parent", path.dirname(journal.metadata.directory), { recursive: true });
  cleanup("cleanup.claim", webDavMoveLockPath(journal.transactionId));
  journal.pendingOperation = "cleanup.journal";
  journal.phase = "cleanup_intent";
  writeWebDavMoveJournal(journal);
  fs.rmSync(journal.journalPath, { force: true });
}

function cleanupOrphanWebDavMoveArtifacts() {
  if (!fs.existsSync(WEBDAV_MOVE_JOURNAL_DIR)) return;
  const transactionPattern = /^rootark-webdav-move-([a-f0-9-]{36})$/i;
  for (const name of fs.readdirSync(WEBDAV_MOVE_JOURNAL_DIR)) {
    const match = transactionPattern.exec(name);
    if (!match) continue;
    const directory = path.resolve(WEBDAV_MOVE_JOURNAL_DIR, name);
    const journalPath = path.resolve(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${match[1]}.json`);
    if (fs.existsSync(journalPath) || !isSafeChildPath(WEBDAV_MOVE_JOURNAL_DIR, directory)) continue;
    fs.rmSync(directory, { recursive: true, force: true });
    fs.rmSync(webDavMoveLockPath(match[1]), { force: true });
  }
  for (const name of fs.readdirSync(WEBDAV_MOVE_JOURNAL_DIR).filter((entry) => /^rootark-webdav-move-[a-f0-9-]{36}\.lock$/i.test(entry))) {
    const transactionId = name.slice("rootark-webdav-move-".length, -".lock".length);
    const journalPath = path.resolve(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${transactionId}.json`);
    if (!fs.existsSync(journalPath)) fs.rmSync(path.join(WEBDAV_MOVE_JOURNAL_DIR, name), { force: true });
  }
}

function recoverWebDavMoveJournals() {
  if (!fs.existsSync(WEBDAV_MOVE_JOURNAL_DIR)) return;
  recoverWebDavMoveClaimTakeovers();
  for (const name of fs.readdirSync(WEBDAV_MOVE_JOURNAL_DIR).filter((entry) => /^rootark-webdav-move-[a-f0-9-]{36}\.json$/i.test(entry))) {
    const journalPath = path.join(WEBDAV_MOVE_JOURNAL_DIR, name);
    let journal;
    try { journal = JSON.parse(fs.readFileSync(journalPath, "utf8")); } catch { throw new Error("Journal WebDAV invalido"); }
    if (!isSafeWebDavMoveJournal(journal)) throw new Error("Journal WebDAV ambiguo");
    if (isDurablyCompletedWebDavMove(journal)) {
      finalizeWebDavMoveJournal(journal);
      continue;
    }
    if (journal.phase === "terminal_reconciliation_failure" || journal.cloud?.state === "terminal_reconciliation_failure") continue;
    if (WEBDAV_MOVE_REMOTE_INTENT_STATES.has(journal.phase) || WEBDAV_MOVE_REMOTE_INTENT_STATES.has(journal.cloud?.state)) continue;
    restoreWebDavMoveMetadata(journal.metadata);
    rollbackWebDavMoveJournal(journal);
  }
  cleanupOrphanWebDavMoveArtifacts();
}

function webDavCloudTransition(journal, state, at, details = {}) {
  journal.cloud = {
    ...journal.cloud,
    ...details,
    state,
    transitions: [...(Array.isArray(journal.cloud?.transitions) ? journal.cloud.transitions : []), { state, at }],
  };
  journal.phase = state === "completed" ? "cloud_complete" : state === "terminal_reconciliation_failure" ? "terminal_reconciliation_failure" : state === "retry_wait" ? "cloud_source_removal_pending" : state === "claimed" ? "cloud_reconciliation_claimed" : state === "destination_upload_intent" ? "cloud_destination_upload_intent" : state === "destination_upload_uncertain" ? "cloud_destination_upload_uncertain" : state === "destination_uploaded" ? "cloud_destination_uploaded" : state === "source_delete_intent" ? "cloud_source_delete_intent" : state === "source_delete_uncertain" ? "cloud_source_delete_uncertain" : journal.phase;
  return journal;
}

function webDavCloudFailureCategory(error) {
  const code = String(error?.code || "");
  if (["not_found", "NoSuchKey", "NotFound", "missing_object"].includes(code) || error?.missing === true) return "source_already_absent";
  if (["already_exists", "PreconditionFailed", "duplicate"].includes(code)) return "destination_already_uploaded";
  if (["configuration", "invalid_path", "unsupported_provider"].includes(code)) return code;
  return "provider_error";
}

function webDavMoveLockPath(transactionId) {
  return path.join(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${transactionId}.lock`);
}

function webDavMoveClaimToken(contents) {
  try { return JSON.parse(contents).token || null; } catch { return String(contents || ""); }
}

function webDavMoveClaimRecord(token, transactionId, now) {
  return { version: 1, token, transactionId, pid: process.pid, processStartIdentity: webDavMoveProcessStartIdentity(process.pid), claimedAt: new Date(now).toISOString() };
}

function webDavMoveProcessStartIdentity(pid) {
  if (process.platform !== "linux") return null;
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
    return stat.slice(stat.lastIndexOf(")") + 1).trim().split(/\s+/)[19] || null;
  } catch {
    return null;
  }
}

function webDavMoveOwnerIsLive(record) {
  if (!Number.isInteger(Number(record?.pid)) || Number(record.pid) <= 0) return false;
  try { process.kill(Number(record.pid), 0); } catch (error) { return error.code === "EPERM"; }
  if (record.processStartIdentity && webDavMoveProcessStartIdentity(Number(record.pid))) return record.processStartIdentity === webDavMoveProcessStartIdentity(Number(record.pid));
  return true;
}

function validWebDavMoveClaimRecord(record, transactionId) {
  return record && record.version === 1 && typeof record.token === "string" && record.token && record.transactionId === transactionId && Number.isInteger(Number(record.pid)) && Number(record.pid) > 0 && typeof record.claimedAt === "string" && Number.isFinite(Date.parse(record.claimedAt));
}

function webDavMoveFileStatIdentity(stat) {
  return stat ? { dev: stat.dev, ino: stat.ino, size: stat.size, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs, birthtimeMs: stat.birthtimeMs } : null;
}

function webDavMoveSameStatIdentity(left, right) {
  return Boolean(left && right && ["dev", "ino", "size", "mtimeMs", "ctimeMs", "birthtimeMs"].every((key) => left[key] === right[key]));
}

function webDavMoveSameRenamedIdentity(left, right) {
  return Boolean(left && right && ["dev", "ino", "size", "mtimeMs", "birthtimeMs"].every((key) => left[key] === right[key]));
}

function webDavMoveClaimObservation(contents, stat) {
  return { contents, stat };
}

function webDavMoveTakeoverDir(lockPath) {
  return `${lockPath}.takeover`;
}

function webDavMoveTakeoverMeta(lockPath) {
  return path.join(webDavMoveTakeoverDir(lockPath), "authority.json");
}

function webDavMoveTakeoverEvidence(lockPath) {
  return path.join(webDavMoveTakeoverDir(lockPath), "evidence");
}

function webDavMoveTakeoverObservation(observed) {
  return { sha256: sha256Buffer(Buffer.from(observed.contents)), size: Buffer.byteLength(observed.contents), stat: webDavMoveFileStatIdentity(observed.stat) };
}

function webDavMoveReadTakeoverAuthority(lockPath, transactionId) {
  const takeoverDir = webDavMoveTakeoverDir(lockPath);
  let stat;
  try {
    const link = fs.lstatSync(takeoverDir);
    if (!link.isDirectory() || link.isSymbolicLink() || !isSafeChildPath(WEBDAV_MOVE_JOURNAL_DIR, takeoverDir)) return { kind: "ambiguous" };
    stat = link;
  } catch (error) {
    if (error.code === "ENOENT") return { kind: "missing" };
    throw error;
  }
  let record;
  try { record = JSON.parse(fs.readFileSync(webDavMoveTakeoverMeta(lockPath), "utf8")); } catch { return { kind: "malformed", mtimeMs: stat.mtimeMs }; }
  const expectedLock = webDavMoveLockPath(transactionId);
  if (record?.version !== 1 || typeof record.token !== "string" || !record.token || record.transactionId !== transactionId || path.resolve(record.lockPath || "") !== path.resolve(expectedLock) || path.resolve(record.evidencePath || "") !== path.resolve(webDavMoveTakeoverEvidence(lockPath)) || !Number.isInteger(Number(record.pid)) || Number(record.pid) <= 0 || !Number.isFinite(Date.parse(record.claimedAt || "")) || !record.observed?.sha256 || !Number.isInteger(record.observed.size) || !record.observed.stat) return { kind: "mismatch", record };
  return { kind: "valid", record, live: webDavMoveOwnerIsLive(record), mtimeMs: stat.mtimeMs };
}

function webDavMoveEvidenceMatchesAuthority(lockPath, authority) {
  let stat;
  let contents;
  try {
    const link = fs.lstatSync(webDavMoveTakeoverEvidence(lockPath));
    if (!link.isFile() || link.isSymbolicLink()) return false;
    stat = link;
    contents = fs.readFileSync(webDavMoveTakeoverEvidence(lockPath));
  } catch (error) {
    return error.code === "ENOENT";
  }
  return sha256Buffer(contents) === authority.observed.sha256 && contents.length === authority.observed.size && webDavMoveSameRenamedIdentity(webDavMoveFileStatIdentity(stat), authority.observed.stat) && webDavMoveClaimToken(contents.toString()) === authority.previousToken;
}

function webDavMoveRemoveTakeoverAuthority(lockPath, transactionId, token) {
  const state = webDavMoveReadTakeoverAuthority(lockPath, transactionId);
  if (state.kind === "missing") return;
  if (state.kind !== "valid" || state.record.token !== token) throw Object.assign(new Error("WebDAV claim takeover evidence is ambiguous"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
  if (!webDavMoveEvidenceMatchesAuthority(lockPath, state.record)) throw Object.assign(new Error("WebDAV claim takeover evidence is ambiguous"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
  try { fs.rmSync(webDavMoveTakeoverEvidence(lockPath), { force: false }); } catch (error) { if (error.code !== "ENOENT") throw error; }
  try { fs.rmSync(webDavMoveTakeoverMeta(lockPath), { force: false }); } catch (error) { if (error.code !== "ENOENT") throw error; }
  try { fs.rmdirSync(webDavMoveTakeoverDir(lockPath)); } catch (error) { if (error.code !== "ENOENT") throw error; }
}

function webDavMoveRecoverTakeoverAuthority(lockPath, transactionId) {
  const state = webDavMoveReadTakeoverAuthority(lockPath, transactionId);
  if (state.kind === "missing") return;
  if (state.kind === "valid" && state.live) throw Object.assign(new Error("WebDAV MOVE claim takeover is still owned"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
  if (state.kind === "malformed") {
    if (Date.now() - state.mtimeMs <= WEBDAV_MOVE_RECONCILIATION_LEASE_MS) throw Object.assign(new Error("WebDAV claim takeover evidence is malformed"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
    if (fs.readdirSync(webDavMoveTakeoverDir(lockPath)).length) throw Object.assign(new Error("WebDAV claim takeover evidence is ambiguous"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
    fs.rmdirSync(webDavMoveTakeoverDir(lockPath));
    return;
  }
  if (state.kind !== "valid") throw Object.assign(new Error("WebDAV claim takeover evidence is ambiguous"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
  webDavMoveRemoveTakeoverAuthority(lockPath, transactionId, state.record.token);
}

function writeWebDavMoveClaimLock(lockPath, record) {
  let fd;
  try {
    fd = fs.openSync(lockPath, "wx");
    const contents = Buffer.from(JSON.stringify(record));
    fs.writeSync(fd, contents, 0, contents.length);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
  } catch (error) {
    try { if (fd !== undefined) fs.closeSync(fd); } catch {}
    throw error;
  }
}

function recoverWebDavMoveClaimTakeovers() {
  if (!fs.existsSync(WEBDAV_MOVE_JOURNAL_DIR)) return;
  const names = fs.readdirSync(WEBDAV_MOVE_JOURNAL_DIR).filter((entry) => /^rootark-webdav-move-[a-f0-9-]{36}\.lock\.takeover$/i.test(entry));
  for (const name of names) {
    const match = name.match(/^rootark-webdav-move-([a-f0-9-]{36})\.lock\.takeover$/i);
    if (!match) continue;
    const lockPath = webDavMoveLockPath(match[1]);
    webDavMoveRecoverTakeoverAuthority(lockPath, match[1]);
  }
}

function takeoverWebDavMoveClaim(lockPath, transactionId, previousToken, observed, now) {
  const ownerToken = `${crypto.randomUUID()}:${crypto.randomUUID()}`;
  const takeoverDir = webDavMoveTakeoverDir(lockPath);
  const authority = { version: 1, transactionId, lockPath, evidencePath: webDavMoveTakeoverEvidence(lockPath), token: ownerToken, previousToken, pid: process.pid, processStartIdentity: webDavMoveProcessStartIdentity(process.pid), claimedAt: new Date(now).toISOString(), observed: webDavMoveTakeoverObservation(observed) };
  try {
    webDavMoveRecoverTakeoverAuthority(lockPath, transactionId);
    fs.mkdirSync(takeoverDir, { recursive: false });
    writeWebDavMoveFileAtomically(webDavMoveTakeoverMeta(lockPath), JSON.stringify(authority));
    let currentStat;
    let currentContents;
    try { currentStat = fs.statSync(lockPath); currentContents = fs.readFileSync(lockPath, "utf8"); } catch (error) { if (error.code === "ENOENT") return null; throw error; }
    if (currentContents !== observed.contents || !webDavMoveSameStatIdentity(webDavMoveFileStatIdentity(currentStat), webDavMoveFileStatIdentity(observed.stat)) || webDavMoveClaimToken(currentContents) !== previousToken) { webDavMoveRemoveTakeoverAuthority(lockPath, transactionId, ownerToken); return null; }
    fs.renameSync(lockPath, webDavMoveTakeoverEvidence(lockPath));
    if (!webDavMoveEvidenceMatchesAuthority(lockPath, authority)) throw new Error("WebDAV claim evidence changed during takeover");
    writeWebDavMoveClaimLock(lockPath, webDavMoveClaimRecord(ownerToken, transactionId, now));
    if (webDavMoveClaimToken(fs.readFileSync(lockPath, "utf8")) !== ownerToken) throw new Error("WebDAV replacement claim was not confirmed");
    webDavMoveRemoveTakeoverAuthority(lockPath, transactionId, ownerToken);
    return ownerToken;
  } catch (error) {
    try { webDavMoveRemoveTakeoverAuthority(lockPath, transactionId, ownerToken); } catch {}
    if (error.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function releaseWebDavMoveClaim(claim) {
  if (!claim?.path) return;
  try { if (webDavMoveClaimToken(fs.readFileSync(claim.path, "utf8")) === claim.token) fs.rmSync(claim.path, { force: true }); } catch {}
}

function claimWebDavMoveJournal(journal, now = Date.now(), workerId = crypto.randomUUID()) {
  const cloud = journal.cloud || {};
  if (!journal || !["queued", "destination_upload_intent", "destination_upload_uncertain", "source_delete_intent", "source_delete_uncertain", "retry_wait", "destination_uploaded", "claimed"].includes(cloud.state)) return null;
  if (cloud.nextAttemptAt && new Date(cloud.nextAttemptAt).getTime() > now) return null;
  if (cloud.leaseToken && new Date(cloud.leaseUntil || 0).getTime() > now) return null;
  recoverWebDavMoveClaimTakeovers();
  const token = `${workerId}:${crypto.randomUUID()}`;
  const lockPath = webDavMoveLockPath(journal.transactionId);
  fs.mkdirSync(WEBDAV_MOVE_JOURNAL_DIR, { recursive: true });
  try {
    writeWebDavMoveClaimLock(lockPath, webDavMoveClaimRecord(token, journal.transactionId, now));
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    try {
      const existingStat = fs.statSync(lockPath);
      const existing = fs.readFileSync(lockPath, "utf8");
      const existingRecord = (() => { try { return JSON.parse(existing); } catch { return null; } })();
      if (!validWebDavMoveClaimRecord(existingRecord, journal.transactionId) || webDavMoveOwnerIsLive(existingRecord)) return null;
      const leaseExpired = existingRecord?.claimedAt ? Date.parse(existingRecord.claimedAt) + WEBDAV_MOVE_RECONCILIATION_LEASE_MS <= now : fs.statSync(lockPath).mtimeMs + WEBDAV_MOVE_RECONCILIATION_LEASE_MS <= now;
      if (!leaseExpired) return null;
      const takeover = takeoverWebDavMoveClaim(lockPath, journal.transactionId, existingRecord.token, webDavMoveClaimObservation(existing, existingStat), now);
      if (!takeover) return null;
      return finalizeWebDavMoveClaim(journal, lockPath, takeover, workerId, now);
    } catch { return null; }
  }
  return finalizeWebDavMoveClaim(journal, lockPath, token, workerId, now);
}

function finalizeWebDavMoveClaim(journal, lockPath, ownerToken, workerId, now) {
  try {
    const current = JSON.parse(fs.readFileSync(journal.journalPath, "utf8"));
    if (current.cloud?.leaseToken && new Date(current.cloud.leaseUntil || 0).getTime() > now) { releaseWebDavMoveClaim({ path: lockPath, token: ownerToken }); return null; }
    const at = new Date(now).toISOString();
    const claimed = webDavCloudTransition(current, "claimed", at, {
      attempts: Math.min(Number(current.cloud.maxAttempts) || WEBDAV_MOVE_RECONCILIATION_MAX_ATTEMPTS, (Number(current.cloud.attempts) || 0) + 1),
      lastAttemptAt: at,
      nextAttemptAt: null,
      leaseToken: ownerToken,
      leaseUntil: new Date(now + WEBDAV_MOVE_RECONCILIATION_LEASE_MS).toISOString(),
      workerId,
    });
    writeWebDavMoveJournal(claimed);
    return { journal: claimed, token: ownerToken, path: lockPath };
  } catch (error) {
    releaseWebDavMoveClaim({ path: lockPath, token: ownerToken });
    throw error;
  }
}

function markWebDavMoveRetry(journal, error, now = Date.now()) {
  const attempts = Number(journal.cloud.attempts) || 0;
  const maxAttempts = Number(journal.cloud.maxAttempts) || WEBDAV_MOVE_RECONCILIATION_MAX_ATTEMPTS;
  const terminal = attempts >= maxAttempts;
  const at = new Date(now).toISOString();
  const nextAttemptAt = terminal ? null : new Date(now + Math.min(WEBDAV_MOVE_RECONCILIATION_MAX_BACKOFF_MS, 1000 * (2 ** Math.max(0, attempts - 1)))).toISOString();
  webDavCloudTransition(journal, terminal ? "terminal_reconciliation_failure" : "retry_wait", at, {
    maxAttempts,
    nextAttemptAt,
    leaseToken: null,
    leaseUntil: null,
    failureCategory: webDavCloudFailureCategory(error),
    terminalAt: terminal ? at : null,
  });
  writeWebDavMoveJournal(journal);
  return terminal;
}

async function reconcileWebDavMoveCloud(journal, { claimToken = null, now = Date.now() } = {}) {
  if (!journal.cloud || !isCloudStorageEnabled()) {
    webDavCloudTransition(journal, "completed", new Date(now).toISOString(), { completedAt: new Date(now).toISOString(), leaseToken: null, leaseUntil: null });
    writeWebDavMoveJournal(journal);
    return { pending: false };
  }
  if (claimToken && journal.cloud.leaseToken !== claimToken) throw Object.assign(new Error("MOVE claim mismatch"), { code: "WEBDAV_MOVE_CLAIM_MISMATCH" });
  const { folderId, sourceName, destinationName } = journal.cloud;
  if (!journal.cloud.destinationUploaded) {
    webDavCloudTransition(journal, "destination_upload_intent", new Date(now).toISOString(), { failureCategory: null });
    writeWebDavMoveJournal(journal);
    webDavCloudTransition(journal, "destination_upload_uncertain", new Date(now).toISOString());
    writeWebDavMoveJournal(journal);
    try {
      await uploadFileToCloud(journal.destinationPath, folderId, destinationName, "uploads");
    } catch (error) {
      if (!['already_exists', 'PreconditionFailed', 'duplicate'].includes(String(error?.code || ""))) {
        const terminal = markWebDavMoveRetry(journal, error, now);
        return { pending: !terminal, terminal, error };
      }
    }
    journal.cloud.destinationUploaded = true;
    journal.completedOperations.push("cloud.destination.upload");
    webDavCloudTransition(journal, "destination_uploaded", new Date(now).toISOString(), { failureCategory: null });
    writeWebDavMoveJournal(journal);
  }
  if (!journal.cloud.lastAttemptAt) {
    journal.cloud.attempts = Math.max(1, Number(journal.cloud.attempts) || 0);
    journal.cloud.lastAttemptAt = new Date(now).toISOString();
    writeWebDavMoveJournal(journal);
  }
  if (!journal.cloud.sourceRemoved) {
    webDavCloudTransition(journal, "source_delete_intent", new Date(now).toISOString(), { failureCategory: null });
    writeWebDavMoveJournal(journal);
    webDavCloudTransition(journal, "source_delete_uncertain", new Date(now).toISOString());
    writeWebDavMoveJournal(journal);
    try {
      await deleteFileFromCloud(folderId, sourceName, "uploads");
    } catch (error) {
      if (webDavCloudFailureCategory(error) === "source_already_absent") {
        // Deleting an already-absent source is the idempotent success case.
      } else {
        const terminal = markWebDavMoveRetry(journal, error, now);
        return { pending: !terminal, terminal, error };
      }
    }
    journal.cloud.sourceRemoved = true;
    journal.completedOperations.push("cloud.source.remove");
    webDavCloudTransition(journal, "completed", new Date(now).toISOString(), { completedAt: new Date(now).toISOString(), nextAttemptAt: null, failureCategory: null, leaseToken: null, leaseUntil: null });
    writeWebDavMoveJournal(journal);
  }
  return { pending: false };
}

async function resumeWebDavMoveCloudJournals() {
  if (webDavReconciliationRunning || !fs.existsSync(WEBDAV_MOVE_JOURNAL_DIR)) return;
  webDavReconciliationRunning = true;
  try {
    for (const name of fs.readdirSync(WEBDAV_MOVE_JOURNAL_DIR).filter((entry) => /^rootark-webdav-move-[a-f0-9-]{36}\.json$/i.test(entry))) {
      const journalPath = path.join(WEBDAV_MOVE_JOURNAL_DIR, name);
      let journal;
      try { journal = JSON.parse(fs.readFileSync(journalPath, "utf8")); } catch { continue; }
      if (!isSafeWebDavMoveJournal(journal)) continue;
      const claim = claimWebDavMoveJournal(journal);
      if (!claim) continue;
      try {
        const result = await reconcileWebDavMoveCloud(claim.journal, { claimToken: claim.token });
        if (!result.pending && !result.terminal) {
          auditLog("webdav.move.reconciliation.completed", { username: "system", role: "system" }, { type: "webdav_move", id: claim.journal.transactionId }, "reconcile", "success", { attempts: claim.journal.cloud.attempts });
          finalizeWebDavMoveJournal(claim.journal);
        } else if (result.terminal) {
          auditLog("webdav.move.reconciliation.terminal", { username: "system", role: "system" }, { type: "webdav_move", id: claim.journal.transactionId }, "reconcile", "failure", { category: claim.journal.cloud.failureCategory, attempts: claim.journal.cloud.attempts });
        } else {
          auditLog("webdav.move.reconciliation.retry", { username: "system", role: "system" }, { type: "webdav_move", id: claim.journal.transactionId }, "reconcile", "pending", { category: claim.journal.cloud.failureCategory, attempts: claim.journal.cloud.attempts });
        }
      } catch (error) {
        try { markWebDavMoveRetry(JSON.parse(fs.readFileSync(journalPath, "utf8")), error); } catch {}
      } finally {
        releaseWebDavMoveClaim(claim);
      }
    }
  } finally {
    webDavReconciliationRunning = false;
  }
}

async function handleWebDavMove(req, res, segments) {
  if (!WEBDAV_ALLOW_MOVE) return res.status(405).send("MOVE is disabled for WebDAV MVP");
  if (!req.user?.permissions?.upload) return res.status(403).send("Upload permission required");
  const source = await resolveWebDavTarget(req, segments);
  const destinationSegments = getWebDavMoveDestination(req);
  const destination = destinationSegments && getWebDavUploadTarget(req, destinationSegments);
  if (!source || source.type !== "file" || !destination) return res.status(409).send("Invalid MOVE target");
  if (source.folder.id !== destination.folder.id) return res.status(403).send("Cross-folder MOVE is not supported");
  if (!hasFileEditAccess(req, source.folder, source.name)) return res.status(403).send("Permission denied");
  if (source.name === destination.fileName) return res.status(403).send("Source and destination are identical");
  const destinationPath = path.join(source.folder.uploadDir, destination.fileName);
  if (!isSafeChildPath(source.folder.uploadDir, source.filePath) || !isSafeChildPath(source.folder.uploadDir, destinationPath)) return res.status(409).send("Invalid MOVE target");
  const overwrite = String(req.headers.overwrite || "F").toUpperCase() === "T";
  const destinationExists = isExistingFile(destinationPath);
  if (destinationExists && !overwrite) return res.status(412).send("Destination exists");
  const transactionId = crypto.randomUUID();
  let journal = {
    version: 1,
    transactionId,
    phase: "prepared",
    journalPath: path.join(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${transactionId}.json`),
    sourcePath: path.resolve(source.filePath),
    destinationPath: path.resolve(destinationPath),
    stagePath: path.resolve(source.folder.uploadDir, `.rootark-move-${transactionId}.source`),
    destinationBackupPath: path.resolve(source.folder.uploadDir, `.rootark-move-${transactionId}.destination`),
    destinationExisted: destinationExists,
    replacementInstalled: false,
    pendingOperation: null,
    sourceIdentity: webDavMoveFileIdentity(source.filePath),
    destinationIdentity: webDavMoveFileIdentity(destinationPath),
    completedOperations: [],
    startedAt: new Date().toISOString(),
  };
  const metadataSnapshot = persistWebDavMoveMetadataSnapshot(transactionId, snapshotWebDavMoveMetadata());
  journal.metadata = metadataSnapshot;
  journal.cloud = {
    operationId: transactionId,
    provider: CLOUD_STORAGE_PROVIDER,
    folderId: source.folder.id,
    sourceName: source.name,
    destinationName: destination.fileName,
    destinationUploaded: false,
    sourceRemoved: false,
    state: "queued",
    attempts: 0,
    maxAttempts: WEBDAV_MOVE_RECONCILIATION_MAX_ATTEMPTS,
    lastAttemptAt: null,
    nextAttemptAt: null,
    leaseToken: null,
    leaseUntil: null,
    failureCategory: null,
    completedAt: null,
    terminalAt: null,
    transitions: [{ state: "queued", at: new Date().toISOString() }],
  };
  if (!isSafeWebDavMoveJournal(journal)) return res.status(409).send("Invalid MOVE target");
  const requestedFailure = process.env.WEBDAV_MOVE_FAIL_AFTER;
  let stepNumber = 0;
  const step = (name, phase) => {
    stepNumber += 1;
    journal.pendingOperation = null;
    journal.phase = phase;
    journal.completedOperations.push(name);
    writeWebDavMoveJournal(journal);
    if (requestedFailure !== undefined && (String(requestedFailure) === name || Number(requestedFailure) === stepNumber)) {
      const error = new Error(`Falha injetada MOVE: ${name}`);
      error.code = "WEBDAV_MOVE_INJECTED_FAILURE";
      throw error;
    }
  };

  try {
    writeWebDavMoveJournal(journal);
    beginWebDavMoveLocalIntent(journal, "source.stage", "source_stage_intent");
    fs.renameSync(source.filePath, journal.stagePath);
    step("source.stage", "source_staged");
    if (destinationExists) {
      beginWebDavMoveLocalIntent(journal, "destination.preserve", "destination_preserve_intent");
      fs.renameSync(destinationPath, journal.destinationBackupPath);
      step("destination.preserve", "destination_preserved");
    }
    beginWebDavMoveLocalIntent(journal, "replacement.install", "replacement_install_intent");
    fs.renameSync(journal.stagePath, destinationPath);
    journal.replacementInstalled = true;
    step("replacement.install", "replacement_installed");
    beginWebDavMoveLocalIntent(journal, "metadata.public_links", "metadata_public_links_intent");
    renamePublicLinksForFile(source.name, destination.fileName, source.folder.id);
    step("metadata.public_links", "metadata_updating");
    beginWebDavMoveLocalIntent(journal, "metadata.permissions", "metadata_permissions_intent");
    renameFilePermission(source.folder.id, source.name, destination.fileName);
    step("metadata.permissions", "metadata_updating");
    beginWebDavMoveLocalIntent(journal, "metadata.expirations", "metadata_expirations_intent");
    renameFileExpiration(source.folder.id, source.name, destination.fileName);
    step("metadata.expirations", "metadata_updating");
    beginWebDavMoveLocalIntent(journal, "metadata.versions", "metadata_versions_intent");
    renameFileVersions(source.folder.id, source.name, destination.fileName);
    step("metadata.versions", "metadata_updating");
    beginWebDavMoveLocalIntent(journal, "metadata.encrypted", "metadata_encrypted_intent");
    renameEncryptedMetadata(source.folder.id, source.name, destination.fileName);
    step("metadata.encrypted", "metadata_updating");
    journal.phase = "metadata_installed";
    journal.completedOperations.push("metadata.commit");
    writeWebDavMoveJournal(journal);
    const cloudClaim = claimWebDavMoveJournal(journal, Date.now(), `initial:${transactionId}`);
    if (!cloudClaim) throw Object.assign(new Error("MOVE cloud reconciliation is already claimed"), { code: "WEBDAV_MOVE_CLAIM_BUSY" });
    journal = cloudClaim.journal;
    let cloudResult;
    try {
      cloudResult = await reconcileWebDavMoveCloud(journal, { claimToken: cloudClaim.token });
    } finally {
      releaseWebDavMoveClaim(cloudClaim);
    }
    if (cloudResult.pending) {
      auditLog("webdav.move.reconciliation.queued", getAuditActor(req), { type: "file", id: destination.fileName }, "move", "pending", { folderId: source.folder.id, overwrite, transactionId });
      return res.status(202).json({ status: "pending", transactionId, fileName: destination.fileName });
    }
    if (cloudResult.terminal) {
      auditLog("webdav.move.reconciliation.terminal", getAuditActor(req), { type: "file", id: destination.fileName }, "move", "failure", { transactionId, category: journal.cloud.failureCategory, attempts: journal.cloud.attempts });
      return res.status(503).json({ status: "terminal_reconciliation_failure", transactionId, fileName: destination.fileName });
    }
    journal.phase = "committed";
    journal.completedOperations.push("move.commit");
    finalizeWebDavMoveJournal(journal);
    auditLog("webdav.move", getAuditActor(req), { type: "file", id: destination.fileName }, "move", "success", { folderId: source.folder.id, overwrite });
    return res.status(destinationExists ? 204 : 201).end();
  } catch (error) {
    const cloudReconciliationPending = Boolean(journal.cloud?.destinationUploaded && !journal.cloud?.sourceRemoved) || WEBDAV_MOVE_REMOTE_INTENT_STATES.has(journal.phase) || WEBDAV_MOVE_REMOTE_INTENT_STATES.has(journal.cloud?.state);
    if (!cloudReconciliationPending && !["committed", "cloud_source_removal_pending", "cloud_complete", "terminal_reconciliation_failure"].includes(journal.phase)) {
      try { journal.phase = "rolling_back"; writeWebDavMoveJournal(journal); } catch {}
      try { restoreWebDavMoveMetadata(metadataSnapshot); } catch {}
      try { rollbackWebDavMoveJournal(journal); } catch (rollbackError) {
        try { journal.phase = "terminal_reconciliation_failure"; journal.cloud.lastFailureCategory = "local_rollback_failed"; writeWebDavMoveJournal(journal); } catch {}
      }
    } else if (!cloudReconciliationPending && !["terminal_reconciliation_failure"].includes(journal.phase)) {
      try { finalizeWebDavMoveJournal(journal); } catch {}
    }
    auditLog("webdav.error", getAuditActor(req), { type: "webdav", id: getSafeWebDavAuditPath(req) }, "move", "failure", { error: error.message, path: getSafeWebDavAuditPath(req) });
    if (cloudReconciliationPending) return res.status(202).json({ status: journal.cloud.state || "retry_wait", transactionId, fileName: destination.fileName });
    return res.status(500).send("MOVE failed");
  }
}

function sendWebDavOptions(req, res) {
  const methods = ["OPTIONS", "PROPFIND", "GET", "HEAD", "PUT", "MKCOL", "LOCK", "UNLOCK"];
  if (WEBDAV_ALLOW_DELETE) methods.push("DELETE");
  if (WEBDAV_ALLOW_MOVE) methods.push("MOVE");
  res.setHeader("DAV", "1");
  res.setHeader("MS-Author-Via", "DAV");
  res.setHeader("Allow", methods.join(", "));
  return res.status(204).end();
}

function registerWebDavRoutes() {
  recoverWebDavMoveJournals();
  resumeWebDavMoveCloudJournals().catch((error) => console.error("[webdav] cloud reconciliation: ", error.message));
  if (!webDavReconciliationTimer) {
    webDavReconciliationTimer = setInterval(() => { void resumeWebDavMoveCloudJournals().catch((error) => console.error("[webdav] cloud reconciliation: ", error.message)); }, WEBDAV_MOVE_RECONCILIATION_INTERVAL_MS);
    server.once("close", () => clearInterval(webDavReconciliationTimer));
  }
  app.get("/webdav/moves/:transactionId/status", authenticate, requirePermission("upload"), (req, res) => {
    if (!/^[a-f0-9-]{36}$/i.test(String(req.params.transactionId || ""))) return res.status(404).send("Not found");
    const journalPath = path.join(WEBDAV_MOVE_JOURNAL_DIR, `rootark-webdav-move-${req.params.transactionId}.json`);
    if (!fs.existsSync(journalPath)) return res.status(404).send("Not found");
    let journal;
    try { journal = JSON.parse(fs.readFileSync(journalPath, "utf8")); } catch { return res.status(409).send("Status unavailable"); }
    if (!isSafeWebDavMoveJournal(journal)) return res.status(409).send("Status unavailable");
    const cloud = journal.cloud || {};
    return res.json({ transactionId: journal.transactionId, phase: journal.phase, state: cloud.state || journal.phase, provider: cloud.provider || null, attempts: cloud.attempts || 0, maxAttempts: cloud.maxAttempts || WEBDAV_MOVE_RECONCILIATION_MAX_ATTEMPTS, lastAttemptAt: cloud.lastAttemptAt || null, nextAttemptAt: cloud.nextAttemptAt || null, failureCategory: cloud.failureCategory || null, completedAt: cloud.completedAt || null, terminalAt: cloud.terminalAt || null, transitions: Array.isArray(cloud.transitions) ? cloud.transitions : [] });
  });
  const handler = async (req, res) => {
    try {
      if (req.method === "OPTIONS") return sendWebDavOptions(req, res);
      if (req.headers.origin && req.headers.origin !== getExpectedOrigin(req)) return res.status(403).send("Origin denied");
      if (!authenticateWebDavRequest(req, res)) return;

      const segments = parseWebDavSegments(req);
      if (!segments) return res.status(404).send("Not found");

      if (req.method === "PROPFIND") return sendWebDavPropfind(req, res, segments);
      if (req.method === "GET") return sendWebDavFile(req, res, segments, false);
      if (req.method === "HEAD") return sendWebDavFile(req, res, segments, true);
      if (req.method === "PUT") return handleWebDavPut(req, res, segments);
      if (req.method === "MKCOL") return handleWebDavMkcol(req, res, segments);

      if (req.method === "DELETE") {
        auditLog("webdav.delete", getAuditActor(req), { type: "webdav", id: getSafeWebDavAuditPath(req) }, "delete", "failure", {
          reason: WEBDAV_ALLOW_DELETE ? "not_implemented" : "disabled",
        });
        return res.status(405).send("DELETE is disabled for WebDAV MVP");
      }

      if (req.method === "MOVE") return handleWebDavMove(req, res, segments);
      if (req.method === "LOCK" || req.method === "UNLOCK") return res.status(501).send("WebDAV locking is not supported in this MVP");
      return res.status(405).send("Method not allowed");
    } catch (error) {
      auditLog("webdav.error", getAuditActor(req, "anonymous"), { type: "webdav", id: getSafeWebDavAuditPath(req) }, req.method, "failure", {
        error: error.message,
        path: getSafeWebDavAuditPath(req),
      });
      return res.status(error.message.includes("Caminho WebDAV") ? 400 : 500).send("WebDAV request failed");
    }
  };

  app.all(WEBDAV_PATH, handler);
  app.all(`${WEBDAV_PATH}/*splat`, handler);
  if (Number(String(require("express/package.json").version).split(".")[0]) < 5) {
    app.all(`${WEBDAV_PATH}/*`, handler);
  }
}

function parseSearchBoolean(value) {
  if (value === undefined || value === null || value === "") return null;
  const normalized = String(value).trim().toLowerCase();
  if (["true", "1", "yes", "sim"].includes(normalized)) return true;
  if (["false", "0", "no", "nao", "não"].includes(normalized)) return false;
  return null;
}

function parseSearchNumber(value) {
  if (value === undefined || value === null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}

function parseSearchDate(value, endOfDay = false) {
  if (!value) return null;
  const raw = String(value).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(raw) && Number.isNaN(Date.parse(raw))) return null;
  const date = /^\d{4}-\d{2}-\d{2}$/.test(raw) ? new Date(`${raw}T${endOfDay ? "23:59:59.999" : "00:00:00.000"}`) : new Date(raw);
  return Number.isNaN(date.getTime()) ? null : date;
}

function normalizeSearchExtension(value) {
  if (!value) return "";
  const normalized = String(value).trim().toLowerCase().replace(/^\.+/, "");
  if (!normalized || !/^[a-z0-9]{1,16}$/.test(normalized)) return "";
  return `.${normalized}`;
}

function isDateWithinRange(file, startDate, endDate) {
  if (!startDate && !endDate) return true;
  const candidates = [file.uploadedAt, file.modifiedAt].filter(Boolean).map((date) => new Date(date)).filter((date) => !Number.isNaN(date.getTime()));
  if (!candidates.length) return false;
  return candidates.some((date) => (!startDate || date >= startDate) && (!endDate || date <= endDate));
}

function getSearchFolders(req, rawFolderId) {
  const folderId = String(rawFolderId || ROOT_FOLDER_ID);
  if (["all", "global", "*"].includes(folderId.toLowerCase())) {
    return loadFolders()
      .filter((folder) => !folder.deletedAt && hasFolderAccess(req, folder))
      .map((folder) => ({ ...folder, ...ensureFolderDirectories(folder.id) }));
  }

  const folder = getFolderById(folderId);
  return folder && !folder.deletedAt && hasFolderAccess(req, folder) ? [{ ...folder, ...ensureFolderDirectories(folder.id) }] : null;
}

function filterSearchResults(files, filters) {
  return files.filter((file) => {
    if (filters.q && !file.name.toLowerCase().includes(filters.q)) return false;
    if (filters.extension && path.extname(file.name).toLowerCase() !== filters.extension) return false;
    if (filters.minSize !== null && file.size < filters.minSize) return false;
    if (filters.maxSize !== null && file.size > filters.maxSize) return false;
    if (filters.owner && !String(file.owner || file.uploadedBy || "").toLowerCase().includes(filters.owner)) return false;
    if (filters.isShared !== null && Boolean(file.isShared) !== filters.isShared) return false;
    if (filters.isEncrypted !== null && Boolean(file.isEncrypted) !== filters.isEncrypted) return false;
    if (!isDateWithinRange(file, filters.startDate, filters.endDate)) return false;
    return true;
  });
}

function sortSearchResults(files, sortBy, sortOrder) {
  const direction = sortOrder === "desc" ? -1 : 1;
  const sorted = files.slice();
  sorted.sort((left, right) => {
    if (sortBy === "size") return ((left.size || 0) - (right.size || 0)) * direction;
    if (sortBy === "date") {
      const leftDate = new Date(left.modifiedAt || left.uploadedAt || 0).getTime() || 0;
      const rightDate = new Date(right.modifiedAt || right.uploadedAt || 0).getTime() || 0;
      return (leftDate - rightDate) * direction;
    }
    return left.name.localeCompare(right.name, "pt-BR", { sensitivity: "base" }) * direction;
  });
  return sorted;
}

app.get("/list", authenticate, requirePermission("listFiles"), async (req, res) => {
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  try {
    const visibleFiles = await listVisibleFilesForFolder(req, folder);
    res.json(visibleFiles);
  } catch (error) {
    res.status(500).json({ error: "Erro ao listar" });
  }
});

async function handleFileSearch(req, res) {
  const foldersToSearch = getSearchFolders(req, req.query.folderId);
  if (!foldersToSearch) return res.status(403).json({ error: "Acesso negado a esta pasta" });

  const sortBy = ["name", "size", "date"].includes(String(req.query.sortBy || "").toLowerCase()) ? String(req.query.sortBy).toLowerCase() : "name";
  const sortOrder = String(req.query.sortOrder || "asc").toLowerCase() === "desc" ? "desc" : "asc";
  const filters = {
    q: String(req.query.q || "").trim().toLowerCase().slice(0, 120),
    extension: normalizeSearchExtension(req.query.extension),
    minSize: parseSearchNumber(req.query.minSize),
    maxSize: parseSearchNumber(req.query.maxSize),
    startDate: parseSearchDate(req.query.startDate),
    endDate: parseSearchDate(req.query.endDate, true),
    owner: String(req.query.owner || "").trim().toLowerCase().slice(0, 80),
    isShared: parseSearchBoolean(req.query.isShared),
    isEncrypted: parseSearchBoolean(req.query.isEncrypted),
  };

  try {
    const caches = getFileListCaches();
    const lists = await Promise.all(foldersToSearch.map((folder) => listVisibleFilesForFolder(req, folder, caches).catch(() => [])));
    const results = sortSearchResults(filterSearchResults(lists.flat(), filters), sortBy, sortOrder);
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: "Erro ao buscar arquivos" });
  }
}

app.get("/versions/:filename", authenticate, requirePermission("listFiles"), (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  const filePath = path.join(folder.uploadDir, name);
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!hasFileAccess(req, folder, name)) {
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  const { history } = ensureVersionHistory(folder, name, normalizeFilePermissionEntry(getFilePermissionEntry(folder.id, name)).owner, "Versao inicial");
  const owner = normalizeFilePermissionEntry(getFilePermissionEntry(folder.id, name)).owner;
  res.json({
    folderId: folder.id,
    fileName: name,
    currentVersion: history.currentVersion,
    canDeleteVersions: Boolean(req.user?.permissions?.delete && (canManageAccess(req) || owner === req.user?.username)),
    canRestore: hasFileEditAccess(req, folder, name),
    versions: history.versions.slice().sort((a, b) => b.version - a.version),
    actionHistory: getActionHistoryForFile(folder.id, name),
  });
});

app.get("/download/:filename/v/:version", authenticate, requirePermission("listFiles"), async (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const versionNumber = Number(req.params.version);
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName || !Number.isInteger(versionNumber) || versionNumber < 1) {
    return res.status(400).json({ error: "Versao invalida" });
  }

  if (!hasFileAccess(req, folder, name)) {
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  const target = getVersionFilePath(folder, name, versionNumber);
  if (target?.version?.storedAs) {
    await ensureCloudFileCached(folder.id, target.version.storedAs, target.filePath, "uploads");
  }
  if (!target || !isExistingFile(target.filePath)) {
    return res.status(404).json({ error: "Versao nao encontrada" });
  }

  if (getEncryptedFileMetadata(folder.id, name)) {
    return res.status(403).json({ error: "Download de versoes criptografadas exige a versao atual da rota segura" });
  }

  sendOptimizedFile(req, res, target.filePath, name, "attachment");
});

app.post("/version-open-token", authenticate, requirePermission("listFiles"), async (req, res) => {
  const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const name = path.basename(rawName);
  const versionNumber = Number(req.body.version);
  const folder = getReadableFolderOrRespond(req, res, req.body.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName || !Number.isInteger(versionNumber) || versionNumber < 1) {
    return res.status(400).json({ error: "Versao invalida" });
  }

  if (!hasFileAccess(req, folder, name)) {
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  const target = getVersionFilePath(folder, name, versionNumber);
  if (target?.version?.storedAs) {
    await ensureCloudFileCached(folder.id, target.version.storedAs, target.filePath, "uploads");
  }
  if (!target || !isExistingFile(target.filePath)) {
    return res.status(404).json({ error: "Versao nao encontrada" });
  }

  const openToken = createOpenFileToken(folder.id, name, {
    filePath: target.filePath,
    downloadName: name,
    cloudFileName: target.version.storedAs,
  });

  res.json({
    downloadUrl: `/open-file/${openToken}/${encodeURIComponent(name)}?download=1`,
    expiresAt: new Date(Date.now() + OPEN_FILE_TOKEN_TTL_MS).toISOString(),
  });
});

app.post("/restore/:filename/v/:version", authenticate, async (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const versionNumber = Number(req.params.version);
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName || !Number.isInteger(versionNumber) || versionNumber < 1) {
    return res.status(400).json({ error: "Versao invalida" });
  }

  if (!hasFileEditAccess(req, folder, name)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  const entries = loadFileVersions();
  const key = getFileVersionKey(folder.id, name);
  const history = normalizeVersionHistory(entries[key]);
  const target = history.versions.find((item) => item.version === versionNumber);

  if (!target) {
    return res.status(404).json({ error: "Versao nao encontrada" });
  }

  if (versionNumber === history.currentVersion) {
    return res.status(400).json({ error: "Esta versao ja e a atual" });
  }

  const currentPath = path.join(folder.uploadDir, name);
  const targetPath = path.join(folder.uploadDir, target.storedAs);
  await ensureCloudFileCached(folder.id, name, currentPath, "uploads");
  await ensureCloudFileCached(folder.id, target.storedAs, targetPath, "uploads");
  if (!isExistingFile(currentPath) || !isExistingFile(targetPath)) {
    return res.status(404).json({ error: "Arquivo da versao nao encontrado" });
  }

  try {
    const oldCurrentVersion = history.currentVersion;
    const archivedName = getStoredVersionName(name, oldCurrentVersion);
    const archivedPath = path.join(folder.uploadDir, archivedName);

    fs.renameSync(currentPath, archivedPath);
    for (const version of history.versions) {
      if (version.version === oldCurrentVersion) {
        version.storedAs = archivedName;
        version.size = fs.statSync(archivedPath).size;
      }
    }

    fs.copyFileSync(targetPath, currentPath);
    const stats = fs.statSync(currentPath);
    const newVersion = oldCurrentVersion + 1;
    history.currentVersion = newVersion;
    history.versions.push({
      version: newVersion,
      storedAs: name,
      uploadedBy: req.user.username,
      uploadedAt: new Date().toISOString(),
      size: stats.size,
      comment: `Restaurado da versao ${versionNumber}`,
    });

    entries[key] = history;
    pruneFileVersions(entries, key, folder);
    saveFileVersions(entries);
    syncFileVersionsToCloud(folder.id, name);
    addActionHistory("version_restored", name, req.user.username, {
      folderId: folder.id,
      folderName: folder.name,
      restoredVersion: versionNumber,
      newVersion,
    });
    logAnalyticsEvent("restore", {
      filename: name,
      restoredBy: req.user.username,
      restoredVersion: versionNumber,
      newVersion,
      folderId: folder.id,
      folderName: folder.name,
    });
    auditLog("file.version.restore", getAuditActor(req), { type: "file", id: name }, "restored", "success", {
      folderId: folder.id,
      restoredVersion: versionNumber,
      newVersion,
    });
    res.json({ message: "Versao restaurada", version: newVersion, restoredVersion: versionNumber });
  } catch (error) {
    console.error("Erro ao restaurar versao:", error.message);
    res.status(500).json({ error: "Erro ao restaurar versao" });
  }
});

app.delete("/versions/:filename/v/:version", authenticate, requirePermission("delete"), (req, res) => {
  const rawName = typeof req.params.filename === "string" ? req.params.filename.trim() : "";
  const name = path.basename(rawName);
  const versionNumber = Number(req.params.version);
  const folder = getReadableFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!rawName || name !== rawName || !Number.isInteger(versionNumber) || versionNumber < 1) {
    return res.status(400).json({ error: "Versao invalida" });
  }

  const owner = normalizeFilePermissionEntry(getFilePermissionEntry(folder.id, name)).owner;
  if (!canManageAccess(req) && owner !== req.user?.username) {
    return res.status(403).json({ error: "Apenas o dono ou admin pode deletar versoes" });
  }

  const entries = loadFileVersions();
  const key = getFileVersionKey(folder.id, name);
  const history = normalizeVersionHistory(entries[key]);
  const target = history.versions.find((item) => item.version === versionNumber);

  if (!target) {
    return res.status(404).json({ error: "Versao nao encontrada" });
  }

  if (versionNumber === history.currentVersion) {
    return res.status(400).json({ error: "A versao atual nao pode ser deletada" });
  }

  fs.rmSync(path.join(folder.uploadDir, target.storedAs), { force: true });
  deleteCloudFileLater(folder.id, target.storedAs, "uploads");
  history.versions = history.versions.filter((item) => item.version !== versionNumber);
  entries[key] = history;
  saveFileVersions(entries);
  addActionHistory("version_deleted", name, req.user.username, {
    folderId: folder.id,
    folderName: folder.name,
    version: versionNumber,
  });
  logAnalyticsEvent("versionDeletion", {
    filename: name,
    deletedBy: req.user.username,
    version: versionNumber,
    folderId: folder.id,
    folderName: folder.name,
  });
  auditLog("file.version.delete", getAuditActor(req), { type: "file", id: name }, "deleted", "success", {
    folderId: folder.id,
    version: versionNumber,
  });
  res.json({ message: "Versao deletada" });
});

app.get("/history", authenticate, requirePermission("listFiles"), (req, res) => {
  try {
    res.json({ items: loadActionHistory().slice(0, 200) });
  } catch {
    res.status(500).json({ error: "Erro ao carregar historico" });
  }
});

registerAnalyticsRoutes(app, {
  authenticate,
  getActiveUsers,
  getAnalyticsSummary,
  getFileTypes,
  getMostDownloadedFiles,
  getRecentAnalyticsEvents,
  getUploadsByMonth,
  getUploadsByUser,
  requireAnalyticsAccess,
});

registerAuditRoutes(app, {
  auditLog,
  authenticate,
  convertAuditLogsToCSV,
  countBy,
  findSuspiciousIPs,
  getAuditActor,
  getFilteredAuditLogs,
  loadAuditLogs,
  requireAuditAccess,
});

registerBackupRoutes(app, {
  auditLog,
  authenticate,
  backupService,
  getAuditActor,
  requireBackupAccess,
  restoreService,
});

registerTrashRoutes(app, {
  addActionHistory,
  auditLog,
  authenticate,
  broadcastDataChanged,
  canManageTrash,
  canRestoreTrashItem,
  deleteCloudTrashItem,
  deleteCloudTrashItemLater,
  ensureFolderDirectories,
  getAuditActor,
  getCloudStorageStatus,
  getFolderById,
  getTrashLoaders,
  isTrashEnabled,
  isCloudStorageEnabled,
  requirePermission,
  requireTrashManageAccess,
  rootFolderId: ROOT_FOLDER_ID,
  serializeTrashItemForUser,
  trashRepository,
  trashService,
});

app.post("/share", authenticate, requirePermission("listFiles"), (req, res) => {
  const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const name = path.basename(rawName);
  const expiresInMinutes = getShareExpirationMinutes(req.body.expiresInMinutes);
  const maxViews = getShareMaxViews(req.body.maxViews);
  const maxDownloads = getShareMaxDownloads(req.body.maxDownloads);
  const passwordHash = getSharePasswordHash(req.body.password);
  const folder = getReadableFolderOrRespond(req, res, req.body.folderId);
  if (!folder) return;

  if (!rawName) {
    return res.status(400).json({ error: "Nome do arquivo e obrigatorio" });
  }

  if (name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  if (!expiresInMinutes) {
    return res.status(400).json({
      error: `Expiracao invalida. Use entre 1 e ${MAX_SHARE_EXPIRATION_MINUTES} minutos.`,
    });
  }

  if (maxViews === null) {
    return res.status(400).json({
      error: `Limite de visualizacoes invalido. Use 0 para ilimitado ou ate ${MAX_SHARE_VIEWS}.`,
    });
  }

  if (maxDownloads === null) {
    return res.status(400).json({
      error: `Limite de downloads invalido. Use 0 para ilimitado ou ate ${MAX_SHARE_DOWNLOADS}.`,
    });
  }

  if (passwordHash === undefined) {
    return res.status(400).json({ error: "Senha do link deve ter entre 4 e 128 caracteres." });
  }

  const filePath = path.join(folder.uploadDir, name);
  if (!isExistingFile(filePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!hasFileAccess(req, folder, name)) {
    return res.status(403).json({ error: "Acesso negado a este arquivo" });
  }

  if (getEncryptedFileMetadata(folder.id, name)) {
    return res.status(403).json({ error: "Links publicos nao estao disponiveis para arquivos criptografados" });
  }

  const links = cleanupExpiredPublicLinks();
  const shareToken = crypto.randomBytes(24).toString("hex");
  const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString();

  links[shareToken] = {
    fileName: name,
    folderId: folder.id,
    createdAt: new Date().toISOString(),
    expiresAt,
    createdBy: req.user.username,
    views: 0,
    maxViews,
    downloads: 0,
    maxDownloads,
    passwordHash,
    activeViewers: {},
  };

  savePublicLinks(links);
  addActionHistory("share_created", name, req.user.username, {
    expiresAt,
    folderId: folder.id,
    folderName: folder.name,
    maxViews,
    maxDownloads,
    passwordProtected: Boolean(passwordHash),
  });
  auditLog("share.created", getAuditActor(req), { type: "file", id: name }, "created", "success", {
    folderId: folder.id,
    token: shareToken,
    expiresAt,
    maxViews,
    maxDownloads,
    passwordProtected: Boolean(passwordHash),
  });
  res.status(201).json({
    token: shareToken,
    url: buildPublicShareUrl(req, shareToken),
    fileName: name,
    expiresAt,
    views: 0,
    maxViews,
    downloads: 0,
    maxDownloads,
    passwordProtected: Boolean(passwordHash),
    remainingViews: maxViews > 0 ? maxViews : null,
    remainingDownloads: maxDownloads > 0 ? maxDownloads : null,
  });
});

app.get("/share/:token", (req, res) => {
  const shareToken = String(req.params.token || "");
  if (!/^[a-f0-9]{48}$/i.test(shareToken)) {
    return res.status(404).type("html").send(getShareFailurePage("Este link nao esta disponivel."));
  }

  const links = loadPublicLinks();
  const link = links[shareToken];
  if (!link) {
    return res.status(404).type("html").send(getShareFailurePage("Este link nao esta disponivel."));
  }

  const expiresAt = new Date(link.expiresAt).getTime();
  if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
    delete links[shareToken];
    savePublicLinks(links);
    return res.status(410).type("html").send(getShareFailurePage("Este link nao esta disponivel."));
  }

  res.type("html").send(renderPublicSharePage(shareToken));
});

app.post("/share/:token/password", async (req, res) => {
  const shareToken = validateShareToken(req.params.token);
  if (!shareToken) return res.status(404).json({ error: "Link indisponivel." });

  const access = await resolveShareAccess(req, res, shareToken, {
    password: req.body?.password || "",
    countView: true,
  });

  if (access.error) {
    return res.status(access.status || 400).json({
      error: access.error,
      passwordRequired: Boolean(access.passwordRequired),
    });
  }

  res.json(getSharePublicPayload(access.link, access.fileInfo, access.limits));
});

app.post("/share/:token/view", async (req, res) => {
  const shareToken = validateShareToken(req.params.token);
  if (!shareToken) return res.status(404).json({ error: "Link indisponivel." });

  const access = await resolveShareAccess(req, res, shareToken, { countView: true });
  if (access.error) return res.status(access.status || 400).json({ error: access.error, passwordRequired: Boolean(access.passwordRequired) });

  res.json({
    ...getSharePublicPayload(access.link, access.fileInfo, access.limits),
    url: `/share/${shareToken}/file`,
  });
});

app.get("/share/:token/download", async (req, res) => {
  const shareToken = validateShareToken(req.params.token);
  if (!shareToken) return res.status(404).type("html").send(getShareFailurePage("Este link nao esta disponivel."));

  const access = await resolveShareAccess(req, res, shareToken, {
    requireViewer: true,
    countDownload: true,
  });
  if (access.error) return res.status(access.status || 400).type("html").send(getShareFailurePage(access.error));

  sendOptimizedFile(req, res, access.fileInfo.filePath, access.fileInfo.fileName, "attachment", {
    cacheControl: "private, max-age=600",
  });
});

app.get("/share/:token/preview", async (req, res) => {
  const shareToken = validateShareToken(req.params.token);
  if (!shareToken) return res.status(404).send("Link indisponivel.");

  const access = await resolveShareAccess(req, res, shareToken, { requireViewer: true });
  if (access.error) return res.status(access.status || 400).send(access.error);
  if (!getPublicShareCanPreview(access.fileInfo.fileName)) return res.status(415).send("Preview indisponivel");

  sendOptimizedFile(req, res, access.fileInfo.filePath, access.fileInfo.fileName, "inline", {
    cacheControl: "private, max-age=600",
  });
});

app.get("/share/:token/qr", async (req, res) => {
  const shareToken = validateShareToken(req.params.token);
  if (!shareToken) return res.status(404).send("Link indisponivel.");

  try {
    const png = await QRCode.toBuffer(buildPublicShareUrl(req, shareToken), {
      type: "png",
      margin: 1,
      width: 320,
      color: { dark: "#044879", light: "#ffffff" },
    });
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Cache-Control", "private, max-age=3600");
    res.send(png);
  } catch (error) {
    res.status(500).send("Nao foi possivel gerar QR Code");
  }
});

app.get("/share/:token/file", async (req, res) => {
  const shareToken = validateShareToken(req.params.token);
  if (!shareToken) return res.status(404).send("Link indisponivel.");

  const access = await resolveShareAccess(req, res, shareToken, { requireViewer: true });
  if (access.error) return res.status(access.status || 400).send(access.error);

  sendOptimizedFile(req, res, access.fileInfo.filePath, access.fileInfo.fileName, "inline", {
    cacheControl: "private, max-age=600",
  });
});

app.get("/pending", authenticate, async (req, res) => {
  if (!req.user?.permissions?.listPending && !req.user?.permissions?.upload) {
    return res.status(403).json({ error: "Permissao negada: listPending" });
  }

  const folder = getAccessibleFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  await repairCompressedTempUploads(folder.tempDir);
  cleanupOrphanTempUploads(folder.tempDir);
  await syncFolderCacheFromCloud(folder.id, "temp");
  listFilesWithDetails(folder.tempDir, (err, files) => {
    if (err) return res.status(500).json({ error: "Erro ao listar" });
    const encryptedFiles = loadEncryptedFiles();

    const visibleFiles = files
      .map((file) => ({
        ...file,
        folderId: folder.id,
        uploadedBy: getPendingUploadOwner(folder.id, file.name),
        encryption: getPublicEncryptionMetadata(getEncryptedFileMetadata(folder.id, file.name, encryptedFiles)),
      }))
      .filter((file) => req.user.permissions.listPending || canAccessPendingFile(req, folder.id, file.name));

    res.json(visibleFiles);
  });
});

app.get("/preview/file/:scope/:name", authenticate, async (req, res) => {
  const target = await ensurePreviewAccess(req, res, req.params.scope, req.params.name, req.query.folderId);
  if (!target) return;

  if (!isInlinePreviewFile(target.name)) {
    return res.status(415).json({ error: "Preview inline indisponivel para este tipo de arquivo" });
  }

  sendOptimizedFile(req, res, target.filePath, target.name, "inline", {
    cacheControl: "private, max-age=600",
    contentType: getMimeType(target.name),
  });
});

app.get("/preview/text/:scope/:name", authenticate, async (req, res) => {
  const target = await ensurePreviewAccess(req, res, req.params.scope, req.params.name, req.query.folderId);
  if (!target) return;

  try {
    return res.json(await previewText(target.filePath, target.name));
  } catch (error) {
    if (error.message === "PREVIEW_TOO_LARGE") return res.status(413).json({ error: "Arquivo muito grande para preview textual. Use download." });
    if (error.message === "PREVIEW_UNSUPPORTED") return res.status(400).json({ error: "Tipo de arquivo sem preview textual" });
    res.status(500).json({ error: "Nao foi possivel gerar a previa" });
  }
});

app.get("/approve/:name", authenticate, requirePermission("approve"), async (req, res) => {
  const name = path.basename(req.params.name);
  const requestedFolder = getAccessibleFolderOrRespond(req, res, req.query.folderId);
  if (!requestedFolder) return;

  try {
    const target = await findPendingApprovalTarget(req, requestedFolder, name);
    if (!target) {
      return res.status(404).json({ error: "Arquivo pendente nao encontrado" });
    }

    const { folder, pendingPath } = target;
    const pendingUploads = loadPendingUploads();
    const key = getPendingKey(folder.id, name);
    const pendingEntry = pendingUploads[key] || pendingUploads[name] || {};
    const uploadedBy = pendingEntry.uploadedBy || null;
    const versionInfo = recordApprovedFileVersion(
      folder,
      name,
      pendingPath,
      uploadedBy || req.user.username,
      pendingEntry.versionComment || ""
    );
    promoteEncryptedMetadataAfterApproval(folder.id, name, uploadedBy || req.user.username);
    syncFileVersionsToCloud(folder.id, name);
    deleteCloudFileLater(folder.id, name, "temp");

    delete pendingUploads[key];
    if (folder.id === ROOT_FOLDER_ID) delete pendingUploads[name];
    savePendingUploads(pendingUploads);
    setFileOwner(folder.id, name, uploadedBy);
    logAnalyticsEvent("approval", {
      filename: name,
      approvedBy: req.user.username,
      folderId: folder.id,
      folderName: folder.name,
    });
    auditLog("file.approve", getAuditActor(req), { type: "file", id: name }, "approved", "success", {
      from: "temp",
      to: "uploads",
      folderId: folder.id,
      version: versionInfo.currentVersion,
    });
    addActionHistory("approved", name, req.user.username, {
      uploadedBy,
      folderId: folder.id,
      folderName: folder.name,
      version: versionInfo.currentVersion,
      replaced: versionInfo.replaced,
    });
    res.json({
      message: "Aprovado",
      fileName: name,
      folderId: folder.id,
      version: versionInfo.currentVersion,
      replaced: versionInfo.replaced,
    });
  } catch (error) {
    console.error("Erro ao aprovar arquivo:", error.message);
    res.status(500).json({ error: "Erro ao aprovar" });
  }
});

app.get("/reject/:name", authenticate, requirePermission("approve"), async (req, res) => {
  const name = path.basename(req.params.name);
  const requestedFolder = getAccessibleFolderOrRespond(req, res, req.query.folderId);
  if (!requestedFolder) return;

  const target = await findPendingApprovalTarget(req, requestedFolder, name);
  if (!target) {
    return res.status(404).json({ error: "Arquivo pendente nao encontrado" });
  }

  const { folder, pendingPath } = target;
  fs.unlink(pendingPath, (err) => {
    if (err) return res.status(500).json({ error: "Erro ao rejeitar" });

    const pendingUploads = loadPendingUploads();
    const key = getPendingKey(folder.id, name);
    const uploadedBy = pendingUploads[key]?.uploadedBy || pendingUploads[name]?.uploadedBy || null;
    delete pendingUploads[key];
    if (folder.id === ROOT_FOLDER_ID) delete pendingUploads[name];
    savePendingUploads(pendingUploads);
    deleteCloudFileLater(folder.id, name, "temp");
    logAnalyticsEvent("rejection", {
      filename: name,
      rejectedBy: req.user.username,
      folderId: folder.id,
      folderName: folder.name,
    });
    auditLog("file.reject", getAuditActor(req), { type: "file", id: name }, "rejected", "success", {
      folderId: folder.id,
      uploadedBy,
    });
    addActionHistory("rejected", name, req.user.username, { uploadedBy, folderId: folder.id, folderName: folder.name });
    res.json({ message: "Rejeitado" });
  });
});

app.get("/delete/:name", authenticate, (req, res) => {
  if (!isTrashEnabled()) return res.status(503).json({ error: "Lixeira desativada" });
  const name = path.basename(req.params.name);
  const folder = getAccessibleFolderOrRespond(req, res, req.query.folderId);
  if (!folder) return;

  if (!canMoveToTrash(req)) {
    return res.status(403).json({ error: "Permissao negada: delete" });
  }

  if (!hasFileEditAccess(req, folder, name)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  const filePath = path.join(folder.uploadDir, name);
  const fileSize = isExistingFile(filePath) ? fs.statSync(filePath).size : 0;

  try {
    const trashItem = trashService.moveFileToTrash({
      folder,
      fileName: name,
      deletedBy: req.user.username,
      loaders: getTrashLoaders(),
    });
    logAnalyticsEvent("deletion", {
      filename: name,
      deletedBy: req.user.username,
      size: fileSize,
      folderId: folder.id,
      folderName: folder.name,
      trashed: true,
    });
    auditLog("trash.file.moved", getAuditActor(req), { type: "trash", id: trashItem.id }, "moved", "success", {
      folderId: folder.id,
      folderName: folder.name,
      fileName: name,
      size: fileSize,
    });
    addActionHistory("deleted", name, req.user.username, { folderId: folder.id, folderName: folder.name, trashId: trashItem.id });
    broadcastDataChanged("trash", { folderId: folder.id, fileName: name, itemType: "file" });
    res.json({ message: "Movido para lixeira", trashItem: serializeTrashItemForUser(trashItem) });
  } catch (error) {
    auditLog("trash.delete.failed", getAuditActor(req), { type: "file", id: name }, "move_to_trash", "failure", {
      folderId: folder.id,
      error: error.message,
    });
    res.status(500).json({ error: "Erro ao mover arquivo para lixeira" });
  }
});

app.put("/rename", authenticate, (req, res) => {
  const rawOldName = typeof req.body.oldName === "string" ? req.body.oldName.trim() : "";
  const rawNewName = typeof req.body.newName === "string" ? req.body.newName.trim() : "";
  const oldName = path.basename(rawOldName);
  const newName = path.basename(rawNewName);
  const folder = getAccessibleFolderOrRespond(req, res, req.body.folderId);
  if (!folder) return;

  if (!rawOldName || !rawNewName) {
    return res.status(400).json({ error: "Nome atual e novo nome sao obrigatorios" });
  }

  if (oldName !== rawOldName || newName !== rawNewName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  if (oldName === newName) {
    return res.status(400).json({ error: "O novo nome precisa ser diferente do atual" });
  }

  if (!isValidFileNameLength(newName)) {
    return res.status(400).json({ error: `O nome do arquivo deve ter no maximo ${MAX_FILE_NAME_LENGTH} caracteres` });
  }

  const oldPath = path.join(folder.uploadDir, oldName);
  const newPath = path.join(folder.uploadDir, newName);
  const oldStoredNames = getVersionHistory(folder.id, oldName).versions
    .map((version) => path.basename(version.storedAs || ""))
    .filter(Boolean);

  if (!fs.existsSync(oldPath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!hasFileEditAccess(req, folder, oldName)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  if (fs.existsSync(newPath)) {
    return res.status(409).json({ error: "Ja existe um arquivo com esse nome" });
  }

  fs.rename(oldPath, newPath, (err) => {
    if (err) return res.status(500).json({ error: "Erro ao renomear arquivo" });
    renamePublicLinksForFile(oldName, newName, folder.id);
    renameFilePermission(folder.id, oldName, newName);
    renameFileExpiration(folder.id, oldName, newName);
    renameFileVersions(folder.id, oldName, newName);
    renameEncryptedMetadata(folder.id, oldName, newName);
    for (const storedName of new Set([oldName, ...oldStoredNames])) {
      deleteCloudFileLater(folder.id, storedName, "uploads");
    }
    syncFileVersionsToCloud(folder.id, newName);
    auditLog("file.rename", getAuditActor(req), { type: "file", id: newName }, "renamed", "success", {
      oldName,
      newName,
      folderId: folder.id,
    });
    addActionHistory("renamed", newName, req.user.username, {
      oldName,
      newName,
      folderId: folder.id,
      folderName: folder.name,
    });
    res.json({ message: "Arquivo renomeado" });
  });
});

app.put("/move", authenticate, (req, res) => {
  const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
  const name = path.basename(rawName);
  const fromFolder = getAccessibleFolderOrRespond(req, res, req.body.fromFolderId);
  if (!fromFolder) return;
  const toFolder = getAccessibleFolderOrRespond(req, res, req.body.toFolderId);
  if (!toFolder) return;

  if (!rawName || name !== rawName) {
    return res.status(400).json({ error: "Nome de arquivo invalido" });
  }

  if (fromFolder.id === toFolder.id) {
    return res.status(400).json({ error: "Escolha uma pasta diferente da atual" });
  }

  const sourcePath = path.join(fromFolder.uploadDir, name);
  if (!isExistingFile(sourcePath)) {
    return res.status(404).json({ error: "Arquivo nao encontrado" });
  }

  if (!hasFileEditAccess(req, fromFolder, name)) {
    return res.status(403).json({ error: "Permissao negada para editar este arquivo" });
  }

  const finalName = getAvailableUploadFileName(name, toFolder.id);
  const destinationPath = path.join(toFolder.uploadDir, finalName);
  const oldStoredNames = getVersionHistory(fromFolder.id, name).versions
    .map((version) => path.basename(version.storedAs || ""))
    .filter(Boolean);

  fs.rename(sourcePath, destinationPath, (err) => {
    if (err) return res.status(500).json({ error: "Erro ao mover arquivo" });

    movePublicLinksForFile(name, finalName, fromFolder.id, toFolder.id);
    moveFilePermission(fromFolder.id, name, toFolder.id, finalName);
    moveFileExpiration(fromFolder.id, name, toFolder.id, finalName);
    moveFileVersions(fromFolder.id, name, toFolder.id, finalName);
    moveEncryptedMetadata(fromFolder.id, name, toFolder.id, finalName);
    for (const storedName of new Set([name, ...oldStoredNames])) {
      deleteCloudFileLater(fromFolder.id, storedName, "uploads");
    }
    syncFileVersionsToCloud(toFolder.id, finalName);
    auditLog("file.move", getAuditActor(req), { type: "file", id: finalName }, "moved", "success", {
      oldName: name,
      newName: finalName,
      fromFolderId: fromFolder.id,
      toFolderId: toFolder.id,
    });
    addActionHistory("moved", finalName, req.user.username, {
      oldName: name,
      newName: finalName,
      fromFolderId: fromFolder.id,
      fromFolderName: fromFolder.name,
      toFolderId: toFolder.id,
      toFolderName: toFolder.name,
    });
    res.json({ message: "Arquivo movido", fileName: finalName, folderId: toFolder.id });
  });
});

initData();
scheduleAutomaticBackups({ cron, createBackup: backupService.createBackup, auditLog, onInvalid: console.error });
cleanupExpiredTemporaryItems();
cleanupExpiredTrashItems();
void processPendingCloudTrashItems();
void processPendingCloudRestoreSync().catch(() => {});
repairCompressedTempUploads().catch((error) => {
  console.error("Falha ao reparar uploads temporarios:", error.message);
});
cleanupOrphanTempUploads();
cleanupIncomingUploads();
setInterval(cleanupExpiredTemporaryItems, 60 * 1000);
setInterval(cleanupExpiredTrashItems, 60 * 60 * 1000);
setInterval(() => { void processPendingCloudTrashItems(); }, 60 * 1000);
setInterval(() => { void processPendingCloudRestoreSync().catch(() => {}); }, 60 * 1000);
setInterval(cleanupIncomingUploads, 60 * 1000);
server.listen(PORT, () => console.log(`Servidor rodando em http://localhost:${PORT}`));
