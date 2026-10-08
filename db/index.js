const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");

const ROOT_DIR = path.resolve(__dirname, "..");
const DEFAULT_DATABASE_PATH = path.join(ROOT_DIR, "data", "rootark.sqlite");

let dbInstance = null;

function isDbEnabled() {
  return String(process.env.DB_ENABLED || "false").toLowerCase() === "true";
}

function isJsonReadFallbackEnabled() {
  return String(process.env.DB_READ_FALLBACK_JSON || "false").toLowerCase() === "true";
}

function isLegacyJsonWriteEnabled() {
  return String(process.env.DB_WRITE_LEGACY_JSON || "false").toLowerCase() === "true";
}

function getDatabasePath() {
  const configured = process.env.DATABASE_URL || DEFAULT_DATABASE_PATH;
  return path.resolve(ROOT_DIR, configured);
}

function getDb() {
  if (dbInstance) return dbInstance;

  const databasePath = getDatabasePath();
  fs.mkdirSync(path.dirname(databasePath), { recursive: true });

  dbInstance = new Database(databasePath);
  dbInstance.pragma("journal_mode = WAL");
  dbInstance.pragma("foreign_keys = ON");
  dbInstance.pragma("busy_timeout = 5000");

  return dbInstance;
}

function closeDb() {
  if (!dbInstance) return;
  dbInstance.close();
  dbInstance = null;
}

function safeJsonParse(value, fallback) {
  if (value === null || value === undefined || value === "") return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function jsonStringify(value) {
  return JSON.stringify(value === undefined ? null : value);
}

function nowIso() {
  return new Date().toISOString();
}

function splitStorageKey(key, defaultFolderId = "root") {
  const value = String(key || "");
  const slashIndex = value.indexOf("/");
  if (slashIndex === -1) {
    return { folderId: defaultFolderId, fileName: path.basename(value) };
  }

  return {
    folderId: value.slice(0, slashIndex) || defaultFolderId,
    fileName: path.basename(value.slice(slashIndex + 1)),
  };
}

module.exports = {
  ROOT_DIR,
  DEFAULT_DATABASE_PATH,
  closeDb,
  getDatabasePath,
  getDb,
  isDbEnabled,
  isJsonReadFallbackEnabled,
  isLegacyJsonWriteEnabled,
  jsonStringify,
  nowIso,
  safeJsonParse,
  splitStorageKey,
};
