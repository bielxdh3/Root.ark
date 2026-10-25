const crypto = require("crypto");
const path = require("path");
const { getDb, jsonStringify, nowIso, safeJsonParse, splitStorageKey } = require("../db");
const { assertNoLocalStrictSyncWriter } = require("../src/services/syncSqliteAccountWriteFence");

function basename(value) {
  return path.basename(String(value || ""));
}

function ensureRootFolder(db) {
  assertNoLocalStrictSyncWriter();
  const now = nowIso();
  db.prepare(`
    INSERT INTO folders (id, name, created_by, created_at, updated_at, allowed_users_json, is_root)
    VALUES ('root', 'Arquivos atuais', 'sistema', ?, ?, '[]', 1)
    ON CONFLICT(id) DO UPDATE SET
      name = excluded.name,
      is_root = 1,
      deleted_at = NULL,
      updated_at = excluded.updated_at
  `).run(now, now);
}

function ensureFolderId(db, folderId) {
  assertNoLocalStrictSyncWriter();
  ensureRootFolder(db);
  const id = String(folderId || "root");
  if (id === "root") return;
  const now = nowIso();
  db.prepare(`
    INSERT OR IGNORE INTO folders (id, name, created_by, created_at, updated_at, allowed_users_json, is_root)
    VALUES (?, ?, 'sistema', ?, ?, '[]', 0)
  `).run(id, `Pasta ${id}`, now, now);
}

function loadKeyedObjectFromTable(options) {
  const db = getDb();
  const rows = db.prepare(options.selectSql).all();
  const entries = {};
  for (const row of rows) {
    const folderId = row.folder_id || "root";
    const fileName = basename(row.file_name);
    if (!fileName) continue;
    entries[`${folderId}/${fileName}`] = options.mapRow(row);
  }
  return entries;
}

function saveKeyedObjectToTable(entries, options) {
  const db = getDb();
  const now = nowIso();
  runWrite(db, () => {
    ensureRootFolder(db);
    db.prepare(options.deleteSql).run();
    const insert = db.prepare(options.insertSql);
    for (const [key, entry] of Object.entries(entries || {})) {
      const parsed = splitStorageKey(key);
      const folderId = entry?.folderId || parsed.folderId || "root";
      const fileName = basename(entry?.fileName || parsed.fileName);
      if (!fileName) continue;
      ensureFolderId(db, folderId);
      insert.run(...options.toParams({ key, entry, folderId, fileName, now }));
    }
  });
}

function randomId() {
  return crypto.randomUUID();
}

function runWrite(db, callback) {
  assertNoLocalStrictSyncWriter();
  if (db.inTransaction) return callback();
  return db.transaction(callback)();
}

module.exports = {
  basename,
  ensureFolderId,
  ensureRootFolder,
  loadKeyedObjectFromTable,
  randomId,
  runWrite,
  safeJsonParse,
  saveKeyedObjectToTable,
  jsonStringify,
  nowIso,
  splitStorageKey,
};
