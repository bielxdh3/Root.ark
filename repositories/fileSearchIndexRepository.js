const path = require("path");
const { getDb } = require("../db");

const MIN_TRIGRAM_LENGTH = 3;

function basename(value) {
  return path.basename(String(value || ""));
}

// Builds a safe trigram MATCH expression: the whole query as one quoted FTS5 phrase
// (embedded double quotes doubled). Trigram phrases match substrings, case-folded,
// which is the same candidate semantics as the existing includes() search. Operators
// such as OR, NEAR(, * or % are literal text inside the quotes. Returns null for
// queries shorter than 3 characters (trigram cannot match them; callers use a full scan).
function buildMatchQuery(rawQuery) {
  const text = String(rawQuery || "");
  if ([...text].length < MIN_TRIGRAM_LENGTH) return null;
  return `"${text.replace(/"/g, '""')}"`;
}

function upsert(folderId, fileName) {
  const name = basename(fileName);
  if (!name) return;
  const folder = String(folderId || "root");
  const db = getDb();
  db.transaction(() => {
    db.prepare("DELETE FROM file_search_index WHERE folder_id = ? AND file_name = ?").run(folder, name);
    db.prepare("INSERT INTO file_search_index (folder_id, file_name) VALUES (?, ?)").run(folder, name);
  })();
}

function remove(folderId, fileName) {
  const name = basename(fileName);
  if (!name) return;
  getDb().prepare("DELETE FROM file_search_index WHERE folder_id = ? AND file_name = ?")
    .run(String(folderId || "root"), name);
}

function rename(folderId, oldName, newName) {
  const db = getDb();
  db.transaction(() => {
    remove(folderId, oldName);
    upsert(folderId, newName);
  })();
}

// Lazy reconciliation: makes the folder's indexed names equal the current listing,
// excluding protected (encrypted) names. Protected names are never inserted.
function syncFolder(folderId, fileNames, isProtected = () => false) {
  const folder = String(folderId || "root");
  const db = getDb();
  const wanted = new Set();
  for (const value of fileNames || []) {
    const name = basename(value);
    if (!name || isProtected(name)) continue;
    wanted.add(name);
  }

  const existing = new Set(
    db.prepare("SELECT file_name FROM file_search_index WHERE folder_id = ?").all(folder).map((row) => row.file_name),
  );

  const toRemove = [...existing].filter((name) => !wanted.has(name));
  const toAdd = [...wanted].filter((name) => !existing.has(name));
  if (!toRemove.length && !toAdd.length) return;

  db.transaction(() => {
    const deleteStmt = db.prepare("DELETE FROM file_search_index WHERE folder_id = ? AND file_name = ?");
    const insertStmt = db.prepare("INSERT INTO file_search_index (folder_id, file_name) VALUES (?, ?)");
    for (const name of toRemove) deleteStmt.run(folder, name);
    for (const name of toAdd) insertStmt.run(folder, name);
  })();
}

// Returns [{ folderId, fileName }] candidates. Query text is bound as a parameter only.
function search(query, limit = 5000, folderId = null) {
  const match = buildMatchQuery(query);
  if (!match) return [];
  const safeLimit = Math.max(1, Math.min(Number(limit) || 5000, 50000));
  const db = getDb();
  const rows = folderId === null || folderId === undefined
    ? db.prepare("SELECT folder_id, file_name FROM file_search_index WHERE file_search_index MATCH ? ORDER BY rank LIMIT ?").all(match, safeLimit)
    : db.prepare("SELECT folder_id, file_name FROM file_search_index WHERE file_search_index MATCH ? AND folder_id = ? ORDER BY rank LIMIT ?").all(match, String(folderId), safeLimit);
  return rows.map((row) => ({ folderId: row.folder_id, fileName: row.file_name }));
}

module.exports = { buildMatchQuery, upsert, remove, rename, syncFolder, search };
