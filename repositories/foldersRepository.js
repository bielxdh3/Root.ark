const { getDb } = require("../db");
const { ensureRootFolder, jsonStringify, nowIso, runWrite, safeJsonParse } = require("./repositoryUtils");

function loadFolders() {
  const db = getDb();
  const folders = db.prepare(`
    SELECT id, name, created_by, created_at, updated_at, allowed_users_json, is_root, expires_at
    FROM folders
    WHERE deleted_at IS NULL
    ORDER BY is_root DESC, created_at ASC
  `).all().map((row) => ({
    id: row.id,
    name: row.name,
    createdBy: row.created_by || "sistema",
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    allowedUsers: safeJsonParse(row.allowed_users_json, []),
    isRoot: Boolean(row.is_root),
    expiresAt: row.expires_at || null,
  }));
  // A read can run during a protected Sync's BEGIN IMMEDIATE reservation.
  // Never UPSERT the root here: that can fail with SQLITE_BUSY and hide every
  // other folder behind the server's legacy fallback. Writes still ensure it.
  if (folders.some((folder) => folder.id === "root")) return folders;
  const now = nowIso();
  return [{ id: "root", name: "Arquivos atuais", createdBy: "sistema",
    createdAt: now, updatedAt: now, allowedUsers: [], isRoot: true,
    expiresAt: null }, ...folders];
}

function saveFolders(folders = []) {
  const db = getDb();
  const now = nowIso();
  runWrite(db, () => {
    ensureRootFolder(db);
    const active = new Set();
    const upsert = db.prepare(`
      INSERT INTO folders (id, name, created_by, created_at, updated_at, allowed_users_json, is_root, expires_at, deleted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        created_by = excluded.created_by,
        updated_at = excluded.updated_at,
        allowed_users_json = excluded.allowed_users_json,
        is_root = excluded.is_root,
        expires_at = excluded.expires_at,
        deleted_at = NULL
    `);

    for (const folder of folders) {
      const id = String(folder?.id || "").trim();
      if (!id) continue;
      active.add(id);
      upsert.run(
        id,
        folder.name || "Pasta",
        folder.createdBy || folder.created_by || "sistema",
        folder.createdAt || folder.created_at || now,
        folder.updatedAt || folder.updated_at || now,
        jsonStringify(folder.allowedUsers || []),
        folder.isRoot ? 1 : 0,
        folder.expiresAt || folder.expires_at || null
      );
    }

    active.add("root");
    const current = db.prepare("SELECT id FROM folders WHERE deleted_at IS NULL AND id <> 'root'").all();
    const softDelete = db.prepare("UPDATE folders SET deleted_at = ?, updated_at = ? WHERE id = ?");
    for (const row of current) {
      if (!active.has(row.id)) softDelete.run(now, now, row.id);
    }
  });
}

module.exports = { loadFolders, saveFolders };
