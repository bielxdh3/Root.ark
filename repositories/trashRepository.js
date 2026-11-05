const fs = require("fs");
const path = require("path");
const { getDb, isDbEnabled, jsonStringify, safeJsonParse } = require("../db");
const { resolveRuntimePath } = require("../src/runtime-paths");

const TRASH_JSON_FILE = resolveRuntimePath("data", "trash-items.json");

function normalizeTrashItem(item = {}) {
  return {
    id: item.id,
    itemType: item.itemType || item.item_type,
    originalFolderId: item.originalFolderId || item.original_folder_id || "root",
    originalFolderName: item.originalFolderName || item.original_folder_name || "",
    originalFileName: item.originalFileName || item.original_file_name || null,
    storedFileName: item.storedFileName || item.stored_file_name || null,
    originalPath: item.originalPath || item.original_path || null,
    trashPath: item.trashPath || item.trash_path || null,
    deletedBy: item.deletedBy || item.deleted_by || null,
    deletedAt: item.deletedAt || item.deleted_at || new Date().toISOString(),
    sizeBytes: Number(item.sizeBytes ?? item.size_bytes) || 0,
    metadata: item.metadata || safeJsonParse(item.metadata_json, {}),
    restoreMetadata: item.restoreMetadata || safeJsonParse(item.restore_metadata_json, {}),
    status: item.status || "trashed",
    restoredBy: item.restoredBy || item.restored_by || null,
    restoredAt: item.restoredAt || item.restored_at || null,
    permanentlyDeletedBy: item.permanentlyDeletedBy || item.permanently_deleted_by || null,
    permanentlyDeletedAt: item.permanentlyDeletedAt || item.permanently_deleted_at || null,
  };
}

function hasTrashTable() {
  try {
    return Boolean(getDb().prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='trash_items'").get());
  } catch {
    return false;
  }
}

function rowToItem(row) {
  return normalizeTrashItem({
    ...row,
    metadata: safeJsonParse(row.metadata_json, {}),
    restoreMetadata: safeJsonParse(row.restore_metadata_json, {}),
  });
}

function loadJsonItems() {
  if (!fs.existsSync(TRASH_JSON_FILE)) return [];
  try {
    const entries = JSON.parse(fs.readFileSync(TRASH_JSON_FILE, "utf-8"));
    return Array.isArray(entries) ? entries.map(normalizeTrashItem) : [];
  } catch {
    return [];
  }
}

function saveJsonItems(items) {
  fs.mkdirSync(path.dirname(TRASH_JSON_FILE), { recursive: true });
  fs.writeFileSync(TRASH_JSON_FILE, JSON.stringify(items.map(normalizeTrashItem), null, 2));
}

function listTrashItems(options = {}) {
  const status = options.status || "trashed";
  if (isDbEnabled() && hasTrashTable()) {
    if (status === "*") {
      return getDb().prepare("SELECT * FROM trash_items ORDER BY deleted_at DESC").all().map(rowToItem);
    }
    return getDb().prepare(`
      SELECT * FROM trash_items
      WHERE status = ?
      ORDER BY deleted_at DESC
    `).all(status).map(rowToItem);
  }

  return loadJsonItems()
    .filter((item) => status === "*" || item.status === status)
    .sort((a, b) => new Date(b.deletedAt) - new Date(a.deletedAt));
}

function getTrashItem(id) {
  if (!id) return null;
  if (isDbEnabled() && hasTrashTable()) {
    const row = getDb().prepare("SELECT * FROM trash_items WHERE id = ?").get(id);
    return row ? rowToItem(row) : null;
  }

  return loadJsonItems().find((item) => item.id === id) || null;
}

function saveTrashItem(item) {
  const normalized = normalizeTrashItem(item);
  if (isDbEnabled() && hasTrashTable()) {
    getDb().prepare(`
      INSERT INTO trash_items (
        id, item_type, original_folder_id, original_folder_name, original_file_name, stored_file_name,
        original_path, trash_path, deleted_by, deleted_at, size_bytes, metadata_json, restore_metadata_json,
        status, restored_by, restored_at, permanently_deleted_by, permanently_deleted_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        item_type = excluded.item_type,
        original_folder_id = excluded.original_folder_id,
        original_folder_name = excluded.original_folder_name,
        original_file_name = excluded.original_file_name,
        stored_file_name = excluded.stored_file_name,
        original_path = excluded.original_path,
        trash_path = excluded.trash_path,
        deleted_by = excluded.deleted_by,
        deleted_at = excluded.deleted_at,
        size_bytes = excluded.size_bytes,
        metadata_json = excluded.metadata_json,
        restore_metadata_json = excluded.restore_metadata_json,
        status = excluded.status,
        restored_by = excluded.restored_by,
        restored_at = excluded.restored_at,
        permanently_deleted_by = excluded.permanently_deleted_by,
        permanently_deleted_at = excluded.permanently_deleted_at
    `).run(
      normalized.id,
      normalized.itemType,
      normalized.originalFolderId,
      normalized.originalFolderName,
      normalized.originalFileName,
      normalized.storedFileName,
      normalized.originalPath,
      normalized.trashPath,
      normalized.deletedBy,
      normalized.deletedAt,
      normalized.sizeBytes,
      jsonStringify(normalized.metadata),
      jsonStringify(normalized.restoreMetadata),
      normalized.status,
      normalized.restoredBy,
      normalized.restoredAt,
      normalized.permanentlyDeletedBy,
      normalized.permanentlyDeletedAt
    );
    return normalized;
  }

  const items = loadJsonItems();
  const index = items.findIndex((entry) => entry.id === normalized.id);
  if (index === -1) items.push(normalized);
  else items[index] = normalized;
  saveJsonItems(items);
  return normalized;
}

// Finish a remote deletion only while the persisted record still belongs to
// the calling worker. A long-running provider call may outlive its lease and
// another worker may reclaim it, or a replacement may cancel the operation.
// SQLite's conditional UPDATE is atomic across processes; no auxiliary claim
// coordinator lock is held while accessing the application database.
function usesSqliteTrashStore() {
  return isDbEnabled() && hasTrashTable();
}

function saveRemoteDeletionIfExpectedLease(id, expectedToken, operationId, update) {
  if (!id || !operationId || typeof update !== "function") {
    throw new TypeError("A remote operation and updater are required");
  }
  const isOwner = (entry) => entry?.status === "remote_delete_pending"
    && (entry.metadata?.remoteDeletion?.leaseToken ?? null) === (expectedToken ?? null)
    && entry.metadata?.remoteDeletion?.operationId === operationId
    && ["pending", "retry_wait", "failed"].includes(entry.metadata.remoteDeletion.state);
  if (usesSqliteTrashStore()) {
    const current = getTrashItem(id);
    if (!isOwner(current)) return current;
    const next = normalizeTrashItem(update(current));
    const result = getDb().prepare(`
      UPDATE trash_items SET status = ?, metadata_json = ?
      WHERE id = ? AND status = 'remote_delete_pending'
        AND json_extract(metadata_json, '$.remoteDeletion.leaseToken') IS ?
        AND json_extract(metadata_json, '$.remoteDeletion.operationId') = ?
        AND json_extract(metadata_json, '$.remoteDeletion.state') IN ('pending', 'retry_wait', 'failed')
    `).run(next.status, jsonStringify(next.metadata), id, expectedToken ?? null, operationId);
    return result.changes === 1 ? next : getTrashItem(id);
  }
  // The legacy JSON mode performs a synchronous read/compare/write without
  // yielding the event loop. SQLite mode above is the cross-process authority.
  const items = loadJsonItems();
  const index = items.findIndex((entry) => entry.id === id);
  if (index < 0) return null;
  const current = items[index];
  if (!isOwner(current)) return current;
  const next = normalizeTrashItem(update(current));
  items[index] = next;
  saveJsonItems(items);
  return next;
}

function saveRemoteDeletionIfLeaseOwner(id, token, operationId, update) {
  if (!token) throw new TypeError("A remote claim token is required");
  return saveRemoteDeletionIfExpectedLease(id, token, operationId, update);
}

function isFileTrashed(folderId, fileName) {
  const name = path.basename(fileName || "");
  if (!name) return false;
  const folder = folderId || "root";
  if (isDbEnabled() && hasTrashTable()) {
    return Boolean(getDb().prepare(`
      SELECT 1 FROM trash_items
      WHERE item_type = ? AND status IN (?, ?) AND original_folder_id = ? AND original_file_name = ?
      LIMIT 1
    `).get("file", "trashed", "remote_delete_pending", folder, name));
  }

  return loadJsonItems().some((item) => (
    item.itemType === "file" &&
    ["trashed", "remote_delete_pending"].includes(item.status) &&
    item.originalFolderId === folder &&
    item.originalFileName === name
  ));
}

function listPendingFileRemoteDeletions(folderId, fileName) {
  const name = path.basename(fileName || "");
  if (!name) return [];
  const folder = folderId || "root";
  if (isDbEnabled() && hasTrashTable()) {
    return getDb().prepare(`
      SELECT * FROM trash_items
      WHERE item_type = ? AND status = ? AND original_folder_id = ? AND original_file_name = ?
      ORDER BY deleted_at DESC
    `).all("file", "remote_delete_pending", folder, name).map(rowToItem);
  }

  return loadJsonItems().filter((item) => (
    item.itemType === "file" && item.status === "remote_delete_pending" &&
    item.originalFolderId === folder && path.basename(item.originalFileName || "") === name
  ));
}

module.exports = {
  getTrashItem,
  isFileTrashed,
  listPendingFileRemoteDeletions,
  listTrashItems,
  saveTrashItem,
  saveRemoteDeletionIfLeaseOwner,
  saveRemoteDeletionIfExpectedLease,
  usesSqliteTrashStore,
};
