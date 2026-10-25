const { getDb } = require("../db");
const { assertNoLocalStrictSyncWriter } = require("../src/services/syncSqliteAccountWriteFence");
const { jsonStringify, randomId, runWrite, safeJsonParse } = require("./repositoryUtils");

const ANALYTICS_KEYS = [
  "uploads",
  "downloads",
  "logins",
  "deletions",
  "approvals",
  "rejections",
  "restores",
  "versionDeletions",
];

const EVENT_TO_KEY = {
  upload: "uploads",
  download: "downloads",
  login: "logins",
  deletion: "deletions",
  approval: "approvals",
  rejection: "rejections",
  restore: "restores",
  versionDeletion: "versionDeletions",
};

const KEY_TO_EVENT = Object.fromEntries(Object.entries(EVENT_TO_KEY).map(([event, key]) => [key, event]));

function getTimestampForKey(key, item) {
  return (
    item.uploadedAt ||
    item.downloadedAt ||
    item.loginAt ||
    item.deletedAt ||
    item.approvedAt ||
    item.rejectedAt ||
    item.restoredAt ||
    item.timestamp ||
    new Date().toISOString()
  );
}

function getUsernameForKey(key, item) {
  return item.uploadedBy || item.downloadedBy || item.username || item.deletedBy || item.approvedBy || item.rejectedBy || item.restoredBy || "";
}

function loadAnalytics() {
  const result = Object.fromEntries(ANALYTICS_KEYS.map((key) => [key, []]));
  const rows = getDb().prepare(`
    SELECT event_type, username, folder_id, folder_name, file_name, size, timestamp, details_json
    FROM analytics_events
    ORDER BY timestamp ASC
  `).all();

  for (const row of rows) {
    const key = EVENT_TO_KEY[row.event_type];
    if (!key) continue;
    const item = safeJsonParse(row.details_json, {});
    result[key].push({
      ...item,
      folderId: item.folderId || row.folder_id || "root",
      folderName: item.folderName || row.folder_name || "",
      filename: item.filename || row.file_name || "",
    });
  }

  return result;
}

function saveAnalytics(entries = {}) {
  assertNoLocalStrictSyncWriter();
  const db = getDb();
  runWrite(db, () => {
    db.prepare("DELETE FROM analytics_events").run();
    const insert = db.prepare(`
      INSERT INTO analytics_events (id, event_type, username, folder_id, folder_name, file_name, size, timestamp, details_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        event_type = excluded.event_type,
        username = excluded.username,
        folder_id = excluded.folder_id,
        folder_name = excluded.folder_name,
        file_name = excluded.file_name,
        size = excluded.size,
        timestamp = excluded.timestamp,
        details_json = excluded.details_json
    `);

    for (const key of ANALYTICS_KEYS) {
      const eventType = KEY_TO_EVENT[key];
      for (const item of entries[key] || []) {
        insert.run(
          item.id || randomId(),
          eventType,
          getUsernameForKey(key, item),
          item.folderId || "root",
          item.folderName || "",
          item.filename || "",
          Number(item.size) || 0,
          getTimestampForKey(key, item),
          jsonStringify(item)
        );
      }
    }
  });
}

module.exports = { loadAnalytics, saveAnalytics };
