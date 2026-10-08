const { getDb } = require("../db");
const { ensureFolderId, ensureRootFolder, jsonStringify, nowIso, safeJsonParse, basename } = require("./repositoryUtils");

function rowToLink(row) {
  const metadata = safeJsonParse(row.metadata_json, {});
  return {
    ...metadata,
    fileName: row.file_name,
    folderId: row.folder_id || "root",
    createdBy: row.created_by || metadata.createdBy || null,
    createdAt: row.created_at,
    expiresAt: row.expires_at,
    maxViews: Number(row.max_views) || 0,
    views: Number(row.views) || 0,
    passwordHash: row.password_hash || metadata.passwordHash || null,
  };
}

function loadPublicLinks() {
  const rows = getDb().prepare(`
    SELECT token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json
    FROM public_links
    WHERE revoked_at IS NULL
  `).all();
  return Object.fromEntries(rows.map((row) => [row.token, rowToLink(row)]));
}

function getRecordedPublicLinkTokens(tokens = []) {
  const db = getDb();
  const recorded = new Set();
  const uniqueTokens = [...new Set((tokens || []).filter((token) => /^[a-f0-9]{48}$/i.test(token)))];
  for (let index = 0; index < uniqueTokens.length; index += 500) {
    const batch = uniqueTokens.slice(index, index + 500);
    const placeholders = batch.map(() => "?").join(", ");
    const rows = db.prepare(`SELECT token FROM public_links WHERE token IN (${placeholders})`).all(...batch);
    for (const row of rows) recorded.add(row.token);
  }
  return recorded;
}

function savePublicLinks(entries = {}, options = {}) {
  const db = getDb();
  const now = nowIso();
  db.transaction(() => {
    ensureRootFolder(db);
    const existingRows = db.prepare(`
      SELECT token, folder_id, file_name, created_by, created_at, expires_at,
        max_views, views, password_hash, metadata_json
      FROM public_links
      WHERE revoked_at IS NULL
    `).all();
    const existingByToken = new Map(existingRows.map((row) => [row.token, row]));
    const activeTokens = new Set();
    const insert = db.prepare(`
      INSERT INTO public_links (token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
      ON CONFLICT(token) DO UPDATE SET
        folder_id = excluded.folder_id,
        file_name = excluded.file_name,
        created_by = excluded.created_by,
        expires_at = excluded.expires_at,
        max_views = excluded.max_views,
        views = excluded.views,
        password_hash = excluded.password_hash,
        metadata_json = excluded.metadata_json,
        revoked_at = NULL
      WHERE public_links.revoked_at IS NULL
    `);

    for (const [token, link] of Object.entries(entries || {})) {
      const fileName = basename(link?.fileName);
      if (!/^[a-f0-9]{48}$/i.test(token) || !fileName) continue;
      ensureFolderId(db, link.folderId || "root");
      const existing = existingByToken.get(token);
      const existingLink = existing ? rowToLink(existing) : null;
      const views = Math.max(Number(link.views) || 0, Number(existing?.views) || 0);
      const downloads = Math.max(Number(link.downloads) || 0, Number(existingLink?.downloads) || 0);
      const activeViewers = {};
      for (const viewers of [existingLink?.activeViewers, link.activeViewers]) {
        if (!viewers || typeof viewers !== "object") continue;
        for (const [viewerId, viewer] of Object.entries(viewers)) {
          const viewerExpiresAt = new Date(viewer?.expiresAt).getTime();
          if (Number.isFinite(viewerExpiresAt) && viewerExpiresAt > Date.now()) activeViewers[viewerId] = viewer;
        }
      }
      const mergedLink = {
        ...link,
        views,
        downloads,
        activeViewers,
        ...(existingLink?.lastViewedAt && (!link.lastViewedAt || existingLink.lastViewedAt > link.lastViewedAt)
          ? { lastViewedAt: existingLink.lastViewedAt }
          : {}),
        ...(existingLink?.lastDownloadedAt && (!link.lastDownloadedAt || existingLink.lastDownloadedAt > link.lastDownloadedAt)
          ? { lastDownloadedAt: existingLink.lastDownloadedAt }
          : {}),
      };
      activeTokens.add(token);
      insert.run(
        token,
        link.folderId || "root",
        fileName,
        link.createdBy || null,
        link.createdAt || now,
        link.expiresAt || now,
        Number(link.maxViews) || 0,
        views,
        link.passwordHash || link.password_hash || null,
        jsonStringify(mergedLink)
      );
    }

    const revoke = db.prepare("UPDATE public_links SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL");
    for (const row of existingRows) {
      if (activeTokens.has(row.token)) continue;
      revoke.run(now, row.token);
    }

    const insertRevoked = db.prepare(`
      INSERT OR IGNORE INTO public_links (token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    for (const [token, link] of Object.entries(options.removedEntries || {})) {
      const fileName = basename(link?.fileName);
      if (activeTokens.has(token) || !/^[a-f0-9]{48}$/i.test(token) || !fileName) continue;
      ensureFolderId(db, link.folderId || "root");
      insertRevoked.run(
        token,
        link.folderId || "root",
        fileName,
        link.createdBy || null,
        link.createdAt || now,
        link.expiresAt || now,
        Number(link.maxViews) || 0,
        Number(link.views) || 0,
        link.passwordHash || link.password_hash || null,
        jsonStringify(link),
        now
      );
    }
  }).immediate();
}

function incrementPublicLinkViews(token, link) {
  const db = getDb();
  const update = () => {
    const row = db.prepare("SELECT views FROM public_links WHERE token = ? AND revoked_at IS NULL").get(token);
    if (!row) return null;

    db.prepare(`
      UPDATE public_links
      SET views = views + 1,
          metadata_json = ?
      WHERE token = ?
    `).run(jsonStringify(link), token);

    return (Number(row.views) || 0) + 1;
  };
  const updated = db.inTransaction ? update() : db.transaction(update)();

  return updated;
}

function consumePublicLinkQuota(token, options = {}) {
  const db = getDb();
  const kind = options.kind;
  if (kind !== "view" && kind !== "download") throw new TypeError("Invalid public link quota kind");

  return db.transaction(() => {
    const fallbackLinks = options.fallbackLinks && typeof options.fallbackLinks === "object" ? options.fallbackLinks : {};
    const insertFallback = db.prepare(`
      INSERT OR IGNORE INTO public_links (token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
    `);
    const now = nowIso();
    for (const [fallbackToken, fallbackLink] of Object.entries(fallbackLinks)) {
      const fileName = basename(fallbackLink?.fileName);
      if (!/^[a-f0-9]{48}$/i.test(fallbackToken) || !fileName) continue;
      ensureFolderId(db, fallbackLink.folderId || "root");
      insertFallback.run(
        fallbackToken,
        fallbackLink.folderId || "root",
        fileName,
        fallbackLink.createdBy || null,
        fallbackLink.createdAt || now,
        fallbackLink.expiresAt || now,
        Number(fallbackLink.maxViews) || 0,
        Number(fallbackLink.views) || 0,
        fallbackLink.passwordHash || fallbackLink.password_hash || null,
        jsonStringify(fallbackLink)
      );
    }

    const row = db.prepare(`
      SELECT token, folder_id, file_name, created_by, created_at, expires_at,
        max_views, views, password_hash, metadata_json
      FROM public_links
      WHERE token = ? AND revoked_at IS NULL
    `).get(token);
    if (!row) return { status: "missing" };

    const link = rowToLink(row);
    if (options.expectedFileName !== undefined && link.fileName !== options.expectedFileName) {
      return { status: "changed" };
    }
    if (options.expectedFolderId !== undefined && link.folderId !== options.expectedFolderId) {
      return { status: "changed" };
    }
    if (Object.prototype.hasOwnProperty.call(options, "expectedPasswordHash")
      && (link.passwordHash || null) !== (options.expectedPasswordHash || null)) {
      return { status: "password_changed" };
    }
    const expiresAt = new Date(link.expiresAt).getTime();
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) return { status: "expired" };

    if (kind === "view") {
      const views = Number(row.views) || 0;
      const maxViews = Number(row.max_views) || 0;
      if (process.env.NODE_ENV === "test" && typeof options.afterQuotaRead === "function") options.afterQuotaRead();
      if (maxViews > 0 && views >= maxViews) return { status: "limit", limit: "views" };

      link.views = views + 1;
      link.lastViewedAt = now;
      if (options.viewer?.id && options.viewer?.expiresAt) {
        const viewers = link.activeViewers && typeof link.activeViewers === "object" ? link.activeViewers : {};
        for (const [viewerId, viewer] of Object.entries(viewers)) {
          const viewerExpiresAt = new Date(viewer?.expiresAt).getTime();
          if (!Number.isFinite(viewerExpiresAt) || viewerExpiresAt <= Date.now()) delete viewers[viewerId];
        }
        viewers[options.viewer.id] = {
          createdAt: options.viewer.createdAt || now,
          expiresAt: options.viewer.expiresAt,
        };
        link.activeViewers = viewers;
      }
      db.prepare("UPDATE public_links SET views = ?, metadata_json = ? WHERE token = ? AND revoked_at IS NULL")
        .run(link.views, jsonStringify(link), token);
    } else {
      const downloads = Number(link.downloads) || 0;
      const maxDownloads = Number(link.maxDownloads) || 0;
      const downloadViewerId = String(options.downloadViewerId || "");
      const viewers = link.activeViewers && typeof link.activeViewers === "object" ? link.activeViewers : {};
      const downloadViewer = viewers[downloadViewerId];
      const viewerExpiresAt = new Date(downloadViewer?.expiresAt).getTime();
      const activeDownloadViewer = downloadViewerId && Number.isFinite(viewerExpiresAt) && viewerExpiresAt > Date.now()
        ? downloadViewer
        : null;
      if (activeDownloadViewer?.downloadCounted) {
        return { status: "ok", link, alreadyConsumed: true };
      }
      if (process.env.NODE_ENV === "test" && typeof options.afterQuotaRead === "function") options.afterQuotaRead();
      if (maxDownloads > 0 && downloads >= maxDownloads) return { status: "limit", limit: "downloads" };

      link.downloads = downloads + 1;
      link.lastDownloadedAt = now;
      if (activeDownloadViewer) {
        activeDownloadViewer.downloadCounted = true;
        link.activeViewers = viewers;
      }
      db.prepare("UPDATE public_links SET metadata_json = ? WHERE token = ? AND revoked_at IS NULL")
        .run(jsonStringify(link), token);
    }

    return { status: "ok", link };
  }).immediate();
}

module.exports = {
  consumePublicLinkQuota,
  getRecordedPublicLinkTokens,
  incrementPublicLinkViews,
  loadPublicLinks,
  savePublicLinks,
};
