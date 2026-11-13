const { getDb } = require("../db");
const { ensureFolderId, ensureRootFolder, jsonStringify, nowIso, safeJsonParse, basename } = require("./repositoryUtils");

function isPublicLinkViewerId(viewerId) {
  return typeof viewerId === "string" && /^[a-f0-9]{32}$/.test(viewerId);
}

const SHARE_OPERATIONS = ["view", "preview", "download"];

// Only a link with no permissions field at all (pre-migration legacy) maps to NULL, which reads back as all operations.
// Every other non-array value is stored as an empty list and fails closed.
function permissionsToColumn(permissions) {
  if (permissions === undefined) return null;
  if (!Array.isArray(permissions)) return "[]";
  return JSON.stringify(SHARE_OPERATIONS.filter((operation) => permissions.includes(operation)));
}

// NULL column = legacy link (no permissions field, all operations). Malformed stored values and NULL rows that carry
// permissions metadata fail closed to no operations.
function rowPermissions(row, metadata) {
  if (row.permissions_json === null || row.permissions_json === undefined) {
    return Object.prototype.hasOwnProperty.call(metadata, "permissions") ? [] : undefined;
  }
  const parsed = safeJsonParse(row.permissions_json, null);
  return Array.isArray(parsed) ? parsed : [];
}

function linkAllowsOperation(link, operation) {
  if (link.permissions === undefined) return SHARE_OPERATIONS.includes(operation);
  return Array.isArray(link.permissions) && link.permissions.includes(operation);
}

function rowToLink(row) {
  const metadata = safeJsonParse(row.metadata_json, {});
  const permissions = rowPermissions(row, metadata);
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
    ...(permissions === undefined ? {} : { permissions }),
  };
}

function loadPublicLinks() {
  const rows = getDb().prepare(`
    SELECT token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, permissions_json
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
  // A stale legacy snapshot is never evidence of capability revocation. An
  // explicit trash lifecycle supplies the affected resource separately; the
  // SQLite transaction revokes ALL matching C-tokens, including grants added
  // after the caller loaded its snapshot.
  const revocation = options.capabilityRevocation;
  if (revocation !== undefined && (!revocation || typeof revocation !== "object"
    || !/^[A-Za-z0-9._:-]{1,160}$/.test(revocation.folderId || "")
    || (revocation.fileName !== undefined
      && (!basename(revocation.fileName) || basename(revocation.fileName) !== revocation.fileName)))) {
    throw new Error("Invalid explicit capability trash revocation scope");
  }
  db.transaction(() => {
    ensureRootFolder(db);
    const existingRows = db.prepare(`
      SELECT token, folder_id, file_name, created_by, created_at, expires_at,
        max_views, views, password_hash, metadata_json, permissions_json
      FROM public_links
      WHERE revoked_at IS NULL
    `).all();
    const existingByToken = new Map(existingRows.map((row) => [row.token, row]));
    const activeTokens = new Set();
    const insert = db.prepare(`
      INSERT INTO public_links (token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, permissions_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
      ON CONFLICT(token) DO UPDATE SET
        folder_id = excluded.folder_id,
        file_name = excluded.file_name,
        created_by = excluded.created_by,
        expires_at = excluded.expires_at,
        max_views = excluded.max_views,
        views = excluded.views,
        password_hash = excluded.password_hash,
        metadata_json = excluded.metadata_json,
        permissions_json = excluded.permissions_json,
        revoked_at = NULL
      WHERE public_links.revoked_at IS NULL
    `);

    for (const [token, link] of Object.entries(entries || {})) {
      const fileName = basename(link?.fileName);
      if (!/^[a-f0-9]{48}$/i.test(token) || !fileName) continue;
      ensureFolderId(db, link.folderId || "root");
      const existing = existingByToken.get(token);
      const existingLink = existing ? rowToLink(existing) : null;
      // The stored capability policy is immutable under legacy whole-map
      // reconciliation. A stale or malformed JSON snapshot cannot replace
      // the binding or silently downgrade an active C-prefixed grant.
      if (existingLink?.shareKind === "capability-v1"
        && (link.shareKind !== "capability-v1"
          || JSON.stringify(existingLink.resourceBinding) !== JSON.stringify(link.resourceBinding)
          || existingLink.fileName !== fileName
          || existingLink.folderId !== (link.folderId || "root"))) {
        activeTokens.add(token);
        continue;
      }
      const views = Math.max(Number(link.views) || 0, Number(existing?.views) || 0);
      const downloads = Math.max(Number(link.downloads) || 0, Number(existingLink?.downloads) || 0);
      const activeViewers = {};
      for (const viewers of [existingLink?.activeViewers, link.activeViewers]) {
        if (!viewers || typeof viewers !== "object") continue;
        for (const [viewerId, viewer] of Object.entries(viewers)) {
          if (!isPublicLinkViewerId(viewerId)) continue;
          const viewerExpiresAt = new Date(viewer?.expiresAt).getTime();
          if (Number.isFinite(viewerExpiresAt) && viewerExpiresAt > Date.now()) {
            const previous = activeViewers[viewerId];
            activeViewers[viewerId] = {
              ...previous,
              ...viewer,
              ...(previous?.downloadCounted === true || viewer?.downloadCounted === true ? { downloadCounted: true } : {}),
            };
          }
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
        // Capability aliases are managed by addCapabilitySession under a
        // dedicated IMMEDIATE transaction. Always preserve the newest DB
        // session set rather than replacing it with a stale legacy snapshot.
        ...(link.shareKind === "capability-v1"
          ? { capabilitySessions: existingLink?.shareKind === "capability-v1"
            ? (existingLink.capabilitySessions || {}) : {} }
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
        jsonStringify(mergedLink),
        permissionsToColumn(Object.prototype.hasOwnProperty.call(link, "permissions") ? link.permissions : existingLink?.permissions)
      );
    }

    const revoke = db.prepare("UPDATE public_links SET revoked_at = ? WHERE token = ? AND revoked_at IS NULL");
    for (const row of existingRows) {
      if (activeTokens.has(row.token)) continue;
      // Only the explicit single-token revokeCapability operation can revoke
      // an UNEXPIRED C-prefixed capability. Absence from a legacy snapshot
      // may mean another process created it after our read. Expired rows can
      // still be tombstoned by routine cleanup to bound metadata retention.
      if (/^C[a-f0-9]{47}$/.test(row.token)
        && new Date(row.expires_at).getTime() > Date.now()) continue;
      revoke.run(now, row.token);
    }

    if (revocation) {
      if (process.platform === "win32" && revocation.fileName !== undefined) {
        // The same physical NTFS file can have old C-token grants recorded
        // under multiple case aliases. SQLite NOCASE only folds ASCII, so
        // compare Unicode spellings under the same IMMEDIATE transaction.
        const rows = db.prepare(`SELECT token, file_name FROM public_links
          WHERE revoked_at IS NULL AND folder_id = ?
            AND token GLOB 'C*' AND LENGTH(token) = 48`).all(revocation.folderId);
        const canonicalFold = revocation.fileName.toLowerCase();
        for (const row of rows) {
          if (/^C[a-f0-9]{47}$/.test(row.token)
            && typeof row.file_name === "string"
            && row.file_name.toLowerCase() === canonicalFold) {
            revoke.run(now, row.token);
          }
        }
      } else {
        // POSIX files named A.txt and a.txt are distinct physical objects.
        db.prepare(`UPDATE public_links SET revoked_at = ?
          WHERE revoked_at IS NULL AND folder_id = ?
            AND token GLOB 'C*' AND LENGTH(token) = 48
            AND (? IS NULL OR file_name = ?)`).run(now, revocation.folderId,
          revocation.fileName ?? null, revocation.fileName ?? null);
      }
    }

    const insertRevoked = db.prepare(`
      INSERT OR IGNORE INTO public_links (token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, permissions_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        permissionsToColumn(link.permissions),
        now
      );
    }
  }).immediate();
}

function createCapability(token, link) {
  if (!/^C[a-f0-9]{47}$/.test(token || "") || link?.shareKind !== "capability-v1"
    || link?.resourceBinding?.version !== 2
    || !/^[a-f0-9]{64}$/.test(link.resourceBinding.identity || "")
    || !basename(link.fileName) || basename(link.fileName) !== link.fileName
    || !link.createdBy || new Date(link.expiresAt).getTime() <= Date.now()) {
    return { status: "invalid" };
  }
  const db = getDb();
  return db.transaction(() => {
    ensureRootFolder(db);
    ensureFolderId(db, link.folderId || "root");
    const result = db.prepare(`INSERT OR IGNORE INTO public_links
      (token, folder_id, file_name, created_by, created_at, expires_at,
       max_views, views, password_hash, metadata_json, permissions_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`).run(
      token, link.folderId || "root", link.fileName, link.createdBy,
      link.createdAt || nowIso(), link.expiresAt, Number(link.maxViews) || 0,
      0, link.passwordHash || null,
      jsonStringify({ ...link, capabilitySessions: {} }), permissionsToColumn(link.permissions));
    return { status: result.changes === 1 ? "ok" : "collision" };
  }).immediate();
}

function revokeCapability(token, username) {
  if (!/^C[a-f0-9]{47}$/.test(token || "")) return { status: "missing" };
  const db = getDb();
  return db.transaction(() => {
    const row = db.prepare(`SELECT created_by, metadata_json FROM public_links
      WHERE token = ? AND revoked_at IS NULL`).get(token);
    if (!row) return { status: "missing" };
    const metadata = safeJsonParse(row.metadata_json, {});
    if (metadata.shareKind !== "capability-v1") return { status: "missing" };
    const owner = String(row.created_by || metadata.createdBy || "").trim().toLowerCase();
    if (!owner || owner !== String(username || "").trim().toLowerCase()) {
      return { status: "forbidden" };
    }
    const outcome = db.prepare(`UPDATE public_links SET revoked_at = ?
      WHERE token = ? AND revoked_at IS NULL`).run(nowIso(), token);
    return { status: outcome.changes === 1 ? "ok" : "missing" };
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

// Mutate precisely ONE capability under SQLite's cross-process writer lock.
// savePublicLinks() intentionally reconciles an entire legacy snapshot and
// would revoke unrelated shares or overwrite another exchange's sessions if
// used after awaiting a filesystem/provider read.
function addCapabilitySession(token, options = {}) {
  const { alias, hash, expiresAt, expectedResourceBinding, maxSessions = 8 } = options;
  if (!/^C[a-f0-9]{47}$/.test(token || "") || !/^[a-f0-9]{32}$/.test(alias || "")
    || !/^[a-f0-9]{64}$/.test(hash || "") || !Number.isSafeInteger(maxSessions)
    || maxSessions < 1 || maxSessions > 64) return { status: "invalid" };

  const db = getDb();
  return db.transaction(() => {
    const row = db.prepare(`
      SELECT token, folder_id, file_name, created_by, created_at, expires_at,
        max_views, views, password_hash, metadata_json, permissions_json
      FROM public_links WHERE token = ? AND revoked_at IS NULL
    `).get(token);
    if (!row) return { status: "missing" };
    const link = rowToLink(row);
    const expiry = new Date(row.expires_at).getTime();
    const sessionExpiry = new Date(expiresAt).getTime();
    const now = Date.now();
    if (link.shareKind !== "capability-v1" || link.resourceBinding?.version !== 2
      || JSON.stringify(link.resourceBinding) !== JSON.stringify(expectedResourceBinding)
      || (options.expectedFileName !== undefined && link.fileName !== options.expectedFileName)
      || (options.expectedFolderId !== undefined && link.folderId !== options.expectedFolderId)
      || !Number.isFinite(expiry) || expiry <= now
      || !Number.isFinite(sessionExpiry) || sessionExpiry <= now || sessionExpiry > expiry
      || sessionExpiry > now + 5 * 60_000) return { status: "changed" };

    const sessions = Object.entries(link.capabilitySessions || {})
      .filter(([id, item]) => /^[a-f0-9]{32}$/.test(id)
        && /^[a-f0-9]{64}$/.test(item?.hash || "")
        && Number.isFinite(new Date(item.expiresAt).getTime())
        && new Date(item.expiresAt).getTime() > now
        && new Date(item.expiresAt).getTime() <= expiry)
      .sort((a, b) => new Date(b[1].expiresAt).getTime() - new Date(a[1].expiresAt).getTime())
      .slice(0, maxSessions - 1);
    if (sessions.some(([id]) => id === alias)) return { status: "collision" };
    link.capabilitySessions = Object.fromEntries([...sessions, [alias, { hash, expiresAt }]]);
    const updated = db.prepare(`UPDATE public_links SET metadata_json = ?
      WHERE token = ? AND revoked_at IS NULL`).run(jsonStringify(link), token);
    if (updated.changes !== 1) return { status: "missing" };
    return { status: "ok", expiresAt };
  }).immediate();
}

function consumePublicLinkQuota(token, options = {}) {
  const db = getDb();
  const kind = options.kind;
  if (kind !== "view" && kind !== "download" && kind !== "session") throw new TypeError("Invalid public link quota kind");

  return db.transaction(() => {
    const fallbackLinks = options.fallbackLinks && typeof options.fallbackLinks === "object" ? options.fallbackLinks : {};
    const insertFallback = db.prepare(`
      INSERT OR IGNORE INTO public_links (token, folder_id, file_name, created_by, created_at, expires_at, max_views, views, password_hash, metadata_json, permissions_json, revoked_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
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
        jsonStringify(fallbackLink),
        permissionsToColumn(fallbackLink.permissions)
      );
    }

    const row = db.prepare(`
      SELECT token, folder_id, file_name, created_by, created_at, expires_at,
        max_views, views, password_hash, metadata_json, permissions_json
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
    if (options.requiredOperation && !linkAllowsOperation(link, options.requiredOperation)) return { status: "operation_denied" };

    if (kind === "view" || kind === "session") {
      const views = Number(row.views) || 0;
      const maxViews = Number(row.max_views) || 0;
      if (process.env.NODE_ENV === "test" && typeof options.afterQuotaRead === "function") options.afterQuotaRead();
      if (kind === "view" && maxViews > 0 && views >= maxViews) return { status: "limit", limit: "views" };

      link.views = kind === "view" ? views + 1 : views;
      if (kind === "view") link.lastViewedAt = now;
      if (isPublicLinkViewerId(options.viewer?.id) && options.viewer?.expiresAt) {
        const viewers = link.activeViewers && typeof link.activeViewers === "object" ? link.activeViewers : {};
        for (const [viewerId, viewer] of Object.entries(viewers)) {
          if (!isPublicLinkViewerId(viewerId)) {
            delete viewers[viewerId];
            continue;
          }
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
      const downloadViewerId = isPublicLinkViewerId(options.downloadViewerId) ? options.downloadViewerId : "";
      const viewers = link.activeViewers && typeof link.activeViewers === "object" ? link.activeViewers : {};
      const downloadViewer = downloadViewerId && Object.prototype.hasOwnProperty.call(viewers, downloadViewerId)
        ? viewers[downloadViewerId]
        : null;
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
  addCapabilitySession,
  createCapability,
  consumePublicLinkQuota,
  getRecordedPublicLinkTokens,
  incrementPublicLinkViews,
  loadPublicLinks,
  revokeCapability,
  savePublicLinks,
};
