const { getDb } = require("../db");
const { jsonStringify, nowIso, safeJsonParse } = require("./repositoryUtils");
const { applySyncResumeAccountProof } = require("../src/services/syncResumeAccountProof");

function loadUsers() {
  return getDb().prepare(`
    SELECT username, password_hash, role, permissions_json, session_version, disabled,
      totp_enabled, totp_secret_json, totp_pending_secret_json, totp_recovery_hashes_json,
      totp_last_used_step, totp_enrolled_at, storage_revision
    FROM users
    WHERE deleted_at IS NULL
    ORDER BY id ASC
  `).all().map((row) => ({
    username: row.username,
    password: row.password_hash,
    role: row.role,
    permissions: safeJsonParse(row.permissions_json, {}),
    sessionVersion: row.session_version || 0,
    disabled: Boolean(row.disabled),
    totpEnabled: Boolean(row.totp_enabled),
    totpSecret: safeJsonParse(row.totp_secret_json, null),
    totpPendingSecret: safeJsonParse(row.totp_pending_secret_json, null),
    totpRecoveryHashes: safeJsonParse(row.totp_recovery_hashes_json, []),
    totpLastUsedStep: row.totp_last_used_step === null ? null : row.totp_last_used_step,
    totpEnrolledAt: row.totp_enrolled_at || null,
    storageRevision: row.storage_revision,
  }));
}

function saveUsers(users = [], { expectedDeletedUsers = [], allowRecreateUsernames = [] } = {}) {
  const db = getDb();
  const now = nowIso();
  const write = () => {
    const active = new Set();
    const existing = db.prepare("SELECT username, storage_revision, deleted_at FROM users").all();
    const byUsername = new Map(existing.map((row) => [row.username, row]));
    const allowedRecreate = new Set(allowRecreateUsernames);
    for (const user of users) {
      const username = String(user?.username || "").trim();
      if (!username) continue;
      if (active.has(username)) throw new Error("Duplicate user in account write");
      active.add(username);
      const row = byUsername.get(username);
      if (!row) {
        if (user.storageRevision !== undefined) throw new Error("User storage revision conflict");
      } else if (row.deleted_at !== null) {
        if (!allowedRecreate.has(username) || user.storageRevision !== undefined) {
          throw new Error("Deleted user storage revision conflict");
        }
      } else if (!Number.isSafeInteger(user.storageRevision)
        || user.storageRevision !== row.storage_revision) {
        throw new Error("User storage revision conflict");
      }
    }
    const expectedDeletes = new Map(expectedDeletedUsers.map((user) => [user.username, user.storageRevision]));
    for (const row of existing) {
      if (row.deleted_at !== null || active.has(row.username)) continue;
      if (expectedDeletes.get(row.username) !== row.storage_revision) {
        throw new Error("User deletion storage revision conflict");
      }
    }
    const upsert = db.prepare(`
      INSERT INTO users (username, password_hash, role, permissions_json, session_version, disabled,
        totp_enabled, totp_secret_json, totp_pending_secret_json, totp_recovery_hashes_json,
        totp_last_used_step, totp_enrolled_at, created_at, updated_at, deleted_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
      ON CONFLICT(username) DO UPDATE SET
        password_hash = excluded.password_hash,
        role = excluded.role,
        permissions_json = excluded.permissions_json,
        session_version = CASE
          WHEN users.deleted_at IS NOT NULL THEN MAX(users.session_version + 1, excluded.session_version)
          ELSE excluded.session_version
        END,
        disabled = excluded.disabled,
        totp_enabled = excluded.totp_enabled,
        totp_secret_json = excluded.totp_secret_json,
        totp_pending_secret_json = excluded.totp_pending_secret_json,
        totp_recovery_hashes_json = excluded.totp_recovery_hashes_json,
        totp_last_used_step = excluded.totp_last_used_step,
        totp_enrolled_at = excluded.totp_enrolled_at,
        storage_revision = users.storage_revision + 1,
        updated_at = excluded.updated_at,
        deleted_at = NULL
    `);

    for (const user of users) {
      const username = String(user?.username || "").trim();
      if (!username) continue;
      active.add(username);
      upsert.run(
        username,
        user.password || user.password_hash || "",
        user.role || "user",
        jsonStringify(user.permissions || {}),
        user.sessionVersion || 0,
        user.disabled ? 1 : 0,
        user.totpEnabled ? 1 : 0,
        user.totpSecret ? jsonStringify(user.totpSecret) : null,
        user.totpPendingSecret ? jsonStringify(user.totpPendingSecret) : null,
        jsonStringify(Array.isArray(user.totpRecoveryHashes) ? user.totpRecoveryHashes : []),
        Number.isSafeInteger(user.totpLastUsedStep) ? user.totpLastUsedStep : null,
        user.totpEnrolledAt || null,
        user.createdAt || user.created_at || now,
        now
      );
    }

    const softDelete = db.prepare("UPDATE users SET deleted_at = ?, updated_at = ?, storage_revision = storage_revision + 1 WHERE username = ? AND storage_revision = ? AND deleted_at IS NULL");
    for (const row of existing) {
      if (row.deleted_at === null && !active.has(row.username)) {
        if (softDelete.run(now, now, row.username, row.storage_revision).changes !== 1) {
          throw new Error("User deletion storage revision conflict");
        }
      }
    }
  };
  if (db.inTransaction) write();
  else db.transaction(write).immediate();
}

function commitSyncResumeProof(claim) {
  if (!claim || typeof claim.username !== "string" || typeof claim.deviceId !== "string"
    || claim.deviceId.length < 1 || claim.deviceId.length > 256
    || (claim.pauseFence !== null && (typeof claim.pauseFence !== "string"
      || claim.pauseFence.length > 512))
    || typeof claim.codeMac !== "string" || !/^[a-f0-9]{64}$/.test(claim.codeMac)) {
    return "conflict";
  }
  const db = getDb();
  // BEGIN IMMEDIATE serializes the read/compare/selective update with
  // concurrent SQLite writers, including other server processes. Never
  // UPSERT a stale users array or soft-delete unrelated accounts.
  return db.transaction(() => {
    const row = db.prepare(`SELECT username, password_hash, role, permissions_json,
      session_version, disabled,
      totp_enabled, totp_secret_json, totp_recovery_hashes_json, totp_last_used_step
      FROM users WHERE username = ? AND deleted_at IS NULL`).get(claim.username);
    if (!row) return "conflict";
    const user = {
      username: row.username,
      password: row.password_hash,
      role: row.role,
      permissions: safeJsonParse(row.permissions_json, {}),
      sessionVersion: row.session_version || 0,
      disabled: Boolean(row.disabled),
      totpEnabled: Boolean(row.totp_enabled),
      totpSecret: safeJsonParse(row.totp_secret_json, null),
      totpRecoveryHashes: safeJsonParse(row.totp_recovery_hashes_json, []),
      totpLastUsedStep: row.totp_last_used_step,
    };
    const result = applySyncResumeAccountProof(user, claim);
    if (result === "already") {
      // An equal replay digest alone is not ownership of the factor: another
      // host could have spent it for a different device/pause. SQLite pins
      // the *exact* signed resume intent in the same transaction as spending.
      const grant = db.prepare(`SELECT code_mac, device_id, pause_fence
        FROM sync_resume_factor_spend_grant
        WHERE username=? AND replay_digest=?`).get(claim.username, claim.expectedReplayDigest);
      return grant && grant.code_mac === claim.codeMac
        && grant.device_id === claim.deviceId
        && grant.pause_fence === claim.pauseFence ? "already" : "conflict";
    }
    if (result !== "committed") return result;
    const update = db.prepare(`UPDATE users SET totp_recovery_hashes_json = ?,
      totp_last_used_step = ?, storage_revision = storage_revision + 1,
      updated_at = ? WHERE username = ? AND deleted_at IS NULL`)
      .run(jsonStringify(user.totpRecoveryHashes), user.totpLastUsedStep, nowIso(), claim.username);
    if (update.changes !== 1) throw new Error("Sync resume account CAS failed");
    db.prepare(`INSERT INTO sync_resume_factor_spend_grant
      (username, replay_digest, code_mac, device_id, pause_fence, committed_at)
      VALUES (?, ?, ?, ?, ?, ?)`).run(claim.username, claim.expectedReplayDigest,
      claim.codeMac, claim.deviceId, claim.pauseFence, nowIso());
    return "committed";
  }).immediate();
}

module.exports = { loadUsers, saveUsers, commitSyncResumeProof };
