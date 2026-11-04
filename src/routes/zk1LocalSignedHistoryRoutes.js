"use strict";

// ISOLATED DEVELOPMENT API: canonical signed zk-1 metadata archive.
// It is NOT a witness/CAS-status authority and MUST NOT authorize protected
// file reads, recovery, migrations, or server-side decryption.
const { Zk1LocalSignedHistoryStore } = require("../services/zk1LocalSignedHistoryStore");
const express = require("express");

const B64 = /^[A-Za-z0-9_-]+$/;
function reject() {
  const error = new Error("ZK1_HISTORY_INVALID");
  error.code = "ZK1_HISTORY_INVALID";
  throw error;
}
function exactFields(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))
    || Reflect.ownKeys(value).some((field) => !fields.includes(field))) reject();
}
function decode64(value, min, max) {
  if (typeof value !== "string" || !value.length || !B64.test(value)
    || value.length % 4 === 1 || value.length > Math.ceil(max * 4 / 3) + 5) reject();
  const raw = Buffer.from(value, "base64url");
  if (raw.length < min || raw.length > max || raw.toString("base64url") !== value) reject();
  return raw;
}
function scope(query) {
  exactFields(query, ["accountId", "compartmentId", "keyringId"]);
  return {
    account_id: decode64(query.accountId, 16, 16),
    compartment_id: decode64(query.compartmentId, 1, 128),
    keyring_id: decode64(query.keyringId, 16, 16),
  };
}
function registerZk1LocalSignedHistoryRoutes({
  app, authenticate, requirePermission, dbPath, nowSeconds, auditLog,
}) {
  const store = new Zk1LocalSignedHistoryStore(dbPath, { nowSeconds });
  const neverCache = (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  };
  const checked = (callback) => async (req, res) => {
    try { await callback(req, res); }
    catch (error) {
      const code = error?.code;
      const status = code === "ZK1_HISTORY_CONFLICT" ? 409
        : code === "ZK1_HISTORY_INVALID" ? 400
          : code === "ZK1_HISTORY_LIMIT" ? 413
          : code === "ZK1_HISTORY_CORRUPT" ? 503
            : error?.name === "RootarkZkError" ? 422 : 503;
      res.status(status).json({ error: status === 503 ? "Storage unavailable"
        : status === 422 ? "Invalid signed manifest or authorization" : code });
    }
  };
  const root = "/zk-dev/v1/zk1-history";
  const reader = [neverCache, authenticate, requirePermission("listFiles")];
  // At most 8 MiB raw canonical CBOR can be ~10.7 MiB after base64url+JSON.
  // Authenticate and authorize BEFORE parsing this exceptional 11 MiB body,
  // so anonymous clients cannot allocate large signed-manifest JSON objects.
  const writer = [neverCache, authenticate, requirePermission("upload"),
    express.json({ limit: "11mb" })];
  const owner = (req) => req.user.username;

  app.post(root, ...writer, checked(async (req, res) => {
    exactFields(req.body, ["account", "manifestBase64", "expectedRevision", "expectedDigest"]);
    if (req.body.account !== owner(req)) {
      res.status(409).json({ error: "VAULT_ACCOUNT_CHANGED" });
      return;
    }
    if (!Number.isSafeInteger(req.body.expectedRevision)
      || req.body.expectedRevision < 0) reject();
    const expectedDigest = req.body.expectedDigest === null ? null
      : decode64(req.body.expectedDigest, 32, 32);
    const committed = await store.append({
      owner: owner(req),
      manifestBytes: decode64(req.body.manifestBase64, 1, 8 * 1024 * 1024),
      expectedRevision: req.body.expectedRevision, expectedDigest,
    });
    if (typeof auditLog === "function") {
      try {
        auditLog("zk_dev.signed_history.append",
          { username: owner(req), role: req.user.role },
          { type: "zk1_local_signed_history" }, "append", "success",
          { revision: committed.revision });
      } catch (_) { /* audit outage must not falsify persisted state */ }
    }
    res.status(201).json({ revision: committed.revision,
      digest: committed.digest.toString("base64url"),
      warning: committed.capacity.warning,
      authority: "LOCAL_ONLY_UNWITNESSED",
    });
  }));

  app.get(root + "/head", ...reader, checked(async (req, res) => {
    const archived = store.snapshot({ owner: owner(req), ...scope(req.query) });
    if (!archived) return res.status(404).json({ error: "ZK1_HISTORY_NOT_FOUND" });
    return res.json({ revision: archived.revision,
      digest: archived.digest.toString("base64url"),
      authority: "LOCAL_ONLY_UNWITNESSED",
    });
  }));

  app.get(root + "/entries/:revision", ...reader, checked(async (req, res) => {
    const value = Number(req.params.revision);
    if (!/^[1-9][0-9]*$/.test(req.params.revision) || !Number.isSafeInteger(value)) reject();
    const archived = store.snapshot({ owner: owner(req), ...scope(req.query) });
    if (!archived || value > archived.revision) {
      return res.status(404).json({ error: "ZK1_HISTORY_NOT_FOUND" });
    }
    return res.json({ revision: value, manifestBase64: archived.entries[value - 1].toString("base64url"),
      headRevision: archived.revision, headDigest: archived.digest.toString("base64url"),
      authority: "LOCAL_ONLY_UNWITNESSED",
    });
  }));
  return store;
}

module.exports = { registerZk1LocalSignedHistoryRoutes };
