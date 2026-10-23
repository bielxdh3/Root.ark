"use strict";

// Opt-in development encrypted-file transport. It neither accepts keys nor
// handles plaintext; normal Root.ark uploads/downloads remain unchanged.
const { OpaqueDevVaultStore } = require("../services/zkOpaqueDevVault");
const fs = require("node:fs");
const express = require("express");
const SODIUM_JS = require.resolve("libsodium-sumo");
const SODIUM_WRAPPERS_JS = require.resolve("libsodium-wrappers-sumo");

function registerOpaqueDevVaultRoutes({ app, authenticate, requirePermission, dbPath, auditLog }) {
  const store = new OpaqueDevVaultStore(dbPath);
  const neverCache = (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  };
  const checked = (fn) => (req, res) => {
    try {
      return fn(req, res);
    } catch (error) {
      const status = error.code === "VAULT_INVALID" ? 400
        : error.code === "VAULT_CONFLICT" || error.code === "VAULT_KEY_MISMATCH" ? 409
          : error.code === "VAULT_NOT_FOUND" ? 404
            : error.code === "VAULT_LIMIT" ? 413 : 503;
      return res.status(status).json({ error: status === 503 ? "Storage unavailable" : error.code });
    }
  };
  const owner = (req) => req.user.username;
  const matchingAccount = (req, res, expectedFields) => {
    const body = req.body;
    if (!body || typeof body !== "object" || Array.isArray(body)
      || Reflect.ownKeys(body).length !== expectedFields.length
      || expectedFields.some((key) => !Object.hasOwn(body, key))) {
      res.status(400).json({ error: "VAULT_INVALID" });
      return false;
    }
    // Reconcile the client's encryption AAD identity with the CURRENT auth
    // cookie in the same HTTP request. A prior GET /session is not sufficient:
    // another tab can switch accounts before the subsequent upload.
    if (body.account !== owner(req)) {
      res.status(409).json({ error: "VAULT_ACCOUNT_CHANGED" });
      return false;
    }
    return true;
  };
  const audit = (req, action, id, revision) => {
    if (typeof auditLog !== "function") return;
    try {
      auditLog("zk_dev.ciphertext." + action,
        { username: owner(req), role: req.user.role },
        { type: "zk_dev_ciphertext", id },
        action, "success", { revision });
    } catch (_) {
      // An audit backend outage must not silently undo a persisted CAS result.
    }
  };
  const reader = [neverCache, authenticate, requirePermission("listFiles")];
  // Larger opaque envelopes are parsed only after session, CSRF and permission
  // checks. GET requests and unknown/disabled routes never parse a JSON body.
  const opaqueJsonParser = express.json({ limit: "9mb" });
  const writer = [neverCache, authenticate, requirePermission("upload"), opaqueJsonParser];
  const deleter = [neverCache, authenticate, requirePermission("delete"), opaqueJsonParser];

  // Installed, audited npm assets are served only while the dev-vault feature
  // is enabled. No third-party CDN or browser request to an external host.
  app.get("/zk-dev/vendor/libsodium-sumo.js", neverCache, (_req, res, next) => {
    res.type("application/javascript");
    const stream = fs.createReadStream(SODIUM_JS);
    stream.on("error", next);
    stream.pipe(res);
  });
  app.get("/zk-dev/vendor/libsodium-wrappers.js", neverCache, (_req, res, next) => {
    res.type("application/javascript");
    const stream = fs.createReadStream(SODIUM_WRAPPERS_JS);
    stream.on("error", next);
    stream.pipe(res);
  });

  app.get("/zk-dev/v1/session", ...reader, checked((req, res) => {
    res.json({ username: owner(req), format: "rootark-dev-file-v1",
      activeKeyId: store.activeKeyId(owner(req)) });
  }));
  app.get("/zk-dev/v1/objects", ...reader, checked((req, res) => {
    res.json({ objects: store.list(owner(req)) });
  }));
  app.get("/zk-dev/v1/objects/:id", ...reader, checked((req, res) => {
    const found = store.get(owner(req), req.params.id);
    if (!found) return res.status(404).json({ error: "VAULT_NOT_FOUND" });
    return res.json(found);
  }));
  app.post("/zk-dev/v1/objects", ...writer, checked((req, res) => {
    if (!matchingAccount(req, res, ["account", "id", "envelope", "keyId"])) return;
    const created = store.create(owner(req), {
      id: req.body.id, envelope: req.body.envelope, keyId: req.body.keyId,
    });
    audit(req, "create", created.id, created.revision);
    return res.status(201).json(created);
  }));
  app.put("/zk-dev/v1/objects/:id", ...writer, checked((req, res) => {
    if (!matchingAccount(req, res, ["account", "expectedRevision", "envelope", "keyId"])) return;
    const body = req.body;
    const updated = store.replace(owner(req), {
      id: req.params.id, expectedRevision: body.expectedRevision, envelope: body.envelope,
      keyId: body.keyId,
    });
    audit(req, "update", updated.id, updated.revision);
    return res.json(updated);
  }));
  app.delete("/zk-dev/v1/objects/:id", ...deleter, checked((req, res) => {
    if (!matchingAccount(req, res, ["account", "expectedRevision"])) return;
    const body = req.body;
    const removed = store.remove(owner(req), {
      id: req.params.id, expectedRevision: body.expectedRevision,
    });
    audit(req, "delete", removed.id, removed.revision);
    return res.json(removed);
  }));
  return store;
}
module.exports = { registerOpaqueDevVaultRoutes };
