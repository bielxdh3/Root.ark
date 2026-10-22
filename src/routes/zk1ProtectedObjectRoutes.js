"use strict";

// Optional zk-1 *ciphertext-only* HTTP endpoints. Mount ONLY with a store
// configured against an independently pinned witness and a trusted manifest
// provider, plus authenticated server-side account-to-scope resolution.
// They do not replace or secure legacy upload/download, WebDAV, or sync.
const express = require("express");
const FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "device_id", "operation",
  "object_id", "expected_object_revision", "manifest_revision", "manifest_digest",
  "epoch", "nonce", "issued_at", "expires_at", "ciphertext_digest",
]);
const BYTE_FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "manifest_digest", "nonce",
  "ciphertext_digest",
]);
const B64U = /^[A-Za-z0-9_-]+$/;

function invalid() {
  const error = new Error("ZK_CONTENT_DENIED");
  error.code = "ZK_CONTENT_DENIED";
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))
    || Reflect.ownKeys(value).some((key) => !fields.includes(key))) invalid();
}
function b64(value, maxBytes) {
  if (typeof value !== "string" || value.length < 1
    || value.length > Math.ceil(maxBytes * 4 / 3) + 4 || !B64U.test(value)) invalid();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length > maxBytes || bytes.toString("base64url") !== value) invalid();
  return bytes;
}
function authorizationWire(raw) {
  exact(raw, FIELDS);
  const result = {};
  for (const field of FIELDS) {
    result[field] = BYTE_FIELDS.includes(field)
      ? raw[field] === null && field === "ciphertext_digest"
        ? null : b64(raw[field], field === "compartment_id" ? 128 : 32)
      : raw[field];
  }
  return result;
}

function registerZk1ProtectedObjectRoutes({ app, store, authenticate,
  requirePermission, resolveTrustedScope }) {
  if (!app || typeof app.post !== "function" || !store
    || typeof store.put !== "function" || typeof store.get !== "function"
    || typeof authenticate !== "function" || typeof requirePermission !== "function"
    || typeof resolveTrustedScope !== "function") invalid();
  const fenceHeaders = (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  };
  const checked = (operation) => async (req, res) => {
    try {
      const trustedScope = resolveTrustedScope(req.user);
      if (!trustedScope) invalid();
      exact(req.body, operation === "put"
        ? ["authorization", "signatureBase64", "ciphertextBase64"]
        : ["authorization", "signatureBase64"]);
      const request = {
        scope: trustedScope, authorization: authorizationWire(req.body.authorization),
        signature: b64(req.body.signatureBase64, 64),
        ...(operation === "put" ? { ciphertext: b64(req.body.ciphertextBase64, 4 * 1024 * 1024) } : {}),
      };
      await store.runWithAdmission(request, operation, (result) => new Promise((resolve, reject) => {
        // Do not release the witness admission when res.json() merely queues
        // bytes. Keep revocation closed until the socket has finished egress
        // into the kernel or has been closed/aborted.
        if (res.destroyed || res.writableEnded) return reject(new Error("ZK_CONTENT_UNAVAILABLE"));
        const clear = () => {
          res.off("finish", settled);
          res.off("close", settled);
        };
        const settled = () => { clear(); resolve(); };
        res.once("finish", settled);
        res.once("close", settled);
        try {
          if (operation === "put") res.status(result.revision === 1 ? 201 : 200).json(result);
          else res.status(200).json({ id: result.id, revision: result.revision,
            epoch: result.epoch, ciphertextBase64: result.ciphertext.toString("base64url") });
        } catch (error) { clear(); reject(error); }
      }));
      return;
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      const status = error?.code === "ZK_CONTENT_NOT_FOUND" ? 404
        : ["ZK_CONTENT_REPLAY", "ZK_CONTENT_CONFLICT"].includes(error?.code) ? 409
          : error?.code === "ZK_CONTENT_DENIED" ? 403 : 503;
      return res.status(status).json({ error: status === 503
        ? "ZK_CONTENT_UNAVAILABLE" : error.code });
    }
  };
  const parseSealedContent = express.json({ limit: "6mb", type: "application/json" });
  // The normal workspace discovers this opt-in capability only through its
  // authenticated session. Registration itself is dev/test-only (bootstrap).
  // Never publish the configured owner's scope or authority pins to browsers.
  app.get("/zk-1/v1/workspace-capability", fenceHeaders, authenticate,
    requirePermission("listFiles"), requirePermission("upload"), (req, res) => {
      try {
        if (!resolveTrustedScope(req.user)) invalid();
        res.json({ enabled: true });
      } catch (_) { res.status(403).json({ error: "ZK_CONTENT_DENIED" }); }
    });
  // POST-for-read prevents accidental caches and keeps signed nonces out of URLs.
  app.post("/zk-1/v1/content/read", fenceHeaders, authenticate,
    requirePermission("listFiles"), parseSealedContent, checked("get"));
  app.post("/zk-1/v1/content/put", fenceHeaders, authenticate,
    requirePermission("upload"), parseSealedContent, checked("put"));
}

module.exports = { registerZk1ProtectedObjectRoutes };
