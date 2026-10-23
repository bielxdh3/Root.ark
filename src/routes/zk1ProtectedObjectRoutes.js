"use strict";

// Optional zk-1 *ciphertext-only* HTTP endpoints. Mount ONLY with a store
// configured against an independently pinned witness and a trusted manifest
// provider, plus authenticated server-side account-to-scope resolution.
// They do not replace or secure legacy upload/download, WebDAV, or sync.
const express = require("express");
const { registerZk1AuthenticatedMultiproviderRestoreRoute } =
  require("./zk1AuthenticatedMultiproviderRestoreRoutes");
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
  requirePermission, resolveTrustedScope, multiproviderRestore = null,
  opaqueCatalog = null,
  environment = "development" }) {
  if (!app || typeof app.post !== "function" || !store
    || typeof store.put !== "function" || typeof store.get !== "function"
    || typeof authenticate !== "function" || typeof requirePermission !== "function"
    || typeof resolveTrustedScope !== "function") invalid();
  const fenceHeaders = (_req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  };
  // A witness validates device authority, not the account's mutable web
  // session. Re-run the same authoritative middleware before sensitive effects
  // and read egress, while admission is still held. Its rejection must never
  // write to the live response: only the route's error handler sends a denial.
  const recheckSession = (req, originalUser, originalScope, permission) => {
    const probe = Object.create(req);
    probe.user = null;
    let approved = false;
    let rejectedStatus = null;
    const shadowResponse = {
      status(status) { rejectedStatus = status; return this; },
      json() { rejectedStatus ||= 403; return this; },
    };
    const denied = () => {
      const error = new Error("ZK_CONTENT_DENIED");
      error.code = "ZK_CONTENT_DENIED";
      error.httpStatus = [401, 403, 503].includes(rejectedStatus) ? rejectedStatus : 403;
      throw error;
    };
    try {
      authenticate(probe, shadowResponse, () => {
        requirePermission(permission)(probe, shadowResponse, () => { approved = true; });
      });
      if (!approved || rejectedStatus !== null || !probe.user
        || probe.user.username !== originalUser.username
        || probe.user.sessionVersion !== originalUser.sessionVersion) denied();
      const scope = resolveTrustedScope(probe.user);
      if (!scope || ["account_id", "compartment_id", "keyring_id"].some((field) =>
        !Buffer.isBuffer(scope[field]) || !Buffer.isBuffer(originalScope[field])
        || !scope[field].equals(originalScope[field]))) denied();
    } catch (error) {
      if (error?.code === "ZK_CONTENT_DENIED") throw error;
      denied();
    }
  };
  const checked = (operation) => async (req, res) => {
    try {
      const trustedScope = resolveTrustedScope(req.user);
      if (!trustedScope) invalid();
      const originalUser = { username: req.user.username,
        sessionVersion: req.user.sessionVersion };
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
        if (res.destroyed || res.writableEnded || res.headersSent) {
          return reject(new Error("ZK_CONTENT_UNAVAILABLE"));
        }
        const clear = () => {
          res.off("finish", settled);
          res.off("close", settled);
        };
        const settled = () => { clear(); resolve(); };
        res.once("finish", settled);
        res.once("close", settled);
        try {
          if (operation === "get") recheckSession(req, originalUser, trustedScope, "listFiles");
          if (operation === "put") res.status(result.revision === 1 ? 201 : 200).json(result);
          else res.status(200).json({ id: result.id, revision: result.revision,
            epoch: result.epoch, ciphertextBase64: result.ciphertext.toString("base64url") });
        } catch (error) { clear(); reject(error); }
      }), operation === "put"
        ? () => recheckSession(req, originalUser, trustedScope, "upload") : undefined);
      return;
    } catch (error) {
      if (res.headersSent || res.destroyed) return;
      const status = error?.httpStatus || (error?.code === "ZK_CONTENT_NOT_FOUND" ? 404
        : ["ZK_CONTENT_REPLAY", "ZK_CONTENT_CONFLICT"].includes(error?.code) ? 409
          : error?.code === "ZK_CONTENT_DENIED" ? 403 : 503);
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
        // V1 is still deliberately available for legacy dev fixtures, but a
        // V2 owner-history browser MUST NOT interpret V1 as equivalent security.
        // This reports a mode, never the owner's private scope or key pins.
        res.json({ enabled: true, securityVersion: store.signedHistoryRequired === true ? 2 : 1,
          signedHistoryRequired: store.signedHistoryRequired === true,
          ...(opaqueCatalog !== null ? { opaqueCatalogV1: true } : {}) });
      } catch (_) { res.status(403).json({ error: "ZK_CONTENT_DENIED" }); }
    });
  // POST-for-read prevents accidental caches and keeps signed nonces out of URLs.
  app.post("/zk-1/v1/content/read", fenceHeaders, authenticate,
    requirePermission("listFiles"), parseSealedContent, checked("get"));
  app.post("/zk-1/v1/content/put", fenceHeaders, authenticate,
    requirePermission("upload"), parseSealedContent, checked("put"));
  // Opt-in only: a separate pinned, independent signed CAS authority must
  // be configured to register these routes. No generic sync-v2 metadata.
  if (opaqueCatalog !== null) {
    if (!store.signedHistoryRequired || typeof opaqueCatalog.commit !== "function"
      || typeof opaqueCatalog.read !== "function"
      || opaqueCatalog.store !== store) invalid();
    // Relay only independently signed, nonce-bound authority statements. The
    // browser verifies both signatures against user-held offline key pins; the
    // application server cannot nominate a trusted key or invent a fresh head.
    const authorityHead = (kind) => async (req, res) => {
      try {
        const scope = resolveTrustedScope(req.user);
        if (!scope) invalid();
        const user = { username: req.user.username, sessionVersion: req.user.sessionVersion };
        exact(req.body, ["nonce"]);
        const nonce = b64(req.body.nonce, 32);
        if (nonce.length !== 32) invalid();
        const signed = kind === "witness"
          ? await store.witnessProvider.freshHead({ scope, nonce })
          : await opaqueCatalog.authority.readHead({ scope, nonce });
        const proof = Buffer.from(signed);
        if (proof.length < 1 || proof.length > 8192) invalid();
        recheckSession(req, user, scope, "listFiles");
        if (res.destroyed || res.headersSent || res.writableEnded) invalid();
        res.status(200).json(kind === "witness"
          ? { receiptBase64: proof.toString("base64url") }
          : { proofBase64: proof.toString("base64url") });
      } catch (error) {
        if (!res.headersSent && !res.destroyed) res.status(error?.httpStatus || 503)
          .json({ error: "ZK_CATALOG_UNAVAILABLE" });
      }
    };
    app.post("/zk-1/v1/catalog/authority/witness-head", fenceHeaders, authenticate,
      requirePermission("listFiles"), parseSealedContent, authorityHead("witness"));
    app.post("/zk-1/v1/catalog/authority/cas-head", fenceHeaders, authenticate,
      requirePermission("listFiles"), parseSealedContent, authorityHead("cas"));
    const sendUnderGate = (res, status, recheck = null) => (result) => new Promise((resolve, reject) => {
      if (res.destroyed || res.writableEnded || res.headersSent) {
        return reject(new Error("ZK_CATALOG_UNAVAILABLE"));
      }
      const done = () => {
        res.off("finish", settled);
        res.off("close", settled);
      };
      const settled = () => { done(); resolve(); };
      res.once("finish", settled);
      res.once("close", settled);
      try {
        if (recheck) recheck();
        res.status(status).json(result);
      }
      catch (error) { done(); reject(error); }
    });
    const respond = (action) => async (req, res) => {
      try {
        const trustedScope = resolveTrustedScope(req.user);
        if (!trustedScope) invalid();
        const originalUser = { username: req.user.username,
          sessionVersion: req.user.sessionVersion };
        const body = req.body;
        const catalogCommitFields = ["authorization", "signatureBase64",
          "headerBase64", "headerSignatureBase64", "pages"];
        exact(body, action === "commit"
          ? (Object.hasOwn(body, "ownerEvidenceBase64")
            ? [...catalogCommitFields, "ownerEvidenceBase64"] : catalogCommitFields)
          : ["authorization", "signatureBase64", "pageIndex"]);
        const authorization = authorizationWire(body.authorization);
        const input = { scope: trustedScope, authorization,
          signature: b64(body.signatureBase64, 64) };
        let result;
        if (action === "commit") {
          const { Zk1OpaqueCatalog } = require("../services/zk1OpaqueCatalog");
          if (!(opaqueCatalog instanceof Zk1OpaqueCatalog)) invalid();
          const headBytes = b64(body.headerBase64, 16384);
          const z = require("../crypto/rootark-zk-1");
          const header = await z.decodeDeterministic(headBytes);
          if (!Buffer.from(await z.encodeDeterministic(header)).equals(headBytes)) invalid();
          if (!Array.isArray(body.pages) || body.pages.length > 128) invalid();
          const pages = body.pages.map((page) => {
            if (!Array.isArray(page) || page.length > 32) invalid();
            return page.map((entry) => {
              exact(entry, ["objectId", "revision", "epoch", "ciphertextDigestBase64",
                "metadataCiphertextBase64"]);
              return { object_id: entry.objectId, revision: entry.revision,
                epoch: entry.epoch, ciphertext_digest: b64(entry.ciphertextDigestBase64, 32),
                metadata_ciphertext: b64(entry.metadataCiphertextBase64, 284) };
            });
          });
          result = await opaqueCatalog.commit({ ...input, header, pages,
            guard: () => recheckSession(req, originalUser, trustedScope, "upload"),
            emit: sendUnderGate(res, 201),
            headerSignature: b64(body.headerSignatureBase64, 64),
            ownerEvidence: body.ownerEvidenceBase64 === undefined
              ? undefined : b64(body.ownerEvidenceBase64, 2 * 1024 * 1024) });
        } else {
          result = await opaqueCatalog.read({ ...input, pageIndex: body.pageIndex,
            emit: sendUnderGate(res, 200,
              () => recheckSession(req, originalUser, trustedScope, "listFiles")) });
        }
        return result;
      } catch (error) {
        if (res.headersSent || res.destroyed) return;
        const status = error?.httpStatus || (["ZK_CATALOG_CONFLICT", "ZK_CATALOG_REPLAY"].includes(error?.code)
          ? 409 : error?.code === "ZK_CATALOG_NOT_FOUND" ? 404
            : ["ZK_CATALOG_DENIED", "ZK_CONTENT_DENIED"].includes(error?.code) ? 403 : 503);
        return res.status(status).json({ error: status === 503
          ? "ZK_CATALOG_UNAVAILABLE" : error.code });
      }
    };
    app.post("/zk-1/v1/catalog/commit", fenceHeaders, authenticate,
      requirePermission("upload"), parseSealedContent, respond("commit"));
    app.post("/zk-1/v1/catalog/read", fenceHeaders, authenticate,
      requirePermission("listFiles"), parseSealedContent, respond("read"));
  }
  if (multiproviderRestore !== null) {
    if (Object.hasOwn(multiproviderRestore, "ioDeadlineMs")) {
      exact(multiproviderRestore, ["gatewayPins", "restoreInput", "ioDeadlineMs"]);
    } else exact(multiproviderRestore, ["gatewayPins", "restoreInput"]);
    registerZk1AuthenticatedMultiproviderRestoreRoute({
      app, store, authenticate, requirePermission, resolveTrustedScope,
      gatewayPins: multiproviderRestore.gatewayPins,
      restoreInput: multiproviderRestore.restoreInput, environment,
      ioDeadlineMs: multiproviderRestore.ioDeadlineMs,
    });
  }
}

module.exports = { registerZk1ProtectedObjectRoutes };
