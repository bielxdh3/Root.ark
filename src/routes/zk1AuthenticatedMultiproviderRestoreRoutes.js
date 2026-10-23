"use strict";

// Optional, development-only server wiring. Trusted configuration comes from
// the operator, never a browser POST. The CURRENT device grant is a signed
// historical GET verified by the existing protected store against its pinned
// witness, CAS manifest and owner-rooted history on every callback. A JSON
// `active: true` supplied by an operator callback is never an authorization.
const crypto = require("node:crypto");
const express = require("express");
const { Zk1ProtectedObjectStore } = require("../services/zk1ProtectedObjectStore");
const { Zk1MultiproviderCiphertextRestore } =
  require("../services/zk1MultiproviderCiphertextRestore");
const { validDeadlineMs, DEFAULT_PROVIDER_DEADLINE_MS } =
  require("../services/zk1ProviderDeadline");

const ROUTE = "/zk-1/v1/multiprovider-restore/read";
const PINS = ["pinnedInventoryPublicKey", "pinnedInventorySignerKeyId",
  "pinnedOwner", "pinnedOwnerHead", "independentInventoryFloor",
  "independentOwnerSpkiSha256", "providerDomainPinset",
  "signedCurrentDeviceGrant", "fetchFreshSignedDeviceState"];
const SCOPE = ["account_id", "compartment_id", "keyring_id"];

function deny() { const error = new Error("ZK_MULTIPROVIDER_HTTP_DENIED"); error.code = error.message; throw error; }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))) deny();
}
function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function b64(raw, length) {
  if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)) deny();
  const value = Buffer.from(raw, "base64url");
  if ((length !== undefined && value.length !== length)
    || value.toString("base64url") !== raw) deny();
  return value;
}
function serializeResult(restored) {
  return {
    format: "rootark-zk1-cloud-recovery-response/v1",
    operationId: restored.operationId.toString("base64url"),
    ciphertextBase64: restored.ciphertext.toString("base64url"),
    ciphertextSha256: restored.ciphertextSha256.toString("base64url"),
    ciphertextRoot: restored.ciphertextRoot.toString("base64url"),
    signedCommittedProof: restored.signedCommittedProof.toString("base64url"),
    signedSnapshot: restored.signedSnapshot.toString("base64url"),
    catalogSequence: restored.signedInventorySequence,
    catalogRoot: restored.signedInventoryRoot.toString("base64url"),
    providerCount: restored.verifiedProviders.length,
    signedCatalogRecoveredFromRemote: restored.signedCatalogRecoveredFromRemote === true,
    remoteDurabilityProven: false, authorizesProductionRestore: false,
  };
}
function registerZk1AuthenticatedMultiproviderRestoreRoute({
  app, store, authenticate, requirePermission, resolveTrustedScope,
  gatewayPins, restoreInput, environment,
  ioDeadlineMs = DEFAULT_PROVIDER_DEADLINE_MS,
}) {
  if (!["development", "test"].includes(environment)
    || !app || typeof app.post !== "function"
    || !(store instanceof Zk1ProtectedObjectStore)
    || store.admissionRequired !== true || store.signedHistoryRequired !== true
    || typeof authenticate !== "function" || typeof requirePermission !== "function"
    || typeof resolveTrustedScope !== "function") deny();
  exact(gatewayPins, PINS); // Explicitly REJECT assertCurrentAuthorization or arbitrary hook.
  validDeadlineMs(ioDeadlineMs);
  if (!restoreInput || !["cloud-catalog", undefined].includes(restoreInput.mode)) deny();
  const source = restoreInput?.mode === "cloud-catalog" ? restoreInput.request : restoreInput;
  const operation = source?.operation;
  const pinned = {
    objectId: Buffer.from(operation?.object_id || []).toString("base64url"),
    revision: operation?.revision, epoch: operation?.epoch,
    digest: Buffer.from(operation?.ciphertext_sha256 || []),
    operationId: Buffer.from(operation?.operation_id || []),
  };
  if (pinned.operationId.length !== 16 || !Number.isSafeInteger(pinned.revision)
    || pinned.revision < 1 || !Number.isSafeInteger(pinned.epoch)
    || pinned.epoch < 1 || pinned.digest.length !== 32
    || !/^[A-Za-z0-9_-]{22}$/.test(pinned.objectId)) deny();
  const pinnedScope = Object.fromEntries(SCOPE.map((name) =>
    [name, Buffer.from(source.scope?.[name] || [])]));
  if (!SCOPE.every((name) => same(pinnedScope[name], store.trustedScope[name]))) deny();
  if (!same(Buffer.from(operation.object_id), Buffer.from(pinned.objectId, "base64url"))) deny();
  // Closure captures only one verified request per HTTP invocation; no global
  // current-device state is shared between unrelated sessions or accounts.
  const content = express.json({ type: "application/json", limit: "8kb" });
  const checkedScope = (user) => {
    const scope = resolveTrustedScope(user);
    if (!scope || !SCOPE.every((name) => same(scope[name], pinnedScope[name]))) deny();
    return scope;
  };
  const permission = requirePermission("listFiles");
  app.post(ROUTE, (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("X-Content-Type-Options", "nosniff");
    next();
  }, authenticate, permission, content, async (req, res) => {
    let restored;
    const cancellation = new AbortController();
    const disconnected = () => cancellation.abort();
    // Terminate the socket at the absolute operator deadline. The witness
    // admission is NOT released by this timer: #withAdmission waits for the
    // actual provider promise to settle after cancellation.
    const watchdog = setTimeout(() => {
      cancellation.abort();
      if (res.headersSent) res.destroy();
      else if (!res.destroyed) res.status(403).json({ error: "ZK_MULTIPROVIDER_HTTP_DENIED" });
    }, ioDeadlineMs);
    res.once("close", disconnected);
    req.once("aborted", disconnected);
    try {
      if (req.aborted || res.destroyed) deny();
      checkedScope(req.user);
      exact(req.body, ["authorization", "signatureBase64"]);
      const auth = req.body.authorization;
      const fields = ["account_id", "compartment_id", "keyring_id", "device_id",
        "operation", "object_id", "expected_object_revision", "manifest_revision",
        "manifest_digest", "epoch", "nonce", "issued_at", "expires_at", "ciphertext_digest"];
      exact(auth, fields);
      const authorization = {};
      for (const name of fields) {
        authorization[name] = SCOPE.includes(name) ? b64(auth[name], name === "compartment_id" ? undefined : 16)
          : ["manifest_digest", "nonce", "ciphertext_digest"].includes(name) ? b64(auth[name], 32)
            : auth[name];
      }
      if (authorization.compartment_id.length < 1 || authorization.compartment_id.length > 128
        || authorization.operation !== "get"
        || authorization.object_id !== pinned.objectId
        || authorization.expected_object_revision !== pinned.revision
        || !same(authorization.ciphertext_digest, pinned.digest)) deny();
      const signedRequest = {
        scope: checkedScope(req.user), authorization,
        signature: b64(req.body.signatureBase64, 64),
      };
      const checkLive = async ({ objectId, revision, ciphertextEpoch,
        ownerHeadRevision, ownerHeadDigest, ownerHeadEpoch }) => {
        if (!same(objectId, Buffer.from(pinned.objectId, "base64url"))
          || revision !== pinned.revision || ciphertextEpoch !== pinned.epoch
          || ownerHeadRevision !== gatewayPins.pinnedOwnerHead.revision
          || ownerHeadEpoch !== gatewayPins.pinnedOwnerHead.epoch
          || !same(ownerHeadDigest, Buffer.from(gatewayPins.pinnedOwnerHead.digest))) deny();
        const fresh = await store.authorize(signedRequest, "get");
        // The identity comes from the exact device entry whose Ed25519
        // signature passed the owner-rooted V2 manifest validation, not
        // from a caller-supplied `authorized: true` object.
        if (!gateway.checkRequesterDeviceIdentity({ authorized: true,
          deviceId: fresh.deviceId, authorizationKeyId: fresh.authorizationKeyId })) deny();
        if (fresh.request.manifest_revision !== ownerHeadRevision
          || fresh.request.epoch !== ownerHeadEpoch
          || !same(fresh.request.manifest_digest, ownerHeadDigest)) deny();
        return { active: true, currentManifestRevision: ownerHeadRevision,
          currentManifestDigest: Buffer.from(ownerHeadDigest), currentEpoch: ownerHeadEpoch };
      };
      // No gateway instance or untrusted authorization callback accepted:
      // construct a PRIVATE gateway bound to the protected store for THIS call.
      const gateway = new Zk1MultiproviderCiphertextRestore({
        ...gatewayPins, assertCurrentAuthorization: checkLive,
        ioDeadlineMs,
      });
      await store.runRestoreGetAdmission(signedRequest, pinned, async () => {
        if (cancellation.signal.aborted) deny();
        restored = restoreInput.mode === "cloud-catalog"
          ? await gateway.restoreFromCloudCatalog(restoreInput.request,
            { abortSignal: cancellation.signal })
          : await gateway.restoreExact(restoreInput, { abortSignal: cancellation.signal });
        if (cancellation.signal.aborted) deny();
        if (!same(restored.operationId, pinned.operationId)) deny();
        // Re-evaluate current sessionVersion, expiry, CSRF, permission and
        // account scope AFTER slow provider reads and before socket egress.
        await new Promise((resolve, reject) => {
          const refused = () => { cleanup(); reject(new Error("session denied")); };
          const cleanup = () => { res.off("finish", refused); res.off("close", refused); };
          res.once("finish", refused); res.once("close", refused);
          try {
            authenticate(req, res, (error) => {
              if (error || res.headersSent) return refused();
              permission(req, res, (permissionError) => {
                if (permissionError || res.headersSent) return refused();
                cleanup(); resolve();
              });
            });
          } catch (_) { refused(); }
        });
        checkedScope(req.user);
        if (req.authExpiresAt !== null && req.authExpiresAt !== undefined
          && Date.now() >= req.authExpiresAt) deny();
        if (cancellation.signal.aborted || res.destroyed || res.writableEnded) deny();
        await new Promise((resolve, reject) => {
          const finish = () => { res.off("finish", finish); res.off("close", finish); resolve(); };
          res.once("finish", finish); res.once("close", finish);
          try { res.status(200).json(serializeResult(restored)); }
          catch (error) { res.off("finish", finish); res.off("close", finish); reject(error); }
        });
      });
    } catch (_) {
      if (!res.headersSent && !res.destroyed) res.status(403).json({ error: "ZK_MULTIPROVIDER_HTTP_DENIED" });
    } finally {
      clearTimeout(watchdog);
      res.off("close", disconnected);
      req.off("aborted", disconnected);
      restored?.ciphertext?.fill(0);
    }
  });
  return Object.freeze({ route: ROUTE, developmentOnly: true });
}

module.exports = { registerZk1AuthenticatedMultiproviderRestoreRoute };
