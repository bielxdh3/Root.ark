"use strict";

const { Zk1ProtectedCiphertextSharing } = require("../services/zk1ProtectedCiphertextSharing");

function registerZk1ProtectedShareRoutes({ app, store, authenticate, requirePermission,
  resolveTrustedScope, fenceHeaders, protectedRequestLimit, parseSealedContent,
  exact, b64, authorizationWire, recheckSession }) {
  const sharing = new Zk1ProtectedCiphertextSharing(store);
  const deny = (res, error) => {
    if (res.headersSent || res.destroyed) return;
    const status = ["ZK_CONTENT_REPLAY", "ZK_CONTENT_CONFLICT", "ZK_SHARE_CONFLICT"]
      .includes(error?.code) ? 409
      : ["ZK_CONTENT_UNAVAILABLE", "ZK_SHARE_UNAVAILABLE"].includes(error?.code) ? 503
        : error?.httpStatus || 403;
    res.status(status).json({ error: status === 503 ? "ZK_SHARE_UNAVAILABLE"
      : status === 409 ? "ZK_SHARE_CONFLICT" : "ZK_SHARE_DENIED" });
  };
  const guardUser = (req, scope) => {
    const original = { username: req.user.username,
      sessionVersion: req.user.sessionVersion };
    return () => recheckSession(req, original, scope, "listFiles");
  };

  const egress = (res) => {
    const send = (payload) => new Promise((resolve) => {
      const settled = () => {
        res.off("finish", settled); res.off("close", settled); resolve();
      };
      res.once("finish", settled); res.once("close", settled);
      if (res.destroyed || res.writableEnded || res.headersSent) {
        if (!res.destroyed) res.destroy();
        // Never release a lease without observing finish/close, even when an
        // unexpected response state prevents sending any ciphertext.
        return;
      }
      try { res.status(200).json(payload); }
      catch (_) {
        // res.json() may have already written part of the ciphertext before
        // throwing. Destroy the socket immediately and keep the listeners
        // active until 'close'; no more bytes may be emitted after revoke ACK.
        try { if (!res.destroyed) res.destroy(); }
        catch (_) { /* no close => unresolved durable lease, never a 200 ACK */ }
      }
    });
    send.abort = () => { if (!res.destroyed) res.destroy(); };
    return send;
  };

  app.post("/zk-1/v1/share/grant", fenceHeaders, protectedRequestLimit, authenticate,
    requirePermission("listFiles"), parseSealedContent, async (req, res) => {
      try {
        exact(req.body, ["grantId", "recipientUsername", "recipientDeviceId", "expiresAt",
          "authorization", "signatureBase64", "shareSignatureBase64"]);
        const scope = resolveTrustedScope(req.user);
        if (!scope) throw Error("ZK_SHARE_DENIED");
        const result = await sharing.issue({
          scope, authorization: authorizationWire(req.body.authorization),
          signature: b64(req.body.signatureBase64, 64),
          shareSignature: b64(req.body.shareSignatureBase64, 64),
          grantId: req.body.grantId, recipientUsername: req.body.recipientUsername,
          recipientDeviceId: req.body.recipientDeviceId, expiresAt: req.body.expiresAt,
          ownerUsername: req.user.username, guard: guardUser(req, scope),
        });
        if (!res.headersSent && !res.destroyed) res.status(201).json(result);
      } catch (error) { deny(res, error); }
    });

  app.post("/zk-1/v1/share/read", fenceHeaders, protectedRequestLimit, authenticate,
    requirePermission("listFiles"), parseSealedContent, async (req, res) => {
      try {
        exact(req.body, ["grantId", "authorization", "signatureBase64"]);
        // Recipient account has no implicit owner scope. The owner-signed
        // grant and the recipient's live device signature authorize this read.
        await sharing.read({ scope: store.trustedScope,
          grantId: req.body.grantId, recipientUsername: req.user.username,
          authorization: authorizationWire(req.body.authorization),
          signature: b64(req.body.signatureBase64, 64),
          guard: guardUser(req, null), emit: egress(res) });
      } catch (error) { deny(res, error); }
    });

  app.post("/zk-1/v1/share/revoke", fenceHeaders, protectedRequestLimit, authenticate,
    requirePermission("listFiles"), parseSealedContent, async (req, res) => {
      try {
        exact(req.body, ["grantId"]);
        const scope = resolveTrustedScope(req.user);
        if (!scope) throw Error("ZK_SHARE_DENIED");
        const guard = guardUser(req, scope);
        guard();
        const result = await sharing.revokeAndDrain(scope, req.body.grantId,
          req.user.username);
        guard();
        if (!res.headersSent && !res.destroyed) res.status(200).json(result);
      } catch (error) { deny(res, error); }
    });
}

module.exports = { registerZk1ProtectedShareRoutes };
