"use strict";

// DEV-OFF WebDAV boundary. The production server has no independent owner
// authority bootstrap. A local username, JWT, Basic password or env flag must
// never constitute an account-wide negative-membership proof.
const { isAuthenticZk10LegacyCutoverFence } = require("./zk10LegacyCutoverFence");
const { createZk10HttpResponseLeaseGuard } = require("./zk10LegacyHttpResponseLease");

const LEASED_READ_METHODS = new Set(["GET", "HEAD", "PROPFIND"]);

async function runZk10LegacyWebDavOperation({ req, res, strict = false,
  legacyCutoverFence = null, operation }, execute) {
  if (typeof execute !== "function") throw new TypeError("WebDAV handler required");
  if (strict !== true) return execute();

  const unavailable = () => {
    if (!res.headersSent && !res.destroyed) res.status(503).send("ZK10 external cutover authority unavailable");
  };
  // The existing WebDAV PUT/MOVE/MKCOL handlers have asynchronous filesystem
  // and cloud side effects that cannot be interrupted atomically by a lease
  // expiry. Until those commits hold an externally serialized fence, strict
  // mode cannot safely admit these writes, even on negative membership.
  if (!LEASED_READ_METHODS.has(req.method)) return unavailable();
  if (!req.user || typeof req.user.username !== "string"
    || !isAuthenticZk10LegacyCutoverFence(legacyCutoverFence)) return unavailable();

  let invoked = false;
  try {
    await legacyCutoverFence.withCurrentAccountLegacyPolicy(Object.freeze({
      authenticatedUsername: req.user.username, operation,
    }), async (lease) => {
      if (invoked) throw new Error("ZK10 WebDAV callback invoked more than once");
      invoked = true;
      if (lease?.status !== "never_enrolled"
        || typeof lease.assertActive !== "function"
        || typeof lease.immutableAccountId !== "string")
        throw new Error("ZK10 signed WebDAV negative-membership lease required");
      lease.assertActive();
      const responseGuard = createZk10HttpResponseLeaseGuard(res,
        lease.signal, lease.assertActive);
      try {
        lease.assertActive();
        const result = await execute();
        await responseGuard.waitForFinish();
        lease.assertActive();
        return result;
      } finally {
        if (res.headersSent && !res.writableFinished && !res.destroyed) res.destroy();
        responseGuard.disarm();
      }
    });
    if (!invoked) unavailable();
  } catch (error) {
    if (res.headersSent || res.destroyed) return;
    if (error?.code === "ZK10_LEGACY_ENFORCED")
      res.status(403).send("WebDAV disabled by owner cutover");
    else unavailable();
  }
}

module.exports = { runZk10LegacyWebDavOperation };
