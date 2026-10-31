"use strict";

// Experimental DEV-OFF fail-closed boundary only. A local environment switch
// cannot establish an owner-signed account cutover or a monotonic off-host floor.
// Do not turn this denial into a positive authorization decision.
function isZk10LegacyBackupStrict(env = process.env) {
  // Match server.js route guards: uppercase OFF is not the explicit 'off'
  // opt-out, so fail closed rather than silently opening the archive plane.
  const value = String(env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT || "").trim();
  return value !== "" && value !== "0" && value !== "off";
}

function assertZk10LegacyBackupNotStrict(env = process.env) {
  if (!isZk10LegacyBackupStrict(env)) return;
  throw Object.assign(new Error("ZK10 external account-wide backup authority unavailable"), {
    code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE",
    statusCode: 503,
  });
}

module.exports = { isZk10LegacyBackupStrict, assertZk10LegacyBackupNotStrict };
