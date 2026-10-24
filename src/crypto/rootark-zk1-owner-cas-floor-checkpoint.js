"use strict";

const crypto = require("node:crypto");

// Shared byte contract for the offline owner and the standalone witness.
// Keep the property order stable: JSON.stringify is the signed wire encoding.
// v1 is intentionally not supported by the owner-authenticated validator.
const DOMAIN = Buffer.from("Root.ark/zk-1/cas-owner-floor/v2\0", "ascii");

function statement({ witnessKeyId, statusKeyId, witnessSpkiSha256, statusSpkiSha256,
  sequence, lastHash, issuedAt, expiresAt }) {
  if (typeof witnessSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(witnessSpkiSha256)
    || typeof statusSpkiSha256 !== "string" || !/^[a-f0-9]{64}$/.test(statusSpkiSha256)) {
    throw new Error("OWNER_FLOOR_CHECKPOINT_INVALID");
  }
  return {
    type: "rootark-zk1-cas-owner-floor/v2",
    witnessKeyId, statusKeyId, witnessSpkiSha256, statusSpkiSha256,
    sequence, lastHash, issuedAt, expiresAt,
  };
}

function signingBytes(value) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(value), "utf8")]);
}

function checkpointDigest(value, signature) {
  return crypto.createHash("sha256").update(signingBytes(value)).update(signature).digest();
}

function spkiFingerprint(publicKey) {
  return crypto.createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest();
}

module.exports = { statement, signingBytes, checkpointDigest, spkiFingerprint };
