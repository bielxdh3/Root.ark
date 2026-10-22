"use strict";

const crypto = require("node:crypto");

// Shared byte contract for the offline owner and the standalone witness.
// Keep the property order stable: JSON.stringify is the wire encoding in v1.
const DOMAIN = Buffer.from("Root.ark/zk-1/cas-owner-floor/v1\0", "ascii");

function statement({ witnessKeyId, statusKeyId, sequence, lastHash, issuedAt, expiresAt }) {
  return {
    type: "rootark-zk1-cas-owner-floor/v1",
    witnessKeyId, statusKeyId, sequence, lastHash, issuedAt, expiresAt,
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
