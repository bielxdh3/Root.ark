"use strict";

// Pin checks must not dispatch to an attacker-controlled KeyObject instance's
// overridable .export method. Capture Node's intrinsic PublicKeyObject method
// once, without generating or retaining any private key.
const crypto = require("node:crypto");
const ZERO_ED25519_SPKI = Buffer.from(
  "302a300506032b6570032100" + "00".repeat(32), "hex");
const PUBLIC_EXPORT = Object.getPrototypeOf(crypto.createPublicKey({
  key: ZERO_ED25519_SPKI, format: "der", type: "spki",
})).export;

function nativeEd25519Spki(publicKey) {
  if (!(publicKey instanceof crypto.KeyObject)
    || publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  const raw = Buffer.from(PUBLIC_EXPORT.call(publicKey, {
    type: "spki", format: "der",
  }));
  if (raw.length !== 44 || !raw.subarray(0, 12).equals(ZERO_ED25519_SPKI.subarray(0, 12))) {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  return raw;
}

module.exports = { nativeEd25519Spki };
