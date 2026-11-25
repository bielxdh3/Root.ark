"use strict";

// Pin checks must not dispatch to an attacker-controlled KeyObject instance's
// overridable .export method. Capture Node's intrinsic PublicKeyObject method
// once, without generating or retaining any private key.
const crypto = require("node:crypto");
// After a caller-owned KeyObject.type getter, even PUBLIC_EXPORT.call(...) is
// not native authority: Function.prototype.call may have been replaced.
const SAFE_APPLY = Reflect.apply.bind(Reflect);
const SAFE_BUFFER_FROM = Buffer.from.bind(Buffer);
const ZERO_ED25519_SPKI = SAFE_BUFFER_FROM(
  "302a300506032b6570032100" + "00".repeat(32), "hex");
const PUBLIC_EXPORT = Object.getPrototypeOf(crypto.createPublicKey({
  key: ZERO_ED25519_SPKI, format: "der", type: "spki",
})).export;

function nativeEd25519Spki(publicKey) {
  if (!(publicKey instanceof crypto.KeyObject)
    || publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  const raw = SAFE_BUFFER_FROM(SAFE_APPLY(PUBLIC_EXPORT, publicKey, [{
    type: "spki", format: "der",
  }]));
  if (raw.length !== 44) throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  for (let index = 0; index < 12; index += 1) {
    if (raw[index] !== ZERO_ED25519_SPKI[index]) {
      throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
    }
  }
  return raw;
}

module.exports = { nativeEd25519Spki };
