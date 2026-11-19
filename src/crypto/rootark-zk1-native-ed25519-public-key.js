"use strict";

// Pin checks must not dispatch to an attacker-controlled KeyObject instance's
// overridable .export method. Capture Node's intrinsic PublicKeyObject method
// once, without generating or retaining any private key.
const crypto = require("node:crypto");
const { createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  timingSafeEqual: NATIVE_TIMING_SAFE_EQUAL } =
  require("./rootark-zk10-native-intrinsics-v1");
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

function pinNativeEd25519PublicKey(publicKey) {
  // Observe the native handle BEFORE any overridable KeyObject.type getter.
  // A malicious getter can synchronously swap B for A, and an async decode
  // can swap it again before verification. Require stable native SPKI across
  // the getter boundary, then verify only with our own fresh native key.
  const before = SAFE_BUFFER_FROM(SAFE_APPLY(PUBLIC_EXPORT, publicKey, [{
    type: "spki", format: "der",
  }]));
  const after = nativeEd25519Spki(publicKey);
  if (before.length !== after.length || !NATIVE_TIMING_SAFE_EQUAL(before, after)) {
    throw new TypeError("ED25519_PUBLIC_KEY_REQUIRED");
  }
  return NATIVE_CREATE_PUBLIC_KEY({ key: before, type: "spki", format: "der" });
}

module.exports = { nativeEd25519Spki, pinNativeEd25519PublicKey };
