"use strict";

// Extra defense at the untrusted web relay. The browser MUST independently
// verify the returned proof with its own owner-selected Ed25519 pins.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const { inspectVerifiedWitnessFreshHeadV1 } =
  require("../crypto/rootark-zk-witness-head-wire-v1");
const DOMAIN = Buffer.from("Root.ark/zk-1/opaque-catalog-cas/v1\0");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const CAS = ["type", ...SCOPE, "sequence", "digest", "nonce", "observed_at"];
function deny() { throw new Error("ZK_AUTHORITY_RELAY_PROOF_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((name) => !Object.hasOwn(value, name))) deny();
}
function bytes(value, low, high = low) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < low || value.byteLength > high) deny();
  return Buffer.from(value);
}
function equal(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function verifyRelayedAuthorityProof({ kind, raw, scope, nonce,
  witnessPinned, minimumHead, casPublicKey, nowSeconds }) {
  try {
    if (!["witness", "cas"].includes(kind)) deny();
    const statementBytes = bytes(raw, 1, 8192);
    const challenge = bytes(nonce, 32);
    exact(scope, SCOPE);
    const pinnedScope = { account_id: bytes(scope.account_id, 16),
      compartment_id: bytes(scope.compartment_id, 1, 128),
      keyring_id: bytes(scope.keyring_id, 16) };
    if (!Number.isSafeInteger(nowSeconds) || nowSeconds < 0) deny();
    const signed = await z.decodeDeterministic(statementBytes);
    if (kind === "witness") {
      if (!witnessPinned || !minimumHead) deny();
      await inspectVerifiedWitnessFreshHeadV1({ raw: statementBytes,
        pinned: witnessPinned, minimumHead, scope: pinnedScope, nonce: challenge });
      if (!Number.isSafeInteger(signed.observed_at)
        || Math.abs(signed.observed_at - nowSeconds) > 30) deny();
    } else {
      exact(signed, [...CAS, "signature"]);
      const { signature, ...head } = signed;
      exact(head, CAS);
      if (!(casPublicKey instanceof crypto.KeyObject)
        || casPublicKey.type !== "public" || casPublicKey.asymmetricKeyType !== "ed25519"
        || head.type !== "rootark-zk1-opaque-catalog-cas/v1"
        || !Number.isSafeInteger(head.sequence) || head.sequence < 0 || head.sequence > 128
        || !Number.isSafeInteger(head.observed_at)
        || Math.abs(head.observed_at - nowSeconds) > 30
        || !equal(bytes(head.nonce, 32), challenge)
        || SCOPE.some((name) => !equal(bytes(head[name],
          name === "compartment_id" ? 1 : 16,
          name === "compartment_id" ? 128 : 16), pinnedScope[name]))
        || (head.sequence === 0 && !equal(bytes(head.digest, 32), Buffer.alloc(32)))
        || !crypto.verify(null, Buffer.concat([DOMAIN,
          Buffer.from(await z.encodeDeterministic(head))]),
        casPublicKey, bytes(signature, 64))) deny();
      bytes(head.digest, 32);
    }
    return Buffer.from(statementBytes);
  } catch (_) { deny(); }
}
module.exports = { verifyRelayedAuthorityProof };
