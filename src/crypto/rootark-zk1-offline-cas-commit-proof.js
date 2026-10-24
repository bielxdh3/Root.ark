"use strict";
// Independent cryptographic CAS authority statement. It verifies an
// assertion from a separately pinned public key, NOT physical durability.
const crypto = require("node:crypto");
const { nativeEd25519Spki } = require("./rootark-zk1-native-ed25519-public-key");
const SCHEMA = "rootark-zk1-offline-cas-commit-proof/v1";
const DOMAIN = Buffer.from("Root.ark/zk-1/offline-cas-commit-proof/v1\0");
const FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
  "revision", "epoch", "digest", "previous_revision", "previous_digest",
  "operation_id", "request_nonce", "commit_nonce", "witness_receipt_sha256",
  "cas_sequence", "witness_sequence", "issued_at", "expires_at"];
function denied() { throw new Error("ZK_OWNER_OFFLINE_CAS_PROOF_DENIED"); }
function exact(raw, fields) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))
    || Reflect.ownKeys(raw).length !== fields.length
    || fields.some((name) => !Object.hasOwn(raw, name))) denied();
}
function b64(raw, count, min = count) {
  if (typeof raw !== "string" || !/^[A-Za-z0-9_-]+$/.test(raw)) denied();
  const bytes = Buffer.from(raw, "base64url");
  if (bytes.length < min || bytes.length > count || bytes.toString("base64url") !== raw) denied();
  return bytes;
}
function integer(raw) {
  if (!Number.isSafeInteger(raw) || raw < 1) denied();
  return raw;
}
function signingBytes(unsigned) {
  exact(unsigned, FIELDS);
  if (unsigned.schema !== SCHEMA || unsigned.status !== "committed") denied();
  b64(unsigned.account_id, 16);
  b64(unsigned.compartment_id, 128, 1);
  b64(unsigned.keyring_id, 16);
  for (const key of ["digest", "previous_digest", "request_nonce",
    "commit_nonce", "witness_receipt_sha256"]) b64(unsigned[key], 32);
  b64(unsigned.operation_id, 16);
  for (const key of ["revision", "epoch", "previous_revision", "cas_sequence",
    "witness_sequence", "issued_at", "expires_at"]) integer(unsigned[key]);
  if (unsigned.revision !== unsigned.previous_revision + 1
    || unsigned.expires_at <= unsigned.issued_at
    || unsigned.expires_at - unsigned.issued_at > 3600) denied();
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(
    Object.fromEntries(FIELDS.map((field) => [field, unsigned[field]]))))]);
}
function verifySignedCasProof({
  proof, signerPublicKey, independentSignerSpkiSha256, scope, previousHead,
  committedHead, operationId, requestNonce, commitNonce,
  witnessReceiptSha256, witnessSequence, minimumCasSequence,
  nowSeconds,
}) {
  exact(proof, [...FIELDS, "signature"]);
  let nativeSpki;
  try { nativeSpki = nativeEd25519Spki(signerPublicKey); }
  catch (_) { denied(); }
  const actual = crypto.createHash("sha256").update(nativeSpki).digest();
  if (!crypto.timingSafeEqual(actual, b64(independentSignerSpkiSha256, 32))) denied();
  const unsigned = Object.fromEntries(FIELDS.map((name) => [name, proof[name]]));
  if (!crypto.verify(null, signingBytes(unsigned), signerPublicKey, b64(proof.signature, 64))) denied();
  for (const field of ["account_id", "compartment_id", "keyring_id"]) {
    if (proof[field] !== Buffer.from(scope[field]).toString("base64url")) denied();
  }
  if (proof.revision !== committedHead.revision || proof.epoch !== committedHead.epoch
    || proof.digest !== Buffer.from(committedHead.digest).toString("base64url")
    || proof.previous_revision !== previousHead.revision
    || proof.previous_digest !== Buffer.from(previousHead.digest).toString("base64url")
    || proof.operation_id !== operationId || proof.request_nonce !== requestNonce
    || proof.commit_nonce !== commitNonce || proof.witness_receipt_sha256 !== witnessReceiptSha256
    || proof.witness_sequence !== witnessSequence
    || proof.cas_sequence <= minimumCasSequence
    || proof.issued_at > nowSeconds || proof.issued_at < nowSeconds - 300
    || proof.expires_at < nowSeconds) denied();
  return Object.freeze({
    independentlyPinnedCasSignatureVerified: true,
    casSequence: proof.cas_sequence, physicalDurabilityProven: false,
  });
}
module.exports = { SCHEMA, FIELDS, signingBytes, verifySignedCasProof };
