"use strict";

// Portable cryptographic proof of a witness' assertion of commitment. The
// signer must be provisioned independently of the Root.ark server. A valid
// signature alone cannot prove external custody or physical durability.
const crypto = require("node:crypto");
const { nativeEd25519Spki } = require("./rootark-zk1-native-ed25519-public-key");
const DOMAIN = Buffer.from("Root.ark/zk-1/offline-commitment-receipt/v1\0");
const SCHEMA = "rootark-zk1-offline-commitment-receipt/v1";
const FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
  "revision", "digest", "epoch", "previous_revision", "previous_digest",
  "operation_id", "pop_challenge_id", "request_nonce", "commit_nonce",
  "sequence", "previous_receipt_sha256", "issued_at", "expires_at"];
function deny() { throw Error("ZK_OFFLINE_COMMITMENT_PROOF_DENIED"); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((name) => !Object.hasOwn(value, name))) deny();
}
function uint(value) {
  if (!Number.isSafeInteger(value) || value < 1) deny();
  return value;
}
function b64(value, size, nullable = false) {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== size || raw.toString("base64url") !== value) deny();
  return raw;
}
function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function signingBytes(unsigned) {
  exact(unsigned, FIELDS);
  if (unsigned.schema !== SCHEMA || unsigned.status !== "committed") deny();
  b64(unsigned.account_id, 16);
  const compartment = Buffer.from(unsigned.compartment_id || "", "base64url");
  if (typeof unsigned.compartment_id !== "string"
    || compartment.length < 1 || compartment.length > 128
    || compartment.toString("base64url") !== unsigned.compartment_id) deny();
  b64(unsigned.keyring_id, 16);
  for (const name of ["digest", "previous_digest", "request_nonce", "commit_nonce",
    "previous_receipt_sha256"]) b64(unsigned[name], 32, name !== "digest");
  for (const name of ["operation_id", "pop_challenge_id"]) b64(unsigned[name], 16, true);
  uint(unsigned.revision);
  uint(unsigned.epoch);
  uint(unsigned.sequence);
  if (unsigned.previous_revision !== null) uint(unsigned.previous_revision);
  uint(unsigned.issued_at);
  uint(unsigned.expires_at);
  if (unsigned.expires_at <= unsigned.issued_at
    || unsigned.expires_at - unsigned.issued_at > 3600) deny();
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(
    Object.fromEntries(FIELDS.map((field) => [field, unsigned[field]]))))]);
}
function commitmentSigningBytes(unsigned) {
  return signingBytes(unsigned);
}
function verifySignedReceipt({ receipt, signerPublicKey, independentSignerSpkiSha256,
  expectedScope, expectedHead, nowSeconds, previousReceipt = null,
  expectedOperation = null }) {
  exact(receipt, [...FIELDS, "signature"]);
  let nativeSpki;
  try { nativeSpki = nativeEd25519Spki(signerPublicKey); }
  catch (_) { deny(); }
  if (!same(crypto.createHash("sha256").update(nativeSpki).digest(),
    b64(independentSignerSpkiSha256, 32))) deny();
  const unsigned = Object.fromEntries(FIELDS.map((key) => [key, receipt[key]]));
  const bytes = commitmentSigningBytes(unsigned);
  if (!crypto.verify(null, bytes, signerPublicKey, b64(receipt.signature, 64))) deny();
  const now = uint(nowSeconds);
  if (receipt.issued_at > now + 30 || receipt.expires_at < now) deny();
  for (const name of ["account_id", "compartment_id", "keyring_id"]) {
    if (!same(Buffer.from(receipt[name], "base64url"), Buffer.from(expectedScope[name]))) deny();
  }
  if (receipt.revision !== expectedHead.revision || receipt.epoch !== expectedHead.epoch
    || !same(b64(receipt.digest, 32), Buffer.from(expectedHead.digest))) deny();
  if (previousReceipt !== null) {
    const priorUnsigned = Object.fromEntries(FIELDS.map((key) => [key, previousReceipt[key]]));
    const priorHash = crypto.createHash("sha256").update(Buffer.concat([
      commitmentSigningBytes(priorUnsigned), b64(previousReceipt.signature, 64)])).digest();
    if (!same(b64(receipt.previous_receipt_sha256, 32), priorHash)
      || receipt.sequence <= previousReceipt.sequence
      || receipt.previous_revision !== previousReceipt.revision
      || !same(b64(receipt.previous_digest, 32), b64(previousReceipt.digest, 32))
      || receipt.epoch < previousReceipt.epoch) deny();
  }
  if (expectedOperation !== null) {
    for (const name of ["operation_id", "pop_challenge_id", "request_nonce", "commit_nonce"]) {
      const len = name === "operation_id" || name === "pop_challenge_id" ? 16 : 32;
      if (!same(b64(receipt[name], len), b64(expectedOperation[name], len))) deny();
    }
  }
  return Object.freeze({ signedReceiptVerified: true, revision: receipt.revision,
    epoch: receipt.epoch, sequence: receipt.sequence,
    // Pure offline verification has no authenticated connection to the
    // external signer, durable ledger, CAS, or physical storage.
    physicalDurabilityProven: false, externalCustodyProven: false });
}
module.exports = { SCHEMA, FIELDS, commitmentSigningBytes, verifySignedReceipt };
