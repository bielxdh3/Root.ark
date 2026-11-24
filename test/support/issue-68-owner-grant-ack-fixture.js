"use strict";

// Test-only trust boundary. The real signed HTTP ACK must exactly match an
// independently owner-built Ed25519 grant before any local fixture is written.
// In particular, this function NEVER returns or serializes network input.
const crypto = require("node:crypto");

const DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
const FIELDS = Object.freeze(["grantId", "expiresAt",
  "shareStatementBase64", "shareSignatureBase64"]);
const BASE64URL = /^[A-Za-z0-9_-]+$/;

function deny() { throw Error("ZK_SHARE_GRANT_ACK_UNVERIFIED"); }
function exact(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== FIELDS.length) deny();
  const record = {};
  for (const field of FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    record[field] = descriptor.value;
  }
  if (!Number.isSafeInteger(record.expiresAt) || record.expiresAt < 1) deny();
  for (const [field, size] of [["grantId", 32], ["shareSignatureBase64", 64]]) {
    const encoded = record[field];
    if (typeof encoded !== "string" || encoded.length > 100
      || !BASE64URL.test(encoded)) deny();
    const decoded = Buffer.from(encoded, "base64url");
    if (decoded.length !== size || decoded.toString("base64url") !== encoded) deny();
  }
  const encoded = record.shareStatementBase64;
  if (typeof encoded !== "string" || encoded.length > 5470
    || !BASE64URL.test(encoded)) deny();
  const statement = Buffer.from(encoded, "base64url");
  if (statement.length < 1 || statement.length > 4096
    || statement.toString("base64url") !== encoded
    || Buffer.byteLength(JSON.stringify(record), "utf8") > 5800) deny();
  return record;
}

function assertAuthenticOwnerGrantAck(actualHttpAck, expectedOwnerAck,
  locallySignedMessage, ownerPinnedPublicKey) {
  try {
    const owner = exact(expectedOwnerAck);
    const observed = exact(actualHttpAck);
    if (!Buffer.isBuffer(locallySignedMessage)
      || locallySignedMessage.length <= DOMAIN.length
      || locallySignedMessage.length > DOMAIN.length + 4096
      || !locallySignedMessage.subarray(0, DOMAIN.length).equals(DOMAIN)
      || owner.shareStatementBase64 !==
        locallySignedMessage.subarray(DOMAIN.length).toString("base64url")
      || !(ownerPinnedPublicKey instanceof crypto.KeyObject)
      || ownerPinnedPublicKey.type !== "public"
      || ownerPinnedPublicKey.asymmetricKeyType !== "ed25519"
      || !crypto.verify(null, locallySignedMessage, ownerPinnedPublicKey,
        Buffer.from(owner.shareSignatureBase64, "base64url"))
      || FIELDS.some((field) => observed[field] !== owner[field])) deny();
    // Return nothing: persisting observed data would reintroduce CodeQL 484.
  } catch (_) { deny(); }
}

module.exports = { assertAuthenticOwnerGrantAck };
