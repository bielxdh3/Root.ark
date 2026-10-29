"use strict";

// Owner-signed, operation-specific remote address. An administrator's domain
// attestation authenticates the provider; this signature pins WHICH immutable
// ciphertext version the owner permits that provider to contribute to quorum.
// The provider GET still must return the exact owner-pinned ciphertext bytes.
const crypto = require("node:crypto");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/owner-provider-version-pin/v1\0");
const FORMAT = "rootark-zk1-owner-provider-version-pin/v1";
const FIELDS = Object.freeze(["format", "account_id", "compartment_id", "keyring_id",
  "operation_id", "object_id", "revision", "epoch", "ciphertext_sha256",
  "ciphertext_root", "byte_length", "owner_head_revision", "owner_head_digest",
  "owner_head_epoch", "provider", "namespace_sha256", "principal_context_sha256",
  "provider_object_key", "provider_file_id", "provider_version_id", "provider_etag"]);
const S3_VERSION = /^[A-Za-z0-9_.+\-=/]{1,1024}$/;
const WEBDAV_ETAG = /^"[A-Za-z0-9_.:-]{1,128}"$/;
const HEX = /^[a-f0-9]{64}$/;
function deny() { throw new Error("ZK_OWNER_PROVIDER_VERSION_PIN_DENIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
  return Object.fromEntries(fields.map((field) => {
    const d = Object.getOwnPropertyDescriptor(value, field);
    if (!d || !Object.hasOwn(d, "value")) deny();
    return [field, d.value];
  }));
}
function encoded(value, length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength !== length
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)) deny();
  return Buffer.from(value).toString("base64url");
}
function positive(value, min = 1) {
  if (!Number.isSafeInteger(value) || value < min) deny();
  return value;
}
function version(provider, fileId, versionId, etag) {
  if (provider === "s3") {
    if (fileId !== null || etag !== null || typeof versionId !== "string"
      || versionId === "null" || !S3_VERSION.test(versionId)) deny();
  } else if (provider === "webdav") {
    if (fileId !== null || versionId !== null || typeof etag !== "string"
      || !WEBDAV_ETAG.test(etag)) deny();
  } else if (provider === "gdrive") {
    if (versionId !== null || etag !== null || typeof fileId !== "string"
      || !/^[A-Za-z0-9_-]{1,256}$/.test(fileId)) deny();
  } else deny();
}
function buildClaim({ scope, operation, root, byteLength, ownerHead, target,
  providerVersionId, providerEtag }) {
  const s = inventory.normalizeScope(scope);
  const op = exact(operation, ["operation_id", "expected_sequence", "expected_root",
    "object_id", "revision", "epoch", "ciphertext_sha256"]);
  const head = exact(ownerHead, ["revision", "digest", "epoch"]);
  const t = exact(target, ["provider", "namespaceIdentity", "expectedReaderContext",
    "providerObjectKey", "pinnedDriveFileId"]);
  if (!HEX.test(t.namespaceIdentity) || !HEX.test(t.expectedReaderContext)
    || typeof t.providerObjectKey !== "string"
    || t.providerObjectKey.length < 1 || t.providerObjectKey.length > 2048) deny();
  version(t.provider, t.pinnedDriveFileId, providerVersionId, providerEtag);
  return {
    format: FORMAT, account_id: encoded(s.account_id, 16),
    compartment_id: Buffer.from(s.compartment_id).toString("base64url"),
    keyring_id: encoded(s.keyring_id, 16),
    operation_id: encoded(op.operation_id, 16), object_id: encoded(op.object_id, 16),
    revision: positive(op.revision), epoch: positive(op.epoch, 0),
    ciphertext_sha256: encoded(op.ciphertext_sha256, 32),
    ciphertext_root: encoded(root, 32), byte_length: positive(byteLength),
    owner_head_revision: positive(head.revision), owner_head_digest: encoded(head.digest, 32),
    owner_head_epoch: positive(head.epoch, 0), provider: t.provider,
    namespace_sha256: t.namespaceIdentity, principal_context_sha256: t.expectedReaderContext,
    provider_object_key: t.providerObjectKey, provider_file_id: t.pinnedDriveFileId,
    provider_version_id: providerVersionId, provider_etag: providerEtag,
  };
}
function signatureBytes(claim) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(claim), "utf8")]);
}
function signOwnerProviderVersionPin({ ownerPrivateKey, ...fields }) {
  const claim = buildClaim(fields);
  if (!(ownerPrivateKey instanceof crypto.KeyObject) || ownerPrivateKey.type !== "private"
    || ownerPrivateKey.asymmetricKeyType !== "ed25519") deny();
  return Object.freeze({ ...claim,
    signature: crypto.sign(null, signatureBytes(claim), ownerPrivateKey).toString("base64url") });
}
function verifyOwnerProviderVersionPin({ signedPin, pinnedOwnerPublicKey, scope,
  operation, root, byteLength, ownerHead, target }) {
  const signed = exact(signedPin, [...FIELDS, "signature"]);
  const expected = buildClaim({ scope, operation, root, byteLength, ownerHead, target,
    providerVersionId: signed.provider_version_id, providerEtag: signed.provider_etag });
  if (FIELDS.some((field) => signed[field] !== expected[field])
    || typeof signed.signature !== "string" || !/^[A-Za-z0-9_-]+$/.test(signed.signature)) deny();
  const sig = Buffer.from(signed.signature, "base64url");
  if (sig.length !== 64 || sig.toString("base64url") !== signed.signature) deny();
  let key;
  try { key = pinnedOwnerPublicKey instanceof crypto.KeyObject
    ? pinnedOwnerPublicKey : crypto.KeyObject.from(pinnedOwnerPublicKey); }
  catch (_) { deny(); }
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519"
    || !crypto.verify(null, signatureBytes(expected), key, sig)) deny();
  return Object.freeze({ providerVersionId: signed.provider_version_id,
    providerEtag: signed.provider_etag });
}

module.exports = { signOwnerProviderVersionPin, verifyOwnerProviderVersionPin };
