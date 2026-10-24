"use strict";

// An out-of-band owner checkpoint on already read-back legacy ZIP bytes and
// their archived SQLite reference graph. The inspector never signs for the
// owner. A matching signature authenticates one bounded HISTORICAL observation
// only; it does not prove the entire live account or permit cutover/deletion.
const crypto = require("node:crypto");
const DOMAIN = Buffer.from("Root.ark/zk-1/legacy-archive-referential-proof/v1\0");
const FORMAT = "rootark-zk1-legacy-archive-referential-proof/v1";
const FIELDS = Object.freeze(["format", "archive_id_sha256", "archive_sha256",
  "referential_sha256", "historical_status"]);
const HEX = /^[a-f0-9]{64}$/;

function deny() { throw new Error("ZK_LEGACY_REFERENTIAL_PROOF_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
  return Object.fromEntries(fields.map((field) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    return [field, descriptor.value];
  }));
}
function evidence(value) {
  const item = exact(value, ["archiveIdSha256", "archiveSha256",
    "referentialSha256", "historicalStatus"]);
  for (const key of ["archiveIdSha256", "archiveSha256", "referentialSha256"])
    if (typeof item[key] !== "string" || !HEX.test(item[key])) deny();
  if (!["BOUNDED_JOINS_ONLY", "UNKNOWN"].includes(item.historicalStatus)) deny();
  return Object.freeze({ format: FORMAT, archive_id_sha256: item.archiveIdSha256,
    archive_sha256: item.archiveSha256, referential_sha256: item.referentialSha256,
    historical_status: item.historicalStatus });
}
function signingMessage(claim) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(claim), "utf8")]);
}
function signZk1LegacyArchiveReferentialProof({ evidence: source, ownerPrivateKey } = {}) {
  if (!(ownerPrivateKey instanceof crypto.KeyObject) || ownerPrivateKey.type !== "private"
    || ownerPrivateKey.asymmetricKeyType !== "ed25519") deny();
  const claim = evidence(source);
  return Object.freeze({ ...claim,
    signature: crypto.sign(null, signingMessage(claim), ownerPrivateKey).toString("base64url") });
}
function verifyZk1LegacyArchiveReferentialProof({ evidence: source, signedProof,
  pinnedOwnerPublicKey } = {}) {
  try {
    if (!(pinnedOwnerPublicKey instanceof crypto.KeyObject)
      || pinnedOwnerPublicKey.type !== "public"
      || pinnedOwnerPublicKey.asymmetricKeyType !== "ed25519") return false;
    const signed = exact(signedProof, [...FIELDS, "signature"]);
    const claim = evidence(source);
    if (FIELDS.some((field) => signed[field] !== claim[field])
      || typeof signed.signature !== "string"
      || !/^[A-Za-z0-9_-]+$/.test(signed.signature)) return false;
    const sig = Buffer.from(signed.signature, "base64url");
    return sig.length === 64 && sig.toString("base64url") === signed.signature
      && crypto.verify(null, signingMessage(claim), pinnedOwnerPublicKey, sig);
  } catch (_) { return false; }
}

module.exports = { signZk1LegacyArchiveReferentialProof,
  verifyZk1LegacyArchiveReferentialProof };
