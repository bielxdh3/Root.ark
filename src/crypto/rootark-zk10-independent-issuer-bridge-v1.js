"use strict";

// DEV-OFF issuer/provisioning contract for anonymous object identity.
// Trusted issuer key, account identity and the current provisioning digest
// MUST arrive from independent provisioning/custody, never the HTTP caller,
// owner-controlled corpus, JWT or local database. No route is enabled here.
const crypto = require("node:crypto");
const { exact, decode, hex, key } = require("./rootark-zk10-account-cutover-v1");
const { FIELDS: OBJECT_BINDING_FIELDS, verifyAnonymousObjectBinding } =
  require("./rootark-zk10-anonymous-object-binding-v1");

const DOMAIN = Buffer.from("Root.ark/zk10/independent-issuer-provisioning/v1\0", "ascii");
const FIELDS = Object.freeze([
  "type", "immutable_account_id", "zk_account_id", "owner_root_spki",
  "owner_generation", "owner_cutover_digest", "inventory_head",
  "object_id", "object_revision", "ciphertext_sha256",
  "grant", "complete_corpus", "nonce",
]);
const CONFIG_FIELDS = Object.freeze([
  "trustedIssuerPublicKey", "immutableAccountId", "independentlyRetainedProvisioningDigest",
]);
const INPUT_FIELDS = Object.freeze([
  "issuerProvisioning", "statement", "ownerCutoverHistory",
  "ownerRotations", "objectMembershipProof", "expectedKind", "expectedToken",
]);

function deny() {
  const error = new Error("ZK10_ISSUER_BRIDGE_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function ownerPublicKey(spki) {
  const bytes = decode(spki, 44);
  const result = crypto.createPublicKey({ key: bytes, format: "der", type: "spki" });
  key(result, "public");
  if (!result.export({ type: "spki", format: "der" }).equals(bytes)) deny();
  return result;
}
function canonical(payload) {
  const p = exact(payload, FIELDS);
  if (p.type !== "rootark-zk10-independent-issuer-provisioning/v1"
    || p.grant !== "protected_enforced" || p.complete_corpus !== true
    || !Number.isSafeInteger(p.owner_generation) || p.owner_generation < 1
    || !Number.isSafeInteger(p.object_revision) || p.object_revision < 1) deny();
  decode(p.immutable_account_id, 16);
  decode(p.zk_account_id, 16);
  ownerPublicKey(p.owner_root_spki);
  hex(p.owner_cutover_digest);
  hex(p.inventory_head);
  decode(p.object_id, 16);
  hex(p.ciphertext_sha256);
  decode(p.nonce, 32);
  return p;
}
function signedBytes(body) {
  return Buffer.concat([DOMAIN, Buffer.from(JSON.stringify(body), "utf8")]);
}
function unpack(wire) {
  const signed = exact(wire, [...FIELDS, "signature"]);
  // exact() reads each data descriptor once and rejects accessors. Keep the
  // resulting plain, immutable copy: a Proxy may change descriptors between
  // reads, so signature, digest and owner/object binding must share this body.
  const body = Object.freeze(canonical(Object.fromEntries(
    FIELDS.map((field) => [field, signed[field]]))));
  return Object.freeze({ body, signature: decode(signed.signature, 64) });
}
function digestSnapshot(bytes, signature) {
  return crypto.createHash("sha256").update(bytes)
    .update(signature).digest("hex");
}
function signIssuerProvisioning(unsigned, issuerPrivateKey) {
  try {
    const body = canonical(unsigned);
    const signature = crypto.sign(null, signedBytes(body), key(issuerPrivateKey, "private"));
    return Object.freeze({ ...body, signature: signature.toString("base64url") });
  } catch (_) { deny(); }
}
function digestIssuerProvisioning(wire) {
  try {
    const { body, signature } = unpack(wire);
    return digestSnapshot(signedBytes(body), signature);
  } catch (_) { deny(); }
}

// Freeze independently provisioned trust at construction time. The request
// contract intentionally has NO owner pin, account pin, expected object or
// issuer-key field; those must be verified against issuer-signed identity.
function createIssuerProvisionedObjectVerifier(config) {
  try {
    const c = exact(config, CONFIG_FIELDS);
    const issuer = key(c.trustedIssuerPublicKey, "public");
    decode(c.immutableAccountId, 16);
    const retainedDigest = hex(c.independentlyRetainedProvisioningDigest);
    return function verifyProvisionedAnonymousObject(input) {
      try {
        const r = exact(input, INPUT_FIELDS);
        const { body, signature } = unpack(r.issuerProvisioning);
        const signedMessage = signedBytes(body);
        if (digestSnapshot(signedMessage, signature) !== retainedDigest
          || body.immutable_account_id !== c.immutableAccountId
          || !crypto.verify(null, signedMessage, issuer, signature)) deny();
        const ownerRoot = ownerPublicKey(body.owner_root_spki);
        // The anonymous owner statement has the same Proxy TOCTOU hazard:
        // downstream verification must see exactly the fields compared here.
        const statement = Object.freeze(exact(r.statement,
          [...OBJECT_BINDING_FIELDS, "signature"]));
        const verified = verifyAnonymousObjectBinding({
          statement,
          ownerCutoverHistory: r.ownerCutoverHistory,
          ownerRotations: r.ownerRotations,
          pinnedOwnerRoot: ownerRoot,
          independentlyRetainedCutoverDigest: body.owner_cutover_digest,
          independentlyExpectedAccountId: body.immutable_account_id,
          expectedKind: r.expectedKind,
          expectedToken: r.expectedToken,
          expectedObject: {
            object_id: body.object_id,
            revision: body.object_revision,
            ciphertext_sha256: body.ciphertext_sha256,
          },
          objectMembershipProof: r.objectMembershipProof,
        });
        if (verified.ownerGeneration !== body.owner_generation
          || statement.zk_account_id !== body.zk_account_id
          || statement.inventory_head !== body.inventory_head
          || verified.ownerCutoverDigest !== body.owner_cutover_digest) deny();
        return Object.freeze({
          ...verified,
          status: "VERIFIED_ISSUER_PROVISIONED_OBJECT_NONAUTHORIZING",
          issuerProvisioningVerified: true,
          issuerAttestedCompleteCorpus: true,
          // Cryptography cannot prove who retained the independent head or
          // that the issuer observed all historical legacy references.
          authorizesIo: false,
          independentObjectOwnershipProven: false,
          completeExternalCorpusProven: false,
          independentAnchorCustodyProven: false,
        });
      } catch (_) { deny(); }
    };
  } catch (_) { deny(); }
}

module.exports = {
  FIELDS, DOMAIN, signIssuerProvisioning, digestIssuerProvisioning,
  createIssuerProvisionedObjectVerifier,
};
