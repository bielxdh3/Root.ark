"use strict";

// DEV-OFF only. Verification of an owner-signed bootstrap roster is NOT an
// independent monotonic owner registry, host custody, physical proof or ACK.
const crypto = require("node:crypto");
const protocol = require("../../sync-client/rootark-sync-protocol");

const DOMAIN = "Root.ark/zk1/sync-atomic-owner-bindings/v1\0";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SCOPE = /^[A-Za-z0-9._:-]{1,256}$/;
const HEX = /^[a-f0-9]{64}$/;
const FIELDS = ["scope", "accountId", "storeId", "username", "compartmentId"];
const fail = () => Object.assign(new Error("ZK1_SYNC_OWNER_ROSTER_DEV_OFF_DENIED"),
  { code: "ZK1_SYNC_OWNER_ROSTER_DEV_OFF_DENIED" });
function check(value) { if (!value) throw fail(); }
function exact(value, fields) {
  check(value && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === fields.length
    && fields.every((key) => Object.hasOwn(value, key)));
}
function verifySignedOwnerBindingsDevOff({ manifest, signature, trustedOwnerPublicKey,
  independentlyPinnedSha256, trustedMinimumRevision } = {}) {
  try {
    check(trustedOwnerPublicKey instanceof crypto.KeyObject
      && trustedOwnerPublicKey.type === "public"
      && trustedOwnerPublicKey.asymmetricKeyType === "ed25519"
      && typeof independentlyPinnedSha256 === "string"
      && HEX.test(independentlyPinnedSha256)
      && Number.isSafeInteger(trustedMinimumRevision)
      && trustedMinimumRevision > 0
      && typeof signature === "string"
      && /^[A-Za-z0-9_-]{86}$/.test(signature));
    // Serialize and detach the mutable caller input before any verification.
    const serialized = protocol.canonicalJson(manifest);
    check(typeof serialized === "string"
      && Buffer.byteLength(serialized, "utf8") <= 262144);
    const record = JSON.parse(serialized);
    exact(record, ["version", "revision", "bindings"]);
    check(record.version === 1
      && Number.isSafeInteger(record.revision)
      && record.revision >= trustedMinimumRevision
      && Array.isArray(record.bindings)
      && record.bindings.length > 0 && record.bindings.length <= 1024);
    const scopes = new Set();
    for (const item of record.bindings) {
      exact(item, FIELDS);
      check(typeof item.scope === "string" && SCOPE.test(item.scope)
        && typeof item.accountId === "string" && UUID.test(item.accountId)
        && typeof item.storeId === "string" && UUID.test(item.storeId)
        && typeof item.username === "string" && item.username.length > 0
        && item.username.length <= 512
        && typeof item.compartmentId === "string" && item.compartmentId.length > 0
        && item.compartmentId.length <= 512 && !scopes.has(item.scope));
      scopes.add(item.scope);
    }
    const statement = Buffer.from(DOMAIN + protocol.canonicalJson(record), "utf8");
    const digest = crypto.createHash("sha256").update(statement).digest("hex");
    const signed = Buffer.from(signature, "base64url");
    check(digest === independentlyPinnedSha256 && signed.length === 64
      && signed.toString("base64url") === signature
      && crypto.verify(null, statement, trustedOwnerPublicKey, signed));
    return Object.freeze({ version: 1, revision: record.revision, digest,
      bindings: Object.freeze(record.bindings.map((item) => Object.freeze(item))) });
  } catch { throw fail(); }
}

module.exports = { verifySignedOwnerBindingsDevOff, DOMAIN };
