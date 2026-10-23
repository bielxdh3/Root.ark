"use strict";

// Offline export: the owner signs a historical signer assertion ONLY after the
// remote V2 inspector independently verifies the signed recovery history,
// pinned genesis, witness, catalog header, owner approval, CAS/FLOOR history,
// and checkpoint. The assertion is transported separately from the intent.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const { inspectIntent } = require("../services/zk1OpaqueCheckpointV2Remote");

const DOMAIN = Buffer.from("Root.ark/zk-1/v2-historical-signer-endorsement/v2\0");
const GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const APPROVAL_DOMAIN = Buffer.from("Root.ark/zk-1/opaque-checkpoint-remote/owner-approval/v2\0");
const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const LEGACY_FIELDS = Object.freeze(["schema", "account_id", "compartment_id", "keyring_id",
  "sequence", "intent_sha256", "operation_id", "head_digest", "checkpoint_digest",
  "signer_device_id", "signer_public_key", "manifest_revision", "manifest_digest",
  "epoch", "genesis_digest", "witness_signer_spki_sha256"]);
const FIELDS = Object.freeze([...LEGACY_FIELDS, "approval_signer_public_key"]);
const sha = (v) => crypto.createHash("sha256").update(v).digest();
function denied() { throw Error("ZK_V2_HISTORICAL_SIGNER_UNVERIFIED"); }
function b64(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) denied();
  const raw = Buffer.from(value, "base64url");
  if (raw.length !== length || raw.toString("base64url") !== value) denied();
  return raw;
}

async function issueVerifiedHistoricalSignerEndorsement({ signedIntent, inspectorOptions,
  trustedOwnerPrivateKey, independentlyPinnedOwnerSpkiSha256,
  currentSignedDeviceGrant, independentlyPinnedCurrentOwnerHead }) {
  try {
    const signer = trustedOwnerPrivateKey?.type === "private"
      ? trustedOwnerPrivateKey : crypto.createPrivateKey(trustedOwnerPrivateKey);
    const owner = crypto.createPublicKey(signer);
    const spki = owner.export({ format: "der", type: "spki" });
    if (signer.asymmetricKeyType !== "ed25519"
      || !sha(spki).equals(Buffer.from(independentlyPinnedOwnerSpkiSha256))
      || !inspectorOptions.ownerTrust?.pinnedWitness?.publicKey
      || !inspectorOptions.ownerTrust?.genesisDigest) denied();
    const grant = currentSignedDeviceGrant;
    const head = independentlyPinnedCurrentOwnerHead;
    if (!grant || !head || Object.keys(grant).length !== GRANT_FIELDS.length + 1
      || !GRANT_FIELDS.every((field) => Object.hasOwn(grant, field))
      || !Object.hasOwn(grant, "signature")
      || grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
      || grant.revoked_at_epoch !== null
      || !Number.isSafeInteger(head.revision) || head.revision < 1
      || !Number.isSafeInteger(head.epoch) || head.epoch < 1
      || !Number.isSafeInteger(grant.enrolled_epoch) || grant.enrolled_epoch < 1
      || !Number.isSafeInteger(grant.current_epoch) || grant.current_epoch < 1
      || !Number.isSafeInteger(grant.manifest_revision) || grant.manifest_revision < 1
      || typeof grant.device_id !== "string" || !grant.device_id || grant.device_id.length > 128
      || !Number.isSafeInteger(grant.enrolled_epoch)
      || grant.enrolled_epoch > head.epoch
      || grant.current_epoch !== head.epoch || grant.manifest_revision !== head.revision
      || !b64(grant.manifest_digest, 32).equals(Buffer.from(head.digest))
      || ["account_id", "compartment_id", "keyring_id"].some((field) =>
        grant[field] !== Buffer.from(inspectorOptions.scope[field]).toString("base64url"))) denied();
    const grantSignerSpki = Buffer.concat([SPKI_PREFIX,
      b64(grant.authorization_public_key, 32)]);
    if (grantSignerSpki.length !== 44
      || !b64(grant.authorization_key_id, 16)
      || grantSignerSpki.equals(spki)
      || !crypto.verify(null, Buffer.concat([GRANT_DOMAIN,
        Buffer.from(JSON.stringify(Object.fromEntries(GRANT_FIELDS.map((f) => [f, grant[f]]))))]),
      owner, b64(grant.signature, 64))) denied();
    const raw = Buffer.from(signedIntent);
    // Historical checkpoints can outlive their owner approver's revocation.
    // The remote inspector authenticates that signer from the signed recovery
    // history at the checkpoint epoch, and verifies witness/CAS/FLOOR lineage.
    // Never source either historical key from the untrusted intent or the
    // current signed-device grant (which may name a different active device).
    const inspected = await inspectIntent(raw, inspectorOptions,
      { freshOwner: false, historicalOwner: true });
    const approvalSpki = Buffer.from(inspected.ownerApprovalSignerSpki || []);
    if (approvalSpki.length !== 44 || !approvalSpki.subarray(0, 12).equals(SPKI_PREFIX)
      || approvalSpki.equals(spki)
      || !crypto.verify(null, Buffer.concat([APPROVAL_DOMAIN,
        Buffer.from(inspected.body.owner_approval)]),
      crypto.createPublicKey({ key: approvalSpki, type: "spki", format: "der" }),
      Buffer.from(inspected.body.owner_signature))) denied();
    const header = await z.decodeDeterministic(inspected.body.records[0].header);
    const scope = inspectorOptions.scope;
    const statement = {
      schema: "rootark-zk1-v2-historical-signer-endorsement/v2",
      ...Object.fromEntries(["account_id", "compartment_id", "keyring_id"]
        .map((field) => [field, Buffer.from(scope[field]).toString("base64url")])),
      sequence: header.sequence, intent_sha256: sha(raw).toString("base64url"),
      operation_id: Buffer.from(inspected.operationId).toString("base64url"),
      head_digest: Buffer.from(inspected.finalDigest).toString("base64url"),
      checkpoint_digest: Buffer.from(inspected.checkpointDigest).toString("base64url"),
      signer_device_id: header.signer_device_id,
      signer_public_key: Buffer.from(inspected.signerSpki).subarray(-32).toString("base64url"),
      manifest_revision: Number(header.manifest_revision),
      manifest_digest: Buffer.from(header.manifest_digest).toString("base64url"),
      epoch: Number(header.epoch),
      genesis_digest: Buffer.from(inspectorOptions.ownerTrust.genesisDigest).toString("base64url"),
      witness_signer_spki_sha256: sha(
        inspectorOptions.ownerTrust.pinnedWitness.publicKey
          .export({ format: "der", type: "spki" })).toString("base64url"),
      // The backend selected this exact approver from authenticated historical
      // owner recovery history; its present-day revocation does not rewrite it.
      approval_signer_public_key: approvalSpki.subarray(-32).toString("base64url"),
    };
    return Object.freeze({ ...statement,
      signature: crypto.sign(null, Buffer.concat([DOMAIN,
        Buffer.from(JSON.stringify(Object.fromEntries(FIELDS.map((f) => [f, statement[f]]))))]),
      signer).toString("base64url") });
  } catch (_) { denied(); }
}

module.exports = { FIELDS, LEGACY_FIELDS, issueVerifiedHistoricalSignerEndorsement };
