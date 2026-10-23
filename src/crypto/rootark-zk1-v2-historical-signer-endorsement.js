"use strict";

// Offline export: the owner signs a historical signer assertion ONLY after the
// remote V2 inspector independently verifies the signed recovery history,
// pinned genesis, witness, catalog header, owner approval, CAS/FLOOR history,
// and checkpoint. The assertion is transported separately from the intent.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const { inspectIntent } = require("../services/zk1OpaqueCheckpointV2Remote");

const DOMAIN = Buffer.from("Root.ark/zk-1/v2-historical-signer-endorsement/v1\0");
const GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const GRANT_FIELDS = ["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key",
  "manifest_revision", "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"];
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const FIELDS = Object.freeze(["schema", "account_id", "compartment_id", "keyring_id",
  "sequence", "intent_sha256", "operation_id", "head_digest", "checkpoint_digest",
  "signer_device_id", "signer_public_key", "manifest_revision", "manifest_digest",
  "epoch", "genesis_digest", "witness_signer_spki_sha256"]);
const sha = (v) => crypto.createHash("sha256").update(v).digest();
function denied() { throw Error("ZK_V2_HISTORICAL_SIGNER_UNVERIFIED"); }

async function issueVerifiedHistoricalSignerEndorsement({ signedIntent, inspectorOptions,
  trustedOwnerPrivateKey, independentlyPinnedOwnerSpkiSha256,
  currentSignedDeviceGrant, independentlyPinnedCurrentOwnerHead }) {
  try {
    const signer = trustedOwnerPrivateKey?.type === "private"
      ? trustedOwnerPrivateKey : crypto.createPrivateKey(trustedOwnerPrivateKey);
    const owner = crypto.createPublicKey(signer);
    const trusted = inspectorOptions.ownerKey?.type === "public"
      ? inspectorOptions.ownerKey : crypto.createPublicKey(inspectorOptions.ownerKey);
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
      || !Number.isSafeInteger(grant.enrolled_epoch)
      || grant.enrolled_epoch > head.epoch
      || grant.current_epoch !== head.epoch || grant.manifest_revision !== head.revision
      || grant.manifest_digest !== Buffer.from(head.digest).toString("base64url")
      || ["account_id", "compartment_id", "keyring_id"].some((field) =>
        grant[field] !== Buffer.from(inspectorOptions.scope[field]).toString("base64url"))) denied();
    const grantSignerSpki = Buffer.concat([SPKI_PREFIX,
      Buffer.from(grant.authorization_public_key, "base64url")]);
    if (grantSignerSpki.length !== 44
      || !grantSignerSpki.equals(trusted.export({ format: "der", type: "spki" }))
      || !crypto.verify(null, Buffer.concat([GRANT_DOMAIN,
        Buffer.from(JSON.stringify(Object.fromEntries(GRANT_FIELDS.map((f) => [f, grant[f]]))))]),
      owner, Buffer.from(grant.signature, "base64url"))) denied();
    const raw = Buffer.from(signedIntent);
    const inspected = await inspectIntent(raw, inspectorOptions, { freshOwner: true });
    const header = await z.decodeDeterministic(inspected.body.records[0].header);
    const scope = inspectorOptions.scope;
    const statement = {
      schema: "rootark-zk1-v2-historical-signer-endorsement/v1",
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
    };
    return Object.freeze({ ...statement,
      signature: crypto.sign(null, Buffer.concat([DOMAIN,
        Buffer.from(JSON.stringify(Object.fromEntries(FIELDS.map((f) => [f, statement[f]]))))]),
      signer).toString("base64url") });
  } catch (_) { denied(); }
}

module.exports = { FIELDS, issueVerifiedHistoricalSignerEndorsement };
