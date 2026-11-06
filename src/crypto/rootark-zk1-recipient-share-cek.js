"use strict";

// DEV-OFF recipient-side bridge. Requires separately provisioned owner/V2
// custody and a real owner-approved, recipient-specific HPKE file CEK.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const { redeemProtectedCiphertextShare } =
  require("../../public/client/rootark-zk1-recipient-share");
const { openOwnerAuthorizedFileCek } =
  require("./rootark-zk1-owner-authorized-file-cek-transfer");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const roots = require("../../public/client/rootark-zk1-ciphertext-chunk-root");

const SHARE_DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const METADATA = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
const ENVELOPE = ["schema", "core", "enc", "ciphertext", "owner_signature",
  "authorizesProductionRestore", "externalCustodyProven"];
function deny() { throw Error("ZK_SHARE_FILE_OPEN_DENIED"); }
const b64 = (value) => Buffer.from(value).toString("base64url");
function strict(value, names) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== names.length
    || names.some((name) => !Object.hasOwn(value, name))) deny();
}
function snapshot(value, names) {
  strict(value, names);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const copy = Object.create(null);
  for (const name of names) {
    const descriptor = descriptors[name];
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    const part = descriptor.value;
    if (part !== null && !["string", "number", "boolean"].includes(typeof part)) deny();
    copy[name] = part;
  }
  return Object.freeze(copy);
}
function safeEnvelope(value) {
  strict(value, ENVELOPE);
  const d = Object.getOwnPropertyDescriptors(value);
  if (ENVELOPE.some((name) => !Object.hasOwn(d[name], "value"))) deny();
  const keys = Reflect.ownKeys(d.core.value);
  if (keys.length > 40 || keys.some((key) => typeof key !== "string")) deny();
  const core = snapshot(d.core.value, keys);
  const other = snapshot({ schema: d.schema.value, enc: d.enc.value,
    ciphertext: d.ciphertext.value, owner_signature: d.owner_signature.value,
    authorizesProductionRestore: d.authorizesProductionRestore.value,
    externalCustodyProven: d.externalCustodyProven.value },
  ENVELOPE.filter((field) => field !== "core"));
  return Object.freeze({ ...other, core });
}
function currentAuthority(snapshotValue, statement, shareSignature, statementBytes) {
  strict(snapshotValue, ["scope", "head", "devices"]);
  strict(snapshotValue.scope, SCOPE);
  strict(snapshotValue.head, ["revision", "epoch", "digest"]);
  if (snapshotValue.head.revision !== statement.manifest_revision
    || snapshotValue.head.epoch !== statement.epoch
    || !Buffer.from(snapshotValue.head.digest || []).equals(statement.manifest_digest)
    || !Array.isArray(snapshotValue.devices) || snapshotValue.devices.length > 128) deny();
  for (const field of SCOPE) {
    if (snapshotValue.scope[field] !== b64(statement[field])) deny();
  }
  const active = (deviceId) => {
    const hits = snapshotValue.devices.filter((device) => device?.deviceId === deviceId);
    if (hits.length !== 1) deny();
    const device = hits[0];
    if (device.revokedAtEpoch !== null || !Number.isSafeInteger(device.enrolledEpoch)
      || device.enrolledEpoch < 1 || device.enrolledEpoch > statement.epoch
      || !(device.authorizationPublicKey instanceof Uint8Array)
      || device.authorizationPublicKey.length !== 32) deny();
    return Buffer.from(device.authorizationPublicKey);
  };
  active(statement.recipient_device_id);
  const issuer = active(statement.issuer_device_id);
  if (!crypto.verify(null, Buffer.concat([SHARE_DOMAIN, statementBytes]),
    crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI, issuer]),
      format: "der", type: "spki" }), shareSignature)) deny();
}
async function openProtectedRecipientShareFile(input) {
  let opened;
  let plaintext;
  try {
    strict(input, ["redeemInput", "envelope", "authority", "operatorMinimumSequence",
      "metadata", "deviceHpkePrivateKey", "nowSeconds"]);
    const metadata = snapshot(input.metadata, METADATA);
    const envelope = safeEnvelope(input.envelope);
    const { redeemInput, authority, operatorMinimumSequence,
      deviceHpkePrivateKey, nowSeconds } = input;
    if (typeof redeemInput?.readIndependentAuthority !== "function"
      || !Number.isSafeInteger(nowSeconds) || nowSeconds < 1) deny();
    const receipt = await redeemProtectedCiphertextShare(redeemInput);
    if (receipt.ownerGrantSignatureVerified !== true
      || receipt.serverRevocationProofVerified !== false
      || receipt.authorizesPlaintextRelease !== false) deny();
    const ciphertext = Buffer.from(receipt.ciphertextBase64, "base64url");
    const statementBytes = Buffer.from(receipt.shareStatementBase64, "base64url");
    const statement = await z.decodeDeterministic(statementBytes);
    const shareSignature = Buffer.from(receipt.shareSignatureBase64, "base64url");
    const core = envelope.core;
    if (statement.recipient_device_id !== redeemInput.recipientDeviceId
      || statement.recipient_username !== redeemInput.recipientUsername
      || receipt.grantId !== b64(statement.grant_id)
      || receipt.objectId !== statement.object_id
      || receipt.revision !== statement.object_revision
      || receipt.epoch !== statement.epoch
      || receipt.ciphertextSha256Base64 !== b64(statement.ciphertext_digest)
      || core.object_id !== receipt.objectId
      || metadata.object_id !== receipt.objectId
      || core.object_revision !== receipt.revision
      || core.epoch !== receipt.epoch || metadata.epoch !== receipt.epoch
      || core.ciphertext_sha256 !== receipt.ciphertextSha256Base64
      || core.device_id !== statement.recipient_device_id
      || core.owner_revision !== statement.manifest_revision
      || core.owner_digest !== b64(statement.manifest_digest)
      || core.owner_epoch !== statement.epoch) deny();
    for (const field of SCOPE) {
      if (core[field] !== b64(statement[field])
        || metadata[field] !== core[field]) deny();
    }
    const ciphertextRoot = await roots.computeCiphertextRoot([ciphertext]);
    opened = await openOwnerAuthorizedFileCek({
      envelope, authority, operatorMinimumSequence, metadata,
      objectRevision: receipt.revision, ciphertext, ciphertextRoot,
      deviceHpkePrivateKey, nowSeconds,
    });
    if (opened.authorizesProductionRestore !== false
      || opened.externalCustodyProven !== false) deny();
    plaintext = await fileContent.decryptFile({
      cek: await fileContent.importFileCek(opened.cek),
      metadata, envelopeBytes: ciphertext,
    });
    // HPKE and file AEAD await. Check the independent head and both live devices
    // again immediately before releasing the decrypted file to this process.
    currentAuthority(await redeemInput.readIndependentAuthority(),
      statement, shareSignature, statementBytes);
    if (Math.floor(Date.now() / 1000) >= statement.expires_at
      || nowSeconds >= statement.expires_at) deny();
    const result = Object.freeze({
      schema: "rootark-zk1-recipient-share-file-dev/v1",
      grantId: receipt.grantId, objectId: receipt.objectId,
      revision: receipt.revision, epoch: receipt.epoch,
      name: plaintext.name, mediaType: plaintext.mediaType, data: plaintext.data,
      ownerGrantSignatureVerified: true, ownerCekTransferVerified: true,
      serverRevocationProofVerified: false, externalCustodyProven: false,
      authorizesProductionIo: false,
    });
    plaintext = null;
    return result;
  } catch (_) { deny(); }
  finally { opened?.cek?.fill(0); plaintext?.data?.fill(0); }
}

module.exports = { openProtectedRecipientShareFile };
