"use strict";

// DEV-OFF recipient-side bridge. Requires separately provisioned owner/V2
// custody and a real owner-approved, recipient-specific HPKE file CEK.
const crypto = require("node:crypto");
const { types: { isProxy, isSharedArrayBuffer, isUint8Array } } = require("node:util");
const z = require("./rootark-zk-1");
const { redeemProtectedCiphertextShare } =
  require("../../public/client/rootark-zk1-recipient-share");
const { openOwnerAuthorizedFileCek } =
  require("./rootark-zk1-owner-authorized-file-cek-transfer");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const roots = require("../../public/client/rootark-zk1-ciphertext-chunk-root");
// Snapshot the native wall-clock entry point before any caller-supplied
// authority callback runs. A callback may overwrite global Date.now, but it
// must not be able to roll back the final post-AEAD release deadline.
const nativeReleaseNow = Date.now;
// The last authority callback is untrusted JavaScript. Even a captured native
// Array#filter invokes the caller's constructor[Symbol.species], allowing a
// forged result that replaces genuinely revoked issuer/recipient records.
// Read only own DATA descriptors, without filters, iterators, or getters.
const nativeIsArray = Array.isArray.bind(Array);
const nativeGetPrototype = Object.getPrototypeOf.bind(Object);
const nativeOwnDescriptor = Object.getOwnPropertyDescriptor.bind(Object);
const nativeHasOwn = Object.hasOwn.bind(Object);
const nativeOwnKeys = Reflect.ownKeys.bind(Reflect);
const nativeApply = Reflect.apply.bind(Reflect);
const NativeUint8Array = Uint8Array;
const nativePlainObjectPrototype = Object.prototype;
const nativeIsSafeInteger = Number.isSafeInteger.bind(Number);
const typedArrayPrototype = nativeGetPrototype(Uint8Array.prototype);
const typedArrayLength = nativeOwnDescriptor(typedArrayPrototype, "length").get;
const typedArrayByteLength = nativeOwnDescriptor(typedArrayPrototype, "byteLength").get;
const typedArrayByteOffset = nativeOwnDescriptor(typedArrayPrototype, "byteOffset").get;
const typedArrayBuffer = nativeOwnDescriptor(typedArrayPrototype, "buffer").get;
const nativeUint8Set = Uint8Array.prototype.set;
const nativeBufferFrom = Buffer.from.bind(Buffer);
const nativeBufferToString = Buffer.prototype.toString;
const nativeBufferConcat = Buffer.concat.bind(Buffer);
const nativeTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeVerify = crypto.verify.bind(crypto);
const nativeFreeze = Object.freeze.bind(Object);
const nativeUint8Fill = Uint8Array.prototype.fill;

const SHARE_DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const METADATA = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
const ENVELOPE = ["schema", "core", "enc", "ciphertext", "owner_signature",
  "authorizesProductionRestore", "externalCustodyProven"];
function deny() { throw Error("ZK_SHARE_FILE_OPEN_DENIED"); }
function copyNativeBytes(value, minLength, maxLength) {
  // A real Uint8Array/Buffer can own hostile `length`, `valueOf` or iterator.
  // Native typed-array accessors read the internal view slots without
  // dispatching those properties; native Set copies actual indexed bytes.
  if (isProxy(value) || !isUint8Array(value)) deny();
  const length = nativeApply(typedArrayLength, value, []);
  const byteLength = nativeApply(typedArrayByteLength, value, []);
  const offset = nativeApply(typedArrayByteOffset, value, []);
  const backing = nativeApply(typedArrayBuffer, value, []);
  if (!nativeIsSafeInteger(length) || length < minLength || length > maxLength
    || byteLength !== length || !nativeIsSafeInteger(offset)
    || offset < 0 || isSharedArrayBuffer(backing)) deny();
  const privateCopy = new NativeUint8Array(length);
  nativeApply(nativeUint8Set, privateCopy, [value]);
  // Buffer.from(ArrayBuffer, offset, length) shares only this new private
  // allocation, never the caller's possibly poisoned original typed array.
  return nativeBufferFrom(nativeApply(typedArrayBuffer, privateCopy, []), 0, length);
}
const copyNativeBytes32 = (value) => copyNativeBytes(value, 32, 32);
// Signed CBOR scope/id bytes may be 16, 32 or bounded compartment bytes.
// Buffer#toString itself can consult a callback-poisoned Buffer.prototype
// length or encoding method AFTER the final authority read. Encode bounded
// freshly copied native bytes directly, without any JS prototype dispatch.
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function b64(value) {
  const bytes = copyNativeBytes(value, 1, 128);
  const size = nativeApply(typedArrayLength, bytes, []);
  let encoded = "";
  for (let index = 0; index < size; index += 3) {
    const a = bytes[index];
    const b = index + 1 < size ? bytes[index + 1] : 0;
    const c = index + 2 < size ? bytes[index + 2] : 0;
    encoded += BASE64URL[a >>> 2];
    encoded += BASE64URL[((a & 3) << 4) | (b >>> 4)];
    if (index + 1 < size) encoded += BASE64URL[((b & 15) << 2) | (c >>> 6)];
    if (index + 2 < size) encoded += BASE64URL[c & 63];
  }
  return encoded;
}
function wipeNativeBytes(value) {
  // Even a genuine Uint8Array or Buffer may have an own fill() or a rebound
  // Buffer.prototype.fill after the final independent authority callback.
  if (value != null && !isProxy(value) && isUint8Array(value)) {
    nativeApply(nativeUint8Fill, value, [0]);
  }
}
function strict(value, names) {
  if (!value || typeof value !== "object" || nativeIsArray(value) || isProxy(value)
    || (nativeGetPrototype(value) !== nativePlainObjectPrototype
      && nativeGetPrototype(value) !== null)
    || nativeOwnKeys(value).length !== names.length) deny();
  for (let i = 0; i < names.length; i += 1) {
    const descriptor = nativeOwnDescriptor(value, names[i]);
    if (!descriptor || !nativeHasOwn(descriptor, "value")) deny();
  }
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
    || !nativeTimingSafeEqual(copyNativeBytes32(snapshotValue.head.digest),
      statement.manifest_digest)
    || !nativeIsArray(snapshotValue.devices) || isProxy(snapshotValue.devices)
    || snapshotValue.devices.length > 128) deny();
  for (let index = 0; index < SCOPE.length; index += 1) {
    const field = SCOPE[index];
    if (snapshotValue.scope[field] !== b64(statement[field])) deny();
  }
  const active = (deviceId) => {
    let found = null;
    for (let i = 0; i < snapshotValue.devices.length; i += 1) {
      const slot = nativeOwnDescriptor(snapshotValue.devices, `${i}`);
      if (!slot || !nativeHasOwn(slot, "value")) deny();
      const device = slot.value;
      strict(device, ["deviceId", "authorizationPublicKey", "enrolledEpoch", "revokedAtEpoch"]);
      const id = nativeOwnDescriptor(device, "deviceId");
      if (!id || !nativeHasOwn(id, "value")) deny();
      if (id.value !== deviceId) continue;
      if (found) deny();
      const revoked = nativeOwnDescriptor(device, "revokedAtEpoch");
      const enrolled = nativeOwnDescriptor(device, "enrolledEpoch");
      const publicKey = nativeOwnDescriptor(device, "authorizationPublicKey");
      if (!revoked || !nativeHasOwn(revoked, "value") || revoked.value !== null
        || !enrolled || !nativeHasOwn(enrolled, "value")
        || !nativeIsSafeInteger(enrolled.value) || enrolled.value < 1
        || enrolled.value > statement.epoch
        || !publicKey || !nativeHasOwn(publicKey, "value")) deny();
      found = copyNativeBytes32(publicKey.value);
    }
    if (!found) deny();
    return found;
  };
  active(statement.recipient_device_id);
  const issuer = active(statement.issuer_device_id);
  if (!nativeVerify(null, nativeBufferConcat([SHARE_DOMAIN, statementBytes]),
    nativeCreatePublicKey({ key: nativeBufferConcat([ED25519_SPKI, issuer]),
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
    // A valid independent reader must stay the SAME reader across the initial
    // signed redemption, owner HPKE, file AEAD and final release fence.
    // An awaited caller callback may otherwise replace this property with a
    // stale always-active authority implementation before the final check.
    const readerDescriptor = redeemInput && !isProxy(redeemInput)
      ? nativeOwnDescriptor(redeemInput, "readIndependentAuthority") : null;
    if (!readerDescriptor || !nativeHasOwn(readerDescriptor, "value")
      || typeof readerDescriptor.value !== "function"
      || !nativeIsSafeInteger(nowSeconds) || nowSeconds < 1) deny();
    const readIndependentAuthority = () =>
      nativeApply(readerDescriptor.value, redeemInput, []);
    const receipt = await redeemProtectedCiphertextShare({
      ...redeemInput, readIndependentAuthority,
    });
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
    currentAuthority(await readIndependentAuthority(),
      statement, shareSignature, statementBytes);
    // Only the owner CEK opener can attest which owner approval and witness
    // it ACTUALLY verified after the preceding asynchronous share redemption.
    const verifiedReleaseExpiresAt = opened.verifiedReleaseExpiresAt;
    if (!nativeIsSafeInteger(verifiedReleaseExpiresAt)
      || verifiedReleaseExpiresAt < 1) deny();
    const releaseSeconds = nativeReleaseNow() / 1000;
    // The independent authority callback just ran. Never dispatch a mutable
    // Array.prototype.some for the final plaintext-release expiry decision.
    if (releaseSeconds >= statement.expires_at
      || releaseSeconds >= verifiedReleaseExpiresAt
      || nowSeconds >= statement.expires_at
      || nowSeconds >= verifiedReleaseExpiresAt) deny();
    // Never delegate DEV-OFF proof flags to a callback-rebound Object.freeze.
    const result = nativeFreeze({
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
  finally { wipeNativeBytes(opened?.cek); wipeNativeBytes(plaintext?.data); }
}

module.exports = { openProtectedRecipientShareFile };
