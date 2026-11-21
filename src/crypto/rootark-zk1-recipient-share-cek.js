"use strict";

// DEV-OFF recipient-side bridge. Requires separately provisioned owner/V2
// custody and a real owner-approved, recipient-specific HPKE file CEK.
const crypto = require("node:crypto");
const { isProxy: isNativeProxy, isSharedArrayBuffer: nativeIsSharedArrayBuffer,
  isUint8Array: nativeIsUint8Array } = require("node:util").types;
const z = require("./rootark-zk-1");
const { redeemProtectedCiphertextShare } =
  require("../../public/client/rootark-zk1-recipient-share");
const { openOwnerAuthorizedFileCek, sealOwnerAuthorizedFileCek } =
  require("./rootark-zk1-owner-authorized-file-cek-transfer");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const roots = require("../../public/client/rootark-zk1-ciphertext-chunk-root");
// Capture the real clock before an independent roster reader gets to execute
// arbitrary JavaScript. An authority callback cannot extend a signed lease by
// replacing the global Date.now function.
const nativeReleaseNow = Date.now;
const nativeReleaseFloor = Math.floor;
const nativeMathCeil = Math.ceil.bind(Math);
const nativeReflectApply = Reflect.apply.bind(Reflect);
const nativeOwnDescriptor = Object.getOwnPropertyDescriptor.bind(Object);
const nativeAllDescriptors = Object.getOwnPropertyDescriptors.bind(Object);
const nativeGetPrototype = Object.getPrototypeOf.bind(Object);
const nativeOwnKeys = Reflect.ownKeys.bind(Reflect);
const nativeHasOwn = Object.hasOwn.bind(Object);
const nativeIsArray = Array.isArray.bind(Array);
const nativeIsSafeInteger = Number.isSafeInteger.bind(Number);
const nativeUint8Array = Uint8Array;
const nativeTypedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const nativeTypedLength = nativeOwnDescriptor(nativeTypedArrayPrototype, "length").get;
const nativeTypedByteLength = nativeOwnDescriptor(nativeTypedArrayPrototype, "byteLength").get;
const nativeTypedByteOffset = nativeOwnDescriptor(nativeTypedArrayPrototype, "byteOffset").get;
const nativeTypedBuffer = nativeOwnDescriptor(nativeTypedArrayPrototype, "buffer").get;
const nativeTypedSet = Uint8Array.prototype.set;
const nativeTypedFill = Uint8Array.prototype.fill;
const nativeBufferFrom = Buffer.from.bind(Buffer);
const nativeBufferToString = Buffer.prototype.toString;
const nativeBufferConcat = Buffer.concat.bind(Buffer);
const nativeTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeVerify = crypto.verify.bind(crypto);
const nativeFreeze = Object.freeze.bind(Object);
const nativeCreateObject = Object.create.bind(Object);
const nativeObjectPrototype = Object.prototype;

const SHARE_DOMAIN = Buffer.from("Root.ark/zk-1/protected-ciphertext-share/v1\0");
const ED25519_SPKI = Buffer.from("302a300506032b6570032100", "hex");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const METADATA = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
const ENVELOPE = ["schema", "core", "enc", "ciphertext", "owner_signature",
  "authorizesProductionRestore", "externalCustodyProven"];
const ENVELOPE_OTHER = ["schema", "enc", "ciphertext", "owner_signature",
  "authorizesProductionRestore", "externalCustodyProven"];
const SHARE = ["type", "grant_id", "account_id", "compartment_id", "keyring_id",
  "object_id", "object_revision", "ciphertext_digest", "epoch", "manifest_revision",
  "manifest_digest", "issuer_device_id", "request_nonce", "issued_at", "expires_at",
  "recipient_username", "recipient_device_id"];
const GRANT = ["grantId", "expiresAt", "shareStatementBase64", "shareSignatureBase64"];
const RECIPIENT_PIN = ["recipientUsername", "deviceId",
  "authorizationPublicKey", "hpkePublicKey"];
const ISSUER_PIN = ["deviceId", "authorizationPublicKey"];
const OFFER = ["schema", "grant", "recipientUsername", "recipientDeviceId",
  "metadata", "envelope", "authorizesProductionIo", "externalCustodyProven"];
function deny() { throw Error("ZK_SHARE_FILE_OPEN_DENIED"); }
function denyOffer() { throw Error("ZK_SHARE_OFFER_DENIED"); }
// Independent roster readers may mutate typed-array prototype methods, own
// `length` fields or Buffer.from between awaited signature checks. Verify the
// actual view's native slots and copy its bytes without using its iterator.
function copyNativeBytes(value, minLength, maxLength) {
  if (isNativeProxy(value) || !nativeIsUint8Array(value)) deny();
  const length = nativeReflectApply(nativeTypedLength, value, []);
  const byteLength = nativeReflectApply(nativeTypedByteLength, value, []);
  const byteOffset = nativeReflectApply(nativeTypedByteOffset, value, []);
  const backing = nativeReflectApply(nativeTypedBuffer, value, []);
  if (!nativeIsSafeInteger(length) || length < minLength || length > maxLength
    || byteLength !== length || !nativeIsSafeInteger(byteOffset)
    || byteOffset < 0 || nativeIsSharedArrayBuffer(backing)) deny();
  const bytes = new nativeUint8Array(length);
  nativeReflectApply(nativeTypedSet, bytes, [value]);
  return nativeBufferFrom(nativeReflectApply(nativeTypedBuffer, bytes, []), 0, length);
}
const copyNativeBytes32 = (value) => copyNativeBytes(value, 32, 32);
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function b64(value) {
  const bytes = copyNativeBytes(value, 1, 128);
  const length = nativeReflectApply(nativeTypedLength, bytes, []);
  let encoded = "";
  for (let index = 0; index < length; index += 3) {
    const a = bytes[index];
    const b = index + 1 < length ? bytes[index + 1] : 0;
    const c = index + 2 < length ? bytes[index + 2] : 0;
    encoded += BASE64URL[a >>> 2];
    encoded += BASE64URL[((a & 3) << 4) | (b >>> 4)];
    if (index + 1 < length) encoded += BASE64URL[((b & 15) << 2) | (c >>> 6)];
    if (index + 2 < length) encoded += BASE64URL[c & 63];
  }
  return encoded;
}
function wipeNativeBytes(value) {
  if (value != null && !isNativeProxy(value) && nativeIsUint8Array(value)) {
    nativeReflectApply(nativeTypedFill, value, [0]);
  }
}
function from64(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
    || value.length > nativeMathCeil(length * 4 / 3) + 4) denyOffer();
  const bytes = nativeBufferFrom(value, "base64url");
  // A signed CBOR statement is up to 4096 bytes, unlike 16/32-byte scope
  // fields. Re-encode through the captured native Buffer method, not the
  // deliberately 128-byte-bounded scope encoder.
  if (bytes.length !== length
    || nativeReflectApply(nativeBufferToString, bytes, ["base64url"]) !== value) denyOffer();
  return bytes;
}
function same(a, b) {
  return a.length === b.length && nativeTimingSafeEqual(a, b);
}
function allOwnData(descriptors, names) {
  // External callbacks can replace Array#some, Array#every, Object.values,
  // and their prototype iterators between signed checks. No user callback
  // participates in checking the captured descriptors.
  for (let index = 0; index < names.length; index++) {
    const field = descriptors[names[index]];
    if (!field || !nativeHasOwn(field, "value")) return false;
  }
  return true;
}
function strict(value, names) {
  if (!value || typeof value !== "object" || nativeIsArray(value)
    || isNativeProxy(value)
    || (nativeGetPrototype(value) !== nativeObjectPrototype
      && nativeGetPrototype(value) !== null)
    || nativeOwnKeys(value).length !== names.length) deny();
  for (let index = 0; index < names.length; index++) {
    const descriptor = nativeOwnDescriptor(value, names[index]);
    if (!descriptor || !nativeHasOwn(descriptor, "value")) deny();
  }
}
function snapshot(value, names) {
  strict(value, names);
  const descriptors = nativeAllDescriptors(value);
  const copy = nativeCreateObject(null);
  for (let index = 0; index < names.length; index++) {
    const name = names[index];
    const descriptor = descriptors[name];
    if (!descriptor || !nativeHasOwn(descriptor, "value")) deny();
    const part = descriptor.value;
    if (part !== null && !["string", "number", "boolean"].includes(typeof part)) deny();
    copy[name] = part;
  }
  return nativeFreeze(copy);
}
// Recipient contact pins come from the owner's separately authenticated
// contact/device enrollment. Neither the server response nor its grant may
// populate them. Reject accessors before any crypto or network await.
function snapshotAuthority(value) {
  // A Proxy over a real Array passes Array.isArray and may forge index
  // descriptors, even when no own map/filter method is invoked. Reject it
  // using the Node intrinsic before any user-controlled reflective access.
  if (isNativeProxy(value)) denyOffer();
  strict(value, ["scope", "head", "devices"]);
  const fields = nativeAllDescriptors(value);
  if (!allOwnData(fields, ["scope", "head", "devices"])) denyOffer();
  if (isNativeProxy(fields.scope.value)
    || isNativeProxy(fields.head.value)
    || isNativeProxy(fields.devices.value)) denyOffer();
  const scope = snapshot(fields.scope.value, SCOPE);
  const headValue = fields.head.value;
  strict(headValue, ["revision", "epoch", "digest"]);
  const h = nativeAllDescriptors(headValue);
  if (!h.revision || !nativeHasOwn(h.revision, "value")
    || !h.epoch || !nativeHasOwn(h.epoch, "value")
    || !h.digest || !nativeHasOwn(h.digest, "value")
    || !nativeIsSafeInteger(h.revision.value) || h.revision.value < 0
    || !nativeIsSafeInteger(h.epoch.value) || h.epoch.value < 0
    || isNativeProxy(h.digest.value)
    || !(h.digest.value instanceof Uint8Array)
    || h.digest.value.length !== 32) denyOffer();
  const head = { revision: h.revision.value, epoch: h.epoch.value,
    digest: copyNativeBytes32(h.digest.value) };
  const sourceDevices = fields.devices.value;
  if (!nativeIsArray(sourceDevices)) denyOffer();
  // Do not invoke an untrusted array's own map/iterator: it can substitute a
  // healthy roster while the actual authority entries are revoked.
  const entries = nativeAllDescriptors(sourceDevices);
  const length = entries.length?.value;
  if (!nativeIsSafeInteger(length) || length > 128
    || nativeOwnKeys(entries).length !== length + 1) denyOffer();
  const devices = [];
  for (let index = 0; index < length; ++index) {
    const entry = entries[index];
    if (!entry || !nativeHasOwn(entry, "value")) denyOffer();
    const device = entry.value;
    if (isNativeProxy(device)) denyOffer();
    strict(device, ["deviceId", "authorizationPublicKey",
      "enrolledEpoch", "revokedAtEpoch"]);
    const d = nativeAllDescriptors(device);
    if (!allOwnData(d, ["deviceId", "authorizationPublicKey",
      "enrolledEpoch", "revokedAtEpoch"])
      || isNativeProxy(d.authorizationPublicKey.value)
      || !(d.authorizationPublicKey.value instanceof Uint8Array)
      || d.authorizationPublicKey.value.length !== 32
      || !nativeIsSafeInteger(d.enrolledEpoch.value) || d.enrolledEpoch.value < 0
      || !(d.revokedAtEpoch.value === null
        || (nativeIsSafeInteger(d.revokedAtEpoch.value)
          && d.revokedAtEpoch.value >= d.enrolledEpoch.value))) denyOffer();
    devices[index] = { deviceId: d.deviceId.value,
      authorizationPublicKey: copyNativeBytes32(d.authorizationPublicKey.value),
      enrolledEpoch: d.enrolledEpoch.value, revokedAtEpoch: d.revokedAtEpoch.value };
  }
  return { scope, head, devices };
}
async function verifyOfferAuthority(authority, statement, bytes, signature, pin,
  issuerPin) {
  const current = snapshotAuthority(await authority());
  currentAuthority(current, statement, signature, bytes);
  // Independent roster membership does NOT grant issuer/owner authority:
  // a recipient may have a legitimate active Ed25519 signing device.
  const issuer = findUniqueDevice(current.devices, issuerPin.deviceId);
  if (!issuer
    || !same(issuer.authorizationPublicKey,
      from64(issuerPin.authorizationPublicKey, 32))) denyOffer();
  const recipient = findUniqueDevice(current.devices, pin.deviceId);
  if (!recipient
    || !same(recipient.authorizationPublicKey,
      from64(pin.authorizationPublicKey, 32))) denyOffer();
  return current;
}
function findUniqueDevice(devices, deviceId) {
  // snapshotAuthority creates a dense private array from checked own data
  // descriptors. Do not run Array#filter or species constructors after the
  // independent authority read: callbacks can poison those mutable methods.
  let found = null;
  for (let index = 0; index < devices.length; index++) {
    if (devices[index].deviceId !== deviceId) continue;
    if (found) deny();
    found = devices[index];
  }
  return found;
}
// Owner-side DEV-OFF portable offer. The owner MUST independently pin the
// authorized issuer's device ID and Ed25519 key; a candidate server ACK has no
// independently verifiable issuance proof and MUST NOT be a source of trust.
// The owner also pins recipient keys outside the untrusted grant/ACK.
async function createProtectedRecipientShareOffer(input) {
  let ownerCek, ciphertext;
  try {
    strict(input, ["grant", "recipientPin", "issuerPin", "readIndependentAuthority",
      "ownerPrivateKey", "ownerHeldCek", "metadata", "objectRevision",
      "ciphertext", "ciphertextRoot", "authority", "nowSeconds"]);
    const d = nativeAllDescriptors(input);
    if (!allOwnData(d, ["grant", "recipientPin", "issuerPin", "readIndependentAuthority",
      "ownerPrivateKey", "ownerHeldCek", "metadata", "objectRevision",
      "ciphertext", "ciphertextRoot", "authority", "nowSeconds"])) denyOffer();
    const grant = snapshot(d.grant.value, GRANT);
    const pin = snapshot(d.recipientPin.value, RECIPIENT_PIN);
    const issuerPin = snapshot(d.issuerPin.value, ISSUER_PIN);
    const metadata = snapshot(d.metadata.value, METADATA);
    if (typeof d.readIndependentAuthority.value !== "function"
      || typeof pin.recipientUsername !== "string"
      || !/^[A-Za-z0-9_.@-]{1,128}$/.test(pin.recipientUsername)
      || typeof pin.deviceId !== "string" || !pin.deviceId
      || pin.deviceId.length > 64
      || /[\x00-\x1f\x7f]/.test(pin.deviceId)
      || typeof issuerPin.deviceId !== "string"
      || !issuerPin.deviceId || issuerPin.deviceId.length > 64
      || /[\x00-\x1f\x7f]/.test(issuerPin.deviceId)
      || issuerPin.deviceId === pin.deviceId
      || !Number.isSafeInteger(d.nowSeconds.value)
      || Math.abs(Math.floor(Date.now() / 1000) - d.nowSeconds.value) > 30
      || !Number.isSafeInteger(d.objectRevision.value)
      || d.objectRevision.value < 1
      || !(d.ownerHeldCek.value instanceof Uint8Array)
      || d.ownerHeldCek.value.length !== 32
      || !(d.ciphertext.value instanceof Uint8Array)
      || d.ciphertext.value.length < 16
      || d.ciphertext.value.length > 4 * 1024 * 1024
      || !(d.ciphertextRoot.value instanceof Uint8Array)
      || d.ciphertextRoot.value.length !== 32) denyOffer();
    from64(pin.authorizationPublicKey, 32);
    from64(pin.hpkePublicKey, 32);
    from64(issuerPin.authorizationPublicKey, 32);
    if (same(from64(issuerPin.authorizationPublicKey, 32),
      from64(pin.authorizationPublicKey, 32))) denyOffer();
    from64(grant.grantId, 32);
    from64(metadata.object_id, 16);
    ownerCek = Buffer.from(d.ownerHeldCek.value);
    ciphertext = Buffer.from(d.ciphertext.value);
    const ciphertextRoot = Buffer.from(d.ciphertextRoot.value);
    if (typeof grant.shareStatementBase64 !== "string"
      || grant.shareStatementBase64.length > 5470) denyOffer();
    const statementBytes = from64(grant.shareStatementBase64,
      nativeBufferFrom(grant.shareStatementBase64, "base64url").length);
    if (statementBytes.length < 1 || statementBytes.length > 4096) denyOffer();
    const statement = await z.decodeDeterministic(statementBytes);
    strict(statement, SHARE);
    if (!same(Buffer.from(await z.encodeDeterministic(statement)), statementBytes)
      || statement.type !== "rootark-zk1-protected-ciphertext-share/v1"
      || !same(Buffer.from(statement.grant_id || []), from64(grant.grantId, 32))
      || statement.expires_at !== grant.expiresAt
      || !Number.isSafeInteger(statement.issued_at) || statement.issued_at < 1
      || statement.issued_at > d.nowSeconds.value + 30
      || !Number.isSafeInteger(statement.expires_at)
      || statement.expires_at <= Math.max(d.nowSeconds.value, statement.issued_at)
      || statement.expires_at - statement.issued_at > 86400
      || statement.recipient_username !== pin.recipientUsername
      || statement.recipient_device_id !== pin.deviceId
      || statement.issuer_device_id !== issuerPin.deviceId
      || statement.object_id !== metadata.object_id
      || statement.object_revision !== d.objectRevision.value
      || statement.epoch !== metadata.epoch
      || !same(Buffer.from(statement.ciphertext_digest || []),
        crypto.createHash("sha256").update(ciphertext).digest())) denyOffer();
    for (let index = 0; index < SCOPE.length; index++) {
      const field = SCOPE[index];
      if (metadata[field] !== b64(statement[field])) denyOffer();
    }
    const signature = from64(grant.shareSignatureBase64, 64);
    const preAuthority = await verifyOfferAuthority(d.readIndependentAuthority.value,
      statement, statementBytes, signature, pin, issuerPin);
    // Existing owner ceremony verifies an independent owner pin, an authentic
    // V2 approval + PoP, witness receipt, matching signed X25519 roster key,
    // real file AEAD and signed HPKE CEK envelope.
    const envelope = await sealOwnerAuthorizedFileCek({
      ownerPrivateKey: d.ownerPrivateKey.value, ownerHeldCek: ownerCek,
      metadata, objectRevision: d.objectRevision.value, ciphertext,
      ciphertextRoot, authority: d.authority.value,
    });
    if (envelope.core.device_id !== pin.deviceId
      || envelope.core.hpke_public_key !== pin.hpkePublicKey
      || envelope.core.object_id !== statement.object_id
      || envelope.core.object_revision !== statement.object_revision
      || envelope.core.ciphertext_sha256 !== b64(statement.ciphertext_digest)
      || envelope.core.owner_revision !== statement.manifest_revision
      || envelope.core.owner_digest !== b64(statement.manifest_digest)
      || envelope.core.owner_epoch !== statement.epoch
      || envelope.core.epoch !== statement.epoch) denyOffer();
    const postAuthority = await verifyOfferAuthority(d.readIndependentAuthority.value,
      statement, statementBytes, signature, pin, issuerPin);
    if (postAuthority.head.revision < preAuthority.head.revision
      || postAuthority.head.epoch < preAuthority.head.epoch) denyOffer();
    // The independently verified second authority read can outlast the
    // owner-approved HPKE envelope even while the share grant remains valid.
    // Neither lease may expire before releasing the portable CEK offer.
    const releaseSeconds = nativeReleaseFloor(nativeReleaseNow() / 1000);
    if (!Number.isSafeInteger(envelope.core.expires_at)
      || releaseSeconds >= envelope.core.expires_at
      || releaseSeconds >= statement.expires_at) denyOffer();
    return Object.freeze({
      schema: "rootark-zk1-recipient-share-offer-dev/v1",
      grant: Object.freeze({ ...grant }),
      recipientUsername: pin.recipientUsername, recipientDeviceId: pin.deviceId,
      metadata: Object.freeze({ ...metadata }), envelope,
      authorizesProductionIo: false, externalCustodyProven: false,
    });
  } catch (_) { denyOffer(); }
  finally { ownerCek?.fill(0); ciphertext?.fill(0); }
}
function safeEnvelope(value) {
  strict(value, ENVELOPE);
  const d = nativeAllDescriptors(value);
  if (!allOwnData(d, ENVELOPE) || isNativeProxy(d.core.value)) deny();
  const keys = nativeOwnKeys(d.core.value);
  if (keys.length > 40) deny();
  for (let index = 0; index < keys.length; index++) {
    if (typeof keys[index] !== "string") deny();
  }
  const core = snapshot(d.core.value, keys);
  const other = snapshot({ schema: d.schema.value, enc: d.enc.value,
    ciphertext: d.ciphertext.value, owner_signature: d.owner_signature.value,
    authorizesProductionRestore: d.authorizesProductionRestore.value,
    externalCustodyProven: d.externalCustodyProven.value },
  ENVELOPE_OTHER);
  return Object.freeze({ ...other, core });
}
function currentAuthority(snapshotValue, statement, shareSignature, statementBytes) {
  strict(snapshotValue, ["scope", "head", "devices"]);
  strict(snapshotValue.scope, SCOPE);
  strict(snapshotValue.head, ["revision", "epoch", "digest"]);
  if (snapshotValue.head.revision !== statement.manifest_revision
    || snapshotValue.head.epoch !== statement.epoch
    || !same(copyNativeBytes32(snapshotValue.head.digest),
      copyNativeBytes32(statement.manifest_digest))
    || !nativeIsArray(snapshotValue.devices) || snapshotValue.devices.length > 128) deny();
  for (let index = 0; index < SCOPE.length; index++) {
    const field = SCOPE[index];
    if (snapshotValue.scope[field] !== b64(statement[field])) deny();
  }
  const active = (deviceId) => {
    const device = findUniqueDevice(snapshotValue.devices, deviceId);
    if (!device) deny();
    if (device.revokedAtEpoch !== null || !nativeIsSafeInteger(device.enrolledEpoch)
      || device.enrolledEpoch < 1 || device.enrolledEpoch > statement.epoch
      || !nativeIsUint8Array(device.authorizationPublicKey)) deny();
    return copyNativeBytes32(device.authorizationPublicKey);
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
    const entry = nativeAllDescriptors(input);
    if (!allOwnData(entry, ["redeemInput", "envelope", "authority", "operatorMinimumSequence",
      "metadata", "deviceHpkePrivateKey", "nowSeconds"])) deny();
    const metadata = snapshot(entry.metadata.value, METADATA);
    const envelope = safeEnvelope(entry.envelope.value);
    const redeemInput = entry.redeemInput.value;
    const authority = entry.authority.value;
    const operatorMinimumSequence = entry.operatorMinimumSequence.value;
    const deviceHpkePrivateKey = entry.deviceHpkePrivateKey.value;
    const nowSeconds = entry.nowSeconds.value;
    // Pin the same independently enrolled authority reader across signed GET,
    // owner HPKE, file AEAD and final plaintext-release validation. A caller
    // must not replace its function after the initial asynchronous GET with a
    // stale but otherwise plausible roster reader.
    const readerDescriptor = redeemInput && !isNativeProxy(redeemInput)
      ? Object.getOwnPropertyDescriptor(redeemInput, "readIndependentAuthority") : null;
    if (!readerDescriptor || !Object.hasOwn(readerDescriptor, "value")
      || typeof readerDescriptor.value !== "function"
      || isNativeProxy(readerDescriptor.value)
      || !Number.isSafeInteger(nowSeconds) || nowSeconds < 1) deny();
    const readIndependentAuthority = () =>
      nativeReflectApply(readerDescriptor.value, redeemInput, []);
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
    for (let index = 0; index < SCOPE.length; index++) {
      const field = SCOPE[index];
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
    currentAuthority(snapshotAuthority(await readIndependentAuthority()),
      statement, shareSignature, statementBytes);
    // Only the owner CEK opener can attest which owner approval and witness
    // it ACTUALLY verified after the preceding asynchronous share redemption.
    const verifiedReleaseExpiresAt = opened.verifiedReleaseExpiresAt;
    if (!Number.isSafeInteger(verifiedReleaseExpiresAt)
      || verifiedReleaseExpiresAt < 1) deny();
    const releaseSeconds = nativeReleaseFloor(nativeReleaseNow() / 1000);
    if (releaseSeconds >= statement.expires_at || nowSeconds >= statement.expires_at
      || releaseSeconds >= verifiedReleaseExpiresAt || nowSeconds >= verifiedReleaseExpiresAt) deny();
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

async function openPortableProtectedRecipientShareFile(input) {
  try {
    strict(input, ["offer", "redeemInput", "authority", "operatorMinimumSequence",
      "deviceHpkePrivateKey", "nowSeconds"]);
    const inputDescriptors = nativeAllDescriptors(input);
    if (!allOwnData(inputDescriptors, ["offer", "redeemInput", "authority",
      "operatorMinimumSequence", "deviceHpkePrivateKey", "nowSeconds"])) deny();
    const offer = inputDescriptors.offer.value;
    strict(offer, OFFER);
    const offerDescriptors = nativeAllDescriptors(offer);
    if (!allOwnData(offerDescriptors, OFFER)) deny();
    if (offer.schema !== "rootark-zk1-recipient-share-offer-dev/v1"
      || offer.authorizesProductionIo !== false
      || offer.externalCustodyProven !== false) deny();
    const grant = snapshot(offer.grant, GRANT);
    const redeemInput = inputDescriptors.redeemInput.value;
    if (!redeemInput || typeof redeemInput !== "object") deny();
    const redeemDescriptors = nativeAllDescriptors(redeemInput);
    if (!allOwnData(redeemDescriptors, ["grant", "recipientUsername", "recipientDeviceId"])) deny();
    const expectedGrant = snapshot(redeemDescriptors.grant.value, GRANT);
    const recipientUsername = redeemDescriptors.recipientUsername.value;
    const recipientDeviceId = redeemDescriptors.recipientDeviceId.value;
    if (typeof recipientUsername !== "string" || typeof recipientDeviceId !== "string") deny();
    let grantMatches = true;
    for (let index = 0; index < GRANT.length; index++) {
      const field = GRANT[index];
      if (grant[field] !== expectedGrant[field]) grantMatches = false;
    }
    if (!grantMatches || offer.recipientUsername !== recipientUsername
      || offer.recipientDeviceId !== recipientDeviceId) deny();
    return await openProtectedRecipientShareFile({
      redeemInput: input.redeemInput, envelope: offer.envelope,
      authority: input.authority,
      operatorMinimumSequence: input.operatorMinimumSequence,
      metadata: offer.metadata, deviceHpkePrivateKey: input.deviceHpkePrivateKey,
      nowSeconds: input.nowSeconds,
    });
  } catch (_) { deny(); }
}
module.exports = { openProtectedRecipientShareFile,
  createProtectedRecipientShareOffer, openPortableProtectedRecipientShareFile };
