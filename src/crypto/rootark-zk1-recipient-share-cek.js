"use strict";

// DEV-OFF recipient-side bridge. Requires separately provisioned owner/V2
// custody and a real owner-approved, recipient-specific HPKE file CEK.
const crypto = require("node:crypto");
const { isProxy: nativeIsProxy, isSharedArrayBuffer: nativeIsSharedArrayBuffer,
  isUint8Array: nativeIsUint8Array } = require("node:util").types;
const nativeNumberIsFinite = Number.isFinite;
const nativeNumberIsSafeInteger = Number.isSafeInteger;
const nativeMathFloor = Math.floor;
const nativeMathAbs = Math.abs;
const nativeMathCeil = Math.ceil;
const nativeMathMax = Math.max;
const nativeReleaseNow = Date.now;
const z = require("./rootark-zk-1");
// The independent-authority callback is caller-controlled and may run after
// several awaits. Capture the reflection, Buffer and crypto intrinsics used
// by the post-callback validation before that callback can poison globals.
const nativeApply = Reflect.apply;
const nativeObjectPrototype = Object.prototype;
const nativeGetPrototypeOf = Object.getPrototypeOf;
const nativeGetOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
const nativeGetOwnPropertyDescriptors = Object.getOwnPropertyDescriptors;
const nativeHasOwn = Object.hasOwn;
const nativeCreate = Object.create;
const nativeFreeze = Object.freeze;
const nativeAssign = Object.assign;
const nativeOwnKeys = Reflect.ownKeys;
const nativeArrayIsArray = Array.isArray;
const NativeUint8Array = Uint8Array;
const nativeTypedArrayPrototype = nativeGetPrototypeOf(Uint8Array.prototype);
const nativeTypedLength = nativeGetOwnPropertyDescriptor(nativeTypedArrayPrototype, "length").get;
const nativeTypedByteLength = nativeGetOwnPropertyDescriptor(nativeTypedArrayPrototype, "byteLength").get;
const nativeTypedByteOffset = nativeGetOwnPropertyDescriptor(nativeTypedArrayPrototype, "byteOffset").get;
const nativeTypedBuffer = nativeGetOwnPropertyDescriptor(nativeTypedArrayPrototype, "buffer").get;
const nativeTypedSet = Uint8Array.prototype.set;
const nativeBufferFrom = Buffer.from.bind(Buffer);
const nativeTypedFill = Uint8Array.prototype.fill;
const nativeBufferConcat = Buffer.concat.bind(Buffer);
const nativeBufferToString = Buffer.prototype.toString;
const nativeTimingSafeEqual = crypto.timingSafeEqual.bind(crypto);
const nativeCreateHash = crypto.createHash.bind(crypto);
const nativeCreatePublicKey = crypto.createPublicKey.bind(crypto);
const nativeVerify = crypto.verify.bind(crypto);
const nativeDecodeDeterministic = z.decodeDeterministic;
const nativeEncodeDeterministic = z.encodeDeterministic;
const nativeHashPrototype = nativeGetPrototypeOf(nativeCreateHash("sha256"));
const nativeHashUpdate = nativeHashPrototype.update;
const nativeHashDigest = nativeHashPrototype.digest;
function nativeSha256(value) {
  const hash = nativeCreateHash("sha256");
  nativeApply(nativeHashUpdate, hash, [value]);
  return nativeApply(nativeHashDigest, hash, []);
}
function nativeBase64Url(value) {
  return nativeApply(nativeBufferToString, nativeBufferFrom(value), ["base64url"]);
}
const { redeemProtectedCiphertextShare } =
  require("../../public/client/rootark-zk1-recipient-share");
const { openOwnerAuthorizedFileCek, sealOwnerAuthorizedFileCek,
  reserveOwnerHpkeWorker, discardOwnerHpkeWorker } =
  require("./rootark-zk1-owner-authorized-file-cek-transfer");
const fileContent = require("../../public/client/rootark-zk1-file-content");
const roots = require("../../public/client/rootark-zk1-ciphertext-chunk-root");

const SHARE_DOMAIN = nativeBufferFrom("Root.ark/zk-1/protected-ciphertext-share/v1\0");
const ED25519_SPKI = nativeBufferFrom("302a300506032b6570032100", "hex");
const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const METADATA = [...SCOPE, "object_id", "version_id", "parent_version_id", "epoch", "kind"];
const ENVELOPE = ["schema", "core", "enc", "ciphertext", "owner_signature",
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
function isProxy(value) { return value !== null && (typeof value === "object" || typeof value === "function")
  && nativeIsProxy(value); }
function copyNativeBytes(value, minLength, maxLength, reject = deny) {
  if (isProxy(value) || !nativeIsUint8Array(value)) reject();
  const length = nativeApply(nativeTypedLength, value, []);
  const byteLength = nativeApply(nativeTypedByteLength, value, []);
  const offset = nativeApply(nativeTypedByteOffset, value, []);
  const backing = nativeApply(nativeTypedBuffer, value, []);
  if (!nativeNumberIsSafeInteger(length) || length < minLength || length > maxLength
    || byteLength !== length || !nativeNumberIsSafeInteger(offset)
    || offset < 0 || nativeIsSharedArrayBuffer(backing)) reject();
  const privateCopy = new NativeUint8Array(length);
  nativeApply(nativeTypedSet, privateCopy, [value]);
  return nativeBufferFrom(nativeApply(nativeTypedBuffer, privateCopy, []), 0, length);
}
const copyNativeBytes32 = (value, reject = deny) => copyNativeBytes(value, 32, 32, reject);
function wipeOwnedBytes(value) {
  if (value && !isProxy(value) && nativeIsUint8Array(value)) {
    nativeApply(nativeTypedFill, value, [0]);
  }
}
function currentSeconds(wallClock, reject = deny) {
  // A caller callback may run arbitrary code across awaits. Fail closed if
  // the global clock changes during the operation.
  if (Date.now !== wallClock) reject();
  // Keep the release clock pinned independently of per-call global changes.
  const milliseconds = nativeReleaseNow();
  if (!nativeNumberIsFinite(milliseconds) || milliseconds < 0) reject();
  return nativeMathFloor(milliseconds / 1000);
}
const BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
function b64(value) {
  const bytes = copyNativeBytes(value, 1, 128);
  const size = nativeApply(nativeTypedLength, bytes, []);
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
function from64(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)
    || value.length > nativeMathCeil(length * 4 / 3) + 4) denyOffer();
  const bytes = nativeBufferFrom(value, "base64url");
  if (bytes.length !== length
    || nativeApply(nativeBufferToString, bytes, ["base64url"]) !== value) denyOffer();
  return bytes;
}
function same(a, b) {
  return a.length === b.length && nativeTimingSafeEqual(a, b);
}
function hasOwnDataFields(descriptors, names) {
  for (let index = 0; index < names.length; index++) {
    const descriptor = descriptors[names[index]];
    if (!descriptor || !nativeHasOwn(descriptor, "value")) return false;
  }
  return true;
}
function strict(value, names) {
  if (!value || isProxy(value) || typeof value !== "object" || nativeArrayIsArray(value)) deny();
  const prototype = nativeGetPrototypeOf(value);
  if (prototype !== nativeObjectPrototype && prototype !== null) deny();
  const keys = nativeOwnKeys(value);
  if (keys.length !== names.length) deny();
  for (let index = 0; index < names.length; index++)
    if (!nativeHasOwn(value, names[index])) deny();
}
function snapshot(value, names) {
  strict(value, names);
  const descriptors = nativeGetOwnPropertyDescriptors(value);
  const copy = nativeCreate(null);
  for (let index = 0; index < names.length; index++) {
    const name = names[index];
    const descriptor = descriptors[name];
    if (!descriptor || !nativeHasOwn(descriptor, "value")) deny();
    const part = descriptor.value;
    if (part !== null && typeof part !== "string" && typeof part !== "number"
      && typeof part !== "boolean") deny();
    copy[name] = part;
  }
  return nativeFreeze(copy);
}
function ownDataDescriptors(value, required, optional = []) {
  if (!value || isProxy(value) || typeof value !== "object" || nativeArrayIsArray(value)) deny();
  const prototype = nativeGetPrototypeOf(value);
  if (prototype !== nativeObjectPrototype && prototype !== null) deny();
  const descriptors = nativeGetOwnPropertyDescriptors(value);
  const keys = nativeOwnKeys(descriptors);
  if (keys.length < required.length || keys.length > required.length + optional.length) deny();
  for (let index = 0; index < required.length; index++)
    if (!nativeHasOwn(descriptors, required[index])) deny();
  for (let index = 0; index < keys.length; index++) {
    const key = keys[index];
    if (typeof key !== "string") deny();
    let allowed = false;
    for (let i = 0; i < required.length; i++) if (required[i] === key) allowed = true;
    for (let i = 0; i < optional.length; i++) if (optional[i] === key) allowed = true;
    if (!allowed || !nativeHasOwn(descriptors[key], "value")) deny();
  }
  return descriptors;
}
const REDEEM_INPUT_REQUIRED = ["origin", "grant", "recipientUsername",
  "recipientDeviceId", "signerKey", "readIndependentAuthority"];
const REDEEM_INPUT_OPTIONAL = ["fetchImpl", "nowSeconds"];
function snapshotRedeemInput(value) {
  const d = ownDataDescriptors(value, REDEEM_INPUT_REQUIRED, REDEEM_INPUT_OPTIONAL);
  const grant = snapshot(d.grant.value, GRANT);
  const origin = d.origin.value;
  const recipientUsername = d.recipientUsername.value;
  const recipientDeviceId = d.recipientDeviceId.value;
  const signerKey = d.signerKey.value;
  const readIndependentAuthority = d.readIndependentAuthority.value;
  if (typeof origin !== "string" || typeof recipientUsername !== "string"
    || typeof recipientDeviceId !== "string" || !signerKey
    || typeof signerKey !== "object" || isProxy(signerKey)
    || typeof readIndependentAuthority !== "function" || isProxy(readIndependentAuthority)) deny();
  const copy = nativeCreate(null);
  copy.origin = origin;
  copy.grant = grant;
  copy.recipientUsername = recipientUsername;
  copy.recipientDeviceId = recipientDeviceId;
  copy.signerKey = signerKey;
  copy.readIndependentAuthority = readIndependentAuthority;
  if (nativeHasOwn(d, "fetchImpl")) {
    if (typeof d.fetchImpl.value !== "function" || isProxy(d.fetchImpl.value)) deny();
    copy.fetchImpl = d.fetchImpl.value;
  }
  if (nativeHasOwn(d, "nowSeconds")) {
    if (typeof d.nowSeconds.value !== "function" || isProxy(d.nowSeconds.value)) deny();
    copy.nowSeconds = d.nowSeconds.value;
  }
  return nativeFreeze(copy);
}
// Recipient contact pins come from the owner's separately authenticated
// contact/device enrollment. Neither the server response nor its grant may
// populate them. Reject accessors before any crypto or network await.
function snapshotAuthority(value) {
  strict(value, ["scope", "head", "devices"]);
  const fields = nativeGetOwnPropertyDescriptors(value);
  if (!hasOwnDataFields(fields, ["scope", "head", "devices"])) denyOffer();
  const scope = snapshot(fields.scope.value, SCOPE);
  const headValue = fields.head.value;
  strict(headValue, ["revision", "epoch", "digest"]);
  const h = nativeGetOwnPropertyDescriptors(headValue);
  if (!hasOwnDataFields(h, ["revision", "epoch", "digest"])) denyOffer();
  if (!nativeNumberIsSafeInteger(h.revision.value) || h.revision.value < 0
    || !nativeNumberIsSafeInteger(h.epoch.value) || h.epoch.value < 0) denyOffer();
  const head = { revision: h.revision.value, epoch: h.epoch.value,
    digest: copyNativeBytes32(h.digest.value, denyOffer) };
  const sourceDevices = fields.devices.value;
  if (isProxy(sourceDevices) || !nativeArrayIsArray(sourceDevices) || sourceDevices.length > 128) denyOffer();
  // Do not dispatch a caller-supplied array's map/filter methods. A hostile
  // realm or a custom own method could conceal a revoked/duplicate signer.
  const slots = nativeGetOwnPropertyDescriptors(sourceDevices);
  const count = slots.length?.value;
  if (!nativeNumberIsSafeInteger(count) || count < 0 || count > 128
    || nativeOwnKeys(slots).length !== count + 1) denyOffer();
  const devices = [];
  for (let index = 0; index < count; index++) {
    const entry = slots[index];
    if (!entry || !nativeHasOwn(entry, "value")) denyOffer();
    const device = entry.value;
    strict(device, ["deviceId", "authorizationPublicKey",
      "enrolledEpoch", "revokedAtEpoch"]);
    const d = nativeGetOwnPropertyDescriptors(device);
    if (!hasOwnDataFields(d, ["deviceId", "authorizationPublicKey",
      "enrolledEpoch", "revokedAtEpoch"])
      || !nativeNumberIsSafeInteger(d.enrolledEpoch.value)
      || d.enrolledEpoch.value < 0
      || !(d.revokedAtEpoch.value === null
        || (nativeNumberIsSafeInteger(d.revokedAtEpoch.value)
          && d.revokedAtEpoch.value >= d.enrolledEpoch.value))) denyOffer();
    devices[index] = { deviceId: d.deviceId.value,
      authorizationPublicKey: copyNativeBytes32(d.authorizationPublicKey.value, denyOffer),
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
  let issuer = null, recipient = null;
  for (let index = 0; index < current.devices.length; index++) {
    const device = current.devices[index];
    if (device.deviceId === issuerPin.deviceId) {
      if (issuer) denyOffer();
      issuer = device;
    }
    if (device.deviceId === pin.deviceId) {
      if (recipient) denyOffer();
      recipient = device;
    }
  }
  if (!issuer
    || !same(issuer.authorizationPublicKey,
      from64(issuerPin.authorizationPublicKey, 32))) denyOffer();
  if (!recipient
    || !same(recipient.authorizationPublicKey,
      from64(pin.authorizationPublicKey, 32))) denyOffer();
  return current;
}
// Owner-side DEV-OFF portable offer. The owner MUST independently pin the
// authorized issuer's device ID and Ed25519 key; a candidate server ACK has no
// independently verifiable issuance proof and MUST NOT be a source of trust.
// The owner also pins recipient keys outside the untrusted grant/ACK.
async function createProtectedRecipientShareOffer(input) {
  const wallClock = Date.now;
  let ownerCek, ciphertext, reservedWorker;
  try {
    strict(input, ["grant", "recipientPin", "issuerPin", "readIndependentAuthority",
      "ownerPrivateKey", "ownerHeldCek", "metadata", "objectRevision",
      "ciphertext", "ciphertextRoot", "authority", "nowSeconds"]);
    const d = nativeGetOwnPropertyDescriptors(input);
    if (!hasOwnDataFields(d, ["grant", "recipientPin", "issuerPin",
      "readIndependentAuthority", "ownerPrivateKey", "ownerHeldCek",
      "metadata", "objectRevision", "ciphertext", "ciphertextRoot",
      "authority", "nowSeconds"])) denyOffer();
    const grant = snapshot(d.grant.value, GRANT);
    const pin = snapshot(d.recipientPin.value, RECIPIENT_PIN);
    const issuerPin = snapshot(d.issuerPin.value, ISSUER_PIN);
    const metadata = snapshot(d.metadata.value, METADATA);
    if (typeof d.readIndependentAuthority.value !== "function"
      || isProxy(d.readIndependentAuthority.value)
      || typeof pin.recipientUsername !== "string"
      || !/^[A-Za-z0-9_.@-]{1,128}$/.test(pin.recipientUsername)
      || typeof pin.deviceId !== "string" || !pin.deviceId
      || pin.deviceId.length > 64
      || /[\x00-\x1f\x7f]/.test(pin.deviceId)
      || typeof issuerPin.deviceId !== "string"
      || !issuerPin.deviceId || issuerPin.deviceId.length > 64
      || /[\x00-\x1f\x7f]/.test(issuerPin.deviceId)
      || issuerPin.deviceId === pin.deviceId
      || !nativeNumberIsSafeInteger(d.nowSeconds.value)
      || nativeMathAbs(currentSeconds(wallClock, denyOffer) - d.nowSeconds.value) > 30
      || !nativeNumberIsSafeInteger(d.objectRevision.value)
      || d.objectRevision.value < 1
      || isProxy(d.ownerHeldCek.value) || !(d.ownerHeldCek.value instanceof Uint8Array)
      || d.ownerHeldCek.value.length !== 32
      || isProxy(d.ciphertext.value) || !(d.ciphertext.value instanceof Uint8Array)
      || d.ciphertext.value.length < 16
      || d.ciphertext.value.length > 4 * 1024 * 1024
      || isProxy(d.ciphertextRoot.value) || !(d.ciphertextRoot.value instanceof Uint8Array)
      || d.ciphertextRoot.value.length !== 32) denyOffer();
    from64(pin.authorizationPublicKey, 32);
    from64(pin.hpkePublicKey, 32);
    from64(issuerPin.authorizationPublicKey, 32);
    if (same(from64(issuerPin.authorizationPublicKey, 32),
      from64(pin.authorizationPublicKey, 32))) denyOffer();
    from64(grant.grantId, 32);
    from64(metadata.object_id, 16);
    ownerCek = nativeBufferFrom(d.ownerHeldCek.value);
    ciphertext = nativeBufferFrom(d.ciphertext.value);
    const ciphertextRoot = nativeBufferFrom(d.ciphertextRoot.value);
    if (typeof grant.shareStatementBase64 !== "string"
      || grant.shareStatementBase64.length > 5470) denyOffer();
    const statementBytes = from64(grant.shareStatementBase64,
      nativeBufferFrom(grant.shareStatementBase64, "base64url").length);
    if (statementBytes.length < 1 || statementBytes.length > 4096) denyOffer();
    // Prepare the trusted LOAD_SCRIPT bootstrap before the FIRST await.
    // Even a CBOR promise continuation must not precede Worker construction.
    reservedWorker = reserveOwnerHpkeWorker();
    const statement = await nativeDecodeDeterministic(statementBytes);
    strict(statement, SHARE);
    if (!same(nativeBufferFrom(await nativeEncodeDeterministic(statement)), statementBytes)
      || statement.type !== "rootark-zk1-protected-ciphertext-share/v1"
      || !same(nativeBufferFrom(statement.grant_id || []), from64(grant.grantId, 32))
      || statement.expires_at !== grant.expiresAt
      || !nativeNumberIsSafeInteger(statement.issued_at) || statement.issued_at < 1
      || statement.issued_at > d.nowSeconds.value + 30
      || !nativeNumberIsSafeInteger(statement.expires_at)
      || statement.expires_at <= nativeMathMax(d.nowSeconds.value, statement.issued_at)
      || statement.expires_at - statement.issued_at > 86400
      || statement.recipient_username !== pin.recipientUsername
      || statement.recipient_device_id !== pin.deviceId
      || statement.issuer_device_id !== issuerPin.deviceId
      || statement.object_id !== metadata.object_id
      || statement.object_revision !== d.objectRevision.value
      || statement.epoch !== metadata.epoch
      || !same(nativeBufferFrom(statement.ciphertext_digest || []), nativeSha256(ciphertext))) denyOffer();
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
    }, reservedWorker);
    reservedWorker = null;
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
    const releaseSeconds = currentSeconds(wallClock, denyOffer);
    if (!nativeNumberIsSafeInteger(envelope.core.expires_at)
      || releaseSeconds >= envelope.core.expires_at
      || releaseSeconds >= statement.expires_at) denyOffer();
    return nativeFreeze({
      schema: "rootark-zk1-recipient-share-offer-dev/v1",
      grant: nativeFreeze({ ...grant }),
      recipientUsername: pin.recipientUsername, recipientDeviceId: pin.deviceId,
      metadata: nativeFreeze({ ...metadata }), envelope,
      authorizesProductionIo: false, externalCustodyProven: false,
    });
  } catch (_) { denyOffer(); }
  finally {
    if (reservedWorker) await discardOwnerHpkeWorker(reservedWorker);
    wipeOwnedBytes(ownerCek);
    wipeOwnedBytes(ciphertext);
  }
}
function safeEnvelope(value) {
  strict(value, ENVELOPE);
  const d = nativeGetOwnPropertyDescriptors(value);
  if (!hasOwnDataFields(d, ENVELOPE)) deny();
  if (isProxy(d.core.value)) deny();
  const keys = nativeOwnKeys(d.core.value);
  if (keys.length > 40) deny();
  for (let index = 0; index < keys.length; index++)
    if (typeof keys[index] !== "string") deny();
  const core = snapshot(d.core.value, keys);
  const other = snapshot({ schema: d.schema.value, enc: d.enc.value,
    ciphertext: d.ciphertext.value, owner_signature: d.owner_signature.value,
    authorizesProductionRestore: d.authorizesProductionRestore.value,
    externalCustodyProven: d.externalCustodyProven.value },
  ["schema", "enc", "ciphertext", "owner_signature",
    "authorizesProductionRestore", "externalCustodyProven"]);
  return nativeFreeze({ ...other, core });
}
function currentAuthority(snapshotValue, statement, shareSignature, statementBytes) {
  // The final post-AEAD read must get the same descriptor-only custody check
  // as the earlier read. Getter and array-method reentry cannot rewrite the
  // authority we compare to the signed grant.
  const current = snapshotAuthority(snapshotValue);
  if (current.head.revision !== statement.manifest_revision
    || current.head.epoch !== statement.epoch
    || !same(current.head.digest, statement.manifest_digest)) deny();
  for (let index = 0; index < SCOPE.length; index++) {
    const field = SCOPE[index];
    if (current.scope[field] !== b64(statement[field])) deny();
  }
  const active = (deviceId) => {
    let device = null;
    for (let index = 0; index < current.devices.length; index++) {
      const candidate = current.devices[index];
      if (candidate.deviceId === deviceId) {
        if (device) deny();
        device = candidate;
      }
    }
    if (!device) deny();
    if (device.revokedAtEpoch !== null || !nativeNumberIsSafeInteger(device.enrolledEpoch)
      || device.enrolledEpoch < 1 || device.enrolledEpoch > statement.epoch) deny();
    return device.authorizationPublicKey;
  };
  active(statement.recipient_device_id);
  const issuer = active(statement.issuer_device_id);
  if (!nativeVerify(null, nativeBufferConcat([SHARE_DOMAIN, statementBytes]),
    nativeCreatePublicKey({ key: nativeBufferConcat([ED25519_SPKI, issuer]),
      format: "der", type: "spki" }), shareSignature)) deny();
}
async function openProtectedRecipientShareFile(input) {
  const wallClock = Date.now;
  let opened;
  let plaintext;
  try {
    const d = ownDataDescriptors(input, ["redeemInput", "envelope", "authority",
      "operatorMinimumSequence", "metadata", "deviceHpkePrivateKey", "nowSeconds"]);
    const redeemInput = snapshotRedeemInput(d.redeemInput.value);
    const metadata = snapshot(d.metadata.value, METADATA);
    const envelope = safeEnvelope(d.envelope.value);
    const authority = d.authority.value;
    const operatorMinimumSequence = d.operatorMinimumSequence.value;
    const deviceHpkePrivateKey = d.deviceHpkePrivateKey.value;
    const nowSeconds = d.nowSeconds.value;
    if (typeof redeemInput.readIndependentAuthority !== "function"
      || !nativeNumberIsSafeInteger(nowSeconds) || nowSeconds < 1) deny();
    const receipt = await redeemProtectedCiphertextShare(redeemInput);
    if (receipt.ownerGrantSignatureVerified !== true
      || receipt.serverRevocationProofVerified !== false
      || receipt.authorizesPlaintextRelease !== false) deny();
    const ciphertext = nativeBufferFrom(receipt.ciphertextBase64, "base64url");
    const statementBytes = nativeBufferFrom(receipt.shareStatementBase64, "base64url");
    const statement = await nativeDecodeDeterministic(statementBytes);
    const shareSignature = nativeBufferFrom(receipt.shareSignatureBase64, "base64url");
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
    currentAuthority(await redeemInput.readIndependentAuthority(),
      statement, shareSignature, statementBytes);
    // The owner approval, witness receipt and HPKE envelope are independent
    // authorization leases. Their verified minimum must still be live after
    // the final authority await, as must the recipient-specific share grant.
    const verifiedReleaseExpiresAt = opened.verifiedReleaseExpiresAt;
    if (!nativeNumberIsSafeInteger(verifiedReleaseExpiresAt)
      || verifiedReleaseExpiresAt < 1) deny();
    const releaseSeconds = currentSeconds(wallClock);
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
  finally { wipeOwnedBytes(opened?.cek); wipeOwnedBytes(plaintext?.data); }
}

async function openPortableProtectedRecipientShareFile(input) {
  try {
    const inputDescriptors = ownDataDescriptors(input, ["offer", "redeemInput",
      "authority", "operatorMinimumSequence", "deviceHpkePrivateKey", "nowSeconds"]);
    const offer = inputDescriptors.offer.value;
    const offerDescriptors = ownDataDescriptors(offer, OFFER);
    const offerSnapshot = nativeFreeze(nativeAssign(nativeCreate(null), {
      schema: offerDescriptors.schema.value,
      grant: snapshot(offerDescriptors.grant.value, GRANT),
      recipientUsername: offerDescriptors.recipientUsername.value,
      recipientDeviceId: offerDescriptors.recipientDeviceId.value,
      metadata: snapshot(offerDescriptors.metadata.value, METADATA),
      envelope: safeEnvelope(offerDescriptors.envelope.value),
      authorizesProductionIo: offerDescriptors.authorizesProductionIo.value,
      externalCustodyProven: offerDescriptors.externalCustodyProven.value,
    }));
    if (offerSnapshot.schema !== "rootark-zk1-recipient-share-offer-dev/v1"
      || offerSnapshot.authorizesProductionIo !== false
      || offerSnapshot.externalCustodyProven !== false
      || typeof offerSnapshot.recipientUsername !== "string"
      || typeof offerSnapshot.recipientDeviceId !== "string") deny();
    const redeemInput = snapshotRedeemInput(inputDescriptors.redeemInput.value);
    for (let index = 0; index < GRANT.length; index++) {
      const key = GRANT[index];
      if (offerSnapshot.grant[key] !== redeemInput.grant[key]) deny();
    }
    if (offerSnapshot.recipientUsername !== redeemInput.recipientUsername
      || offerSnapshot.recipientDeviceId !== redeemInput.recipientDeviceId) deny();
    const openInput = nativeFreeze(nativeAssign(nativeCreate(null), {
      redeemInput,
      envelope: offerSnapshot.envelope,
      authority: inputDescriptors.authority.value,
      operatorMinimumSequence: inputDescriptors.operatorMinimumSequence.value,
      metadata: offerSnapshot.metadata,
      deviceHpkePrivateKey: inputDescriptors.deviceHpkePrivateKey.value,
      nowSeconds: inputDescriptors.nowSeconds.value,
    }));
    return await openProtectedRecipientShareFile(openInput);
  } catch (_) { deny(); }
}
module.exports = { openProtectedRecipientShareFile,
  createProtectedRecipientShareOffer, openPortableProtectedRecipientShareFile };
