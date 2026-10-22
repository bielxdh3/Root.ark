"use strict";

// Both the owner and the active device sign a fresh, per-read challenge.
// An old signed grant is NOT online revocation evidence. The owner-state
// authority must be externally managed; this code never has its signing key.
const crypto = require("node:crypto");
const GRANT_DOMAIN = Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0");
const STATUS_DOMAIN = Buffer.from("Root.ark/zk-1/current-device-restore-state/v1\0");
const POP_DOMAIN = Buffer.from("Root.ark/zk-1/current-device-restore-pop/v1\0");
const GRANT_FIELDS = Object.freeze(["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "authorization_public_key", "manifest_revision",
  "manifest_digest", "current_epoch", "enrolled_epoch", "revoked_at_epoch"]);
const STATE_FIELDS = Object.freeze(["schema", "account_id", "compartment_id", "keyring_id",
  "device_id", "authorization_key_id", "operation_id", "manifest_revision",
  "manifest_digest", "current_epoch", "state", "nonce", "issued_at", "expires_at"]);
function deny() { throw new Error("ZK_FRESH_RESTORE_DEVICE_UNVERIFIED"); }
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((field) => !Object.hasOwn(value, field))) deny();
  return Object.fromEntries(fields.map((name) => {
    const d = Object.getOwnPropertyDescriptor(value, name);
    if (!d || !Object.hasOwn(d, "value")) deny();
    return [name, d.value];
  }));
}
function b64(value, size, max = size) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < size || bytes.length > max || bytes.toString("base64url") !== value) deny();
  return bytes;
}
function number(value, minimum = 1) {
  if (!Number.isSafeInteger(value) || value < minimum) deny();
  return value;
}
function signingBytes(domain, fields, body) {
  const canonical = exact(body, fields);
  const serialized = Buffer.from(JSON.stringify(canonical), "utf8");
  if (serialized.length > 2048) deny();
  return Buffer.concat([domain, serialized]);
}
function textId(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 64
    || /[\u0000-\u001f\u007f]/.test(value)) deny();
  return value;
}
function scopeFields(scope) {
  const v = exact(scope, ["account_id", "compartment_id", "keyring_id"]);
  return Object.fromEntries(Object.entries(v).map(([key, value]) =>
    [key, (Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value)
      : b64(value, key === "compartment_id" ? 1 : 16,
        key === "compartment_id" ? 128 : 16)).toString("base64url")]));
}
function pinnedKey(value) {
  if (!value || value.type !== "public" || value.algorithm?.name !== "Ed25519"
    || !value.usages?.includes("verify")) deny();
  return value;
}
async function verifyFreshOwnerDeviceRestoreAuthority({
  signedDeviceGrant, pinnedOwnerPublicKey, fetchSignedCurrentDeviceState,
  scope, operation, ownerHead, nowSeconds = Math.floor(Date.now() / 1000),
} = {}) {
  try {
    const owner = pinnedKey(pinnedOwnerPublicKey);
    if (typeof fetchSignedCurrentDeviceState !== "function") deny();
    const trustedScope = scopeFields(scope);
    const grant = exact(signedDeviceGrant, [...GRANT_FIELDS, "signature"]);
    if (grant.schema !== "rootark-zk1-browser-owner-device-grant/v1"
      || !Object.keys(trustedScope).every((name) => grant[name] === trustedScope[name])
      || grant.manifest_revision !== number(ownerHead.revision)
      || grant.manifest_digest !== Buffer.from(ownerHead.digest).toString("base64url")
      || grant.current_epoch !== number(ownerHead.epoch)
      || number(grant.enrolled_epoch) > grant.current_epoch
      || grant.revoked_at_epoch !== null) deny();
    textId(grant.device_id);
    const deviceId = b64(grant.authorization_key_id, 16).toString("base64url");
    const keyRaw = b64(grant.authorization_public_key, 32);
    if (!await crypto.webcrypto.subtle.verify("Ed25519", owner,
      b64(grant.signature, 64), signingBytes(GRANT_DOMAIN, GRANT_FIELDS,
        Object.fromEntries(GRANT_FIELDS.map((field) => [field, grant[field]]))))) deny();
    const devicePublic = await crypto.webcrypto.subtle.importKey("raw", keyRaw,
      "Ed25519", false, ["verify"]);
    const nonce = crypto.randomBytes(32).toString("base64url");
    const opId = Buffer.from(operation.operation_id).toString("base64url");
    const challenge = Object.freeze({ scope: { ...trustedScope },
      deviceId: grant.device_id, authorizationKeyId: deviceId,
      operationId: opId, nonce, manifestRevision: ownerHead.revision,
      manifestDigest: Buffer.from(ownerHead.digest).toString("base64url"),
      currentEpoch: ownerHead.epoch });
    const answer = exact(await fetchSignedCurrentDeviceState(challenge),
      ["state", "deviceProofOfPossession"]);
    const state = exact(answer.state, [...STATE_FIELDS, "signature"]);
    if (state.schema !== "rootark-zk1-current-device-restore-state/v1"
      || !Object.keys(trustedScope).every((field) => state[field] === trustedScope[field])
      || state.device_id !== grant.device_id
      || state.authorization_key_id !== deviceId
      || state.operation_id !== opId
      || state.manifest_revision !== ownerHead.revision
      || state.manifest_digest !== challenge.manifestDigest
      || state.current_epoch !== ownerHead.epoch
      || state.state !== "ACTIVE" || state.nonce !== nonce) deny();
    const issued = number(state.issued_at);
    const expires = number(state.expires_at, issued + 1);
    const now = number(nowSeconds);
    if (issued > now + 2 || expires < now || expires - issued > 15) deny();
    const bytes = signingBytes(STATUS_DOMAIN, STATE_FIELDS,
      Object.fromEntries(STATE_FIELDS.map((field) => [field, state[field]])));
    if (!await crypto.webcrypto.subtle.verify("Ed25519", owner, b64(state.signature, 64), bytes)) deny();
    const pop = Buffer.concat([POP_DOMAIN, Buffer.from(nonce, "base64url"),
      Buffer.from(opId, "base64url"), Buffer.from(grant.signature, "base64url")]);
    if (!await crypto.webcrypto.subtle.verify("Ed25519", devicePublic,
      b64(answer.deviceProofOfPossession, 64), pop)) deny();
    return Object.freeze({ signedOwnerStateVerified: true,
      currentDevicePossessionVerified: true, nonceBoundCurrentRevocationChecked: true,
      externalOwnerAuthorityCustodyProven: false, authorizesIo: false,
      deviceId: grant.device_id, authorizationKeyId: deviceId });
  } catch (_) { deny(); }
}
module.exports = { GRANT_FIELDS, STATE_FIELDS, GRANT_DOMAIN, STATUS_DOMAIN, POP_DOMAIN,
  verifyFreshOwnerDeviceRestoreAuthority };
