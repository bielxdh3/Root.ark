"use strict";

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const targetAuthorization = require("./rootark-zk-recovery-authorization");

const MANIFEST_TYPE = "rootark-zk-keyring-manifest";
const MANIFEST_VERSION = 2;
const OPERATIONS = Object.freeze([
  "initialize", "enroll-device", "revoke-device", "register-package",
  "replace-package", "revoke-package", "recover-device", "compromise-package",
]);
const MANIFEST_FIELDS = Object.freeze([
  "type", "version", "suite", "account_id", "compartment_id", "keyring_id", "revision",
  "current_epoch", "epochs", "devices", "wraps", "recovery_authority", "recovery_wraps",
  "previous_manifest_digest", "operation", "mac", "actor_signature",
]);
const CORE_FIELDS = Object.freeze(MANIFEST_FIELDS.slice(0, -2));
const OPERATION_FIELDS = Object.freeze([
  "operation_id", "operation_type", "actor_type", "actor_key_id", "target_device_id",
  "target_device_key_digest", "compromised_package_id", "recovery_policy_change",
  "target_epoch_coverage", "target_pop_proof", "issued_at", "expires_at", "request_digest",
]);
const EPOCH_FIELDS = Object.freeze(["epoch", "key_ref"]);
const DEVICE_FIELDS = Object.freeze([
  "device_id", "hpke_key_id", "hpke_public_key", "authorization_key_id",
  "authorization_public_key", "enrolled_epoch", "revoked_at_epoch",
]);
const WRAP_FIELDS = Object.freeze(["device_id", "epoch", "key_ref", "wrap_id", "enc", "ciphertext"]);
const RECOVERY_WRAP_FIELDS = Object.freeze([
  "package_id", "hpke_key_id", "epoch", "key_ref", "wrap_id", "enc", "ciphertext",
]);
const RECOVERY_AUTHORITY_FIELDS = Object.freeze([
  "package_id", "hpke_key_id", "hpke_public_key", "authorization_key_id", "authorization_public_key",
  "status", "activation_revision", "previous_revision", "previous_manifest_digest", "operation_id",
  "activation_context_digest", "package_envelope_digest",
]);
const MAC_INFO_PREFIX_FIELDS = Object.freeze([
  "type", "suite", "purpose", "account_id", "compartment_id", "current_epoch", "revision",
]);
const MANIFEST_DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-manifest-digest/v1\0", "ascii");
const REQUEST_DIGEST_PREFIX = Buffer.from("Root.ark/zk-1/recovery-cas-request/v2\0", "ascii");
const SIGNATURE_PREFIX = Buffer.from("Root.ark/zk-1/recovery-manifest/v1\0", "ascii");
const KEY_REF_PREFIX = Buffer.from("Root.ark/zk-1/recovery-key-ref/v1\0", "ascii");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const MAX_EPOCHS = 64;
const MAX_DEVICES = 256;
const verifiedPublicTransitions = new WeakMap();

function fail(code = "HISTORY_INVALID") {
  throw new z.RootarkZkError(code);
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function plainMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail();
  if (Reflect.ownKeys(value).some((key) => typeof key !== "string"
    || key === "__proto__" || key === "constructor" || key === "prototype")) fail();
  return value;
}

function exactMap(value, fields) {
  plainMap(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some((key) => typeof key !== "string" || !fields.includes(key))
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  return value;
}

function checkBytes(value, length, min, max) {
  if (!isBytes(value)) fail();
  if (length !== undefined && value.byteLength !== length) fail();
  if (min !== undefined && value.byteLength < min) fail();
  if (max !== undefined && value.byteLength > max) fail();
  return Buffer.from(value);
}

function u64(value, min = 0n, max = 0xffffffffffffffffn) {
  let result;
  if (typeof value === "bigint") result = value;
  else if (Number.isSafeInteger(value)) result = BigInt(value);
  else fail();
  if (result < min || result > max) fail();
  return result;
}

function sameBytes(a, b) {
  return isBytes(a) && isBytes(b) && a.byteLength === b.byteLength
    && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function asNumber(value) {
  const n = u64(value);
  if (n > BigInt(Number.MAX_SAFE_INTEGER)) fail();
  return Number(n);
}

function idHex(value) {
  return Buffer.from(value).toString("hex");
}

function idKey(kind, value) {
  return `${kind}:${idHex(value)}`;
}

function deviceIdKey(value) {
  return `device-name:${value}`;
}

function recoveryError(code) {
  return new z.RootarkZkError(code);
}

function assertRecoveryActorOperation(actorType, operationType) {
  if (!OPERATIONS.includes(operationType)) fail("UNKNOWN_RECOVERY_OPERATION");
  const allowed = actorType === "device"
    ? operationType !== "revoke-package"
    : actorType === "recovery-package" && operationType === "recover-device";
  if (!allowed) fail("UNAUTHORIZED_ACTOR");
  return true;
}

function verifyRecoveryAdmissionWindowV2(input) {
  if (!input || typeof input !== "object" || input.clockHealthy !== true) fail("AUTHORIZATION_EXPIRED");
  let issuedAt;
  let expiresAt;
  let now;
  try {
    issuedAt = asNumber(input.issuedAt);
    expiresAt = asNumber(input.expiresAt);
    now = asNumber(input.now);
  } catch (_) {
    fail("AUTHORIZATION_EXPIRED");
  }
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 300 || now < issuedAt - 30 || now > expiresAt) {
    fail("AUTHORIZATION_EXPIRED");
  }
  return true;
}

function digest(prefix, bytes) {
  return crypto.createHash("sha256").update(prefix).update(bytes).digest();
}

async function recoveryManifestDigestV2(manifest) {
  return digest(MANIFEST_DIGEST_PREFIX, await z.encodeDeterministic(manifest));
}

async function recoveryRequestDigestV2(requestCore) {
  return digest(REQUEST_DIGEST_PREFIX, await z.encodeDeterministic(requestCore));
}

async function buildRecoveryRequestCoreV2(previousManifest, proposedCore) {
  exactMap(proposedCore, CORE_FIELDS);
  const { request_digest: _requestDigest, ...operation } = exactMap(proposedCore.operation, OPERATION_FIELDS);
  const proposedOperation = { ...operation };
  const proposedManifestCore = { ...proposedCore, operation: proposedOperation };
  const expectedRevision = previousManifest ? previousManifest.revision : null;
  const expectedDigest = previousManifest ? await recoveryManifestDigestV2(previousManifest) : null;
  const packageEnvelopeDigest = proposedCore.recovery_authority?.status === "active"
    ? proposedCore.recovery_authority.package_envelope_digest : null;
  return {
    expected_revision: expectedRevision,
    expected_manifest_digest: expectedDigest,
    operation_id: operation.operation_id,
    operation_type: operation.operation_type,
    actor_type: operation.actor_type,
    actor_key_id: operation.actor_key_id,
    target_device_id: operation.target_device_id,
    target_device_key_digest: operation.target_device_key_digest,
    compromised_package_id: operation.compromised_package_id,
    recovery_policy_change: operation.recovery_policy_change,
    issued_at: operation.issued_at,
    expires_at: operation.expires_at,
    target_pop_proof: operation.target_pop_proof,
    proposed_manifest_core: proposedManifestCore,
    package_envelope_digest: packageEnvelopeDigest,
  };
}

async function expectedRecoveryRequestDigestV2(previousManifest, proposedCore) {
  return recoveryRequestDigestV2(await buildRecoveryRequestCoreV2(previousManifest, proposedCore));
}

async function recoveryKeyRefV2(scope, epoch) {
  const context = {
    suite: "rootark-zk-1",
    account_id: checkBytes(scope.account_id, 16),
    compartment_id: checkBytes(scope.compartment_id, undefined, 1, 128),
    epoch: asNumber(epoch),
  };
  return digest(KEY_REF_PREFIX, await z.encodeDeterministic(context));
}

function rawEd25519PublicKey(keyBytes) {
  checkBytes(keyBytes, 32);
  try {
    return crypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(keyBytes)]),
      format: "der",
      type: "spki",
    });
  } catch (_) {
    fail();
  }
}

function normalizeIdentifierInventory(inventory) {
  if (!inventory || inventory.complete !== true || !(inventory.values instanceof Set)) fail("HISTORY_INVALID");
  return new Set(inventory.values);
}

function manifestIdentifiers(manifest) {
  const result = new Set();
  if (!manifest) return result;
  const operation = manifest.operation;
  if (operation?.operation_id) result.add(idKey("operation", operation.operation_id));
  for (const device of manifest.devices || []) {
    result.add(deviceIdKey(device.device_id));
    result.add(idKey("key", device.hpke_key_id));
    result.add(idKey("key", device.authorization_key_id));
    result.add(idKey("x25519-public", device.hpke_public_key));
    result.add(idKey("ed25519-public", device.authorization_public_key));
  }
  const authority = manifest.recovery_authority;
  if (authority) {
    result.add(idKey("package", authority.package_id));
    result.add(idKey("key", authority.hpke_key_id));
    result.add(idKey("key", authority.authorization_key_id));
    result.add(idKey("x25519-public", authority.hpke_public_key));
    result.add(idKey("ed25519-public", authority.authorization_public_key));
  }
  for (const wrap of manifest.wraps || []) result.add(idKey("wrap", wrap.wrap_id));
  for (const wrap of manifest.recovery_wraps || []) result.add(idKey("wrap", wrap.wrap_id));
  const challengeId = operation?.target_pop_proof?.challenge_context?.challenge_id;
  if (challengeId) result.add(idKey("challenge", challengeId));
  return result;
}

function newManifestIdentifiers(previousManifest, nextManifest) {
  const previous = manifestIdentifiers(previousManifest);
  const next = manifestIdentifiers(nextManifest);
  return new Set([...next].filter((id) => !previous.has(id)));
}

function ensureIdentifierInventory(previousManifest, nextManifest, inventory) {
  const used = normalizeIdentifierInventory(inventory);
  if (nextManifest.operation?.operation_id
    && used.has(idKey("operation", nextManifest.operation.operation_id))) fail("HISTORY_INVALID");
  for (const id of manifestIdentifiers(previousManifest)) {
    if (!used.has(id)) fail("HISTORY_INVALID");
  }
  for (const id of newManifestIdentifiers(previousManifest, nextManifest)) {
    if (used.has(id)) fail("HISTORY_INVALID");
  }
  return new Set([...used, ...manifestIdentifiers(nextManifest)]);
}

function isDeviceActive(device) {
  return device && device.revoked_at_epoch === null;
}

function activeDevice(previousManifest, keyId) {
  return previousManifest.devices.find((device) => isDeviceActive(device)
    && sameBytes(device.authorization_key_id, keyId));
}

function authorityActive(authority) {
  return authority && authority.status === "active";
}

function assertOperationMap(operation) {
  exactMap(operation, OPERATION_FIELDS);
  checkBytes(operation.operation_id, 16);
  checkBytes(operation.actor_key_id, 16);
  checkBytes(operation.request_digest, 32);
  if (operation.target_device_id !== null
    && (typeof operation.target_device_id !== "string" || operation.target_device_id.length < 1 || operation.target_device_id.length > 64)) fail();
  if (operation.target_device_key_digest !== null) checkBytes(operation.target_device_key_digest, 32);
  if (operation.compromised_package_id !== null) checkBytes(operation.compromised_package_id, 16);
  if (operation.recovery_policy_change !== null && operation.recovery_policy_change !== "device-only") fail();
  if (!Array.isArray(operation.target_epoch_coverage)) fail();
  let priorEpoch = 0n;
  for (const epoch of operation.target_epoch_coverage) {
    const value = u64(epoch, 1n);
    if (value <= priorEpoch) fail();
    priorEpoch = value;
  }
  u64(operation.issued_at);
  u64(operation.expires_at);
  if (u64(operation.expires_at) <= u64(operation.issued_at)
    || u64(operation.expires_at) - u64(operation.issued_at) > 300n) fail("AUTHORIZATION_EXPIRED");
  if (!OPERATIONS.includes(operation.operation_type)) fail("UNKNOWN_RECOVERY_OPERATION");
  if (operation.actor_type !== "device" && operation.actor_type !== "recovery-package") fail();
  const proofRequired = operation.operation_type === "enroll-device" || operation.operation_type === "recover-device";
  if (proofRequired !== (operation.target_pop_proof !== null)) fail();
  if (!proofRequired && operation.target_epoch_coverage.length !== 0) fail();
  if (operation.operation_type === "compromise-package" && operation.compromised_package_id === null) fail();
  if (operation.operation_type !== "compromise-package" && operation.compromised_package_id !== null) fail();
  if (operation.operation_type === "revoke-package") {
    if (operation.recovery_policy_change !== "device-only") fail("UNAUTHORIZED_ACTOR");
    fail("UNAUTHORIZED_ACTOR");
  }
  if (operation.operation_type !== "revoke-package" && operation.recovery_policy_change !== null) fail();
  return operation;
}

function validateManifestShape(manifest) {
  exactMap(manifest, MANIFEST_FIELDS);
  if (manifest.type !== MANIFEST_TYPE || manifest.version !== MANIFEST_VERSION || manifest.suite !== "rootark-zk-1") fail();
  checkBytes(manifest.account_id, 16);
  checkBytes(manifest.compartment_id, undefined, 1, 128);
  checkBytes(manifest.keyring_id, 16);
  const revision = u64(manifest.revision, 1n);
  const currentEpoch = u64(manifest.current_epoch, 1n, BigInt(MAX_EPOCHS));
  if (!Array.isArray(manifest.epochs) || manifest.epochs.length !== Number(currentEpoch) || manifest.epochs.length > MAX_EPOCHS) fail();
  let previousEpoch = 0n;
  for (const epoch of manifest.epochs) {
    exactMap(epoch, EPOCH_FIELDS);
    const current = u64(epoch.epoch, 1n);
    if (current !== previousEpoch + 1n) fail();
    previousEpoch = current;
    checkBytes(epoch.key_ref, 32);
  }
  if (!Array.isArray(manifest.devices) || manifest.devices.length > MAX_DEVICES) fail();
  const deviceIds = new Set();
  const keyIds = new Set();
  const publicKeys = new Set();
  for (const device of manifest.devices) {
    exactMap(device, DEVICE_FIELDS);
    if (typeof device.device_id !== "string" || device.device_id.length < 1 || device.device_id.length > 64) fail();
    if (deviceIds.has(device.device_id)) fail();
    deviceIds.add(device.device_id);
    checkBytes(device.hpke_key_id, 16);
    checkBytes(device.hpke_public_key, 32);
    checkBytes(device.authorization_key_id, 16);
    checkBytes(device.authorization_public_key, 32);
    if (keyIds.has(idHex(device.hpke_key_id)) || keyIds.has(idHex(device.authorization_key_id))) fail();
    keyIds.add(idHex(device.hpke_key_id));
    keyIds.add(idHex(device.authorization_key_id));
    const hpkePublicId = idHex(device.hpke_public_key);
    const authorizationPublicId = idHex(device.authorization_public_key);
    if (publicKeys.has(`x:${hpkePublicId}`) || publicKeys.has(`e:${authorizationPublicId}`)) fail();
    publicKeys.add(`x:${hpkePublicId}`);
    publicKeys.add(`e:${authorizationPublicId}`);
    const enrolled = u64(device.enrolled_epoch, 1n, currentEpoch);
    if (device.revoked_at_epoch !== null) u64(device.revoked_at_epoch, enrolled, currentEpoch);
  }

  if (!Array.isArray(manifest.wraps) || !Array.isArray(manifest.recovery_wraps)) fail();
  const wrapIds = new Set();
  for (const wrap of manifest.wraps) {
    exactMap(wrap, WRAP_FIELDS);
    if (typeof wrap.device_id !== "string" || !deviceIds.has(wrap.device_id)) fail();
    const epoch = u64(wrap.epoch, 1n, currentEpoch);
    checkBytes(wrap.key_ref, 32);
    if (!sameBytes(wrap.key_ref, manifest.epochs[Number(epoch) - 1].key_ref)) fail("KEY_COVERAGE_INCOMPLETE");
    checkBytes(wrap.wrap_id, 16);
    checkBytes(wrap.enc, 32);
    checkBytes(wrap.ciphertext, 48);
    const id = idHex(wrap.wrap_id);
    const recipientEpoch = `${wrap.device_id}:${epoch}`;
    if (wrapIds.has(id) || wrapIds.has(recipientEpoch)) fail();
    wrapIds.add(id);
    wrapIds.add(recipientEpoch);
  }
  checkBytes(manifest.previous_manifest_digest, 32);
  assertOperationMap(manifest.operation);
  checkBytes(manifest.mac, 32);
  checkBytes(manifest.actor_signature, 64);

  let activeAuthority = false;
  if (manifest.recovery_authority === null) {
    if (manifest.recovery_wraps.length !== 0) fail();
  } else {
    const authority = exactMap(manifest.recovery_authority, RECOVERY_AUTHORITY_FIELDS);
    checkBytes(authority.package_id, 16);
    checkBytes(authority.hpke_key_id, 16);
    checkBytes(authority.hpke_public_key, 32);
    checkBytes(authority.authorization_key_id, 16);
    checkBytes(authority.authorization_public_key, 32);
    if (authority.status !== "active" && authority.status !== "revoked") fail();
    u64(authority.activation_revision, 1n, revision);
    u64(authority.previous_revision, 1n);
    checkBytes(authority.previous_manifest_digest, 32);
    checkBytes(authority.operation_id, 16);
    checkBytes(authority.activation_context_digest, 32);
    checkBytes(authority.package_envelope_digest, 32);
    if (u64(authority.previous_revision, 1n) + 1n !== u64(authority.activation_revision, 1n)) fail();
    activeAuthority = authority.status === "active";
    if (!activeAuthority && manifest.recovery_wraps.length !== 0) fail();
    if (activeAuthority && manifest.recovery_wraps.length !== manifest.epochs.length) fail("KEY_COVERAGE_INCOMPLETE");
    for (let i = 0; i < manifest.recovery_wraps.length; i += 1) {
      const wrap = exactMap(manifest.recovery_wraps[i], RECOVERY_WRAP_FIELDS);
      if (!sameBytes(wrap.package_id, authority.package_id) || !sameBytes(wrap.hpke_key_id, authority.hpke_key_id)
        || u64(wrap.epoch, 1n) !== u64(manifest.epochs[i].epoch, 1n)
        || !sameBytes(wrap.key_ref, manifest.epochs[i].key_ref)) fail("KEY_COVERAGE_INCOMPLETE");
      checkBytes(wrap.wrap_id, 16);
      checkBytes(wrap.enc, 32);
      checkBytes(wrap.ciphertext, 48);
      const id = idHex(wrap.wrap_id);
      if (wrapIds.has(id)) fail();
      wrapIds.add(id);
    }
    if (keyIds.has(idHex(authority.hpke_key_id)) || keyIds.has(idHex(authority.authorization_key_id))) fail();
    if (publicKeys.has(`x:${idHex(authority.hpke_public_key)}`)
      || publicKeys.has(`e:${idHex(authority.authorization_public_key)}`)) fail();
  }
  return { revision, currentEpoch, activeAuthority };
}

async function verifyKeyRefs(manifest) {
  for (const item of manifest.epochs) {
    const expected = await recoveryKeyRefV2(manifest, item.epoch);
    if (!sameBytes(item.key_ref, expected)) fail();
  }
}

function findActorPublicKey(previousManifest, operation, nextManifest) {
  let device;
  if (previousManifest === null) {
    if (operation.operation_type !== "initialize" || operation.actor_type !== "device") fail("UNAUTHORIZED_ACTOR");
    device = nextManifest.devices.find((entry) => sameBytes(entry.authorization_key_id, operation.actor_key_id));
  } else if (operation.actor_type === "device") {
    device = activeDevice(previousManifest, operation.actor_key_id);
  } else if (operation.actor_type === "recovery-package") {
    const authority = previousManifest.recovery_authority;
    if (authorityActive(authority) && sameBytes(authority.authorization_key_id, operation.actor_key_id)) {
      return rawEd25519PublicKey(authority.authorization_public_key);
    }
  }
  if (!device) fail("UNAUTHORIZED_ACTOR");
  return rawEd25519PublicKey(device.authorization_public_key);
}

async function assertTargetTransition(operation, previousManifest, nextManifest) {
  const nextDeviceIds = new Set(nextManifest.devices.map((device) => device.device_id));
  const previousDeviceIds = new Set(previousManifest?.devices.map((device) => device.device_id) || []);
  if (operation.operation_type === "enroll-device" || operation.operation_type === "recover-device") {
    const target = nextManifest.devices.find((device) => device.device_id === operation.target_device_id);
    if (!target || !nextDeviceIds.has(operation.target_device_id) || previousDeviceIds.has(operation.target_device_id)
      || !isDeviceActive(target) || asNumber(target.enrolled_epoch) !== asNumber(nextManifest.current_epoch)) fail();
    const expectedDigest = await targetAuthorization.recoveryTargetDeviceKeyDigest({
      deviceId: target.device_id,
      hpkeKeyId: target.hpke_key_id,
      hpkePublicKey: target.hpke_public_key,
      authorizationKeyId: target.authorization_key_id,
      authorizationPublicKey: target.authorization_public_key,
    });
    if (!sameBytes(operation.target_device_key_digest, expectedDigest)) fail();
    const proof = exactMap(operation.target_pop_proof, [
      "challenge_context", "enc", "ciphertext", "challenge", "target_signature",
    ]);
    const verified = await targetAuthorization.verifyTargetPopTranscript({
      transcript: proof,
      expectedScope: nextManifest,
      expectedDeviceKeyDigest: expectedDigest,
      targetAuthorizationPublicKey: target.authorization_public_key,
    });
    const context = verified.challengeContext;
    if (!sameBytes(context.operation_id, operation.operation_id)
      || context.target_device_id !== target.device_id
      || !sameBytes(context.target_device_key_digest, expectedDigest)) fail();
  } else if (operation.operation_type === "revoke-device") {
    if (typeof operation.target_device_id !== "string" || !previousDeviceIds.has(operation.target_device_id)
      || operation.target_device_key_digest !== null) fail();
  } else if (operation.target_device_id !== null || operation.target_device_key_digest !== null) {
    fail();
  }
}

async function sameCanonical(left, right) {
  return sameBytes(await z.encodeDeterministic(left), await z.encodeDeterministic(right));
}

async function assertDevicesUnchanged(previous, next) {
  if (previous.devices.length !== next.devices.length) fail();
  for (let index = 0; index < previous.devices.length; index += 1) {
    if (!await sameCanonical(previous.devices[index], next.devices[index])) fail();
  }
}

async function assertDeviceAddition(previous, next, targetDeviceId) {
  if (next.devices.length !== previous.devices.length + 1
    || next.devices[previous.devices.length]?.device_id !== targetDeviceId) fail();
  for (let index = 0; index < previous.devices.length; index += 1) {
    if (!await sameCanonical(previous.devices[index], next.devices[index])) fail();
  }
}

async function assertDeviceRevocation(previous, next, targetDeviceId, freshEpoch) {
  if (next.devices.length !== previous.devices.length) fail();
  let changed = 0;
  for (let index = 0; index < previous.devices.length; index += 1) {
    const before = previous.devices[index];
    const after = next.devices[index];
    if (before.device_id === targetDeviceId) {
      if (!isDeviceActive(before) || after.device_id !== before.device_id
        || u64(after.revoked_at_epoch, 1n) !== BigInt(freshEpoch)) fail();
      const expected = { ...before, revoked_at_epoch: freshEpoch };
      if (!await sameCanonical(expected, after)) fail();
      changed += 1;
    } else if (!await sameCanonical(before, after)) fail();
  }
  if (changed !== 1) fail();
}

async function assertWrapPrefix(previous, next) {
  if (next.wraps.length < previous.wraps.length) fail();
  for (let index = 0; index < previous.wraps.length; index += 1) {
    if (!await sameCanonical(previous.wraps[index], next.wraps[index])) fail();
  }
  return next.wraps.slice(previous.wraps.length);
}

async function assertRecoveryWrapPrefix(previous, next) {
  if (next.recovery_wraps.length < previous.recovery_wraps.length) fail("KEY_COVERAGE_INCOMPLETE");
  for (let index = 0; index < previous.recovery_wraps.length; index += 1) {
    if (!await sameCanonical(previous.recovery_wraps[index], next.recovery_wraps[index])) fail("KEY_COVERAGE_INCOMPLETE");
  }
  return true;
}

async function assertAddedDeviceWraps(previous, next, targetDeviceId, targetEpochs) {
  const added = await assertWrapPrefix(previous, next);
  const epochs = added.map((wrap) => asNumber(wrap.epoch)).sort((a, b) => a - b);
  if (added.some((wrap) => wrap.device_id !== targetDeviceId)
    || epochs.length !== targetEpochs.length
    || epochs.some((epoch, index) => epoch !== asNumber(targetEpochs[index]))) fail("KEY_COVERAGE_INCOMPLETE");
  if (new Set(epochs).size !== epochs.length) fail("KEY_COVERAGE_INCOMPLETE");
}

async function assertRotationDeviceWraps(previous, next, freshEpoch) {
  const added = await assertWrapPrefix(previous, next);
  const activeDevices = next.devices.filter(isDeviceActive);
  const fresh = added.filter((wrap) => asNumber(wrap.epoch) === freshEpoch);
  if (added.length !== fresh.length || fresh.length !== activeDevices.length
    || activeDevices.some((device) => fresh.filter((wrap) => wrap.device_id === device.device_id).length !== 1)
    || fresh.some((wrap) => !sameBytes(wrap.key_ref, next.epochs[freshEpoch - 1].key_ref))) {
    fail("KEY_COVERAGE_INCOMPLETE");
  }
}

async function assertPriorEpochKeyCoverage(priorEpochKeys, epochCount) {
  const entries = priorEpochKeys instanceof Map
    ? [...priorEpochKeys].map(([epoch, key]) => ({ epoch, key }))
    : priorEpochKeys;
  if (!Array.isArray(entries) || entries.length !== epochCount) fail("KEY_COVERAGE_INCOMPLETE");
  const epochs = new Set();
  for (const entry of entries) {
    if (!entry || !isBytes(entry.key) || entry.key.byteLength !== 32) fail("KEY_COVERAGE_INCOMPLETE");
    const epoch = asNumber(entry.epoch);
    if (epoch < 1 || epoch > epochCount || epochs.has(epoch)) fail("KEY_COVERAGE_INCOMPLETE");
    epochs.add(epoch);
  }
  for (let epoch = 1; epoch <= epochCount; epoch += 1) if (!epochs.has(epoch)) fail("KEY_COVERAGE_INCOMPLETE");
}

async function assertOperationState(previousManifest, nextManifest, priorEpochKeys) {
  const operation = nextManifest.operation;
  const priorAuthority = previousManifest?.recovery_authority || null;
  const nextAuthority = nextManifest.recovery_authority;
  const priorEpoch = previousManifest ? asNumber(previousManifest.current_epoch) : 0;
  const nextEpoch = asNumber(nextManifest.current_epoch);
  const rotates = operation.operation_type === "revoke-device" || operation.operation_type === "compromise-package";
  if (operation.operation_type !== "initialize" && !previousManifest) fail();
  if (rotates ? nextEpoch !== priorEpoch + 1 : nextEpoch !== (previousManifest ? priorEpoch : 1)) fail();
  if (previousManifest && priorAuthority && !nextAuthority) fail();

  switch (operation.operation_type) {
    case "initialize":
      if (previousManifest || u64(nextManifest.revision, 1n) !== 1n || asNumber(nextManifest.current_epoch) !== 1
        || nextManifest.devices.length !== 1 || !isDeviceActive(nextManifest.devices[0])
        || nextManifest.wraps.length !== 0 || nextAuthority !== null || nextManifest.recovery_wraps.length !== 0) fail();
      break;
    case "enroll-device":
      if (!previousManifest) fail();
      await assertDeviceAddition(previousManifest, nextManifest, operation.target_device_id);
      await assertAddedDeviceWraps(previousManifest, nextManifest, operation.target_device_id, operation.target_epoch_coverage);
      if (!await sameCanonical(previousManifest.recovery_authority, nextAuthority)
        || !await sameCanonical(previousManifest.recovery_wraps, nextManifest.recovery_wraps)) fail();
      break;
    case "revoke-device": {
      if (!previousManifest || !operation.target_device_id) fail();
      const priorTarget = previousManifest.devices.find((device) => device.device_id === operation.target_device_id);
      const nextTarget = nextManifest.devices.find((device) => device.device_id === operation.target_device_id);
      if (!priorTarget || !isDeviceActive(priorTarget) || !nextTarget
        || u64(nextTarget.revoked_at_epoch, 1n) !== BigInt(nextEpoch)) fail();
      await assertPriorEpochKeyCoverage(priorEpochKeys, previousManifest.epochs.length);
      await assertDeviceRevocation(previousManifest, nextManifest, operation.target_device_id, nextEpoch);
      await assertRotationDeviceWraps(previousManifest, nextManifest, nextEpoch);
      if (!await sameCanonical(previousManifest.recovery_authority, nextAuthority)) fail();
      if (nextManifest.devices.filter(isDeviceActive).length === 0 && !authorityActive(nextAuthority)) {
        fail("COMPROMISE_RECOVERY_UNAVAILABLE");
      }
      if (authorityActive(nextAuthority)) {
        if (nextManifest.recovery_wraps.length !== previousManifest.recovery_wraps.length + 1) fail("KEY_COVERAGE_INCOMPLETE");
        await assertRecoveryWrapPrefix(previousManifest, nextManifest);
        const freshRecoveryWrap = nextManifest.recovery_wraps[nextEpoch - 1];
        if (asNumber(freshRecoveryWrap.epoch) !== nextEpoch
          || !sameBytes(freshRecoveryWrap.package_id, nextAuthority.package_id)
          || !sameBytes(freshRecoveryWrap.hpke_key_id, nextAuthority.hpke_key_id)
          || !sameBytes(freshRecoveryWrap.key_ref, nextManifest.epochs[nextEpoch - 1].key_ref)) fail("KEY_COVERAGE_INCOMPLETE");
      } else if (nextManifest.recovery_wraps.length !== 0) fail("KEY_COVERAGE_INCOMPLETE");
      break;
    }
    case "register-package":
      if (authorityActive(priorAuthority) || !authorityActive(nextAuthority)) fail();
      await assertDevicesUnchanged(previousManifest, nextManifest);
      if (previousManifest && !await sameCanonical(previousManifest.wraps, nextManifest.wraps)) fail();
      break;
    case "replace-package":
      if (!authorityActive(priorAuthority) || !authorityActive(nextAuthority)
        || sameBytes(priorAuthority.package_id, nextAuthority.package_id)) fail();
      await assertDevicesUnchanged(previousManifest, nextManifest);
      if (!await sameCanonical(previousManifest.wraps, nextManifest.wraps)) fail();
      break;
    case "revoke-package":
      fail("UNAUTHORIZED_ACTOR");
      break;
    case "recover-device":
      if (operation.actor_type === "recovery-package" && !authorityActive(priorAuthority)) fail("UNAUTHORIZED_ACTOR");
      if (!previousManifest) fail();
      await assertDeviceAddition(previousManifest, nextManifest, operation.target_device_id);
      await assertAddedDeviceWraps(previousManifest, nextManifest, operation.target_device_id, operation.target_epoch_coverage);
      if (operation.actor_type === "recovery-package"
        && operation.target_epoch_coverage.length !== previousManifest.epochs.length) fail("KEY_COVERAGE_INCOMPLETE");
      if (!await sameCanonical(previousManifest.recovery_authority, nextAuthority)
        || !await sameCanonical(previousManifest.recovery_wraps, nextManifest.recovery_wraps)) fail();
      break;
    case "compromise-package":
      if (!previousManifest) fail();
      await assertDevicesUnchanged(previousManifest, nextManifest);
      await assertRotationDeviceWraps(previousManifest, nextManifest, nextEpoch);
      assertCompromisePackageTransition({ previousManifest, nextManifestCore: coreOf(nextManifest), priorEpochKeys });
      break;
    default:
      fail("UNKNOWN_RECOVERY_OPERATION");
  }
  await assertTargetTransition(operation, previousManifest, nextManifest);
}

function coreOf(manifest) {
  const core = {};
  for (const field of CORE_FIELDS) core[field] = manifest[field];
  return core;
}

async function checkHistoryHead(priorVerifiedHistory) {
  const historyVerifier = require("./rootark-zk-recovery-history-v2");
  if (!(await historyVerifier.isVerifiedRecoveryHistoryV2(priorVerifiedHistory))) fail("HISTORY_INVALID");
  if (!priorVerifiedHistory || priorVerifiedHistory.complete !== true || !priorVerifiedHistory.headManifest
    || !(priorVerifiedHistory.usedIdentifiers instanceof Set) || !Array.isArray(priorVerifiedHistory.epochKeys)) fail("HISTORY_INVALID");
  const head = priorVerifiedHistory.headManifest;
  validateManifestShape(head);
  if (u64(priorVerifiedHistory.revision, 1n) !== u64(head.revision, 1n)
    || !sameBytes(priorVerifiedHistory.headDigest, await recoveryManifestDigestV2(head))) fail("HISTORY_INVALID");
  return priorVerifiedHistory;
}

function deriveManifestMacKey(epochKey, manifest) {
  const info = z.encodeDeterministic({
    type: "rootark-keyring-manifest-mac-info-v2",
    suite: "rootark-zk-1",
    purpose: "manifest-mac",
    account_id: manifest.account_id,
    compartment_id: manifest.compartment_id,
    current_epoch: manifest.current_epoch,
    revision: manifest.revision,
  });
  return info.then((encodedInfo) => z.hkdfSha256({
    ikm: epochKey,
    salt: Buffer.alloc(0),
    info: encodedInfo,
    length: 32,
  }));
}

async function manifestMac(manifestCore, epochKey) {
  const macKey = await deriveManifestMacKey(epochKey, manifestCore);
  try {
    return crypto.createHmac("sha256", macKey).update(await z.encodeDeterministic(manifestCore)).digest();
  } finally {
    z.clearSecret(macKey);
  }
}

async function verifyRecoveryTransitionPublicV2(input) {
  const previousManifest = input.previousManifest === null ? null : input.previousManifest;
  const nextManifest = input.nextManifest;
  validateManifestShape(nextManifest);
  await verifyKeyRefs(nextManifest);
  if (previousManifest !== null) {
    validateManifestShape(previousManifest);
    await verifyKeyRefs(previousManifest);
  }
  const operation = nextManifest.operation;
  assertRecoveryActorOperation(operation.actor_type, operation.operation_type);
  let scope;
  try {
    const expectedScope = exactMap(input.expectedScope, ["account_id", "compartment_id", "keyring_id"]);
    scope = {
      account_id: checkBytes(expectedScope.account_id, 16),
      compartment_id: checkBytes(expectedScope.compartment_id, undefined, 1, 128),
      keyring_id: checkBytes(expectedScope.keyring_id, 16),
    };
  } catch (_) {
    fail("SCOPE_MISMATCH");
  }
  if (!sameBytes(nextManifest.account_id, scope.account_id)
    || !sameBytes(nextManifest.compartment_id, scope.compartment_id)
    || !sameBytes(nextManifest.keyring_id, scope.keyring_id)) fail("SCOPE_MISMATCH");
  if (previousManifest === null) {
    if (operation.operation_type !== "initialize") fail();
    if (!sameBytes(nextManifest.previous_manifest_digest, Buffer.alloc(32))) fail();
  } else {
    if (operation.operation_type === "initialize") fail();
    if (!sameBytes(previousManifest.account_id, nextManifest.account_id)
      || !sameBytes(previousManifest.compartment_id, nextManifest.compartment_id)
      || !sameBytes(previousManifest.keyring_id, nextManifest.keyring_id)) fail("SCOPE_MISMATCH");
    if (u64(nextManifest.revision, 1n) !== u64(previousManifest.revision, 1n) + 1n) fail();
    if (!sameBytes(nextManifest.previous_manifest_digest, await recoveryManifestDigestV2(previousManifest))) fail();
  }
  const admissionShape = {
    issuedAt: operation.issued_at,
    expiresAt: operation.expires_at,
    now: operation.issued_at,
    clockHealthy: true,
  };
  // Historical verification checks the signed lifetime shape, but never expires a committed transition.
  const issuedAt = asNumber(admissionShape.issuedAt);
  const expiresAt = asNumber(admissionShape.expiresAt);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 300) fail("AUTHORIZATION_EXPIRED");

  const publicKey = findActorPublicKey(previousManifest, operation, nextManifest);
  const core = coreOf(nextManifest);
  const expectedRequestDigest = await expectedRecoveryRequestDigestV2(previousManifest, core);
  if (!sameBytes(expectedRequestDigest, operation.request_digest)) fail("HISTORY_INVALID");
  const signedCore = { ...core, mac: nextManifest.mac };
  const signatureInput = Buffer.concat([SIGNATURE_PREFIX, await z.encodeDeterministic(signedCore)]);
  if (!crypto.verify(null, signatureInput, publicKey, Buffer.from(nextManifest.actor_signature))) fail("HISTORY_INVALID");
  await assertOperationState(previousManifest, nextManifest, input.priorEpochKeys || []);

  const identifiers = ensureIdentifierInventory(previousManifest, nextManifest, input.retainedIdentifiers);
  const proof = Object.freeze({
    previousManifest,
    nextManifest,
    revision: nextManifest.revision,
    manifestDigest: await recoveryManifestDigestV2(nextManifest),
    identifiers,
    actorPublicKey: publicKey,
    core,
  });
  verifiedPublicTransitions.set(proof, {
    previousManifest: previousManifest === null ? null : await z.encodeDeterministic(previousManifest),
    nextManifest: await z.encodeDeterministic(nextManifest),
  });
  return proof;
}

async function verifyRecoveryTransitionMacV2(input) {
  const proof = input.publicTransitionProof;
  if (!proof || !proof.nextManifest || !await module.exports.isVerifiedRecoveryTransitionPublicProofV2(proof)) fail();
  checkBytes(input.manifestMacKey, 32);
  if (proof.previousManifest
    && asNumber(proof.nextManifest.current_epoch) > asNumber(proof.previousManifest.current_epoch)) {
    await assertPriorEpochKeyCoverage(input.priorEpochKeys, proof.previousManifest.epochs.length);
    const priorKeys = input.priorEpochKeys instanceof Map
      ? [...input.priorEpochKeys.values()]
      : input.priorEpochKeys.map((entry) => entry.key);
    if (priorKeys.some((key) => sameBytes(key, input.manifestMacKey))) fail("HISTORY_INVALID");
  }
  const expected = await manifestMac(proof.core, input.manifestMacKey);
  try {
    if (!sameBytes(expected, proof.nextManifest.mac)) fail("HISTORY_INVALID");
    return true;
  } finally {
    z.clearSecret(expected);
  }
}

async function verifyRecoveryManifestMacV2(input) {
  const manifest = input?.manifest;
  validateManifestShape(manifest);
  checkBytes(input.epochKey, 32);
  const expected = await manifestMac(coreOf(manifest), input.epochKey);
  if (!sameBytes(expected, manifest.mac)) fail("HISTORY_INVALID");
  return true;
}

async function signRecoveryTransitionV2(input) {
  if (!input || typeof input !== "object") fail();
  let previousManifest = null;
  let priorIdentifiers = new Set();
  let priorEpochKeys = [];
  if (input.proposedCore.operation.operation_type !== "initialize") {
    const prior = await checkHistoryHead(input.priorVerifiedHistory);
    previousManifest = prior.headManifest;
    priorIdentifiers = prior.usedIdentifiers;
    priorEpochKeys = prior.epochKeys;
  }
  const core = exactMap(input.proposedCore, CORE_FIELDS);
  if (["enroll-device", "recover-device"].includes(core.operation.operation_type)
    && !await targetAuthorization.isVerifiedTargetPopResponse(core.operation.target_pop_proof, input.now)) {
    fail("INVALID_TARGET_POP");
  }
  assertRecoveryActorOperation(core.operation.actor_type, core.operation.operation_type);
  verifyRecoveryAdmissionWindowV2({
    issuedAt: core.operation.issued_at,
    expiresAt: core.operation.expires_at,
    now: input.now,
    clockHealthy: input.clockHealthy,
  });
  const expectedRequestDigest = await expectedRecoveryRequestDigestV2(previousManifest, core);
  if (!sameBytes(expectedRequestDigest, core.operation.request_digest)) fail();
  checkBytes(input.manifestMacKey, 32);
  if (!input.actorPrivateKey || input.actorPrivateKey.type !== "private"
    || input.actorPrivateKey.asymmetricKeyType !== "ed25519") fail("UNAUTHORIZED_ACTOR");
  const mac = await manifestMac(core, input.manifestMacKey);
  const signedCore = { ...core, mac };
  const actorSignature = crypto.sign(null, Buffer.concat([SIGNATURE_PREFIX, await z.encodeDeterministic(signedCore)]), input.actorPrivateKey);
  const nextManifest = { ...signedCore, actor_signature: actorSignature };
  const publicProof = await verifyRecoveryTransitionPublicV2({
    previousManifest,
    nextManifest,
    expectedScope: {
      account_id: core.account_id,
      compartment_id: core.compartment_id,
      keyring_id: core.keyring_id,
    },
    retainedIdentifiers: { complete: true, values: priorIdentifiers },
    priorEpochKeys,
  });
  await verifyRecoveryTransitionMacV2({
    publicTransitionProof: publicProof,
    manifestMacKey: input.manifestMacKey,
    priorEpochKeys,
  });
  return nextManifest;
}

function wrapAsMap(value) {
  return exactMap(value, RECOVERY_WRAP_FIELDS);
}

function assertCompromisePackageTransition(input) {
  const previous = input.previousManifest;
  const next = input.nextManifestCore;
  if (!previous || !next) fail("COMPROMISE_RECOVERY_UNAVAILABLE");
  const oldAuthority = previous.recovery_authority;
  const newAuthority = next.recovery_authority;
  if (!authorityActive(oldAuthority) || !authorityActive(newAuthority)
    || !sameBytes(input.operation?.compromised_package_id ?? next.operation?.compromised_package_id, oldAuthority.package_id)
    || sameBytes(oldAuthority.package_id, newAuthority.package_id)
    || sameBytes(oldAuthority.hpke_key_id, newAuthority.hpke_key_id)
    || sameBytes(oldAuthority.hpke_public_key, newAuthority.hpke_public_key)
    || sameBytes(oldAuthority.authorization_key_id, newAuthority.authorization_key_id)
    || sameBytes(oldAuthority.authorization_public_key, newAuthority.authorization_public_key)) {
    fail("COMPROMISE_RECOVERY_UNAVAILABLE");
  }
  const oldEpoch = asNumber(previous.current_epoch);
  const freshEpoch = asNumber(next.current_epoch);
  if (freshEpoch !== oldEpoch + 1) fail("COMPROMISE_RECOVERY_UNAVAILABLE");
  const oldEpochs = previous.epochs.map((epoch) => asNumber(epoch.epoch));
  const priorKeys = input.priorEpochKeys instanceof Map
    ? [...input.priorEpochKeys].map(([epoch, key]) => ({ epoch, key }))
    : input.priorEpochKeys;
  if (!Array.isArray(priorKeys) || priorKeys.length !== oldEpochs.length
    || oldEpochs.some((epoch) => !priorKeys.some((entry) => asNumber(entry.epoch) === epoch && isBytes(entry.key) && entry.key.byteLength === 32))) {
    fail("KEY_COVERAGE_INCOMPLETE");
  }
  const activeDevices = next.devices.filter(isDeviceActive);
  if (activeDevices.length === 0) fail("COMPROMISE_RECOVERY_UNAVAILABLE");
  if (!Array.isArray(next.recovery_wraps) || next.recovery_wraps.length !== oldEpochs.length + 1) fail("KEY_COVERAGE_INCOMPLETE");
  const expectedEpochs = [...oldEpochs, freshEpoch];
  for (let index = 0; index < expectedEpochs.length; index += 1) {
    const wrap = wrapAsMap(next.recovery_wraps[index]);
    if (expectedEpochs[index] === freshEpoch && sameBytes(wrap.package_id, oldAuthority.package_id)) {
      fail("COMPROMISE_RECOVERY_UNAVAILABLE");
    }
    if (!sameBytes(wrap.package_id, newAuthority.package_id)
      || !sameBytes(wrap.hpke_key_id, newAuthority.hpke_key_id)
      || asNumber(wrap.epoch) !== expectedEpochs[index]
      || !sameBytes(wrap.key_ref, next.epochs[index].key_ref)) fail("KEY_COVERAGE_INCOMPLETE");
  }
  const freshDeviceWraps = next.wraps.filter((wrap) => asNumber(wrap.epoch) === freshEpoch);
  if (freshDeviceWraps.length !== activeDevices.length
    || activeDevices.some((device) => freshDeviceWraps.filter((wrap) => wrap.device_id === device.device_id).length !== 1)) {
    fail("KEY_COVERAGE_INCOMPLETE");
  }
  return true;
}

module.exports = {
  MANIFEST_TYPE,
  MANIFEST_VERSION,
  OPERATIONS,
  assertRecoveryActorOperation,
  verifyRecoveryAdmissionWindowV2,
  recoveryManifestDigestV2,
  recoveryRequestDigestV2,
  expectedRecoveryRequestDigestV2,
  recoveryKeyRefV2,
  recoveryManifestIdentifiersV2: (manifest) => new Set(manifestIdentifiers(manifest)),
  isVerifiedRecoveryTransitionPublicProofV2: async (proof) => {
    const snapshot = proof && verifiedPublicTransitions.get(proof);
    if (!snapshot) return false;
    try {
      const previous = proof.previousManifest === null ? null : await z.encodeDeterministic(proof.previousManifest);
      const next = await z.encodeDeterministic(proof.nextManifest);
      return (snapshot.previousManifest === null ? previous === null : sameBytes(snapshot.previousManifest, previous))
        && sameBytes(snapshot.nextManifest, next);
    } catch (_) {
      return false;
    }
  },
  validateManifestShape,
  verifyRecoveryTransitionPublicV2,
  verifyRecoveryTransitionMacV2,
  verifyRecoveryManifestMacV2,
  signRecoveryTransitionV2,
  assertCompromisePackageTransition,
};
