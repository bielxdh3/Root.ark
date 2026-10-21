"use strict";

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const manifestV2 = require("./rootark-zk-recovery-manifest-v2");
const packageV1 = require("./rootark-zk-recovery-package-v1");

const MAX_TRANSITIONS = 4096;
const MAX_HISTORY_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const WARNING_PERCENT = 75;
const WRAP_INFO_PREFIX = Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0", "ascii");
const WRAP_AAD_PREFIX = Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0", "ascii");
const RECOVERY_PACKAGE_KEY_FIELDS = Object.freeze(["package_id", "hpke_key_id", "hpke_private_key"]);
const WITNESS_BASE_PREFIX = Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0", "ascii");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const WITNESS_RECEIPT_FIELDS = Object.freeze([
  "type", "witness_key_id", "account_id", "compartment_id", "keyring_id", "revision",
  "manifest_digest", "witness_sequence", "nonce", "observed_at", "status", "signature",
]);
const verifiedHistories = new WeakMap();
const publicHistories = new WeakMap();

function fail(code = "HISTORY_INVALID") {
  throw new z.RootarkZkError(code);
}

function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}

function bytes(value, length, min, max) {
  if (!isBytes(value) || (length !== undefined && value.byteLength !== length)
    || (min !== undefined && value.byteLength < min) || (max !== undefined && value.byteLength > max)) fail();
  return Buffer.from(value);
}

function sameBytes(left, right) {
  return isBytes(left) && isBytes(right) && left.byteLength === right.byteLength
    && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right));
}

function u64(value, minimum = 0n) {
  let result;
  if (typeof value === "bigint") result = value;
  else if (Number.isSafeInteger(value)) result = BigInt(value);
  else fail();
  if (result < minimum || result > 0xffffffffffffffffn) fail();
  return result;
}

function exactMap(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) fail();
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length || keys.some((key) => typeof key !== "string" || !fields.includes(key))
    || fields.some((field) => !Object.hasOwn(value, field))) fail();
  return value;
}

function validateScope(scope) {
  const accountId = bytes(scope?.account_id, 16);
  const compartmentId = bytes(scope?.compartment_id, undefined, 1, 128);
  const keyringId = bytes(scope?.keyring_id, 16);
  return { account_id: accountId, compartment_id: compartmentId, keyring_id: keyringId };
}

function checkRecoveryHistoryCapacity(input) {
  const transitionCount = input?.transitionCount;
  const historyBytes = input?.historyBytes;
  const nextEntryBytes = input?.nextEntryBytes;
  if (![transitionCount, historyBytes, nextEntryBytes].every(Number.isSafeInteger)
    || transitionCount < 0 || historyBytes < 0 || nextEntryBytes < 0) fail("HISTORY_CAPACITY_REACHED");
  if (nextEntryBytes > MAX_ENTRY_BYTES || transitionCount >= MAX_TRANSITIONS
    || historyBytes + nextEntryBytes > MAX_HISTORY_BYTES) fail("HISTORY_CAPACITY_REACHED");
  const usedTransitions = transitionCount + 1;
  const usedBytes = historyBytes + nextEntryBytes;
  return Object.freeze({
    usedTransitions,
    usedBytes,
    warning: usedTransitions * 100 >= MAX_TRANSITIONS * WARNING_PERCENT
      || usedBytes * 100 >= MAX_HISTORY_BYTES * WARNING_PERCENT,
    maxTransitions: MAX_TRANSITIONS,
    maxBytes: MAX_HISTORY_BYTES,
    maxEntryBytes: MAX_ENTRY_BYTES,
  });
}

function normalizeEpochKeys(input) {
  const entries = input instanceof Map
    ? [...input].map(([epoch, key]) => ({ epoch, key }))
    : input;
  if (!Array.isArray(entries)) fail("KEY_COVERAGE_INCOMPLETE");
  const keys = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") fail("KEY_COVERAGE_INCOMPLETE");
    const epoch = Number(u64(entry.epoch, 1n));
    const key = bytes(entry.key, 32);
    if (keys.has(epoch)) fail("KEY_COVERAGE_INCOMPLETE");
    keys.set(epoch, key);
  }
  return keys;
}

function keysThrough(epochKeys, epochCount) {
  const result = [];
  for (let epoch = 1; epoch <= epochCount; epoch += 1) {
    const key = epochKeys.get(epoch);
    if (!key) fail("KEY_COVERAGE_INCOMPLETE");
    result.push({ epoch, key });
  }
  return result;
}

function recoveryPackageKeyMap(input) {
  if (!Array.isArray(input) || input.length > MAX_TRANSITIONS + 1) fail("KEY_COVERAGE_INCOMPLETE");
  const result = new Map();
  try {
    for (const value of input) {
      const entry = exactMap(value, RECOVERY_PACKAGE_KEY_FIELDS);
      const packageId = bytes(entry.package_id, 16);
      const hpkeKeyId = bytes(entry.hpke_key_id, 16);
      const privateKey = bytes(entry.hpke_private_key, 32);
      const token = `${packageId.toString("hex")}:${hpkeKeyId.toString("hex")}`;
      if (result.has(token)) fail("KEY_COVERAGE_INCOMPLETE");
      result.set(token, privateKey);
    }
  } catch (error) {
    for (const key of result.values()) z.clearSecret(key);
    throw error;
  }
  return result;
}

function recoveryPackagePublicKey(privateKeyBytes) {
  const privateKeyDer = Buffer.concat([X25519_PKCS8_PREFIX, privateKeyBytes]);
  try {
    const privateKey = crypto.createPrivateKey({ key: privateKeyDer, format: "der", type: "pkcs8" });
    const publicKeyDer = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
    return Buffer.from(publicKeyDer).subarray(-32);
  } catch (_) {
    fail("KEY_COVERAGE_INCOMPLETE");
  } finally {
    z.clearSecret(privateKeyDer);
  }
}

async function verifyNewRecoveryWraps(previousManifest, nextManifest, scope, epochKeys, inputKeys) {
  const operationType = nextManifest.operation.operation_type;
  let wraps = [];
  if (["register-package", "replace-package", "compromise-package"].includes(operationType)) {
    wraps = nextManifest.recovery_wraps;
  } else if (operationType === "revoke-device") {
    wraps = nextManifest.recovery_wraps.slice(previousManifest.recovery_wraps.length);
  }
  if (wraps.length === 0) return new Map();

  const keys = recoveryPackageKeyMap(inputKeys);
  const recovered = new Map();
  try {
    for (const wrap of wraps) {
      const packageId = bytes(wrap.package_id, 16);
      const hpkeKeyId = bytes(wrap.hpke_key_id, 16);
      const wrapId = bytes(wrap.wrap_id, 16);
      const keyRef = bytes(wrap.key_ref, 32);
      const epoch = Number(u64(wrap.epoch, 1n));
      const privateKeyBytes = keys.get(`${packageId.toString("hex")}:${hpkeKeyId.toString("hex")}`);
      const expectedEpochKey = epochKeys.get(epoch) || recovered.get(epoch);
      const isFreshRotationKey = !expectedEpochKey
        && ["revoke-device", "compromise-package"].includes(operationType)
        && epoch === Number(u64(nextManifest.current_epoch, 1n))
        && epoch === Number(u64(previousManifest.current_epoch, 1n)) + 1;
      if (!privateKeyBytes || (!expectedEpochKey && !isFreshRotationKey)) fail("KEY_COVERAGE_INCOMPLETE");
      if (!sameBytes(recoveryPackagePublicKey(privateKeyBytes), nextManifest.recovery_authority.hpke_public_key)) {
        fail("KEY_COVERAGE_INCOMPLETE");
      }

      const context = {
        suite: "rootark-zk-1",
        account_id: Buffer.from(scope.account_id),
        compartment_id: Buffer.from(scope.compartment_id),
        purpose: "recovery-package",
        recipient_type: "recovery-package",
        recipient_id: packageId,
        recipient_key_id: hpkeKeyId,
        epoch,
        key_ref: keyRef,
        wrap_id: wrapId,
      };
      const contextBytes = await z.encodeDeterministic(context);
      let plaintext;
      try {
        const recipientKey = await z.hpkeSuite().kem.deserializePrivateKey(privateKeyBytes);
        plaintext = await z.hpkeOpen({
          recipientKey,
          enc: wrap.enc,
          info: Buffer.concat([WRAP_INFO_PREFIX, contextBytes]),
          aad: Buffer.concat([WRAP_AAD_PREFIX, contextBytes]),
          ciphertext: wrap.ciphertext,
        });
      } catch (_) {
        fail("KEY_COVERAGE_INCOMPLETE");
      }
      try {
        if (plaintext.byteLength !== 32) fail("KEY_COVERAGE_INCOMPLETE");
        if (expectedEpochKey) {
          if (!sameBytes(plaintext, expectedEpochKey)) fail("KEY_COVERAGE_INCOMPLETE");
        } else {
          if (recovered.has(epoch)) fail("KEY_COVERAGE_INCOMPLETE");
          recovered.set(epoch, Buffer.from(plaintext));
        }
      } finally {
        if (plaintext) z.clearSecret(plaintext);
      }
    }
    return recovered;
  } catch (error) {
    for (const key of recovered.values()) z.clearSecret(key);
    throw error;
  } finally {
    for (const key of keys.values()) z.clearSecret(key);
  }
}

function verifyRecoveryPackageBaseKey(baseManifest, packageId, inputKeys) {
  const authority = baseManifest.recovery_authority;
  if (authority?.status !== "active" || !packageId || !sameBytes(authority.package_id, packageId)) return;
  const keys = recoveryPackageKeyMap(inputKeys);
  try {
    const privateKey = keys.get(`${Buffer.from(authority.package_id).toString("hex")}:${Buffer.from(authority.hpke_key_id).toString("hex")}`);
    if (!privateKey || !sameBytes(recoveryPackagePublicKey(privateKey), authority.hpke_public_key)) {
      fail("KEY_COVERAGE_INCOMPLETE");
    }
  } finally {
    for (const key of keys.values()) z.clearSecret(key);
  }
}

async function verifyManifestKeyRefs(manifest) {
  for (const entry of manifest.epochs) {
    const expected = await manifestV2.recoveryKeyRefV2(manifest, entry.epoch);
    if (!sameBytes(expected, entry.key_ref)) fail("HISTORY_INVALID");
  }
}

async function verifyWitnessReceipt(input, scope, manifest) {
  const receipt = exactMap(input.baseReceipt, WITNESS_RECEIPT_FIELDS);
  const pinned = input.pinnedWitness;
  if (!pinned || !(pinned.publicKey instanceof crypto.KeyObject) || pinned.publicKey.type !== "public"
    || pinned.publicKey.asymmetricKeyType !== "ed25519") fail();
  bytes(pinned.keyId, 16);
  bytes(receipt.witness_key_id, 16);
  bytes(receipt.account_id, 16);
  bytes(receipt.compartment_id, undefined, 1, 128);
  bytes(receipt.keyring_id, 16);
  bytes(receipt.manifest_digest, 32);
  bytes(receipt.nonce, 32);
  bytes(receipt.signature, 64);
  u64(receipt.revision, 1n);
  u64(receipt.witness_sequence, 1n);
  u64(receipt.observed_at);
  if (receipt.type !== "rootark-recovery-witness-base/v1" || receipt.status !== "committed"
    || !sameBytes(receipt.witness_key_id, pinned.keyId)
    || !sameBytes(receipt.account_id, scope.account_id)
    || !sameBytes(receipt.compartment_id, scope.compartment_id)
    || !sameBytes(receipt.keyring_id, scope.keyring_id)
    || u64(receipt.revision, 1n) !== u64(manifest.revision, 1n)
    || !sameBytes(receipt.manifest_digest, await manifestV2.recoveryManifestDigestV2(manifest))) fail();
  const unsigned = {};
  for (const field of WITNESS_RECEIPT_FIELDS) if (field !== "signature") unsigned[field] = receipt[field];
  const signatureInput = Buffer.concat([WITNESS_BASE_PREFIX, await z.encodeDeterministic(unsigned)]);
  try {
    if (!crypto.verify(null, signatureInput, pinned.publicKey, Buffer.from(receipt.signature))) fail();
  } catch (_) {
    fail();
  }
  return true;
}

function normalizePackageEnvelopes(input) {
  const result = new Map();
  if (Array.isArray(input.packageEnvelopes)) {
    for (const item of input.packageEnvelopes) {
      if (!item || !Number.isSafeInteger(item.activationRevision) || !isBytes(item.envelopeBytes)) fail();
      if (result.has(item.activationRevision)) fail();
      result.set(item.activationRevision, Buffer.from(item.envelopeBytes));
    }
  }
  return result;
}

async function parseEnvelopeHeader(envelopeBytes, scope) {
  const parsed = await packageV1.parseRecoveryPackageV1({ envelopeBytes, expectedScope: scope });
  return parsed.envelope;
}

function validateHistoryInput(input, mode) {
  if (!input || typeof input !== "object" || Array.isArray(input)) fail();
  const proto = Object.getPrototypeOf(input);
  if (proto !== Object.prototype && proto !== null) fail();
  const fields = [
    "expectedScope", "baseManifest", "baseReceipt", "pinnedWitness", "transitions",
    "packageEnvelopeBytes", "packageEnvelopes", "now",
  ];
  if (mode !== "public") fields.push("epochKeys");
  if (mode === "recovery-package") fields.push("recoveryPackageKeys");
  if (Reflect.ownKeys(input).some((field) => typeof field !== "string" || !fields.includes(field))) fail("HISTORY_INVALID");
}

async function verifyRecoveryHistoryInternal(input, mode) {
  try {
    validateHistoryInput(input, mode);
    const scope = validateScope(input.expectedScope);
    const baseManifest = input.baseManifest;
    manifestV2.validateManifestShape(baseManifest);
    if (!sameBytes(baseManifest.account_id, scope.account_id)
      || !sameBytes(baseManifest.compartment_id, scope.compartment_id)
      || !sameBytes(baseManifest.keyring_id, scope.keyring_id)) fail("SCOPE_MISMATCH");
    await verifyManifestKeyRefs(baseManifest);
    const baseEpoch = Number(u64(baseManifest.current_epoch, 1n));
    const epochKeys = mode === "public" ? null : normalizeEpochKeys(input.epochKeys);
    if (mode === "recovery-package" && [...epochKeys.keys()].some((epoch) => epoch > baseEpoch)) {
      fail("KEY_COVERAGE_INCOMPLETE");
    }
    if (epochKeys) {
      keysThrough(epochKeys, baseEpoch);
      await manifestV2.verifyRecoveryManifestMacV2({ manifest: baseManifest, epochKey: epochKeys.get(baseEpoch) });
    }
    await verifyWitnessReceipt(input, scope, baseManifest);

    if (!Array.isArray(input.transitions)) fail();
    const baseDigest = await manifestV2.recoveryManifestDigestV2(baseManifest);
    let headManifest = baseManifest;
    let usedIdentifiers = manifestV2.recoveryManifestIdentifiersV2(baseManifest);
    let transitionCount = 0;
    let historyBytes = 0;
    let capacityWarning = false;
    let packageId = baseManifest.recovery_authority?.package_id || null;
    const firstEnvelopeBytes = isBytes(input.packageEnvelopeBytes) ? Buffer.from(input.packageEnvelopeBytes) : null;
    const envelopeBytesByRevision = normalizePackageEnvelopes(input);
    if (firstEnvelopeBytes) {
      const firstEnvelope = await parseEnvelopeHeader(firstEnvelopeBytes, scope);
      packageId = Buffer.from(firstEnvelope.package_id);
      // The user-selected package may activate AFTER enrollment or another
      // signed transition. Its predecessor is checked at that actual
      // activation below, never assumed to equal the initial base manifest.
      if (!envelopeBytesByRevision.has(Number(firstEnvelope.activation_revision))) {
        envelopeBytesByRevision.set(Number(firstEnvelope.activation_revision), firstEnvelopeBytes);
      } else if (!sameBytes(envelopeBytesByRevision.get(Number(firstEnvelope.activation_revision)), firstEnvelopeBytes)) {
        fail("INVALID_RECOVERY_PACKAGE");
      }
    }
    let firstEnvelopeUsed = false;
    let verifiedPackageActivations = 0;

    for (let index = 0; index < input.transitions.length; index += 1) {
      const entryBytes = bytes(input.transitions[index], undefined, 1, MAX_ENTRY_BYTES);
      let nextManifest;
      try {
        nextManifest = await z.decodeDeterministic(entryBytes);
        if (!sameBytes(await z.encodeDeterministic(nextManifest), entryBytes)) fail();
      } catch (_) {
        fail();
      }
      const capacity = checkRecoveryHistoryCapacity({ transitionCount, historyBytes, nextEntryBytes: entryBytes.byteLength });
      transitionCount = capacity.usedTransitions;
      historyBytes = capacity.usedBytes;
      capacityWarning ||= capacity.warning;

      const priorEpoch = Number(u64(headManifest.current_epoch, 1n));
      const priorEpochKeys = epochKeys ? keysThrough(epochKeys, priorEpoch) : null;
      const publicProof = await manifestV2.verifyRecoveryTransitionPublicV2({
        previousManifest: headManifest,
        nextManifest,
        expectedScope: scope,
        retainedIdentifiers: { complete: true, values: usedIdentifiers },
      });

      const nextAuthority = nextManifest.recovery_authority;
      const previousAuthority = headManifest.recovery_authority;
      const activatesPackage = nextAuthority?.status === "active"
        && (!previousAuthority || previousAuthority.status !== "active"
          || !sameBytes(previousAuthority.package_id, nextAuthority.package_id));
      if (activatesPackage) {
        const activationRevision = Number(u64(nextAuthority.activation_revision, 1n));
        const envelopeBytes = envelopeBytesByRevision.get(activationRevision);
        if (!envelopeBytes && (mode === "public" || firstEnvelopeBytes || envelopeBytesByRevision.size)) {
          fail("INVALID_RECOVERY_PACKAGE");
        }
        if (envelopeBytes) {
          // This checks the actual previous signed manifest revision/digest,
          // package ID, operation ID, activation revision and envelope hash.
          await packageV1.verifyRecoveryPackageActivation({ publicTransitionProof: publicProof, envelopeBytes });
          verifiedPackageActivations += 1;
          if (firstEnvelopeBytes && sameBytes(firstEnvelopeBytes, envelopeBytes)) firstEnvelopeUsed = true;
        }
      }

      const nextEpoch = Number(u64(nextManifest.current_epoch, 1n));
      if (mode === "trusted-device") {
        keysThrough(epochKeys, nextEpoch);
        await manifestV2.verifyRecoveryTransitionMacV2({
          publicTransitionProof: publicProof,
          manifestMacKey: epochKeys.get(nextEpoch),
          priorEpochKeys,
        });
      } else if (mode === "recovery-package") {
        const recoveredKeys = await verifyNewRecoveryWraps(
          headManifest, nextManifest, scope, epochKeys, input.recoveryPackageKeys,
        );
        const candidateEpochKeys = new Map(epochKeys);
        for (const [epoch, key] of recoveredKeys) candidateEpochKeys.set(epoch, key);
        try {
          keysThrough(candidateEpochKeys, nextEpoch);
          await manifestV2.verifyRecoveryTransitionMacV2({
            publicTransitionProof: publicProof,
            manifestMacKey: candidateEpochKeys.get(nextEpoch),
            priorEpochKeys,
          });
          for (const [epoch, key] of recoveredKeys) epochKeys.set(epoch, key);
        } catch (error) {
          for (const key of recoveredKeys.values()) z.clearSecret(key);
          throw error;
        }
      }
      headManifest = nextManifest;
      usedIdentifiers = new Set(publicProof.identifiers);
    }
    if ((firstEnvelopeBytes && !firstEnvelopeUsed)
      || envelopeBytesByRevision.size !== verifiedPackageActivations) {
      fail("INVALID_RECOVERY_PACKAGE");
    }

    if (epochKeys && epochKeys.size !== Number(u64(headManifest.current_epoch, 1n))) {
      fail("KEY_COVERAGE_INCOMPLETE");
    }
    const packageAuthorityStatus = packageId === null
      ? (headManifest.recovery_authority?.status === "active" ? "active" : "none")
      : headManifest.recovery_authority?.status === "active"
        && sameBytes(headManifest.recovery_authority.package_id, packageId)
        ? "active" : "revoked";
    if (mode === "recovery-package") {
      verifyRecoveryPackageBaseKey(baseManifest, packageId, input.recoveryPackageKeys);
      if (packageId === null || packageAuthorityStatus !== "active") fail("INVALID_RECOVERY_PACKAGE");
    }
    const headDigest = await manifestV2.recoveryManifestDigestV2(headManifest);
    const result = Object.freeze({
      complete: mode !== "public",
      signedStateVerified: true,
      authorizationVerified: mode !== "public",
      packageRecoverabilityVerified: mode === "recovery-package",
      verificationMode: mode,
      baseManifest,
      headManifest,
      headDigest,
      revision: headManifest.revision,
      usedIdentifiers,
      transitionCount,
      historyBytes,
      capacityWarning,
      maxTransitions: MAX_TRANSITIONS,
      maxBytes: MAX_HISTORY_BYTES,
      maxEntryBytes: MAX_ENTRY_BYTES,
      packageAuthorityStatus,
      packageEnvelopeBound: firstEnvelopeUsed || verifiedPackageActivations > 0,
      freshnessProven: false,
      ...(epochKeys ? { epochKeys: keysThrough(epochKeys, Number(u64(headManifest.current_epoch, 1n))) } : {}),
    });
    const snapshot = {
      verificationMode: mode,
      headManifest: await z.encodeDeterministic(headManifest),
      headDigest: Buffer.from(headDigest),
      revision: u64(headManifest.revision, 1n),
      usedIdentifiers: [...usedIdentifiers].sort(),
    };
    if (epochKeys) {
      snapshot.epochKeys = keysThrough(epochKeys, Number(u64(headManifest.current_epoch, 1n))).map((entry) => ({
        epoch: entry.epoch,
        key: Buffer.from(entry.key),
      }));
      verifiedHistories.set(result, snapshot);
    } else {
      publicHistories.set(result, snapshot);
    }
    return result;
  } catch (error) {
    if (error instanceof z.RootarkZkError) throw error;
    fail();
  }
}

async function verifyRecoveryHistoryPublicV2(input) {
  return verifyRecoveryHistoryInternal(input, "public");
}

async function verifyTrustedDeviceRecoveryHistoryV2(input) {
  return verifyRecoveryHistoryInternal(input, "trusted-device");
}

async function verifyRecoveryPackageHistoryV2(input) {
  return verifyRecoveryHistoryInternal(input, "recovery-package");
}

// Preserve the original entry point as strict package recovery; device-only authorization is explicit.
async function verifyRecoveryHistoryV2(input) {
  return verifyRecoveryPackageHistoryV2(input);
}

async function isVerifiedRecoveryHistoryV2(history, requiredMode) {
  const snapshot = history && verifiedHistories.get(history);
  if (!snapshot || (requiredMode && snapshot.verificationMode !== requiredMode)) return false;
  try {
    if (history.complete !== true || history.signedStateVerified !== true || history.authorizationVerified !== true
      || history.verificationMode !== snapshot.verificationMode
      || history.packageRecoverabilityVerified !== (snapshot.verificationMode === "recovery-package")) return false;
    const encodedHead = await z.encodeDeterministic(history.headManifest);
    const digestMatches = sameBytes(await manifestV2.recoveryManifestDigestV2(history.headManifest), snapshot.headDigest)
      && sameBytes(history.headDigest, snapshot.headDigest);
    const identifiers = [...history.usedIdentifiers].sort();
    const epochKeys = normalizeEpochKeys(history.epochKeys);
    if (epochKeys.size !== snapshot.epochKeys.length) return false;
    return sameBytes(encodedHead, snapshot.headManifest)
      && digestMatches
      && u64(history.revision, 1n) === snapshot.revision
      && JSON.stringify(identifiers) === JSON.stringify(snapshot.usedIdentifiers)
      && keysThrough(epochKeys, snapshot.epochKeys.length).every((entry, index) =>
        entry.epoch === snapshot.epochKeys[index].epoch && sameBytes(entry.key, snapshot.epochKeys[index].key));
  } catch (_) {
    return false;
  }
}

async function isVerifiedPublicRecoveryHistoryV2(history) {
  const snapshot = history && publicHistories.get(history);
  if (!snapshot) return false;
  try {
    if (history.complete !== false || history.signedStateVerified !== true || history.authorizationVerified !== false
      || history.packageRecoverabilityVerified !== false || history.verificationMode !== "public"
      || Object.hasOwn(history, "epochKeys")) return false;
    const encodedHead = await z.encodeDeterministic(history.headManifest);
    const digestMatches = sameBytes(await manifestV2.recoveryManifestDigestV2(history.headManifest), snapshot.headDigest)
      && sameBytes(history.headDigest, snapshot.headDigest);
    const identifiers = [...history.usedIdentifiers].sort();
    return sameBytes(encodedHead, snapshot.headManifest)
      && digestMatches
      && u64(history.revision, 1n) === snapshot.revision
      && JSON.stringify(identifiers) === JSON.stringify(snapshot.usedIdentifiers);
  } catch (_) {
    return false;
  }
}

async function isVerifiedTrustedDeviceRecoveryHistoryV2(history) {
  return isVerifiedRecoveryHistoryV2(history, "trusted-device");
}

async function isVerifiedRecoveryPackageHistoryV2(history) {
  return isVerifiedRecoveryHistoryV2(history, "recovery-package");
}

module.exports = {
  MAX_ENTRY_BYTES,
  MAX_HISTORY_BYTES,
  MAX_TRANSITIONS,
  checkRecoveryHistoryCapacity,
  isVerifiedPublicRecoveryHistoryV2,
  isVerifiedRecoveryHistoryV2,
  isVerifiedRecoveryPackageHistoryV2,
  isVerifiedTrustedDeviceRecoveryHistoryV2,
  verifyRecoveryHistoryPublicV2,
  verifyRecoveryPackageHistoryV2,
  verifyRecoveryHistoryV2,
  verifyTrustedDeviceRecoveryHistoryV2,
};
