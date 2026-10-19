"use strict";

const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const manifestV2 = require("./rootark-zk-recovery-manifest-v2");
const packageV1 = require("./rootark-zk-recovery-package-v1");

const MAX_TRANSITIONS = 4096;
const MAX_HISTORY_BYTES = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES = 8 * 1024 * 1024;
const WARNING_PERCENT = 75;
const WITNESS_HEAD_PREFIX = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const WITNESS_RECEIPT_FIELDS = Object.freeze([
  "type", "witness_key_id", "account_id", "compartment_id", "keyring_id", "revision",
  "manifest_digest", "witness_sequence", "nonce", "observed_at", "status", "signature",
]);
const verifiedHistories = new WeakMap();

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
  if (receipt.type !== "rootark-recovery-witness-head" || receipt.status !== "committed"
    || !sameBytes(receipt.witness_key_id, pinned.keyId)
    || !sameBytes(receipt.account_id, scope.account_id)
    || !sameBytes(receipt.compartment_id, scope.compartment_id)
    || !sameBytes(receipt.keyring_id, scope.keyring_id)
    || u64(receipt.revision, 1n) !== u64(manifest.revision, 1n)
    || !sameBytes(receipt.manifest_digest, await manifestV2.recoveryManifestDigestV2(manifest))) fail();
  const unsigned = {};
  for (const field of WITNESS_RECEIPT_FIELDS) if (field !== "signature") unsigned[field] = receipt[field];
  const signatureInput = Buffer.concat([WITNESS_HEAD_PREFIX, await z.encodeDeterministic(unsigned)]);
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

async function verifyRecoveryHistoryV2(input) {
  try {
    const scope = validateScope(input.expectedScope);
    const baseManifest = input.baseManifest;
    manifestV2.validateManifestShape(baseManifest);
    if (!sameBytes(baseManifest.account_id, scope.account_id)
      || !sameBytes(baseManifest.compartment_id, scope.compartment_id)
      || !sameBytes(baseManifest.keyring_id, scope.keyring_id)) fail("SCOPE_MISMATCH");
    await verifyManifestKeyRefs(baseManifest);
    const epochKeys = normalizeEpochKeys(input.epochKeys);
    const baseEpoch = Number(u64(baseManifest.current_epoch, 1n));
    keysThrough(epochKeys, baseEpoch);
    await manifestV2.verifyRecoveryManifestMacV2({ manifest: baseManifest, epochKey: epochKeys.get(baseEpoch) });
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
      if (u64(firstEnvelope.base_revision, 1n) !== u64(baseManifest.revision, 1n)
        || !sameBytes(firstEnvelope.base_manifest_digest, baseDigest)) fail("INVALID_RECOVERY_PACKAGE");
      if (!envelopeBytesByRevision.has(Number(firstEnvelope.activation_revision))) {
        envelopeBytesByRevision.set(Number(firstEnvelope.activation_revision), firstEnvelopeBytes);
      } else if (!sameBytes(envelopeBytesByRevision.get(Number(firstEnvelope.activation_revision)), firstEnvelopeBytes)) {
        fail("INVALID_RECOVERY_PACKAGE");
      }
    }

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
      const priorEpochKeys = keysThrough(epochKeys, priorEpoch);
      const publicProof = await manifestV2.verifyRecoveryTransitionPublicV2({
        previousManifest: headManifest,
        nextManifest,
        expectedScope: scope,
        retainedIdentifiers: { complete: true, values: usedIdentifiers },
        priorEpochKeys,
      });

      const nextAuthority = nextManifest.recovery_authority;
      const previousAuthority = headManifest.recovery_authority;
      const activatesPackage = nextAuthority?.status === "active"
        && (!previousAuthority || previousAuthority.status !== "active"
          || !sameBytes(previousAuthority.package_id, nextAuthority.package_id));
      if (activatesPackage && firstEnvelopeBytes) {
        const activationRevision = Number(u64(nextAuthority.activation_revision, 1n));
        const envelopeBytes = envelopeBytesByRevision.get(activationRevision);
        if (!envelopeBytes) fail("INVALID_RECOVERY_PACKAGE");
        await packageV1.verifyRecoveryPackageActivation({ publicTransitionProof: publicProof, envelopeBytes });
        if (index === 0 && (!firstEnvelopeBytes || !sameBytes(firstEnvelopeBytes, envelopeBytes))) fail("INVALID_RECOVERY_PACKAGE");
      } else if (index === 0 && firstEnvelopeBytes && !activatesPackage) {
        fail("INVALID_RECOVERY_PACKAGE");
      }

      const nextEpoch = Number(u64(nextManifest.current_epoch, 1n));
      keysThrough(epochKeys, nextEpoch);
      await manifestV2.verifyRecoveryTransitionMacV2({
        publicTransitionProof: publicProof,
        manifestMacKey: epochKeys.get(nextEpoch),
        priorEpochKeys,
      });
      headManifest = nextManifest;
      usedIdentifiers = new Set(publicProof.identifiers);
    }

    const packageAuthorityStatus = packageId === null
      ? (headManifest.recovery_authority?.status === "active" ? "active" : "none")
      : headManifest.recovery_authority?.status === "active"
        && sameBytes(headManifest.recovery_authority.package_id, packageId)
        ? "active" : "revoked";
    const headDigest = await manifestV2.recoveryManifestDigestV2(headManifest);
    const result = Object.freeze({
      complete: true,
      baseManifest,
      headManifest,
      headDigest,
      revision: headManifest.revision,
      usedIdentifiers,
      epochKeys: keysThrough(epochKeys, Number(u64(headManifest.current_epoch, 1n))),
      transitionCount,
      historyBytes,
      capacityWarning,
      maxTransitions: MAX_TRANSITIONS,
      maxBytes: MAX_HISTORY_BYTES,
      maxEntryBytes: MAX_ENTRY_BYTES,
      packageAuthorityStatus,
      packageEnvelopeBound: firstEnvelopeBytes !== null,
      freshnessProven: false,
    });
    verifiedHistories.set(result, {
      headManifest: await z.encodeDeterministic(headManifest),
      headDigest: Buffer.from(headDigest),
      revision: u64(headManifest.revision, 1n),
      usedIdentifiers: [...usedIdentifiers].sort(),
      epochKeys: keysThrough(epochKeys, Number(u64(headManifest.current_epoch, 1n))).map((entry) => ({
        epoch: entry.epoch,
        key: Buffer.from(entry.key),
      })),
    });
    return result;
  } catch (error) {
    if (error instanceof z.RootarkZkError) throw error;
    fail();
  }
}

async function isVerifiedRecoveryHistoryV2(history) {
  const snapshot = history && verifiedHistories.get(history);
  if (!snapshot) return false;
  try {
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

module.exports = {
  MAX_ENTRY_BYTES,
  MAX_HISTORY_BYTES,
  MAX_TRANSITIONS,
  checkRecoveryHistoryCapacity,
  isVerifiedRecoveryHistoryV2,
  verifyRecoveryHistoryV2,
};
