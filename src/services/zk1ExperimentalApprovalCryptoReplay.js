"use strict";

// Standalone CRYPTO + durable replay experiment, not a publishing authority.
// The pinned witness receipt is caller-supplied, not fetched from a live CAS.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const { inspectZk1CiphertextApprovalHeadPreflightV1 } =
  require("../crypto/rootark-zk-ciphertext-approval-head-preflight-v1");
const { Zk1ExperimentalPgApprovalReplayLedger } =
  require("./zk1ExperimentalPgApprovalReplayLedger");

const FIELDS = ["rawApproval", "verifiedPublicHistory", "rawWitnessHead",
  "witnessPinned", "witnessNonce", "minimumHead", "pinnedDevice",
  "expected", "nowSeconds"];
function deny() {
  const e = new Error("ZK_CRYPTO_REPLAY_LAB_DENIED");
  e.code = e.message;
  throw e;
}
function exact(object, keys) {
  if (!object || typeof object !== "object" || Array.isArray(object)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(object))
    || Reflect.ownKeys(object).length !== keys.length
    || keys.some((k) => !Object.hasOwn(object, k))) deny();
}
function b(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) deny();
  return Buffer.from(value);
}
function pinned(value, fields, keyField) {
  exact(value, fields);
  if (!(value.publicKey instanceof crypto.KeyObject)
    || value.publicKey.type !== "public"
    || value.publicKey.asymmetricKeyType !== "ed25519") deny();
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(value.publicKey.export({ type: "spki", format: "der" })),
    type: "spki", format: "der",
  });
  return { [keyField]: b(value[keyField], 16), publicKey,
    ...(fields.includes("deviceId") ? { deviceId: value.deviceId } : {}) };
}
function scope(value) {
  exact(value, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: b(value.account_id, 16),
    compartment_id: b(value.compartment_id, 1, 128),
    keyring_id: b(value.keyring_id, 16) };
}
function snapshot(input) {
  exact(input, FIELDS);
  exact(input.expected,
    ["scope", "objectId", "objectRevision", "expectedChunkCount", "expectedRootHash", "nonce"]);
  exact(input.minimumHead, ["revision", "digest", "witnessSequence"]);
  const expected = input.expected;
  const floor = input.minimumHead;
  return {
    rawApproval: b(input.rawApproval, 100, 4096),
    verifiedPublicHistory: input.verifiedPublicHistory,
    rawWitnessHead: b(input.rawWitnessHead, 1, 8 * 1024 * 1024),
    witnessPinned: pinned(input.witnessPinned, ["keyId", "publicKey"], "keyId"),
    witnessNonce: b(input.witnessNonce, 32),
    minimumHead: { revision: floor.revision, digest: b(floor.digest, 32),
      witnessSequence: floor.witnessSequence },
    pinnedDevice: pinned(input.pinnedDevice,
      ["deviceId", "signerKeyId", "publicKey"], "signerKeyId"),
    expected: { scope: scope(expected.scope), objectId: expected.objectId,
      objectRevision: expected.objectRevision,
      expectedChunkCount: expected.expectedChunkCount,
      expectedRootHash: b(expected.expectedRootHash, 32),
      nonce: b(expected.nonce, 32) },
    nowSeconds: input.nowSeconds,
  };
}

async function inspectAndRecordExperimentalApproval({ ledger, preflight } = {}) {
  try {
    if (!(ledger instanceof Zk1ExperimentalPgApprovalReplayLedger)) deny();
    // Snapshot before the first async verifier operation so mutation of a
    // caller's nonce/key/root cannot retarget the later committed SQL row.
    const input = snapshot(preflight);
    const evidence = await inspectZk1CiphertextApprovalHeadPreflightV1(input);
    if (evidence.cryptographicLinkVerified !== true
      || evidence.signerListedActiveInSignedHead !== true
      || evidence.witnessHeadSignatureMatched !== true
      || evidence.authorizesRelease !== false
      || evidence.liveAuthorityVerified !== false
      || evidence.nonceConsumed !== false) deny();
    const signed = await z.decodeDeterministic(input.rawApproval);
    const witness = await z.decodeDeterministic(input.rawWitnessHead);
    if (!Number.isSafeInteger(signed.expires_at)
      || !Number.isSafeInteger(witness.witness_sequence)
      || witness.witness_sequence < 1) deny();
    const persisted = await ledger.consumeCandidate({
      scope: input.expected.scope, nonce: input.expected.nonce,
      rawSignedApproval: input.rawApproval,
      deviceKeyId: input.pinnedDevice.signerKeyId,
      manifestRevision: signed.manifest_revision,
      manifestDigest: Buffer.from(signed.manifest_digest),
      witnessSequence: witness.witness_sequence,
      expiresAt: signed.expires_at,
    });
    if (persisted.replayRecordCommitted !== true
      || persisted.authorizesRelease !== false) deny();
    return Object.freeze({ historicalCryptographicLinkVerified: true,
      replayTombstoneCommitted: true, freshLiveAuthorityVerified: false,
      authorizesRelease: false, protectedIoAdmission: false });
  } catch (_) { deny(); }
}

module.exports = { inspectAndRecordExperimentalApproval };
