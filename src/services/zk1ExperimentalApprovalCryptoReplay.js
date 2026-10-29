"use strict";

// Standalone CRYPTO + durable replay experiment, not a publishing authority.
// The pinned witness receipt is caller-supplied, not fetched from a live CAS.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const { inspectZk1CiphertextApprovalHeadPreflightV1 } =
  require("../crypto/rootark-zk-ciphertext-approval-head-preflight-v1");
const { Zk1ExperimentalPgApprovalReplayLedger,
  consumeAuthenticExperimentalReplayCandidate } =
  require("./zk1ExperimentalPgApprovalReplayLedger");
const { createZk1WitnessHttpsClient } = require("./zk1WitnessHttpsClient");

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
    const persisted = await consumeAuthenticExperimentalReplayCandidate(ledger, {
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

// An additive, still NON-AUTHORIZING experiment. Unlike the historical
// caller-supplied receipt above, this makes a new challenge and fetches the
// signed head from the configured, certificate-pinned mTLS witness endpoint.
// Nothing here establishes independent operator custody, monotonic client
// state, atomic authority with protected I/O or post-response non-revocation.
async function inspectAndRecordExperimentalOnlineApproval({ ledger, preflight, witnessTls } = {}) {
  try {
    if (!(ledger instanceof Zk1ExperimentalPgApprovalReplayLedger)) deny();
    const ONLINE_FIELDS = FIELDS.filter((field) =>
      field !== "rawWitnessHead" && field !== "witnessNonce");
    exact(preflight, ONLINE_FIELDS);
    const checked = snapshot({ ...preflight, rawWitnessHead: Buffer.from([0]),
      witnessNonce: crypto.randomBytes(32), nowSeconds: Math.floor(Date.now() / 1000) });
    exact(witnessTls, Object.hasOwn(witnessTls || {}, "timeoutMs")
      ? ["endpoint", "ca", "clientKey", "clientCert", "serverFingerprint256", "timeoutMs"]
      : ["endpoint", "ca", "clientKey", "clientCert", "serverFingerprint256"]);
    // Do not allow mutable caller TLS byte buffers to be retargeted while
    // waiting for an asynchronous challenge response.
    const tlsSettings = { ...witnessTls };
    for (const name of ["ca", "clientKey", "clientCert"]) {
      if (Buffer.isBuffer(tlsSettings[name]) || tlsSettings[name] instanceof Uint8Array) {
        if (tlsSettings[name].byteLength === 0 || tlsSettings[name].byteLength > 65536) deny();
        tlsSettings[name] = Buffer.from(tlsSettings[name]);
      } else if (typeof tlsSettings[name] !== "string"
        || tlsSettings[name].length === 0 || tlsSettings[name].length > 65536) deny();
    }
    const witness = createZk1WitnessHttpsClient(tlsSettings);
    const fetched = await witness.freshHead({
      scope: scope(checked.expected.scope),
      nonce: Buffer.from(checked.witnessNonce),
    });
    // A healthy witness can sign in the next clock second while HTTPS is
    // in flight. Refresh only the local verifier time, never caller bytes.
    const receivedAtSeconds = Math.floor(Date.now() / 1000);
    return await inspectAndRecordExperimentalApproval({ ledger, preflight: {
      ...checked, nowSeconds: receivedAtSeconds,
      rawWitnessHead: b(fetched, 1, 8 * 1024 * 1024),
    } });
  } catch (_) { deny(); }
}

module.exports = { inspectAndRecordExperimentalApproval,
  inspectAndRecordExperimentalOnlineApproval };
