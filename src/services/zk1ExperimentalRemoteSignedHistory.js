"use strict";

// Non-authorizing bridge: independently configured mTLS CAS history pages
// + a pinned Ed25519 genesis receipt + a fresh, nonce-bound witness HEAD.
// The two HTTP listeners being reachable does NOT establish independent
// operator/host custody, linearizability or authorization of protected I/O.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const v2 = require("../crypto/rootark-zk-recovery-manifest-v2");
const historyV2 = require("../crypto/rootark-zk-recovery-history-v2");
const { verifyWitnessHeadMatchesSignedHistoryV1 } =
  require("../crypto/rootark-zk-witness-history-consistency-v1");

const MAX_HISTORY = 64 * 1024 * 1024;
const BASE_FIELDS = ["type", "witness_key_id", "account_id",
  "compartment_id", "keyring_id", "revision", "manifest_digest",
  "witness_sequence", "nonce", "observed_at", "status", "signature"];
function fail() {
  const error = new Error("ZK_REMOTE_HISTORY_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) fail();
}
function bytes(value, length, minimum = length, maximum = length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || (length !== undefined && value.byteLength !== length)
    || (minimum !== undefined && value.byteLength < minimum)
    || (maximum !== undefined && value.byteLength > maximum)) fail();
  return Buffer.from(value);
}
function scope(input) {
  exact(input, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: bytes(input.account_id, 16),
    compartment_id: bytes(input.compartment_id, undefined, 1, 128),
    keyring_id: bytes(input.keyring_id, 16) };
}
function signedGenesis(receipt) {
  exact(receipt, BASE_FIELDS);
  return Object.fromEntries(BASE_FIELDS.map((field) => [field,
    ["witness_key_id", "account_id", "compartment_id", "keyring_id",
      "manifest_digest", "nonce", "signature"].includes(field)
      ? bytes(receipt[field], field === "signature" ? 64
        : field === "compartment_id" ? undefined
          : field === "manifest_digest" || field === "nonce" ? 32 : 16,
      field === "compartment_id" ? 1 : undefined,
      field === "compartment_id" ? 128 : undefined)
      : receipt[field]]));
}
function pinned(input) {
  exact(input, ["keyId", "publicKey"]);
  if (!(input.publicKey instanceof crypto.KeyObject)
    || input.publicKey.type !== "public"
    || input.publicKey.asymmetricKeyType !== "ed25519") fail();
  return { keyId: bytes(input.keyId, 16), publicKey: input.publicKey };
}
function floor(input) {
  exact(input, ["revision", "digest", "witnessSequence"]);
  if (!Number.isSafeInteger(input.revision) || input.revision < 1
    || !Number.isSafeInteger(input.witnessSequence)
    || input.witnessSequence < input.revision) fail();
  return { revision: input.revision, witnessSequence: input.witnessSequence,
    digest: bytes(input.digest, 32) };
}
function envelopes(input) {
  if (!Array.isArray(input) || input.length > historyV2.MAX_TRANSITIONS) fail();
  let total = 0;
  const items = input.map((item) => {
    exact(item, ["activationRevision", "envelopeBytes"]);
    if (!Number.isSafeInteger(item.activationRevision) || item.activationRevision < 2) fail();
    const length = item.envelopeBytes?.byteLength;
    if (!Number.isSafeInteger(length) || length < 1
      || length > 8 * 1024 * 1024 || length > MAX_HISTORY - total) fail();
    // Enforce a *combined* copy budget before allocating each buffer:
    // a thousand independently valid envelopes cannot exhaust Node's heap.
    total += length;
    return { activationRevision: item.activationRevision,
      envelopeBytes: bytes(item.envelopeBytes, undefined, 1, 8 * 1024 * 1024) };
  });
  return { items, total };
}
async function inspectZk1ExperimentalRemoteSignedHistory(input) {
  try {
    exact(input, ["casClient", "witnessClient", "expectedScope",
      "baseReceipt", "pinnedWitness", "minimumHead", "packageEnvelopes", "nowSeconds"]);
    const casClient = input.casClient;
    const witnessClient = input.witnessClient;
    if (typeof casClient?.getCommittedHistory !== "function"
      || typeof witnessClient?.freshHead !== "function"
      || typeof input.nowSeconds !== "function") fail();
    const requestedScope = scope(input.expectedScope);
    const genesis = signedGenesis(input.baseReceipt);
    const witnessPin = pinned(input.pinnedWitness);
    const minimumHead = floor(input.minimumHead);
    const packageEnvelopes = envelopes(input.packageEnvelopes);
    if (genesis.revision !== 1 || genesis.witness_sequence !== 1
      || minimumHead.revision < 1) fail();
    const result = await casClient.getCommittedHistory({ scope: requestedScope });
    if (!result || !Number.isSafeInteger(result.headRevision)
      || result.headRevision < 1 || result.headRevision > 4097
      || !Array.isArray(result.entries)
      || result.entries.length !== result.headRevision) fail();
    const claimedHead = bytes(result.headDigest, 32);
    let total = packageEnvelopes.total;
    const entries = result.entries.map((entry) => {
      const length = entry?.byteLength;
      if (!Number.isSafeInteger(length) || length < 1
        || length > 8 * 1024 * 1024 || length > MAX_HISTORY - total) fail();
      const copied = bytes(entry, undefined, 1, 8 * 1024 * 1024);
      total += copied.length;
      return copied;
    });
    const baseManifest = await z.decodeDeterministic(entries[0]);
    const publicHistory = await historyV2.verifyRecoveryHistoryPublicV2({
      expectedScope: requestedScope, baseManifest, baseReceipt: genesis,
      pinnedWitness: witnessPin,
      transitions: entries.slice(1), packageEnvelopes: packageEnvelopes.items,
      now: 0, // public historical signatures are not a live authority
    });
    if (!await historyV2.isVerifiedPublicRecoveryHistoryV2(publicHistory)
      || Number(publicHistory.revision) !== result.headRevision
      || !Buffer.from(publicHistory.headDigest).equals(claimedHead)) fail();
    const nonce = crypto.randomBytes(32);
    const raw = bytes(await witnessClient.freshHead({
      scope: requestedScope, nonce: Buffer.from(nonce),
    }), undefined, 1, 8192);
    const checked = await verifyWitnessHeadMatchesSignedHistoryV1({
      verifiedPublicHistory: publicHistory, raw, nonce,
      scope: requestedScope, pinned: witnessPin, minimumHead,
    });
    if (checked.verifiedConsistentHead !== true
      || checked.authorizesProtectedIo !== false || checked.authorizesRecovery !== false) fail();
    const head = await z.decodeDeterministic(raw);
    const now = input.nowSeconds();
    if (!Number.isSafeInteger(now) || now < 0
      || !Number.isSafeInteger(Number(head.observed_at))
      || Math.abs(Number(head.observed_at) - now) > 30) fail();
    return Object.freeze({
      revision: Number(publicHistory.revision), digest: Buffer.from(publicHistory.headDigest),
      signedPublicHistoryVerified: true, freshWitnessHeadMatchesHistory: true,
      authorizesRecovery: false, authorizesProtectedIo: false,
      independentlyOperatedAuthoritiesVerified: false,
    });
  } catch (_) { fail(); }
}

module.exports = { inspectZk1ExperimentalRemoteSignedHistory };
