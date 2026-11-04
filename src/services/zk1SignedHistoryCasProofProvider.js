"use strict";

// Read-only owner-rooted public-signature verifier. This module does not
// approve an operation, consume a challenge or start protected ciphertext I/O.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const manifestV2 = require("../crypto/rootark-zk-recovery-manifest-v2");
const historyV2 = require("../crypto/rootark-zk-recovery-history-v2");

const MAX_HISTORY = 64 * 1024 * 1024;
const MAX_ENTRY = 8 * 1024 * 1024;
function fail() {
  const error = new Error("ZK1_SIGNED_HISTORY_UNVERIFIED");
  error.code = error.message;
  throw error;
}
function asBytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function scopeCopy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Reflect.ownKeys(value).length !== 3
    || !["account_id", "compartment_id", "keyring_id"].every(
      (key) => Object.hasOwn(value, key))) fail();
  return {
    account_id: asBytes(value.account_id, 16),
    compartment_id: asBytes(value.compartment_id, 1, 128),
    keyring_id: asBytes(value.keyring_id, 16),
  };
}
function baseCopy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const result = {};
  for (const name of Reflect.ownKeys(value)) {
    if (typeof name !== "string") fail();
    const item = value[name];
    if (Buffer.isBuffer(item) || item instanceof Uint8Array) result[name] = Buffer.from(item);
    else if (item === null || typeof item === "number"
      || typeof item === "bigint" || typeof item === "string"
      || typeof item === "boolean") result[name] = item;
    else fail();
  }
  return result;
}
function createZk1SignedHistoryCasProofProvider({
  casClient, trustedScope, trustedGenesisDigest, baseReceipt,
  pinnedBaseWitness, packageEnvelopes = [], nowSeconds = () => Math.floor(Date.now() / 1000),
} = {}) {
  if (typeof casClient?.getCommittedHistory !== "function"
    || typeof nowSeconds !== "function"
    || !(pinnedBaseWitness?.publicKey instanceof crypto.KeyObject)
    || pinnedBaseWitness.publicKey.type !== "public"
    || pinnedBaseWitness.publicKey.asymmetricKeyType !== "ed25519") fail();
  const fixedScope = scopeCopy(trustedScope);
  const genesisDigest = asBytes(trustedGenesisDigest, 32);
  const signedBase = baseCopy(baseReceipt);
  const pinned = { keyId: asBytes(pinnedBaseWitness.keyId, 16),
    publicKey: pinnedBaseWitness.publicKey };
  if (!Array.isArray(packageEnvelopes) || packageEnvelopes.length > 4096) fail();
  let envelopeBytes = 0;
  const envelopes = packageEnvelopes.map((item) => {
    if (!item || !Number.isSafeInteger(item.activationRevision)
      || item.activationRevision < 2) fail();
    const original = item.envelopeBytes;
    const size = original?.byteLength;
    if (!Number.isSafeInteger(size) || size < 1
      || size > MAX_ENTRY || size > MAX_HISTORY - envelopeBytes) fail();
    envelopeBytes += size;
    return { activationRevision: item.activationRevision,
      envelopeBytes: asBytes(original, 1, MAX_ENTRY) };
  });

  return async function fetchTrustedSignedHistory({ scope } = {}) {
    try {
      const target = scopeCopy(scope);
      if (!["account_id", "compartment_id", "keyring_id"].every(
        (name) => same(target[name], fixedScope[name]))) fail();
      const fetched = await casClient.getCommittedHistory({ scope: target });
      if (!fetched || !Number.isSafeInteger(fetched.headRevision)
        || fetched.headRevision < 1 || fetched.headRevision > 4097
        || !Array.isArray(fetched.entries)
        || fetched.entries.length !== fetched.headRevision) fail();
      const declared = asBytes(fetched.headDigest, 32);
      let budget = envelopeBytes;
      const entries = fetched.entries.map((entry) => {
        if (!entry || !Number.isSafeInteger(entry.byteLength)
          || entry.byteLength < 1 || entry.byteLength > MAX_ENTRY
          || entry.byteLength > MAX_HISTORY - budget) fail();
        budget += entry.byteLength;
        return asBytes(entry, 1, MAX_ENTRY);
      });
      const genesis = await z.decodeDeterministic(entries[0]);
      if (!same(Buffer.from(await z.encodeDeterministic(genesis)), entries[0])
        || !same(await manifestV2.recoveryManifestDigestV2(genesis),
          genesisDigest)) fail();
      const now = nowSeconds();
      if (!Number.isSafeInteger(now) || now < 0) fail();
      const proof = await historyV2.verifyRecoveryHistoryPublicV2({
        expectedScope: fixedScope, baseManifest: genesis, baseReceipt: signedBase,
        pinnedWitness: pinned, transitions: entries.slice(1),
        packageEnvelopes: envelopes, now,
      });
      if (!await historyV2.isVerifiedPublicRecoveryHistoryV2(proof)
        || Number(proof.revision) !== fetched.headRevision
        || !same(asBytes(proof.headDigest, 32), declared)) fail();
      return proof;
    } catch (_) { fail(); }
  };
}

module.exports = { createZk1SignedHistoryCasProofProvider };
