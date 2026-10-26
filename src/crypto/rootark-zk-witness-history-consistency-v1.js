"use strict";

// Pure cryptographic consistency check between a separately verified public
// keyring history and an independently pinned, nonce-bound signed witness
// head. It does NOT fetch a witness, enforce nonce uniqueness, establish
// operator independence, or authorize recovery/protected content I/O.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const histories = require("./rootark-zk-recovery-history-v2");
const witness = require("./rootark-zk-witness-head-wire-v1");

function fail() { throw new z.RootarkZkError("WITNESS_HISTORY_MISMATCH"); }
function copied(value, length, min = length, max = length) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.byteLength < min || value.byteLength > max) fail();
  return Buffer.from(value);
}
function equalBytes(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b)
    && a.length === b.length && crypto.timingSafeEqual(a, b);
}
function sameRevision(a, b) {
  const left = typeof a === "bigint" ? a : Number.isSafeInteger(a) ? BigInt(a) : -1n;
  const right = typeof b === "bigint" ? b : Number.isSafeInteger(b) ? BigInt(b) : -2n;
  return left >= 1n && left === right;
}

async function verifyWitnessHeadMatchesSignedHistoryV1(input) {
  try {
    const history = input?.verifiedPublicHistory;
    // Take local snapshots of every mutable byte input BEFORE the second
    // verifier (or ANY other asynchronous operation) awaits. A late caller
    // mutation must not change an accepted hash, identity, scope or floor.
    const digest = copied(history.headDigest, 32);
    const revision = history.revision;
    const historicAccount = copied(history.headManifest.account_id, 16);
    const historicCompartment = copied(history.headManifest.compartment_id, undefined, 1, 128);
    const historicKeyring = copied(history.headManifest.keyring_id, 16);
    const historicRevision = history.headManifest.revision;
    const account = copied(input.scope?.account_id, 16);
    const compartment = copied(input.scope?.compartment_id, undefined, 1, 128);
    const keyring = copied(input.scope?.keyring_id, 16);
    const raw = copied(input.raw, undefined, 1, 8 * 1024 * 1024);
    const nonce = copied(input.nonce, 32);
    const floor = {
      revision: input.minimumHead?.revision,
      digest: copied(input.minimumHead?.digest, 32),
      witnessSequence: input.minimumHead?.witnessSequence,
    };
    const pinned = {
      publicKey: input.pinned?.publicKey,
      keyId: copied(input.pinned?.keyId, 16),
    };
    if (!await histories.isVerifiedPublicRecoveryHistoryV2(history)
      || !sameRevision(revision, historicRevision)
      || !equalBytes(account, historicAccount)
      || !equalBytes(compartment, historicCompartment)
      || !equalBytes(keyring, historicKeyring)) fail();
    const checked = await witness.inspectVerifiedWitnessFreshHeadV1({
      raw, pinned, nonce,
      scope: { account_id: account, compartment_id: compartment, keyring_id: keyring },
      minimumHead: floor,
    });
    if (checked.verifiedSignatureOnly !== true || checked.authorizesRecovery !== false) fail();
    const actual = await z.decodeDeterministic(raw);
    if (!sameRevision(actual.current_revision, revision)
      || !equalBytes(copied(actual.current_manifest_digest, 32), digest)
      || !await histories.isVerifiedPublicRecoveryHistoryV2(history)) fail();
    return Object.freeze({
      verifiedConsistentHead: true,
      revision: actual.current_revision,
      authorizesRecovery: false,
      authorizesProtectedIo: false,
    });
  } catch (_) { fail(); }
}

module.exports = { verifyWitnessHeadMatchesSignedHistoryV1 };
