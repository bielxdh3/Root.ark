"use strict";

// Cryptographic linkage only. The actual CAS durable no-commit fence,
// expiry/clock-health check, witness gate resolution and subsequent fresh
// committed head are external obligations; this cannot authorize recovery.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const { inspectVerifiedCasStatusProofV1 } = require("./rootark-zk-cas-status-wire-v1");
const { inspectVerifiedWitnessCancellationV1 } = require("./rootark-zk-witness-operation-wire-v1");

function copyBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value) : value;
}
function snapshotContext(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return value;
  const clone = Object.create(null);
  for (const key of Object.keys(value)) clone[key] = copyBytes(value[key]);
  return clone;
}
async function inspectCancellationCryptoLinkV1(input) {
  const rawStatus = input?.rawStatus;
  if (!(Buffer.isBuffer(rawStatus) || rawStatus instanceof Uint8Array)) {
    throw new z.RootarkZkError("CANCELLATION_CRYPTO_LINK_INVALID");
  }
  // Both operations must use an identical byte snapshot. Never hash a
  // caller-owned Buffer after an await: it can be changed between signature
  // verification and the cancellation proof-digest calculation.
  const verifiedRawStatus = Buffer.from(rawStatus);
  // The nonce, scoped query and pinned key IDs must be the invocation-time
  // values for BOTH asynchronous verifications, never mutable caller state.
  const statusPinned = snapshotContext(input.statusPinned);
  const witnessPinned = snapshotContext(input.witnessPinned);
  const query = snapshotContext(input.query);
  const nonce = copyBytes(input.nonce);
  const rawCancellation = copyBytes(input.rawCancellation);
  try {
    const proof = await inspectVerifiedCasStatusProofV1({
      raw: verifiedRawStatus,
      pinned: statusPinned,
      query,
      nonce,
    });
    if (proof.terminal_status !== "not-committed-final"
      || proof.authorizesRecovery !== false) {
      throw new Error("Not a final non-commit proof");
    }
    // inspectVerifiedCasStatusProofV1 has already enforced bytewise
    // deterministic-CBOR canonicality. Its raw signed CBOR bytes include
    // the 64-byte Ed25519 signature; hashing only unsigned fields is wrong.
    const signedProofDigest = crypto.createHash("sha256")
      .update(verifiedRawStatus).digest();
    const cancellation = await inspectVerifiedWitnessCancellationV1({
      raw: rawCancellation,
      pinned: witnessPinned,
      operation: query,
      verifiedTerminalProofDigest: signedProofDigest,
    });
    if (!cancellation.verifiedSignatureOnly || cancellation.authorizesRecovery !== false) {
      throw new Error("Unverified cancellation receipt");
    }
  } catch (_) {
    throw new z.RootarkZkError("CANCELLATION_CRYPTO_LINK_INVALID");
  }
  return Object.freeze({ linkVerified: true, authorizesRecovery: false });
}

module.exports = { inspectCancellationCryptoLinkV1 };
