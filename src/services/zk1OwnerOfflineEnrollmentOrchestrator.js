"use strict";

// Local owner-only orchestration: the existing cryptographic module holds
// unexportable WeakMap PoP provenance for the lifetime of this ONE process.
// No server account endpoint, signing key delivery, or invented CAS confirmation.
const crypto = require("node:crypto");
const history = require("../crypto/rootark-zk-recovery-history-v2");
const manifest = require("../crypto/rootark-zk-recovery-manifest-v2");
const commitment = require("../crypto/rootark-zk1-offline-commitment-receipt");
const enrollment = require("../crypto/rootark-zk1-owner-offline-v2-enrollment");
const z = require("../crypto/rootark-zk-1");

function denied() { throw new Error("ZK_OWNER_CEREMONY_DENIED"); }
function bytes64(value, length) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) denied();
  const result = Buffer.from(value, "base64url");
  if (result.byteLength !== length || result.toString("base64url") !== value) denied();
  return result;
}
function equal(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function receiptSha256(receipt) {
  const unsigned = Object.fromEntries(commitment.FIELDS.map((name) => [name, receipt?.[name]]));
  return crypto.createHash("sha256").update(Buffer.concat([
    commitment.commitmentSigningBytes(unsigned), bytes64(receipt?.signature, 64),
  ])).digest();
}
function now() { return Math.floor(Date.now() / 1000); }
async function executeOwnerEnrollment({
  trusted, externalPins, request, publishChallenge, awaitTargetPoP,
  publishCandidate, awaitWitnessCommitment, publishDelivery, clock = now,
}) {
  if (!trusted || !externalPins || !request
    || ![publishChallenge, awaitTargetPoP, publishCandidate,
      awaitWitnessCommitment, publishDelivery, clock].every((f) => typeof f === "function")) denied();
  let started = false;
  let stage = "initial";
  try {
    // Explicit external floor never taken from request, receipt or browser delivery.
    if (!await history.isVerifiedTrustedDeviceRecoveryHistoryV2(trusted.verifiedHistory)) denied();
    const head = trusted.verifiedHistory.headManifest;
    const digest = await manifest.recoveryManifestDigestV2(head);
    if (!Number.isSafeInteger(externalPins.revision)
      || !Number.isSafeInteger(externalPins.epoch)
      || !equal(bytes64(externalPins.digest, 32), digest)
      || head.revision !== externalPins.revision
      || head.current_epoch !== externalPins.epoch
      || !equal(receiptSha256(trusted.trustedPriorCommitment),
        bytes64(externalPins.priorCommitmentSha256, 32))) denied();
    if (trusted.trustedOwnerPublicKey?.type !== "public"
      || trusted.trustedCommitmentSignerPublicKey?.type !== "public"
      || trusted.trustedOwnerPublicKey.asymmetricKeyType !== "ed25519"
      || trusted.trustedCommitmentSignerPublicKey.asymmetricKeyType !== "ed25519") denied();
    const sourceTime = clock();
    if (!Number.isSafeInteger(sourceTime)
      || Math.abs(sourceTime - now()) > 30) denied();
    const prepared = await enrollment.beginOwnerEnrollment({
      request, verifiedHistory: trusted.verifiedHistory,
      externalCurrentHead: { revision: externalPins.revision,
        digest: externalPins.digest, epoch: externalPins.epoch },
      trustedOwnerPublicKey: trusted.trustedOwnerPublicKey,
      independentOwnerSpkiSha256: externalPins.ownerSpkiSha256,
      trustedCommitmentSignerPublicKey: trusted.trustedCommitmentSignerPublicKey,
      independentCommitmentSignerSpkiSha256: externalPins.witnessSpkiSha256,
      trustedPriorCommitment: trusted.trustedPriorCommitment,
      nowSeconds: sourceTime,
    });
    started = true;
    stage = "challenge";
    await publishChallenge(enrollment.exportBrowserChallenge(prepared));
    stage = "pop";
    const response = await awaitTargetPoP();
    const candidate = await enrollment.stageBrowserPopResponse({
      prepared, response, trustedActorPrivateKey: trusted.trustedActorPrivateKey,
      nowSeconds: clock(),
    });
    // Candidate manifest is ALREADY signed by the current device, but it is
    // NOT a committed head. Only a trusted separate witness/CAS can attest it.
    const candidateBytes = Buffer.from(await z.encodeDeterministic(candidate.manifest));
    stage = "uncommitted";
    await publishCandidate(Object.freeze({
      schema: "rootark-zk1-owner-uncommitted-candidate/v1",
      manifestBase64: candidateBytes.toString("base64url"),
      digest: Buffer.from(await manifest.recoveryManifestDigestV2(candidate.manifest))
        .toString("base64url"),
      revision: candidate.manifest.revision,
      epoch: candidate.manifest.current_epoch,
      operationId: Buffer.from(candidate.manifest.operation.operation_id).toString("base64url"),
      popChallengeId: Buffer.from(candidate.manifest.operation.target_pop_proof.challenge_context.challenge_id)
        .toString("base64url"),
      requestNonce: request.challenge,
      commitNonce: candidate.commitmentNonce,
      // Markers prevent downstream tooling from treating candidate as authority.
      signedCandidateOnly: true, ownerApproved: false, committed: false,
    }));
    stage = "commitment";
    const signedCommittedHead = await awaitWitnessCommitment();
    const issued = await enrollment.ownerApproveCommittedEnrollment({
      candidate, signedCommittedHead,
      ownerPrivateKey: trusted.ownerPrivateKey, nowSeconds: clock(),
    });
    if (issued.signedCommitmentVerified !== true || issued.noServerSecretExposure !== true
      || issued.physicalDurabilityProven !== false
      || issued.browserDelivery?.schema !== "rootark-zk1-v2-owner-browser-delivery/v1") denied();
    stage = "delivery";
    await publishDelivery(issued.browserDelivery);
    return Object.freeze({ completed: true, schema: issued.browserDelivery.schema,
      revision: candidate.manifest.revision, digest: Buffer.from(
        await manifest.recoveryManifestDigestV2(candidate.manifest)).toString("base64url"),
      committedWitnessReceiptCryptographicallyVerified: true,
      physicalDurabilityProven: false, externalCustodyProven: false,
      ownerPrivateKeyExported: false, stage: "complete" });
  } catch (_) {
    // Never emit grant, keys or partial "approval". No replay of a claimed PoP.
    throw Object.assign(new Error("ZK_OWNER_CEREMONY_DENIED"), {
      phase: started ? stage : "preflight",
    });
  }
}

module.exports = { executeOwnerEnrollment };
