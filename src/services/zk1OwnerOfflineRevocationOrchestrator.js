"use strict";

// Owner-side V2 revoke + epoch rotation. Produces no new authority until an
// independently signed committed-head receipt confirms the exact candidate.
const crypto = require("node:crypto");
const z = require("../crypto/rootark-zk-1");
const history = require("../crypto/rootark-zk-recovery-history-v2");
const manifest = require("../crypto/rootark-zk-recovery-manifest-v2");
const commitment = require("../crypto/rootark-zk1-offline-commitment-receipt");
const casProofs = require("../crypto/rootark-zk1-offline-cas-commit-proof");

const SCOPE = ["account_id", "compartment_id", "keyring_id"];
const INFO = Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0");
const AAD = Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0");
const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/owner-v2-revocation-delivery/v1\0");
const HEAD_FIELDS = ["schema", "status", "account_id", "compartment_id", "keyring_id",
  "revision", "digest", "epoch", "previous_revision", "previous_digest",
  "operation_id", "pop_challenge_id", "request_nonce", "commit_nonce",
  "sequence", "previous_receipt_sha256", "issued_at", "expires_at"];
// Capture the built-in public-key exporter at module load. An Ed25519
// KeyObject instance is extensible: caller code can override `.export()` to
// invent an unrelated SPKI pin without changing crypto.verify's real key.
const NATIVE_PUBLIC_EXPORT = Object.getPrototypeOf(crypto.createPublicKey({
  key: Buffer.from("302a300506032b6570032100" + "00".repeat(32), "hex"),
  format: "der", type: "spki",
})).export;
function denied() { throw new Error("ZK_OWNER_V2_REVOCATION_DENIED"); }
function nativePublicSpki(value) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
    || value.asymmetricKeyType !== "ed25519") denied();
  return Buffer.from(NATIVE_PUBLIC_EXPORT.call(value, { format: "der", type: "spki" }));
}
function b64(value, size) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) denied();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== size || bytes.toString("base64url") !== value) denied();
  return bytes;
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function hash(data) { return crypto.createHash("sha256").update(data).digest(); }
function receiptHash(receipt) {
  return hash(Buffer.concat([commitment.commitmentSigningBytes(
    Object.fromEntries(commitment.FIELDS.map((name) => [name, receipt?.[name]]))),
  b64(receipt?.signature, 64)]));
}
function now() { return Math.floor(Date.now() / 1000); }
function ownerKeyMatches(privateKey, ownerPublicKey, pinnedSpki) {
  if (privateKey?.type !== "private" || privateKey.asymmetricKeyType !== "ed25519"
    || ownerPublicKey?.type !== "public" || ownerPublicKey.asymmetricKeyType !== "ed25519") denied();
  const ownerSpki = nativePublicSpki(ownerPublicKey);
  if (!crypto.KeyObject.prototype.equals.call(ownerPublicKey, crypto.createPublicKey(privateKey))
    || !same(hash(ownerSpki), b64(pinnedSpki, 32))) denied();
}
function actorDevice(prior, privateKey, revokedId) {
  if (privateKey?.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") denied();
  const raw = crypto.createPublicKey(privateKey)
    .export({ format: "der", type: "spki" }).subarray(-32);
  const actor = prior.devices.find((device) => device.revoked_at_epoch === null
    && device.device_id !== revokedId && same(device.authorization_public_key, raw));
  if (!actor) denied();
  return actor;
}
async function wrapEpoch(scope, receiverType, recipient, epoch, keyRef, epochKey) {
  const wrapId = crypto.randomBytes(16);
  const isDevice = receiverType === "device";
  const context = { suite: "rootark-zk-1",
    account_id: Buffer.from(scope.account_id), compartment_id: Buffer.from(scope.compartment_id),
    purpose: isDevice ? "key-wrap" : "recovery-package",
    recipient_type: receiverType,
    recipient_id: isDevice ? recipient.device_id : recipient.package_id,
    recipient_key_id: recipient.hpke_key_id,
    epoch, key_ref: keyRef, wrap_id: wrapId };
  const encoded = await z.encodeDeterministic(context);
  const recipientPublicKey = await z.hpkeSuite().kem.deserializePublicKey(recipient.hpke_public_key);
  const sealed = await z.hpkeSeal({ recipientPublicKey, plaintext: epochKey,
    info: Buffer.concat([INFO, encoded]), aad: Buffer.concat([AAD, encoded]) });
  return { ...(isDevice ? { device_id: recipient.device_id }
    : { package_id: recipient.package_id, hpke_key_id: recipient.hpke_key_id }),
  epoch, key_ref: keyRef, wrap_id: wrapId,
  enc: Buffer.from(sealed.enc), ciphertext: Buffer.from(sealed.ciphertext) };
}
async function executeOwnerRevocation({
  trusted, externalPins, targetDeviceId, publishCandidate,
  awaitWitnessCommitment, publishDelivery, clock = now, maxWaitMs = 300000,
}) {
  let phase = "preflight";
  let epochKey;
  try {
    if (!Number.isSafeInteger(maxWaitMs) || maxWaitMs < 10 || maxWaitMs > 300000) denied();
    const deadline = Date.now() + maxWaitMs;
    const bounded = async (operation) => {
      const ms = deadline - Date.now();
      if (ms <= 0) denied();
      let timeout;
      try {
        return await Promise.race([
          Promise.resolve().then(operation),
          new Promise((_, reject) => {
            timeout = setTimeout(() => reject(new Error("owner ceremony deadline")), ms);
          }),
        ]);
      } finally { clearTimeout(timeout); }
    };
    if (![publishCandidate, awaitWitnessCommitment, publishDelivery, clock]
      .every((fn) => typeof fn === "function") || !trusted || !externalPins
      || typeof targetDeviceId !== "string" || targetDeviceId.length < 1
      || targetDeviceId.length > 64) denied();
    if (!await history.isVerifiedTrustedDeviceRecoveryHistoryV2(trusted.verifiedHistory)) denied();
    const prior = trusted.verifiedHistory.headManifest;
    const currentDigest = await manifest.recoveryManifestDigestV2(prior);
    if (prior.revision !== externalPins.revision || prior.current_epoch !== externalPins.epoch
      || !same(currentDigest, b64(externalPins.digest, 32))
      || !same(receiptHash(trusted.trustedPriorCommitment),
        b64(externalPins.priorCommitmentSha256, 32))) denied();
    const currentTime = clock();
    if (!Number.isSafeInteger(currentTime) || Math.abs(currentTime - now()) > 30) denied();
    const target = prior.devices.find((device) => device.device_id === targetDeviceId
      && device.revoked_at_epoch === null);
    if (!target || prior.current_epoch >= 64) denied();
    if (!trusted.trustedCommitmentSignerPublicKey
      || trusted.trustedCommitmentSignerPublicKey.type !== "public"
      || trusted.trustedCommitmentSignerPublicKey.asymmetricKeyType !== "ed25519"
      || !same(hash(nativePublicSpki(trusted.trustedCommitmentSignerPublicKey)),
        b64(externalPins.witnessSpkiSha256, 32))) denied();
    if (trusted.trustedCasSignerPublicKey?.type !== "public"
      || trusted.trustedCasSignerPublicKey.asymmetricKeyType !== "ed25519"
      || !Number.isSafeInteger(externalPins.casSequence)
      || externalPins.casSequence < 1
      || !same(hash(nativePublicSpki(trusted.trustedCasSignerPublicKey)),
        b64(externalPins.casSpkiSha256, 32))
      || crypto.KeyObject.prototype.equals.call(trusted.trustedCasSignerPublicKey,
        trusted.trustedCommitmentSignerPublicKey)) denied();
    ownerKeyMatches(trusted.ownerPrivateKey, trusted.trustedOwnerPublicKey,
      externalPins.ownerSpkiSha256);
    const actor = actorDevice(prior, trusted.trustedActorPrivateKey, targetDeviceId);
    const priorHead = { revision: prior.revision, digest: currentDigest, epoch: prior.current_epoch };
    const scope = Object.fromEntries(SCOPE.map((field) => [field, Buffer.from(prior[field])]));
    // Historical receipt may have expired: verify it at its own signed time.
    commitment.verifySignedReceipt({
      receipt: trusted.trustedPriorCommitment,
      signerPublicKey: trusted.trustedCommitmentSignerPublicKey,
      independentSignerSpkiSha256: externalPins.witnessSpkiSha256,
      expectedScope: scope, expectedHead: priorHead,
      nowSeconds: trusted.trustedPriorCommitment.issued_at,
    });
    const previousKeys = trusted.verifiedHistory.epochKeys;
    if (!Array.isArray(previousKeys) || previousKeys.length !== prior.current_epoch) denied();
    const freshEpoch = prior.current_epoch + 1;
    epochKey = crypto.randomBytes(32);
    if (previousKeys.some((entry) => same(entry.key, epochKey))) denied();
    const keyRef = await manifest.recoveryKeyRefV2(scope, freshEpoch);
    const devices = prior.devices.map((device) => device.device_id === targetDeviceId
      ? { ...device, revoked_at_epoch: freshEpoch } : device);
    const survivors = devices.filter((device) => device.revoked_at_epoch === null);
    if (survivors.length < 1) denied();
    const added = [];
    for (const device of survivors) {
      added.push(await wrapEpoch(scope, "device", device, freshEpoch, keyRef, epochKey));
    }
    const authority = prior.recovery_authority;
    let recoveryAdded = [];
    if (authority?.status === "active") {
      recoveryAdded = [await wrapEpoch(scope, "recovery-package", authority,
        freshEpoch, keyRef, epochKey)];
    }
    const operationId = crypto.randomBytes(16);
    const requestNonce = crypto.randomBytes(32);
    const commitNonce = crypto.randomBytes(32);
    const issued = clock();
    if (!Number.isSafeInteger(issued) || issued < currentTime || issued > currentTime + 30
      || issued > now() + 30) denied();
    const core = { type: prior.type, version: prior.version, suite: prior.suite,
      ...scope, revision: prior.revision + 1, current_epoch: freshEpoch,
      epochs: [...prior.epochs, { epoch: freshEpoch, key_ref: keyRef }],
      devices, wraps: [...prior.wraps, ...added],
      recovery_authority: authority,
      recovery_wraps: [...prior.recovery_wraps, ...recoveryAdded],
      previous_manifest_digest: currentDigest,
      operation: { operation_id: operationId, operation_type: "revoke-device",
        actor_type: "device", actor_key_id: actor.authorization_key_id,
        target_device_id: targetDeviceId, target_device_key_digest: null,
        compromised_package_id: null, recovery_policy_change: null,
        target_epoch_coverage: [], target_pop_proof: null,
        issued_at: issued, expires_at: issued + 300,
        request_digest: Buffer.alloc(32) } };
    core.operation.request_digest = await manifest.expectedRecoveryRequestDigestV2(prior, core);
    const next = await manifest.signRecoveryTransitionV2({
      proposedCore: core, priorVerifiedHistory: trusted.verifiedHistory,
      actorPrivateKey: trusted.trustedActorPrivateKey, manifestMacKey: epochKey,
      now: issued, clockHealthy: true,
    });
    const digest = Buffer.from(await manifest.recoveryManifestDigestV2(next));
    const candidate = Object.freeze({
      schema: "rootark-zk1-owner-revocation-candidate/v1",
      signedV2Manifest: Buffer.from(await z.encodeDeterministic(next)).toString("base64url"),
      revision: next.revision, digest: digest.toString("base64url"), epoch: freshEpoch,
      previousRevision: prior.revision, previousDigest: currentDigest.toString("base64url"),
      revokedDeviceId: targetDeviceId, operationId: operationId.toString("base64url"),
      requestNonce: requestNonce.toString("base64url"), commitNonce: commitNonce.toString("base64url"),
      signedCandidateOnly: true, committed: false, ownerApproved: false,
    });
    phase = "uncommitted";
    await bounded(() => publishCandidate(candidate));
    phase = "commitment";
    const receipt = await bounded(awaitWitnessCommitment);
    const observed = clock();
    if (!Number.isSafeInteger(observed) || observed < issued || observed > issued + 300
      || observed > now() + 30) denied();
    const result = commitment.verifySignedReceipt({
      receipt, signerPublicKey: trusted.trustedCommitmentSignerPublicKey,
      independentSignerSpkiSha256: externalPins.witnessSpkiSha256,
      expectedScope: scope, expectedHead: { revision: next.revision, digest, epoch: freshEpoch },
      previousReceipt: trusted.trustedPriorCommitment, nowSeconds: observed,
    });
    if (!result.signedReceiptVerified
      || receipt.operation_id !== candidate.operationId
      || receipt.pop_challenge_id !== null
      || receipt.request_nonce !== candidate.requestNonce
      || receipt.commit_nonce !== candidate.commitNonce
      || receipt.issued_at < issued || receipt.issued_at > observed
      || receipt.revision !== prior.revision + 1
      || receipt.previous_revision !== prior.revision
      || receipt.previous_digest !== candidate.previousDigest) denied();
    // Separate current-head evidence is REQUIRED. Signed witness receipt is
    // not assumed to prove durable CAS status or independent physical custody.
    if (typeof trusted.verifyExternalCommittedCas !== "function") denied();
    const cas = await bounded(() => trusted.verifyExternalCommittedCas({
      candidate, receipt, expectedSequence: receipt.sequence, priorCommitment: trusted.trustedPriorCommitment,
    }));
    if (cas?.committed !== true || cas.independent !== true
      || cas.revision !== candidate.revision || cas.epoch !== candidate.epoch
      || cas.digest !== candidate.digest || cas.operationId !== candidate.operationId
      || cas.sequence !== receipt.sequence || cas.previousReceiptSha256 !== externalPins.priorCommitmentSha256) denied();
    // A caller-supplied {committed:true} is NOT sufficient: the CAS adapter
    // must provide an independently signed head proof verifiable under the
    // externally pinned witness key, distinct from the first commitment.
    if (!cas.signedHeadProof || cas.signedHeadProof === receipt) denied();
    const headProof = commitment.verifySignedReceipt({
      receipt: cas.signedHeadProof,
      signerPublicKey: trusted.trustedCommitmentSignerPublicKey,
      independentSignerSpkiSha256: externalPins.witnessSpkiSha256,
      expectedScope: scope, expectedHead: { revision: next.revision, digest, epoch: freshEpoch },
      previousReceipt: receipt, nowSeconds: observed,
    });
    if (!headProof.signedReceiptVerified || cas.signedHeadProof.operation_id !== candidate.operationId
      || cas.signedHeadProof.request_nonce !== candidate.requestNonce
      || cas.signedHeadProof.commit_nonce !== candidate.commitNonce
      || cas.signedHeadProof.pop_challenge_id !== null
      || cas.signedHeadProof.sequence !== receipt.sequence + 1) denied();
    if (!cas.signedCasProof) denied();
    const casVerified = casProofs.verifySignedCasProof({
      proof: cas.signedCasProof, signerPublicKey: trusted.trustedCasSignerPublicKey,
      independentSignerSpkiSha256: externalPins.casSpkiSha256, scope,
      previousHead: priorHead, committedHead: { revision: next.revision, digest, epoch: freshEpoch },
      operationId: candidate.operationId, requestNonce: candidate.requestNonce,
      commitNonce: candidate.commitNonce,
      witnessReceiptSha256: receiptHash(receipt).toString("base64url"),
      witnessSequence: receipt.sequence, minimumCasSequence: externalPins.casSequence,
      nowSeconds: observed,
    });
    if (!casVerified.independentlyPinnedCasSignatureVerified) denied();
    ownerKeyMatches(trusted.ownerPrivateKey, trusted.trustedOwnerPublicKey,
      externalPins.ownerSpkiSha256);
    const signedSurvivorGrants = survivors.map((device) => {
      const grant = {
        schema: "rootark-zk1-browser-owner-device-grant/v1",
        ...Object.fromEntries(SCOPE.map((field) => [field, scope[field].toString("base64url")])),
        device_id: device.device_id,
        authorization_key_id: Buffer.from(device.authorization_key_id).toString("base64url"),
        authorization_public_key: Buffer.from(device.authorization_public_key).toString("base64url"),
        manifest_revision: next.revision,
        manifest_digest: candidate.digest,
        current_epoch: freshEpoch,
        enrolled_epoch: device.enrolled_epoch,
        revoked_at_epoch: null,
      };
      const signature = crypto.sign(null, Buffer.concat([
        Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"),
        Buffer.from(JSON.stringify(grant))]), trusted.ownerPrivateKey);
      return { ...grant, signature: signature.toString("base64url") };
    });
    const unsigned = {
      schema: "rootark-zk1-v2-owner-revocation-delivery/v1",
      scope: Object.fromEntries(SCOPE.map((field) => [field, scope[field].toString("base64url")])),
      revokedDeviceId: targetDeviceId, revision: next.revision, epoch: freshEpoch,
      digest: candidate.digest, previousRevision: prior.revision,
      previousDigest: candidate.previousDigest, operationId: candidate.operationId,
      signedV2Manifest: candidate.signedV2Manifest,
      committedReceipt: JSON.parse(JSON.stringify(receipt)),
      signedHeadProof: JSON.parse(JSON.stringify(cas.signedHeadProof)),
      signedCasProof: JSON.parse(JSON.stringify(cas.signedCasProof)),
      signedSurvivorGrants,
      previousReceipt: JSON.parse(JSON.stringify(trusted.trustedPriorCommitment)),
      witnessSpkiSha256: externalPins.witnessSpkiSha256,
      casSpkiSha256: externalPins.casSpkiSha256,
      ownerSpkiSha256: externalPins.ownerSpkiSha256,
      authoritativeOutsideApp: true, physicalDurabilityProven: false,
      historicalCiphertextAccessRevoked: false,
    };
    const ownerSignature = crypto.sign(null, Buffer.concat([
      OWNER_DOMAIN, Buffer.from(JSON.stringify(unsigned))]), trusted.ownerPrivateKey);
    phase = "delivery";
    const delivery = Object.freeze({ ...unsigned, ownerSignature: ownerSignature.toString("base64url") });
    await bounded(() => publishDelivery(delivery));
    return Object.freeze({ completed: true, revision: next.revision, epoch: freshEpoch,
      revokedDeviceId: targetDeviceId, committedWitnessReceiptCryptographicallyVerified: true,
      externalCasSignedHeadVerified: true, independentCasSignatureVerified: true,
      physicalDurabilityProven: false,
      pastCiphertextRevocationProven: false, ownerPrivateKeyExported: false });
  } catch (_) {
    throw Object.assign(new Error("ZK_OWNER_V2_REVOCATION_DENIED"), { phase });
  } finally {
    if (epochKey) epochKey.fill(0);
  }
}
module.exports = { executeOwnerRevocation };
