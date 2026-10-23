"use strict";

// OFFLINE trusted-device owner ceremony. No server routes and no owner-key
// bootstrap from a server response. A signed candidate manifest is NOT proof
// of CAS/witness durability: commit confirmation is a separate caller step.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");
const v2 = require("./rootark-zk-recovery-manifest-v2");
const auth = require("./rootark-zk-recovery-authorization");
const history = require("./rootark-zk-recovery-history-v2");
const commitment = require("./rootark-zk1-offline-commitment-receipt");
const browserApproval = require("../../public/client/rootark-zk1-v2-device-approval");
const sessions = new WeakMap();
const staged = new WeakMap();
const usedOperations = new Set();
const scopeKeys = ["account_id", "compartment_id", "keyring_id"];
const requestKeys = ["schema", "device_id", "authorization_key_id",
  "authorization_public_key", "hpke_key_id", "hpke_public_key", "challenge", "approval"];
const requestSchema = "rootark-zk1-device-enrollment-request/v1";
const infoPrefix = Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0");
const aadPrefix = Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0");
const popInfo = Buffer.from("Root.ark/zk-1/recovery-target-pop-info/v1\0");
const popAad = Buffer.from("Root.ark/zk-1/recovery-target-pop-aad/v1\0");
const popResponse = Buffer.from("Root.ark/zk-1/recovery-target-pop-response/v1\0");
function deny() { throw Error("ZK_OWNER_OFFLINE_ENROLLMENT_DENIED"); }
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key))) deny();
}
function b64(value, len) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) deny();
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength !== len || bytes.toString("base64url") !== value) deny();
  return bytes;
}
function match(left, right) {
  return Buffer.isBuffer(left) || left instanceof Uint8Array
    ? Buffer.isBuffer(right) || right instanceof Uint8Array
      ? left.length === right.length && crypto.timingSafeEqual(Buffer.from(left), Buffer.from(right))
      : false : false;
}
function safeTime(value) {
  if (!Number.isSafeInteger(value) || value <= 0) deny();
  return value;
}
function checkedClock(value) {
  const now = safeTime(value);
  // A caller-supplied stale timestamp cannot silently extend a 5-minute
  // offline ceremony. A broken or rolled-back local clock fails closed.
  if (Math.abs(now - Math.floor(Date.now() / 1000)) > 30) deny();
  return now;
}
function ceremonyClock(value, state) {
  const now = checkedClock(value);
  const elapsedNanoseconds = process.hrtime.bigint() - state.monotonicStart;
  if (elapsedNanoseconds < 0n || elapsedNanoseconds > 300000000000n
    || now < state.now
    // Compare against an independent monotonic process clock. Merely moving
    // the wall clock backwards must not extend the challenge's live window.
    || now + 1 < state.now + Number(elapsedNanoseconds / 1000000000n)) deny();
  return now;
}
function parseRequest(request) {
  exact(request, requestKeys);
  if (request.schema !== requestSchema
    || request.approval !== "OWNER_MUST_VERIFY_IDENTITY_AND_FINISH_V2_POP_AND_SIGN_CURRENT_GRANT"
    || typeof request.device_id !== "string" || request.device_id.length < 1
    || request.device_id.length > 64) deny();
  return { device_id: request.device_id,
    hpke_key_id: b64(request.hpke_key_id, 16),
    hpke_public_key: b64(request.hpke_public_key, 32),
    authorization_key_id: b64(request.authorization_key_id, 16),
    authorization_public_key: b64(request.authorization_public_key, 32),
    challenge: b64(request.challenge, 32) };
}
function currentMatches(head, pin) {
  exact(pin, ["revision", "digest", "epoch"]);
  if (pin.revision !== head.revision || pin.epoch !== head.current_epoch
    || !match(b64(pin.digest, 32), head._digest)) deny();
}
function ownerPins(pub, externalSha256) {
  if (pub?.type !== "public" || pub.asymmetricKeyType !== "ed25519"
    || !match(crypto.createHash("sha256").update(pub.export({ type: "spki", format: "der" })).digest(),
      b64(externalSha256, 32))) deny();
}
async function beginOwnerEnrollment({ request, verifiedHistory, externalCurrentHead,
  trustedOwnerPublicKey, independentOwnerSpkiSha256,
  trustedCommitmentSignerPublicKey, independentCommitmentSignerSpkiSha256,
  trustedPriorCommitment, nowSeconds }) {
  try {
    const target = parseRequest(request);
    if (!await history.isVerifiedTrustedDeviceRecoveryHistoryV2(verifiedHistory)) deny();
    ownerPins(trustedOwnerPublicKey, independentOwnerSpkiSha256);
    const prior = verifiedHistory.headManifest;
    const digest = await v2.recoveryManifestDigestV2(prior);
    currentMatches({ ...prior, _digest: digest }, externalCurrentHead);
    if (prior.devices.some((device) => device.device_id === target.device_id
      || match(device.hpke_public_key, target.hpke_public_key)
      || match(device.authorization_public_key, target.authorization_public_key))) deny();
    const now = checkedClock(nowSeconds);
    commitment.verifySignedReceipt({ receipt: trustedPriorCommitment,
      signerPublicKey: trustedCommitmentSignerPublicKey,
      independentSignerSpkiSha256: independentCommitmentSignerSpkiSha256,
      expectedScope: prior,
      expectedHead: { revision: prior.revision, digest, epoch: prior.current_epoch },
      nowSeconds: now });
    const operationId = crypto.randomBytes(16);
    const commitmentNonce = crypto.randomBytes(32).toString("base64url");
    const challenge = await auth.createTargetPopChallenge({
      scope: Object.fromEntries(scopeKeys.map((key) => [key, prior[key]])),
      operationId, targetDeviceId: target.device_id,
      hpkeKeyId: target.hpke_key_id, hpkePublicKey: target.hpke_public_key,
      authorizationKeyId: target.authorization_key_id,
      authorizationPublicKey: target.authorization_public_key,
      issuedAt: now, expiresAt: now + 300,
    });
    const result = Object.freeze({ request, challenge, commitmentNonce });
    sessions.set(result, { target, operationId, challenge, verifiedHistory,
      trustedOwnerPublicKey, independentOwnerSpkiSha256, externalCurrentHead,
      trustedCommitmentSignerPublicKey, independentCommitmentSignerSpkiSha256,
      trustedPriorCommitment: JSON.parse(JSON.stringify(trustedPriorCommitment)),
      commitmentNonce, now, monotonicStart: process.hrtime.bigint(), completed: false });
    return result;
  } catch (_) { deny(); }
}
async function answerTargetPop({ request, challenge, deviceHpkePrivateDer,
  deviceAuthorizationPrivateDer, nowSeconds }) {
  let hpkeRaw;
  try {
    const target = parseRequest(request);
    const context = challenge.challengeContext;
    if (context.target_device_id !== target.device_id
      || !match(context.target_device_key_digest,
        await auth.recoveryTargetDeviceKeyDigest({
          deviceId: target.device_id, hpkeKeyId: target.hpke_key_id,
          hpkePublicKey: target.hpke_public_key, authorizationKeyId: target.authorization_key_id,
          authorizationPublicKey: target.authorization_public_key,
        })) || safeTime(nowSeconds) > context.expires_at) deny();
    const hpkePriv = crypto.createPrivateKey({ key: Buffer.from(deviceHpkePrivateDer),
      format: "der", type: "pkcs8" });
    const hpkePub = crypto.createPublicKey(hpkePriv).export({ format: "der", type: "spki" }).subarray(-32);
    if (!match(hpkePub, target.hpke_public_key)) deny();
    hpkeRaw = hpkePriv.export({ format: "der", type: "pkcs8" }).subarray(-32);
    const recipientKey = await z.hpkeSuite().kem.deserializePrivateKey(hpkeRaw);
    const encoded = await z.encodeDeterministic(context);
    const challengeSecret = Buffer.from(await z.hpkeOpen({ recipientKey,
      enc: challenge.enc, ciphertext: challenge.ciphertext,
      info: Buffer.concat([popInfo, encoded]), aad: Buffer.concat([popAad, encoded]) }));
    const signer = crypto.createPrivateKey({ key: Buffer.from(deviceAuthorizationPrivateDer),
      format: "der", type: "pkcs8" });
    if (!match(crypto.createPublicKey(signer).export({ format: "der", type: "spki" }).subarray(-32),
      target.authorization_public_key)) deny();
    const body = { challenge_context: context, challenge: Buffer.from(challengeSecret) };
    const signature = crypto.sign(null, Buffer.concat([popResponse,
      await z.encodeDeterministic(body)]), signer);
    challengeSecret.fill(0);
    return { ...body, target_signature: signature };
  } catch (_) { deny(); }
  finally { hpkeRaw?.fill(0); }
}
// Transfer only the encrypted one-time PoP challenge to the fresh browser.
// The original live WeakMap challenge MUST remain on the trusted owner host:
// a JSON clone returned by a browser is never a valid replacement.
function exportBrowserChallenge(prepared) {
  const state = sessions.get(prepared);
  if (!state || state.completed) deny();
  const context = state.challenge.challengeContext;
  const enc = (value) => Buffer.from(value).toString("base64url");
  return {
    schema: "rootark-zk1-v2-browser-pop-challenge/v1",
    challenge_context: Object.fromEntries(Object.entries(context).map(([key, value]) =>
      [key, Buffer.isBuffer(value) || value instanceof Uint8Array ? enc(value) : value])),
    enc: enc(state.challenge.enc), ciphertext: enc(state.challenge.ciphertext),
  };
}
async function stageBrowserPopResponse({ prepared, response, trustedActorPrivateKey, nowSeconds }) {
  try {
    const state = sessions.get(prepared);
    if (!state || state.completed) deny();
    exact(response, ["schema", "challenge_context", "challenge", "target_signature"]);
    if (response.schema !== "rootark-zk1-v2-browser-pop-response/v1") deny();
    const expected = exportBrowserChallenge(prepared).challenge_context;
    if (JSON.stringify(response.challenge_context) !== JSON.stringify(expected)) deny();
    return await stageV2Enrollment({
      prepared, trustedActorPrivateKey, nowSeconds,
      response: { challenge_context: state.challenge.challengeContext,
        challenge: b64(response.challenge, 32),
        target_signature: b64(response.target_signature, 64) },
    });
  } catch (_) { deny(); }
}
async function stageV2Enrollment({ prepared, response, trustedActorPrivateKey,
  nowSeconds }) {
  try {
    const state = sessions.get(prepared);
    if (!state || state.completed) deny();
    // Claim the one-shot challenge before the first asynchronous operation.
    // Parallel owner/offline callers cannot race two different V2 manifests
    // over the same target PoP and operation ID.
    state.completed = true;
    const now = ceremonyClock(nowSeconds, state);
    if (now < state.now || now > state.now + 300) deny();
    const { target, challenge, verifiedHistory: priorHistory } = state;
    if (!await history.isVerifiedTrustedDeviceRecoveryHistoryV2(priorHistory)) deny();
    const prior = priorHistory.headManifest;
    const scope = Object.fromEntries(scopeKeys.map((key) => [key, prior[key]]));
    const targetDigest = await auth.recoveryTargetDeviceKeyDigest({
      deviceId: target.device_id, hpkeKeyId: target.hpke_key_id,
      hpkePublicKey: target.hpke_public_key, authorizationKeyId: target.authorization_key_id,
      authorizationPublicKey: target.authorization_public_key });
    const verifiedPop = await auth.verifyTargetPopResponse({ challenge,
      challengeContext: challenge.challengeContext, response, expectedScope: scope,
      expectedDeviceKeyDigest: targetDigest, now });
    const currentActor = prior.devices.find((device) => device.revoked_at_epoch === null
      && match(crypto.createPublicKey(trustedActorPrivateKey)
        .export({ format: "der", type: "spki" }).subarray(-32),
      device.authorization_public_key));
    if (!currentActor) deny();
    const epochKeys = priorHistory.epochKeys;
    if (!Array.isArray(epochKeys) || epochKeys.length !== prior.epochs.length) deny();
    const recipientPublicKey = await z.hpkeSuite().kem.deserializePublicKey(target.hpke_public_key);
    const added = [];
    for (const epochEntry of prior.epochs) {
      const epochKey = epochKeys.find((entry) => entry.epoch === epochEntry.epoch);
      if (!epochKey || epochKey.key.byteLength !== 32) deny();
      const wrapId = crypto.randomBytes(16);
      const context = { suite: "rootark-zk-1", account_id: scope.account_id,
        compartment_id: scope.compartment_id, purpose: "key-wrap",
        recipient_type: "device", recipient_id: target.device_id,
        recipient_key_id: target.hpke_key_id, epoch: epochEntry.epoch,
        key_ref: epochEntry.key_ref, wrap_id: wrapId };
      const encoded = await z.encodeDeterministic(context);
      const sealed = await z.hpkeSeal({ recipientPublicKey, plaintext: epochKey.key,
        info: Buffer.concat([infoPrefix, encoded]), aad: Buffer.concat([aadPrefix, encoded]) });
      added.push({ device_id: target.device_id, epoch: epochEntry.epoch,
        key_ref: epochEntry.key_ref, wrap_id: wrapId,
        enc: Buffer.from(sealed.enc), ciphertext: Buffer.from(sealed.ciphertext) });
    }
    const core = { type: prior.type, version: prior.version, suite: prior.suite,
      ...scope, revision: prior.revision + 1, current_epoch: prior.current_epoch,
      epochs: prior.epochs,
      devices: [...prior.devices, { device_id: target.device_id,
        hpke_key_id: target.hpke_key_id, hpke_public_key: target.hpke_public_key,
        authorization_key_id: target.authorization_key_id,
        authorization_public_key: target.authorization_public_key,
        enrolled_epoch: prior.current_epoch, revoked_at_epoch: null }],
      wraps: [...prior.wraps, ...added],
      recovery_authority: prior.recovery_authority,
      recovery_wraps: prior.recovery_wraps,
      previous_manifest_digest: await v2.recoveryManifestDigestV2(prior),
      operation: { operation_id: state.operationId, operation_type: "enroll-device",
        actor_type: "device", actor_key_id: currentActor.authorization_key_id,
        target_device_id: target.device_id, target_device_key_digest: targetDigest,
        compromised_package_id: null, recovery_policy_change: null,
        target_epoch_coverage: prior.epochs.map((entry) => entry.epoch),
        target_pop_proof: verifiedPop, issued_at: now, expires_at: now + 300,
        request_digest: Buffer.alloc(32) } };
    core.operation.request_digest = await v2.expectedRecoveryRequestDigestV2(prior, core);
    const manifest = await v2.signRecoveryTransitionV2({ proposedCore: core,
      priorVerifiedHistory: priorHistory, actorPrivateKey: trustedActorPrivateKey,
      manifestMacKey: epochKeys.find((entry) => entry.epoch === prior.current_epoch).key,
      now, clockHealthy: true });
    const candidate = Object.freeze({ request: prepared.request, manifest,
      commitmentNonce: state.commitmentNonce });
    staged.set(candidate, { ...state, digest: await v2.recoveryManifestDigestV2(manifest),
      manifest, target, stagedAt: now, confirmed: false });
    return candidate;
  } catch (_) { deny(); }
}
async function ownerApproveCommittedEnrollment({ candidate, signedCommittedHead,
  ownerPrivateKey, nowSeconds }) {
  try {
    const state = staged.get(candidate);
    if (!state || state.confirmed) deny();
    const current = candidate.manifest;
    if (usedOperations.has(state.operationId.toString("hex"))) deny();
    const now = ceremonyClock(nowSeconds, state);
    if (now < state.stagedAt || now > state.now + 300) deny();
    // A bare self-reported revision/digest/epoch is never commitment evidence.
    // The pinned independent signer binds a fresh nonce, V2 PoP operation,
    // previous signed witness floor, exact digest and monotonic sequence.
    const commitmentProof = commitment.verifySignedReceipt({
      receipt: signedCommittedHead,
      signerPublicKey: state.trustedCommitmentSignerPublicKey,
      independentSignerSpkiSha256: state.independentCommitmentSignerSpkiSha256,
      expectedScope: current,
      expectedHead: { revision: current.revision, digest: state.digest,
        epoch: current.current_epoch },
      previousReceipt: state.trustedPriorCommitment,
      expectedOperation: { operation_id: state.operationId.toString("base64url"),
        pop_challenge_id: current.operation.target_pop_proof.challenge_context.challenge_id.toString("base64url"),
        request_nonce: state.target.challenge.toString("base64url"),
        commit_nonce: state.commitmentNonce },
      nowSeconds: now,
    });
    if (signedCommittedHead.issued_at < state.stagedAt
      || signedCommittedHead.issued_at > now) deny();
    const pub = crypto.createPublicKey(ownerPrivateKey);
    if (!match(pub.export({ format: "der", type: "spki" }),
      state.trustedOwnerPublicKey.export({ format: "der", type: "spki" }))) deny();
    ownerPins(pub, state.independentOwnerSpkiSha256);
    const grant = { schema: "rootark-zk1-browser-owner-device-grant/v1",
      ...Object.fromEntries(scopeKeys.map((key) => [key, Buffer.from(current[key]).toString("base64url")])),
      device_id: state.target.device_id,
      authorization_key_id: state.target.authorization_key_id.toString("base64url"),
      authorization_public_key: state.target.authorization_public_key.toString("base64url"),
      manifest_revision: current.revision, manifest_digest: state.digest.toString("base64url"),
      current_epoch: current.current_epoch, enrolled_epoch: current.current_epoch,
      revoked_at_epoch: null };
    const fields = Object.keys(grant);
    const payload = Buffer.from(JSON.stringify(Object.fromEntries(fields.map((key) => [key, grant[key]]))));
    grant.signature = crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/browser-owner-device-grant/v1\0"), payload]), ownerPrivateKey)
      .toString("base64url");
    // Only claim after cheap synchronous external-head/owner checks but before
    // async owner signing, so two concurrent requests cannot both approve.
    state.confirmed = true;
    const approval = await browserApproval.signOwnerApproval({
      request: candidate.request, signedDeviceGrant: grant,
      ownerPrivateKey: await crypto.webcrypto.subtle.importKey("pkcs8",
        ownerPrivateKey.export({ format: "der", type: "pkcs8" }),
        "Ed25519", false, ["sign"]),
      manifestOperationId: state.operationId.toString("base64url"),
      targetDeviceKeyDigest: current.operation.target_device_key_digest.toString("base64url"),
      popChallengeId: current.operation.target_pop_proof.challenge_context.challenge_id.toString("base64url"),
      issuedAt: now, expiresAt: now + 300,
    });
    usedOperations.add(state.operationId.toString("hex"));
    const signedV2Manifest = Buffer.from(await z.encodeDeterministic(current)).toString("base64url");
    return Object.freeze({ approval, signedDeviceGrant: grant,
      signedV2Manifest,
      // Browser transport only; its witness pubkey / SPKI and predecessor
      // commitment hash MUST still be provisioned over an independent channel.
      browserDelivery: Object.freeze({
        schema: "rootark-zk1-v2-owner-browser-delivery/v1",
        request: candidate.request, approval, signedDeviceGrant: grant,
        signedV2Manifest,
        committedReceipt: JSON.parse(JSON.stringify(signedCommittedHead)),
        previousReceipt: JSON.parse(JSON.stringify(state.trustedPriorCommitment)),
      }),
      signedCommitmentVerified: commitmentProof.signedReceiptVerified,
      commitmentSignerSpkiMatchedSuppliedPin: true,
      independentPinOriginProven: false,
      physicalDurabilityProven: false, externalCustodyProven: false,
      noServerSecretExposure: true });
  } catch (_) { deny(); }
}
module.exports = { beginOwnerEnrollment, answerTargetPop, exportBrowserChallenge,
  stageBrowserPopResponse, stageV2Enrollment, ownerApproveCommittedEnrollment };
