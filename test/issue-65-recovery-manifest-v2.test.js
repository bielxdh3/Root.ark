"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const m = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const packageV1 = require("../src/crypto/rootark-zk-recovery-package-v1");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");

const OPERATIONS = [
  "initialize", "enroll-device", "revoke-device", "register-package",
  "replace-package", "revoke-package", "recover-device", "compromise-package",
];

test("rejectsEveryDisallowedActorOperationPair", () => {
  for (const operationType of OPERATIONS) {
    const deviceAllowed = operationType !== "revoke-package";
    const packageAllowed = operationType === "recover-device";
    if (deviceAllowed) assert.doesNotThrow(() => m.assertRecoveryActorOperation("device", operationType));
    else assert.throws(
      () => m.assertRecoveryActorOperation("device", operationType),
      (error) => error instanceof z.RootarkZkError && error.code === "UNAUTHORIZED_ACTOR",
    );
    if (packageAllowed) assert.doesNotThrow(() => m.assertRecoveryActorOperation("recovery-package", operationType));
    else assert.throws(
      () => m.assertRecoveryActorOperation("recovery-package", operationType),
      (error) => error instanceof z.RootarkZkError && error.code === "UNAUTHORIZED_ACTOR",
    );
  }
  assert.throws(
    () => m.assertRecoveryActorOperation("device", "admin-reset"),
    (error) => error instanceof z.RootarkZkError && error.code === "UNKNOWN_RECOVERY_OPERATION",
  );
});
test("rejectsUnknownOperationAndAdmissionClockBoundary", () => {
  assert.equal(m.verifyRecoveryAdmissionWindowV2({ issuedAt: 1000, expiresAt: 1300, now: 970, clockHealthy: true }), true);
  assert.equal(m.verifyRecoveryAdmissionWindowV2({ issuedAt: 1000, expiresAt: 1300, now: 1300, clockHealthy: true }), true);
  for (const input of [
    { issuedAt: 1000, expiresAt: 1300, now: 969, clockHealthy: true },
    { issuedAt: 1000, expiresAt: 1300, now: 1301, clockHealthy: true },
    { issuedAt: 1000, expiresAt: 1300, now: 1000, clockHealthy: false },
    { issuedAt: 1000, expiresAt: 1301, now: 1000, clockHealthy: true },
    { issuedAt: 1000, expiresAt: 1000, now: 1000, clockHealthy: true },
  ]) {
    assert.throws(
      () => m.verifyRecoveryAdmissionWindowV2(input),
      (error) => error instanceof z.RootarkZkError && error.code === "AUTHORIZATION_EXPIRED",
    );
  }
  assert.throws(
    () => m.assertRecoveryActorOperation("device", "unknown-operation"),
    (error) => error.code === "UNKNOWN_RECOVERY_OPERATION",
  );
});

test("manifestAndRequestDigestsAreDomainSeparatedAndDeterministic", async () => {
  const value = { revision: 3, account_id: Buffer.alloc(16, 4), operation_id: Buffer.alloc(16, 9) };
  const encoded = await z.encodeDeterministic(value);
  const manifestDigest = await m.recoveryManifestDigestV2(value);
  const requestDigest = await m.recoveryRequestDigestV2(value);
  const expectedManifest = crypto.createHash("sha256")
    .update("Root.ark/zk-1/recovery-manifest-digest/v1\0", "ascii")
    .update(encoded).digest();
  const expectedRequest = crypto.createHash("sha256")
    .update("Root.ark/zk-1/recovery-cas-request/v2\0", "ascii")
    .update(encoded).digest();
  assert.deepEqual(manifestDigest, expectedManifest);
  assert.deepEqual(requestDigest, expectedRequest);
  assert.notDeepEqual(manifestDigest, requestDigest);
});

test("signingRejectsAnAlteredPriorHistoryDigest", async () => {
  const state = await fixtures.createInitialState();
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-1");
  const prior = state.verifiedHistory;
  prior.headDigest[0] ^= 0xff;
  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore: prepared.core,
      priorVerifiedHistory: prior,
      actorPrivateKey: state.actors.get(state.headManifest.devices[0].authorization_key_id.toString("hex")),
      manifestMacKey: prepared.newKey,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );
});

test("signingRejectsAnActorWhoIsNotAuthorizedByThePriorState", async () => {
  const state = await fixtures.createInitialState(2);
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-1");
  const prior = state.verifiedHistory;
  const targetActor = state.actors.get(state.headManifest.devices[1].authorization_key_id.toString("hex"));

  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore: prepared.core,
      priorVerifiedHistory: prior,
      actorPrivateKey: targetActor,
      manifestMacKey: prepared.newKey,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );
});

test("signingRejectsCallerConstructedPriorHistoryWithoutVerifierBrand", async () => {
  const state = await fixtures.createInitialState(1);
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-0");
  const forgedPrior = {
    complete: true,
    headManifest: state.headManifest,
    headDigest: await m.recoveryManifestDigestV2(state.headManifest),
    revision: state.headManifest.revision,
    usedIdentifiers: new Set(state.usedIdentifiers),
    epochKeys: [...state.epochKeys],
  };
  const actor = state.actors.get(state.headManifest.devices[0].authorization_key_id.toString("hex"));

  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore: prepared.core,
      priorVerifiedHistory: forgedPrior,
      actorPrivateKey: actor,
      manifestMacKey: prepared.newKey,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );
});

test("signingRejectsTargetTranscriptWithoutLiveChallengeVerification", async () => {
  const state = await fixtures.createInitialState(1);
  const prior = state.verifiedHistory;
  const previous = prior.headManifest;
  const next = await fixtures.appendDeviceEnrollment(state, 1);
  const proposedCore = await z.decodeDeterministic(await fixtures.encodeManifest(next));
  delete proposedCore.mac;
  delete proposedCore.actor_signature;
  proposedCore.operation.target_pop_proof = {
    ...proposedCore.operation.target_pop_proof,
    challenge_context: { ...proposedCore.operation.target_pop_proof.challenge_context },
  };

  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore,
      priorVerifiedHistory: prior,
      actorPrivateKey: state.actors.get(previous.devices[0].authorization_key_id.toString("hex")),
      manifestMacKey: prior.epochKeys[0].key,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP",
  );
});

test("signingRejectsMutationOfALocallyVerifiedTargetChallenge", async () => {
  const state = await fixtures.createInitialState(1);
  const prior = state.verifiedHistory;
  const previous = prior.headManifest;
  const next = await fixtures.appendDeviceEnrollment(state, 1);
  const proposedCore = { ...next };
  delete proposedCore.mac;
  delete proposedCore.actor_signature;
  proposedCore.operation.target_pop_proof.ciphertext[0] ^= 0xff;
  proposedCore.operation.request_digest = await m.expectedRecoveryRequestDigestV2(previous, proposedCore);

  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore,
      priorVerifiedHistory: prior,
      actorPrivateKey: state.actors.get(previous.devices[0].authorization_key_id.toString("hex")),
      manifestMacKey: prior.epochKeys[0].key,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "INVALID_TARGET_POP",
  );
});

test("signsAValidPriorStateDeviceRevocationAtTheNextRevision", async () => {
  const state = await fixtures.createInitialState();
  const previousRevision = state.headManifest.revision;
  const manifest = await fixtures.appendDeviceRevocation(state, "trusted-1");
  assert.equal(manifest.revision, previousRevision + 1);
  assert.equal(manifest.current_epoch, 2);
  assert.equal(manifest.devices.find((device) => device.device_id === "trusted-1").revoked_at_epoch, 2);
});

test("rejectsAnEpochRotationThatReusesAnyPriorEpochKey", async () => {
  const state = await fixtures.createInitialState();
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-1");
  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore: prepared.core,
      priorVerifiedHistory: state.verifiedHistory,
      actorPrivateKey: state.actors.get(state.headManifest.devices[0].authorization_key_id.toString("hex")),
      manifestMacKey: state.epochKeys[0].key,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );
});

test("cannotRevokeTheFinalDeviceWithoutAnActiveRecoveryPackage", async () => {
  const state = await fixtures.createInitialState(1);
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-0");
  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore: prepared.core,
      priorVerifiedHistory: state.verifiedHistory,
      actorPrivateKey: state.actors.get(state.headManifest.devices[0].authorization_key_id.toString("hex")),
      manifestMacKey: prepared.newKey,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "COMPROMISE_RECOVERY_UNAVAILABLE",
  );
});

test("rejectsAChangedActorSignatureScopeAndManifestMac", async () => {
  const state = await fixtures.createInitialState();
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-1");
  const actor = state.actors.get(state.headManifest.devices[0].authorization_key_id.toString("hex"));
  const manifest = await m.signRecoveryTransitionV2({
    proposedCore: prepared.core,
    priorVerifiedHistory: state.verifiedHistory,
    actorPrivateKey: actor,
    manifestMacKey: prepared.newKey,
    now: 1100,
    clockHealthy: true,
  });
  const verificationInput = {
    previousManifest: state.headManifest,
    nextManifest: manifest,
    expectedScope: state.scope,
    retainedIdentifiers: { complete: true, values: new Set(state.usedIdentifiers) },
    priorEpochKeys: state.epochKeys,
  };
  const proof = await m.verifyRecoveryTransitionPublicV2(verificationInput);
  await assert.rejects(
    m.verifyRecoveryTransitionMacV2({
      publicTransitionProof: proof,
      manifestMacKey: Buffer.alloc(32, 0xff),
      priorEpochKeys: state.epochKeys,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );

  const changedSignature = { ...manifest, actor_signature: Buffer.from(manifest.actor_signature) };
  changedSignature.actor_signature[0] ^= 1;
  await assert.rejects(
    m.verifyRecoveryTransitionPublicV2({ ...verificationInput, nextManifest: changedSignature }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );
  await assert.rejects(
    m.verifyRecoveryTransitionPublicV2({
      ...verificationInput,
      expectedScope: { ...state.scope, account_id: Buffer.alloc(16, 0xff) },
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "SCOPE_MISMATCH",
  );
});

test("transitionRejectsAnOperationIdAlreadyConsumedByPriorHistory", async () => {
  const state = await fixtures.createInitialState();
  const reusedOperationId = state.headManifest.operation.operation_id;
  const prepared = await fixtures.prepareDeviceRevocation(state, "trusted-1", reusedOperationId);
  await assert.rejects(
    m.signRecoveryTransitionV2({
      proposedCore: prepared.core,
      priorVerifiedHistory: state.verifiedHistory,
      actorPrivateKey: state.actors.get(state.headManifest.devices[0].authorization_key_id.toString("hex")),
      manifestMacKey: prepared.newKey,
      now: 1100,
      clockHealthy: true,
    }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
  );
});

test("rejectsReusedIdentifiersFromPriorHistoryInventory", async () => {
  const state = await fixtures.createInitialState(1);
  const id = (kind, value) => `${kind}:${Buffer.from(value).toString("hex")}`;
  const assertCollisions = async (previous, next, priorIdentifiers, priorEpochKeys, candidates) => {
    for (const candidate of candidates) {
      const values = new Set(priorIdentifiers);
      values.add(candidate);
      await assert.rejects(
        m.verifyRecoveryTransitionPublicV2({
          previousManifest: previous,
          nextManifest: next,
          expectedScope: state.scope,
          retainedIdentifiers: { complete: true, values },
          priorEpochKeys,
        }),
        (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
        `accepted reused identifier ${candidate}`,
      );
    }
  };

  const previousDeviceState = state.headManifest;
  const priorDeviceIdentifiers = new Set(state.verifiedHistory.usedIdentifiers);
  const priorDeviceKeys = state.verifiedHistory.epochKeys;
  const enrollment = await fixtures.appendDeviceEnrollment(state, 1);
  const enrolledDevice = enrollment.devices.at(-1);
  const deviceWraps = enrollment.wraps.slice(previousDeviceState.wraps.length);
  await assertCollisions(previousDeviceState, enrollment, priorDeviceIdentifiers, priorDeviceKeys, [
    id("operation", enrollment.operation.operation_id),
    `device-name:${enrolledDevice.device_id}`,
    id("key", enrolledDevice.hpke_key_id),
    id("key", enrolledDevice.authorization_key_id),
    id("x25519-public", enrolledDevice.hpke_public_key),
    id("ed25519-public", enrolledDevice.authorization_public_key),
    id("challenge", enrollment.operation.target_pop_proof.challenge_context.challenge_id),
    ...deviceWraps.map((wrap) => id("wrap", wrap.wrap_id)),
  ]);

  const previousPackageState = state.headManifest;
  const priorPackageIdentifiers = new Set(state.verifiedHistory.usedIdentifiers);
  const priorPackageKeys = state.verifiedHistory.epochKeys;
  const packageFixture = await fixtures.createPackageEnvelope(state);
  const activation = await fixtures.appendPackageActivation(state, packageFixture.envelopeBytes);
  const authority = activation.manifest.recovery_authority;
  const recoveryWraps = activation.manifest.recovery_wraps.slice(previousPackageState.recovery_wraps.length);
  await assertCollisions(previousPackageState, activation.manifest, priorPackageIdentifiers, priorPackageKeys, [
    id("operation", activation.manifest.operation.operation_id),
    id("package", authority.package_id),
    id("key", authority.hpke_key_id),
    id("key", authority.authorization_key_id),
    id("x25519-public", authority.hpke_public_key),
    id("ed25519-public", authority.authorization_public_key),
    ...recoveryWraps.map((wrap) => id("wrap", wrap.wrap_id)),
  ]);
});

test("bindsVerifiedPackageActivationToTheExactEnvelopeBytes", async () => {
  const state = await fixtures.createInitialState();
  const prior = state.headManifest;
  const priorIdentifiers = new Set(state.usedIdentifiers);
  const packageFixture = await fixtures.createPackageEnvelope(state, { previousManifest: prior });
  const activation = await fixtures.appendPackageActivation(state, packageFixture.envelopeBytes);
  const proof = await m.verifyRecoveryTransitionPublicV2({
    previousManifest: prior,
    nextManifest: activation.manifest,
    expectedScope: state.scope,
    retainedIdentifiers: { complete: true, values: priorIdentifiers },
  });
  assert.equal(await packageV1.verifyRecoveryPackageActivation({
    publicTransitionProof: proof,
    envelopeBytes: packageFixture.envelopeBytes,
  }), true);

  const changed = Buffer.from(packageFixture.envelopeBytes);
  changed[changed.length - 1] ^= 1;
  await assert.rejects(
    packageV1.verifyRecoveryPackageActivation({ publicTransitionProof: proof, envelopeBytes: changed }),
    (error) => error instanceof z.RootarkZkError && error.code === "INVALID_RECOVERY_PACKAGE",
  );

  activation.manifest.recovery_authority.package_envelope_digest[0] ^= 1;
  await assert.rejects(
    packageV1.verifyRecoveryPackageActivation({ publicTransitionProof: proof, envelopeBytes: packageFixture.envelopeBytes }),
    (error) => error instanceof z.RootarkZkError && error.code === "INVALID_RECOVERY_PACKAGE",
  );
});
