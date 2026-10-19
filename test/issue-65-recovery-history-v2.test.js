"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const m = require("../src/crypto/rootark-zk-recovery-manifest-v2");
const packageV1 = require("../src/crypto/rootark-zk-recovery-package-v1");
const h = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");

async function createHistory({ replacePackage = false } = {}) {
  const state = await fixtures.createInitialState(4);
  const baseManifest = state.headManifest;
  const baseAnchor = await fixtures.createWitnessAnchor(state);
  const firstPackage = await fixtures.createPackageEnvelope(state, { previousManifest: baseManifest });
  const registration = await fixtures.appendPackageActivation(state, firstPackage.envelopeBytes);
  const transitions = [registration.manifest];
  transitions.push(await fixtures.appendDeviceRevocation(state, "trusted-1"));
  transitions.push(await fixtures.appendDeviceRevocation(state, "trusted-2"));
  transitions.push(await fixtures.appendDeviceRevocation(state, "trusted-3"));
  const packageEnvelopes = [{ activationRevision: registration.manifest.revision, envelopeBytes: firstPackage.envelopeBytes }];
  let replacementPackage;
  if (replacePackage) {
    replacementPackage = await fixtures.createPackageEnvelope(state);
    const replacement = await fixtures.appendPackageActivation(state, replacementPackage.envelopeBytes, "replace-package");
    transitions.push(replacement.manifest);
    packageEnvelopes.push({ activationRevision: replacement.manifest.revision, envelopeBytes: replacementPackage.envelopeBytes });
  }
  return { state, baseManifest, baseAnchor, firstPackage, packageEnvelopes, replacementPackage, transitions };
}

async function historyInput(scenario, transitions = scenario.transitions, packageEnvelopes = scenario.packageEnvelopes) {
  const encodedTransitions = [];
  for (const transition of transitions) encodedTransitions.push(await fixtures.encodeManifest(transition));
  return {
    baseManifest: scenario.baseManifest,
    baseReceipt: scenario.baseAnchor.receipt,
    pinnedWitness: scenario.baseAnchor.pinnedWitness,
    expectedScope: scenario.state.scope,
    packageEnvelopeBytes: scenario.firstPackage.envelopeBytes,
    packageEnvelopes,
    transitions: encodedTransitions,
    epochKeys: scenario.state.epochKeys,
    now: 100_000,
  };
}

async function packageHistoryInput(scenario, transitions = scenario.transitions, packageEnvelopes = scenario.packageEnvelopes) {
  const input = await historyInput(scenario, transitions, packageEnvelopes);
  input.recoveryPackageKeys = scenario.state.recoveryPackageKeys;
  return input;
}

async function createRecoveryWrapForTest(scope, authority, epoch, keyRef, epochKey) {
  const wrapId = crypto.randomBytes(16);
  const context = {
    suite: "rootark-zk-1",
    account_id: Buffer.from(scope.account_id),
    compartment_id: Buffer.from(scope.compartment_id),
    purpose: "recovery-package",
    recipient_type: "recovery-package",
    recipient_id: Buffer.from(authority.package_id),
    recipient_key_id: Buffer.from(authority.hpke_key_id),
    epoch,
    key_ref: Buffer.from(keyRef),
    wrap_id: wrapId,
  };
  const contextBytes = await z.encodeDeterministic(context);
  const sealed = await z.hpkeSeal({
    recipientPublicKey: await z.hpkeSuite().kem.deserializePublicKey(authority.hpke_public_key),
    info: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-wrap-info/v2\0", "ascii"), contextBytes]),
    aad: Buffer.concat([Buffer.from("Root.ark/zk-1/keyring-wrap-aad/v2\0", "ascii"), contextBytes]),
    plaintext: epochKey,
  });
  return {
    package_id: Buffer.from(authority.package_id),
    hpke_key_id: Buffer.from(authority.hpke_key_id),
    epoch,
    key_ref: Buffer.from(keyRef),
    wrap_id: wrapId,
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
  };
}

async function resignCore(core, epochKey, actorPrivateKey) {
  const macInfo = await z.encodeDeterministic({
    type: "rootark-keyring-manifest-mac-info-v2",
    suite: "rootark-zk-1",
    purpose: "manifest-mac",
    account_id: core.account_id,
    compartment_id: core.compartment_id,
    current_epoch: core.current_epoch,
    revision: core.revision,
  });
  const macKey = await z.hkdfSha256({ ikm: epochKey, salt: Buffer.alloc(0), info: macInfo, length: 32 });
  const mac = crypto.createHmac("sha256", macKey).update(await z.encodeDeterministic(core)).digest();
  z.clearSecret(macKey);
  const signaturePrefix = Buffer.from("Root.ark/zk-1/recovery-manifest/v1\0", "ascii");
  const actorSignature = crypto.sign(null,
    Buffer.concat([signaturePrefix, await z.encodeDeterministic({ ...core, mac })]), actorPrivateKey);
  return { ...core, mac, actor_signature: actorSignature };
}

async function resignFirstTransition(scenario, mutateCore) {
  const core = await z.decodeDeterministic(await z.encodeDeterministic(scenario.transitions[0]));
  delete core.mac;
  delete core.actor_signature;
  await mutateCore(core);
  core.operation.request_digest = await m.expectedRecoveryRequestDigestV2(scenario.baseManifest, core);
  const epochKey = scenario.state.epochKeys.find((entry) => entry.epoch === core.current_epoch).key;
  const actorPrivateKey = scenario.state.actors.get(Buffer.from(core.operation.actor_key_id).toString("hex"));
  return resignCore(core, epochKey, actorPrivateKey);
}

test("verifiesContiguousHistoryAndExpiredCommittedTransitionsForTrustedDevice", async () => {
  const scenario = await createHistory();
  const result = await h.verifyRecoveryHistoryV2(await historyInput(scenario));
  assert.equal(result.revision, scenario.state.headManifest.revision);
  assert.equal(result.transitionCount, 4);
  assert.equal(result.packageAuthorityStatus, "active");
  assert.equal(result.freshnessProven, false);
  assert.equal(result.authorizationVerified, true);
  assert.equal(result.packageRecoverabilityVerified, false);
});

test("rejectsFreshWitnessHeadInThePackageBaseReceiptSlot", async () => {
  const scenario = await createHistory();
  const input = await historyInput(scenario);
  const base = input.baseReceipt;
  const unsigned = {
    type: "rootark-recovery-witness-head/v1",
    witness_key_id: base.witness_key_id,
    account_id: base.account_id,
    compartment_id: base.compartment_id,
    keyring_id: base.keyring_id,
    current_revision: base.revision,
    current_manifest_digest: base.manifest_digest,
    witness_sequence: base.witness_sequence,
    nonce: base.nonce,
    observed_at: base.observed_at,
    status: "committed",
    pending_reservation_id: null,
  };
  input.baseReceipt = {
    ...unsigned,
    signature: crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii"),
      await z.encodeDeterministic(unsigned),
    ]), scenario.baseAnchor.signingPrivateKey),
  };

  await assert.rejects(h.verifyRecoveryHistoryV2(input), (error) => error.code === "HISTORY_INVALID");
});

test("rejectsPendingBaseReceiptAsACommittedSnapshot", async () => {
  const scenario = await createHistory();
  const input = await historyInput(scenario);
  const unsigned = { ...input.baseReceipt, status: "pending" };
  delete unsigned.signature;
  input.baseReceipt = {
    ...unsigned,
    signature: crypto.sign(null, Buffer.concat([
      Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0", "ascii"),
      await z.encodeDeterministic(unsigned),
    ]), scenario.baseAnchor.signingPrivateKey),
  };

  await assert.rejects(h.verifyRecoveryHistoryV2(input), (error) => error.code === "HISTORY_INVALID");
});

test("packageRecoveryRequiresThePrivateKeyToVerifyNewRecoveryWraps", async () => {
  const scenario = await createHistory();
  const input = await packageHistoryInput(scenario);
  delete input.recoveryPackageKeys;

  await assert.rejects(
    h.verifyRecoveryPackageHistoryV2(input),
    (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
  );
});

test("rejectsSignedSyntheticRecoveryWrapsThatCannotDecryptTheEpochKey", async () => {
  const scenario = await createHistory();
  const malformedActivation = await resignFirstTransition(scenario, (core) => {
    core.recovery_wraps[0].enc = crypto.randomBytes(32);
    core.recovery_wraps[0].ciphertext = crypto.randomBytes(48);
  });
  const input = await packageHistoryInput(scenario, [malformedActivation]);

  await assert.rejects(
    h.verifyRecoveryPackageHistoryV2(input),
    (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
  );
});

test("rejectsRecoveryWrapOpenedByKeyUnrelatedToManifestPackagePublicKey", async () => {
  const scenario = await createHistory();
  let alternatePrivateKey;
  const mismatchedActivation = await resignFirstTransition(scenario, async (core) => {
    const alternatePair = await z.hpkeSuite().kem.generateKeyPair();
    alternatePrivateKey = Buffer.from(await z.hpkeSuite().kem.serializePrivateKey(alternatePair.privateKey));
    const alternateAuthority = {
      ...core.recovery_authority,
      hpke_public_key: Buffer.from(await z.hpkeSuite().kem.serializePublicKey(alternatePair.publicKey)),
    };
    const epoch = core.recovery_wraps[0].epoch;
    const epochKey = scenario.state.epochKeys.find((entry) => entry.epoch === epoch).key;
    core.recovery_wraps[0] = await createRecoveryWrapForTest(
      scenario.state.scope,
      alternateAuthority,
      epoch,
      core.recovery_wraps[0].key_ref,
      epochKey,
    );
  });
  const input = await packageHistoryInput(scenario, [mismatchedActivation]);
  input.recoveryPackageKeys = [{
    package_id: Buffer.from(mismatchedActivation.recovery_authority.package_id),
    hpke_key_id: Buffer.from(mismatchedActivation.recovery_authority.hpke_key_id),
    hpke_private_key: alternatePrivateKey,
  }];

  try {
    await assert.rejects(
      h.verifyRecoveryPackageHistoryV2(input),
      (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
    );
  } finally {
    z.clearSecret(alternatePrivateKey);
  }
});

test("rejectsMisboundRecoveryWrapsAfterTheTransitionIsResigned", async () => {
  const scenario = await createHistory();
  const mutations = [
    (core) => {
      core.recovery_wraps[0].enc = crypto.randomBytes(32);
      core.recovery_wraps[0].ciphertext = crypto.randomBytes(48);
    },
    (core) => {
      const enc = Buffer.from(core.recovery_wraps[0].enc);
      enc[0] ^= 0xff;
      core.recovery_wraps[0].enc = enc;
    },
    (core) => { core.recovery_wraps[0].package_id = Buffer.alloc(16, 0xff); },
    (core) => { core.recovery_wraps[0].epoch = 2; },
    (core) => { core.recovery_wraps[0].key_ref = Buffer.alloc(32, 0xff); },
  ];

  for (const mutateCore of mutations) {
    const malformedActivation = await resignFirstTransition(scenario, mutateCore);
    const input = await packageHistoryInput(scenario, [malformedActivation]);
    await assert.rejects(
      h.verifyRecoveryPackageHistoryV2(input),
      (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
    );
  }
});

test("requiresEveryHistoricalEpochKeyForRecoveryCoverage", async () => {
  const scenario = await createHistory();
  const input = await historyInput(scenario);
  input.epochKeys = [];

  await assert.rejects(
    h.verifyRecoveryHistoryV2(input),
    (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
  );
});

test("rejectsAnEpochKeyAppendedToAHistoryVerifierResult", async () => {
  const scenario = await createHistory();
  const result = await h.verifyRecoveryHistoryV2(await historyInput(scenario));
  result.epochKeys.push({ epoch: 99, key: Buffer.alloc(32, 0x99) });
  assert.equal(await h.isVerifiedRecoveryHistoryV2(result), false);
});

test("rejectsMissingReorderedDuplicateAlteredAndTruncatedTransitions", async () => {
  const scenario = await createHistory();
  const valid = await historyInput(scenario);
  const failHistory = async (entries) => h.verifyRecoveryHistoryV2({ ...valid, transitions: entries });

  await assert.rejects(failHistory(valid.transitions.slice(1)), (error) => error.code === "HISTORY_INVALID");
  await assert.rejects(failHistory([...valid.transitions].reverse()), (error) => error.code === "HISTORY_INVALID");
  await assert.rejects(failHistory([...valid.transitions, valid.transitions[0]]), (error) => error.code === "HISTORY_INVALID");

  const altered = [...valid.transitions];
  const modified = await z.decodeDeterministic(altered[1]);
  modified.actor_signature = Buffer.alloc(64, 0xff);
  altered[1] = await z.encodeDeterministic(modified);
  await assert.rejects(failHistory(altered), (error) => error.code === "HISTORY_INVALID");

  const truncated = [...valid.transitions];
  truncated[0] = truncated[0].subarray(0, truncated[0].byteLength - 1);
  await assert.rejects(failHistory(truncated), (error) => error.code === "HISTORY_INVALID");
});

test("rejectsOperationIdentifierReuseEvenWhenTheAttackerResigns", async () => {
  const scenario = await createHistory();
  const valid = await historyInput(scenario);
  const previous = scenario.transitions[1];
  const reused = await z.decodeDeterministic(valid.transitions[2]);
  reused.operation.operation_id = Buffer.from(scenario.transitions[0].operation.operation_id);
  reused.operation.request_digest = Buffer.alloc(32);
  reused.operation.request_digest = await m.expectedRecoveryRequestDigestV2(previous, (() => {
    const core = { ...reused };
    delete core.mac;
    delete core.actor_signature;
    return core;
  })());
  const epochKey = scenario.state.epochKeys.find((entry) => entry.epoch === reused.current_epoch).key;
  const actor = scenario.state.actors.get(previous.devices[0].authorization_key_id.toString("hex"));
  valid.transitions[2] = await z.encodeDeterministic(await resignCore((() => {
    const core = { ...reused };
    delete core.mac;
    delete core.actor_signature;
    return core;
  })(), epochKey, actor));
  await assert.rejects(h.verifyRecoveryHistoryV2(valid), (error) => error.code === "HISTORY_INVALID");
});

test("rejectsAValidButDifferentEnvelopeUnderTheSamePackageId", async () => {
  const scenario = await createHistory();
  const changed = await fixtures.createPackageEnvelope(scenario.state, {
    previousManifest: scenario.baseManifest,
    operationId: scenario.firstPackage.envelope.operation_id,
    packageId: scenario.firstPackage.envelope.package_id,
    activationContextDigest: scenario.firstPackage.envelope.activation_context_digest,
  });
  const input = await historyInput(scenario);
  input.packageEnvelopeBytes = changed.envelopeBytes;
  input.packageEnvelopes = [{ activationRevision: scenario.transitions[0].revision, envelopeBytes: changed.envelopeBytes }];
  await assert.rejects(h.verifyRecoveryHistoryV2(input), (error) => error.code === "INVALID_RECOVERY_PACKAGE");
});

test("marksTheOriginalRecoveryPackageRevokedAfterSignedReplacement", async () => {
  const scenario = await createHistory({ replacePackage: true });
  const result = await h.verifyRecoveryHistoryV2(await historyInput(scenario));
  assert.equal(result.packageAuthorityStatus, "revoked");
  assert.equal(Buffer.from(result.headManifest.recovery_authority.package_id)
    .equals(Buffer.from(scenario.firstPackage.envelope.package_id)), false);
});

test("recoversRotatedEpochFromPackageWrapWithoutFutureKeyInput", async () => {
  const scenario = await createHistory();
  const input = await packageHistoryInput(scenario);
  input.epochKeys = scenario.state.epochKeys.filter((entry) => entry.epoch <= scenario.baseManifest.current_epoch);

  const result = await h.verifyRecoveryPackageHistoryV2(input);
  assert.equal(result.headManifest.current_epoch, scenario.state.headManifest.current_epoch);
  assert.deepEqual(result.epochKeys.map((entry) => entry.epoch), [1, 2, 3, 4]);
  for (const expected of scenario.state.epochKeys) {
    assert.deepEqual(result.epochKeys.find((entry) => entry.epoch === expected.epoch).key, expected.key);
  }
  assert.equal(result.packageRecoverabilityVerified, true);
});

test("packageRecoveryRejectsAnOpenedButUnauthenticatedFutureEpochKey", async () => {
  const scenario = await createHistory();
  const wrongEpochKey = Buffer.alloc(32, 0xee);
  const changed = await z.decodeDeterministic(await fixtures.encodeManifest(scenario.transitions[1]));
  delete changed.mac;
  delete changed.actor_signature;
  const wrapIndex = changed.recovery_wraps.findIndex((wrap) => wrap.epoch === 2);
  assert.notEqual(wrapIndex, -1);
  changed.recovery_wraps[wrapIndex] = await createRecoveryWrapForTest(
    scenario.state.scope,
    changed.recovery_authority,
    2,
    changed.recovery_wraps[wrapIndex].key_ref,
    wrongEpochKey,
  );
  const actor = scenario.state.actors.get(Buffer.from(changed.operation.actor_key_id).toString("hex"));
  const signed = await resignCore(changed, scenario.state.epochKeys.find((entry) => entry.epoch === 2).key, actor);
  const input = await packageHistoryInput(scenario);
  input.epochKeys = scenario.state.epochKeys.filter((entry) => entry.epoch <= scenario.baseManifest.current_epoch);
  input.transitions[1] = await fixtures.encodeManifest(signed);

  try {
    await assert.rejects(
      h.verifyRecoveryPackageHistoryV2(input),
      (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID",
    );
  } finally {
    z.clearSecret(wrongEpochKey);
  }
});

test("trustedDeviceHistoryVerifiesAndSignsWithoutRecoveryPackagePrivateKey", async () => {
  const scenario = await createHistory();
  const input = await historyInput(scenario);

  const result = await h.verifyTrustedDeviceRecoveryHistoryV2(input);
  assert.equal(result.packageRecoverabilityVerified, false);
  assert.equal(result.authorizationVerified, true);
  assert.equal(await h.isVerifiedRecoveryPackageHistoryV2(result), false);

  const prepared = await fixtures.prepareDeviceRevocation(scenario.state, "trusted-0");
  const actorId = scenario.state.headManifest.devices.find((device) => device.device_id === "trusted-0").authorization_key_id;
  const signed = await m.signRecoveryTransitionV2({
    proposedCore: prepared.core,
    priorVerifiedHistory: result,
    actorPrivateKey: scenario.state.actors.get(Buffer.from(actorId).toString("hex")),
    manifestMacKey: prepared.newKey,
    now: 1100,
    clockHealthy: true,
  });
  assert.equal(signed.operation.operation_type, "revoke-device");
  assert.equal(signed.operation.actor_type, "device");
});

test("publicSignedStateValidationCannotBeClaimedAsAuthorizationOrPackageRecovery", async () => {
  const scenario = await createHistory();
  const input = await historyInput(scenario);
  delete input.epochKeys;

  const result = await h.verifyRecoveryHistoryPublicV2(input);
  assert.equal(result.signedStateVerified, true);
  assert.equal(result.authorizationVerified, false);
  assert.equal(result.packageRecoverabilityVerified, false);
  assert.equal(Object.hasOwn(result, "epochKeys"), false);
  assert.equal(await h.isVerifiedPublicRecoveryHistoryV2(result), true);
  assert.equal(await h.isVerifiedRecoveryHistoryV2(result), false);

  const secretBearingInput = { ...input, epochKeys: scenario.state.epochKeys };
  await assert.rejects(h.verifyRecoveryHistoryPublicV2(secretBearingInput),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID");

  const prepared = await fixtures.prepareDeviceRevocation(scenario.state, "trusted-0");
  const actorId = scenario.state.headManifest.devices.find((device) => device.device_id === "trusted-0").authorization_key_id;
  await assert.rejects(m.signRecoveryTransitionV2({
    proposedCore: prepared.core,
    priorVerifiedHistory: result,
    actorPrivateKey: scenario.state.actors.get(Buffer.from(actorId).toString("hex")),
    manifestMacKey: prepared.newKey,
    now: 1100,
    clockHealthy: true,
  }), (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_INVALID");
});

test("packageRecoveryRejectsFutureEpochKeysSuppliedInsteadOfOpeningWraps", async () => {
  const scenario = await createHistory();
  const input = await packageHistoryInput(scenario);

  await assert.rejects(
    h.verifyRecoveryPackageHistoryV2(input),
    (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
  );
});
