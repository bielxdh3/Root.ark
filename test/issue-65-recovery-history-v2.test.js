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

test("acceptsCompleteContiguousHistoryAndExpiredCommittedTransitions", async () => {
  const scenario = await createHistory();
  const result = await h.verifyRecoveryHistoryV2(await historyInput(scenario));
  assert.equal(result.revision, scenario.state.headManifest.revision);
  assert.equal(result.transitionCount, 4);
  assert.equal(result.packageAuthorityStatus, "active");
  assert.equal(result.freshnessProven, false);
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
