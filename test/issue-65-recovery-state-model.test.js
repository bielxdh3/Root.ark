"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { FakeRecoveryStateModel } = require("./support/issue-65-recovery-state-model");

const SCOPE = Object.freeze({
  accountId: Buffer.alloc(16, 0x31),
  compartmentId: Buffer.from("mock-compartment"),
  keyringId: Buffer.alloc(16, 0x32),
});

function createModel(options = {}) {
  return new FakeRecoveryStateModel({
    scope: SCOPE,
    initialRevision: 7,
    initialEpoch: 2,
    activeDeviceIds: ["trusted-a", "trusted-b"],
    recoveryPackageId: "package-old",
    now: 1000,
    ...options,
  });
}

function revokeTransition(operationByte = 1, overrides = {}) {
  return {
    scope: SCOPE,
    operationId: Buffer.alloc(16, operationByte),
    requestBytes: Buffer.from(`signed-revoke-${operationByte}`),
    expectedRevision: 7,
    operationType: "revoke-device",
    actorId: "trusted-a",
    targetDeviceId: "trusted-b",
    issuedAt: 1000,
    expiresAt: 1300,
    ...overrides,
  };
}

function expectCode(expected) {
  return (error) => error && error.code === expected;
}

test("mockOnlyModelMakesNoRealProviderOrDeploymentClaim", (t) => {
  t.diagnostic("mock-only: in-memory contract simulation; no real CAS, witness, status authority, admission, or crash-recovery evidence");
  assert.equal(FakeRecoveryStateModel.name, "FakeRecoveryStateModel");
});

test("pendingRevocationBlocksRestoredOldHeadAfterCasCommit", async () => {
  let model = createModel();
  const ticket = model.reserveTransition(revokeTransition());

  assert.throws(
    () => model.admitRead({ revision: 7, actorId: "trusted-a" }),
    expectCode("PENDING_RESERVATION"),
  );
  assert.throws(
    () => model.admitWrite({ revision: 7, actorId: "trusted-a" }),
    expectCode("PENDING_RESERVATION"),
  );
  assert.throws(
    () => model.admitRead({ revision: 7, actorId: "trusted-b" }),
    expectCode("PENDING_RESERVATION"),
  );
  model.commitCas(ticket);
  model = model.restart({ restoreApplicationRevision: 7 });
  const resumedTicket = model.resumeReservation(ticket.reservationId);

  assert.throws(
    () => model.admitRead({ revision: 7, actorId: "trusted-a" }),
    expectCode("PENDING_RESERVATION"),
  );
  assert.throws(
    () => model.admitRead({ revision: 8, actorId: "trusted-a" }),
    expectCode("PENDING_RESERVATION"),
  );

  const receipt = model.issueTerminalStatusReceipt(resumedTicket);
  model.resolveReservation(resumedTicket, receipt);
  assert.throws(
    () => model.admitRead({ revision: 7, actorId: "trusted-a" }),
    expectCode("STALE_HEAD"),
  );
  assert.throws(
    () => model.admitRead({ revision: 8, actorId: "trusted-b" }),
    expectCode("UNAUTHORIZED_ACTOR"),
  );
  assert.equal(await model.admitRead({ revision: 8, actorId: "trusted-a" }), true);
});

test("witnessOutageAndRestartPreservePendingGate", async () => {
  let model = createModel();
  const ticket = model.reserveTransition(revokeTransition());
  model = model.restart({ restoreApplicationRevision: 7, witnessAvailable: false });

  assert.throws(
    () => model.admitRead({ revision: 7, actorId: "trusted-a" }),
    expectCode("WITNESS_UNAVAILABLE"),
  );
  model.setWitnessAvailable(true);
  assert.throws(
    () => model.admitWrite({ revision: 7, actorId: "trusted-a" }),
    expectCode("PENDING_RESERVATION"),
  );
  model.setStatusAuthorityAvailable(false);
  assert.throws(
    () => model.issueTerminalStatusReceipt(ticket),
    expectCode("STATUS_AUTHORITY_UNAVAILABLE"),
  );
  model.setStatusAuthorityAvailable(true);
  assert.equal(model.pendingReservationId, ticket.reservationId);
});

test("onlyExactCommittedOrFinalNoCommitProofResolvesReservation", async () => {
  const committedModel = createModel();
  const committedTicket = committedModel.reserveTransition(revokeTransition(1));
  committedModel.commitCas(committedTicket);
  const committedProof = committedModel.issueTerminalStatusReceipt(committedTicket);
  assert.equal(committedModel.resolveReservation(committedTicket, committedProof), "committed");

  const cancelledModel = createModel();
  const cancelledTicket = cancelledModel.reserveTransition(revokeTransition(2));
  assert.throws(
    () => cancelledModel.issueTerminalStatusReceipt(cancelledTicket),
    expectCode("RESERVATION_UNRESOLVED"),
  );
  cancelledModel.advanceClock(1329);
  assert.throws(
    () => cancelledModel.issueTerminalStatusReceipt(cancelledTicket),
    expectCode("RESERVATION_UNRESOLVED"),
  );
  cancelledModel.advanceClock(1330);
  const lostNoCommitProof = cancelledModel.issueTerminalStatusReceipt(cancelledTicket);
  assert.equal(lostNoCommitProof.status, "not-committed");
  const retriedNoCommitProof = cancelledModel.issueTerminalStatusReceipt(cancelledTicket);
  assert.equal(retriedNoCommitProof.status, "not-committed");
  assert.equal(cancelledModel.resolveReservation(cancelledTicket, retriedNoCommitProof), "cancelled");
  assert.equal(cancelledModel.freshHeadReadRevision, 7);
  assert.throws(
    () => cancelledModel.commitCas(cancelledTicket),
    expectCode("IDEMPOTENCY_CONFLICT"),
  );
  const restartedAfterCancel = cancelledModel.restart({ restoreApplicationRevision: 7 });
  assert.equal(restartedAfterCancel.freshHeadReadRevision, 7);
  assert.equal(await restartedAfterCancel.admitRead({ revision: 7, actorId: "trusted-a" }), true);
});

test("rejectsStaleOrWrongScopeTerminalReceipt", async () => {
  const model = createModel();
  const ticket = model.reserveTransition(revokeTransition());
  model.commitCas(ticket);

  const wrongScope = model.issueTerminalStatusReceipt(ticket);
  wrongScope.scope.accountId[0] ^= 0xff;
  assert.throws(() => model.resolveReservation(ticket, wrongScope), expectCode("INVALID_STATUS_PROOF"));

  const staleHead = model.issueTerminalStatusReceipt(ticket);
  staleHead.headRevision -= 1;
  assert.throws(() => model.resolveReservation(ticket, staleHead), expectCode("INVALID_STATUS_PROOF"));

  const staleNonce = model.issueTerminalStatusReceipt(ticket);
  staleNonce.nonce[0] ^= 0xff;
  assert.throws(() => model.resolveReservation(ticket, staleNonce), expectCode("INVALID_STATUS_PROOF"));

  const appServerAssertion = { ...model.issueTerminalStatusReceipt(ticket), source: "application-server" };
  assert.throws(() => model.resolveReservation(ticket, appServerAssertion), expectCode("INVALID_STATUS_PROOF"));
  assert.equal(model.pendingReservationId, ticket.reservationId);
  assert.equal(model.resolveReservation(ticket, model.issueTerminalStatusReceipt(ticket)), "committed");
});

test("sameOperationExactBytesAreIdempotentButChangedBytesConflict", () => {
  const model = createModel();
  const first = revokeTransition(1);
  const original = model.reserveTransition(first);
  const retry = model.reserveTransition({ ...first, operationId: Buffer.from(first.operationId), requestBytes: Buffer.from(first.requestBytes) });
  assert.equal(retry.reservationId, original.reservationId);

  assert.throws(
    () => model.reserveTransition({ ...first, requestBytes: Buffer.from("different signed bytes") }),
    expectCode("IDEMPOTENCY_CONFLICT"),
  );
});

test("concurrentWritersHaveOneWinner", async () => {
  const model = createModel();
  const results = await Promise.allSettled([
    Promise.resolve().then(() => model.reserveTransition(revokeTransition(1))),
    Promise.resolve().then(() => model.reserveTransition(revokeTransition(2))),
  ]);

  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.find((result) => result.status === "rejected");
  assert.equal(rejected.reason.code, "PENDING_RESERVATION");
});

test("compromiseRotationNeverPromotesOnUncertainCasOrLosesFinalPath", async () => {
  let model = createModel();
  const compromise = {
    ...revokeTransition(3),
    operationType: "compromise-package",
    targetDeviceId: null,
    compromisedPackageId: "package-old",
    replacementPackageId: "package-new",
    priorEpochsAvailable: [1, 2],
    recoveryWrapPackageId: "package-new",
    recoveryWrapEpochs: [1, 2, 3],
    deviceWrapRecipients: ["trusted-a", "trusted-b"],
    newEpochKeyId: "synthetic-new-epoch-key",
  };
  const ticket = model.reserveTransition(compromise);
  assert.equal(model.localEpoch, 2);
  model.commitCas(ticket);
  model = model.restart({ restoreApplicationRevision: 7, witnessAvailable: false });
  assert.equal(model.localEpoch, 2);
  assert.throws(
    () => model.promoteLocalAfterWitnessedCommit(ticket),
    expectCode("WITNESS_UNAVAILABLE"),
  );
  model.setWitnessAvailable(true);
  const proof = model.issueTerminalStatusReceipt(ticket);
  model.resolveReservation(ticket, proof);
  assert.equal(await model.promoteLocalAfterWitnessedCommit(ticket), true);
  assert.equal(model.localEpoch, 3);
  assert.equal(model.localRecoveryPackageId, "package-new");

  const missingEpoch = createModel();
  assert.throws(
    () => missingEpoch.reserveTransition({ ...compromise, operationId: Buffer.alloc(16, 4), priorEpochsAvailable: [1] }),
    expectCode("KEY_COVERAGE_INCOMPLETE"),
  );

  const losingCas = createModel();
  const losingTicket = losingCas.reserveTransition({
    ...compromise,
    operationId: Buffer.alloc(16, 6),
    requestBytes: Buffer.from("compromise-cas-lost"),
  });
  losingCas.advanceClock(1330);
  const noCommitProof = losingCas.issueTerminalStatusReceipt(losingTicket);
  assert.equal(losingCas.resolveReservation(losingTicket, noCommitProof), "cancelled");
  assert.equal(losingCas.localEpoch, 2);
  assert.equal(losingCas.localRecoveryPackageId, "package-old");

  const noAlternateAuthority = createModel({ recoveryPackageId: null, activeDeviceIds: ["trusted-a"] });
  assert.throws(
    () => noAlternateAuthority.reserveTransition(revokeTransition(5, { targetDeviceId: "trusted-a" })),
    expectCode("COMPROMISE_RECOVERY_UNAVAILABLE"),
  );
});
