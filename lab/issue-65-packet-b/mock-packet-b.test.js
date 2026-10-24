'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const modelPath = path.join(__dirname, 'mock-packet-b.js');
const model = fs.existsSync(modelPath) ? require(modelPath) : {};

function requireExport(name) {
  assert.equal(typeof model[name], 'function', `${name} should be exported by the lab model`);
  return model[name];
}

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => error && error.code === code);
}

test('copy-on-write rollback preserves the mock CAS snapshot', async () => {
  const MockCasLedger = requireExport('MockCasLedger');
  const ledger = new MockCasLedger();
  const before = ledger.snapshot();

  await rejectsCode(ledger.commit({
    operationId: 'op-rollback',
    expectedRevision: 0,
    payloadDigest: 'digest-a',
    failAfterTransition: true,
  }), 'INJECTED_ROLLBACK');

  assert.deepEqual(ledger.snapshot(), before);
  await rejectsCode(ledger.sealNoCommit({
    operationId: 'op-fence-rollback',
    expectedRevision: 0,
    payloadDigest: 'digest-a',
    failAfterFence: true,
  }), 'INJECTED_ROLLBACK');
  assert.deepEqual(ledger.snapshot(), before);
});

test('a lost commit acknowledgement retries to the same durable mock result', async () => {
  const MockCasLedger = requireExport('MockCasLedger');
  const ledger = new MockCasLedger();
  const request = {
    operationId: 'op-lost-ack',
    expectedRevision: 0,
    payloadDigest: 'digest-b',
  };

  await rejectsCode(ledger.commit({ ...request, loseAcknowledgement: true }), 'LOST_ACK');
  const resultAfterRetry = await ledger.commit(request);
  const snapshot = ledger.snapshot();

  assert.equal(snapshot.transitions.length, 1);
  assert.equal(snapshot.operations.length, 1);
  assert.deepEqual(resultAfterRetry, snapshot.operations[0].result);
  assert.equal(snapshot.head.revision, 1);
});

test('commit and no-commit fence serialize to one terminal outcome', async (t) => {
  const MockCasLedger = requireExport('MockCasLedger');

  for (const first of ['commit', 'fence']) {
    await t.test(`${first} queued first`, async () => {
      const ledger = new MockCasLedger();
      const commit = () => ledger.commit({
        operationId: 'op-race',
        expectedRevision: 0,
        payloadDigest: 'digest-c',
      });
      const fence = () => ledger.sealNoCommit({
        operationId: 'op-race',
        expectedRevision: 0,
        payloadDigest: 'digest-c',
      });
      const outcomes = first === 'commit'
        ? await Promise.allSettled([commit(), fence()])
        : await Promise.allSettled([fence(), commit()]);
      const snapshot = ledger.snapshot();

      assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
      assert.equal(snapshot.operations.length + snapshot.noCommitFences.length, 1);
      assert.notEqual(snapshot.operations.length > 0, snapshot.noCommitFences.length > 0);
    });
  }
});

test('mock gate binds a single-use permit and quiesces before its local fence', () => {
  const MockGateAuthority = requireExport('MockGateAuthority');
  const gate = new MockGateAuthority();
  const permit = gate.issuePermit({ operationId: 'op-gate', effectId: 'effect-1' });
  const secondPermit = gate.issuePermit({ operationId: 'op-gate', effectId: 'effect-2' });
  const unusedPermit = gate.issuePermit({ operationId: 'op-gate', effectId: 'effect-3' });

  assert.throws(
    () => gate.consumePermit({ permitId: permit.permitId, operationId: 'op-gate', effectId: 'other-effect' }),
    { code: 'SCOPE_MISMATCH' },
  );
  const lease = gate.consumePermit({ permitId: permit.permitId, operationId: 'op-gate', effectId: 'effect-1' });
  assert.throws(
    () => gate.consumePermit({ permitId: permit.permitId, operationId: 'op-gate', effectId: 'effect-1' }),
    { code: 'PERMIT_ALREADY_CONSUMED' },
  );
  const secondLease = gate.consumePermit({ permitId: secondPermit.permitId, operationId: 'op-gate', effectId: 'effect-2' });
  assert.equal(secondLease.generation, permit.generation);

  gate.performChunk({ leaseId: lease.leaseId, chunkIndex: 0 });
  const stopRequest = gate.quiesce();
  assert.equal(stopRequest.generation, permit.generation + 1);
  assert.equal(stopRequest.stopRequests.length, 2);
  assert.throws(
    () => gate.consumePermit({ permitId: unusedPermit.permitId, operationId: 'op-gate', effectId: 'effect-3' }),
    { code: 'GATE_NOT_OPEN' },
  );
  assert.throws(
    () => gate.performChunk({ leaseId: lease.leaseId, chunkIndex: 1 }),
    { code: 'GATE_NOT_OPEN' },
  );
  assert.throws(() => gate.sealNoCommit('op-gate'), { code: 'STOP_ACK_REQUIRED' });

  const firstStop = stopRequest.stopRequests.find((row) => row.effectId === 'effect-1');
  const secondStop = stopRequest.stopRequests.find((row) => row.effectId === 'effect-2');
  gate.acknowledgeStop({ effectId: firstStop.effectId, acknowledgementId: firstStop.acknowledgementId });
  assert.throws(() => gate.sealNoCommit('op-gate'), { code: 'STOP_ACK_REQUIRED' });
  gate.acknowledgeStop({ effectId: secondStop.effectId, acknowledgementId: secondStop.acknowledgementId });
  const fence = gate.sealNoCommit('op-gate');
  assert.equal(fence.operationId, 'op-gate');
  assert.equal(gate.snapshot().mode, 'BLOCKED');
  assert.throws(() => gate.performChunk({ leaseId: lease.leaseId, chunkIndex: 1 }), { code: 'GATE_NOT_OPEN' });
});

test('CAS state is isolated by account, compartment, and keyring tuple', async () => {
  const MockCasLedger = requireExport('MockCasLedger');
  const ledger = new MockCasLedger();
  const scope = { accountId: 'account-a', compartmentId: 'compartment-a', keyringId: 'keyring-a' };
  const otherKeyring = { ...scope, keyringId: 'keyring-b' };
  const otherCompartment = { ...scope, compartmentId: 'compartment-b' };
  const otherAccount = { ...scope, accountId: 'account-b' };

  await ledger.commit({ scope, operationId: 'op-scope', expectedRevision: 0, payloadDigest: 'digest-d' });

  assert.equal(ledger.snapshot(scope).head.revision, 1);
  for (const isolatedScope of [otherKeyring, otherCompartment, otherAccount]) {
    assert.equal(ledger.snapshot(isolatedScope).head.revision, 0);
    assert.equal(ledger.snapshot(isolatedScope).operations.length, 0);
  }
});
