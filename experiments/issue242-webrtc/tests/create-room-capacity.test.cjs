'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { makeBroker } = require('../server.cjs');

const grant = { fingerprint: 'a'.repeat(64), sha256: 'b'.repeat(64), bytes: 32 * 1024 * 1024 };
function request(owner = 'alice') {
  return { headers: { 'x-owner': owner },
    body: { boundObject: { folderId: 'root', fileName: 'sealed.bin' } } };
}
async function brokerFixture(t, authorizeObject) {
  const broker = makeBroker({ authorizeObject,
    // Broker capacity tests use synthetic startup-injected authorities; no
    // production version, real signature or all-writer ACL guarantee implied.
    authorizeImmutableVersion: () => Object.freeze({ versionId: 'test-immutable-v1' }),
    authorizeSignalSnapshot: () => null,
    authenticateSession: req => ({ username: req.headers['x-owner'], sessionVersion: 1,
      expiresAt: Date.now() + 60_000 }) });
  await broker.listen();
  t.after(() => broker.close());
  return broker;
}
function deferred() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { promise, release };
}

test('full owner returns 429 without reading or hashing another object', async t => {
  let checks = 0;
  const broker = await brokerFixture(t, async () => { checks++; return grant; });
  assert.equal((await broker.createRoom(request())).status, 200);
  assert.equal((await broker.createRoom(request())).status, 200);
  assert.equal(checks, 2);
  assert.equal((await broker.createRoom(request())).status, 429);
  assert.equal(checks, 2, 'full owner must be rejected before costly authorization');
  assert.equal((await broker.createRoom(request('bob'))).status, 200,
    'another owner remains eligible for unused global capacity');
});

test('concurrent creations reserve owner slots before entering async authorization', async t => {
  const gate = deferred();
  let checks = 0;
  const broker = await brokerFixture(t, async () => { checks++; await gate.promise; return grant; });
  const first = broker.createRoom(request());
  const second = broker.createRoom(request());
  const rejected = broker.createRoom(request());
  try {
    assert.equal(checks, 2, 'third request must not enter hashing while two are pending');
  } finally {
    gate.release();
  }
  const results = await Promise.all([first, second, rejected]);
  assert.deepEqual(results.map(x => x.status), [200, 200, 429]);
  assert.notEqual(results[0].roomId, results[1].roomId);
});

test('global capacity includes all pending object authorizations', async t => {
  const gate = deferred();
  let checks = 0;
  const broker = await brokerFixture(t, async () => { checks++; await gate.promise; return grant; });
  const pending = Array.from({ length: 16 }, (_, i) => broker.createRoom(request(`owner${i}`)));
  const overflow = broker.createRoom(request('seventeenth'));
  try {
    assert.equal(checks, 16, '17th owner must not begin expensive work');
  } finally {
    gate.release();
  }
  assert.deepEqual((await Promise.all([...pending, overflow])).map(x => x.status),
    [...Array(16).fill(200), 429]);
});

test('deny, throw and aborted request release their pending slots without creating rooms', async t => {
  let checks = 0;
  const gate = deferred();
  const broker = await brokerFixture(t, async () => {
    checks++;
    if (checks === 1) return null;
    if (checks === 2) throw new Error('fixture authority failure');
    if (checks === 3) { await gate.promise; return grant; }
    return grant;
  });
  assert.equal((await broker.createRoom(request())).status, 403);
  assert.equal((await broker.createRoom(request())).status, 403);
  const abortedReq = request();
  const aborted = broker.createRoom(abortedReq);
  abortedReq.aborted = true;
  gate.release();
  assert.equal((await aborted).status, 403, 'aborted request must not create a room');
  assert.equal((await broker.createRoom(request())).status, 200);
  assert.equal((await broker.createRoom(request())).status, 200);
  assert.equal((await broker.createRoom(request())).status, 429);
  assert.equal(checks, 5, 'denied, failed and aborted requests leave no pending slot');
});

test('session revoked while hashing cannot create a stale signed room', async t => {
  let currentVersion = 1;
  const gate = deferred();
  const broker = makeBroker({
    authenticateSession: req => ({ username: req.headers['x-owner'],
      sessionVersion: currentVersion, expiresAt: Date.now() + 60_000 }),
    authorizeImmutableVersion: () => Object.freeze({ versionId: 'test-immutable-v1' }),
    authorizeSignalSnapshot: () => null,
    authorizeObject: async () => { await gate.promise; return grant; },
  });
  await broker.listen();
  t.after(() => broker.close());
  const pending = broker.createRoom(request());
  currentVersion++;
  gate.release();
  assert.equal((await pending).status, 401);
  assert.equal((await broker.createRoom(request())).status, 200,
    'a fresh session can use released capacity');
});

test('unbound room creation also respects active owner and global limits', async t => {
  let hashes = 0;
  const broker = await brokerFixture(t, async () => { hashes++; return grant; });
  const unbound = owner => ({ headers: { 'x-owner': owner } });
  assert.equal((await broker.createRoom(unbound('alice'))).status, 200);
  assert.equal((await broker.createRoom(unbound('alice'))).status, 200);
  assert.equal((await broker.createRoom(unbound('alice'))).status, 429);
  assert.equal((await broker.createRoom(request('alice'))).status, 429);
  assert.equal(hashes, 0);
});
