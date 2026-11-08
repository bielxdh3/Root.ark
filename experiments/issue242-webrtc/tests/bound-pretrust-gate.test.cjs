'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');

const BOUND = Object.freeze({ folderId: 'root', fileName: 'sealed.bin' });
const SIGNED = Object.freeze({ fingerprint: 'a'.repeat(64),
  sha256: 'b'.repeat(64), bytes: 32 * 1024 * 1024 });
function session(req) {
  return { username: req.headers['x-fixture-owner'] || 'owner',
    sessionVersion: 1, expiresAt: Date.now() + 60_000 };
}
function request(owner = 'owner', boundObject = BOUND) {
  return { headers: { 'x-fixture-owner': owner }, body: { boundObject } };
}
function fixture(t, options = {}) {
  let reads = 0;
  const broker = makeBroker({ authenticateSession: session,
    authorizeObject: async () => { reads++; return SIGNED; }, ...options });
  t.after(() => broker.close());
  return { broker, get reads() { return reads; } };
}

test('missing trusted immutable-version AND all-party ACL authority denies 16 concurrent bound admissions before any hashing', async t => {
  const f = fixture(t);
  const replies = await Promise.all(Array.from({ length: 16 }, (_, index) =>
    f.broker.createRoom(request('owner-' + index))));
  assert.ok(replies.every(reply => reply.status === 403));
  assert.equal(f.reads, 0, 'missing authority cannot hash even one 32 MiB object');
  assert.ok(replies.every(reply => !reply.roomId && !reply.boundObject),
    'denied request cannot get room IDs or ephemeral P2P capabilities');
  const unbound = await f.broker.createRoom({ headers: { 'x-fixture-owner': 'owner' } });
  assert.equal(unbound.status, 200, 'manual unbound rooms remain available');
  assert.equal(f.reads, 0, 'unbound admission does not touch ciphertext');
  const again = await f.broker.createRoom(request('owner'));
  assert.equal(again.status, 403, 'unbound room allocation does not enable bound admission');
});

test('client-supplied trust assertions and an object hash callback cannot enable protected rooms', async t => {
  const f = fixture(t, { authorizeSignalSnapshot: () => null });
  const injected = {
    folderId: 'root', fileName: 'sealed.bin',
    immutableVersionAuthority: true, mutationSerializedSnapshot: true,
  };
  assert.equal((await f.broker.createRoom(request('owner', injected))).status, 403);
  assert.equal((await f.broker.createRoom(request())).status, 403,
    'all-party snapshot callback alone does not attest immutability');
  assert.equal(f.reads, 0);
  assert.equal((await f.broker.createRoom({ ...request(), immutableVersionAuthority: true,
    mutationSerializedSnapshot: true })).status, 403);
});

test('presence of only an immutable-version callback does not bypass missing common ACL snapshot', async t => {
  const f = fixture(t, { authorizeImmutableVersion: () => SIGNED });
  assert.equal((await f.broker.createRoom(request())).status, 403);
  assert.equal(f.reads, 0);
});

test('unbound signed-session 1:N room remains usable for host, recipient, consent and signaling', async t => {
  const f = fixture(t);
  const origin = await f.broker.listen();
  const result = await f.broker.createRoom({ headers: { 'x-fixture-owner': 'owner' } });
  assert.equal(result.status, 200);
  const connections = [];
  t.after(() => connections.forEach(ws => ws.terminate()));
  async function connect(username) {
    const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', {
      headers: { origin, 'x-fixture-owner': username },
    });
    ws.on('error', () => {});
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    connections.push(ws);
    const messages = [], waiters = [];
    ws.on('message', data => {
      const message = JSON.parse(data.toString());
      const index = waiters.findIndex(waiter => waiter.type === message.type);
      if (index !== -1) waiters.splice(index, 1)[0].resolve(message);
      else messages.push(message);
    });
    return {
      send: value => ws.send(JSON.stringify(value)),
      next(type) {
        return new Promise((resolve, reject) => {
          const index = messages.findIndex(value => value.type === type);
          if (index !== -1) return resolve(messages.splice(index, 1)[0]);
          const waiter = { type, resolve };
          waiters.push(waiter);
          setTimeout(() => {
            const position = waiters.indexOf(waiter);
            if (position !== -1) { waiters.splice(position, 1); reject(Error('timeout ' + type)); }
          }, 2000).unref();
        });
      },
    };
  }
  const host = await connect('owner');
  host.send({ type: 'join', roomId: result.roomId, hostKey: result.hostKey });
  const joinedHost = await host.next('joined');
  host.send({ type: 'invite', recipient: 'guest' });
  const invitation = (await host.next('invited')).invitation;
  const guest = await connect('guest');
  guest.send({ type: 'join', roomId: result.roomId, invitation });
  const joinedGuest = await guest.next('joined');
  host.send({ type: 'request-peer', to: joinedGuest.peerId });
  const pending = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: pending.requestId, accept: true });
  await host.next('peer-accepted');
  host.send({ type: 'signal', to: joinedGuest.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'manual-p2p' } } });
  assert.equal((await guest.next('signal')).signal.candidate.candidate, 'manual-p2p');
  assert.equal(joinedHost.role, 'host');
  assert.equal(f.reads, 0, 'manual signaling never hashes private server ciphertext');
});
