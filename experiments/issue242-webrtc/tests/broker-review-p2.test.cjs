'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');

const fingerprint = 'a'.repeat(64);
const sha256 = 'b'.repeat(64);
function deferred() {
  let release;
  const promise = new Promise(resolve => { release = resolve; });
  return { promise, release };
}
function authenticateSession(req) {
  const username = req.headers['x-fixture-user'];
  return typeof username === 'string' && username.length > 0
    ? { username, sessionVersion: 1, expiresAt: Date.now() + 60_000 } : null;
}
async function fixture(t, authorizeObject) {
  const broker = makeBroker({ authenticateSession, authorizeObject,
    authorizeRecipient: (_owner, recipient) => ({ username: recipient, sessionVersion: 1 }) });
  const origin = await broker.listen();
  const sockets = [];
  t.after(async () => {
    for (const connection of sockets) connection.ws.terminate();
    await broker.close();
  });
  async function connect(username) {
    const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', {
      headers: { Origin: origin, 'x-fixture-user': username },
    });
    ws.on('error', () => {});
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
    });
    const queue = [], waiters = [], received = [];
    ws.on('message', bytes => {
      const value = JSON.parse(bytes.toString());
      received.push(value);
      const index = waiters.findIndex(waiter => waiter.type === value.type);
      if (index < 0) queue.push(value);
      else waiters.splice(index, 1)[0].resolve(value);
    });
    const connection = { ws, received,
      send: value => ws.send(JSON.stringify(value)),
      next: type => new Promise((resolve, reject) => {
        const index = queue.findIndex(value => value.type === type);
        if (index >= 0) return resolve(queue.splice(index, 1)[0]);
        const waiter = { type, resolve };
        waiters.push(waiter);
        setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index >= 0) { waiters.splice(index, 1); reject(new Error('timeout ' + type)); }
        }, 2000).unref();
      }),
    };
    sockets.push(connection);
    return connection;
  }
  async function room() {
    const result = await broker.createRoom({ headers: { 'x-fixture-user': 'owner' },
      body: { boundObject: { folderId: 'root', fileName: 'secret.bin' } } });
    assert.equal(result.status, 200);
    return result;
  }
  return { connect, room };
}
function authorized() { return { fingerprint, sha256, bytes: 32 * 1024 * 1024 }; }
async function inviteJoin(host, room, connect, recipient) {
  host.send({ type: 'invite', recipient });
  const invitation = (await host.next('invited')).invitation;
  const guest = await connect(recipient);
  guest.send({ type: 'join', roomId: room.roomId, invitation });
  const joined = await guest.next('joined');
  await host.next('peer-joined');
  return { guest, joined };
}

test('socket closed during owner object hash cannot activate host or burn reserved room', async t => {
  let holdHost = false;
  const entered = deferred(), gate = deferred();
  const f = await fixture(t, async ({ recipient }) => {
    if (holdHost && recipient === null) {
      entered.release();
      await gate.promise;
    }
    return authorized();
  });
  const room = await f.room();
  const dead = await f.connect('owner');
  holdHost = true;
  dead.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await entered.promise;
  const closed = new Promise(resolve => dead.ws.once('close', resolve));
  dead.ws.terminate();
  await closed;
  // A client-side close event can precede the server-side close callback on
  // WSL loopback. Hold the hash while the server observes the disconnected fd.
  await new Promise(resolve => setTimeout(resolve, 50));
  holdHost = false;
  gate.release();
  const live = await f.connect('owner');
  live.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  assert.equal((await live.next('joined')).role, 'host', 'dead socket cannot consume hostJoined');
});

test('socket closed during guest object hash cannot consume one-use invite', async t => {
  let holdGuest = false;
  const entered = deferred(), gate = deferred();
  const f = await fixture(t, async ({ recipient }) => {
    if (holdGuest && recipient === 'guest') {
      entered.release();
      await gate.promise;
    }
    return authorized();
  });
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  host.send({ type: 'invite', recipient: 'guest' });
  const invite = (await host.next('invited')).invitation;
  const deadGuest = await f.connect('guest');
  holdGuest = true;
  deadGuest.send({ type: 'join', roomId: room.roomId, invitation: invite });
  await entered.promise;
  const closed = new Promise(resolve => deadGuest.ws.once('close', resolve));
  deadGuest.ws.terminate();
  await closed;
  await new Promise(resolve => setTimeout(resolve, 50));
  holdGuest = false;
  gate.release();
  const liveGuest = await f.connect('guest');
  liveGuest.send({ type: 'join', roomId: room.roomId, invitation: invite });
  assert.equal((await liveGuest.next('joined')).role, 'guest', 'dead socket cannot burn invite');
});

test('bad credentials and full rooms do not hash 32 MiB object for each join', async t => {
  let hashes = 0;
  const f = await fixture(t, async () => { hashes++; return authorized(); });
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  const stranger = await f.connect('stranger');
  const beforeBad = hashes;
  for (let i = 0; i < 3; i++) {
    stranger.send({ type: 'join', roomId: room.roomId, hostKey: 'bogus', invitation: 'bogus' });
    assert.equal((await stranger.next('error')).code, 'INVALID_INVITE');
  }
  assert.equal(hashes, beforeBad, 'bogus credentials must be rejected before object read/hash');
  for (const recipient of ['a', 'b', 'c']) await inviteJoin(host, room, f.connect, recipient);
  const overflow = await f.connect('stranger');
  const beforeFull = hashes;
  for (let i = 0; i < 120; i++) {
    overflow.send({ type: 'join', roomId: room.roomId, hostKey: 'bogus', invitation: 'bogus' });
    assert.equal((await overflow.next('error')).code, 'FULL');
  }
  assert.equal(hashes, beforeFull, 'full room must reject before owner and guest 32 MiB hashes');
});

test('guest revoked while later guest hash awaits receives no authorized signal', async t => {
  let delaySecondGuest = false;
  let firstGuestAllowed = true;
  const entered = deferred(), gate = deferred();
  const f = await fixture(t, async ({ recipient }) => {
    if (delaySecondGuest && recipient === 'guest2') {
      entered.release();
      await gate.promise;
    }
    return recipient === 'guest1' && !firstGuestAllowed ? null : authorized();
  });
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hostJoined = await host.next('joined');
  const first = await inviteJoin(host, room, f.connect, 'guest1');
  await inviteJoin(host, room, f.connect, 'guest2');
  host.send({ type: 'request-peer', to: first.joined.peerId });
  const request = await first.guest.next('peer-request');
  first.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await first.guest.next('peer-allowed');
  const closed = new Promise(resolve => first.guest.ws.once('close', resolve));
  delaySecondGuest = true;
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'must-not-arrive' } } });
  await entered.promise;
  firstGuestAllowed = false;
  gate.release();
  await closed;
  assert.equal(first.guest.received.filter(message => message.type === 'signal').length, 0,
    'late ACL change after an earlier guest hash must fence signal egress');
  assert.equal(hostJoined.role, 'host');
});

test('owner revoked during final guest ACL await cannot signal or retain room members', async t => {
  let ownerAllowed = true;
  let countGuestChecks = false, guestChecks = 0;
  const enteredFinalGuest = deferred(), finishFinalGuest = deferred();
  const f = await fixture(t, async ({ recipient }) => {
    if (recipient === null) return ownerAllowed ? authorized() : null;
    if (recipient === 'guest1' && countGuestChecks && ++guestChecks === 2) {
      // The room-wide check has already read the owner. This second guest
      // check is the guest await in forwardLiveSignal after the initial
      // room-wide owner recheck. The final owner check must follow this wait.
      enteredFinalGuest.release();
      await finishFinalGuest.promise;
    }
    return authorized();
  });
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hostJoined = await host.next('joined');
  const first = await inviteJoin(host, room, f.connect, 'guest1');
  const second = await inviteJoin(host, room, f.connect, 'guest2');
  host.send({ type: 'request-peer', to: first.joined.peerId });
  const request = await first.guest.next('peer-request');
  first.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await first.guest.next('peer-allowed');
  const hostClose = new Promise(resolve => host.ws.once('close', resolve));
  const firstClose = new Promise(resolve => first.guest.ws.once('close', resolve));
  const secondClose = new Promise(resolve => second.guest.ws.once('close', resolve));
  countGuestChecks = true;
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'owner-revoked-during-guest' } } });
  await enteredFinalGuest.promise;
  assert.equal(guestChecks, 2, 'test must block after owner check, at final guest await');
  ownerAllowed = false;
  finishFinalGuest.release();
  await Promise.all([hostClose, firstClose, secondClose]);
  assert.equal(first.guest.received.filter(message => message.type === 'signal').length, 0,
    'owner ACL revoked during final guest await must block signaling');
  assert.equal(hostJoined.role, 'host');
  const late = await f.connect('owner');
  late.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  assert.equal((await late.next('error')).code, 'INVALID_INVITE',
    'stale owner/member room must not survive an ACL revocation');
});
