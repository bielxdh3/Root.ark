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
async function fixture(t, authorizeObject, authorizeSignalSnapshot = null) {
  // Synthetic broker-only version authority: deliberately injected at
  // construction, never provided by HTTP or claimed to be an owner signature.
  // These unit tests examine broker races, not real immutable storage custody.
  const broker = makeBroker({ authenticateSession, authorizeObject,
    authorizeImmutableVersion: input => Object.freeze({
      ...input, boundObject: { ...input.boundObject }, versionId: 'test-immutable-v1',
    }),
    // A present but unavailable snapshot must still deny protected SDP/ICE;
    // the separate pretrust test covers truly missing startup capabilities.
    authorizeSignalSnapshot: authorizeSignalSnapshot ?? (() => null),
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
function authority() {
  const current = new Map([['owner', true], ['guest1', true], ['guest2', true]]);
  let revision = 1;
  return {
    revoke(username) { current.set(username, false); revision++; },
    snapshot({ owner, recipients, pin, sha256: digest, bytes }) {
      if (!current.get(owner) || !recipients.every(name => current.get(name))) return null;
      return { owner, recipients, pin, sha256: digest, bytes, revision };
    },
  };
}
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
  const acl = authority();
  let delaySecondGuest = false;
  let firstGuestAllowed = true;
  const entered = deferred(), gate = deferred();
  const f = await fixture(t, async ({ recipient }) => {
    if (delaySecondGuest && recipient === 'guest2') {
      entered.release();
      await gate.promise;
    }
    return recipient === 'guest1' && !firstGuestAllowed ? null : authorized();
  }, input => acl.snapshot(input));
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
  const outcome = Promise.race([
    new Promise(resolve => first.guest.ws.once('close', () => resolve('closed'))),
    first.guest.next('signal').then(() => 'unauthorized-signal'),
  ]);
  delaySecondGuest = true;
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'must-not-arrive' } } });
  await entered.promise;
  firstGuestAllowed = false;
  acl.revoke('guest1');
  gate.release();
  assert.equal(await outcome, 'closed', 'revoked guest must not receive ICE/SDP');
  assert.equal(first.guest.received.filter(message => message.type === 'signal').length, 0,
    'late ACL change after an earlier guest hash must fence signal egress');
  assert.equal(hostJoined.role, 'host');
});

test('owner revoked during final guest ACL await cannot signal or retain room members', async t => {
  const acl = authority();
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
  }, input => acl.snapshot(input));
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
  acl.revoke('owner');
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

test('guest revocation during the final async owner check cannot forward a 1:N signal', async t => {
  const acl = authority();
  let ownerChecks = 0;
  let trapFinalOwner = false;
  const entered = deferred(), resume = deferred();
  const f = await fixture(t, async ({ recipient }) => {
    if (recipient === null && trapFinalOwner && ++ownerChecks === 2) {
      entered.release();
      await resume.promise;
    }
    return authorized(); // stale per-principal grant can still appear valid
  }, input => acl.snapshot(input));
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  const first = await inviteJoin(host, room, f.connect, 'guest1');
  await inviteJoin(host, room, f.connect, 'guest2');
  host.send({ type: 'request-peer', to: first.joined.peerId });
  const request = await first.guest.next('peer-request');
  first.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await first.guest.next('peer-allowed');
  const outcome = Promise.race([
    new Promise(resolve => first.guest.ws.once('close', () => resolve('closed'))),
    first.guest.next('signal').then(() => 'unauthorized-signal'),
  ]);
  trapFinalOwner = true;
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'must-not-leak-after-guest-revoke' } } });
  await entered.promise;
  assert.equal(ownerChecks, 2, 'the adverse join must pause on final owner await');
  acl.revoke('guest1');
  resume.release();
  assert.equal(await outcome, 'closed', 'revoked guest must not receive ICE/SDP');
  assert.equal(first.guest.received.filter(message => message.type === 'signal').length, 0,
    'multi-party ACL must be read in a single synchronous authority view');
});

test('unavailable, asynchronous and partial authority snapshots fail closed for bound signaling', async t => {
  for (const impl of [null, async input => authority().snapshot(input),
    input => ({ ...authority().snapshot(input), revision: -1 })]) {
    await t.test(impl === null ? 'absent' : 'invalid or asynchronous', async sub => {
      const f = await fixture(sub, async () => authorized(), impl);
      const room = await f.room();
      const host = await f.connect('owner');
      host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
      await host.next('joined');
      const first = await inviteJoin(host, room, f.connect, 'guest1');
      host.send({ type: 'request-peer', to: first.joined.peerId });
      const request = await first.guest.next('peer-request');
      first.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
      await host.next('peer-accepted');
      await first.guest.next('peer-allowed');
      const outcome = Promise.race([
        new Promise(resolve => first.guest.ws.once('close', () => resolve('closed'))),
        first.guest.next('signal').then(() => 'unauthorized-signal'),
      ]);
      host.send({ type: 'signal', to: first.joined.peerId,
        signal: { kind: 'ice', candidate: { candidate: 'denied-without-atomic-ACL' } } });
      assert.equal(await outcome, 'closed', 'missing coherent snapshot must deny signal');
      assert.equal(first.guest.received.some(message => message.type === 'signal'), false);
    });
  }
});

test('consented one-guest and 1:N bound signals work with a synchronous common ACL authority', async t => {
  const acl = authority();
  const f = await fixture(t, async () => authorized(), input => acl.snapshot(input));
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hostJoin = await host.next('joined');
  const first = await inviteJoin(host, room, f.connect, 'guest1');
  host.send({ type: 'request-peer', to: first.joined.peerId });
  let request = await first.guest.next('peer-request');
  first.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await first.guest.next('peer-allowed');
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'single-guest-live' } } });
  assert.equal((await first.guest.next('signal')).signal.candidate.candidate, 'single-guest-live');
  const second = await inviteJoin(host, room, f.connect, 'guest2');
  host.send({ type: 'request-peer', to: second.joined.peerId });
  request = await second.guest.next('peer-request');
  second.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await second.guest.next('peer-allowed');
  second.guest.send({ type: 'signal', to: hostJoin.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'multi-guest-live' } } });
  assert.equal((await host.next('signal')).signal.candidate.candidate, 'multi-guest-live');
});

test('a bound room rejects an authority revision rollback after an earlier authorized signal', async t => {
  const acl = authority();
  let revision = 2;
  const f = await fixture(t, async () => authorized(),
    input => ({ ...acl.snapshot(input), revision }));
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  const first = await inviteJoin(host, room, f.connect, 'guest1');
  host.send({ type: 'request-peer', to: first.joined.peerId });
  const request = await first.guest.next('peer-request');
  first.guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await first.guest.next('peer-allowed');
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'new-authority' } } });
  assert.equal((await first.guest.next('signal')).signal.candidate.candidate, 'new-authority');
  revision = 1;
  const outcome = Promise.race([
    new Promise(resolve => first.guest.ws.once('close', () => resolve('closed'))),
    first.guest.next('signal').then(() => 'stale-authority-leak'),
  ]);
  host.send({ type: 'signal', to: first.joined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'old-authority' } } });
  assert.equal(await outcome, 'closed', 'older accepted authority epoch cannot regain signaling');
});

test('fake revokes and invalid room frames are rejected without hashing 32 MiB ciphertext', async t => {
  let hashes = 0;
  const f = await fixture(t, async () => { hashes++; return authorized(); });
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  const { guest, joined } = await inviteJoin(host, room, f.connect, 'guest1');

  // A real peer request + consent is allowed to recheck current object ACL.
  host.send({ type: 'request-peer', to: joined.peerId });
  const request = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  await guest.next('peer-allowed');
  const before = hashes;

  for (let i = 0; i < 20; i++) {
    host.send({ type: 'revoke', inviteId: i.toString(16).padStart(16, '0') });
    assert.equal((await host.next('error')).code, 'FORBIDDEN',
      'a non-existent invitation must never receive a revoke ACK');
  }
  const invalid = [
    [host, { type: 'signal', to: 'invalid-peer-id', signal: { kind: 'ice', candidate: {} } }, 'FORBIDDEN'],
    [host, { type: 'request-peer', to: 'invalid-peer-id' }, 'FORBIDDEN'],
    [host, { type: 'kick', to: 'invalid-peer-id' }, 'FORBIDDEN'],
    [host, { type: 'consent', requestId: 'absent', accept: true }, 'FORBIDDEN'],
    [host, { type: 'unknown-event' }, 'FORBIDDEN'],
    [host, { type: 'invite', recipient: '' }, 'BAD_RECIPIENT'],
    [guest, { type: 'invite', recipient: 'guest2' }, 'FORBIDDEN'],
    [guest, { type: 'revoke', inviteId: '0'.repeat(16) }, 'FORBIDDEN'],
    [guest, { type: 'signal', to: 'wrong-peer-id', signal: { kind: 'offer', sdp: 'fake' } }, 'FORBIDDEN'],
  ];
  for (const [peer, message, expected] of invalid) {
    peer.send(message);
    assert.equal((await peer.next('error')).code, expected);
  }
  assert.equal(hashes, before, 'invalid frames must never trigger object ACL hashing');
  assert.equal(host.received.some(message => message.type === 'revoked'), false);
  assert.equal(guest.received.some(message => message.type === 'signal'), false);
});

test('valid revoke rechecks current ACL and never ACKs a revoked owner', async t => {
  let hashes = 0;
  let ownerAllowed = true;
  const f = await fixture(t, async ({ recipient }) => {
    hashes++;
    return recipient === null && !ownerAllowed ? null : authorized();
  });
  const room = await f.room();
  const host = await f.connect('owner');
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  host.send({ type: 'invite', recipient: 'guest1' });
  const first = await host.next('invited');
  const beforeValid = hashes;
  host.send({ type: 'revoke', inviteId: first.inviteId });
  assert.equal((await host.next('revoked')).inviteId, first.inviteId);
  assert.ok(hashes > beforeValid, 'genuine revoke must still check the authoritative ACL');

  host.send({ type: 'invite', recipient: 'guest2' });
  const second = await host.next('invited');
  const beforeRevoked = hashes;
  ownerAllowed = false;
  const closed = new Promise(resolve => host.ws.once('close', resolve));
  host.send({ type: 'revoke', inviteId: second.inviteId });
  await closed;
  assert.ok(hashes > beforeRevoked, 'revoked owner must trigger the ACL guard');
  assert.equal(host.received.some(message => message.type === 'revoked' &&
    message.inviteId === second.inviteId), false, 'stale ACL cannot authorize a revoke');
});
