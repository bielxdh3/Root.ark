'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const jwt = require('jsonwebtoken');
const WebSocket = require('ws');
const { createRealtimeAuthenticator, parseCookies } = require('../../../src/middlewares/auth');
const { makeBroker } = require('../server.cjs');

async function fixture(t, options = {}) {
  const secret = randomBytes(48).toString('hex');
  const users = new Map(['alice', 'bob', 'eve'].map(username => [
    username, { username, role: 'user', sessionVersion: 1, disabled: false, totpEnabled: true, permissions: {} }
  ]));
  const verify = createRealtimeAuthenticator({
    jwt, jwtSecret: secret, loadUser: username => users.get(username),
    normalizeUserPermissions: user => user.permissions
  });
  const auth = req => verify(parseCookies(req.headers.cookie).get('rootark_session'));
  const broker = makeBroker({ authenticateSession: auth, ...options });
  const origin = await broker.listen();
  const sockets = [];
  t.after(async () => {
    for (const ws of sockets) ws.terminate();
    await broker.close();
  });
  function cookie(username, overrides = {}) {
    const { expiresIn = '5m', ...claimsOverride } = overrides;
    const claims = { username, sessionVersion: 1, ...claimsOverride };
    const signed = jwt.sign(claims, secret, { algorithm: 'HS256', expiresIn });
    return 'rootark_session=' + signed;
  }
  async function createRoom(sessionCookie) {
    const response = await fetch(origin + '/rooms', {
      method: 'POST', headers: { Origin: origin, Cookie: sessionCookie || '' }
    });
    return { status: response.status, data: response.ok ? await response.json() : null };
  }
  async function connect(sessionCookie) {
    const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', {
      headers: { Origin: origin, Cookie: sessionCookie || '' }
    });
    sockets.push(ws);
    await new Promise((resolve, reject) => {
      ws.once('open', resolve);
      ws.once('error', reject);
      ws.once('unexpected-response', (_req, res) => {
        res.resume();
        reject(new Error('upgrade ' + res.statusCode));
      });
    });
    const pending = [], waiters = [];
    ws.on('message', bytes => {
      const value = JSON.parse(bytes.toString());
      const index = waiters.findIndex(w => w.type === value.type);
      if (index === -1) pending.push(value);
      else waiters.splice(index, 1)[0].resolve(value);
    });
    return {
      ws,
      send: value => ws.send(JSON.stringify(value)),
      next: type => new Promise((resolve, reject) => {
        const index = pending.findIndex(v => v.type === type);
        if (index !== -1) return resolve(pending.splice(index, 1)[0]);
        const waiter = { type, resolve };
        waiters.push(waiter);
        setTimeout(() => {
          const index = waiters.indexOf(waiter);
          if (index !== -1) { waiters.splice(index, 1); reject(new Error('timeout ' + type)); }
        }, 2000).unref();
      })
    };
  }
  return { users, cookie, createRoom, connect };
}

test('real Root.ark session verification gates room creation and WebSocket upgrades', async t => {
  const f = await fixture(t);
  assert.equal((await f.createRoom('')).status, 401);
  assert.equal((await f.createRoom('rootark_session=forged')).status, 401);
  assert.equal((await f.createRoom(f.cookie('alice', { sessionVersion: 0 }))).status, 401);
  assert.equal((await f.createRoom(f.cookie('alice', { expiresIn: -1 }))).status, 401);
  assert.equal((await f.createRoom(f.cookie('alice', { totpEnrollment: true }))).status, 401);
  await assert.rejects(f.connect(''), /upgrade 401/);
  await assert.rejects(f.connect('rootark_session=forged'), /upgrade 401/);
  assert.equal((await f.createRoom(f.cookie('alice'))).status, 200);
});

test('recipient-bound single-use invite and host session prevent impersonation and unauthorized signaling', async t => {
  const f = await fixture(t);
  const room = (await f.createRoom(f.cookie('alice'))).data;
  const host = await f.connect(f.cookie('alice'));
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hp = await host.next('joined');
  assert.equal(hp.username, 'alice');
  const eve = await f.connect(f.cookie('eve'));
  eve.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  assert.equal((await eve.next('error')).code, 'INVALID_INVITE');
  host.send({ type: 'invite' });
  assert.equal((await host.next('error')).code, 'BAD_RECIPIENT');
  host.send({ type: 'invite', recipient: 'bob' });
  const { invitation } = await host.next('invited');
  eve.send({ type: 'join', roomId: room.roomId, invitation });
  assert.equal((await eve.next('error')).code, 'INVALID_INVITE');
  const guest = await f.connect(f.cookie('bob'));
  guest.send({ type: 'join', roomId: room.roomId, invitation });
  const joined = await guest.next('joined');
  assert.equal(joined.username, 'bob');
  assert.equal((await host.next('peer-joined')).username, 'bob');
  guest.send({ type: 'signal', to: hp.peerId, signal: { kind: 'offer', sdp: 'unauthorized' } });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  host.send({ type: 'request-peer', to: joined.peerId });
  const request = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  guest.send({ type: 'signal', to: hp.peerId, signal: { kind: 'ice', candidate: { candidate: 'fixture' } } });
  assert.equal((await host.next('signal')).peerId, joined.peerId);
  const replay = await f.connect(f.cookie('bob'));
  replay.send({ type: 'join', roomId: room.roomId, invitation });
  assert.equal((await replay.next('error')).code, 'INVALID_INVITE');
});

test('revoked or expired Root.ark session closes its previously consented peer channel', async t => {
  const f = await fixture(t);
  const room = (await f.createRoom(f.cookie('alice'))).data;
  const host = await f.connect(f.cookie('alice'));
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  await host.next('joined');
  host.send({ type: 'invite', recipient: 'bob' });
  const { invitation } = await host.next('invited');
  const guest = await f.connect(f.cookie('bob'));
  guest.send({ type: 'join', roomId: room.roomId, invitation });
  await guest.next('joined');
  await host.next('peer-joined');
  const closed = new Promise(resolve => guest.ws.once('close', code => resolve(code)));
  f.users.get('bob').sessionVersion++;
  guest.send({ type: 'invite' });
  assert.equal(await closed, 1008);
  await assert.rejects(f.connect(f.cookie('bob')), /upgrade 401/);
});

test('a room created before a session epoch change cannot be activated after revocation', async t => {
  const f = await fixture(t);
  const oldRoom = (await f.createRoom(f.cookie('alice'))).data;
  f.users.get('alice').sessionVersion = 2;
  const freshSession = await f.connect(f.cookie('alice', { sessionVersion: 2 }));
  freshSession.send({ type: 'join', roomId: oldRoom.roomId, hostKey: oldRoom.hostKey });
  assert.equal((await freshSession.next('error')).code, 'INVALID_INVITE');
  const newRoom = (await f.createRoom(f.cookie('alice', { sessionVersion: 2 }))).data;
  freshSession.send({ type: 'join', roomId: newRoom.roomId, hostKey: newRoom.hostKey });
  assert.equal((await freshSession.next('joined')).username, 'alice');
});

test('signal is never delivered to a recipient whose session was just revoked', async t => {
  const f = await fixture(t);
  const room = (await f.createRoom(f.cookie('alice'))).data;
  const host = await f.connect(f.cookie('alice'));
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hp = await host.next('joined');
  host.send({ type: 'invite', recipient: 'bob' });
  const invite = await host.next('invited');
  const guest = await f.connect(f.cookie('bob'));
  guest.send({ type: 'join', roomId: room.roomId, invitation: invite.invitation });
  const gp = await guest.next('joined');
  await host.next('peer-joined');
  host.send({ type: 'request-peer', to: gp.peerId });
  const req = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: req.requestId, accept: true });
  await host.next('peer-accepted');
  await guest.next('peer-allowed');
  const deliveries = [];
  guest.ws.on('message', bytes => {
    if (JSON.parse(bytes.toString()).type === 'signal') deliveries.push(true);
  });
  const closed = new Promise(resolve => guest.ws.once('close', code => resolve(code)));
  f.users.get('bob').disabled = true;
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'ice', candidate: { candidate: 'late' } } });
  assert.equal(await closed, 1008);
  assert.deepEqual(deliveries, [], 'live revocation must be checked before forwarding signaling');
  assert.equal(hp.username, 'alice');
});

test('unjoined same-owner rooms are reclaimed at 15 seconds without ending joined sessions', async t => {
  let time = Date.now();
  const f = await fixture(t, { now: () => time });
  const alice = f.cookie('alice');
  const bob = f.cookie('bob');
  const first = (await f.createRoom(alice)).data;
  const second = (await f.createRoom(alice)).data;
  assert.equal((await f.createRoom(alice)).status, 429);
  assert.equal((await f.createRoom(bob)).status, 200);

  const host = await f.connect(alice);
  host.send({ type: 'join', roomId: first.roomId, hostKey: first.hostKey });
  assert.equal((await host.next('joined')).role, 'host');
  time += 15_001;
  // "second" was never hosted; it must expire. The joined first room must
  // retain its original 5-minute lifetime and remain usable for invites.
  const replacement = await f.createRoom(alice);
  assert.equal(replacement.status, 200);
  const unused = await f.connect(alice);
  unused.send({ type: 'join', roomId: second.roomId, hostKey: second.hostKey });
  assert.equal((await unused.next('error')).code, 'INVALID_INVITE');
  host.send({ type: 'invite', recipient: 'bob' });
  assert.equal((await host.next('invited')).recipient, 'bob');
  assert.equal((await f.createRoom(alice)).status, 429);

  time += 15_001;
  assert.equal((await f.createRoom(alice)).status, 200,
    'second idle room must also release owner capacity');
  host.send({ type: 'invite', recipient: 'bob' });
  assert.equal((await host.next('invited')).recipient, 'bob');
  assert.notEqual(first.roomId, second.roomId);
});
