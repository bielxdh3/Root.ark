'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const WebSocket = require('ws');
const { makeBroker } = require('../server.cjs');

async function setup(t, opts) {
  const broker = makeBroker(opts);
  const origin = await broker.listen();
  const sockets = new Set();
  t.after(async () => {
    for (const ws of sockets) ws.terminate();
    await broker.close();
  });
  function connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(origin.replace('http:', 'ws:') + '/signal', { headers: { Origin: origin } });
      sockets.add(ws);
      ws.once('open', () => {
        const queue = [], waiters = [];
        ws.on('message', bytes => {
          const message = JSON.parse(bytes.toString());
          const i = waiters.findIndex(w => w.type === message.type);
          if (i < 0) queue.push(message);
          else waiters.splice(i, 1)[0].resolve(message);
        });
        resolve({
          ws,
          send: value => ws.send(JSON.stringify(value)),
          next: (type) => new Promise((res, rej) => {
            const i = queue.findIndex(m => m.type === type);
            if (i >= 0) return res(queue.splice(i, 1)[0]);
            const waiter = { type, resolve: res };
            waiters.push(waiter);
            setTimeout(() => {
              const pending = waiters.indexOf(waiter);
              if (pending >= 0) { waiters.splice(pending, 1); rej(new Error('timeout for ' + type)); }
            }, 1500).unref();
          })
        });
      });
      ws.once('error', reject);
    });
  }
  async function room() {
    const response = await fetch(origin + '/rooms', { method: 'POST', headers: { Origin: origin } });
    assert.equal(response.status, 200);
    return response.json();
  }
  return { broker, origin, connect, room };
}
test('invites are unpredictable, single-use, expired and revocable', async t => {
  let time = 1000;
  const h = await setup(t, { now: () => time, inviteTtlMs: 500 });
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  assert.equal((await host.next('joined')).role, 'host');

  const guessed = await h.connect();
  guessed.send({ type: 'join', roomId, invitation: 'easy-code' });
  assert.equal((await guessed.next('error')).code, 'INVALID_INVITE');

  host.send({ type: 'invite' });
  const invite = await host.next('invited');
  assert.match(invite.invitation, /^[0-9a-f]{64}$/);
  host.send({ type: 'revoke', inviteId: invite.inviteId });
  assert.equal((await host.next('revoked')).inviteId, invite.inviteId);
  guessed.send({ type: 'join', roomId, invitation: invite.invitation });
  assert.equal((await guessed.next('error')).code, 'INVALID_INVITE');

  host.send({ type: 'invite' });
  const expired = await host.next('invited');
  time += 501;
  guessed.send({ type: 'join', roomId, invitation: expired.invitation });
  assert.equal((await guessed.next('error')).code, 'INVALID_INVITE');

  host.send({ type: 'invite' });
  const live = await host.next('invited');
  guessed.send({ type: 'join', roomId, invitation: live.invitation });
  assert.equal((await guessed.next('joined')).role, 'guest');
  guessed.send({ type: 'join', roomId, invitation: live.invitation });
  assert.equal((await guessed.next('error')).code, 'FORBIDDEN');
  const replay = await h.connect();
  replay.send({ type: 'join', roomId, invitation: live.invitation });
  assert.equal((await replay.next('error')).code, 'INVALID_INVITE');
});

test('signal requires host request and recipient consent; revoke disconnects guest', async t => {
  const h = await setup(t);
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  const hp = await host.next('joined');
  host.send({ type: 'invite' });
  const { invitation } = await host.next('invited');
  const guest = await h.connect();
  guest.send({ type: 'join', roomId, invitation });
  const gp = await guest.next('joined');
  await host.next('peer-joined');
  guest.send({ type: 'signal', to: hp.peerId, signal: { kind: 'offer', sdp: 'forged' } });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  guest.send({ type: 'invite' });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  host.send({ type: 'request-peer', to: gp.peerId });
  const request = await guest.next('peer-request');
  assert.equal(request.peerId, hp.peerId);
  guest.send({ type: 'consent', requestId: 'incorrect', accept: true });
  assert.equal((await guest.next('error')).code, 'FORBIDDEN');
  guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  assert.equal((await host.next('peer-accepted')).peerId, gp.peerId);
  assert.equal((await guest.next('peer-allowed')).peerId, hp.peerId);
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'ice', candidate: { candidate: 'fixture' } } });
  const forwarded = await guest.next('signal');
  assert.equal(forwarded.signal.candidate.candidate, 'fixture');
  host.send({ type: 'kick', to: gp.peerId });
  assert.equal((await guest.next('error')).code, 'REVOKED');
  assert.equal((await host.next('peer-left')).peerId, gp.peerId);
  guest.ws.terminate();
  const replay = await h.connect();
  replay.send({ type: 'join', roomId, invitation });
  assert.equal((await replay.next('error')).code, 'INVALID_INVITE');
});

test('room size, invalid origin and bounded WebSocket payload', async t => {
  const h = await setup(t);
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  await host.next('joined');
  for (let i = 0; i < 3; i++) {
    host.send({ type: 'invite' });
    const { invitation } = await host.next('invited');
    const guest = await h.connect();
    guest.send({ type: 'join', roomId, invitation });
    await guest.next('joined');
  }
  host.send({ type: 'invite' });
  assert.equal((await host.next('error')).code, 'FULL');

  const wsBadOrigin = new WebSocket(h.origin.replace('http:', 'ws:') + '/signal', { headers: { Origin: 'http://invalid.test' } });
  wsBadOrigin.on('error', () => {});
  const status = await new Promise(resolve => wsBadOrigin.once('unexpected-response', (_req, res) => {
    res.resume();
    resolve(res.statusCode);
  }));
  assert.equal(status, 403);

  const oversized = await h.connect();
  const closed = new Promise(resolve => oversized.ws.once('close', code => resolve(code)));
  oversized.ws.send('x'.repeat(20_000));
  assert.equal(await closed, 1009);
});

test('room expires even when idle, and rejected consent cannot forward SDP', async t => {
  let now = 100;
  const h = await setup(t, { now: () => now, roomTtlMs: 300 });
  const { roomId, hostKey } = await h.room();
  const host = await h.connect();
  host.send({ type: 'join', roomId, hostKey });
  const hp = await host.next('joined');
  host.send({ type: 'invite' });
  const { invitation } = await host.next('invited');
  const guest = await h.connect();
  guest.send({ type: 'join', roomId, invitation });
  const gp = await guest.next('joined');
  host.send({ type: 'request-peer', to: gp.peerId });
  const req = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: req.requestId, accept: false });
  assert.equal((await host.next('peer-declined')).peerId, gp.peerId);
  host.send({ type: 'signal', to: gp.peerId, signal: { kind: 'offer', sdp: { type: 'offer', sdp: 'fixture' } } });
  assert.equal((await host.next('error')).code, 'FORBIDDEN');
  assert.equal(hp.role, 'host');
  now = 401;
  assert.equal((await host.next('error')).code, 'ROOM_CLOSED');
  assert.equal((await guest.next('error')).code, 'ROOM_CLOSED');
});
