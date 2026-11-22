'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { writeFileSync } = require('node:fs');
const { fixture } = require('./support/issue242-app-fixture');
const WebSocket = require('ws');

test('real Root.ark session, CSRF, recipient ACL and revocation protect the app P2P path', { timeout: 110_000 }, async t => {
  const f = await fixture();
  t.after(f.close);
  const alice = await f.login('alice');
  const bob = await f.login('bob');
  const carol = await f.login('carol');
  const eve = await f.login('eve');
  assert.equal((await f.request('/p2p/')).status, 401);
  assert.equal((await f.request('/p2p/', { session: eve })).status, 403);
  const appPage = await f.request('/p2p/', { session: alice });
  assert.equal(appPage.status, 200, appPage.text.slice(0, 240));
  const me = await f.request('/auth/me', { session: alice });
  assert.equal(JSON.parse(me.text).experimentalP2pEnabled, true);
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: alice, csrf: false })).status, 403);
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: alice,
    requestOrigin: 'https://untrusted.example' })).status, 403);
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: eve })).status, 403);
  const created = await f.request('/p2p/rooms', { method: 'POST', session: alice });
  assert.equal(created.status, 200);
  const room = JSON.parse(created.text);
  assert.ok(room.roomId && room.hostKey);
  const host = await f.connect(alice);
  const target = await f.connect(bob);
  const wrongRecipient = await f.connect(carol);
  const intruder = await f.connect(eve);
  t.after(() => { for (const p of [host, target, wrongRecipient, intruder]) p.socket.terminate(); });
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const acceptedHost = await host.next('joined');
  assert.equal(acceptedHost.username, 'alice');
  host.send({ type: 'invite', recipient: 'eve' });
  assert.equal((await host.next('error')).code, 'BAD_RECIPIENT');
  host.send({ type: 'invite', recipient: 'bob' });
  const invitation = (await host.next('invited')).invitation;
  wrongRecipient.send({ type: 'join', roomId: room.roomId, invitation });
  assert.equal((await wrongRecipient.next('error')).code, 'INVALID_INVITE');
  host.send({ type: 'invite', recipient: 'carol' });
  const staleCarolInvitation = (await host.next('invited')).invitation;
  f.users.find(user => user.username === 'carol').sessionVersion++;
  writeFileSync(f.usersPath, JSON.stringify(f.users));
  const renewedCarol = await f.connect(await f.login('carol'));
  t.after(() => renewedCarol.socket.terminate());
  renewedCarol.send({ type: 'join', roomId: room.roomId, invitation: staleCarolInvitation });
  assert.equal((await renewedCarol.next('error')).code, 'INVALID_INVITE',
    'a new recipient session must not redeem an invitation issued for the old epoch');
  const unauthorizedClosed = new Promise(resolve => intruder.socket.once('close', resolve));
  intruder.send({ type: 'join', roomId: room.roomId, invitation });
  assert.equal(await unauthorizedClosed, 1008);
  target.send({ type: 'join', roomId: room.roomId, invitation });
  const joined = await target.next('joined');
  assert.equal(joined.username, 'bob');
  const peerJoined = await host.next('peer-joined');
  assert.equal(peerJoined.username, 'bob');
  target.send({ type: 'signal', to: acceptedHost.peerId, signal: { kind: 'offer', sdp: 'bad' } });
  assert.equal((await target.next('error')).code, 'FORBIDDEN');
  host.send({ type: 'request-peer', to: joined.peerId });
  const request = await target.next('peer-request');
  target.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  target.send({ type: 'signal', to: acceptedHost.peerId, signal: { kind: 'ice', candidate: { candidate: 'valid' } } });
  assert.equal((await host.next('signal')).peerId, joined.peerId);
  f.users.find(u => u.username === 'bob').permissions.listFiles = false;
  writeFileSync(f.usersPath, JSON.stringify(f.users));
  host.send({ type: 'signal', to: joined.peerId, signal: { kind: 'ice', candidate: { candidate: 'should-not-deliver' } } });
  const denied = await new Promise(resolve => target.socket.once('close', resolve));
  assert.equal(denied, 1008);
});

test('feature flag off leaves the real Root.ark app and navigation unchanged', { timeout: 90_000 }, async t => {
  const f = await fixture({ enabled: false });
  t.after(f.close);
  const alice = await f.login('alice');
  const me = await f.request('/auth/me', { session: alice });
  assert.equal(JSON.parse(me.text).experimentalP2pEnabled, undefined);
  assert.equal((await f.request('/p2p/', { session: alice })).status, 404);
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: alice })).status, 404);
});

test('P2P shared socket admits 35 consented ICE frames without weakening ordinary 30-frame burst denial',
  { timeout: 110_000 }, async t => {
    const f = await fixture();
    t.after(f.close);
    const alice = await f.login('alice');
    const bob = await f.login('bob');
    const carol = await f.login('carol');
    const roomResponse = await f.request('/p2p/rooms', { method: 'POST', session: alice });
    assert.equal(roomResponse.status, 200);
    const room = JSON.parse(roomResponse.text);
    const host = await f.connect(alice);
    const guest = await f.connect(bob);
    const ordinary = await f.connect(carol);
    const spoofed = await f.connect(carol);
    const brokerBounded = await f.connect(carol);
    t.after(() => [host, guest, ordinary, spoofed, brokerBounded]
      .forEach(peer => peer.socket.terminate()));
    host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
    const joinedHost = await host.next('joined');
    host.send({ type: 'invite', recipient: 'bob' });
    const invitation = (await host.next('invited')).invitation;
    guest.send({ type: 'join', roomId: room.roomId, invitation });
    const joinedGuest = await guest.next('joined');
    await host.next('peer-joined');
    host.send({ type: 'request-peer', to: joinedGuest.peerId });
    const request = await guest.next('peer-request');
    guest.send({ type: 'consent', requestId: request.requestId, accept: true });
    await host.next('peer-accepted');
    await guest.next('peer-allowed');

    for (let i = 0; i < 35; i++) {
      host.send({ type: 'signal', to: joinedGuest.peerId,
        signal: { kind: 'ice', candidate: { candidate: `candidate-${i}` } } });
    }
    for (let i = 0; i < 35; i++) {
      const forwarded = await guest.next('signal');
      assert.equal(forwarded.signal.candidate.candidate, `candidate-${i}`);
      assert.equal(forwarded.peerId, joinedHost.peerId);
    }
    assert.equal(host.socket.readyState, WebSocket.OPEN,
      'authorized ICE burst must not be closed by the unrelated generic realtime budget');

    const genericClose = new Promise(resolve => ordinary.socket.once('close', resolve));
    for (let i = 0; i < 31; i++) ordinary.send({ event: 'ping' });
    assert.equal(await genericClose, 1008,
      'ordinary realtime messages must retain their independent 30/10s limit');

    const spoofedClose = new Promise(resolve => spoofed.socket.once('close', resolve));
    for (let i = 0; i < 31; i++) spoofed.send({ type: 'signal', event: 'ping' });
    assert.equal(await spoofedClose, 1008,
      'a room-like message carrying a generic event cannot evade the generic limit');

    const brokerClose = new Promise(resolve => brokerBounded.socket.once('close', resolve));
    for (let i = 0; i < 121; i++) brokerBounded.send({ type: 'signal',
      roomId: 'unknown-room', to: 'unknown-peer', signal: { kind: 'ice' } });
    assert.equal(await brokerClose, 1008,
      'the experimental broker still enforces its independent 120-frame budget');
  });

test('P2: 16 hostile room creates by one real user cannot globally starve another user', { timeout: 110_000 }, async t => {
  const f = await fixture();
  t.after(f.close);
  const alice = await f.login('alice');
  const bob = await f.login('bob');
  const attempts = [];
  for (let i = 0; i < 16; i++) {
    attempts.push(await f.request('/p2p/rooms', { method: 'POST', session: alice }));
  }
  // Same owner should be allowed simultaneous legitimate browser instances,
  // but cannot consume the entire shared 16-room capacity without joining.
  const accepted = attempts.filter(result => result.status === 200);
  assert.equal(accepted.length, 2, 'a single owner is limited to two active rooms');
  assert.ok(attempts.slice(2).every(result => result.status === 429));
  const other = await f.request('/p2p/rooms', { method: 'POST', session: bob });
  assert.equal(other.status, 200, 'other authenticated users must not be starved');
  const rooms = [JSON.parse(accepted[0].text), JSON.parse(accepted[1].text), JSON.parse(other.text)];
  const clients = await Promise.all([f.connect(alice), f.connect(alice), f.connect(bob)]);
  t.after(() => clients.forEach(client => client.socket.terminate()));
  for (let i = 0; i < 3; i++) {
    clients[i].send({ type: 'join', roomId: rooms[i].roomId, hostKey: rooms[i].hostKey });
    assert.equal((await clients[i].next('joined')).role, 'host',
      'normal multi-client host join must remain functional');
  }
});

test('P2: signed room release frees abandoned capacity but cannot free a different principal or key', { timeout: 110_000 }, async t => {
  const f = await fixture();
  t.after(f.close);
  const alice = await f.login('alice');
  const bob = await f.login('bob');
  const first = await f.request('/p2p/rooms', { method: 'POST', session: alice });
  const second = await f.request('/p2p/rooms', { method: 'POST', session: alice });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: alice })).status, 429);
  const { roomId, hostKey } = JSON.parse(first.text);
  const proof = { roomId, hostKey };
  const release = (session, body, csrf = true) => f.request('/p2p/rooms/release', {
    method: 'POST', session, body: JSON.stringify(body), csrf,
  });

  assert.equal((await release(bob, proof)).status, 204);
  assert.equal((await release(alice, { ...proof, hostKey: '0'.repeat(64) })).status, 204);
  assert.equal((await release(alice, proof, false)).status, 403,
    'browser release requires the same session CSRF proof as creating a room');
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: alice })).status, 429,
    'unauthorized release attempts must not return owner capacity');
  assert.equal((await release(alice, proof)).status, 204);
  assert.equal((await release(alice, proof)).status, 204);
  assert.equal((await f.request('/p2p/rooms', { method: 'POST', session: alice })).status, 200,
    'canceling the delivered-but-unjoined room must immediately restore one owner slot');
});
