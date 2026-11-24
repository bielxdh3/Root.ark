'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { writeFileSync } = require('node:fs');
const { fixture } = require('./support/issue242-app-fixture');

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
