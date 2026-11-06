'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { writeFileSync, mkdirSync } = require('node:fs');
const { createHash } = require('node:crypto');
const { join } = require('node:path');
const { fixture } = require('./support/issue242-app-fixture');

test('real signed sessions require an exact current encrypted object ACL for bound P2P signaling', { timeout: 115_000 }, async t => {
  const f = await fixture();
  t.after(f.close);
  const alice = await f.login('alice');
  const bob = await f.login('bob');
  const carol = await f.login('carol');
  mkdirSync(join(f.directory, 'uploads'), { recursive: true });
  const ciphertextPath = join(f.directory, 'uploads', 'sealed.bin');
  const ciphertext = Buffer.alloc(92, 0xa5); // disposable opaque ciphertext fixture only
  writeFileSync(ciphertextPath, ciphertext);
  const metadataPath = join(f.directory, 'data', 'encrypted-files.json');
  const permissionsPath = join(f.directory, 'data', 'file-permissions.json');
  const metadata = {
    fileName: 'sealed.bin', folderId: 'root', uploadedAt: '2026-11-06T12:00:00.000Z',
    size: 64, encryptedSize: 92, encryptionLevel: 'user-key',
    algorithm: 'aes-256-gcm', layers: [{ type: 'user', iv: '0011', authTag: '0022' }],
    accessControl: { owner: 'alice', authorizedUsers: ['alice', 'bob'], expiresAt: null },
  };
  const stored = { 'root/sealed.bin': metadata };
  const save = () => writeFileSync(metadataPath, JSON.stringify(stored));
  save();
  const boundObject = { folderId: 'root', fileName: 'sealed.bin' };
  const create = async (session, object) => f.request('/p2p/rooms', {
    method: 'POST', session, body: JSON.stringify({ boundObject: object }),
  });
  assert.equal((await create(alice, boundObject)).status, 403,
    'missing exact private per-file ACL is not an implicit public grant');
  const filePermissions = { 'root/sealed.bin': {
    public: false, owner: 'alice', users: { bob: { read: true, edit: false } }
  } };
  writeFileSync(permissionsPath, JSON.stringify(filePermissions));
  assert.equal((await create(bob, boundObject)).status, 403, 'recipient cannot impersonate owner');
  assert.equal((await create(alice, { folderId: 'other', fileName: 'sealed.bin' })).status, 403,
    'same basename in another tenant/folder does not inherit authorization');
  assert.equal((await create(alice, { folderId: 'root', fileName: '../sealed.bin' })).status, 403);
  const created = await create(alice, boundObject);
  assert.equal(created.status, 200, created.text.slice(0, 180));
  const room = JSON.parse(created.text);
  assert.deepEqual(room.boundObject, { ...boundObject, size: ciphertext.byteLength,
    sha256: createHash('sha256').update(ciphertext).digest('hex') },
  'room is bound to the exact ciphertext byte digest and ACL');
  const host = await f.connect(alice);
  const target = await f.connect(bob);
  const other = await f.connect(carol);
  t.after(() => [host, target, other].forEach(c => c.socket.terminate()));
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hostJoined = await host.next('joined');
  assert.deepEqual(hostJoined.boundObject, room.boundObject);
  host.send({ type: 'invite', recipient: 'carol' });
  assert.equal((await host.next('error')).code, 'OBJECT_ACCESS_DENIED');
  filePermissions['root/sealed.bin'].users = {};
  writeFileSync(permissionsPath, JSON.stringify(filePermissions));
  host.send({ type: 'invite', recipient: 'bob' });
  assert.equal((await host.next('error')).code, 'OBJECT_ACCESS_DENIED',
    'an encrypted-files grant cannot override the stricter current file ACL');
  filePermissions['root/sealed.bin'].users.bob = { read: true, edit: false };
  writeFileSync(permissionsPath, JSON.stringify(filePermissions));
  host.send({ type: 'invite', recipient: 'bob' });
  const invite = (await host.next('invited')).invitation;
  target.send({ type: 'join', roomId: room.roomId, invitation: invite });
  const bobJoined = await target.next('joined');
  host.send({ type: 'request-peer', to: bobJoined.peerId });
  const offer = await target.next('peer-request');
  target.send({ type: 'consent', requestId: offer.requestId, accept: true });
  await host.next('peer-accepted');
  target.send({ type: 'signal', to: hostJoined.peerId, signal: { kind: 'ice', candidate: { candidate: 'fixture' } } });
  assert.equal((await host.next('signal')).peerId, bobJoined.peerId);
  const closed = new Promise(resolve => target.socket.once('close', resolve));
  metadata.accessControl.authorizedUsers = ['alice']; // revocation in the real authoritative JSON store.
  save();
  host.send({ type: 'signal', to: bobJoined.peerId, signal: { kind: 'ice', candidate: { candidate: 'forbidden' } } });
  assert.equal(await closed, 1008, 'revoked recipient loses signaling admission even when already consented');
  const second = await create(alice, boundObject);
  assert.equal(second.status, 200);
  const nextRoom = JSON.parse(second.text);
  const host2 = await f.connect(alice);
  t.after(() => host2.socket.terminate());
  host2.send({ type: 'join', roomId: nextRoom.roomId, hostKey: nextRoom.hostKey });
  await host2.next('joined');
  host2.send({ type: 'invite', recipient: 'bob' });
  assert.equal((await host2.next('error')).code, 'OBJECT_ACCESS_DENIED');
  metadata.accessControl.authorizedUsers.push('bob');
  save();
  host2.send({ type: 'invite', recipient: 'bob' });
  const newInvite = (await host2.next('invited')).invitation;
  writeFileSync(ciphertextPath, Buffer.alloc(92, 0xb6)); // in-place bytes change, metadata unchanged
  const restoredBob = await f.connect(bob);
  t.after(() => restoredBob.socket.terminate());
  restoredBob.send({ type: 'join', roomId: nextRoom.roomId, invitation: newInvite });
  assert.equal((await restoredBob.next('error')).code, 'INVALID_INVITE',
    'replacement under same filename invalidates bound room grant');
  assert.ok(other.socket.readyState <= 1);
});

test('a bounded ciphertext signal flood leaves the real HTTP event loop responsive', { timeout: 115_000 }, async t => {
  const f = await fixture();
  t.after(f.close);
  const alice = await f.login('alice');
  const bob = await f.login('bob');
  const ciphertext = Buffer.alloc(32 * 1024 * 1024, 0xa7);
  mkdirSync(join(f.directory, 'uploads'), { recursive: true });
  writeFileSync(join(f.directory, 'uploads', 'load.bin'), ciphertext);
  writeFileSync(join(f.directory, 'data', 'encrypted-files.json'), JSON.stringify({
    'root/load.bin': {
      fileName: 'load.bin', folderId: 'root', uploadedAt: '2026-11-06T12:00:00.000Z',
      size: ciphertext.length - 28, encryptedSize: ciphertext.length,
      encryptionLevel: 'user-key', algorithm: 'aes-256-gcm',
      layers: [{ type: 'user', iv: '0011', authTag: '0022' }],
      accessControl: { owner: 'alice', authorizedUsers: ['alice', 'bob'], expiresAt: null },
    },
  }));
  writeFileSync(join(f.directory, 'data', 'file-permissions.json'), JSON.stringify({
    'root/load.bin': { owner: 'alice', public: false, users: { bob: { read: true } } },
  }));
  const created = await f.request('/p2p/rooms', { method: 'POST', session: alice,
    body: JSON.stringify({ boundObject: { folderId: 'root', fileName: 'load.bin' } }) });
  assert.equal(created.status, 200);
  const room = JSON.parse(created.text);
  const host = await f.connect(alice);
  const guest = await f.connect(bob);
  t.after(() => { host.socket.terminate(); guest.socket.terminate(); });
  host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
  const hostJoined = await host.next('joined');
  host.send({ type: 'invite', recipient: 'bob' });
  const invitation = (await host.next('invited')).invitation;
  guest.send({ type: 'join', roomId: room.roomId, invitation });
  const joined = await guest.next('joined');
  host.send({ type: 'request-peer', to: joined.peerId });
  const request = await guest.next('peer-request');
  guest.send({ type: 'consent', requestId: request.requestId, accept: true });
  await host.next('peer-accepted');
  for (let i = 0; i < 12; i++) guest.send({ type: 'signal', to: hostJoined.peerId,
    signal: { kind: 'ice', candidate: { candidate: 'load-' + i } } });
  await host.next('signal', 30_000);
  const before = performance.now();
  const heartbeat = await f.request('/login.html');
  const elapsed = performance.now() - before;
  assert.equal(heartbeat.status, 200);
  assert.ok(elapsed < 700, `HTTP event loop stalled for ${Math.round(elapsed)}ms under bounded signaling load`);
  const closed = new Promise(resolve => guest.socket.once('close', resolve));
  writeFileSync(join(f.directory, 'uploads', 'load.bin'), Buffer.alloc(ciphertext.length, 0xb8));
  let closeTimeout;
  try {
    assert.equal(await Promise.race([closed, new Promise((_, reject) => {
      closeTimeout = setTimeout(() => reject(new Error('changed ciphertext kept an authorized peer alive')), 30_000);
    })]), 1000, 'same-size replacement during queued signaling must close the pinned room');
  } finally { clearTimeout(closeTimeout); }
});
