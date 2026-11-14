'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { writeFileSync, mkdirSync } = require('node:fs');
const { join } = require('node:path');
const { performance } = require('node:perf_hooks');
const { fixture } = require('./support/issue242-app-fixture');

const boundObject = { folderId: 'root', fileName: 'sealed.bin' };
const body = JSON.stringify({ boundObject });
function provisionDisposableLegacyObject(f, ciphertextBytes) {
  mkdirSync(join(f.directory, 'uploads'), { recursive: true });
  writeFileSync(join(f.directory, 'uploads', boundObject.fileName),
    Buffer.alloc(ciphertextBytes, 0xa5));
  writeFileSync(join(f.directory, 'data', 'encrypted-files.json'), JSON.stringify({
    'root/sealed.bin': {
      fileName: 'sealed.bin', folderId: 'root', uploadedAt: '2026-11-06T12:00:00.000Z',
      size: ciphertextBytes - 28, encryptedSize: ciphertextBytes,
      encryptionLevel: 'user-key', algorithm: 'aes-256-gcm',
      layers: [{ type: 'user', iv: '0011', authTag: '0022' }],
      accessControl: { owner: 'alice', authorizedUsers: ['alice', 'bob'], expiresAt: null },
    },
  }));
  writeFileSync(join(f.directory, 'data', 'file-permissions.json'), JSON.stringify({
    'root/sealed.bin': {
      public: false, owner: 'alice', users: { bob: { read: true, edit: false } },
    },
  }));
}

test('real Root.ark signed HTTP denies even a valid legacy ACL-bound ciphertext room without immutable and atomic authority',
  { timeout: 115_000 }, async t => {
    const f = await fixture();
    t.after(f.close);
    const alice = await f.login('alice');
    const bob = await f.login('bob');
    provisionDisposableLegacyObject(f, 92);
    const postBound = (session, input = boundObject) => f.request('/p2p/rooms', {
      method: 'POST', session, body: JSON.stringify({ boundObject: input }),
    });

    const before = await postBound(alice);
    assert.equal(before.status, 403,
      'a valid legacy owner+recipient file ACL is not an immutable signed object authority');
    assert.ok(!before.text.includes('roomId') && !before.text.includes('hostKey'),
      'missing trust capability cannot allocate even a temporary protected room');
    assert.equal((await postBound(bob)).status, 403,
      'recipient cannot claim the owner object');
    assert.equal((await postBound(alice, {
      ...boundObject, immutableVersionAuthority: true, mutationSerializedSnapshot: true,
    })).status, 403, 'untrusted request flags cannot elevate trust');

    const manual = await f.request('/p2p/rooms', { method: 'POST', session: alice });
    assert.equal(manual.status, 200, manual.text.slice(0, 180));
    const room = JSON.parse(manual.text);
    assert.ok(room.roomId && room.hostKey);
    assert.equal(room.boundObject, undefined, 'manual room has no false ciphertext entitlement');
    const host = await f.connect(alice);
    t.after(() => host.socket.terminate());
    host.send({ type: 'join', roomId: room.roomId, hostKey: room.hostKey });
    assert.equal((await host.next('joined')).role, 'host');
  });

test('16 concurrent real signed bound attempts reject without starving manual rooms or the HTTP event loop',
  { timeout: 115_000 }, async t => {
    const f = await fixture();
    t.after(f.close);
    const alice = await f.login('alice');
    const bob = await f.login('bob');
    provisionDisposableLegacyObject(f, 32 * 1024 * 1024);
    const start = performance.now();
    const results = await Promise.all(Array.from({ length: 16 }, () =>
      f.request('/p2p/rooms', { method: 'POST', session: alice, body })));
    assert.ok(results.every(value => value.status === 403),
      'a 32 MiB object cannot force expensive hash admission when trusted authorities are absent');
    assert.ok(results.every(value => !value.text.includes('roomId') && !value.text.includes('hostKey')));
    const elapsed = performance.now() - start;
    assert.ok(elapsed < 15_000, 'pretrust requests unexpectedly stalled for ' + Math.round(elapsed) + 'ms');

    const heartbeat = await f.request('/login.html');
    assert.equal(heartbeat.status, 200);
    const unbound = await f.request('/p2p/rooms', { method: 'POST', session: alice });
    const second = await f.request('/p2p/rooms', { method: 'POST', session: alice });
    const ownerFull = await f.request('/p2p/rooms', { method: 'POST', session: alice });
    const otherOwner = await f.request('/p2p/rooms', { method: 'POST', session: bob });
    assert.deepEqual([unbound.status, second.status, ownerFull.status, otherOwner.status],
      [200, 200, 429, 200], 'denied bound attempts must consume no global or per-owner room slots');
  });
