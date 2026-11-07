'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { inspect } = require('node:util');
const { assessEphemeralTurnFixture } = require('../turn-config-policy.cjs');

const TURN_URL = 'turns:relay.example.test:5349?transport=tcp';
const ORIGIN = 'https://files.example.test';
const NOW = 1_790_000_000_000;
const PIN = 'a'.repeat(64);
const DIGEST = 'b'.repeat(64);
const object = () => ({ folderId: 'root', fileName: 'sealed.bin',
  pin: PIN, sha256: DIGEST, bytes: 4096 });

function fixture() {
  return {
    nowMs: NOW,
    trustedPublicOrigin: ORIGIN,
    allowedRelayUrls: [TURN_URL],
    actor: { principal: 'bob', sessionEpoch: 3 },
    room: { id: '0123456789abcdef', epoch: 5, owner: 'alice',
      guests: ['bob'], boundObject: object(), aclRevisionFloor: 7 },
    aclSnapshot: { atomic: true, owner: 'alice', guests: ['bob'],
      roomId: '0123456789abcdef', roomEpoch: 5,
      boundObject: object(), revision: 7 },
    issuedFields: [
      ['turnUrl', TURN_URL],
      ['username', 'fixture-username-180000'],
      ['credential', 'fixture-only-credential-value'],
      ['origin', ORIGIN],
      ['principal', 'bob'],
      ['sessionEpoch', 3],
      ['roomId', '0123456789abcdef'],
      ['roomEpoch', 5],
      ['aclRevision', 7],
      ['pin', PIN],
      ['sha256', DIGEST],
      ['bytes', 4096],
      ['issuedAtMs', NOW - 1_000],
      ['expiresAtMs', NOW + 30_000],
    ],
  };
}
function field(input, name, value) {
  const pair = input.issuedFields.find(entry => entry[0] === name);
  assert.ok(pair, 'fixture field exists');
  pair[1] = value;
}
function denied(input, label) {
  const result = assessEphemeralTurnFixture(input);
  assert.deepEqual(result, { accepted: false, authorizesIo: false }, label);
  assert.equal(result.serverOnlyCredentials, undefined, label);
}

test('mock trusted ephemeral TURN metadata validates without enabling I/O or exposing secrets in logs', () => {
  const input = fixture();
  const before = structuredClone(input);
  const result = assessEphemeralTurnFixture(input);
  assert.equal(result.accepted, true);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.iceServers, undefined);
  assert.equal(result.turnUrl, TURN_URL);
  assert.equal(result.expiresAtMs, NOW + 30_000);
  assert.equal(result.serverOnlyCredentials.username, 'fixture-username-180000');
  assert.equal(result.serverOnlyCredentials.credential, 'fixture-only-credential-value');
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.serverOnlyCredentials), true);
  assert.equal(Object.keys(result).includes('serverOnlyCredentials'), false);
  for (const printed of [JSON.stringify(result), inspect(result)]) {
    assert.equal(printed.includes('fixture-only-credential-value'), false);
    assert.equal(printed.includes('fixture-username-180000'), false);
    assert.equal(printed.includes('iceServers'), false);
  }
  assert.deepEqual(input, before, 'pure policy must not mutate supplied state');
});

test('rejects arbitrary URLs, malformed allowlists and embedded URL credentials', async t => {
  const badUrls = [
    'stun:relay.example.test:5349',
    'stuns:relay.example.test:5349',
    'turn:relay.example.test:5349?transport=tcp',
    'http://relay.example.test:5349',
    'https://relay.example.test:5349',
    'turns://relay.example.test:5349?transport=tcp',
    'turns:relay.example.test:3478?transport=tcp',
    'turns:relay.example.test:5349?transport=udp',
    'turns:relay.example.test:5349?transport=tcp&bypass=true',
    'turns:relay.example.test:5349?transport=tcp#fragment',
    'turns:relay.example.test.evil.test:5349?transport=tcp',
    'turns:user:password@relay.example.test:5349?transport=tcp',
    'turns:username@relay.example.test:5349?transport=tcp',
    'turns:relay.example.test:5349?transport=tcp@evil.test',
    'turns:RELAY.example.test:5349?transport=tcp',
    'turns:127.0.0.1:5349?transport=tcp',
    'turns:relay.example.test.:5349?transport=tcp',
    'turns:relay.example.test:5349?transport=tcp\nsecret',
  ];
  for (const [i, url] of badUrls.entries()) {
    await t.test('invalid URL ' + i, () => {
      const input = fixture();
      field(input, 'turnUrl', url);
      denied(input, 'URL must use exact allowlisted TLS/TCP relay');
      const invalidList = fixture();
      invalidList.allowedRelayUrls = [url];
      denied(invalidList, 'allowlist itself must contain only safe TURN URLs');
    });
  }
  const unlisted = fixture();
  field(unlisted, 'turnUrl', 'turns:other.example.test:5349?transport=tcp');
  denied(unlisted, 'valid syntax without exact allowlist entry is insufficient');
  const duplicateList = fixture();
  duplicateList.allowedRelayUrls.push(TURN_URL);
  denied(duplicateList, 'duplicate allowlist entries rejected');
  const extraList = fixture();
  extraList.allowedRelayUrls.push('turns:other.example.test:5349?transport=tcp');
  assert.equal(assessEphemeralTurnFixture(extraList).accepted, true,
    'trusted allowlist may contain another distinct relay while selection stays exact');
});

test('rejects unknown, missing, duplicate and unsafe metadata fields', () => {
  const bad = [
    input => input.issuedFields.push(['turnUrl', TURN_URL]),
    input => input.issuedFields.push(['extra', 'attacker-data']),
    input => input.issuedFields.pop(),
    input => input.issuedFields[1] = ['credential', 'missing-username'],
    input => input.issuedFields[0] = ['turnUrl'],
    input => input.issuedFields[0] = ['turnUrl', TURN_URL, 'extra'],
    input => { input.issuedFields = {}; },
    input => { input.extra = true; },
    input => { input.room.extra = true; },
    input => { input.actor.password = 'fixture'; },
    input => { input.aclSnapshot.extra = true; },
    input => { input.room.boundObject.secret = true; },
    input => { input.aclSnapshot.boundObject.secret = true; },
    input => { field(input, 'username', ''); },
    input => { field(input, 'username', 'user\nnew-line'); },
    input => { field(input, 'credential', ''); },
    input => { field(input, 'credential', 'fixture\nlogging-injection'); },
    input => { field(input, 'credential', 'x'.repeat(513)); },
    input => { input.issuedFields[0] = [Symbol('turnUrl'), TURN_URL]; },
    input => { Object.defineProperty(input.actor, 'principal', { get() { throw Error('fixture poison'); } }); },
    input => { Object.setPrototypeOf(input.issuedFields, null); },
  ];
  bad.forEach((change, i) => {
    const input = fixture();
    change(input);
    denied(input, 'malformed field case ' + i);
  });
});

test('rejects principal, session, room epoch, origin and object identity mismatches', () => {
  const bad = [
    input => field(input, 'principal', 'mallory'),
    input => field(input, 'sessionEpoch', 2),
    input => field(input, 'roomId', '0000000000000000'),
    input => field(input, 'roomEpoch', 4),
    input => field(input, 'origin', 'https://evil.example.test'),
    input => { input.actor.principal = 'mallory'; },
    input => { input.actor.sessionEpoch = 4; },
    input => { input.room.id = '1111111111111111'; },
    input => { input.room.epoch = 9; },
    input => { input.room.owner = 'mallory'; },
    input => { input.room.guests = ['charlie']; },
    input => { input.room.guests = ['bob', 'bob']; },
    input => { input.room.boundObject.sha256 = 'c'.repeat(64); },
    input => { input.room.boundObject.pin = 'c'.repeat(64); },
    input => { input.room.boundObject.bytes = 0; },
    input => { input.trustedPublicOrigin = 'http://files.example.test'; },
    input => { input.trustedPublicOrigin = 'https://files.example.test/path'; },
    input => { input.trustedPublicOrigin = 'https://user@files.example.test'; },
    input => { input.trustedPublicOrigin = 'https://files.example.test.evil.test'; },
  ];
  bad.forEach((change, i) => {
    const input = fixture();
    change(input);
    denied(input, 'identity/origin case ' + i);
  });
});

test('requires matching whole-party bound ACL fixture with a current revision', () => {
  const bad = [
    input => { input.aclSnapshot = null; },
    input => { input.aclSnapshot = Promise.resolve(input.aclSnapshot); },
    input => { input.aclSnapshot.atomic = false; },
    input => { delete input.aclSnapshot.atomic; },
    input => { input.aclSnapshot.owner = 'mallory'; },
    input => { input.aclSnapshot.guests = []; },
    input => { input.aclSnapshot.guests = ['bob', 'charlie']; },
    input => { input.aclSnapshot.guests = ['bob', 'bob']; },
    input => { input.aclSnapshot.roomId = 'ffffffffffffffff'; },
    input => { input.aclSnapshot.roomEpoch = 6; },
    input => { input.aclSnapshot.revision = 6; },
    input => { input.aclSnapshot.revision = NaN; },
    input => { input.aclSnapshot.boundObject.sha256 = 'f'.repeat(64); },
    input => { input.aclSnapshot.boundObject.folderId = 'other'; },
    input => { field(input, 'aclRevision', 6); },
    input => { field(input, 'aclRevision', 8); },
    input => { field(input, 'pin', 'c'.repeat(64)); },
    input => { field(input, 'sha256', 'c'.repeat(64)); },
    input => { field(input, 'bytes', 4097); },
    input => { input.room.aclRevisionFloor = 8; },
    input => { input.room.boundObject = null; },
  ];
  bad.forEach((change, i) => {
    const input = fixture();
    change(input);
    denied(input, 'atomic ACL case ' + i);
  });
});

test('rejects expired, excessive, future-issued and non-finite TTLs', () => {
  const bad = [
    input => { field(input, 'expiresAtMs', NOW); },
    input => { field(input, 'expiresAtMs', NOW - 1); },
    input => { field(input, 'expiresAtMs', NOW + 60_001); },
    input => { field(input, 'expiresAtMs', Number.NaN); },
    input => { field(input, 'expiresAtMs', Infinity); },
    input => { field(input, 'expiresAtMs', String(NOW + 1)); },
    input => { field(input, 'issuedAtMs', NOW + 1); },
    input => { field(input, 'issuedAtMs', NOW - 60_001); },
    input => { field(input, 'issuedAtMs', Number.NaN); },
    input => { field(input, 'issuedAtMs', -1); },
    input => { input.nowMs = NaN; },
    input => { input.nowMs = Infinity; },
    input => { input.nowMs = -1; },
  ];
  bad.forEach((change, i) => {
    const input = fixture();
    change(input);
    denied(input, 'expiration case ' + i);
  });
});
