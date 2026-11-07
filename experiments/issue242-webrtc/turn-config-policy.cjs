'use strict';

// DEV-OFF, source-only fixture contract for a FUTURE trusted TURN issuer.
// No TURN provider, cryptographic issuer proof, socket, broker integration,
// browser delivery, or ICE configuration exists here. A field named "atomic"
// is only a claim made by the supplied fixture; checking its shape cannot
// establish that all real ACL writers share a serialized authority.
//
// The issuer metadata is supplied as [name, value] pairs to reject duplicate
// fields instead of silently accepting JSON.parse's last-write-wins behavior.
// Never log the supplied issuance. The only credential-bearing result property
// is nonenumerable and explicitly for trusted server-side fixture inspection.
const MAX_TTL_MS = 60_000;
const MAX_CIPHERTEXT_BYTES = 32 * 1024 * 1024;
const DENIED = Object.freeze({ accepted: false, authorizesIo: false });
const INPUT_KEYS = [
  'nowMs', 'trustedPublicOrigin', 'allowedRelayUrls',
  'actor', 'room', 'aclSnapshot', 'issuedFields',
];
const ACTOR_KEYS = ['principal', 'sessionEpoch'];
const ROOM_KEYS = ['id', 'epoch', 'owner', 'guests', 'boundObject', 'aclRevisionFloor'];
const SNAPSHOT_KEYS = ['atomic', 'owner', 'guests', 'roomId', 'roomEpoch', 'boundObject', 'revision'];
const OBJECT_KEYS = ['folderId', 'fileName', 'pin', 'sha256', 'bytes'];
const ISSUED_KEYS = [
  'turnUrl', 'username', 'credential', 'origin', 'principal',
  'sessionEpoch', 'roomId', 'roomEpoch', 'aclRevision',
  'pin', 'sha256', 'bytes', 'issuedAtMs', 'expiresAtMs',
];

function exactRecord(value, expectedKeys) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actualKeys = Reflect.ownKeys(value);
  if (actualKeys.length !== expectedKeys.length) return false;
  return expectedKeys.every(key => {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return descriptor && Object.hasOwn(descriptor, 'value');
  });
}

function exactArray(value, length = null) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
    (length !== null && value.length !== length)) return false;
  if (Reflect.ownKeys(value).length !== value.length + 1) return false;
  for (let i = 0; i < value.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) return false;
  }
  return true;
}

function nonnegativeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function principal(value) {
  return typeof value === 'string' &&
    /^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$/.test(value);
}

function fqdn(value) {
  if (typeof value !== 'string' || value.length > 253) return false;
  const labels = value.split('.');
  return labels.length >= 2 && !/^\d+$/.test(labels.at(-1)) &&
    labels.every(label => label.length >= 1 && label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label));
}

function relayUrl(value) {
  if (typeof value !== 'string') return false;
  // Exact single TLS-over-TCP URL on the standard TURN/TLS port. No userinfo,
  // encoded aliases, fragments, alternative transports or query parameters.
  const match = /^turns:([^/:?#@\s]+):5349\?transport=tcp$/.exec(value);
  return !!match && fqdn(match[1]);
}

function publicHttpsOrigin(value) {
  if (typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === 'https:' && parsed.origin === value &&
      parsed.pathname === '/' && parsed.search === '' && parsed.hash === '' &&
      parsed.username === '' && parsed.password === '' && fqdn(parsed.hostname);
  } catch {
    return false;
  }
}

function boundObject(value) {
  return exactRecord(value, OBJECT_KEYS) &&
    typeof value.folderId === 'string' && /^[A-Za-z0-9_-]{1,80}$/.test(value.folderId) &&
    typeof value.fileName === 'string' && value.fileName.length > 0 &&
    value.fileName.length <= 100 && value.fileName !== '.' && value.fileName !== '..' &&
    !/[/\\\x00-\x1f\x7f]/.test(value.fileName) &&
    typeof value.pin === 'string' && /^[a-f0-9]{64}$/.test(value.pin) &&
    typeof value.sha256 === 'string' && /^[a-f0-9]{64}$/.test(value.sha256) &&
    Number.isSafeInteger(value.bytes) && value.bytes >= 1 &&
    value.bytes <= MAX_CIPHERTEXT_BYTES;
}

function sameBoundObject(a, b) {
  return OBJECT_KEYS.every(key => a[key] === b[key]);
}

function guests(value) {
  if (!exactArray(value) || value.length < 1 || value.length > 3) return false;
  return value.every((name, i) => principal(name) &&
    (i === 0 || value[i - 1] < name));
}

function issuedPairs(value) {
  if (!exactArray(value, ISSUED_KEYS.length)) return null;
  const data = Object.create(null);
  for (const entry of value) {
    if (!exactArray(entry, 2) || typeof entry[0] !== 'string' ||
      !ISSUED_KEYS.includes(entry[0]) || Object.hasOwn(data, entry[0])) return null;
    data[entry[0]] = entry[1];
  }
  return Object.keys(data).length === ISSUED_KEYS.length ? data : null;
}

function check(input) {
  if (!exactRecord(input, INPUT_KEYS) || !nonnegativeInteger(input.nowMs) ||
    !publicHttpsOrigin(input.trustedPublicOrigin) ||
    !exactArray(input.allowedRelayUrls) ||
    input.allowedRelayUrls.length === 0 || input.allowedRelayUrls.length > 8 ||
    !input.allowedRelayUrls.every(relayUrl) ||
    new Set(input.allowedRelayUrls).size !== input.allowedRelayUrls.length) return null;

  const { actor, room, aclSnapshot } = input;
  if (!exactRecord(actor, ACTOR_KEYS) || !principal(actor.principal) ||
    !nonnegativeInteger(actor.sessionEpoch) ||
    !exactRecord(room, ROOM_KEYS) || !/^[a-f0-9]{16}$/.test(room.id) ||
    !nonnegativeInteger(room.epoch) || !principal(room.owner) ||
    !guests(room.guests) || room.guests.includes(room.owner) ||
    !boundObject(room.boundObject) ||
    !nonnegativeInteger(room.aclRevisionFloor) ||
    (actor.principal !== room.owner && !room.guests.includes(actor.principal))) return null;

  // A single complete snapshot must cover the exact owner, every currently
  // joined guest, the exact pinned ciphertext and the room's monotonic floor.
  // This is deliberately a fixture-format check; atomic:true is not proof of
  // a real lock, transaction, independent signature, or current authority.
  if (!exactRecord(aclSnapshot, SNAPSHOT_KEYS) || aclSnapshot.atomic !== true ||
    aclSnapshot.owner !== room.owner ||
    !guests(aclSnapshot.guests) ||
    aclSnapshot.guests.length !== room.guests.length ||
    !aclSnapshot.guests.every((name, i) => name === room.guests[i]) ||
    aclSnapshot.roomId !== room.id || aclSnapshot.roomEpoch !== room.epoch ||
    !boundObject(aclSnapshot.boundObject) ||
    !sameBoundObject(aclSnapshot.boundObject, room.boundObject) ||
    !nonnegativeInteger(aclSnapshot.revision) ||
    aclSnapshot.revision < room.aclRevisionFloor) return null;

  const issued = issuedPairs(input.issuedFields);
  if (!issued || !relayUrl(issued.turnUrl) ||
    !input.allowedRelayUrls.includes(issued.turnUrl) ||
    !publicHttpsOrigin(issued.origin) || issued.origin !== input.trustedPublicOrigin ||
    issued.principal !== actor.principal || issued.sessionEpoch !== actor.sessionEpoch ||
    issued.roomId !== room.id || issued.roomEpoch !== room.epoch ||
    issued.aclRevision !== aclSnapshot.revision ||
    issued.pin !== room.boundObject.pin || issued.sha256 !== room.boundObject.sha256 ||
    issued.bytes !== room.boundObject.bytes) return null;

  if (typeof issued.username !== 'string' || typeof issued.credential !== 'string' ||
    issued.username.length < 1 || issued.username.length > 128 ||
    issued.credential.length < 1 || issued.credential.length > 512 ||
    !/^[\x21-\x7e]+$/.test(issued.username) ||
    !/^[\x21-\x7e]+$/.test(issued.credential)) return null;

  const { nowMs } = input;
  if (!nonnegativeInteger(issued.issuedAtMs) ||
    !nonnegativeInteger(issued.expiresAtMs) ||
    issued.issuedAtMs > nowMs || issued.expiresAtMs <= nowMs ||
    issued.expiresAtMs - issued.issuedAtMs > MAX_TTL_MS ||
    issued.expiresAtMs <= issued.issuedAtMs ||
    issued.expiresAtMs - nowMs > MAX_TTL_MS) return null;
  return issued;
}

function assessEphemeralTurnFixture(input) {
  try {
    const issued = check(input);
    if (!issued) return DENIED;
    // The output does not build an RTCIceServer, authorize I/O, or expose a
    // browser-ready config. Hide credentials from console/JSON/spread defaults.
    const result = {
      accepted: true,
      authorizesIo: false,
      turnUrl: issued.turnUrl,
      expiresAtMs: issued.expiresAtMs,
    };
    Object.defineProperty(result, 'serverOnlyCredentials', {
      configurable: false,
      enumerable: false,
      writable: false,
      value: Object.freeze({ username: issued.username, credential: issued.credential }),
    });
    return Object.freeze(result);
  } catch {
    // Malformed/proxy/accessor inputs never leak a supplied secret or exception.
    return DENIED;
  }
}

module.exports = { assessEphemeralTurnFixture };
