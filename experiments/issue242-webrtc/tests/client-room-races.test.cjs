'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

const boundObject = { folderId: 'root', fileName: 'sealed.bin', size: 92,
  sha256: 'a'.repeat(64) };

function browser({ fetch, cookie = '', digest = async () => new Uint8Array(32).buffer }) {
  const elements = new Map();
  const sockets = [];
  const peerConnections = [];
  const element = () => ({
    hidden: false, disabled: false, textContent: '', dataset: {}, attributes: new Map(),
    setAttribute(name, value) { this.attributes.set(name, String(value)); },
    getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; },
    removeAttribute(name) { this.attributes.delete(name); },
    replaceChildren() {}, append() {}, remove() {}, addEventListener() {},
  });
  const document = {
    cookie,
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, element());
      return elements.get(id);
    },
    createElement: element,
    querySelectorAll: () => [],
  };
  class FakeWebSocket {
    constructor() { this.readyState = 1; this.sent = []; sockets.push(this); }
    send(data) { this.sent.push(JSON.parse(data)); }
    close() { this.readyState = 3; }
  }
  class FakeRTCPeerConnection {
    constructor() { peerConnections.push(this); }
    close() { this.closed = true; }
  }
  const window = { P2PFileWire: { MAX_FILE: 32 * 1024 * 1024,
    CHUNK_BYTES: 64 * 1024, validDigest: hash => /^[0-9a-f]{64}$/.test(hash),
    packFrame: (_id, _offset, bytes) => bytes.buffer.slice(0) } };
  vm.runInNewContext(readFileSync(join(__dirname, '..', 'client.js'), 'utf8'), {
    document, window, WebSocket: FakeWebSocket, RTCPeerConnection: FakeRTCPeerConnection,
    crypto: { subtle: { digest }, randomUUID: () => 'abcdef' }, TextEncoder,
    AbortController, setTimeout: () => 1, clearTimeout() {},
    location: { origin: 'http://127.0.0.1', pathname: '/p2p/' }, fetch,
  }, { filename: 'client.js' });
  const joined = (socket, roomBoundObject = null) => socket.onmessage({ data: JSON.stringify({
    type: 'joined', role: 'host', peerId: 'host', boundObject: roomBoundObject,
  }) });
  const channel = (socket, id) => {
    socket.onmessage({ data: JSON.stringify({ type: 'peer-allowed', peerId: id }) });
    const dc = { label: 'fixture-transfer', ordered: true, maxRetransmits: null,
      maxPacketLifeTime: null, readyState: 'open', bufferedAmount: 0, sent: [],
      send(data) { this.sent.push(typeof data === 'string' ? JSON.parse(data) : data); } };
    peerConnections.at(-1).ondatachannel({ channel: dc });
    return dc;
  };
  return { window, sockets, peerConnections, elements, joined, channel };
}

function smallFile() {
  const bytes = Uint8Array.of(1, 2, 3, 4);
  return { name: 'secret.txt', size: bytes.byteLength,
    arrayBuffer: async () => bytes.buffer.slice(0),
    slice: (start, end) => ({ arrayBuffer: async () => bytes.slice(start, end).buffer }) };
}

test('pending plaintext SHA must not send into a newly joined ciphertext-bound room', async () => {
  const pendingDigests = [];
  let created = 0;
  const b = browser({
    digest: () => new Promise(resolve => pendingDigests.push(resolve)),
    fetch: async () => ({ ok: true, json: async () => created++ === 0
      ? { roomId: 'unbound', hostKey: 'old' }
      : { roomId: 'protected', hostKey: 'new', boundObject } }),
  });
  await b.window.__poc.createRoom();
  b.joined(b.sockets[0]);
  const oldChannel = b.channel(b.sockets[0], 'same-peer-id');
  const plaintext = b.window.__poc.sendText('SENSITIVE-PLAINTEXT');
  assert.equal(pendingDigests.length, 1, 'digest must be paused before room switch');

  await b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  b.joined(b.sockets[1], boundObject);
  const protectedChannel = b.channel(b.sockets[1], 'same-peer-id');
  pendingDigests[0](new Uint8Array(32).fill(7).buffer);
  await plaintext;
  assert.equal(b.window.__poc.snapshot().boundObject.sha256, boundObject.sha256);
  assert.deepEqual(protectedChannel.sent, [], 'old plaintext leaked to protected DataChannel');
  assert.deepEqual(oldChannel.sent, [], 'stale text was sent after room switch');
});

test('incoming plaintext SHA completing after room switch cannot enter protected-room diagnostics', async () => {
  const digests = [];
  let created = 0;
  const b = browser({
    digest: () => new Promise(resolve => digests.push(resolve)),
    fetch: async () => ({ ok: true, json: async () => created++ === 0
      ? { roomId: 'unbound', hostKey: 'old' }
      : { roomId: 'protected', hostKey: 'new', boundObject } }),
  });
  await b.window.__poc.createRoom();
  b.joined(b.sockets[0]);
  const oldChannel = b.channel(b.sockets[0], 'old-guest');
  const incoming = oldChannel.onmessage({ data: JSON.stringify({
    type: 'text', text: 'OLD_ROOM_PLAINTEXT', digest: '0'.repeat(64),
  }) });
  assert.equal(digests.length, 1, 'the receive callback must wait on real async digest');
  assert.equal(b.window.__poc.snapshot().diagnostics.verifiedTexts.length, 0);

  await b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  b.joined(b.sockets[1], boundObject);
  assert.equal(b.peerConnections[0].closed, true, 'the old peer must have been retired');
  digests[0](new Uint8Array(32).buffer); // Exact accepted SHA-256 string in this fixture.
  await incoming;
  assert.equal(b.window.__poc.snapshot().boundObject.sha256, boundObject.sha256);
  assert.equal(b.window.__poc.snapshot().diagnostics.verifiedTexts.length, 0,
    'a stale plaintext result must never appear as a verified text in the protected room');
  assert.equal(b.window.__poc.snapshot().diagnostics.rejected.length, 0,
    'stale results must not be reported as new-room digest failures either');

  const live = browser({ fetch: async () => ({ ok: true, json: async () =>
    ({ roomId: 'unbound', hostKey: 'current' }) }) });
  await live.window.__poc.createRoom();
  live.joined(live.sockets[0]);
  const liveChannel = live.channel(live.sockets[0], 'current-guest');
  await liveChannel.onmessage({ data: JSON.stringify({
    type: 'text', text: 'CURRENT_ROOM_TEXT', digest: '0'.repeat(64),
  }) });
  assert.equal(live.window.__poc.snapshot().diagnostics.verifiedTexts[0].text, 'CURRENT_ROOM_TEXT',
    'ordinary same-room verified text must continue to work');
});

test('starting a protected room intent cancels pending plaintext before HTTP completes', async () => {
  const pendingDigests = [];
  const requests = [];
  const b = browser({
    digest: () => new Promise(resolve => pendingDigests.push(resolve)),
    fetch: () => new Promise(resolve => requests.push(resolve)),
  });
  const first = b.window.__poc.createRoom();
  requests[0]({ ok: true, json: async () => ({ roomId: 'unbound', hostKey: 'old' }) });
  await first;
  b.joined(b.sockets[0]);
  const oldChannel = b.channel(b.sockets[0], 'old-peer');
  const plaintext = b.window.__poc.sendText('SENSITIVE-PLAINTEXT');
  const protectedCreation = b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  pendingDigests[0](new Uint8Array(32).fill(7).buffer);
  await plaintext;
  assert.deepEqual(oldChannel.sent, [], 'plaintext sent after user requested a bound room');
  requests[1]({ ok: true, json: async () =>
    ({ roomId: 'protected', hostKey: 'new', boundObject }) });
  await protectedCreation;
  assert.equal(b.window.__poc.snapshot().roomId, 'protected');
});

test('pending unbound create cannot overlap a protected create or downgrade it later', async () => {
  const requests = [];
  const b = browser({ fetch: () => new Promise(resolve => requests.push(resolve)) });
  const older = b.window.__poc.createRoom();
  assert.equal(await b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' }),
    false, 'concurrent room creation must be rejected before a second HTTP request');
  assert.equal(requests.length, 1, 'create-room lock prevents overlapping responses');
  requests[0]({ ok: true, json: async () =>
    ({ roomId: 'unbound', hostKey: 'obsolete' }) });
  await older;
  b.joined(b.sockets[0]);
  const obsoleteSocket = b.sockets[0];
  const newer = b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  assert.equal(requests.length, 2);
  requests[1]({ ok: true, json: async () =>
    ({ roomId: 'protected', hostKey: 'current', boundObject }) });
  await newer;
  b.joined(b.sockets[1], boundObject);
  const protectedSocket = b.sockets[1];
  obsoleteSocket.onmessage({ data: JSON.stringify({
    type: 'joined', role: 'host', peerId: 'late-old-room', boundObject: null,
  }) });
  obsoleteSocket.onclose();
  assert.equal(b.sockets.length, 2, 'stale callbacks must not open another WebSocket');
  assert.equal(protectedSocket.readyState, 1, 'obsolete response closed protected WebSocket');
  assert.equal(b.window.__poc.snapshot().roomId, 'protected');
  assert.equal(b.window.__poc.snapshot().boundObject.sha256, boundObject.sha256);
});

test('leaving a pending creation allows a new room while stale HTTP completion stays fenced', async () => {
  const requests = [];
  const b = browser({ fetch: (_url, options) => new Promise(resolve =>
    requests.push({ resolve, signal: options.signal })) });
  const oldCreate = b.window.__poc.createRoom({ folderId: 'root', fileName: 'old.bin' });
  assert.equal(requests.length, 1);
  assert.equal(b.elements.get('leave').disabled, false,
    'a pending room creation must expose a way to cancel it');
  assert.equal(b.elements.get('leave').textContent, 'Cancelar criação');
  b.elements.get('leave').onclick();
  assert.equal(requests[0].signal.aborted, true);
  assert.equal(b.window.__poc.snapshot().roomId, null);

  const newCreate = b.window.__poc.createRoom({ folderId: 'root', fileName: 'new.bin' });
  assert.equal(requests.length, 2,
    'the old server/response must not hold the creation lock after leave');
  requests[0].resolve({ ok: true, json: async () => ({ roomId: 'stale', hostKey: 'old' }) });
  assert.equal(await oldCreate, false, 'a canceled response must not reconnect');
  assert.equal(await b.window.__poc.createRoom(), false,
    'stale completion must not unlock the second pending creation');
  assert.equal(requests.length, 2);
  assert.equal(b.elements.get('leave').disabled, false,
    'the active creation must retain its cancel control');

  requests[1].resolve({ ok: true, json: async () =>
    ({ roomId: 'current', hostKey: 'new', boundObject }) });
  assert.equal(await newCreate, true);
  assert.equal(b.sockets.length, 1);
  b.joined(b.sockets[0], boundObject);
  assert.equal(b.window.__poc.snapshot().roomId, 'current');
  assert.equal(b.window.__poc.snapshot().boundObject.sha256, boundObject.sha256);
});

test('canceling a delivered room POST reclaims its exact unused server reservation', async () => {
  const held = [], released = [];
  const reservation = { roomId: 'a'.repeat(16), hostKey: 'b'.repeat(64) };
  const b = browser({ cookie: 'rootark_csrf=csrf-test',
    fetch: (url, options) => {
      if (url === '/p2p/rooms/release') {
        released.push({ proof: JSON.parse(options.body), headers: options.headers });
        return Promise.resolve({ status: 204 });
      }
      return new Promise(resolve => held.push({ resolve, signal: options.signal }));
    },
  });
  const pending = b.window.__poc.createRoom();
  assert.equal(held.length, 1);
  b.elements.get('leave').onclick();
  assert.equal(held[0].signal.aborted, true);
  held[0].resolve({ ok: true, json: async () => reservation });
  assert.equal(await pending, false, 'obsolete POST must not connect its canceled room');
  assert.equal(b.sockets.length, 0);
  assert.equal(b.window.__poc.snapshot().roomId, null);
  assert.equal(released.length, 1, 'late completed POST must release the orphan capacity');
  assert.deepEqual(released[0].proof, reservation,
    'release must use the exact server-issued room ID and host secret');
  assert.equal(released[0].headers['X-CSRF-Token'], 'csrf-test');
});

test('canceling an unjoined signaling handshake releases its reserved room, not a joined room', async () => {
  const released = [];
  const reservation = { roomId: 'c'.repeat(16), hostKey: 'd'.repeat(64) };
  const b = browser({ cookie: 'rootark_csrf=csrf-test',
    fetch: async (url, options) => {
      if (url === '/p2p/rooms/release') {
        released.push(JSON.parse(options.body));
        return { status: 204 };
      }
      return { ok: true, json: async () => reservation };
    },
  });
  await b.window.__poc.createRoom();
  assert.equal(b.sockets.length, 1);
  assert.equal(b.window.__poc.snapshot().role, null);
  b.elements.get('leave').onclick();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(b.window.__poc.snapshot().roomId, null);
  assert.equal(released.length, 1);
  assert.deepEqual(released[0], reservation);
});

test('new text and file cannot leave the old unbound channel after protected intent, before HTTP responds', async () => {
  const requests = [];
  const b = browser({ fetch: () => new Promise(resolve => requests.push(resolve)) });
  const initial = b.window.__poc.createRoom();
  requests[0]({ ok: true, json: async () => ({ roomId: 'unbound', hostKey: 'old' }) });
  await initial;
  b.joined(b.sockets[0]);
  const oldChannel = b.channel(b.sockets[0], 'old-peer');
  const protectedCreation = b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  assert.equal(requests.length, 2, 'protected HTTP request must remain pending');
  await b.window.__poc.sendText('LEAK_AFTER_PROTECTED_INTENT');
  await b.window.__poc.sendFile(smallFile());
  assert.deepEqual(oldChannel.sent, [], 'old room received text or file after protected intent');
  requests[1]({ ok: true, json: async () =>
    ({ roomId: 'protected', hostKey: 'new', boundObject }) });
  await protectedCreation;
});

test('old file offer cannot be accepted and completed after protected intent', async () => {
  const requests = [];
  const b = browser({ fetch: () => new Promise(resolve => requests.push(resolve)) });
  const initial = b.window.__poc.createRoom();
  requests[0]({ ok: true, json: async () => ({ roomId: 'unbound', hostKey: 'old' }) });
  await initial;
  b.joined(b.sockets[0]);
  const oldChannel = b.channel(b.sockets[0], 'old-peer');
  await b.window.__poc.sendFile(smallFile());
  const offer = oldChannel.sent.find(message => message.type === 'offer-file');
  assert.ok(offer, 'unbound room should offer a regular file before switch');
  const protectedCreation = b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  await oldChannel.onmessage({ data: JSON.stringify({ type: 'accept-file', id: offer.id }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(oldChannel.sent.filter(message => message instanceof ArrayBuffer ||
    message.type === 'end-file').length, 0, 'old file completed after protected intent');
  assert.equal(b.window.__poc.snapshot().peers.length, 0, 'old peers must retire immediately');
  assert.equal(b.peerConnections[0].closed, true);
  requests[1]({ ok: true, json: async () =>
    ({ roomId: 'protected', hostKey: 'new', boundObject }) });
  await protectedCreation;
});

test('file hash pending before protected intent cannot offer into old channel afterward', async () => {
  const requests = [], hashes = [];
  const b = browser({
    fetch: () => new Promise(resolve => requests.push(resolve)),
    digest: () => new Promise(resolve => hashes.push(resolve)),
  });
  const initial = b.window.__poc.createRoom();
  requests[0]({ ok: true, json: async () => ({ roomId: 'unbound', hostKey: 'old' }) });
  await initial;
  b.joined(b.sockets[0]);
  const oldChannel = b.channel(b.sockets[0], 'old-peer');
  const offering = b.window.__poc.sendFile(smallFile());
  await new Promise(resolve => setImmediate(resolve)); // File read and async SHA are both queued.
  assert.equal(hashes.length, 1);
  const protectedCreation = b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  hashes[0](new Uint8Array(32).buffer);
  await offering;
  assert.deepEqual(oldChannel.sent, [], 'old room received offer after protected intent');
  requests[1]({ ok: true, json: async () =>
    ({ roomId: 'protected', hostKey: 'new', boundObject }) });
  await protectedCreation;
});

test('regular room can still send text and complete an ordinary file transfer', async () => {
  const b = browser({ fetch: async () => ({ ok: true, json: async () =>
    ({ roomId: 'unbound', hostKey: 'old' }) }) });
  await b.window.__poc.createRoom();
  b.joined(b.sockets[0]);
  const dc = b.channel(b.sockets[0], 'normal-peer');
  await b.window.__poc.sendText('REGULAR_TEXT');
  await b.window.__poc.sendFile(smallFile());
  const offer = dc.sent.find(message => message.type === 'offer-file');
  assert.ok(offer);
  await dc.onmessage({ data: JSON.stringify({ type: 'accept-file', id: offer.id }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(dc.sent.some(message => message instanceof ArrayBuffer), true);
  assert.equal(dc.sent.some(message => message.type === 'end-file'), true);
  assert.equal(dc.sent.some(message => message.type === 'text' && message.text === 'REGULAR_TEXT'), true);
});
