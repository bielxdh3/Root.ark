'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

const boundObject = { folderId: 'root', fileName: 'sealed.bin', size: 92,
  sha256: 'a'.repeat(64) };

function browser({ fetch, digest = async () => new Uint8Array(32).buffer,
  waitForSendWindow = require('../transfer-protocol.js').waitForSendWindow }) {
  const elements = new Map();
  const sockets = [];
  const peerConnections = [];
  const element = () => ({
    hidden: false, disabled: false, textContent: '', dataset: {},
    replaceChildren() {}, append() {}, remove() {}, addEventListener() {},
  });
  const document = {
    cookie: '',
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
    waitForSendWindow,
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
  return { window, sockets, peerConnections, joined, channel };
}

function smallFile() {
  const bytes = Uint8Array.of(1, 2, 3, 4);
  return { name: 'secret.txt', size: bytes.byteLength,
    arrayBuffer: async () => bytes.buffer.slice(0),
    slice: (start, end) => ({ arrayBuffer: async () => bytes.slice(start, end).buffer }) };
}

test('1:N full sender path cancels only stalled peer; healthy sibling still receives SHA ACK', async () => {
  let stalled;
  const b = browser({
    fetch: async () => ({ ok: true, json: async () => ({ roomId: 'test', hostKey: 'local' }) }),
    waitForSendWindow: dc => dc === stalled
      ? Promise.reject(new Error('P2P_SEND_BUFFER_STALLED')) : Promise.resolve(),
  });
  await b.window.__poc.createRoom();
  b.joined(b.sockets[0]);
  stalled = b.channel(b.sockets[0], 'slow-peer');
  const healthy = b.channel(b.sockets[0], 'healthy-peer');
  await b.window.__poc.sendFile(smallFile());
  const offered = dc => dc.sent.find(m => m.type === 'offer-file');
  assert.ok(offered(stalled));
  assert.ok(offered(healthy));
  await stalled.onmessage({ data: JSON.stringify({
    type: 'accept-file', id: offered(stalled).id,
  }) });
  await healthy.onmessage({ data: JSON.stringify({
    type: 'accept-file', id: offered(healthy).id,
  }) });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(stalled.sent.filter(message => message instanceof ArrayBuffer).length, 0);
  assert.ok(stalled.sent.some(message => message.type === 'cancel-file'));
  assert.equal(healthy.sent.filter(message => message instanceof ArrayBuffer).length, 1);
  assert.ok(healthy.sent.some(message => message.type === 'end-file'));
  assert.deepEqual(Array.from(b.window.__poc.snapshot().peers, p => p.outgoingPhase),
    [null, 'verifying']);
  assert.ok(b.window.__poc.snapshot().diagnostics.rejected.includes('P2P_SEND_BUFFER_STALLED'));
  await healthy.onmessage({ data: JSON.stringify({
    type: 'verified-file', id: offered(healthy).id, digest: '0'.repeat(64),
  }) });
  assert.deepEqual(Array.from(b.window.__poc.snapshot().peers, p => p.outgoingPhase),
    [null, null]);
});

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

test('late response to older unbound createRoom cannot downgrade newer protected room', async () => {
  const requests = [];
  const b = browser({ fetch: () => new Promise(resolve => requests.push(resolve)) });
  const older = b.window.__poc.createRoom();
  const newer = b.window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  assert.equal(requests.length, 2);
  requests[1]({ ok: true, json: async () =>
    ({ roomId: 'protected', hostKey: 'current', boundObject }) });
  await newer;
  b.joined(b.sockets[0], boundObject);
  const protectedSocket = b.sockets[0];
  requests[0]({ ok: true, json: async () =>
    ({ roomId: 'unbound', hostKey: 'obsolete' }) });
  await older;
  assert.equal(b.sockets.length, 1, 'obsolete response replaced protected WebSocket');
  assert.equal(protectedSocket.readyState, 1, 'obsolete response closed protected WebSocket');
  assert.equal(b.window.__poc.snapshot().roomId, 'protected');
  assert.equal(b.window.__poc.snapshot().boundObject.sha256, boundObject.sha256);
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
