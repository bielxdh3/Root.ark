'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');

const boundObject = { folderId: 'root', fileName: 'sealed.bin', size: 92,
  sha256: 'a'.repeat(64) };

function browser({ fetch, digest = async () => new Uint8Array(32).buffer }) {
  const elements = new Map();
  const sockets = [];
  const peerConnections = [];
  const document = {
    cookie: '',
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, {
        hidden: false, disabled: false, textContent: '',
        replaceChildren() {}, append() {},
      });
      return elements.get(id);
    },
    querySelectorAll: () => [],
  };
  class FakeWebSocket {
    constructor() { this.readyState = 1; this.sent = []; sockets.push(this); }
    send(data) { this.sent.push(JSON.parse(data)); }
    close() { this.readyState = 3; }
  }
  class FakeRTCPeerConnection {
    constructor() { peerConnections.push(this); }
    close() {}
  }
  const window = { P2PFileWire: { MAX_FILE: 32 * 1024 * 1024,
    validDigest: hash => /^[0-9a-f]{64}$/.test(hash) } };
  vm.runInNewContext(readFileSync(join(__dirname, '..', 'client.js'), 'utf8'), {
    document, window, WebSocket: FakeWebSocket, RTCPeerConnection: FakeRTCPeerConnection,
    crypto: { subtle: { digest }, randomUUID: () => 'abcdef' }, TextEncoder,
    location: { origin: 'http://127.0.0.1', pathname: '/p2p/' }, fetch,
  }, { filename: 'client.js' });
  const joined = (socket, roomBoundObject = null) => socket.onmessage({ data: JSON.stringify({
    type: 'joined', role: 'host', peerId: 'host', boundObject: roomBoundObject,
  }) });
  const channel = (socket, id) => {
    socket.onmessage({ data: JSON.stringify({ type: 'peer-allowed', peerId: id }) });
    const dc = { label: 'fixture-transfer', ordered: true, maxRetransmits: null,
      maxPacketLifeTime: null, readyState: 'open', sent: [],
      send(data) { this.sent.push(JSON.parse(data)); } };
    peerConnections.at(-1).ondatachannel({ channel: dc });
    return dc;
  };
  return { window, sockets, joined, channel };
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
