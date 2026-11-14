'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const fileWire = require('../transfer-protocol.js');

const source = fs.readFileSync(path.join(__dirname, '..', 'client.js'), 'utf8');

function makeChannel(overrides = {}) {
  return {
    label: 'fixture-transfer',
    ordered: true,
    maxRetransmits: null,
    maxPacketLifeTime: null,
    readyState: 'open',
    send() {},
    bufferedAmount: 0,
    close() { this.readyState = 'closed'; },
    ...overrides
  };
}

function clientFixture() {
  const elements = new Map(), sockets = [], peerConnections = [];
  const makeNode = () => ({
    children: [], dataset: {}, disabled: false, textContent: '',
    append(...parts) { this.children.push(...parts); },
    replaceChildren(...parts) { this.children = [...parts]; },
    remove() { this.removed = true; },
    addEventListener(name, fn) { this['on' + name] = fn; },
  });
  const document = {
    getElementById(id) { if (!elements.has(id)) elements.set(id, makeNode()); return elements.get(id); },
    createElement: makeNode,
    querySelectorAll() { return []; },
  };
  class FakeSocket {
    constructor(url) { this.url = url; this.readyState = 1; this.sent = []; sockets.push(this); }
    close() { this.readyState = 2; this.closeRequested = true; }
    send(wire) { this.sent.push(JSON.parse(wire)); }
  }
  class FakePeer {
    constructor() { this.closed = false; peerConnections.push(this); }
    createDataChannel(label, opts = {}) {
      return makeChannel({
        label: label || 'fixture-transfer',
        ordered: opts.ordered !== undefined ? opts.ordered : true,
        maxRetransmits: opts.maxRetransmits ?? null,
        maxPacketLifeTime: opts.maxPacketLifeTime ?? null
      });
    }
    async createOffer() { return { type: 'offer', sdp: 'disposable' }; }
    async setLocalDescription(description) { this.localDescription = description; }
    close() { this.closed = true; }
  }
  const ctx = {
    document,
    window: { P2PFileWire: { ...fileWire } },
    WebSocket: FakeSocket,
    RTCPeerConnection: FakePeer,
    crypto: crypto.webcrypto,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    location: { origin: 'http://127.0.0.1:1234', pathname: '/' },
    setTimeout,
    console
  };
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  async function incoming(socket, value) {
    await socket.onmessage({ data: JSON.stringify(value) });
  }
  return { ...ctx.window.__poc, window: ctx.window, sockets, elements, incoming, peerConnections };
}

test('P2: delayed old-room close cannot revoke or tear down new-room peer', async () => {
  const f = clientFixture();
  f.joinRoom('A', 'invite-A');
  const old = f.sockets[0];
  await f.incoming(old, { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(old, { type: 'peer-accepted', peerId: 'peer-A' });
  assert.equal(f.snapshot().peers.length, 1);
  f.joinRoom('B', 'invite-B');
  const fresh = f.sockets[1];
  await f.incoming(fresh, { type: 'joined', role: 'host', peerId: 'host-B' });
  await f.incoming(fresh, { type: 'peer-accepted', peerId: 'peer-B' });
  assert.equal(f.snapshot().peers.some(x => x.id === 'peer-B'), true);
  assert.equal(f.elements.get('invite').disabled, false);
  old.onclose(); // Deliberately delayed callback from previous socket.
  await f.incoming(old, { type: 'peer-left', peerId: 'peer-B' }); // Late malicious notification.
  assert.equal(f.snapshot().peers.some(x => x.id === 'peer-B'), true,
    'new peer must survive stale close and event handlers from old socket');
  assert.equal(f.elements.get('invite').disabled, false,
    'old close must not disable new room controls');
  assert.equal(f.peerConnections.at(-1).closed, false);
});

test('P2: empty offer IDs cannot create unbounded consent panels; valid offer still works', async () => {
  const f = clientFixture();
  f.joinRoom('room', 'invitation');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
  await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
  const peer = f.peerConnections[0];
  const channel = makeChannel();
  peer.ondatachannel({ channel });
  const payload = { type: 'offer-file', id: '', name: 'fixture.bin', size: 2,
    digest: 'a'.repeat(64) };
  for (let i = 0; i < 128; i++) await channel.onmessage({ data: JSON.stringify(payload) });
  assert.equal(f.elements.get('incoming').children.length, 0,
    'empty IDs must be rejected rather than creating 128 consent dialogs');
  payload.id = 'a'.repeat(32);
  await channel.onmessage({ data: JSON.stringify(payload) });
  assert.equal(f.elements.get('incoming').children.length, 1,
    'legitimate bounded ID must still create one consent dialog');
  await channel.onmessage({ data: JSON.stringify(payload) });
  assert.equal(f.elements.get('incoming').children.length, 1,
    'repeated pending ID may not create more dialogs');
});

test('P1: offer validation requires both P2PFileWire.validOffer and strict inline checks', async () => {
  const f = clientFixture();
  f.joinRoom('room', 'invitation');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
  await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
  const peer = f.peerConnections[0];
  const channel = makeChannel();
  peer.ondatachannel({ channel });

  // 1. validOffer returning false still rejects even if inline fields pass
  // id satisfies inline /^[A-Za-z0-9_-]{1,64}$/, but fails P2PFileWire.validOffer (requires 32 hex chars)
  const offerFailingWire = {
    type: 'offer-file',
    id: 'valid-offer-inline-only-01',
    name: 'test.bin',
    size: 10,
    digest: 'a'.repeat(64)
  };
  await channel.onmessage({ data: JSON.stringify(offerFailingWire) });
  assert.equal(f.elements.get('incoming').children.length, 0,
    'offer rejected by validOffer must not create consent dialog even if inline checks pass');
  assert.ok(f.snapshot().diagnostics.rejected.includes('BAD_OFFER'));

  // Also test when validOffer is stubbed to return false on an otherwise valid payload
  f.window.P2PFileWire.validOffer = () => false;
  const standardOffer = {
    type: 'offer-file',
    id: 'b'.repeat(32),
    name: 'test.bin',
    size: 10,
    digest: 'a'.repeat(64)
  };
  await channel.onmessage({ data: JSON.stringify(standardOffer) });
  assert.equal(f.elements.get('incoming').children.length, 0,
    'validOffer returning false must reject offer even when inline fields are valid');

  // 2. invalid id still rejects even if validOffer passes
  f.window.P2PFileWire.validOffer = () => true;
  const offerEmptyId = {
    type: 'offer-file',
    id: '',
    name: 'test.bin',
    size: 10,
    digest: 'a'.repeat(64)
  };
  await channel.onmessage({ data: JSON.stringify(offerEmptyId) });
  assert.equal(f.elements.get('incoming').children.length, 0,
    'invalid empty id must reject offer even if validOffer returns true');

  const offerInvalidChars = {
    type: 'offer-file',
    id: 'invalid id with spaces!',
    name: 'test.bin',
    size: 10,
    digest: 'a'.repeat(64)
  };
  await channel.onmessage({ data: JSON.stringify(offerInvalidChars) });
  assert.equal(f.elements.get('incoming').children.length, 0,
    'disallowed id characters must reject offer even if validOffer returns true');
});

test('P2: attachChannel strictly rejects data channels with missing or invalid label, ordered, or retransmit constraints', async () => {
  // Missing label
  {
    const f = clientFixture();
    f.joinRoom('room', 'invitation');
    await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
    await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
    const peer = f.peerConnections[0];
    let closed = false;
    const ch = makeChannel({ label: undefined, close() { closed = true; } });
    peer.ondatachannel({ channel: ch });
    assert.equal(closed, true, 'missing label must cause channel.close()');
    assert.ok(f.snapshot().diagnostics.rejected.includes('INVALID_CHANNEL'));
    assert.equal(f.snapshot().peers[0].channel, 'none');
  }

  // Label mismatch
  {
    const f = clientFixture();
    f.joinRoom('room', 'invitation');
    await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
    await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
    const peer = f.peerConnections[0];
    let closed = false;
    const ch = makeChannel({ label: 'wrong-label', close() { closed = true; } });
    peer.ondatachannel({ channel: ch });
    assert.equal(closed, true, 'wrong label must cause channel.close()');
    assert.ok(f.snapshot().diagnostics.rejected.includes('INVALID_CHANNEL'));
    assert.equal(f.snapshot().peers[0].channel, 'none');
  }

  // Missing or false ordered property
  {
    const f = clientFixture();
    f.joinRoom('room', 'invitation');
    await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
    await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
    const peer = f.peerConnections[0];
    let closed = false;
    const ch = makeChannel({ ordered: false, close() { closed = true; } });
    peer.ondatachannel({ channel: ch });
    assert.equal(closed, true, 'unordered channel must cause channel.close()');
    assert.ok(f.snapshot().diagnostics.rejected.includes('INVALID_CHANNEL'));
    assert.equal(f.snapshot().peers[0].channel, 'none');
  }

  // Non-null maxRetransmits
  {
    const f = clientFixture();
    f.joinRoom('room', 'invitation');
    await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
    await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
    const peer = f.peerConnections[0];
    let closed = false;
    const ch = makeChannel({ maxRetransmits: 3, close() { closed = true; } });
    peer.ondatachannel({ channel: ch });
    assert.equal(closed, true, 'non-null maxRetransmits must cause channel.close()');
    assert.ok(f.snapshot().diagnostics.rejected.includes('INVALID_CHANNEL'));
  }

  // Non-null maxPacketLifeTime
  {
    const f = clientFixture();
    f.joinRoom('room', 'invitation');
    await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
    await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
    const peer = f.peerConnections[0];
    let closed = false;
    const ch = makeChannel({ maxPacketLifeTime: 500, close() { closed = true; } });
    peer.ondatachannel({ channel: ch });
    assert.equal(closed, true, 'non-null maxPacketLifeTime must cause channel.close()');
    assert.ok(f.snapshot().diagnostics.rejected.includes('INVALID_CHANNEL'));
  }
});
