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

function clientFixture({ cryptoApi = {
  subtle: crypto.webcrypto.subtle,
  randomUUID: () => crypto.randomUUID(),
}, fetchImpl } = {}) {
  const elements = new Map(), sockets = [], peerConnections = [];
  const makeNode = () => ({
    children: [], dataset: {}, disabled: false, textContent: '', attributes: new Map(),
    setAttribute(name, value) { this.attributes.set(name, String(value)); },
    getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; },
    removeAttribute(name) { this.attributes.delete(name); },
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
    constructor() { this.closed = false; this.channels = []; peerConnections.push(this); }
    createDataChannel(label, opts = {}) {
      const channel = makeChannel({
        label: label || 'fixture-transfer',
        ordered: opts.ordered !== undefined ? opts.ordered : true,
        maxRetransmits: opts.maxRetransmits ?? null,
        maxPacketLifeTime: opts.maxPacketLifeTime ?? null
      });
      channel.sent = [];
      channel.send = wire => channel.sent.push(JSON.parse(wire));
      this.channels.push(channel);
      return channel;
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
    crypto: cryptoApi,
    fetch: fetchImpl,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    ArrayBuffer,
    AbortController,
    DOMException,
    location: { origin: 'http://127.0.0.1:1234', pathname: '/' },
    setTimeout,
    clearTimeout,
    console
  };
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  async function incoming(socket, value) {
    await socket.onmessage({ data: JSON.stringify(value) });
  }
  return { ...ctx.window.__poc, window: ctx.window, sockets, elements, incoming, peerConnections };
}

test('P2 RED: hashing old-room text must not deliver it to a newly joined room', async () => {
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const cryptoApi = { subtle: { digest: async (...args) => {
    await blocked;
    return crypto.webcrypto.subtle.digest(...args);
  } } };
  const f = clientFixture({ cryptoApi });
  f.joinRoom('room-A', 'invite-A');
  const old = f.sockets[0];
  await f.incoming(old, { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(old, { type: 'peer-accepted', peerId: 'peer-A' });
  const oldChannel = f.peerConnections[0].channels[0];
  assert.ok(oldChannel, 'real client peer setup must create DataChannel A');
  const pending = f.sendText('confidential text intended only for room A');
  f.joinRoom('room-B', 'invite-B');
  const fresh = f.sockets[1];
  await f.incoming(fresh, { type: 'joined', role: 'host', peerId: 'host-B' });
  await f.incoming(fresh, { type: 'peer-accepted', peerId: 'peer-B' });
  const newChannel = f.peerConnections[1].channels[0];
  assert.ok(newChannel, 'real client peer setup must create DataChannel B');
  release();
  await pending;
  assert.deepEqual(newChannel.sent.filter(item => item.type === 'text'), [],
    'bytes authorized for old room must never be sent to a new recipient after async hash');
  assert.deepEqual(oldChannel.sent.filter(item => item.type === 'text'), [],
    'departed room must not receive a delayed transmission either');
  await f.sendText('fresh text intended only for room B');
  assert.equal(newChannel.sent.filter(item => item.type === 'text').length, 1,
    'a legitimate send in the new room must still work');
});

test('P2 RED: hashing an old-room file cannot offer it to a revoked peer after room switch', async () => {
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const f = clientFixture();
  f.joinRoom('room-A', 'invite-A');
  const old = f.sockets[0];
  await f.incoming(old, { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(old, { type: 'peer-accepted', peerId: 'peer-A' });
  const oldChannel = f.peerConnections[0].channels[0];
  const payload = new TextEncoder().encode('private file bytes for room A');
  const file = { name: 'private.txt', size: payload.length,
    async arrayBuffer() { await blocked; return payload.buffer.slice(0); } };
  const pending = f.sendFile(file);
  f.joinRoom('room-B', 'invite-B');
  const fresh = f.sockets[1];
  await f.incoming(fresh, { type: 'joined', role: 'host', peerId: 'host-B' });
  await f.incoming(fresh, { type: 'peer-accepted', peerId: 'peer-B' });
  const newChannel = f.peerConnections[1].channels[0];
  release();
  await pending;
  assert.deepEqual(oldChannel.sent.filter(item => item.type === 'offer-file'), [],
    'a stale DataChannel from a revoked room must not receive a delayed file offer');
  assert.deepEqual(newChannel.sent.filter(item => item.type === 'offer-file'), [],
    'file selected for the old room must not be offered to the new room');
  await f.sendFile(file);
  assert.equal(newChannel.sent.filter(item => item.type === 'offer-file').length, 1,
    'legitimate offer in the new room must still work: denial must not be vacuous; state=' +
      f.elements.get('state').textContent);
  fresh.onclose(); // Cancel the 60s consent timer; do not leak handles across tests.
});

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

test('P2: a signaling connection can be canceled before joined without stale reconnection', async () => {
  const f = clientFixture();
  f.joinRoom('pending', 'invite-old');
  const pendingSocket = f.sockets[0];
  assert.equal(f.elements.get('leave').disabled, false,
    'the user must be able to cancel a stalled signaling connection');
  assert.equal(f.elements.get('leave').textContent, 'Cancelar conexão');
  f.elements.get('leave').onclick();
  assert.equal(pendingSocket.closeRequested, true);
  assert.equal(f.snapshot().roomId, null);
  assert.equal(f.elements.get('leave').disabled, true);

  f.joinRoom('fresh', 'invite-new');
  const newSocket = f.sockets[1];
  pendingSocket.onopen();
  await f.incoming(pendingSocket, { type: 'joined', role: 'host', peerId: 'stale' });
  pendingSocket.onclose();
  assert.equal(f.snapshot().roomId, 'fresh');
  assert.equal(f.snapshot().role, null);
  assert.equal(newSocket.closeRequested, undefined);

  await f.incoming(newSocket, { type: 'joined', role: 'guest', peerId: 'fresh-peer' });
  assert.equal(f.snapshot().role, 'guest');
  assert.equal(f.elements.get('leave').textContent, 'Sair da sala');
  assert.equal(f.elements.get('leave').disabled, false);
});

test('P2: leaving retires an old file-hash lock without clearing a newer room send', async () => {
  const f = clientFixture();
  f.joinRoom('room-A', 'invite-A');
  const oldSocket = f.sockets[0];
  await f.incoming(oldSocket, { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(oldSocket, { type: 'peer-accepted', peerId: 'peer-A' });

  let releaseOld;
  const oldFile = { name: 'old.bin', size: 2,
    arrayBuffer: () => new Promise(resolve => { releaseOld = resolve; }) };
  const oldSend = f.sendFile(oldFile);
  assert.equal(typeof releaseOld, 'function', 'old file hashing must be pending');

  f.elements.get('leave').onclick();
  assert.equal(f.snapshot().roomId, null);
  assert.equal(f.snapshot().peers.length, 0);

  f.joinRoom('room-B', 'invite-B');
  const newSocket = f.sockets[1];
  await f.incoming(newSocket, { type: 'joined', role: 'host', peerId: 'host-B' });
  await f.incoming(newSocket, { type: 'peer-accepted', peerId: 'peer-B' });

  let releaseNew;
  const newFile = { name: 'new.bin', size: 2,
    arrayBuffer: () => new Promise(resolve => { releaseNew = resolve; }) };
  const newSend = f.sendFile(newFile);
  assert.equal(typeof releaseNew, 'function', 'new room file hashing must be pending');

  let thirdReadStarted = false;
  const thirdFile = { name: 'third.bin', size: 2,
    arrayBuffer: () => { thirdReadStarted = true; return Promise.resolve(new Uint8Array([7, 8]).buffer); } };
  await f.sendFile(thirdFile);
  assert.equal(thirdReadStarted, false, 'the new room must retain its own preparation lock');

  releaseOld(new Uint8Array([1, 2]).buffer);
  await oldSend;
  await f.sendFile(thirdFile);
  assert.equal(thirdReadStarted, false,
    'a stale old-room finally block must not release the newer room preparation lock');

  releaseNew(new Uint8Array([3, 4]).buffer);
  await newSend;
  assert.equal(f.snapshot().peers.some(peer => peer.outgoingPhase === 'offered'), true,
    'the new room send must complete after its own hash resolves');
});

test('P2: a retired outgoing cancel callback cannot abort a later transfer to the same peer', async () => {
  const f = clientFixture();
  f.joinRoom('room', 'invitation');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'host', peerId: 'host' });
  await f.incoming(f.sockets[0], { type: 'peer-accepted', peerId: 'peer-A' });
  const channel = f.testChannel(0);
  const sent = [];
  channel.send = data => sent.push(JSON.parse(data));
  const file = name => ({ name, size: 2,
    arrayBuffer: async () => new Uint8Array([1, 2]).buffer });

  await f.sendFile(file('old.bin'));
  const retiredCancel = f.elements.get('transfers').children[0].children[1].onclick;
  const firstOffer = sent.find(message => message.type === 'offer-file');
  assert.ok(firstOffer);
  await channel.onmessage({ data: JSON.stringify({ type: 'decline-file', id: firstOffer.id }) });
  assert.equal(f.snapshot().peers[0].outgoingPhase, null);

  await f.sendFile(file('current.bin'));
  const currentOffer = sent.filter(message => message.type === 'offer-file').at(-1);
  assert.notEqual(currentOffer.id, firstOffer.id);
  assert.equal(f.snapshot().peers[0].outgoingPhase, 'offered');
  retiredCancel(); // A previously queued click from a now-removed control.
  assert.equal(f.snapshot().peers[0].outgoingPhase, 'offered',
    'an obsolete cancel callback must not release the new transfer');
  assert.equal(sent.some(message => message.type === 'cancel-file' && message.id === currentOffer.id), false);

  f.elements.get('transfers').children[1].children[1].onclick();
  assert.equal(f.snapshot().peers[0].outgoingPhase, null);
  assert.equal(sent.some(message => message.type === 'cancel-file' && message.id === currentOffer.id), true,
    'the current transfer must still be cancellable');
});

test('P2: a retired offer consent callback cannot accept or decline a replacement with a reused ID', async () => {
  const f = clientFixture();
  f.joinRoom('room', 'invitation');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
  await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
  const channel = makeChannel();
  const sent = [];
  channel.send = data => sent.push(JSON.parse(data));
  f.peerConnections[0].ondatachannel({ channel });
  const offer = { type: 'offer-file', id: 'a'.repeat(32), name: 'old.bin',
    size: 2, digest: 'b'.repeat(64) };
  await channel.onmessage({ data: JSON.stringify(offer) });
  const oldUi = f.elements.get('incoming').children[0];
  const oldAccept = oldUi.children[0].onclick;
  const oldDecline = oldUi.children[1].onclick;
  oldDecline();
  assert.equal(f.snapshot().peers[0].pendingOffer, false);

  await channel.onmessage({ data: JSON.stringify({ ...offer, name: 'new.bin' }) });
  assert.equal(f.snapshot().peers[0].pendingOffer, true);
  const sentBeforeStale = sent.length;
  oldAccept();
  oldDecline();
  assert.equal(sent.length, sentBeforeStale,
    'stale consent must neither accept nor decline a different offer with the same ID');
  assert.equal(f.snapshot().peers[0].pendingOffer, true,
    'replacement offer must retain its own consent');

  const currentAccept = f.elements.get('incoming').children[1].children[0].onclick;
  currentAccept();
  assert.equal(f.snapshot().peers[0].pendingOffer, false);
  assert.equal(sent.filter(message => message.type === 'accept-file' && message.id === offer.id).length, 1,
    'the current consent button must still accept the replacement');
});

test('P2: an old incoming cancel callback cannot cancel a replacement receiving the same ID', async () => {
  const f = clientFixture();
  f.joinRoom('room', 'invitation');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'guest', peerId: 'guest' });
  await f.incoming(f.sockets[0], { type: 'peer-allowed', peerId: 'peer-A' });
  const channel = makeChannel();
  const sent = [];
  channel.send = data => sent.push(JSON.parse(data));
  f.peerConnections[0].ondatachannel({ channel });
  const offer = { type: 'offer-file', id: 'c'.repeat(32), name: 'old.bin',
    size: 2, digest: 'd'.repeat(64) };
  await channel.onmessage({ data: JSON.stringify(offer) });
  f.elements.get('incoming').children[0].children[0].onclick();
  const oldCancel = f.elements.get('transfers').children[0].children[1].onclick;
  await channel.onmessage({ data: JSON.stringify({ type: 'cancel-file', id: offer.id }) });

  await channel.onmessage({ data: JSON.stringify({ ...offer, name: 'current.bin' }) });
  f.elements.get('incoming').children[1].children[0].onclick();
  oldCancel();
  assert.equal(sent.filter(message => message.type === 'cancel-file').length, 0,
    'the obsolete cancel handler must not clear the new transfer');
  f.elements.get('transfers').children[1].children[1].onclick();
  assert.equal(sent.filter(message => message.type === 'cancel-file').length, 1,
    'the current incoming cancellation must still notify the peer');
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

test('P2 RED: late room creation response cannot hijack a newer signed room join', async () => {
  let releaseFirst, calls = 0;
  const f = clientFixture({ fetchImpl: async () => {
    calls++;
    if (calls === 1) await new Promise(resolve => { releaseFirst = resolve; });
    return { ok: true, json: async () => ({ roomId: 'stale-created-A', hostKey: 'secret-A' }) };
  } });
  const pending = f.createRoom();
  assert.equal(typeof releaseFirst, 'function', 'test must really hold the HTTP response');
  f.joinRoom('chosen-B', 'invite-B');
  assert.equal(f.snapshot().roomId, 'chosen-B');
  releaseFirst();
  await pending;
  assert.equal(f.snapshot().roomId, 'chosen-B',
    'obsolete HTTP creation response must not replace the newer room intent');
  assert.equal(f.sockets.length, 1, 'no stale WebSocket should be created');
});

test('P2: createRoom starting during async hashing invalidates pending sendText and sendFile', async () => {
  let releaseHash;
  const releaseFetches = [];
  const cryptoApi = {
    subtle: {
      digest: async (...args) => {
        await new Promise(resolve => { releaseHash = resolve; });
        return crypto.webcrypto.subtle.digest(...args);
      }
    },
    randomUUID: () => crypto.randomUUID(),
  };
  const f = clientFixture({
    cryptoApi,
    fetchImpl: async () => {
      await new Promise(resolve => { releaseFetches.push(resolve); });
      return { ok: true, json: async () => ({ roomId: 'room-B', hostKey: 'host-B' }) };
    }
  });
  f.joinRoom('room-A', 'invite-A');
  const sockA = f.sockets[0];
  await f.incoming(sockA, { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(sockA, { type: 'peer-accepted', peerId: 'peer-A' });
  const channel = f.peerConnections[0].channels[0];

  const pendingText = f.sendText('secret-for-A');
  assert.equal(typeof releaseHash, 'function', 'hashing must pause before createRoom');
  const pendingCreate = f.createRoom();
  releaseHash();
  await pendingText;
  assert.equal(channel.sent.length, 0, 'pending sendText must abort once createRoom increments roomGeneration');
  for (const r of releaseFetches.splice(0)) r();
  await pendingCreate;

  f.joinRoom('room-A2', 'invite-A2');
  const sockA2 = f.sockets[f.sockets.length - 1];
  await f.incoming(sockA2, { type: 'joined', role: 'host', peerId: 'host-A2' });
  await f.incoming(sockA2, { type: 'peer-accepted', peerId: 'peer-A2' });
  const channel2 = f.peerConnections[f.peerConnections.length - 1].channels[0];

  releaseHash = null;
  const file = {
    name: 'secret.txt',
    size: 5,
    async arrayBuffer() { return new Uint8Array([1, 2, 3, 4, 5]).buffer; }
  };
  const pendingFile = f.sendFile(file);
  // Wait a microtask for file.arrayBuffer() to settle before subtle.digest is entered
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(typeof releaseHash, 'function', 'file hashing must pause before second createRoom');
  const pendingCreate2 = f.createRoom();
  releaseHash();
  await pendingFile;
  assert.equal(channel2.sent.length, 0, 'pending sendFile must abort once createRoom increments roomGeneration');

  for (const r of releaseFetches.splice(0)) r();
  await pendingCreate2;
});
