'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, '..', 'client.js'), 'utf8');

function clientFixture({ digest, fetchRoom } = {}) {
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
    createDataChannel() {
      const channel = { readyState: 'open', sent: [], bufferedAmount: 0,
        send(value) { this.sent.push(typeof value === 'string' ? JSON.parse(value) : value); } };
      this.channel = channel;
      return channel;
    }
    async createOffer() { return { type: 'offer', sdp: 'disposable' }; }
    async setLocalDescription(description) { this.localDescription = description; }
    close() { this.closed = true; if (this.channel) this.channel.readyState = 'closed'; }
  }
  const ctx = { document, window: {}, WebSocket: FakeSocket, RTCPeerConnection: FakePeer,
    crypto: digest ? { subtle: { digest }, randomUUID: crypto.randomUUID } : crypto.webcrypto,
    fetch: fetchRoom, TextEncoder, TextDecoder, Uint8Array, ArrayBuffer,
    location: { origin: 'http://127.0.0.1:1234' }, setTimeout, console };
  vm.createContext(ctx);
  vm.runInContext(source, ctx);
  async function incoming(socket, value) {
    await socket.onmessage({ data: JSON.stringify(value) });
  }
  return { ...ctx.window.__poc, sockets, elements, incoming, peerConnections };
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
  const channel = { readyState: 'open', send() {}, bufferedAmount: 0 };
  peer.ondatachannel({ channel });
  const payload = { type: 'offer-file', id: '', name: 'fixture.bin', size: 2,
    digest: 'a'.repeat(64) };
  for (let i = 0; i < 128; i++) await channel.onmessage({ data: JSON.stringify(payload) });
  assert.equal(f.elements.get('incoming').children.length, 0,
    'empty IDs must be rejected rather than creating 128 consent dialogs');
  payload.id = 'valid-offer-01';
  await channel.onmessage({ data: JSON.stringify(payload) });
  assert.equal(f.elements.get('incoming').children.length, 1,
    'legitimate bounded ID must still create one consent dialog');
  await channel.onmessage({ data: JSON.stringify(payload) });
  assert.equal(f.elements.get('incoming').children.length, 1,
    'repeated pending ID may not create more dialogs');
});

test('P2: delayed text hash cannot deliver to another room or a newly joined recipient', async () => {
  let blocked = null;
  function holdDigest() {
    let release;
    const promise = new Promise(resolve => { release = resolve; });
    blocked = promise;
    return release;
  }
  const f = clientFixture({ digest: async (...args) => {
    const pause = blocked;
    blocked = null;
    if (pause) await pause;
    return crypto.webcrypto.subtle.digest(...args);
  } });
  f.joinRoom('room-A', 'invite-A');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(f.sockets[0], { type: 'peer-accepted', peerId: 'peer-A' });
  const oldChannel = f.peerConnections[0].channel;
  await f.sendText('valid A');
  assert.deepEqual(oldChannel.sent.filter(x => x.type === 'text').map(x => x.text), ['valid A'],
    'positive control: an established A peer receives ordinary text');

  const finishHash = holdDigest();
  const pending = f.sendText('private to room A');
  f.joinRoom('room-B', 'invite-B');
  await f.incoming(f.sockets[1], { type: 'joined', role: 'host', peerId: 'host-B' });
  await f.incoming(f.sockets[1], { type: 'peer-accepted', peerId: 'peer-B' });
  const newChannel = f.peerConnections[1].channel;
  finishHash();
  await pending;
  assert.deepEqual(newChannel.sent.filter(x => x.type === 'text'), [],
    'old room text must not escape to a new room after a delayed SHA-256');

  const finishSecondHash = holdDigest();
  const pendingB = f.sendText('only current B peers');
  await f.incoming(f.sockets[1], { type: 'peer-accepted', peerId: 'late-peer-B' });
  const lateChannel = f.peerConnections[2].channel;
  finishSecondHash();
  await pendingB;
  assert.deepEqual(lateChannel.sent.filter(x => x.type === 'text'), [],
    'joining after the send click must not retroactively authorize that text');
  assert.deepEqual(newChannel.sent.filter(x => x.type === 'text').map(x => x.text),
    ['only current B peers'], 'the original recipient must still receive its text');
  await f.sendText('valid after join');
  assert.deepEqual(lateChannel.sent.filter(x => x.type === 'text').map(x => x.text),
    ['valid after join'], 'positive control: later explicit sends reach the new peer');
});

test('P2: delayed file reading cannot offer earlier room bytes to fresh peers', async () => {
  const f = clientFixture();
  f.joinRoom('room-A', 'invite-A');
  await f.incoming(f.sockets[0], { type: 'joined', role: 'host', peerId: 'host-A' });
  await f.incoming(f.sockets[0], { type: 'peer-accepted', peerId: 'peer-A' });
  let releaseRead;
  const readGate = new Promise(resolve => { releaseRead = resolve; });
  const pendingFile = f.sendFile({
    name: 'private-A.bin', size: 3,
    async arrayBuffer() { await readGate; return Uint8Array.of(1, 2, 3).buffer; }
  });
  f.joinRoom('room-B', 'invite-B');
  await f.incoming(f.sockets[1], { type: 'joined', role: 'host', peerId: 'host-B' });
  await f.incoming(f.sockets[1], { type: 'peer-accepted', peerId: 'peer-B' });
  const newChannel = f.peerConnections[1].channel;
  releaseRead();
  await pendingFile;
  assert.deepEqual(newChannel.sent.filter(x => x.type === 'offer-file'), [],
    'bytes chosen for room A must never be offered to room B');

  await f.sendFile({ name: 'valid-B.bin', size: 3, async arrayBuffer() {
    return Uint8Array.of(4, 5, 6).buffer;
  } });
  assert.deepEqual(newChannel.sent.filter(x => x.type === 'offer-file').map(x => x.name),
    ['valid-B.bin'], 'positive control: deliberate new-room file offer still works');
});

test('P2: a late create-room HTTP response cannot replace a newer join intent', async () => {
  let finishFirstFetch, calls = 0;
  const f = clientFixture({ fetchRoom: () => {
    const n = ++calls;
    if (n === 1) return new Promise(resolve => {
      finishFirstFetch = () => resolve({
        ok: true, json: async () => ({ roomId: 'late-created-A', hostKey: 'key-A' })
      });
    });
    return Promise.resolve({
      ok: true, json: async () => ({ roomId: 'chosen-C', hostKey: 'key-C' })
    });
  } });
  const staleCreate = f.createRoom();
  f.joinRoom('chosen-B', 'invite-B');
  finishFirstFetch();
  await staleCreate;
  assert.equal(f.snapshot().roomId, 'chosen-B',
    'older HTTP response must not silently take control of the current room');
  assert.equal(f.sockets.length, 1, 'stale response must not open a replacement WebSocket');
  await f.createRoom();
  assert.equal(f.snapshot().roomId, 'chosen-C', 'fresh explicit room creation still works');
  assert.equal(f.sockets.length, 2);
});
