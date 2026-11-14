'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { join } = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

test('late old WebSocket callbacks cannot replace a newly joined ciphertext-only room', async () => {
  const elements = new Map();
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
  const sockets = [];
  class FakeWebSocket {
    constructor() { this.readyState = 1; this.sent = []; sockets.push(this); }
    send(value) { this.sent.push(JSON.parse(value)); }
    close() { this.readyState = 3; }
  }
  const boundObject = { folderId: 'root', fileName: 'sealed.bin', size: 92,
    sha256: 'a'.repeat(64) };
  let requests = 0;
  const window = { P2PFileWire: { MAX_FILE: 32 * 1024 * 1024,
    validDigest: hash => /^[a-f0-9]{64}$/.test(hash) } };
  vm.runInNewContext(readFileSync(join(__dirname, '..', 'client.js'), 'utf8'), {
    document, window, WebSocket: FakeWebSocket, crypto: webcrypto,
    location: { origin: 'http://127.0.0.1', pathname: '/p2p/' },
    fetch: async () => ({
      ok: true, json: async () => requests++ === 0
        ? { roomId: 'unbound', hostKey: 'old' }
        : { roomId: 'protected', hostKey: 'current', boundObject },
    }),
  }, { filename: 'client.js' });
  await window.__poc.createRoom();
  const old = sockets[0];
  old.onopen();
  old.onmessage({ data: JSON.stringify({ type: 'joined', role: 'host', peerId: 'old-peer' }) });
  await window.__poc.createRoom({ folderId: 'root', fileName: 'sealed.bin' });
  const current = sockets[1];
  current.onopen();
  current.onmessage({ data: JSON.stringify({
    type: 'joined', role: 'host', peerId: 'bound-peer', boundObject,
  }) });
  assert.equal(window.__poc.snapshot().boundObject?.sha256, boundObject.sha256);
  const sent = current.sent.length;
  old.onmessage({ data: JSON.stringify({ type: 'joined', role: 'guest', peerId: 'stale' }) });
  assert.equal(window.__poc.snapshot().boundObject?.sha256, boundObject.sha256,
    'late unbound joined cleared the ciphertext-only receiver policy');
  old.onopen();
  old.onmessage({ data: JSON.stringify({ type: 'error', code: 'STALE_ERROR' }) });
  old.onclose();
  assert.equal(current.sent.length, sent, 'late old onopen sent a join on the current socket');
  assert.equal(window.__poc.snapshot().roomId, 'protected');
  assert.equal(window.__poc.snapshot().role, 'host');
  assert.equal(window.__poc.snapshot().peerId, 'bound-peer');
  assert.equal(window.__poc.snapshot().diagnostics.rejected.includes('STALE_ERROR'), false);
});
