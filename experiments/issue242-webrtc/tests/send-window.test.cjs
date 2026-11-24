'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const wire = require('../transfer-protocol.js');

const high = 256 * 1024;
class DisposableChannel extends EventTarget {
  constructor(bufferedAmount) {
    super();
    this.bufferedAmount = bufferedAmount;
    this.readyState = 'open';
    this.listeners = new Set();
  }
  addEventListener(type, callback, options) {
    this.listeners.add(type + ':' + callback);
    super.addEventListener(type, callback, options);
  }
  removeEventListener(type, callback, options) {
    this.listeners.delete(type + ':' + callback);
    super.removeEventListener(type, callback, options);
  }
  drain(bytes) {
    this.bufferedAmount = bytes;
    this.dispatchEvent(new Event('bufferedamountlow'));
  }
  close() {
    this.readyState = 'closed';
    this.dispatchEvent(new Event('close'));
  }
}

test('stalled per-recipient DataChannel returns bounded timeout and removes listeners', async () => {
  assert.equal(typeof wire.waitForSendWindow, 'function');
  const slow = new DisposableChannel(high + 1);
  const signal = new AbortController();
  await assert.rejects(
    wire.waitForSendWindow(slow, signal.signal, 15),
    /P2P_SEND_BUFFER_STALLED/,
  );
  assert.equal(slow.listeners.size, 0);
  slow.drain(0); signal.abort();
});

test('backpressure drain, cancellation and close settle exactly once without leaks', async () => {
  assert.equal(typeof wire.waitForSendWindow, 'function');
  const dc = new DisposableChannel(high + 1);
  const abort = new AbortController();
  const waiting = wire.waitForSendWindow(dc, abort.signal, 100);
  dc.drain(64 * 1024);
  await waiting;
  assert.equal(dc.listeners.size, 0);
  dc.close(); abort.abort();
  const canceled = new DisposableChannel(high);
  const pending = new AbortController();
  const stopped = wire.waitForSendWindow(canceled, pending.signal, 100);
  pending.abort();
  await stopped;
  assert.equal(canceled.listeners.size, 0);
  const closed = new DisposableChannel(high);
  const ending = wire.waitForSendWindow(closed, new AbortController().signal, 100);
  closed.close();
  await ending;
  assert.equal(closed.listeners.size, 0);
});

test('1:N independent receivers: stalled peer fails but healthy peer verifies exact 1 MiB ciphertext', async () => {
  const stalledPeer = new DisposableChannel(high);
  const healthyPeer = new DisposableChannel(0);
  const sender = new AbortController();
  const healthy = new AbortController();
  const id = '0123456789abcdef0123456789abcdef';
  const source = Buffer.alloc(1024 * 1024);
  for (let i = 0; i < source.length; i++) source[i] = i % 251;
  const received = [];
  const blocked = wire.waitForSendWindow(stalledPeer, sender.signal, 20);
  for (let offset = 0; offset < source.length; offset += wire.CHUNK_BYTES) {
    await wire.waitForSendWindow(healthyPeer, healthy.signal, 20);
    const chunk = source.subarray(offset, offset + wire.CHUNK_BYTES);
    received.push(wire.parseFrame(
      wire.packFrame(id, offset, chunk).buffer, id, offset, source.length));
  }
  await assert.rejects(blocked, /P2P_SEND_BUFFER_STALLED/);
  assert.equal(stalledPeer.listeners.size, 0);
  const actual = Buffer.concat(received);
  assert.deepEqual(actual, source);
  assert.equal(createHash('sha256').update(actual).digest('hex'),
    createHash('sha256').update(source).digest('hex'));
  assert.equal(healthyPeer.listeners.size, 0);
});

test('1:N late corruption aborts only offending receiver transfer', () => {
  const id = '0123456789abcdef0123456789abcdef';
  const file = Buffer.alloc(wire.CHUNK_BYTES * 2, 17);
  const correct = [0, wire.CHUNK_BYTES].map(offset =>
    wire.packFrame(id, offset, file.subarray(offset, offset + wire.CHUNK_BYTES)));
  const corrupt = correct[1].slice();
  corrupt[23] ^= 1;
  const verified = [], denied = [];
  for (const [index, frames] of [[0, correct], [1, [correct[0], corrupt]]]) {
    let offset = 0;
    try {
      for (const frame of frames) {
        const chunk = wire.parseFrame(frame.buffer, id, offset, file.byteLength);
        offset += chunk.byteLength;
      }
      if (offset === file.byteLength) verified.push(index);
    } catch { denied.push(index); }
  }
  assert.deepEqual(verified, [0]);
  assert.deepEqual(denied, [1]);
});
