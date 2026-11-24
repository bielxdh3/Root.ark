'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const wire = require('../transfer-protocol.js');

const id = '0123456789abcdef0123456789abcdef';
const other = 'fedcba9876543210fedcba9876543210';

test('32 MiB maximum; strict id, declared size and metadata bounds', () => {
  assert.equal(wire.MAX_FILE, 32 * 1024 * 1024);
  assert.ok(wire.validOffer({ type: 'offer-file', id, name: 'fixture.bin',
    size: wire.MAX_FILE, digest: 'a'.repeat(64) }));
  for (const override of [{ size: wire.MAX_FILE + 1 }, { size: 0 },
    { name: 'a'.repeat(101) }, { id: 'not-an-id' }, { digest: 'bad' }]) {
    assert.equal(wire.validOffer({ type: 'offer-file', id, name: 'fixture.bin', size: 1,
      digest: 'a'.repeat(64), ...override }), false);
  }
});

test('binary frame identifies the transfer, absolute offset and exact chunk length', () => {
  const bytes = Uint8Array.from({ length: wire.CHUNK_BYTES }, (_, i) => i % 251);
  const frame = wire.packFrame(id, 0, bytes);
  const first = wire.parseFrame(frame.buffer, id, 0, wire.CHUNK_BYTES + 7);
  assert.equal(first.byteLength, wire.CHUNK_BYTES);
  assert.deepEqual(first, bytes);
  const last = wire.parseFrame(wire.packFrame(id, wire.CHUNK_BYTES, Uint8Array.from({ length: 7 })).buffer,
    id, wire.CHUNK_BYTES, wire.CHUNK_BYTES + 7);
  assert.equal(last.byteLength, 7);
});

test('malformed, replayed, truncated, oversized and cross-transfer frames fail closed', () => {
  const payload = Uint8Array.from({ length: wire.CHUNK_BYTES });
  const frame = wire.packFrame(id, 0, payload);
  const corrupt = frame.slice(); corrupt[0] ^= 255;
  const tamperedOffset = frame.slice(); tamperedOffset[23] = 1;
  const mismatched = wire.packFrame(other, 0, payload);
  for (const bytes of [new Uint8Array(0), frame.slice(0, 23),
    wire.packFrame(id, 0, new Uint8Array(1)),
    corrupt, tamperedOffset, mismatched,
    new Uint8Array(wire.HEADER_BYTES + wire.CHUNK_BYTES + 1)]) {
    assert.throws(() => wire.parseFrame(bytes.buffer, id, 0, wire.CHUNK_BYTES + 1), /frame/i);
  }
  assert.throws(() => wire.parseFrame(frame.buffer, id, wire.CHUNK_BYTES, 2 * wire.CHUNK_BYTES), /frame/i);
  assert.throws(() => wire.parseFrame(frame.buffer, id, 0, wire.CHUNK_BYTES - 1), /frame/i);
  assert.throws(() => wire.packFrame(id, 0, new Uint8Array(0)), /frame/i);
  assert.throws(() => wire.packFrame(id, 0, new Uint8Array(wire.CHUNK_BYTES + 1)), /frame/i);
});
