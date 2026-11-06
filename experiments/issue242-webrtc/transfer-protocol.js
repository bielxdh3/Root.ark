'use strict';
// Small independent wire format for the disposable #242 experiment.
// Ordered, reliable DataChannel: magic (4), transfer nonce (16), offset BE (4), bytes.
(() => {
  const MAX_FILE = 32 * 1024 * 1024;
  const CHUNK_BYTES = 8 * 1024;
  const HEADER_BYTES = 24;
  const MAX_CHUNKS = MAX_FILE / CHUNK_BYTES;
  const idPattern = /^[0-9a-f]{32}$/;
  const digestPattern = /^[0-9a-f]{64}$/;
  const magic = [0x52, 0x32, 0x34, 0x32]; // R242
  const validOffer = m => m && m.type === 'offer-file' && idPattern.test(m.id) &&
    typeof m.name === 'string' && m.name.length > 0 && m.name.length <= 100 &&
    Number.isSafeInteger(m.size) && m.size > 0 && m.size <= MAX_FILE && digestPattern.test(m.digest);

  function packFrame(id, offset, payload) {
    if (!idPattern.test(id) || !Number.isSafeInteger(offset) || offset < 0 ||
      offset > MAX_FILE || !(payload instanceof Uint8Array) ||
      payload.byteLength === 0 || payload.byteLength > CHUNK_BYTES ||
      offset + payload.byteLength > MAX_FILE) throw new RangeError('Invalid file frame');
    const frame = new Uint8Array(HEADER_BYTES + payload.byteLength);
    frame.set(magic);
    for (let i = 0; i < 16; i++) frame[4 + i] = Number.parseInt(id.slice(i * 2, i * 2 + 2), 16);
    new DataView(frame.buffer).setUint32(20, offset, false);
    frame.set(payload, HEADER_BYTES);
    return frame;
  }

  function parseFrame(buffer, expectedId, expectedOffset, fileSize) {
    if (!(buffer instanceof ArrayBuffer) || !idPattern.test(expectedId) ||
      !Number.isSafeInteger(expectedOffset) || expectedOffset < 0 ||
      !Number.isSafeInteger(fileSize) || fileSize <= 0 || fileSize > MAX_FILE ||
      buffer.byteLength <= HEADER_BYTES || buffer.byteLength > HEADER_BYTES + CHUNK_BYTES ||
      expectedOffset >= fileSize) throw new RangeError('Invalid file frame');
    const view = new Uint8Array(buffer);
    for (let i = 0; i < magic.length; i++) if (view[i] !== magic[i]) throw new RangeError('Invalid file frame magic');
    for (let i = 0; i < 16; i++) {
      if (view[4 + i] !== Number.parseInt(expectedId.slice(i * 2, i * 2 + 2), 16)) {
        throw new RangeError('Invalid file frame id');
      }
    }
    if (new DataView(buffer).getUint32(20, false) !== expectedOffset ||
      buffer.byteLength - HEADER_BYTES !== Math.min(CHUNK_BYTES, fileSize - expectedOffset)) {
      throw new RangeError('Invalid file frame offset/length');
    }
    return view.subarray(HEADER_BYTES);
  }

  const api = Object.freeze({ MAX_FILE, CHUNK_BYTES, HEADER_BYTES, MAX_CHUNKS, validOffer,
    packFrame, parseFrame, validId: id => idPattern.test(id), validDigest: digest => digestPattern.test(digest) });
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (typeof window !== 'undefined') window.P2PFileWire = api;
})();
