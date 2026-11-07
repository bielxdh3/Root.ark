'use strict';
// Small independent wire format for the disposable #242 experiment.
// Ordered, reliable DataChannel: magic (4), transfer nonce (16), offset BE (4), bytes.
(() => {
  const MAX_FILE = 32 * 1024 * 1024;
  const CHUNK_BYTES = 8 * 1024;
  const HEADER_BYTES = 24;
  const MAX_CHUNKS = MAX_FILE / CHUNK_BYTES;
  const BUFFER_HIGH = 256 * 1024;
  const SEND_STALL_MS = 30_000;
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

  // A slow 1:N recipient must not hold a sender's transfer state forever.
  // Every DataChannel has its own bounded wait, abort and listener lifetime.
  function waitForSendWindow(dc, signal, timeoutMs = SEND_STALL_MS) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 ||
      timeoutMs > SEND_STALL_MS) throw new RangeError('Invalid send wait');
    if (dc.bufferedAmount < BUFFER_HIGH || signal.aborted ||
      dc.readyState !== 'open') return Promise.resolve();
    return new Promise((resolve, reject) => {
      let settled = false;
      let timer;
      const finish = error => {
        if (settled) return;
        settled = true;
        dc.removeEventListener('bufferedamountlow', onDrain);
        dc.removeEventListener('close', onStop);
        signal.removeEventListener('abort', onStop);
        clearTimeout(timer);
        if (error) reject(new Error('P2P_SEND_BUFFER_STALLED'));
        else resolve();
      };
      const onDrain = () => {
        if (dc.bufferedAmount < BUFFER_HIGH) finish();
      };
      const onStop = () => finish();
      dc.addEventListener('bufferedamountlow', onDrain);
      dc.addEventListener('close', onStop);
      signal.addEventListener('abort', onStop, { once: true });
      timer = setTimeout(() => {
        if (signal.aborted || dc.readyState !== 'open' ||
          dc.bufferedAmount < BUFFER_HIGH) finish();
        else finish(true);
      }, timeoutMs);
      if (signal.aborted || dc.readyState !== 'open' ||
        dc.bufferedAmount < BUFFER_HIGH) finish();
    });
  }

  const api = Object.freeze({ MAX_FILE, CHUNK_BYTES, HEADER_BYTES, MAX_CHUNKS, validOffer,
    packFrame, parseFrame, waitForSendWindow,
    validId: id => idPattern.test(id), validDigest: digest => digestPattern.test(digest) });
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (typeof window !== 'undefined') window.P2PFileWire = api;
})();
