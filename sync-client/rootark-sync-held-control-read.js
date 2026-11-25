"use strict";

// Cold metadata files are untrusted local input. Even a read from the correct
// opened inode can consume unbounded memory if a same-principal writer grows
// it after fstat but before FileHandle.readFile() reaches EOF. Bound the read
// to the *original* observed size, plus one byte to detect concurrent growth.
// This is resource/identity hardening, NOT independent root custody.
const MAX_COLD_CONTROL_BYTES = 256 * 1024 * 1024;
const HELD_READ_CHUNK_BYTES = 64 * 1024;

async function readExactOpenedControlBytes(handle, expectedSize, invalid) {
  if (typeof expectedSize !== "bigint" || expectedSize < 0n
    || expectedSize > BigInt(MAX_COLD_CONTROL_BYTES)) throw invalid();
  const size = Number(expectedSize);
  const buffer = Buffer.allocUnsafe(size + 1);
  let total = 0;
  while (total < buffer.length) {
    const length = Math.min(HELD_READ_CHUNK_BYTES, buffer.length - total);
    const { bytesRead } = await handle.read(buffer, total, length, total);
    if (!Number.isInteger(bytesRead) || bytesRead < 0 || bytesRead > length) {
      throw invalid();
    }
    if (bytesRead === 0) break;
    total += bytesRead;
  }
  if (total !== size) throw invalid();
  return buffer.subarray(0, total);
}

module.exports = { readExactOpenedControlBytes };
