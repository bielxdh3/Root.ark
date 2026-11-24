"use strict";

function createPrivateShareSnapshotBudget({ maxConcurrent, maxBytes }) {
  if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1
    || !Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new TypeError("Snapshot budget limits must be positive safe integers");
  }

  let active = 0;
  let reservedBytes = 0;

  function reserve(bytes) {
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maxBytes
      || active >= maxConcurrent || reservedBytes + bytes > maxBytes) return null;
    active += 1;
    reservedBytes += bytes;
    let activeReleased = false;
    let bytesReleased = false;
    const releaseActive = () => {
      if (activeReleased) return;
      activeReleased = true;
      active -= 1;
    };
    const releaseBytes = () => {
      if (bytesReleased) return;
      bytesReleased = true;
      reservedBytes -= bytes;
    };
    const release = () => {
      releaseActive();
      releaseBytes();
    };
    Object.defineProperty(release, "releaseActive", { value: releaseActive });
    return release;
  }

  return Object.freeze({
    reserve,
    getState: () => Object.freeze({ active, reservedBytes }),
  });
}

module.exports = { createPrivateShareSnapshotBudget };
