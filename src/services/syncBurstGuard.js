"use strict";

// Metadata-only burst detector for sync destructive operations (issue #67).
// It sees only the authenticated username, the opaque device id, the opaque object id and the
// fact that an operation is a delete or an overwrite. It never reads ciphertext, names or paths.
//
// Two windowed counters are kept:
//   - per (user, device): total destructive operations (SYNC_BURST_MAX_DESTRUCTIVE);
//   - per (user, device, object): repeated destructive operations on one object
//     (SYNC_BURST_MAX_PER_OBJECT). This catches a client overwriting one file faster than the
//     per-device total would notice, before per-object history is pruned.
//
// Memory is bounded: each key keeps at most limit + 1 timestamps, and each counter map is capped
// at maxKeys (expired keys are pruned first, then the oldest-inserted key is evicted).

const DEFAULT_MAX_DESTRUCTIVE = 200;
const DEFAULT_MAX_PER_OBJECT = 16;
const DEFAULT_WINDOW_MS = 600000;
const DEFAULT_MAX_KEYS = 5000;

function positiveInteger(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : fallback;
}

function createWindowCounter({ limit, windowMs, maxKeys, clock }) {
  const buckets = new Map();

  function pruneExpired(cutoff) {
    for (const [key, entries] of buckets) {
      if (!entries.length || entries[entries.length - 1] <= cutoff) buckets.delete(key);
    }
  }

  // `exceeded` is true from the (limit + 1)-th operation inside the window.
  function record(key, at) {
    const cutoff = at - windowMs;
    let entries = buckets.get(key);
    if (!entries) {
      if (buckets.size >= maxKeys) pruneExpired(cutoff);
      if (buckets.size >= maxKeys) buckets.delete(buckets.keys().next().value);
      entries = [];
      buckets.set(key, entries);
    }
    let expired = 0;
    while (expired < entries.length && entries[expired] <= cutoff) expired += 1;
    if (expired) entries.splice(0, expired);
    entries.push(at);
    if (entries.length > limit + 1) entries.splice(0, entries.length - (limit + 1));
    return { exceeded: entries.length > limit, count: entries.length, limit, windowMs };
  }

  return { record, size: () => buckets.size, clear: (key) => buckets.delete(key) };
}

function createSyncBurstGuard(options = {}) {
  const env = options.env || process.env;
  const maxDestructive = positiveInteger(options.maxDestructive ?? env.SYNC_BURST_MAX_DESTRUCTIVE, DEFAULT_MAX_DESTRUCTIVE);
  const maxPerObject = positiveInteger(options.maxPerObject ?? env.SYNC_BURST_MAX_PER_OBJECT, DEFAULT_MAX_PER_OBJECT);
  const windowMs = positiveInteger(options.windowMs ?? env.SYNC_BURST_WINDOW_MS, DEFAULT_WINDOW_MS);
  const maxKeys = positiveInteger(options.maxKeys ?? env.SYNC_BURST_MAX_KEYS, DEFAULT_MAX_KEYS);
  const clock = typeof options.now === "function" ? options.now : () => Date.now();
  const perDevice = createWindowCounter({ limit: maxDestructive, windowMs, maxKeys, clock });
  const perObject = createWindowCounter({ limit: maxPerObject, windowMs, maxKeys, clock });

  function deviceKey(username, deviceId) {
    return JSON.stringify([String(username), String(deviceId)]);
  }

  // Records one destructive operation. Returns the device-level and object-level results.
  // `exceeded` on either result means the device must be paused.
  function recordDestructive(username, deviceId, objectId = null, at = clock()) {
    const device = perDevice.record(deviceKey(username, deviceId), at);
    const object = objectId === null || objectId === undefined
      ? { exceeded: false, count: 0, limit: maxPerObject, windowMs }
      : perObject.record(JSON.stringify([String(username), String(deviceId), String(objectId)]), at);
    return {
      exceeded: device.exceeded || object.exceeded,
      deviceExceeded: device.exceeded,
      objectExceeded: object.exceeded,
      count: device.count,
      limit: maxDestructive,
      objectCount: object.count,
      objectLimit: maxPerObject,
      windowMs,
    };
  }

  function reset(username, deviceId) {
    perDevice.clear(deviceKey(username, deviceId));
  }

  function trackedKeys() {
    return perDevice.size() + perObject.size();
  }

  return {
    recordDestructive,
    reset,
    trackedKeys,
    config: Object.freeze({ maxDestructive, maxPerObject, windowMs, maxKeys }),
  };
}

module.exports = { DEFAULT_MAX_DESTRUCTIVE, DEFAULT_MAX_PER_OBJECT, DEFAULT_WINDOW_MS, DEFAULT_MAX_KEYS, createSyncBurstGuard };
