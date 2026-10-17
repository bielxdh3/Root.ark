"use strict";

// Metadata-only burst detector for sync destructive operations (issue #67, step 1).
// It sees only the authenticated username, the opaque device id and the fact that an
// operation is a delete or an overwrite. It never reads ciphertext, names or paths.
//
// Memory is bounded: each (user, device) key keeps at most maxDestructive + 1 timestamps,
// and the number of tracked keys is capped at maxKeys (expired keys are pruned first, then
// the oldest-inserted key is evicted).

const DEFAULT_MAX_DESTRUCTIVE = 200;
const DEFAULT_WINDOW_MS = 600000;
const DEFAULT_MAX_KEYS = 5000;

function positiveInteger(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const number = Number(value);
  return Number.isSafeInteger(number) && number > 0 ? number : fallback;
}

function createSyncBurstGuard(options = {}) {
  const env = options.env || process.env;
  const maxDestructive = positiveInteger(options.maxDestructive ?? env.SYNC_BURST_MAX_DESTRUCTIVE, DEFAULT_MAX_DESTRUCTIVE);
  const windowMs = positiveInteger(options.windowMs ?? env.SYNC_BURST_WINDOW_MS, DEFAULT_WINDOW_MS);
  const maxKeys = positiveInteger(options.maxKeys ?? env.SYNC_BURST_MAX_KEYS, DEFAULT_MAX_KEYS);
  const clock = typeof options.now === "function" ? options.now : () => Date.now();
  const buckets = new Map();

  function keyOf(username, deviceId) {
    return JSON.stringify([String(username), String(deviceId)]);
  }

  function pruneExpired(cutoff) {
    for (const [key, entries] of buckets) {
      if (!entries.length || entries[entries.length - 1] <= cutoff) buckets.delete(key);
    }
  }

  // Records one destructive operation and reports whether the device exceeded the window limit.
  // `exceeded` is true from the (maxDestructive + 1)-th destructive operation inside the window.
  function recordDestructive(username, deviceId, at = clock()) {
    const key = keyOf(username, deviceId);
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
    if (entries.length > maxDestructive + 1) entries.splice(0, entries.length - (maxDestructive + 1));
    return { exceeded: entries.length > maxDestructive, count: entries.length, limit: maxDestructive, windowMs };
  }

  function reset(username, deviceId) {
    buckets.delete(keyOf(username, deviceId));
  }

  function trackedKeys() {
    return buckets.size;
  }

  return {
    recordDestructive,
    reset,
    trackedKeys,
    config: Object.freeze({ maxDestructive, windowMs, maxKeys }),
  };
}

module.exports = { DEFAULT_MAX_DESTRUCTIVE, DEFAULT_WINDOW_MS, DEFAULT_MAX_KEYS, createSyncBurstGuard };
