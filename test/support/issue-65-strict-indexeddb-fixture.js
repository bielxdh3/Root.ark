"use strict";

// Deterministic test-only IndexedDB transaction simulator. Not a physical
// durability substitute: real Chromium IndexedDB is tested separately.
function strictIndexedDB({ refuseStrict = false, failCommit = false,
  cloneOnRead = (value) => value } = {}) {
  const values = new Map();
  const names = { contains: (name) => name === "sealed-intents" || initialized };
  let initialized = false, writes = 0;
  const schedule = (fn) => setImmediate(fn);
  const result = {
    values, get writes() { return writes; },
    open() {
      const request = {};
      schedule(() => {
        const db = {
          objectStoreNames: names,
          createObjectStore() { initialized = true; }, close() {},
          transaction(_store, mode, opts) {
            let dead = false;
            const strict = opts?.durability === "strict";
            const tx = {
              durability: mode === "readwrite" && strict && !refuseStrict ? "strict" : "default",
              abort() { dead = true; schedule(() => tx.onabort?.()); },
              objectStore() {
                const enqueue = (action) => {
                  const req = {};
                  schedule(() => {
                    if (dead) return;
                    let item;
                    try {
                      item = action();
                      if (mode === "readwrite" && failCommit) {
                        tx.abort(); return;
                      }
                      req.result = item;
                      req.onsuccess?.();
                      if (!dead) schedule(() => tx.oncomplete?.());
                    } catch (_) { tx.abort(); }
                  });
                  return req;
                };
                return {
                  get(key) { return enqueue(() => cloneOnRead(values.get(key))); },
                  add(value, key) { return enqueue(() => {
                    if (values.has(key)) throw Error("unique conflict");
                    values.set(key, structuredClone(value)); writes++; return key;
                  }); },
                  getAllKeys() { return enqueue(() => [...values.keys()]); },
                };
              },
            };
            return tx;
          },
        };
        request.result = db;
        if (!initialized) { initialized = true; request.onupgradeneeded?.(); }
        request.onsuccess?.();
      });
      return request;
    },
  };
  return result;
}
module.exports = { strictIndexedDB };
