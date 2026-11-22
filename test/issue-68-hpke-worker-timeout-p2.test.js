"use strict";

// Deterministic fault injection on the actual production lifecycle helper.
// A fake Worker never acknowledges CEK sealing; the real timeout/termination
// implementation is exercised without slowing hosted suites by 45 seconds.
// Cryptographic correctness is separately tested with a REAL worker and HPKE.
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");

test("P2: an unresponsive HPKE worker times out and is terminated without CEK release", async () => {
  const location = path.resolve(__dirname,
    "../src/crypto/rootark-zk1-owner-authorized-file-cek-transfer.js");
  const source = fs.readFileSync(location, "utf8");
  const marker = "module.exports = { sealOwnerAuthorizedFileCek,";
  assert.ok(source.includes(marker), "must exercise actual shipped worker lifecycle helper");
  let created = 0, terminated = 0;
  class UnresponsiveWorker extends EventEmitter {
    constructor(script, options) {
      super();
      created++;
      assert.ok(script.endsWith("rootark-zk1-owner-authorized-hpke-seal-worker.js"));
      assert.deepEqual(options.execArgv, []);
      assert.deepEqual(Object.keys(options.env), []);
    }
    postMessage() { /* A stalled worker never responds. */ }
    terminate() { terminated++; return Promise.resolve(1); }
  }
  const injected = new Module(location, module);
  injected.filename = location;
  injected.paths = Module._nodeModulePaths(path.dirname(location));
  const originalRequire = injected.require;
  injected.require = function (id) {
    if (id === "node:worker_threads") return { Worker: UnresponsiveWorker };
    return Reflect.apply(originalRequire, this, [id]);
  };
  const realSetTimeout = global.setTimeout;
  try {
    global.setTimeout = (fn, _ms, ...args) => realSetTimeout(fn, 5, ...args);
    injected._compile(source.replace(marker,
      "module.exports = { __testMakeWorker: newPrivateHpkeWorker, sealOwnerAuthorizedFileCek,"),
    location);
  } finally { global.setTimeout = realSetTimeout; }
  const issued = injected.exports.__testMakeWorker();
  await assert.rejects(issued.reply, /ZK_OWNER_HPKE_WORKER_TIMEOUT/);
  assert.equal(created, 1);
  assert.equal(terminated, 1);
});
