"use strict";
const path = require("node:path");
const { Worker } = require("node:worker_threads");

// better-sqlite3's BEGIN IMMEDIATE callback is synchronous. A native security
// check outside that writer lock is not the same admission decision. Keep the
// caller blocked INSIDE the SQLite transaction while a separate Node worker
// drives the verified resident C# PowerShell ACL check (never a cached verdict).
function createWindowsSynchronousPrivateAclVerifier() {
  if (process.platform !== "win32") return { verify() {}, verifyAuthorityFile() {}, stop() {} };
  const DEADLINE_MS = 12000;
  let stopped = false;
  let dead = false;
  let worker = null;
  const denial = () => new Error("Windows SQLite CAS ACL validation failed");
  function verify(directory, kind) {
      if (stopped || dead || typeof directory !== "string" || !directory.length
        || Buffer.byteLength(directory, "utf8") > 65000) throw denial();
      if (!worker) {
        try {
          worker = new Worker(path.join(__dirname,
            "zk1WindowsSynchronousPrivateAclWorker.js"));
          worker.on("error", () => { dead = true; });
          worker.on("exit", () => { dead = true; });
          worker.unref();
        } catch (_) { dead = true; throw denial(); }
      }
      // A distinct shared slot per call prevents a late response to an
      // expired check from authorizing ANY later operation.
      const status = new Int32Array(new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT));
      try { worker.postMessage({ path: directory, kind, signal: status.buffer }); }
      catch (_) { dead = true; throw denial(); }
      const result = Atomics.wait(status, 0, 0, DEADLINE_MS);
      // A fast native worker may notify before Atomics.wait starts; Node
      // reports "not-equal" in that case, with the same checked status.
      if ((result !== "ok" && result !== "not-equal")
        || Atomics.load(status, 0) !== 1) {
        if (result === "timed-out") {
          dead = true;
          worker.terminate();
        }
        throw denial();
      }
      if (stopped || dead) throw denial();
  }
  return {
    verify(directory) { return verify(directory, "private-directory"); },
    verifyAuthorityFile(filename) { return verify(filename, "authority-file"); },
    stop() {
      if (stopped) return;
      stopped = true;
      if (worker) {
        try { worker.postMessage({ action: "stop" }); }
        catch (_) { worker.terminate(); }
      }
    },
  };
}

module.exports = { createWindowsSynchronousPrivateAclVerifier };
