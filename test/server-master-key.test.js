"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { Worker } = require("node:worker_threads");
const test = require("node:test");
const { getServerMasterKey } = require("../services/serverMasterKey");

function startConcurrentInitialization(filePath, gate) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(`
      const fs = require("node:fs");
      const crypto = require("node:crypto");
      const { parentPort, workerData } = require("node:worker_threads");
      const originalExistsSync = fs.existsSync;
      fs.existsSync = function (candidate) {
        if (pathResolve(candidate) === workerData.filePath) {
          const exists = originalExistsSync.call(this, candidate);
          const counter = new Int32Array(workerData.gate);
          if (Atomics.add(counter, 0, 1) === 1) Atomics.notify(counter, 0, 2);
          else Atomics.wait(counter, 0, 1);
          return exists;
        }
        return originalExistsSync.call(this, candidate);
      };
      const pathResolve = require("node:path").resolve;
      const { getServerMasterKey } = require(workerData.servicePath);
      const key = getServerMasterKey({ filePath: workerData.filePath, env: {} });
      parentPort.postMessage(crypto.createHash("sha256").update(key).digest("hex"));
    `, {
      eval: true,
      workerData: { filePath, gate, servicePath: path.resolve(__dirname, "../services/serverMasterKey.js") },
    });
    worker.once("message", resolve);
    worker.once("error", reject);
    worker.once("exit", (code) => { if (code !== 0) reject(new Error(`worker exited ${code}`)); });
  });
}

test("concurrent first boots return the exact same persisted master key", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-master-key-"));
  const filePath = path.join(directory, "server-master.key");
  try {
    const gate = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
    const digests = await Promise.all([
      startConcurrentInitialization(filePath, gate),
      startConcurrentInitialization(filePath, gate),
    ]);
    assert.deepEqual(fs.readdirSync(directory), ["server-master.key"]);
    const persistedKey = Buffer.from(fs.readFileSync(filePath, "utf8").trim(), "hex");
    assert.equal(persistedKey.length, 32);
    const persistedDigest = crypto.createHash("sha256").update(persistedKey).digest("hex");
    assert.ok(digests.every((digest) => digest === persistedDigest));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("an existing malformed partial key fails closed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-master-key-partial-"));
  const filePath = path.join(directory, "server-master.key");
  try {
    fs.writeFileSync(filePath, "ab12");
    assert.throws(() => getServerMasterKey({ filePath, env: {} }), /invalida/);
    assert.equal(fs.readFileSync(filePath, "utf8"), "ab12");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("first boot syncs publication on POSIX and skips directory fsync on Windows", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-master-key-fsync-"));
  const filePath = path.join(directory, "server-master.key");
  const originalOpenSync = fs.openSync;
  const originalFsyncSync = fs.fsyncSync;
  const originalLinkSync = fs.linkSync;
  const originalUnlinkSync = fs.unlinkSync;
  const events = [];
  let directoryFd = null;
  let failDirectorySync = true;
  try {
    fs.openSync = function (target, ...args) {
      const descriptor = originalOpenSync.call(this, target, ...args);
      if (path.resolve(String(target)) === directory) {
        directoryFd = descriptor;
        events.push("directory-open");
      }
      return descriptor;
    };
    fs.fsyncSync = function (descriptor) {
      if (descriptor === directoryFd) {
        events.push("directory-fsync");
        if (failDirectorySync) {
          failDirectorySync = false;
          throw Object.assign(new Error("injected directory sync failure"), { code: "EIO" });
        }
      }
      return originalFsyncSync.call(this, descriptor);
    };
    fs.linkSync = function (...args) {
      events.push("publish");
      return originalLinkSync.apply(this, args);
    };
    fs.unlinkSync = function (target) {
      if (String(target).startsWith(`${filePath}.`)) events.push("temp-cleanup");
      return originalUnlinkSync.call(this, target);
    };

    if (process.platform === "win32") {
      assert.equal(getServerMasterKey({ filePath, env: {} }).length, 32);
      assert.deepEqual(events, ["publish", "temp-cleanup"]);
    } else {
      assert.throws(() => getServerMasterKey({ filePath, env: {} }), { code: "EIO" });
      assert.deepEqual(events, ["publish", "temp-cleanup", "directory-open", "directory-fsync"]);
      assert.equal(getServerMasterKey({ filePath, env: {} }).length, 32);
      assert.deepEqual(events, [
        "publish", "temp-cleanup", "directory-open", "directory-fsync", "directory-open", "directory-fsync",
      ]);
    }
    assert.deepEqual(fs.readdirSync(directory), ["server-master.key"]);
  } finally {
    fs.openSync = originalOpenSync;
    fs.fsyncSync = originalFsyncSync;
    fs.linkSync = originalLinkSync;
    fs.unlinkSync = originalUnlinkSync;
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("env key and createIfMissing false retain their existing semantics", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-master-key-options-"));
  const filePath = path.join(directory, "server-master.key");
  const envKey = crypto.randomBytes(32);
  try {
    assert.deepEqual(getServerMasterKey({ filePath, env: { SERVER_MASTER_KEY: envKey.toString("hex") } }), envKey);
    assert.deepEqual(getServerMasterKey({ filePath, env: { SERVER_MASTER_KEY: envKey.toString("base64") } }), envKey);
    assert.equal(fs.existsSync(filePath), false);
    assert.throws(() => getServerMasterKey({ filePath, env: {}, createIfMissing: false }), /ausente/);
    assert.equal(fs.existsSync(filePath), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
