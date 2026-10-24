"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const workerThreads = require("node:worker_threads");
const { RootarkZkError } = require("../src/crypto/rootark-zk-1");
const { deriveRecoveryKeyBounded } = require("../src/crypto/rootark-zk-recovery-kdf");

const password = "phase-one-password";
const salt = Buffer.alloc(16, 0x31);

function fakeWorkerClass(onCreate) {
  return class FakeWorker extends EventEmitter {
    constructor(filename, options) {
      super();
      this.filename = filename;
      this.options = options;
      onCreate(this);
    }

    terminate() {
      return Promise.resolve(0);
    }
  };
}

function emitMessage(worker, key = Buffer.alloc(32, 0x5a)) {
  setImmediate(() => worker.emit("message", { ok: true, key }));
}

test("usesFixedArgon2id13ProfileAndReturns32Bytes", async (t) => {
  let workerData;
  t.mock.method(workerThreads, "Worker", fakeWorkerClass((worker) => {
    workerData = worker.options.workerData;
    emitMessage(worker);
  }));

  const key = await deriveRecoveryKeyBounded({ password, salt });

  assert.equal(key.length, 32);
  assert.deepEqual(workerData.profile, {
    id: "argon2id13",
    opslimit: 3,
    memlimit: 268435456,
    outputLength: 32,
  });
  assert.equal(workerData.salt.length, 16);
  assert.ok(workerData.password instanceof Uint8Array);
});

test("realWorkerReturns32ByteKeyUnderFixedProfile", async () => {
  const key = await deriveRecoveryKeyBounded({ password, salt });
  assert.equal(key.length, 32);
  key.fill(0);
});

test("returnsKdfBusyWithoutQueueingSecondDerivation", async (t) => {
  let worker;
  let starts = 0;
  t.mock.method(workerThreads, "Worker", fakeWorkerClass((created) => {
    starts += 1;
    worker = created;
  }));

  const first = deriveRecoveryKeyBounded({ password, salt });
  await assert.rejects(
    deriveRecoveryKeyBounded({ password: `${password}-second`, salt }),
    (error) => error instanceof RootarkZkError && error.code === "KDF_BUSY",
  );
  assert.equal(starts, 1);

  emitMessage(worker);
  assert.equal((await first).length, 32);
});

test("mapsWorkerStartupErrorExitTimeoutAndAllocationFailureToRecoveryKdfFailed", async (t) => {
  await t.test("startup error", async (t) => {
    t.mock.method(workerThreads, "Worker", class StartupFailure {
      constructor() {
        throw new Error("worker startup failed");
      }
    });
    await assert.rejects(
      deriveRecoveryKeyBounded({ password, salt }),
      (error) => error instanceof RootarkZkError && error.code === "RECOVERY_KDF_FAILED",
    );
  });

  await t.test("worker error", async (t) => {
    t.mock.method(workerThreads, "Worker", fakeWorkerClass((worker) => {
      setImmediate(() => worker.emit("error", new Error("worker failed")));
    }));
    await assert.rejects(
      deriveRecoveryKeyBounded({ password, salt }),
      (error) => error instanceof RootarkZkError && error.code === "RECOVERY_KDF_FAILED",
    );
  });

  await t.test("nonzero exit", async (t) => {
    t.mock.method(workerThreads, "Worker", fakeWorkerClass((worker) => {
      setImmediate(() => worker.emit("exit", 1));
    }));
    await assert.rejects(
      deriveRecoveryKeyBounded({ password, salt }),
      (error) => error instanceof RootarkZkError && error.code === "RECOVERY_KDF_FAILED",
    );
  });

  await t.test("timeout", async (t) => {
    t.mock.method(workerThreads, "Worker", fakeWorkerClass(() => {}));
    t.mock.method(global, "setTimeout", (callback, delay) => {
      assert.equal(delay, 120000);
      queueMicrotask(callback);
      return 1;
    });
    t.mock.method(global, "clearTimeout", () => {});
    await assert.rejects(
      deriveRecoveryKeyBounded({ password, salt }),
      (error) => error instanceof RootarkZkError && error.code === "RECOVERY_KDF_FAILED",
    );
  });

  await t.test("allocation failure", async (t) => {
    t.mock.method(workerThreads, "Worker", fakeWorkerClass((worker) => {
      const error = new Error("worker allocation failed");
      error.code = "ERR_WORKER_OUT_OF_MEMORY";
      setImmediate(() => worker.emit("error", error));
    }));
    await assert.rejects(
      deriveRecoveryKeyBounded({ password, salt }),
      (error) => error instanceof RootarkZkError && error.code === "RECOVERY_KDF_FAILED",
    );
  });
});

test("rejectsInvalidPasswordAndSaltBeforeStartingWorker", async (t) => {
  let starts = 0;
  t.mock.method(workerThreads, "Worker", fakeWorkerClass(() => {
    starts += 1;
  }));

  await assert.rejects(deriveRecoveryKeyBounded({ password: "", salt }));
  await assert.rejects(deriveRecoveryKeyBounded({ password: "x".repeat(1025), salt }));
  await assert.rejects(deriveRecoveryKeyBounded({ password, salt: Buffer.alloc(15) }));
  assert.equal(starts, 0);
});
