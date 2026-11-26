"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { once } = require("node:events");
const { createRequire } = require("node:module");
const path = require("node:path");
const test = require("node:test");
const { Worker } = require("node:worker_threads");
const z = require("../src/crypto/rootark-zk-1");

const SCRIPT = path.resolve(__dirname,
  "../src/crypto/rootark-zk1-owner-authorized-hpke-seal-worker.js");
const nativeSet = Uint8Array.prototype.set;
const hpkeRequire = createRequire(require.resolve("@hpke/core"));
const aesPrototype = hpkeRequire("./src/aeads/aesGcm.js").AesGcmContext.prototype;
const mutexPrototype = hpkeRequire("./src/mutex.js").Mutex.prototype;

test("P1: isolated production HPKE worker never dispatches poisoned main-realm AES or mutex", async (t) => {
  const pair = await z.hpkeSuite().kem.generateKeyPair();
  const publicKey = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(pair.publicKey));
  const cek = crypto.randomBytes(32);
  const info = Buffer.from("Root.ark/zk-1/sharing/isolated-worker-p1/info\0");
  const aad = Buffer.from("Root.ark/zk-1/sharing/isolated-worker-p1/aad\0");
  const source = new ArrayBuffer(32);
  Reflect.apply(nativeSet, new Uint8Array(source), [cek]);
  const ackKey = crypto.randomBytes(32);
  const ackTransport = new ArrayBuffer(32);
  Reflect.apply(nativeSet, new Uint8Array(ackTransport), [ackKey]);
  const originalAesSeal = aesPrototype.seal;
  const originalMutexLock = mutexPrototype.lock;
  const subtle = crypto.webcrypto.subtle;
  const originalSubtleEncrypt = subtle.encrypt;
  let attackerAesCalls = 0, attackerMutexCalls = 0, attackerSubtleCalls = 0;
  let observedCek = false;
  const worker = new Worker(SCRIPT, { execArgv: [], env: {} });
  t.after(async () => { await worker.terminate().catch(() => {}); });
  const response = once(worker, "message");
  try {
    aesPrototype.seal = function (iv, raw, ...args) {
      attackerAesCalls++;
      if ((raw instanceof ArrayBuffer || ArrayBuffer.isView(raw))
        && crypto.timingSafeEqual(Buffer.from(raw), cek)) observedCek = true;
      return Reflect.apply(originalAesSeal, this, [iv, raw, ...args]);
    };
    mutexPrototype.lock = function (...args) {
      attackerMutexCalls++;
      return Reflect.apply(originalMutexLock, this, args);
    };
    subtle.encrypt = function (...args) {
      attackerSubtleCalls++;
      if ((args[2] instanceof ArrayBuffer || ArrayBuffer.isView(args[2]))
        && Buffer.from(args[2]).length === 32
        && crypto.timingSafeEqual(Buffer.from(args[2]), cek)) observedCek = true;
      return Reflect.apply(originalSubtleEncrypt, this, args);
    };
    worker.postMessage({ type: "seal", cek: source, ackKey: ackTransport,
      recipientPublicKey: publicKey, info, aad }, [source, ackTransport]);
    assert.equal(source.byteLength, 0, "the owner's original CEK buffer must detach synchronously");
    assert.equal(ackTransport.byteLength, 0,
      "the worker acknowledgement key must also cross an isolated transfer boundary");
    const [sealed] = await response;
    assert.equal(sealed.ok, true);
    assert.equal(Buffer.from(sealed.enc).length, 32);
    assert.equal(Buffer.from(sealed.ciphertext).length, 48);
    assert.deepEqual(Buffer.from(sealed.ackMac), crypto.createHmac("sha256", ackKey)
      .update(Buffer.from("Root.ark/zk-1/owner-hpke-worker-ack/v1\0"))
      .update(sealed.enc).update(sealed.ciphertext).digest(),
    "the real worker must authenticate the exact encrypted CEK bytes");
    assert.equal(attackerAesCalls, 0);
    assert.equal(attackerMutexCalls, 0);
    assert.equal(attackerSubtleCalls, 0);
    assert.equal(observedCek, false);
    // Do not run unwrapping in the poisoned main realm. Restore authentic
    // intrinsics before proving a real RFC9180 authenticated round-trip.
    aesPrototype.seal = originalAesSeal;
    mutexPrototype.lock = originalMutexLock;
    subtle.encrypt = originalSubtleEncrypt;
    const opened = await z.hpkeOpen({ recipientKey: pair.privateKey,
      enc: sealed.enc, ciphertext: sealed.ciphertext, info, aad });
    assert.deepEqual(Buffer.from(opened), cek);
    Buffer.from(opened).fill(0);
  } finally {
    aesPrototype.seal = originalAesSeal;
    mutexPrototype.lock = originalMutexLock;
    subtle.encrypt = originalSubtleEncrypt;
    cek.fill(0);
    ackKey.fill(0);
  }
});

test("P1: isolated production HPKE worker rejects malformed raw CEK without ciphertext", async (t) => {
  const worker = new Worker(SCRIPT, { execArgv: [], env: {} });
  t.after(async () => { await worker.terminate().catch(() => {}); });
  const response = once(worker, "message");
  worker.postMessage({ type: "seal", cek: new ArrayBuffer(31), ackKey: new ArrayBuffer(32),
    recipientPublicKey: new Uint8Array(32), info: new Uint8Array(1),
    aad: new Uint8Array(1) });
  assert.deepEqual((await response)[0], { ok: false });
});
