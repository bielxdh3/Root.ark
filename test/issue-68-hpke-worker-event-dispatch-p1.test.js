"use strict";

// RED -> GREEN: a hostile authority callback controls the parent's global
// EventEmitter prototype. The production worker must never dispatch a
// forged `message` or suppress `exit` through that mutable prototype.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { EventEmitter } = require("node:events");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const test = require("node:test");
const { Worker, MessagePort } = require("node:worker_threads");
const z = require("../src/crypto/rootark-zk-1");

function privateSealHelpers({ holdAfterClose = false } = {}) {
  const location = path.resolve(__dirname,
    "../src/crypto/rootark-zk1-owner-authorized-file-cek-transfer.js");
  const source = fs.readFileSync(location, "utf8");
  const marker = "module.exports = { sealOwnerAuthorizedFileCek,";
  assert.ok(source.includes(marker));
  const injected = new Module(location, module);
  injected.filename = location;
  injected.paths = Module._nodeModulePaths(path.dirname(location));
  let instrumented = source.replace(marker,
    "module.exports = { __newPrivateHpkeWorker: newPrivateHpkeWorker, "
      + "__sealPrivateCekHpke: sealPrivateCekHpke, sealOwnerAuthorizedFileCek,");
  if (holdAfterClose) {
    // Execute the actual HPKE worker module; retain one fixture-only event-loop
    // handle so its natural parentPort.close cannot race our termination oracle.
    const spawn = "const worker = new Worker(hpkeSealWorkerPath, options);";
    assert.ok(instrumented.includes(spawn));
    injected.closeState = new Int32Array(new SharedArrayBuffer(4));
    instrumented = instrumented.replace(spawn, `const worker = new Worker(
      'const { parentPort, workerData } = require("node:worker_threads");'
      + 'parentPort.once("close", () => { Atomics.store(workerData, 0, 1); Atomics.notify(workerData, 0); });'
      + 'setInterval(() => {}, 1000); require(' + JSON.stringify(hpkeSealWorkerPath) + ');',
      { ...options, eval: true, workerData: module.closeState });`);
  }
  injected._compile(instrumented, location);
  if (holdAfterClose) injected.exports.closeState = injected.closeState;
  return injected.exports;
}

test("P1: callback-patched EventEmitter.emit cannot forge owner CEK ciphertext or hide worker exit", async () => {
  // Import module before callback poisoning, as in production.
  const helper = privateSealHelpers();
  const pair = await z.hpkeSuite().kem.generateKeyPair();
  const pub = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(pair.publicKey));
  const info = Buffer.from("Root.ark/sharing/worker-event-dispatch-p1/info\0");
  const aad = Buffer.from("Root.ark/sharing/worker-event-dispatch-p1/aad\0");
  const realCek = crypto.randomBytes(32);
  const attackerCek = crypto.randomBytes(32);
  const forged = await z.hpkeSeal({ recipientPublicKey: pair.publicKey,
    plaintext: attackerCek, info, aad });
  const issued = helper.__newPrivateHpkeWorker();
  const savedEmit = EventEmitter.prototype.emit;
  const terminate = Worker.prototype.terminate;
  let forgedMessages = 0, interceptedExit = 0;
  let secretReturned;
  try {
    EventEmitter.prototype.emit = function (kind, ...args) {
      if (this === issued.worker && kind === "message") {
        forgedMessages++;
        return Reflect.apply(savedEmit, this, [kind,
          { ok: true, enc: forged.enc, ciphertext: forged.ciphertext }, ...args.slice(1)]);
      }
      if (this === issued.worker && kind === "exit") {
        interceptedExit++;
        return true; // maliciously suppress the event terminate() awaits
      }
      return Reflect.apply(savedEmit, this, [kind, ...args]);
    };
    const encrypted = await helper.__sealPrivateCekHpke(
      issued, pub, realCek, info, aad);
    secretReturned = Buffer.from(await z.hpkeOpen({ recipientKey: pair.privateKey,
      enc: encrypted.enc, ciphertext: encrypted.ciphertext, info, aad }));
    const exitStatus = await Reflect.apply(terminate, issued.worker, []);
    assert.ok(exitStatus === undefined || Number.isInteger(exitStatus),
      "worker termination must settle, including if the helper already exited cleanly");
    assert.equal(forgedMessages, 0,
      "main-realm EventEmitter override cannot substitute attacker-chosen CEK");
    assert.equal(interceptedExit, 0,
      "main-realm EventEmitter override cannot swallow worker exit events");
    assert.deepEqual(secretReturned, realCek,
      "genuine X25519/AES256GCM HPKE must recover only original owner CEK");
    assert.notDeepEqual(secretReturned, attackerCek);
    const pinned = Object.getOwnPropertyDescriptor(issued.worker, "emit");
    assert.equal(pinned?.writable, false);
    assert.equal(pinned?.configurable, false);
  } finally {
    EventEmitter.prototype.emit = savedEmit;
    await Reflect.apply(terminate, issued.worker, []).catch(() => {});
    realCek.fill(0);
    attackerCek.fill(0);
    secretReturned?.fill(0);
  }
});

test("P2: callback-poisoned EventEmitter.once cannot strand the owner HPKE worker termination", async () => {
  const helper = privateSealHelpers({ holdAfterClose: true });
  const pair = await z.hpkeSuite().kem.generateKeyPair();
  const pub = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(pair.publicKey));
  const info = Buffer.from("Root.ark/sharing/worker-once-exit-p2/info\0");
  const aad = Buffer.from("Root.ark/sharing/worker-once-exit-p2/aad\0");
  const ownerCek = crypto.randomBytes(32);
  const savedOnce = EventEmitter.prototype.once;
  const terminate = Worker.prototype.terminate;
  let issued, onceSpyCalls = 0, opened;
  try {
    // The owner now reserves a genuine Worker BEFORE the authority callback.
    // Node 22 terminate() dynamically reads this.once('exit', resolve).
    issued = helper.__newPrivateHpkeWorker();
    EventEmitter.prototype.once = function (kind, listener) {
      if (issued && this === issued.worker && kind === "exit") {
        onceSpyCalls++;
        return this; // attacker silently drops the worker-exit listener
      }
      return Reflect.apply(savedOnce, this, [kind, listener]);
    };
    const sealed = await helper.__sealPrivateCekHpke(issued, pub, ownerCek, info, aad);
    // Wait for genuine worker-side port closure, not a guessed scheduling delay.
    await Atomics.waitAsync(helper.closeState, 0, 0, 3000).value;
    assert.equal(Atomics.load(helper.closeState, 0), 1, "real HPKE worker must close its port");
    assert.ok(issued.worker.threadId >= 0,
      "test must terminate a real active Worker, not accept an already stopped fixture");
    let timer;
    const settled = await Promise.race([
      Reflect.apply(terminate, issued.worker, []).then(() => true, () => false),
      new Promise((resolve) => { timer = setTimeout(() => resolve(false), 3000); }),
    ]).finally(() => clearTimeout(timer));
    assert.equal(settled, true,
      "the real Worker.terminate() promise must settle despite the poisoned exit listener");
    assert.equal(onceSpyCalls, 0,
      "worker termination may never call callback-replaced EventEmitter.once");
    for (const key of ["on", "once", "emit"]) {
      const pinned = Object.getOwnPropertyDescriptor(issued.worker, key);
      assert.equal(pinned?.writable, false, `${key} must be pinned on the worker instance`);
      assert.equal(pinned?.configurable, false, `${key} must not be replaceable`);
    }
    opened = Buffer.from(await z.hpkeOpen({ recipientKey: pair.privateKey,
      enc: sealed.enc, ciphertext: sealed.ciphertext, info, aad }));
    assert.deepEqual(opened, ownerCek, "the actual HPKE result must still be intact");
  } finally {
    EventEmitter.prototype.once = savedOnce;
    if (issued) await Reflect.apply(terminate, issued.worker, []).catch(() => {});
    opened?.fill(0);
    ownerCek.fill(0);
  }
});

test("P1: callback-patched MessagePort.postMessage cannot read transferred owner CEK", async () => {
  const helper = privateSealHelpers();
  const pair = await z.hpkeSuite().kem.generateKeyPair();
  const pub = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(pair.publicKey));
  const info = Buffer.from("Root.ark/sharing/worker-messageport-p1/info\0");
  const aad = Buffer.from("Root.ark/sharing/worker-messageport-p1/aad\0");
  const realCek = crypto.randomBytes(32);
  const originalPostMessage = MessagePort.prototype.postMessage;
  const terminate = Worker.prototype.terminate;
  let messagesObserved = 0, exposedCek = false;
  let issued;
  try {
    // The trusted worker bootstrap is already complete before this callback
    // can poison the parent's global transport prototype.
    issued = helper.__newPrivateHpkeWorker();
    MessagePort.prototype.postMessage = function (value, ...args) {
      if (value && value.type === "seal") {
        messagesObserved++;
        if (value.cek instanceof ArrayBuffer
          && crypto.timingSafeEqual(Buffer.from(value.cek), realCek)) {
          exposedCek = true;
        }
      }
      return Reflect.apply(originalPostMessage, this, [value, ...args]);
    };
    const encrypted = await helper.__sealPrivateCekHpke(issued, pub, realCek, info, aad);
    // Restore the untrusted global immediately after the sensitive handoff;
    // verify an actual authenticated HPKE round-trip using the private key.
    MessagePort.prototype.postMessage = originalPostMessage;
    const opened = Buffer.from(await z.hpkeOpen({ recipientKey: pair.privateKey,
      enc: encrypted.enc, ciphertext: encrypted.ciphertext, info, aad }));
    try { assert.deepEqual(opened, realCek); }
    finally { opened.fill(0); }
    assert.equal(messagesObserved, 0,
      "no callback-replaced MessagePort prototype may receive the CEK payload");
    assert.equal(exposedCek, false, "raw CEK cannot escape to a parent MessagePort spy");
  } finally {
    MessagePort.prototype.postMessage = originalPostMessage;
    if (issued) await Reflect.apply(terminate, issued.worker, []).catch(() => {});
    realCek.fill(0);
  }
});

test("P1: poisoned pre-bootstrap MessagePort.on is denied before a worker can receive CEK", async () => {
  const helper = privateSealHelpers();
  const pair = await z.hpkeSuite().kem.generateKeyPair();
  const pub = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(pair.publicKey));
  const info = Buffer.from("Root.ark/sharing/worker-reply-forgery-p1/info\0");
  const aad = Buffer.from("Root.ark/sharing/worker-reply-forgery-p1/aad\0");
  const realCek = crypto.randomBytes(32);
  const attackerCek = crypto.randomBytes(32);
  const forged = await z.hpkeSeal({ recipientPublicKey: pair.publicKey,
    plaintext: attackerCek, info, aad });
  const originalOn = MessagePort.prototype.on;
  const terminate = Worker.prototype.terminate;
  let registeredHandlers = 0, injectedReplies = 0;
  let issued;
  try {
    MessagePort.prototype.on = function (kind, listener) {
      if (kind !== "message" || typeof listener !== "function")
        return Reflect.apply(originalOn, this, [kind, listener]);
      registeredHandlers++;
      return Reflect.apply(originalOn, this, [kind, function (payload, ...args) {
        if (payload && payload.ok === true && payload.ackMac) {
          injectedReplies++;
          return Reflect.apply(listener, this, [{ ...payload,
            enc: forged.enc, ciphertext: forged.ciphertext }, ...args]);
        }
        return Reflect.apply(listener, this, [payload, ...args]);
      }]);
    };
    assert.throws(() => { issued = helper.__newPrivateHpkeWorker(); },
      /ZK_OWNER_FILE_CEK_DENIED/,
      "worker bootstrap must fail closed if the callback replaced MessagePort.on");
    assert.equal(registeredHandlers, 0,
      "no attacker-controlled listener may run during a denied LOAD_SCRIPT bootstrap");
    assert.equal(injectedReplies, 0,
      "no attacker HPKE reply may reach a worker that was never created");
  } finally {
    MessagePort.prototype.on = originalOn;
    if (issued) await Reflect.apply(terminate, issued.worker, []).catch(() => {});
    realCek.fill(0);
    attackerCek.fill(0);
  }
});

test("P1: forged worker HPKE reply plus poisoned native HMAC binding cannot manufacture owner signature", async () => {
  const helper = privateSealHelpers();
  const pair = await z.hpkeSuite().kem.generateKeyPair();
  const pub = Buffer.from(await z.hpkeSuite().kem.serializePublicKey(pair.publicKey));
  const info = Buffer.from("Root.ark/sharing/worker-hmac-binding-p1/info\0");
  const aad = Buffer.from("Root.ark/sharing/worker-hmac-binding-p1/aad\0");
  const ownerCek = crypto.randomBytes(32);
  const attackCek = crypto.randomBytes(32);
  const forged = await z.hpkeSeal({ recipientPublicKey: pair.publicKey,
    plaintext: attackCek, info, aad });
  const fakeAck = crypto.randomBytes(32);
  const handleCarrier = crypto.createHmac("sha256", Buffer.alloc(32));
  const handleSymbol = Reflect.ownKeys(handleCarrier).find((key) =>
    typeof key === "symbol" && String(key) === "Symbol(kHandle)");
  assert.ok(handleSymbol, "Node22 HMAC test requires the genuine native binding handle");
  const nativeHandlePrototype = Object.getPrototypeOf(handleCarrier[handleSymbol]);
  const originalDigest = Object.getOwnPropertyDescriptor(nativeHandlePrototype, "digest");
  assert.ok(originalDigest && originalDigest.configurable);
  const terminate = Worker.prototype.terminate;
  let bindingSpyCalls = 0, issued;
  try {
    // A test-only injected response simulates compromised delivery EVEN
    // though the production Worker listeners are now prepared earlier.
    issued = helper.__newPrivateHpkeWorker();
    Object.defineProperty(nativeHandlePrototype, "digest", { ...originalDigest,
      value() { bindingSpyCalls++; return Buffer.from(fakeAck); } });
    const activeProbe = crypto.createHmac("sha256", Buffer.alloc(32)).update("oracle").digest();
    assert.deepEqual(activeProbe, fakeAck,
      "oracle must prove that an ordinary JS HMAC digest is callback-replaceable");
    bindingSpyCalls = 0;
    issued.reply = Promise.resolve({ ok: true, enc: forged.enc,
      ciphertext: forged.ciphertext, ackMac: Buffer.from(fakeAck) });
    await assert.rejects(helper.__sealPrivateCekHpke(issued, pub, ownerCek, info, aad),
      /ZK_OWNER_FILE_CEK_DENIED/,
      "a modified native HMAC binding cannot authenticate another CEK and induce owner signature");
    assert.equal(bindingSpyCalls, 0,
      "WebCrypto native HMAC verification must not call callback-poisoned Hmac binding.digest");
  } finally {
    Object.defineProperty(nativeHandlePrototype, "digest", originalDigest);
    if (issued) await Reflect.apply(terminate, issued.worker, []).catch(() => {});
    ownerCek.fill(0);
    attackCek.fill(0);
    fakeAck.fill(0);
  }
});

test("P1: LOAD_SCRIPT replacement via MessagePort.postMessage is denied before bootstrap", async () => {
  const helper = privateSealHelpers();
  const actualPost = MessagePort.prototype.postMessage;
  let replacedBoot = 0;
  try {
    // This is the actual Node22 worker bootstrap message, NOT merely the
    // later application-level {type:'seal'} message. A malicious callback
    // could swap it for attacker-controlled Worker eval code and steal CEK.
    MessagePort.prototype.postMessage = function (payload, ...args) {
      if (payload?.type === "loadScript") {
        replacedBoot++;
        return Reflect.apply(actualPost, this, [{ ...payload,
          filename: "globalThis.onmessage=()=>{};", doEval: "classic" }, ...args]);
      }
      return Reflect.apply(actualPost, this, [payload, ...args]);
    };
    assert.throws(() => helper.__newPrivateHpkeWorker(),
      /ZK_OWNER_FILE_CEK_DENIED/,
      "a tainted LOAD_SCRIPT transport must reject before creating any worker");
    assert.equal(replacedBoot, 0,
      "the compromised constructor method must never receive LOAD_SCRIPT");
  } finally {
    MessagePort.prototype.postMessage = actualPost;
  }
});

test("P1: callback MessagePort.on cannot reentrantly replace worker LOAD_SCRIPT after transport guard", async () => {
  const helper = privateSealHelpers();
  const actualOn = MessagePort.prototype.on;
  const actualPost = MessagePort.prototype.postMessage;
  let constructorOnCalls = 0, swappedBoots = 0;
  try {
    // A precheck only of postMessage is bypassable: on('message') occurs
    // earlier inside Node22 Worker constructor. Enforce pristine `.on` too.
    MessagePort.prototype.on = function (...args) {
      constructorOnCalls++;
      MessagePort.prototype.postMessage = function (payload, ...postArgs) {
        if (payload?.type === "loadScript") swappedBoots++;
        return Reflect.apply(actualPost, this, [payload, ...postArgs]);
      };
      return Reflect.apply(actualOn, this, args);
    };
    assert.throws(() => helper.__newPrivateHpkeWorker(),
      /ZK_OWNER_FILE_CEK_DENIED/,
      "a callback-controlled .on hook must not run inside the constructor");
    assert.equal(constructorOnCalls, 0, "no reentrant constructor hook may fire");
    assert.equal(swappedBoots, 0, "no bootstrap can be rewritten after a partial precheck");
  } finally {
    MessagePort.prototype.on = actualOn;
    MessagePort.prototype.postMessage = actualPost;
  }
});

test("P1: a poisoned WeakMap lookup cannot replace the prepared trusted CEK worker", async () => {
  const helper = privateSealHelpers();
  const reservation = helper.reserveOwnerHpkeWorker();
  const nativeGet = WeakMap.prototype.get;
  const nativeDelete = WeakMap.prototype.delete;
  let forgedLookups = 0, forgedDeletes = 0;
  try {
    // The reservation crosses an external authority callback. If its one-shot
    // lookup dispatches to the callback-replaced WeakMap.prototype.get, an
    // attacker can supply an entirely different real Worker to receive CEK.
    WeakMap.prototype.get = function (key) {
      if (key === reservation) { forgedLookups++; return { worker: {} }; }
      return Reflect.apply(nativeGet, this, [key]);
    };
    WeakMap.prototype.delete = function (key) {
      if (key === reservation) { forgedDeletes++; return true; }
      return Reflect.apply(nativeDelete, this, [key]);
    };
    await assert.rejects(helper.sealOwnerAuthorizedFileCek(null, reservation),
      /ZK_OWNER_FILE_CEK_DENIED/,
      "invalid owner input must deny while consuming the authentic reservation");
    assert.equal(forgedLookups, 0,
      "the owner must not dispatch its one-shot worker lookup to a patched WeakMap.get");
    assert.equal(forgedDeletes, 0,
      "the owner must consume its one-shot token through the pinned native delete");
  } finally {
    WeakMap.prototype.get = nativeGet;
    WeakMap.prototype.delete = nativeDelete;
    await helper.discardOwnerHpkeWorker(reservation);
  }
});
