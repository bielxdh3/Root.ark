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

function privateSealHelpers() {
  const location = path.resolve(__dirname,
    "../src/crypto/rootark-zk1-owner-authorized-file-cek-transfer.js");
  const source = fs.readFileSync(location, "utf8");
  const marker = "module.exports = { sealOwnerAuthorizedFileCek,";
  assert.ok(source.includes(marker));
  const injected = new Module(location, module);
  injected.filename = location;
  injected.paths = Module._nodeModulePaths(path.dirname(location));
  injected._compile(source.replace(marker,
    "module.exports = { __newPrivateHpkeWorker: newPrivateHpkeWorker, "
      + "__sealPrivateCekHpke: sealPrivateCekHpke, sealOwnerAuthorizedFileCek,"), location);
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
    // Installed exactly where an untrusted authority callback can poison the
    // caller's global prototype. The native Worker method delegates through
    // private MessagePorts, so capturing only Worker.postMessage is unsafe.
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
    issued = helper.__newPrivateHpkeWorker();
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

test("P1: forged valid HPKE reply through MessagePort.on fails authentication before owner signing", async () => {
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
    issued = helper.__newPrivateHpkeWorker();
    await assert.rejects(helper.__sealPrivateCekHpke(issued, pub, realCek, info, aad),
      /ZK_OWNER_FILE_CEK_DENIED/,
      "callback-forged HPKE ciphertext must not receive a valid owner signature");
    assert.ok(registeredHandlers > 0,
      "the patched native transport listener must be exercised");
    assert.ok(injectedReplies > 0,
      "the test must substitute a REAL attacker-key HPKE reply");
  } finally {
    MessagePort.prototype.on = originalOn;
    if (issued) await Reflect.apply(terminate, issued.worker, []).catch(() => {});
    realCek.fill(0);
    attackerCek.fill(0);
  }
});
