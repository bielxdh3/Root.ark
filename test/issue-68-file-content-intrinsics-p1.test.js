"use strict";

// Independent RED -> GREEN regression: the file-content module is imported
// BEFORE any adversarial owner/recipient callback mutates shared intrinsics.
// This exercises actual WebCrypto AES-GCM and @hpke, not cryptography mocks.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const content = require("../public/client/rootark-zk1-file-content");
const zk1 = require("../src/crypto/rootark-zk-1");

const id = byte => Buffer.alloc(16, byte).toString("base64url");
function metadata() {
  return {
    account_id: id(1), compartment_id: id(2), keyring_id: id(3),
    object_id: id(4), version_id: id(5), parent_version_id: null,
    epoch: 1, kind: "file",
  };
}
function overrideRng(value) {
  const engine = crypto.webcrypto;
  const own = Object.getOwnPropertyDescriptor(engine, "getRandomValues");
  Object.defineProperty(engine, "getRandomValues", {
    configurable: true, writable: true, value,
  });
  return () => {
    if (own) Object.defineProperty(engine, "getRandomValues", own);
    else delete engine.getRandomValues;
  };
}

test("P1: post-authority RNG interception never observes a newly generated raw file CEK", async () => {
  const engine = crypto.webcrypto;
  const actual = engine.getRandomValues;
  let calls = 0, observedKeyBytes = false;
  const replacement = function (target) {
    calls++;
    if (target.byteLength === 32) observedKeyBytes = true;
    return Reflect.apply(actual, engine, [target]); // real entropy, not a mock
  };
  const restore = overrideRng(replacement);
  try {
    // Prove the hostile replacement is installed and callable.
    engine.getRandomValues(new Uint8Array(1));
    assert.equal(calls, 1, "the test must actually install a callable RNG observer");
    calls = 0;
    const key = await content.generateFileCek();
    assert.equal(key.type, "secret");
    assert.equal(key.algorithm.name, "AES-GCM");
    assert.equal(key.algorithm.length, 256);
    assert.equal(key.extractable, false);
    assert.equal(observedKeyBytes, false, "authority code must not observe raw CEK bytes");
    assert.equal(calls, 0, "no post-load RNG method lookup may be dispatched");
  } finally {
    restore();
  }
});

test("P1: hostile RNG replacement cannot force 96-bit AES-GCM nonce reuse", async () => {
  const key = await content.generateFileCek();
  const context = metadata();
  let forcedCalls = 0;
  const restore = overrideRng(function (target) {
    forcedCalls++;
    target.fill(0x5a); // an untrusted callback can otherwise force nonce reuse
    return target;
  });
  try {
    const first = await content.encryptFile({
      cek: key, metadata: context, name: "nonce-one.txt",
      mediaType: "text/plain", data: Buffer.from("first authenticated file"),
    });
    const second = await content.encryptFile({
      cek: key, metadata: context, name: "nonce-two.txt",
      mediaType: "text/plain", data: Buffer.from("second authenticated file"),
    });
    const firstWire = JSON.parse(Buffer.from(first).toString("utf8"));
    const secondWire = JSON.parse(Buffer.from(second).toString("utf8"));
    assert.notEqual(firstWire.nonce, secondWire.nonce,
      "genuine independent native IVs must be used despite an installed RNG override");
    assert.equal(forcedCalls, 0,
      "AES-GCM nonce generation must never dispatch a callback-replaced RNG");
    const opened = await content.decryptFile({ cek: key, metadata: context, envelopeBytes: first });
    assert.deepEqual(Buffer.from(opened.data), Buffer.from("first authenticated file"));
    opened.data.fill(0);
  } finally {
    restore();
  }
});

test("P1: inherited toJSON cannot read authenticated plaintext through real HPKE and AES-GCM", async () => {
  const pair = await zk1.hpkeSuite().kem.generateKeyPair();
  const raw = crypto.randomBytes(32);
  const info = Buffer.from("Root.ark/zk-1/file-content-intrinsics-p1/info\0");
  const aad = Buffer.from("Root.ark/zk-1/file-content-intrinsics-p1/aad\0");
  const wrapped = await zk1.hpkeSeal({
    recipientPublicKey: pair.publicKey, plaintext: raw, info, aad,
  });
  const unwrapped = await zk1.hpkeOpen({
    recipientKey: pair.privateKey, enc: wrapped.enc, ciphertext: wrapped.ciphertext,
    info, aad,
  });
  assert.deepEqual(unwrapped, raw, "must complete genuine X25519 HPKE unwrap");
  const cek = await content.importFileCek(unwrapped);
  unwrapped.fill(0);
  raw.fill(0);
  const context = metadata();
  const originalPayload = Buffer.from("private plaintext marker: not for inherited toJSON");
  const privateB64 = originalPayload.toString("base64url");
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, "toJSON");
  let probeCalls = 0, observedPrivatePayload = false;
  let testingProbe = true;
  const hostile = function () {
    if (Object.hasOwn(this, "content") && this.content === privateB64) {
      if (testingProbe) probeCalls++;
      else observedPrivatePayload = true;
    }
    return this;
  };
  Object.defineProperty(Object.prototype, "toJSON", {
    configurable: true, value: hostile,
  });
  try {
    // Demonstrate the inherited hook would really observe a normal payload.
    JSON.stringify({ content: privateB64 });
    assert.equal(probeCalls, 1,
      "test must prove Object.prototype.toJSON is inherited and active");
    testingProbe = false;
    const sealed = await content.encryptFileWithParent({
      cek, metadata: context, name: "private.txt", mediaType: "text/plain",
      data: originalPayload, parentFolderId: id(9),
    });
    const opened = await content.decryptFile({
      cek, metadata: context, envelopeBytes: sealed,
    });
    assert.deepEqual(Buffer.from(opened.data), originalPayload,
      "real file AEAD must still round-trip exact private bytes");
    assert.equal(opened.parentFolderId, id(9));
    assert.equal(observedPrivatePayload, false,
      "inherited JSON serialization hooks must never see authenticated plaintext");
    opened.data.fill(0);
  } finally {
    if (previous) Object.defineProperty(Object.prototype, "toJSON", previous);
    else delete Object.prototype.toJSON;
  }
});
