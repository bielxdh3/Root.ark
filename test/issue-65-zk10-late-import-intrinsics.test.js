"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");

// Import the trusted cutover verifier FIRST. The attack happens only later,
// through a genuine KeyObject's inherited native-handle getter, before a
// different DEV-OFF crypto module is lazily imported. A test that eagerly
// imports both modules would miss this inter-module snapshot poisoning.
const { spkiHash } = require("../src/crypto/rootark-zk10-account-cutover-v1");
const issuerModulePath = require.resolve("../src/crypto/rootark-zk10-independent-issuer-bridge-v1");

const id = (v) => Buffer.alloc(16, v).toString("base64url");
const hex = (v) => Buffer.alloc(32, v).toString("hex");
const nonce = (v) => Buffer.alloc(32, v).toString("base64url");
const DOMAIN = Buffer.from("Root.ark/zk10/independent-issuer-provisioning/v1\0", "ascii");

test("P2: late issuer module must reuse native hash/sign methods pinned before hostile owner getter", () => {
  assert.equal(require.cache[issuerModulePath], undefined,
    "issuer must genuinely be loaded only AFTER the adversarial getter");
  const owner = crypto.generateKeyPairSync("ed25519");
  const issuer = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const bodyA = {
    type: "rootark-zk10-independent-issuer-provisioning/v1",
    immutable_account_id: id(11), zk_account_id: id(12),
    owner_root_spki: owner.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    owner_generation: 1, owner_cutover_digest: hex(13), inventory_head: hex(14),
    object_id: id(15), object_revision: 2, ciphertext_sha256: hex(16),
    grant: "protected_enforced", complete_corpus: true, nonce: nonce(17),
  };
  const bodyB = { ...bodyA, nonce: nonce(18) };
  const signedMessage = (body) => Buffer.concat([DOMAIN,
    Buffer.from(JSON.stringify(body), "utf8")]);
  const signedABytes = signedMessage(bodyA);
  const signedBBytes = signedMessage(bodyB);
  const signatureA = crypto.sign(null, signedABytes, issuer.privateKey);
  const signatureB = crypto.sign(null, signedBBytes, issuer.privateKey);
  assert.equal(crypto.verify(null, signedABytes, issuer.publicKey, signatureA), true);
  assert.equal(crypto.verify(null, signedBBytes, issuer.publicKey, signatureB), true);
  const hash = (payload, signature) => crypto.createHash("sha256")
    .update(payload).update(signature).digest("hex");
  const digestA = hash(signedABytes, signatureA);
  const digestB = hash(signedBBytes, signatureB);
  assert.notEqual(digestA, digestB);
  const wireA = Object.freeze({ ...bodyA, signature: signatureA.toString("base64url") });

  const prototype = Object.getPrototypeOf(crypto.createHash("sha256"));
  const originalHashDigest = Object.getOwnPropertyDescriptor(prototype, "digest");
  const originalSign = crypto.sign;
  const originalVerify = crypto.verify;
  const ownerHandleSymbol = Object.getOwnPropertySymbols(owner.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(ownerHandleSymbol);
  const inherited = Object.create(owner.publicKey);
  let hostileGetterReads = 0;
  let interceptedDigestCalls = 0;
  let interceptedSignCalls = 0;
  Object.defineProperty(inherited, ownerHandleSymbol, { get() {
    hostileGetterReads += 1;
    Object.defineProperty(prototype, "digest", {
      ...originalHashDigest, value: function forgedDigest(encoding) {
        const actual = originalHashDigest.value.call(this, encoding);
        if (actual === digestA) {
          interceptedDigestCalls += 1;
          return digestB;
        }
        return actual;
      },
    });
    crypto.sign = (_alg, message) => {
      interceptedSignCalls += 1;
      return originalSign(null, message, attacker.privateKey);
    };
    // A late module that binds crypto.verify will be poisoned, too; the
    // genuine signature control below uses the saved original verifier.
    crypto.verify = () => true;
    return owner.publicKey[ownerHandleSymbol];
  } });
  try {
    const expectedOwnerSpki = spkiHash(owner.publicKey);
    assert.equal(spkiHash(inherited), expectedOwnerSpki,
      "early trusted module still binds the genuine Ed25519 public key");
    assert.ok(hostileGetterReads > 0);
    assert.equal(require.cache[issuerModulePath], undefined,
      "the malicious getter must poison the realm before the issuer module loads");
    const late = require("../src/crypto/rootark-zk10-independent-issuer-bridge-v1");
    const observedDigest = late.digestIssuerProvisioning(wireA);
    assert.equal(observedDigest, digestA,
      "signed issuer A must never be retargeted to independently pinned B");
    assert.equal(interceptedDigestCalls, 0,
      "late issuer must not snapshot a poisoned Hash.prototype.digest");
    const generated = late.signIssuerProvisioning(bodyA, issuer.privateKey);
    assert.equal(originalVerify(null, signedABytes, issuer.publicKey,
      Buffer.from(generated.signature, "base64url")), true,
    "late issuer must not sign with an attacker-rebound JS crypto.sign");
    assert.equal(interceptedSignCalls, 0,
      "late issuer must reuse the genuine earlier native sign intrinsic");
  } finally {
    Object.defineProperty(prototype, "digest", originalHashDigest);
    crypto.sign = originalSign;
    crypto.verify = originalVerify;
  }
});
