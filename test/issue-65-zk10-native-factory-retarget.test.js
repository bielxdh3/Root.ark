"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const {
  spkiHash, signatureBytes, verifyOwnerRotationKeys,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const DOMAIN_ROTATION = Buffer.from("Root.ark/zk10/owner-rotation/v1\0");
const id = (value) => Buffer.alloc(16, value).toString("base64url");

function rotation(ownerA, advertisedB, signerB) {
  const statement = {
    type: "rootark-zk10-owner-rotation/v1",
    immutable_account_id: id(1), generation: 1,
    from_spki_sha256: spkiHash(ownerA.publicKey),
    next_public_key: advertisedB.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    previous_rotation_digest: null,
  };
  const encoded = signatureBytes(DOMAIN_ROTATION, statement);
  return { ...statement,
    signature_from: crypto.sign(null, encoded, ownerA.privateKey).toString("base64url"),
    signature_next: crypto.sign(null, encoded, signerB.privateKey).toString("base64url") };
}

test("P2: native owner rotation cannot use a dynamically rebound JS public-key factory", () => {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  assert.notEqual(spkiHash(A.publicKey), spkiHash(B.publicKey));
  const correct = rotation(A, B, B);
  const validKeys = verifyOwnerRotationKeys([correct], A.publicKey, id(1));
  assert.equal(validKeys.length, 2);
  assert.equal(spkiHash(validKeys[1]), spkiHash(B.publicKey));

  const forged = rotation(A, B, A);
  assert.throws(() => verifyOwnerRotationKeys([forged], A.publicKey, id(1)),
    { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
    "without mutable caller code, signature_next by A cannot approve advertised B");

  const nativeCreatePublicKey = crypto.createPublicKey;
  const fakeRoot = Object.create(A.publicKey);
  const sym = Object.getOwnPropertySymbols(A.publicKey)
    .find((symbol) => String(symbol) === "Symbol(kHandle)");
  assert.ok(sym, "real native Ed25519 KeyObject exposes original kHandle");
  let getterCalls = 0, retargetCalls = 0;
  Object.defineProperty(fakeRoot, sym, { configurable: true, get() {
    getterCalls += 1;
    crypto.createPublicKey = (arg) => {
      retargetCalls += 1;
      const requested = arg?.key;
      if (Buffer.isBuffer(requested) && requested.equals(
        B.publicKey.export({ type: "spki", format: "der" }))) {
        return A.publicKey;
      }
      return nativeCreatePublicKey(arg);
    };
    return A.publicKey[sym];
  } });
  try {
    assert.throws(() => verifyOwnerRotationKeys([forged], fakeRoot, id(1)),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "a getter must not turn claimed B into actually verified A");
    assert.ok(getterCalls > 0, "attack must execute real caller-owned handle getter");
    assert.notEqual(crypto.createPublicKey, nativeCreatePublicKey,
      "the caller executed its hostile global-factory replacement");
    assert.equal(retargetCalls, 0,
      "the verifier must never consume the injected JS factory");
  } finally {
    crypto.createPublicKey = nativeCreatePublicKey;
  }
});

test("P2: inherited kHandle getter cannot replace native Ed25519 verification", () => {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  const bad = rotation(A, B, A);
  const handleSymbol = Object.getOwnPropertySymbols(A.publicKey)
    .find((symbol) => String(symbol) === "Symbol(kHandle)");
  assert.ok(handleSymbol);
  const poisoned = Object.create(A.publicKey);
  const nativeVerify = crypto.verify;
  let getterCalls = 0, fakeVerifyCalls = 0;
  Object.defineProperty(poisoned, handleSymbol, { get() {
    getterCalls += 1;
    crypto.verify = () => { fakeVerifyCalls += 1; return true; };
    return A.publicKey[handleSymbol];
  } });
  try {
    assert.throws(() => verifyOwnerRotationKeys([bad], poisoned, id(1)),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "caller must not approve an unowned next signer by swapping crypto.verify");
    assert.ok(getterCalls > 0, "real caller-owned KeyObject getter was exercised");
    assert.notEqual(crypto.verify, nativeVerify, "the hostile verifier override was installed");
    assert.equal(fakeVerifyCalls, 0, "no injected JS verify implementation may be used");
  } finally {
    crypto.verify = nativeVerify;
  }
});
