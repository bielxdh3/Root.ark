"use strict";
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory,
  signOwnerRotation, verifyOwnerRotationKeys, spkiHash,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");
const { jsonStringify } = require("../src/crypto/rootark-zk10-native-intrinsics-v1");

const id = (n) => Buffer.alloc(16, n).toString("base64url");
const hex = (n) => Buffer.alloc(32, n).toString("hex");
const accountId = id(31);
function cutover(keypair, inventoryHead) {
  return signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1", immutable_account_id: accountId,
    zk_account_id: id(32), generation: 1, previous_cutover_digest: null,
    inventory_head: inventoryHead, complete_corpus: true,
    covered_compartments: [id(33)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted", migration_disposition: "closed",
    grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: Buffer.alloc(32, 34).toString("base64url"), issued_at: 1800000000,
  }, keypair.privateKey);
}

test("P2: native signed JSON array serializer ignores hostile String(index) remapping", () => {
  const A = crypto.generateKeyPairSync("ed25519");
  const ids = [id(40), id(41)];
  const statement = { schema: "owner-signed-test", covered_compartments: ids };
  const forged = { ...statement, covered_compartments: [ids[1], ids[0]] };
  const signBytes = (wire) => Buffer.from(jsonStringify(wire), "utf8");
  const signedBytesA = signBytes(statement);
  const signatureA = crypto.sign(null, signedBytesA, A.privateKey);
  assert.equal(crypto.verify(null, signBytes(statement), A.publicKey, signatureA), true);
  assert.equal(crypto.verify(null, signBytes(forged), A.publicKey, signatureA), false,
    "reversed array is not the genuine Ed25519-signed record");
  const kHandle = Object.getOwnPropertySymbols(A.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(kHandle);
  const rogueRoot = Object.create(A.publicKey);
  const originalString = global.String;
  let getterReads = 0;
  const poisoned = new Proxy(originalString, { apply(target, receiver, args) {
    if (args.length === 1 && args[0] === 0) return "1";
    if (args.length === 1 && args[0] === 1) return "0";
    return Reflect.apply(target, receiver, args);
  } });
  Object.defineProperty(rogueRoot, kHandle, { get() {
    getterReads++;
    global.String = poisoned;
    return A.publicKey[kHandle];
  } });
  try {
    const ownerKeys = verifyOwnerRotationKeys([], rogueRoot, accountId);
    assert.equal(ownerKeys.length, 1);
    assert.ok(getterReads > 0, "same-realm poison installed by actual KeyObject getter");
    assert.equal(global.String, poisoned);
    assert.equal(crypto.verify(null, signedBytesA, A.publicKey, signatureA), true);
    assert.equal(crypto.verify(null, signBytes(forged), A.publicKey, signatureA), false,
      "a reversed wire must never be reserialized as Ed25519-signed record A");
  } finally {
    global.String = originalString;
  }
});


test("P2: poisoned String must not erase signed root from a verified owner rotation", () => {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  const body = {
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: accountId,
    generation: 1, from_spki_sha256: spkiHash(A.publicKey),
    next_public_key: B.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    previous_rotation_digest: null,
  };
  const signedRotation = signOwnerRotation(body, A.privateKey, B.privateKey);
  const signedCutover = cutover(B, hex(51));
  const cutoverDigest = digestOwnerCutover(signedCutover);
  const nativeEquals = crypto.KeyObject.prototype.equals;
  const hasKey = (keys, publicKey) => keys.some((key) =>
    Reflect.apply(nativeEquals, key, [publicKey]));
  const control = verifyOwnerRotationKeys([signedRotation], A.publicKey, accountId);
  assert.equal(control.length, 2, "real owner A and rotated B must both be retained");
  assert.equal(hasKey(control, A.publicKey), true);
  assert.equal(hasKey(control, B.publicKey), true);
  assert.equal(verifyOwnerCutoverHistory([signedCutover], control, accountId).digest,
    cutoverDigest, "genuine B-signed cutover must verify");
  const kHandle = Object.getOwnPropertySymbols(A.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(kHandle, "actual Node Ed25519 KeyObject handle required");
  const hostileRoot = Object.create(A.publicKey);
  const originalString = global.String;
  let nativeGetterReads = 0, redirected = 0;
  const poisonedString = new Proxy(originalString, {
    apply(target, receiver, args) {
      if (args.length === 1 && args[0] === 1) {
        redirected++;
        return "0";
      }
      return Reflect.apply(target, receiver, args);
    },
  });
  Object.defineProperty(hostileRoot, kHandle, { get() {
    nativeGetterReads++;
    global.String = poisonedString;
    return A.publicKey[kHandle];
  } });
  try {
    const keys = verifyOwnerRotationKeys([signedRotation], hostileRoot, accountId);
    assert.ok(nativeGetterReads > 0, "genuine crypto KeyObject getter executed");
    assert.equal(global.String, poisonedString, "the real KeyObject getter poisoned the ambient realm");
    assert.equal(keys.length, 2, "rotated signer must append after owner root");
    assert.equal(hasKey(keys, A.publicKey), true,
      "old owner A must remain in trusted key set for independent signer check");
    assert.equal(hasKey(keys, B.publicKey), true);
    assert.equal(verifyOwnerCutoverHistory([signedCutover], keys, accountId).digest,
      cutoverDigest, "signed cutover remains valid after all signer pins retained");
  } finally {
    global.String = originalString;
  }
});

test("P2: a native owner kHandle getter cannot rebind JSON.stringify to verify A signature on B inventory", () => {
  const A = crypto.generateKeyPairSync("ed25519");
  const B = crypto.generateKeyPairSync("ed25519");
  const signedA = cutover(A, hex(51));
  const signedB = cutover(B, hex(52));
  const digestA = digestOwnerCutover(signedA);
  const digestB = digestOwnerCutover(signedB);
  assert.notEqual(digestA, digestB);
  assert.equal(verifyOwnerCutoverHistory([signedA], [A.publicKey], accountId).digest, digestA);
  assert.equal(verifyOwnerCutoverHistory([signedB], [B.publicKey], accountId).digest, digestB);
  const forgedB = Object.freeze({ ...signedB, signature: signedA.signature });
  assert.throws(() => verifyOwnerCutoverHistory([forgedB], [A.publicKey], accountId),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/, "B inventory and A signature are not valid together");

  const kHandle = Object.getOwnPropertySymbols(A.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(kHandle, "Node22 native KeyObject handle required");
  const rogue = Object.create(A.publicKey);
  const original = JSON.stringify;
  let getterReads = 0, forgedSerializations = 0;
  Object.defineProperty(rogue, kHandle, { get() {
    getterReads++;
    JSON.stringify = (value, ...args) => {
      if (value && value.type === signedB.type && value.inventory_head === signedB.inventory_head) {
        forgedSerializations++;
        return original({ ...value, inventory_head: signedA.inventory_head }, ...args);
      }
      return original(value, ...args);
    };
    return A.publicKey[kHandle];
  } });
  try {
    let outcome;
    try { outcome = verifyOwnerCutoverHistory([forgedB], [rogue], accountId); }
    catch (err) { assert.match(err.message, /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/); }
    assert.equal(getterReads > 0, true, "actual native kHandle getter must be exercised");
    assert.equal(outcome, undefined,
      "a legitimate signed A digest must never authenticate B's inventory_head");
    assert.equal(forgedSerializations, 0,
      "trusted wire encoder must not dispatch to JSON.stringify replaced after the getter");
  } finally { JSON.stringify = original; }

  const rotation = signOwnerRotation({
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: accountId,
    generation: 1, from_spki_sha256: spkiHash(A.publicKey),
    next_public_key: B.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    previous_rotation_digest: null,
  }, A.privateKey, B.privateKey);
  assert.equal(verifyOwnerRotationKeys([rotation], A.publicKey, accountId).length, 2,
    "genuine A to B owner rotation must remain valid");
});
