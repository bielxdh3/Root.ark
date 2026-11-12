"use strict";

// Real disposable owner/inventory Ed25519 signature with a hostile same-realm
// native KeyObject handle. No persisted or production authority is involved.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");

test("P2 inventory: signed object A must not make requested B PRESENT via post-key Buffer.compare", async () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const signerKeyId = Buffer.alloc(16, 71);
  const scope = { account_id: Buffer.alloc(16, 72),
    compartment_id: Buffer.from("inventory-same-realm"),
    keyring_id: Buffer.alloc(16, 73) };
  const requestedA = { object_id: Buffer.alloc(16, 74),
    revision: 1, epoch: 1, ciphertext_sha256: Buffer.alloc(32, 75) };
  const requestedB = { ...requestedA, object_id: Buffer.alloc(16, 76) };
  const previousRoot = Buffer.alloc(32, 77);
  const nonce = Buffer.alloc(32, 78);
  const signedRoot = await inventory.computeRoot(scope, 1, previousRoot, [requestedA]);
  const serialized = await inventory.createSignedSnapshot({
    signerKeyId, privateKey: signer.privateKey, scope, sequence: 1,
    previousRoot, entries: [requestedA], nonce,
  });
  const args = (pin, requested) => ({
    serialized, pinnedPublicKey: pin, pinnedSignerKeyId: signerKeyId,
    expectedScope: scope, requested, minimumHead: { sequence: 1, root: signedRoot },
    nonce,
  });
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedA))).outcome,
    "PRESENT", "real owner-signed entry A accepted");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedB))).outcome,
    "ABSENT", "unlisted object B absent with original comparisons");

  const handle = Object.getOwnPropertySymbols(signer.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node22 real native Ed25519 key handle");
  const poisonedPin = Object.create(signer.publicKey);
  const originalCompare = Buffer.compare;
  let getterReads = 0;
  let substitutions = 0;
  Object.defineProperty(poisonedPin, handle, { get() {
    getterReads += 1;
    Buffer.compare = function(left, right) {
      if (Buffer.isBuffer(left) && Buffer.isBuffer(right)
        && left.equals(requestedA.object_id) && right.equals(requestedB.object_id)) {
        substitutions += 1;
        return 0;
      }
      return Reflect.apply(originalCompare, Buffer, [left, right]);
    };
    return signer.publicKey[handle];
  } });
  try {
    assert.equal((await inventory.verifySnapshot(args(poisonedPin, requestedB))).outcome,
      "ABSENT", "valid signature for A must not authorize unlisted object B");
  } finally { Buffer.compare = originalCompare; }
  assert.ok(getterReads > 0, "product verification must invoke hostile inherited kHandle");
  assert.equal(substitutions, 0, "lookup must retain early native buffer comparator");
  assert.equal((await inventory.verifySnapshot(args(signer.publicKey, requestedA))).outcome,
    "PRESENT", "valid real Ed25519 owner remains accepted after the attack");
});
