"use strict";

// Genuine Ed25519 terminal A; attacker supplies a different canonical wire B.
// The owner-controlled KeyObject getter must not retarget codec input bytes.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const z = require("../src/crypto/rootark-zk-1");

test("terminal Ed25519 A must never authorize forged raw B by poisoned decoder Buffer.from", async () => {
  const pair = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("terminal-w20"), keyring_id: crypto.randomBytes(16) };
  const signerKeyId = crypto.randomBytes(16);
  const operation = { operation_id: crypto.randomBytes(16),
    expected_sequence: 0, expected_root: crypto.randomBytes(32),
    object_id: crypto.randomBytes(16), revision: 1, epoch: 1,
    ciphertext_sha256: crypto.randomBytes(32) };
  const observedRoot = crypto.randomBytes(32);
  assert.notDeepEqual(observedRoot, operation.expected_root);
  const signedA = await inventory.createTerminalProof({
    signerKeyId, privateKey: pair.privateKey, scope, operation,
    observedSequence: 0, observedRoot, priorRevision: 0, priorEpoch: 0,
    reason: "EXPECTED_HEAD_CHANGED", blockingOperationId: null,
  });
  const decodedA = await z.decodeDeterministic(signedA);
  const rawB = await z.encodeDeterministic({
    ...decodedA, observed_root: crypto.randomBytes(32),
  });
  assert.notDeepEqual(rawB, signedA, "A and B must differ");
  assert.equal(rawB.length, signedA.length,
    "attacker must not rely on a malformed-length rejection");
  const args = (key, serialized) => ({ serialized,
    pinnedPublicKey: key, pinnedSignerKeyId: signerKeyId,
    expectedScope: scope, operation });
  const originalBufferFrom = Buffer.from;
  const nativeCompare = Buffer.compare.bind(Buffer);
  assert.equal((await inventory.verifyTerminalProof(args(pair.publicKey, signedA)))
    .outcome, "NOT_COMMITTED_FINAL", "real A must pass");
  await assert.rejects(inventory.verifyTerminalProof(args(pair.publicKey, rawB)),
    { code: "INVENTORY_SIGNATURE" }, "forged B must fail even without attacker getter");

  const pinned = crypto.createPublicKey({
    key: pair.publicKey.export({ type: "spki", format: "der" }),
    type: "spki", format: "der",
  });
  let getterCalls = 0, decoderPoisonCalls = 0;
  Object.defineProperty(pinned, "type", { configurable: true, get() {
    getterCalls++;
    Buffer.from = function(value, ...rest) {
      if (Buffer.isBuffer(value) && value.length === rawB.length
        && nativeCompare(value, rawB) === 0) {
        decoderPoisonCalls++;
        return originalBufferFrom(signedA);
      }
      return Reflect.apply(originalBufferFrom, Buffer, [value, ...rest]);
    };
    return "public";
  } });
  try {
    await assert.rejects(inventory.verifyTerminalProof(args(pinned, rawB)),
      { code: "INVENTORY_SIGNATURE" },
      "B must be bound to its received canonical bytes before Ed25519 is trusted");
  } finally {
    Buffer.from = originalBufferFrom;
    delete pinned.type;
  }
  assert.ok(getterCalls > 0, "genuine Node22 KeyObject.type getter must run");
  assert.equal(decoderPoisonCalls, 0,
    "pinned input copy must never invoke replaced Buffer.from");
  assert.equal((await inventory.verifyTerminalProof(args(pair.publicKey, signedA)))
    .reason, "EXPECTED_HEAD_CHANGED", "A positive preserved after poisoning");
});
