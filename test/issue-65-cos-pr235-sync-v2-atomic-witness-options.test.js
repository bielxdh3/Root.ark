"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { trustedAtomicBatchWitnessOptions } = require("../sync-client/rootark-sync-v2");

function trustedFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  return {
    pinnedPublicKey: keys.publicKey.export({ type: "spki", format: "der" }),
    scope: "alice:store",
    readback: async () => null,
  };
}

test("standalone Sync v2 keeps remote atomic witness disabled without external injection", () => {
  assert.deepEqual(trustedAtomicBatchWitnessOptions({}, false), {});
  assert.deepEqual(trustedAtomicBatchWitnessOptions({}, true), {});
});

test("config-only or legacy admission cannot enable the atomic batch witness", () => {
  const trusted = trustedFixture();
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: trusted,
  }, false), /strict externally pinned readback/);
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: null,
  }, true), /strict externally pinned readback/);
});

test("external atomic witness requires a complete independent key, scope and readback", () => {
  for (const changed of [
    { readback: null }, { pinnedPublicKey: null }, { scope: "../unsafe" },
    { scope: "alice:store", remotePhysicalDurable: true },
  ]) {
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: { ...trustedFixture(), ...changed },
    }, true), /strict externally pinned readback/);
  }
});

test("trusted batch witness snapshots owner key and keeps challenge arrays isolated", async () => {
  const trusted = trustedFixture();
  let received;
  trusted.readback = async (challenge) => {
    received = challenge;
    challenge.operationIds[0] = "ATTACKER_REPLACED";
    challenge.envelopeDigests[0] = "BAD_DIGEST";
    return null;
  };
  const opts = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted }, true);
  const pinnedCopy = Buffer.from(opts.atomicBatchWitnessPublicKey);
  trusted.pinnedPublicKey.fill(0);
  assert.deepEqual(opts.atomicBatchWitnessPublicKey, pinnedCopy);
  assert.equal(opts.atomicBatchWitnessScope, "alice:store");
  const challenge = {
    scope: "alice:store", nonce: "challenge-nonce",
    operationIds: ["delete-id", "move-id"],
    envelopeDigests: ["delete-digest", "move-digest"],
  };
  await opts.atomicBatchWitnessReadback(challenge);
  assert.deepEqual(challenge.operationIds, ["delete-id", "move-id"]);
  assert.deepEqual(challenge.envelopeDigests, ["delete-digest", "move-digest"]);
  assert.equal(received.nonce, challenge.nonce);
});
