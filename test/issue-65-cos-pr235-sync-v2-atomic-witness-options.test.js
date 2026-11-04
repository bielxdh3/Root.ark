"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { trustedAtomicBatchWitnessOptions,
  assertPinnedStrictLocalDeviceIdentity } = require("../sync-client/rootark-sync-v2");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

function trustedFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  return {
    pinnedPublicKey: keys.publicKey.export({ type: "spki", format: "der" }),
    scope: "alice:store",
    readback: async () => null,
  };
}

test("atomic witness accepts an independently pinned Ed25519 public KeyObject without reimport", () => {
  const pair = crypto.generateKeyPairSync("ed25519");
  const witness = { pinnedPublicKey: pair.publicKey,
    scope: "alice:store", readback: async () => null };
  const configured = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: witness }, true);
  const makeEngine = (atomicBatchWitnessPublicKey) => new SyncEngine({
    adapter: { push: async () => null, list: async () => [] },
    atomicBatchWitnessPublicKey,
  });
  assert.equal(makeEngine(configured.atomicBatchWitnessPublicKey).atomicBatchWitnessPublicKey,
    pair.publicKey);
  assert.equal(makeEngine(pair.publicKey.export({ type: "spki", format: "der" }))
    .atomicBatchWitnessPublicKey.asymmetricKeyType, "ed25519");
  assert.throws(() => makeEngine(crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048 }).publicKey), /must be an Ed25519 public key/);
});

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

test("strict Sync v2 checks owner-pinned local device identity before opening the engine", () => {
  const signing = crypto.generateKeyPairSync("ed25519");
  const pinnedDeviceSpki = signing.publicKey
    .export({ type: "spki", format: "der" }).toString("base64url");
  const policy = {
    username: "alice",
    trustedDevicePublicKeys: { "device-a": pinnedDeviceSpki },
    revokedDeviceIds: [],
  };
  const config = {
    username: "alice", deviceId: "device-a",
    publicKey: pinnedDeviceSpki, privateKey: signing.privateKey,
  };
  assert.equal(assertPinnedStrictLocalDeviceIdentity(config, policy), true);
  for (const altered of [
    { username: "mallory" },
    { deviceId: "other-device" },
    { publicKey: "locally-replaced-signing-key" },
    { deviceId: "__proto__" },
  ]) {
    assert.throws(() => assertPinnedStrictLocalDeviceIdentity(
      { ...config, ...altered }, policy), /externally pinned owner policy/);
  }
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity(config, {
    ...policy, revokedDeviceIds: ["device-a"],
  }), /externally pinned owner policy/);
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity(config, {
    ...policy,
    trustedDevicePublicKeys: Object.create({ "device-a": config.publicKey }),
  }), /externally pinned owner policy/,
  "inherited device entries are never trusted owner pins");
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity(config, {
    ...policy, username: "mallory",
  }), /externally pinned owner policy/);
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity({
    ...config, privateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  }, policy), /externally pinned owner policy/,
  "an attacker cannot supply the pinned public key with a different private key");
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity({
    ...config, privateKey: null,
  }, policy), /externally pinned owner policy/);
});
