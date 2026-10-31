"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { trustedAtomicBatchWitnessOptions,
  assertPinnedStrictLocalDeviceIdentity } = require("../sync-client/rootark-sync-v2");
const DENIED_UNTRUSTED_WITNESS = /(?:independently pinned readback and external CAS floor|immutable canonical owner authority options)/;

function trustedFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const casKeys = crypto.generateKeyPairSync("ed25519");
  return {
    pinnedPublicKey: keys.publicKey.export({ type: "spki", format: "der" }),
    scope: "alice:store",
    ownerIdentity: {
      accountId: "ca628a48-765e-4b0d-a746-3bc67d53e3b1",
      storeId: "d95a7868-857c-4213-a5ad-3c10374b4fa7",
      username: "alice", compartmentId: "private",
    },
    readback: async () => null,
    casPinnedPublicKey: casKeys.publicKey.export({ type: "spki", format: "der" }),
    casReadback: async () => null,
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
  }, false), DENIED_UNTRUSTED_WITNESS);
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: null,
  }, true), DENIED_UNTRUSTED_WITNESS);
});

test("external atomic witness requires a complete independent key, scope and readback", () => {
  for (const changed of [
    { readback: null }, { pinnedPublicKey: null }, { scope: "../unsafe" },
    { scope: "alice:store", remotePhysicalDurable: true },
    { casReadback: null }, { casPinnedPublicKey: null },
    { ownerIdentity: null },
    { ownerIdentity: { ...trustedFixture().ownerIdentity, storeId: "not-a-uuid" } },
    { ownerIdentity: { ...trustedFixture().ownerIdentity, accountId: "not-a-uuid" } },
    { ownerIdentity: { ...trustedFixture().ownerIdentity, extra: true } },
  ]) {
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: { ...trustedFixture(), ...changed },
    }, true), DENIED_UNTRUSTED_WITNESS);
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
  trusted.casReadback = async (challenge) => {
    received = challenge;
    return null;
  };
  const opts = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted },
    true, { username: "alice" }, "private");
  const pinnedCopy = Buffer.from(opts.atomicBatchWitnessPublicKey);
  const casPinnedCopy = Buffer.from(opts.atomicBatchCasFloorPublicKey);
  trusted.pinnedPublicKey.fill(0);
  trusted.casPinnedPublicKey.fill(0);
  assert.deepEqual(opts.atomicBatchWitnessPublicKey, pinnedCopy);
  assert.deepEqual(opts.atomicBatchCasFloorPublicKey, casPinnedCopy);
  assert.equal(opts.atomicBatchWitnessScope, "alice:store");
  assert.equal(Object.isFrozen(opts.atomicBatchOwnerIdentity), true);
  assert.equal(opts.atomicBatchOwnerIdentity.accountId,
    "ca628a48-765e-4b0d-a746-3bc67d53e3b1");
  trusted.ownerIdentity.storeId = "ad112afc-ff8e-4803-9f5c-b517cc778588";
  assert.equal(opts.atomicBatchOwnerIdentity.storeId,
    "d95a7868-857c-4213-a5ad-3c10374b4fa7");
  const challenge = {
    scope: "alice:store", accountId: opts.atomicBatchOwnerIdentity.accountId,
    storeId: opts.atomicBatchOwnerIdentity.storeId, nonce: "challenge-nonce",
    operationIds: ["delete-id", "move-id"],
    envelopeDigests: ["delete-digest", "move-digest"],
  };
  await opts.atomicBatchWitnessReadback(challenge);
  assert.deepEqual(challenge.operationIds, ["delete-id", "move-id"]);
  assert.deepEqual(challenge.envelopeDigests, ["delete-digest", "move-digest"]);
  assert.equal(received.nonce, challenge.nonce);
  const floorChallenge = {
    scope: "alice:store", accountId: opts.atomicBatchOwnerIdentity.accountId,
    storeId: opts.atomicBatchOwnerIdentity.storeId,
    nonce: "second-nonce", commitId: "commit-1",
    storeHeadSha256: "a".repeat(64), fencingEpoch: 3,
  };
  await opts.atomicBatchCasFloorReadback(floorChallenge);
  assert.deepEqual(received, floorChallenge);
});

test("external atomic witness rejects owner or compartment mismatches from trusted local policy", () => {
  const trusted = trustedFixture();
  assert.throws(() => trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted },
    true, { username: "mallory" }, "private"), /external CAS floor/);
  assert.throws(() => trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted },
    true, { username: "alice" }, "other-compartment"), /external CAS floor/);
  assert.deepEqual(trustedAtomicBatchWitnessOptions({}, true,
    { username: "alice" }, "private"), {});
});

test("trusted atomic witness rejects getter authority swaps before construction", () => {
  for (const key of ["scope", "pinnedPublicKey", "casPinnedPublicKey",
    "readback", "casReadback", "ownerIdentity"]) {
    const supplied = trustedFixture();
    Object.defineProperty(supplied, key, {
      enumerable: true, configurable: true,
      get: () => { throw new Error("SHOULD_NOT_READ_ACCESSOR"); },
    });
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: supplied,
    }, true), /immutable canonical owner authority options/);
  }
});

test("trusted atomic witness captures one Proxy descriptor snapshot, not mutable get traps", () => {
  const original = trustedFixture();
  let getTraps = 0;
  const supplied = new Proxy(original, {
    get(target, prop, receiver) {
      getTraps++;
      if (prop === "scope") return "mallory:store";
      if (prop === "readback") return async () => { throw Error("SWAPPED_CALLBACK"); };
      return Reflect.get(target, prop, receiver);
    },
  });
  const opts = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: supplied }, true);
  assert.equal(getTraps, 0, "capture must use only own property descriptors");
  assert.equal(opts.atomicBatchWitnessScope, "alice:store");
  assert.equal(opts.atomicBatchOwnerIdentity.username, "alice");
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
