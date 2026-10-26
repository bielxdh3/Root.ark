"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const h = require("../src/crypto/rootark-zk-recovery-history-v2");
const fixtures = require("./support/issue-65-recovery-v2-fixtures");
const { verifyWitnessHeadMatchesSignedHistoryV1 } =
  require("../src/crypto/rootark-zk-witness-history-consistency-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
async function setup() {
  const state = await fixtures.createInitialState(1);
  const verified = await h.verifyRecoveryHistoryPublicV2({
    expectedScope: state.scope, baseManifest: state.baseManifest,
    baseReceipt: state.baseReceipt, pinnedWitness: state.pinnedWitness,
    transitions: [], packageEnvelopes: [], now: 100_000,
  });
  const signing = crypto.generateKeyPairSync("ed25519");
  const keyId = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(32);
  const scope = {
    account_id: Buffer.from(state.scope.account_id),
    compartment_id: Buffer.from(state.scope.compartment_id),
    keyring_id: Buffer.from(state.scope.keyring_id),
  };
  const unsigned = {
    type: "rootark-recovery-witness-head/v1",
    witness_key_id: keyId,
    ...scope,
    current_revision: verified.revision,
    current_manifest_digest: Buffer.from(verified.headDigest),
    witness_sequence: verified.revision,
    nonce, observed_at: 1100,
    status: "committed", pending_reservation_id: null,
  };
  const context = {
    verifiedPublicHistory: verified,
    pinned: { keyId, publicKey: signing.publicKey },
    scope, nonce,
    minimumHead: {
      revision: verified.revision,
      digest: Buffer.from(verified.headDigest),
      witnessSequence: verified.revision,
    },
  };
  async function encode(input = unsigned) {
    const signature = crypto.sign(null, Buffer.concat([
      DOMAIN, await z.encodeDeterministic(input),
    ]), signing.privateKey);
    return z.encodeDeterministic({ ...input, signature });
  }
  return { context, unsigned, encode };
}

test("signed independent nonce-bound witness must report the exact verified keyring head", async () => {
  const f = await setup();
  const result = await verifyWitnessHeadMatchesSignedHistoryV1({
    ...f.context, raw: await f.encode(),
  });
  assert.equal(result.verifiedConsistentHead, true);
  assert.equal(result.revision, 1);
  assert.equal(result.authorizesRecovery, false);
  assert.equal(result.authorizesProtectedIo, false);
  assert.equal(Object.isFrozen(result), true);
});

test("validly signed but different digest, revision, scope or nonce cannot match a signed history", async () => {
  const f = await setup();
  for (const mutate of [
    { current_manifest_digest: crypto.randomBytes(32) },
    { current_revision: 2, witness_sequence: 2 },
    { account_id: crypto.randomBytes(16) },
    { nonce: crypto.randomBytes(32) },
  ]) {
    await assert.rejects(verifyWitnessHeadMatchesSignedHistoryV1({
      ...f.context, raw: await f.encode({ ...f.unsigned, ...mutate }),
    }), /WITNESS_HISTORY_MISMATCH|WITNESS_HEAD_UNACCEPTABLE/);
  }
});

test("caller-constructed history and a substituted witness identity fail closed", async () => {
  const f = await setup();
  const raw = await f.encode();
  await assert.rejects(verifyWitnessHeadMatchesSignedHistoryV1({
    ...f.context, verifiedPublicHistory: { ...f.context.verifiedPublicHistory }, raw,
  }), /WITNESS_HISTORY_MISMATCH/);
  await assert.rejects(verifyWitnessHeadMatchesSignedHistoryV1({
    ...f.context, pinned: { ...f.context.pinned,
      publicKey: crypto.generateKeyPairSync("ed25519").publicKey }, raw,
  }), /WITNESS_HISTORY_MISMATCH|WITNESS_HEAD_UNACCEPTABLE/);
  await assert.rejects(verifyWitnessHeadMatchesSignedHistoryV1({
    ...f.context, minimumHead: null, raw,
  }));
});

test("independently supplied wire, challenge, witness ID, scope and floor are captured before any await", async () => {
  const f = await setup();
  const correctRaw = Buffer.from(await f.encode());
  const cases = [
    { name: "raw", original: correctRaw,
      override: (wrong) => ({ raw: wrong }) },
    { name: "nonce", original: f.context.nonce,
      override: (wrong) => ({ raw: correctRaw, nonce: wrong }) },
    { name: "keyId", original: f.context.pinned.keyId,
      override: (wrong) => ({ raw: correctRaw, pinned: {
        ...f.context.pinned, keyId: wrong,
      } }) },
    { name: "account", original: f.context.scope.account_id,
      override: (wrong) => ({ raw: correctRaw, scope: {
        ...f.context.scope, account_id: wrong,
      } }) },
    { name: "floor", original: f.context.minimumHead.digest,
      override: (wrong) => ({ raw: correctRaw, minimumHead: {
        ...f.context.minimumHead, digest: wrong,
      } }) },
  ];
  for (const scenario of cases) {
    const wrong = Buffer.from(scenario.original);
    wrong[0] ^= 0xff;
    const checking = verifyWitnessHeadMatchesSignedHistoryV1({
      ...f.context, ...scenario.override(wrong),
    });
    queueMicrotask(() => wrong.set(scenario.original));
    await assert.rejects(checking, /WITNESS_HISTORY_MISMATCH/,
      scenario.name + " was substituted after invocation");
  }
});
