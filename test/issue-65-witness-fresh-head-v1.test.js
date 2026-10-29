"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { inspectVerifiedWitnessFreshHeadV1 } = require("../src/crypto/rootark-zk-witness-head-wire-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
function fixture() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const keyId = Buffer.alloc(16, 0x11);
  const scope = {
    account_id: Buffer.alloc(16, 0x12),
    compartment_id: Buffer.from("compartment", "ascii"),
    keyring_id: Buffer.alloc(16, 0x13),
  };
  const nonce = Buffer.alloc(32, 0x14);
  const head = {
    type: "rootark-recovery-witness-head/v1", witness_key_id: keyId, ...scope,
    current_revision: 2, current_manifest_digest: Buffer.alloc(32, 0x15),
    witness_sequence: 2, nonce, observed_at: 1760000000,
    status: "committed", pending_reservation_id: null,
  };
  const context = { pinned: { keyId, publicKey }, scope, nonce,
    minimumHead: { revision: 2, digest: head.current_manifest_digest, witnessSequence: 2 } };
  async function sign(data = head, domain = DOMAIN) {
    return z.encodeDeterministic({
      ...data,
      signature: crypto.sign(null, Buffer.concat([
        domain, await z.encodeDeterministic(data),
      ]), privateKey),
    });
  }
  return { head, context, sign };
}

test("fresh committed witness head verifies canonical bytes and pinned authority but never authorizes recovery alone", async () => {
  const f = fixture();
  const result = await inspectVerifiedWitnessFreshHeadV1({ raw: await f.sign(), ...f.context });
  assert.equal(result.verifiedSignatureOnly, true);
  assert.equal(result.authorizesRecovery, false);
  assert.equal(result.status, "committed");
  assert.equal(Object.isFrozen(result), true);
});

test("pending witness gate is never an acceptable committed head, even when correctly signed", async () => {
  const f = fixture();
  const pending = { ...f.head, current_revision: null, current_manifest_digest: null,
    status: "pending", pending_reservation_id: Buffer.alloc(16, 0x21) };
  await assert.rejects(inspectVerifiedWitnessFreshHeadV1({ raw: await f.sign(pending), ...f.context }),
    (e) => e.code === "WITNESS_HEAD_UNACCEPTABLE");
  const falseCommitted = { ...f.head, pending_reservation_id: Buffer.alloc(16, 0x21) };
  await assert.rejects(inspectVerifiedWitnessFreshHeadV1({
    raw: await f.sign(falseCommitted), ...f.context,
  }));
});

test("valid signatures cannot bypass nonce, pinned key, scope, revision, high-water or digest", async () => {
  const f = fixture();
  for (const change of [
    { nonce: Buffer.alloc(32, 0xee) },
    { witness_key_id: Buffer.alloc(16, 0xee) },
    { account_id: Buffer.alloc(16, 0xee) },
    { keyring_id: Buffer.alloc(16, 0xee) },
    { current_revision: 1, witness_sequence: 1 },
    { current_manifest_digest: Buffer.alloc(32, 0xee) },
    { witness_sequence: 3 },
    { type: "rootark-recovery-witness-base/v1" },
    { current_revision: null, current_manifest_digest: null },
    { observed_at: -1 },
  ]) {
    const changed = { ...f.head, ...change };
    if (changed.observed_at < 0) {
      await assert.rejects(f.sign(changed), (e) => e.code === "UNSUPPORTED_CBOR_VALUE");
    } else {
      await assert.rejects(inspectVerifiedWitnessFreshHeadV1({
        raw: await f.sign(changed), ...f.context,
      }), (e) => e.code === "WITNESS_HEAD_UNACCEPTABLE",
      Object.keys(change)[0]);
    }
  }
  const anotherKey = crypto.generateKeyPairSync("ed25519").publicKey;
  await assert.rejects(inspectVerifiedWitnessFreshHeadV1({
    raw: await f.sign(), ...f.context, pinned: { ...f.context.pinned, publicKey: anotherKey },
  }));
});

test("missing independent inputs, forged bytes and noncanonical CBOR fail closed", async () => {
  const f = fixture();
  const raw = await f.sign();
  for (const overrides of [
    { nonce: undefined }, { pinned: undefined }, { scope: undefined },
    { minimumHead: undefined }, { minimumHead: { revision: 0, digest: null, witnessSequence: 0 } },
  ]) {
    await assert.rejects(inspectVerifiedWitnessFreshHeadV1({
      raw, ...f.context, ...overrides,
    }));
  }
  for (const altered of [
    Buffer.from("a2616101616102", "hex"),
    Buffer.concat([raw, Buffer.from([0])]),
    await f.sign(f.head, Buffer.from("Root.ark/zk-1/recovery-witness-base/v1\0", "ascii")),
    await f.sign({ ...f.head, unexpected: 1 }),
  ]) {
    await assert.rejects(inspectVerifiedWitnessFreshHeadV1({ raw: altered, ...f.context }));
  }
});

test("mutable challenge, scope, pinned key ID and high-water digest are snapshotted before awaits", async () => {
  const f = fixture();
  const raw = await f.sign();
  for (const which of ["nonce", "scope", "pinned", "minimumHead"]) {
    const wrong = Buffer.alloc(which === "nonce" || which === "minimumHead" ? 32 : 16, 0xed);
    const changed = which === "nonce" ? { nonce: wrong }
      : which === "scope" ? { scope: { ...f.context.scope, account_id: wrong } }
        : which === "pinned" ? { pinned: { ...f.context.pinned, keyId: wrong } }
          : { minimumHead: { ...f.context.minimumHead, digest: wrong } };
    const verifying = inspectVerifiedWitnessFreshHeadV1({ raw, ...f.context, ...changed });
    const desired = which === "nonce" ? f.context.nonce
      : which === "scope" ? f.context.scope.account_id
        : which === "pinned" ? f.context.pinned.keyId : f.context.minimumHead.digest;
    queueMicrotask(() => wrong.set(desired));
    await assert.rejects(verifying, (e) => e.code === "WITNESS_HEAD_UNACCEPTABLE",
      "must bind " + which + " to invocation-time bytes");
  }
});

test("a caller cannot replace the trusted witness public key during async verification", async () => {
  const f = fixture();
  const pinned = {
    ...f.context.pinned,
    publicKey: crypto.generateKeyPairSync("ed25519").publicKey,
  };
  const verifying = inspectVerifiedWitnessFreshHeadV1({
    raw: await f.sign(), ...f.context, pinned,
  });
  queueMicrotask(() => { pinned.publicKey = f.context.pinned.publicKey; });
  await assert.rejects(verifying, (error) => error.code === "WITNESS_HEAD_UNACCEPTABLE");
});
