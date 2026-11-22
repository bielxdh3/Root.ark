"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory, verifyOwnerCutover,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const id = (byte) => Buffer.alloc(16, byte).toString("base64url");
const nonce = (byte) => Buffer.alloc(32, byte).toString("base64url");
const hash = (byte) => Buffer.alloc(32, byte).toString("hex");

test("owner history digest must describe the same owner-signed bytes that were verified", () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const owner = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: id(1), zk_account_id: id(2),
    generation: 1, previous_cutover_digest: null, inventory_head: hash(3),
    complete_corpus: true, covered_compartments: [id(4)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced",
    grants: [], suite: "zk1-v2", nonce: nonce(5), issued_at: 1_800_000_000,
  }, keys.privateKey);
  const unsigned = { ...owner, nonce: nonce(6),
    signature: Buffer.alloc(64, 7).toString("base64url") };
  const signedDigest = digestOwnerCutover(owner);
  const forgedDigest = digestOwnerCutover(unsigned);
  assert.notEqual(signedDigest, forgedDigest);
  const verified = verifyOwnerCutoverHistory([owner], [keys.publicKey], id(1));
  assert.equal(verified.statement.inventory_head, owner.inventory_head);
  assert.equal(verified.digest, signedDigest,
    "a genuine owner statement retains the digest of its verified signed bytes");
  assert.notEqual(verified.digest, forgedDigest);

  // Reentrant descriptors return a real signed cutover to the verifier, then
  // an unsigned cutover when the history algorithm re-reads for its digest.
  let descriptorReads = 0;
  const switching = new Proxy({ ...owner }, {
    getOwnPropertyDescriptor(_target, property) {
      const source = ++descriptorReads <= OWNER_FIELDS.length + 1 ? owner : unsigned;
      return { ...Object.getOwnPropertyDescriptor(source, property), configurable: true };
    },
  });
  assert.throws(() => verifyOwnerCutoverHistory([switching], [keys.publicKey], id(1)),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/,
    "reject caller-controlled proxy descriptors before authentication");
  assert.equal(descriptorReads, 0,
    "a proxy trap must not execute before Ed25519 verification");
});

test("a proxy cutover must not poison crypto.verify before owner signature validation", () => {
  const keys = crypto.generateKeyPairSync("ed25519");
  const valid = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: id(1), zk_account_id: id(2),
    generation: 1, previous_cutover_digest: null, inventory_head: hash(3),
    complete_corpus: true, covered_compartments: [id(4)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced",
    grants: [], suite: "zk1-v2", nonce: nonce(5), issued_at: 1_800_000_000,
  }, keys.privateKey);
  const unsigned = { ...valid, inventory_head: hash(8) };
  assert.throws(() => verifyOwnerCutover(unsigned, keys.publicKey),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  const nativeVerify = crypto.verify;
  let traps = 0;
  const hostile = new Proxy(unsigned, {
    getPrototypeOf(target) {
      traps += 1;
      // Without an early proxy rejection this hook forges the crypto result.
      crypto.verify = () => true;
      return Reflect.getPrototypeOf(target);
    },
  });
  try {
    assert.throws(() => verifyOwnerCutover(hostile, keys.publicKey),
      /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
    assert.equal(traps, 0, "caller-supplied Proxy traps must never execute");
    assert.strictEqual(crypto.verify, nativeVerify,
      "the forged verifier must not be installed before rejection");
    const hostileHistory = new Proxy([unsigned], {
      get(target, property, receiver) {
        traps += 1;
        crypto.verify = () => true;
        return Reflect.get(target, property, receiver);
      },
    });
    assert.throws(() => verifyOwnerCutoverHistory(hostileHistory,
      [keys.publicKey], id(1)), /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
    assert.equal(traps, 0, "history array proxy hooks must not run before verification");
    assert.strictEqual(crypto.verify, nativeVerify);
    const hostileCompartmentList = new Proxy([id(4)], {
      get(target, property, receiver) {
        traps += 1;
        crypto.verify = () => true;
        return Reflect.get(target, property, receiver);
      },
    });
    assert.throws(() => verifyOwnerCutover({ ...unsigned,
      covered_compartments: hostileCompartmentList }, keys.publicKey),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
    assert.equal(traps, 0, "nested owner-signed array proxy hooks must not run");
    assert.strictEqual(crypto.verify, nativeVerify);
    const accessorHistory = [unsigned];
    Object.defineProperty(accessorHistory, 0, { configurable: true, enumerable: true,
      get() {
        traps += 1;
        crypto.verify = () => true;
        return unsigned;
      } });
    assert.throws(() => verifyOwnerCutoverHistory(accessorHistory,
      [keys.publicKey], id(1)), /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
    assert.equal(traps, 0, "own indexed history getters must not execute");
    assert.strictEqual(crypto.verify, nativeVerify);
    const accessorCompartmentList = [id(4)];
    Object.defineProperty(accessorCompartmentList, 0, { configurable: true, enumerable: true,
      get() {
        traps += 1;
        crypto.verify = () => true;
        return id(4);
      } });
    assert.throws(() => verifyOwnerCutover({ ...unsigned,
      covered_compartments: accessorCompartmentList }, keys.publicKey),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
    assert.equal(traps, 0, "own indexed compartment getters must not execute");
    assert.strictEqual(crypto.verify, nativeVerify);
  } finally { crypto.verify = nativeVerify; }
});
