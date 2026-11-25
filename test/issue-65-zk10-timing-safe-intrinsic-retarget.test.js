"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, verifyOwnerCutover, digestOwnerCutover,
  buildSparseEnrollmentProof, verifySparseEnrollmentProof,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");
const {
  buildSparseObjectInventoryProof, verifySparseObjectInventoryProof,
} = require("../src/crypto/rootark-zk10-anonymous-object-binding-v1");

const id = (value) => Buffer.alloc(16, value).toString("base64url");
const hex = (value) => Buffer.alloc(32, value).toString("hex");
const account = id(32);

function genuineOwnerFixture() {
  const owner = crypto.generateKeyPairSync("ed25519");
  const signed = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: id(33),
    generation: 1, previous_cutover_digest: null,
    inventory_head: hex(34), complete_corpus: true,
    covered_compartments: [id(35)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced",
    grants: [], suite: "zk1-v2", nonce: Buffer.alloc(32, 36).toString("base64url"),
    issued_at: 1800000000,
  }, owner.privateKey);
  assert.equal(verifyOwnerCutover(signed, owner.publicKey).generation, 1);
  return { owner, signed, digest: digestOwnerCutover(signed) };
}

function withNativeKeyGetterRebindingTimingSafeEqual(fixture, check) {
  const { owner, signed } = fixture;
  const handle = Object.getOwnPropertySymbols(owner.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "test requires Node 22 native Ed25519 KeyObject");
  const inherited = Object.create(owner.publicKey);
  const original = crypto.timingSafeEqual;
  let getterCalls = 0;
  let forgedComparisons = 0;
  const poison = () => {
    crypto.timingSafeEqual = () => { forgedComparisons += 1; return true; };
  };
  Object.defineProperty(inherited, handle, { get() {
    getterCalls += 1;
    poison();
    return owner.publicKey[handle];
  } });
  try {
    assert.throws(() => verifyOwnerCutover(signed, inherited),
      { code: "ZK10_ACCOUNT_CUTOVER_UNVERIFIED" },
      "inherited native handle must fail closed before the hostile getter");
    assert.equal(getterCalls, 0, "the untrusted native getter must not execute");
    assert.equal(crypto.timingSafeEqual, original,
      "rejection must not mutate the process comparator");
    // Exercise the original comparator replacement with a genuine pinned key.
    poison();
    assert.equal(verifyOwnerCutover(signed, owner.publicKey).generation, 1);
    assert.notEqual(crypto.timingSafeEqual, original,
      "the fixture must install the same hostile comparator replacement");
    check();
    assert.equal(forgedComparisons, 0,
      "the verified Merkle root must never dispatch to attacker JS comparator");
  } finally {
    crypto.timingSafeEqual = original;
  }
}

test("P2 enrollment proof rejects wrong independently pinned root after hostile signed-owner KeyObject getter", () => {
  const f = genuineOwnerFixture();
  const proof = buildSparseEnrollmentProof([{ accountId: account,
    cutoverDigest: f.digest }], account);
  const wrongRoot = hex(71);
  assert.notEqual(proof.root, wrongRoot);
  assert.equal(verifySparseEnrollmentProof(account, f.digest, proof.siblings, proof.root), true);
  assert.throws(() => verifySparseEnrollmentProof(account, f.digest, proof.siblings, wrongRoot),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  withNativeKeyGetterRebindingTimingSafeEqual(f, () => {
    assert.throws(() => verifySparseEnrollmentProof(account, f.digest, proof.siblings, wrongRoot),
      /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/);
  });
});

test("P2 inventory proof rejects wrong owner-signed root after hostile signed-owner KeyObject getter", () => {
  const f = genuineOwnerFixture();
  const object = { object_id: id(45), revision: 2, ciphertext_sha256: hex(46) };
  const entry = { immutable_account_id: account, owner_generation: 1, ...object };
  const proof = buildSparseObjectInventoryProof([entry], account, object.object_id, object.revision);
  const wrongRoot = hex(72);
  assert.notEqual(proof.root, wrongRoot);
  assert.equal(verifySparseObjectInventoryProof(account, 1, object, proof.siblings, proof.root), true);
  assert.throws(() => verifySparseObjectInventoryProof(account, 1, object, proof.siblings, wrongRoot),
    /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  withNativeKeyGetterRebindingTimingSafeEqual(f, () => {
    assert.throws(() => verifySparseObjectInventoryProof(account, 1, object, proof.siblings, wrongRoot),
      /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  });
});
