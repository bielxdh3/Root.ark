"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  OWNER_FIELDS, signOwnerCutover, digestOwnerCutover, verifyOwnerCutoverHistory,
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

  // Reentrant descriptors return a real signed cutover to the verifier, then
  // an unsigned cutover when the history algorithm re-reads for its digest.
  let descriptorReads = 0;
  const switching = new Proxy({ ...owner }, {
    getOwnPropertyDescriptor(_target, property) {
      const source = ++descriptorReads <= OWNER_FIELDS.length + 1 ? owner : unsigned;
      return { ...Object.getOwnPropertyDescriptor(source, property), configurable: true };
    },
  });
  const verified = verifyOwnerCutoverHistory([switching], [keys.publicKey], id(1));
  assert.equal(verified.statement.inventory_head, owner.inventory_head);
  assert.equal(verified.digest, signedDigest,
    "a digest built from unsigned alternate descriptors must never be accepted");
  assert.notEqual(verified.digest, forgedDigest);
  assert.equal(descriptorReads, OWNER_FIELDS.length + 1,
    "capture one owner statement before signature and digest checks");
});
