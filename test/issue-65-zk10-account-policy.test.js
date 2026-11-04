"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, verifyOwnerCutover, buildSparseEnrollmentProof,
  verifySparseEnrollmentProof, digestOwnerCutover, signOwnerRotation,
  verifyOwnerRotationKeys, verifyOwnerCutoverHistory, spkiHash,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");

const id = (n) => Buffer.alloc(16, n).toString("base64url");
const hash = (n) => Buffer.alloc(32, n).toString("hex");
const keys = crypto.generateKeyPairSync("ed25519");
function statement() {
  return { type: "rootark-zk10-owner-account-cutover/v1", immutable_account_id: id(1),
    zk_account_id: id(2), generation: 1, previous_cutover_digest: null,
    inventory_head: hash(3), complete_corpus: true,
    covered_compartments: [id(4)], legacy_egress_scope: "all",
    reference_disposition: "fully_accounted", migration_disposition: "closed",
    grant: "protected_enforced", grants: [], suite: "zk1-v2",
    nonce: Buffer.alloc(32, 5).toString("base64url"),
    issued_at: 1_800_000_000 };
}

test("owner-signed account-wide cutover requires exact domain and complete corpus", () => {
  const signed = signOwnerCutover(statement(), keys.privateKey);
  assert.equal(verifyOwnerCutover(signed, keys.publicKey).grant, "protected_enforced");
  for (const field of ["complete_corpus", "inventory_head", "immutable_account_id",
    "zk_account_id", "generation", "covered_compartments", "migration_disposition", "grants"]) {
    const modified = { ...signed, [field]: field === "complete_corpus" ? false
      : field === "generation" ? 2
      : field === "covered_compartments" ? [id(6)]
        : field === "grants" ? ["legacy:read"] : "tampered" };
    assert.throws(() => verifyOwnerCutover(modified, keys.publicKey));
  }
  assert.throws(() => verifyOwnerCutover({ ...signed, extra: true }, keys.publicKey));
  assert.throws(() => verifyOwnerCutover(signed, crypto.generateKeyPairSync("ed25519").publicKey));
});

test("owner rotation requires signatures from both keys and chained generation history", () => {
  const next = crypto.generateKeyPairSync("ed25519");
  const rotation = signOwnerRotation({ type: "rootark-zk10-owner-rotation/v1",
    immutable_account_id: id(1), generation: 1,
    from_spki_sha256: spkiHash(keys.publicKey),
    next_public_key: next.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    previous_rotation_digest: null }, keys.privateKey, next.privateKey);
  const chain = verifyOwnerRotationKeys([rotation], keys.publicKey, id(1));
  const first = signOwnerCutover(statement(), keys.privateKey);
  const second = signOwnerCutover({ ...statement(), generation: 2,
    previous_cutover_digest: digestOwnerCutover(first), issued_at: 1_800_000_001 },
  next.privateKey);
  assert.equal(verifyOwnerCutoverHistory([first, second], chain, id(1)).digest,
    digestOwnerCutover(second));
  assert.throws(() => verifyOwnerRotationKeys([{ ...rotation,
    signature_next: rotation.signature_from }], keys.publicKey, id(1)));
  assert.throws(() => verifyOwnerCutoverHistory([first,
    { ...second, previous_cutover_digest: hash(8) }], chain, id(1)));
  assert.throws(() => verifyOwnerCutoverHistory([first], chain, id(1)),
    "stale retired owner cannot be current after a signed rotation");
});

test("sparse enrolled and never-enrolled proofs are authenticated against one root", () => {
  const owner = signOwnerCutover(statement(), keys.privateKey);
  const entry = { accountId: id(1), cutoverDigest: digestOwnerCutover(owner) };
  const included = buildSparseEnrollmentProof([entry], id(1));
  assert.equal(verifySparseEnrollmentProof(id(1), entry.cutoverDigest,
    included.siblings, included.root), true);
  const excluded = buildSparseEnrollmentProof([entry], id(8));
  assert.equal(verifySparseEnrollmentProof(id(8), null,
    excluded.siblings, excluded.root), true);
  assert.equal(included.root, excluded.root);
  assert.throws(() => verifySparseEnrollmentProof(id(1), null,
    included.siblings, included.root));
  assert.throws(() => verifySparseEnrollmentProof(id(8), entry.cutoverDigest,
    excluded.siblings, excluded.root));
  assert.throws(() => verifySparseEnrollmentProof(id(8), null,
    excluded.siblings.slice(1), excluded.root));
});
