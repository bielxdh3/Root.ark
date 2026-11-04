"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const {
  signOwnerCutover, signOwnerRotation, digestOwnerCutover, spkiHash,
} = require("../src/crypto/rootark-zk10-account-cutover-v1");
const {
  tokenDigest, signAnonymousObjectBinding, verifyAnonymousObjectBinding,
  buildSparseObjectInventoryProof, verifySparseObjectInventoryProof,
} = require("../src/crypto/rootark-zk10-anonymous-object-binding-v1");

const id = (value) => Buffer.alloc(16, value).toString("base64url");
const hash = (value) => Buffer.alloc(32, value).toString("hex");
const nonce = (value) => Buffer.alloc(32, value).toString("base64url");
const ownerA = crypto.generateKeyPairSync("ed25519");
const ownerB = crypto.generateKeyPairSync("ed25519");
const token = "a1".repeat(24);
const object = { object_id: id(11), revision: 3, ciphertext_sha256: hash(12) };

function cutover(account, key, generation = 1, prior = null, inventoryHead = hash(18)) {
  return signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: id(17),
    generation, previous_cutover_digest: prior, inventory_head: inventoryHead,
    complete_corpus: true, covered_compartments: [id(19)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced",
    grants: [], suite: "zk1-v2", nonce: nonce(20), issued_at: 1_800_000_000 + generation,
  }, key);
}
function membership(account, generation) {
  return buildSparseObjectInventoryProof([{
    immutable_account_id: account, owner_generation: generation,
    object_id: object.object_id, revision: object.revision,
    ciphertext_sha256: object.ciphertext_sha256,
  }], account, object.object_id, object.revision);
}
function fixture({ kind = "share", owner = ownerB, account = id(2) } = {}) {
  const proof = membership(account, 1);
  const signedOwner = cutover(account, owner.privateKey, 1, null, proof.root);
  const headDigest = digestOwnerCutover(signedOwner);
  const record = {
    type: "rootark-zk10-anonymous-object-binding/v1",
    kind, immutable_account_id: account, zk_account_id: id(17),
    owner_generation: 1, owner_cutover_digest: headDigest,
    inventory_head: proof.root, object_id: object.object_id,
    object_revision: object.revision, ciphertext_sha256: object.ciphertext_sha256,
    token_digest: tokenDigest(kind, token), nonce: nonce(21),
  };
  return {
    statement: signAnonymousObjectBinding(record, owner.privateKey),
    ownerCutoverHistory: [signedOwner], ownerRotations: [],
    pinnedOwnerRoot: owner.publicKey,
    independentlyRetainedCutoverDigest: headDigest,
    independentlyExpectedAccountId: account, expectedKind: kind,
    expectedToken: token, expectedObject: object,
    objectMembershipProof: proof.siblings,
  };
}
function verified(input) {
  return verifyAnonymousObjectBinding(input);
}

test("owner B signed object remains bound to B even when creator A issued legacy link", () => {
  // The legacy creator is deliberately outside the signed authority contract.
  // An anonymous route may not substitute this username for an owner pin.
  const legacyLink = { createdBy: "creator-A", folderId: "root", fileName: "same.txt" };
  const b = fixture();
  assert.equal(legacyLink.createdBy, "creator-A");
  assert.equal(verified(b).status, "VERIFIED_SIGNED_OBJECT_BINDING_NONAUTHORIZING");
  assert.equal(verified(b).authorizesIo, false);
  assert.equal(verified(b).independentObjectOwnershipProven, false);
  assert.equal(verified(b).completeExternalCorpusProven, false);
  assert.throws(() => verified({
    ...fixture({ owner: ownerA, account: id(1) }),
    independentlyExpectedAccountId: id(2),
  }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, pinnedOwnerRoot: ownerA.publicKey }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, independentlyExpectedAccountId: id(1) }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  const { signature: _signature, ...bodyClaimingB } = b.statement;
  const attackerAForgerOfB = signAnonymousObjectBinding(bodyClaimingB, ownerA.privateKey);
  assert.throws(() => verified({ ...b, statement: attackerAForgerOfB }),
    /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});

test("object UUID, revision and ciphertext digest reject name-reuse and rollback", () => {
  const b = fixture();
  for (const expectedObject of [
    { ...object, object_id: id(22) },
    { ...object, revision: 2 },
    { ...object, revision: 4 },
    { ...object, ciphertext_sha256: hash(23) },
  ]) assert.throws(() => verified({ ...b, expectedObject }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({
    ...b, independentlyRetainedCutoverDigest: hash(24),
  }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, expectedToken: "bc".repeat(24) }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, expectedKind: "open" }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, statement: { ...b.statement, object_id: id(22) } }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, statement: { ...b.statement, signature: nonce(22) } }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});

test("owner signature alone cannot bypass exact 256-level signed inventory membership", () => {
  const b = fixture();
  assert.equal(verified(b).signedInventoryMembershipVerified, true);
  const altered = b.objectMembershipProof.slice();
  altered[0] = hash(99);
  assert.throws(() => verified({ ...b, objectMembershipProof: altered }),
    /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => verified({ ...b, objectMembershipProof: [] }),
    /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  // Even an unforgeable owner-signed claim MUST fail if no object membership was supplied.
  const noProof = { ...b };
  delete noProof.objectMembershipProof;
  assert.throws(() => verified(noProof), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});

test("two-object manifest inclusion rejects forged sparse subset and cross-owner entry", () => {
  const account = id(2);
  const first = { immutable_account_id: account, owner_generation: 1,
    object_id: object.object_id, revision: object.revision,
    ciphertext_sha256: object.ciphertext_sha256 };
  const another = { ...first, object_id: id(33), revision: 1, ciphertext_sha256: hash(34) };
  const p1 = buildSparseObjectInventoryProof([first, another], account,
    object.object_id, object.revision);
  const p2 = buildSparseObjectInventoryProof([another, first], account,
    another.object_id, another.revision);
  assert.equal(p1.root, p2.root);
  assert.equal(verifySparseObjectInventoryProof(account, 1, object, p1.siblings, p1.root), true);
  assert.equal(verifySparseObjectInventoryProof(account, 1, {
    object_id: another.object_id, revision: 1, ciphertext_sha256: another.ciphertext_sha256,
  }, p2.siblings, p2.root), true);
  const forgedSubset = buildSparseObjectInventoryProof([first], account,
    object.object_id, object.revision);
  assert.notEqual(p1.root, forgedSubset.root);
  assert.throws(() => verifySparseObjectInventoryProof(account, 1, object,
    forgedSubset.siblings, p1.root), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => buildSparseObjectInventoryProof([first, {
    ...another, immutable_account_id: id(1),
  }], account, object.object_id, object.revision), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});

test("same token is domain-separated across anonymous /share and /open-file", () => {
  assert.notEqual(tokenDigest("share", token), tokenDigest("open", token));
  const b = fixture({ kind: "open" });
  assert.equal(verified(b).status, "VERIFIED_SIGNED_OBJECT_BINDING_NONAUTHORIZING");
  assert.throws(() => verified({ ...b, expectedKind: "share" }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  assert.throws(() => signAnonymousObjectBinding({
    ...b.statement, extra: "untrusted",
  }, ownerB.privateKey), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});

test("owner key rotation requires exact signed chain and current externally retained cutover", () => {
  const next = crypto.generateKeyPairSync("ed25519");
  const b = fixture();
  const first = b.ownerCutoverHistory[0];
  const rotation = signOwnerRotation({
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: id(2),
    generation: 1, from_spki_sha256: spkiHash(ownerB.publicKey),
    next_public_key: next.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    previous_rotation_digest: null,
  }, ownerB.privateKey, next.privateKey);
  const proof2 = membership(id(2), 2);
  const second = cutover(id(2), next.privateKey, 2, digestOwnerCutover(first), proof2.root);
  const { signature: _oldSignature, ...unsigned } = b.statement;
  const upgraded = {
    ...b, ownerCutoverHistory: [first, second], ownerRotations: [rotation],
    independentlyRetainedCutoverDigest: digestOwnerCutover(second),
    objectMembershipProof: proof2.siblings,
    statement: signAnonymousObjectBinding({
      ...unsigned, owner_generation: 2,
      owner_cutover_digest: digestOwnerCutover(second),
      inventory_head: proof2.root,
    }, next.privateKey),
  };
  assert.equal(verified(upgraded).status, "VERIFIED_SIGNED_OBJECT_BINDING_NONAUTHORIZING");
  for (const invalid of [
    { ...upgraded, statement: b.statement },
    { ...upgraded, ownerCutoverHistory: [first] },
    { ...upgraded, ownerRotations: [] },
    { ...upgraded, independentlyRetainedCutoverDigest: digestOwnerCutover(first) },
  ]) assert.throws(() => verified(invalid), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});

test("requires explicit externally supplied pins and expected object instead of accepting DB identity", () => {
  const b = fixture();
  for (const key of ["pinnedOwnerRoot", "independentlyRetainedCutoverDigest",
    "independentlyExpectedAccountId", "expectedObject", "objectMembershipProof"]) {
    const invalid = { ...b };
    delete invalid[key];
    assert.throws(() => verified(invalid), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
  }
  assert.throws(() => verified({ ...b, creator: "alice" }), /ZK10_ANONYMOUS_BINDING_UNVERIFIED/);
});
