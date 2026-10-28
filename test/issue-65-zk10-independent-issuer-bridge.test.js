"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const { signOwnerCutover, signOwnerRotation, spkiHash, digestOwnerCutover } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");
const { signAnonymousObjectBinding, tokenDigest, buildSparseObjectInventoryProof } =
  require("../src/crypto/rootark-zk10-anonymous-object-binding-v1");
const { signIssuerProvisioning, digestIssuerProvisioning, createIssuerProvisionedObjectVerifier } =
  require("../src/crypto/rootark-zk10-independent-issuer-bridge-v1");

const id = (v) => Buffer.alloc(16, v).toString("base64url");
const hex = (v) => Buffer.alloc(32, v).toString("hex");
const nonce = (v) => Buffer.alloc(32, v).toString("base64url");
const token = "ae".repeat(24);
const owner = crypto.generateKeyPairSync("ed25519");
const issuer = crypto.generateKeyPairSync("ed25519");
const attacker = crypto.generateKeyPairSync("ed25519");
const nextOwner = crypto.generateKeyPairSync("ed25519");
const accountId = id(1);
const zkId = id(2);
const object = { object_id: id(3), revision: 2, ciphertext_sha256: hex(4) };
const extraObject = { object_id: id(5), revision: 1, ciphertext_sha256: hex(6) };

function makeFixture({ fullCorpus = true, ownerKeys = owner, rotate = false } = {}) {
  const generation = rotate ? 2 : 1;
  const entry = (item) => ({
    immutable_account_id: accountId, owner_generation: generation,
    object_id: item.object_id, revision: item.revision, ciphertext_sha256: item.ciphertext_sha256,
  });
  const proof = buildSparseObjectInventoryProof(
    fullCorpus ? [entry(object), entry(extraObject)] : [entry(object)],
    accountId, object.object_id, object.revision);
  const cutoverBody = (epoch, previous, inventoryRoot) => ({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: accountId, zk_account_id: zkId, generation: epoch,
    previous_cutover_digest: previous, inventory_head: inventoryRoot,
    complete_corpus: true, covered_compartments: [id(7)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: nonce(8), issued_at: 1800000000 + epoch,
  });
  const first = signOwnerCutover(cutoverBody(1, null,
    rotate ? hex(80) : proof.root), ownerKeys.privateKey);
  const activeKeys = rotate ? nextOwner : ownerKeys;
  const head = rotate
    ? signOwnerCutover(cutoverBody(2, digestOwnerCutover(first), proof.root),
      activeKeys.privateKey)
    : first;
  const ownerRotations = rotate ? [signOwnerRotation({
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: accountId,
    generation: 1, from_spki_sha256: spkiHash(ownerKeys.publicKey),
    next_public_key: activeKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64url"),
    previous_rotation_digest: null,
  }, ownerKeys.privateKey, activeKeys.privateKey)] : [];
  const ownerCutoverHistory = rotate ? [first, head] : [head];
  const cutoverDigest = digestOwnerCutover(head);
  const binding = signAnonymousObjectBinding({
    type: "rootark-zk10-anonymous-object-binding/v1", kind: "share",
    immutable_account_id: accountId, zk_account_id: zkId,
    owner_generation: generation, owner_cutover_digest: cutoverDigest,
    inventory_head: proof.root, object_id: object.object_id,
    object_revision: object.revision, ciphertext_sha256: object.ciphertext_sha256,
    token_digest: tokenDigest("share", token), nonce: nonce(9),
  }, activeKeys.privateKey);
  const issuerBody = {
    type: "rootark-zk10-independent-issuer-provisioning/v1",
    immutable_account_id: accountId, zk_account_id: zkId,
    owner_root_spki: ownerKeys.publicKey.export({ format: "der", type: "spki" }).toString("base64url"),
    owner_generation: generation, owner_cutover_digest: cutoverDigest,
    inventory_head: proof.root, object_id: object.object_id,
    object_revision: object.revision, ciphertext_sha256: object.ciphertext_sha256,
    grant: "protected_enforced", complete_corpus: true, nonce: nonce(10),
  };
  const issuerProvisioning = signIssuerProvisioning(issuerBody, issuer.privateKey);
  const verify = createIssuerProvisionedObjectVerifier({
    trustedIssuerPublicKey: issuer.publicKey,
    immutableAccountId: accountId,
    independentlyRetainedProvisioningDigest: digestIssuerProvisioning(issuerProvisioning),
  });
  return {
    verify, issuerProvisioning, issuerBody, head, proof, binding,
    input: {
      issuerProvisioning, statement: binding, ownerCutoverHistory,
      ownerRotations, objectMembershipProof: proof.siblings,
      expectedKind: "share", expectedToken: token,
    },
  };
}

test("independent issuer bridges exact current owner/account and object identity without I/O authorization", () => {
  const f = makeFixture();
  const result = f.verify(f.input);
  assert.equal(result.issuerProvisioningVerified, true);
  assert.equal(result.ownerGeneration, 1);
  assert.equal(result.objectRevision, object.revision);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.completeExternalCorpusProven, false);
  assert.equal(result.independentAnchorCustodyProven, false);
});

test("unsigned legacy or client-selected pins cannot downgrade protected identity", () => {
  const f = makeFixture();
  const { issuerProvisioning: _ignored, ...withoutIssuer } = f.input;
  assert.throws(() => f.verify(withoutIssuer), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => f.verify({ ...f.input, issuerProvisioning: { createdBy: "legacy" } }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => f.verify({ ...f.input, independentlyExpectedAccountId: accountId }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => f.verify({ ...f.input, pinnedOwnerRoot: owner.publicKey }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
});

test("issuer trust pin, independently retained digest and immutable account are mandatory", () => {
  const f = makeFixture();
  const forged = signIssuerProvisioning(f.issuerBody, attacker.privateKey);
  assert.throws(() => f.verify({ ...f.input, issuerProvisioning: forged }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => createIssuerProvisionedObjectVerifier({
    trustedIssuerPublicKey: issuer.publicKey, immutableAccountId: accountId,
  }), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => createIssuerProvisionedObjectVerifier({
    trustedIssuerPublicKey: issuer.publicKey, immutableAccountId: id(99),
    independentlyRetainedProvisioningDigest: digestIssuerProvisioning(f.issuerProvisioning),
  })(f.input), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
});

test("issuer attested whole inventory rejects owner-signed partial corpus (anti-omission)", () => {
  const f = makeFixture();
  const subset = makeFixture({ fullCorpus: false });
  assert.notEqual(f.proof.root, subset.proof.root);
  assert.throws(() => f.verify({
    ...subset.input, issuerProvisioning: f.issuerProvisioning,
  }), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
});

test("even properly issuer-signed and re-pinned conflicting identities fail owner/SMT checks", () => {
  const f = makeFixture();
  const otherOwner = makeFixture({ ownerKeys: attacker });
  assert.throws(() => f.verify({
    ...otherOwner.input, issuerProvisioning: f.issuerProvisioning,
  }), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  for (const field of [
    "object_id", "object_revision", "ciphertext_sha256", "owner_generation",
    "zk_account_id", "inventory_head",
  ]) {
    const tampered = { ...f.issuerBody, [field]: field === "owner_generation" ? 2 :
      field === "object_revision" ? 3 :
        field === "object_id" || field === "zk_account_id" ? id(99) : hex(99) };
    const signed = signIssuerProvisioning(tampered, issuer.privateKey);
    const rePinned = createIssuerProvisionedObjectVerifier({
      trustedIssuerPublicKey: issuer.publicKey,
      immutableAccountId: accountId,
      independentlyRetainedProvisioningDigest: digestIssuerProvisioning(signed),
    });
    assert.throws(() => rePinned({ ...f.input, issuerProvisioning: signed }),
      /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  }
  assert.throws(() => f.verify({ ...f.input, expectedToken: "bf".repeat(24) }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
});

test("issuer attestations are generation-specific across signed owner key rotations", () => {
  const previous = makeFixture();
  const current = makeFixture({ rotate: true });
  assert.equal(current.verify(current.input).ownerGeneration, 2);
  assert.throws(() => current.verify({
    ...previous.input, issuerProvisioning: current.issuerProvisioning,
  }), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => current.verify({
    ...current.input, ownerRotations: [],
  }), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.throws(() => current.verify({
    ...current.input, ownerCutoverHistory: [current.head],
  }), /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
});

test("alternating Proxy issuer descriptors cannot combine stale signature with current digest", () => {
  const f = makeFixture();
  // Both wire statements have valid signatures under the same issuer; only
  // current is committed to the verifier's independent provisioning digest.
  const stale = signIssuerProvisioning({
    ...f.issuerBody, nonce: nonce(77),
  }, issuer.privateKey);
  assert.notEqual(digestIssuerProvisioning(stale),
    digestIssuerProvisioning(f.issuerProvisioning));
  const fieldCount = Reflect.ownKeys(f.issuerProvisioning).length;
  let descriptorReads = 0;
  const switchingWire = new Proxy({ ...f.issuerProvisioning }, {
    getOwnPropertyDescriptor(_target, property) {
      descriptorReads += 1;
      const source = descriptorReads <= fieldCount ? stale : f.issuerProvisioning;
      return { ...Object.getOwnPropertyDescriptor(source, property), configurable: true };
    },
  });
  assert.throws(() => f.verify({ ...f.input, issuerProvisioning: switchingWire }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  assert.equal(descriptorReads, fieldCount,
    "issuer statement must be captured once and never re-read for digest");
});

test("accessor and throwing Proxy issuer descriptors fail closed", () => {
  const f = makeFixture();
  const withGetter = { ...f.issuerProvisioning };
  Object.defineProperty(withGetter, "nonce", {
    configurable: true, enumerable: true,
    get() { return nonce(10); },
  });
  assert.throws(() => f.verify({ ...f.input, issuerProvisioning: withGetter }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
  const throwingProxy = new Proxy({ ...f.issuerProvisioning }, {
    getOwnPropertyDescriptor() { throw new Error("attacker descriptor getter"); },
  });
  assert.throws(() => f.verify({ ...f.input, issuerProvisioning: throwingProxy }),
    /ZK10_ISSUER_BRIDGE_UNVERIFIED/);
});
