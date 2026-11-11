"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { DOMAIN: SOURCE_DOMAIN } = require("../sync-client/rootark-sync-atomic-owner-provision");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { signOwnerCutover, digestOwnerCutover, signOwnerRotation, spkiHash } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");
const { buildSparseObjectInventoryProof } =
  require("../src/crypto/rootark-zk10-anonymous-object-binding-v1");
const {
  signOwnerObjectMap, digestOwnerObjectMap, signCurrentMappingHead,
  createOwnerObjectMapVerifier,
} = require("../src/crypto/rootark-zk10-sync-v2-owner-object-map-v1");

// Entirely synthetic test identities. No external owner/issuer/custody is asserted.
const keys = Object.fromEntries(["owner", "source", "witness", "cas", "device", "authority", "attacker"]
  .map((name) => [name, crypto.generateKeyPairSync("ed25519")]));
const id = (n) => Buffer.alloc(16, n).toString("base64url");
const hex = (n) => Buffer.alloc(32, n).toString("hex");
const b64 = (key) => key.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
const identity = Object.freeze({
  accountId: "11111111-1111-4111-8111-111111111111",
  storeId: "22222222-2222-4222-8222-222222222222",
  username: "test-owner", compartmentId: "private",
});
const immutableId = id(1);
const zkAccountId = id(2);
const zkObjectId = id(3);
const zkCiphertext = Buffer.from("synthetic-zk-ciphertext");
const target = Object.freeze({ object_id: zkObjectId, revision: 2,
  epoch: 4, ciphertext: zkCiphertext.toString("base64url") });
const targetHash = crypto.createHash("sha256").update(zkCiphertext).digest("hex");
const deny = /ZK10_SYNC_V2_MAP_UNVERIFIED/;

function sourceProvisioning() {
  const statement = { type: "atomic-owner-provisioning", version: 1,
    scope: "synthetic-owner", ...identity, witnessSpki: b64(keys.witness),
    casSpki: b64(keys.cas), sequence: 1 };
  const signature = crypto.sign(null, Buffer.from(SOURCE_DOMAIN + protocol.canonicalJson(statement)),
    keys.source.privateKey).toString("base64url");
  const provisioning = { statement, signature };
  const digest = crypto.createHash("sha256")
    .update(SOURCE_DOMAIN + protocol.canonicalJson(provisioning)).digest("hex");
  return { provisioning, digest };
}

async function fixture(overrides = {}) {
  const source = protocol.createOperation({ operation: "create", objectId: "source-object-4",
    fileId: "source-file-4", versionId: "source-version-4", operationId: "op-123",
    deviceId: "source-device-4", compartmentId: identity.compartmentId,
    keyEpoch: "epoch-4", revision: { counter: 7, deviceId: "source-device-4" },
    metadata: { path: "encrypted.fixture" }, fileKey: Buffer.alloc(32, 8),
    plaintext: Buffer.from("synthetic-sync-v2-data") });
  source.authorization = await createAuthorizationProof(source, {
    privateKey: keys.device.privateKey, publicKey: b64(keys.device),
    username: identity.username, expiresAt: Date.now() + 600_000 });
  const proof = buildSparseObjectInventoryProof([{
    immutable_account_id: immutableId, owner_generation: 1, object_id: zkObjectId,
    revision: target.revision, ciphertext_sha256: targetHash,
  }], immutableId, zkObjectId, target.revision);
  const cutover = signOwnerCutover({ type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: immutableId, zk_account_id: zkAccountId, generation: 1,
    previous_cutover_digest: null, inventory_head: proof.root,
    complete_corpus: true, covered_compartments: [id(9)],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: Buffer.alloc(32, 7).toString("base64url"),
    issued_at: 1800000000 }, keys.owner.privateKey);
  const cutoverDigest = digestOwnerCutover(cutover);
  const payload = {
    type: "rootark-zk10-sync-v2-owner-object-map/v1",
    sync_account_id: identity.accountId, sync_store_id: identity.storeId,
    sync_compartment_id: identity.compartmentId, sync_object_id: source.objectId,
    sync_file_id: source.fileId, sync_version_id: source.versionId,
    sync_operation_id: source.operationId, sync_revision_counter: source.revision.counter,
    sync_revision_device_id: source.revision.deviceId,
    sync_key_epoch: 4,
    sync_ciphertext_sha256: crypto.createHash("sha256")
      .update(Buffer.from(source.ciphertext, "base64url")).digest("hex"),
    zk_immutable_account_id: immutableId, zk_account_id: zkAccountId,
    zk_object_id: zkObjectId, zk_object_revision: target.revision,
    zk_ciphertext_sha256: targetHash, zk_epoch: target.epoch,
    owner_generation: 1, owner_cutover_digest: cutoverDigest,
    mapping_sequence: 5, previous_mapping_digest: hex(77),
    nonce: Buffer.alloc(32, 8).toString("base64url"),
  };
  const mapping = signOwnerObjectMap({ ...payload, ...overrides }, keys.owner.privateKey);
  const mappingDigest = digestOwnerObjectMap(mapping);
  const src = sourceProvisioning();
  const authority = {
    pinnedPublicKey: keys.authority.publicKey,
    independentlyRetainedFloor: { sequence: 4, digest: hex(77) },
    readCurrentHead: async (challenge) => signCurrentMappingHead({
      type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
      sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
      mapping_sequence: payload.mapping_sequence, mapping_digest: mappingDigest,
    }, keys.authority.privateKey),
  };
  const sourceAuthority = {
    identity, provisioning: src.provisioning, provisionerPublicKey: keys.source.publicKey,
    provisioningDigest: src.digest, witnessPublicKey: keys.witness.publicKey,
    casPublicKey: keys.cas.publicKey, scope: "synthetic-owner",
    pinnedDevicePolicy: { username: identity.username,
      trustedDevicePublicKeys: { "source-device-4": b64(keys.device) }, revokedDeviceIds: [] },
    currentDevicePolicy: () => ({ username: identity.username,
      trustedDevicePublicKeys: { "source-device-4": b64(keys.device) }, revokedDeviceIds: [] }),
  };
  const zkAuthority = { immutableAccountId: immutableId, ownerRootPublicKey: keys.owner.publicKey,
    ownerCutoverHistory: [cutover], ownerRotations: [],
    independentlyRetainedCutoverDigest: cutoverDigest };
  return { source, target, mapping, mappingDigest, payload, proof,
    sourceAuthority, zkAuthority, authority,
    input: { sourceOperation: source, zkObject: target,
      zkMembershipProof: proof.siblings, ownerMapping: mapping } };
}

test("owner/SyncV2 device signatures + independent current challenged head bind exact ciphertext identities", async () => {
  const f = await fixture();
  const verify = createOwnerObjectMapVerifier({ sourceAuthority: f.sourceAuthority,
    zkAuthority: f.zkAuthority, mappingAuthority: f.authority });
  const result = await verify(f.input);
  assert.equal(result.status, "VERIFIED_SIGNED_SYNC_V2_ZK10_MAPPING_NONAUTHORIZING");
  assert.equal(result.mappingDigest, f.mappingDigest);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.independentCustodyProven, false);
  await assert.rejects(verify(f.input), deny, "accepted mapping cannot replay in one verifier");
});

test("tampered map identity, revisions, ciphertext digests, and epochs fail closed", async () => {
  const f = await fixture();
  for (const [field, value] of Object.entries({
    sync_account_id: "33333333-3333-4333-8333-333333333333",
    sync_revision_counter: 8, sync_key_epoch: 5,
    sync_ciphertext_sha256: hex(99), zk_immutable_account_id: id(66),
    zk_object_id: id(77), zk_object_revision: 3, zk_ciphertext_sha256: hex(5),
    zk_epoch: 5, owner_generation: 2, mapping_sequence: 6,
  })) {
    const broken = { ...f.mapping, [field]: value };
    const verify = createOwnerObjectMapVerifier({ sourceAuthority: f.sourceAuthority,
      zkAuthority: f.zkAuthority, mappingAuthority: f.authority });
    await assert.rejects(verify({ ...f.input, ownerMapping: broken }), deny, field);
  }
  const forged = signOwnerObjectMap(f.payload, keys.attacker.privateKey);
  await assert.rejects(createOwnerObjectMapVerifier({ sourceAuthority: f.sourceAuthority,
    zkAuthority: f.zkAuthority, mappingAuthority: f.authority })({ ...f.input,
    ownerMapping: forged }), deny);
});

test("signed owner statement still must match actual SyncV2 signed envelope and ZK1 inventory", async () => {
  const f = await fixture();
  const verifier = () => createOwnerObjectMapVerifier({ sourceAuthority: f.sourceAuthority,
    zkAuthority: f.zkAuthority, mappingAuthority: f.authority });
  await assert.rejects(verifier()({ ...f.input, sourceOperation: {
    ...f.source, ciphertext: Buffer.from("substituted").toString("base64url") } }), deny);
  await assert.rejects(verifier()({ ...f.input, zkObject: {
    ...f.target, ciphertext: Buffer.from("substituted").toString("base64url") } }), deny);
  await assert.rejects(verifier()({ ...f.input, zkMembershipProof: f.proof.siblings.slice(1) }), deny);
  await assert.rejects(verifier()({ ...f.input, zkObject: { ...f.target, epoch: 3 } }), deny);
  await assert.rejects(verifier()({ ...f.input, sourceOperation: {
    ...f.source, authorization: { ...f.source.authorization,
      publicKey: b64(keys.attacker) } } }), deny);
});

test("even re-signed owner and authority claims cannot substitute a different source object or revision", async () => {
  for (const patch of [
    { sync_object_id: "other-source" }, { sync_revision_counter: 8 },
    { sync_ciphertext_sha256: hex(99) }, { sync_key_epoch: 5 },
    { zk_ciphertext_sha256: hex(98) }, { zk_object_id: id(88) },
  ]) {
    const f = await fixture(patch);
    await assert.rejects(createOwnerObjectMapVerifier({
      sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
      mappingAuthority: f.authority })(f.input), deny);
  }
});

test("concurrent attempts cannot both consume one mapping sequence", async () => {
  const f = await fixture();
  const delayed = [];
  let acknowledge;
  const allArrived = new Promise((resolve) => { acknowledge = resolve; });
  const authority = { ...f.authority,
    readCurrentHead: async (challenge) => {
      let release;
      const pause = new Promise((resolve) => { release = resolve; });
      delayed.push({ challenge, release });
      if (delayed.length === 2) acknowledge();
      await pause;
      return signCurrentMappingHead({
        type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
        sync_account_id: identity.accountId,
        zk_immutable_account_id: immutableId, mapping_sequence: 5,
        mapping_digest: f.mappingDigest,
      }, keys.authority.privateKey);
    },
  };
  const verify = createOwnerObjectMapVerifier({ sourceAuthority: f.sourceAuthority,
    zkAuthority: f.zkAuthority, mappingAuthority: authority });
  const attempts = [verify(f.input), verify(f.input)];
  await allArrived;
  for (const item of delayed) item.release();
  const outcome = await Promise.allSettled(attempts);
  assert.deepEqual(outcome.map((v) => v.status).sort(), ["fulfilled", "rejected"]);
  assert.match(outcome.find((v) => v.status === "rejected").reason.message, deny);
});

test("independent signer, externally pinned floor and fresh challenge are mandatory", async () => {
  const f = await fixture();
  const verifier = (authority) => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: authority });
  for (const floor of [
    { sequence: 5, digest: hex(99) }, { sequence: 6, digest: f.mappingDigest },
    { sequence: 3, digest: hex(77) },
  ]) {
    await assert.rejects(verifier({ ...f.authority, independentlyRetainedFloor: floor })(f.input), deny);
  }
  await assert.rejects(verifier({ ...f.authority, pinnedPublicKey: keys.attacker.publicKey })(f.input), deny);
  await assert.rejects(verifier({ ...f.authority,
    readCurrentHead: async () => signCurrentMappingHead({
      type: "rootark-zk10-sync-v2-current-map-head/v1",
      challenge: Buffer.alloc(32).toString("base64url"), sync_account_id: identity.accountId,
      zk_immutable_account_id: immutableId, mapping_sequence: 5,
      mapping_digest: f.mappingDigest,
    }, keys.authority.privateKey) })(f.input), deny);
  assert.throws(() => verifier({ ...f.authority, readCurrentHead: null }), deny);
  assert.throws(() => verifier({ ...f.authority, independentlyRetainedFloor: null }), deny);
});

test("wrong source owner provisioning, signer pin or current revocation fail", async () => {
  const f = await fixture();
  const make = (sourceAuthority) => createOwnerObjectMapVerifier({
    sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: f.authority });
  assert.throws(() => make({ ...f.sourceAuthority, provisioningDigest: hex(99) }), deny);
  assert.throws(() => make({ ...f.sourceAuthority,
    provisionerPublicKey: keys.attacker.publicKey }), deny);
  await assert.rejects(make({ ...f.sourceAuthority,
    currentDevicePolicy: () => ({ username: identity.username,
      trustedDevicePublicKeys: { "source-device-4": b64(keys.device) },
      revokedDeviceIds: ["source-device-4"] }) })(f.input), deny);
});

test("P2 rotated owner signer must NEVER double as independently pinned mapping head signer", async () => {
  const f = await fixture();
  const rotated = crypto.generateKeyPairSync("ed25519");
  const rotation = signOwnerRotation({
    type: "rootark-zk10-owner-rotation/v1", immutable_account_id: immutableId,
    generation: 1, from_spki_sha256: spkiHash(keys.owner.publicKey),
    next_public_key: b64(rotated), previous_rotation_digest: null,
  }, keys.owner.privateKey, rotated.privateKey);
  const { signature: _oldSignature, ...cutoverBody } = f.zkAuthority.ownerCutoverHistory[0];
  const cutover = signOwnerCutover(cutoverBody, rotated.privateKey);
  const cutoverDigest = digestOwnerCutover(cutover);
  const mapping = signOwnerObjectMap({ ...f.payload,
    owner_cutover_digest: cutoverDigest }, rotated.privateKey);
  const mappingDigest = digestOwnerObjectMap(mapping);
  const zkAuthority = { ...f.zkAuthority, ownerRotations: [rotation],
    ownerCutoverHistory: [cutover], independentlyRetainedCutoverDigest: cutoverDigest };
  const makeHead = (privateKey) => async (challenge) => signCurrentMappingHead({
    type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
    sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
    mapping_sequence: f.payload.mapping_sequence, mapping_digest: mappingDigest,
  }, privateKey);
  // Positive control: the legitimate rotation remains valid with a genuinely
  // distinct authority, rather than rejecting rotations outright.
  const distinct = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority, mappingAuthority: {
      ...f.authority, readCurrentHead: makeHead(keys.authority.privateKey),
    },
  });
  assert.equal((await distinct({ ...f.input, ownerMapping: mapping })).authorizesIo, false);
  // Same K owns the freshly rotated owner certificate AND the separately
  // claimed external head: signatures are valid but independence is false.
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority, mappingAuthority: {
      ...f.authority, pinnedPublicKey: rotated.publicKey,
      readCurrentHead: makeHead(rotated.privateKey),
    },
  }), deny);
  // A caller may override only the JavaScript instance export. The real
  // Ed25519 key still belongs to the rotated owner, so it cannot also be
  // the independent CURRENT authority even if the displayed SPKI differs.
  const unrelatedSpki = keys.attacker.publicKey.export({ format: "der", type: "spki" });
  Object.defineProperty(rotated.publicKey, "export", { value: () => unrelatedSpki });
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority, mappingAuthority: {
      ...f.authority, pinnedPublicKey: rotated.publicKey,
      readCurrentHead: makeHead(rotated.privateKey),
    },
  }), deny, "the same real owner key cannot masquerade as a distinct authority via .export");
});

test("native Ed25519 roles use actual key material despite shadowed type and export metadata", async () => {
  const f = await fixture();
  const copy = (publicKey) => crypto.createPublicKey({
    key: publicKey.export({ format: "der", type: "spki" }),
    format: "der", type: "spki",
  });
  const ownerCopy = copy(keys.owner.publicKey);
  const authorityCopy = copy(keys.authority.publicKey);
  for (const candidate of [ownerCopy, authorityCopy]) {
    Object.defineProperties(candidate, {
      type: { value: "private" },
      asymmetricKeyType: { value: "rsa" },
      export: { value: () => { throw Error("caller-shadowed-export-must-not-run"); } },
    });
  }
  const verifier = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority,
    zkAuthority: { ...f.zkAuthority, ownerRootPublicKey: ownerCopy },
    mappingAuthority: { ...f.authority, pinnedPublicKey: authorityCopy },
  });
  const result = await verifier(f.input);
  assert.equal(result.status, "VERIFIED_SIGNED_SYNC_V2_ZK10_MAPPING_NONAUTHORIZING");
  assert.equal(result.authorizesIo, false);
  assert.equal(result.independentCustodyProven, false);
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority,
    zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority, pinnedPublicKey: {
      type: "public", asymmetricKeyType: "ed25519", export: () => Buffer.alloc(44),
    } },
  }), deny, "plain signer objects must never masquerade as native public KeyObjects");
});

test("P2 owner cutover is snapshotted: two distinct valid signatures cannot splice a foreign inventory root", async () => {
  const f = await fixture();
  const signedA = f.zkAuthority.ownerCutoverHistory[0];
  const { signature: _signature, ...cutoverBody } = signedA;
  const signedB = signOwnerCutover({ ...cutoverBody, inventory_head: hex(99) },
    keys.owner.privateKey);
  const digestB = digestOwnerCutover(signedB);
  const mapping = signOwnerObjectMap({ ...f.payload,
    owner_cutover_digest: digestB }, keys.owner.privateKey);
  const digestBMap = digestOwnerObjectMap(mapping);
  const authority = { ...f.authority,
    readCurrentHead: async (challenge) => signCurrentMappingHead({
      type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
      sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
      mapping_sequence: f.payload.mapping_sequence, mapping_digest: digestBMap,
    }, keys.authority.privateKey),
  };
  let observedReads = 0;
  const swappedByProxy = new Proxy([signedA], {
    get(target, field, receiver) {
      if (field === "0") return ++observedReads === 1 ? signedA : signedB;
      return Reflect.get(target, field, receiver);
    },
  });
  const attempted = () => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority,
    zkAuthority: { ...f.zkAuthority, ownerCutoverHistory: swappedByProxy,
      independentlyRetainedCutoverDigest: digestB },
    mappingAuthority: authority,
  });
  // The current retained digest B is not the inventory root A whose sparse
  // membership proof is supplied. A/B are BOTH legitimately owner signed.
  await assert.rejects(async () => {
    const verifier = attempted();
    await verifier({ ...f.input, ownerMapping: mapping });
  }, deny);
  // A genuine array accessor is also forbidden, rather than allowing a
  // mutable getter to change the cutover between cryptographic operations.
  const withGetter = [signedA];
  Object.defineProperty(withGetter, "0", {
    enumerable: true, configurable: true,
    get: () => ++observedReads % 2 ? signedA : signedB,
  });
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority,
    zkAuthority: { ...f.zkAuthority, ownerCutoverHistory: withGetter,
      independentlyRetainedCutoverDigest: digestB },
    mappingAuthority: authority,
  }), deny);
  // Fixed inputs with A under a retained B digest are rejected even without
  // hostile callbacks. No independent custody or actual migration is implied.
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority,
    zkAuthority: { ...f.zkAuthority, independentlyRetainedCutoverDigest: digestB },
    mappingAuthority: authority,
  }), deny);
});

function signedHead(f, challenge) {
  return signCurrentMappingHead({
    type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
    sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
    mapping_sequence: f.payload.mapping_sequence, mapping_digest: f.mappingDigest,
  }, keys.authority.privateKey);
}

async function withinHeadDeadline(promise, milliseconds = 400) {
  let timeout;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error("head read never settled")), milliseconds);
    })]);
  } finally { clearTimeout(timeout); }
}

test("W26: never-settling external head is aborted and retains its occupied slot", async () => {
  const f = await fixture();
  const signals = [];
  const authority = { ...f.authority, readCurrentHead: (_challenge, { signal } = {}) => {
    signals.push(signal);
    return new Promise(() => {});
  } };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: authority,
  }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(signals.length, 1);
  assert.equal(signals[0].aborted, true);
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(signals.length, 1, "noncooperative head read must retain the one-slot budget");
});

test("W26: late valid signed head cannot settle a timed-out verification", async () => {
  const f = await fixture();
  const calls = [];
  const authority = { ...f.authority, readCurrentHead: (challenge, { signal } = {}) =>
    new Promise((resolve) => calls.push({ challenge, signal, resolve })) };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: authority,
  }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
  const expired = verify(f.input);
  await withinHeadDeadline(assert.rejects(expired, deny));
  assert.equal(calls[0].signal.aborted, true);
  calls[0].resolve(signedHead(f, calls[0].challenge));
  for (let i = 0; i < 5; i++) await Promise.resolve();
  const fresh = verify(f.input);
  await withinHeadDeadline(new Promise((resolve) => {
    const poll = () => {
      if (calls.length === 2) resolve();
      else setImmediate(poll);
    };
    poll();
  }));
  calls[1].resolve(signedHead(f, calls[1].challenge));
  const result = await withinHeadDeadline(fresh);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.independentCustodyProven, false);
  assert.equal(calls.length, 2, "a stale head cannot be reused for a new challenge");
});

test("W26: caller cancellation aborts native head read without later acceptance", async () => {
  const f = await fixture();
  const controller = new AbortController();
  const calls = [];
  const authority = { ...f.authority, readCurrentHead: (challenge, { signal } = {}) =>
    new Promise((resolve) => calls.push({ challenge, signal, resolve })) };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: authority,
  }, { headTimeoutMs: 1000, maxPendingHeadReads: 1 });
  const cancelled = verify(f.input, { signal: controller.signal });
  await withinHeadDeadline(new Promise((resolve) => {
    const poll = () => {
      if (calls.length === 1) resolve();
      else setImmediate(poll);
    };
    poll();
  }));
  controller.abort();
  await withinHeadDeadline(assert.rejects(cancelled, deny));
  assert.equal(calls[0].signal.aborted, true);
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(calls.length, 1, "cancelled native promise continues consuming budget");
  calls[0].resolve(signedHead(f, calls[0].challenge));
  for (let i = 0; i < 5; i++) await Promise.resolve();
});

test("W26: concurrent external head calls share strict outstanding budget", async () => {
  const f = await fixture();
  const calls = [];
  const authority = { ...f.authority, readCurrentHead: (challenge, { signal } = {}) =>
    new Promise((resolve) => calls.push({ challenge, signal, resolve })) };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: authority,
  }, { headTimeoutMs: 80, maxPendingHeadReads: 2 });
  const first = verify(f.input);
  const second = verify(f.input);
  await withinHeadDeadline(new Promise((resolve) => {
    const poll = () => {
      if (calls.length === 2) resolve();
      else setImmediate(poll);
    };
    poll();
  }));
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(calls.length, 2, "overflow cannot dispatch another native read");
  await withinHeadDeadline(Promise.all([
    assert.rejects(first, deny), assert.rejects(second, deny),
  ]));
  assert.equal(calls.every(({ signal }) => signal.aborted), true);
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(calls.length, 2, "timeout does not release noncooperative capacity");
  calls[0].resolve(signedHead(f, calls[0].challenge));
  for (let i = 0; i < 5; i++) await Promise.resolve();
  const next = verify(f.input);
  await withinHeadDeadline(new Promise((resolve) => {
    const poll = () => {
      if (calls.length === 3) resolve();
      else setImmediate(poll);
    };
    poll();
  }));
  calls[2].resolve(signedHead(f, calls[2].challenge));
  const result = await withinHeadDeadline(next);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.independentCustodyProven, false);
  calls[1].resolve(signedHead(f, calls[1].challenge));
});

test("W26: event-loop-blocking external callback cannot slip a late valid head past deadline", async () => {
  const f = await fixture();
  let signal;
  const authority = { ...f.authority, readCurrentHead: (challenge, { signal: nativeSignal }) => {
    signal = nativeSignal;
    // The event loop cannot run setTimeout during this real synchronous stall.
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 40);
    return signedHead(f, challenge);
  } };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: authority,
  }, { headTimeoutMs: 10, maxPendingHeadReads: 1 });
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(signal.aborted, true);
});

test("W26: invalid head limits and pre-aborted signal fail before native work", async () => {
  const f = await fixture();
  for (const limits of [
    { headTimeoutMs: 0, maxPendingHeadReads: 1 },
    { headTimeoutMs: Infinity, maxPendingHeadReads: 1 },
    { headTimeoutMs: 5001, maxPendingHeadReads: 1 },
    { headTimeoutMs: 100, maxPendingHeadReads: 0 },
    { headTimeoutMs: 100, maxPendingHeadReads: 65 },
  ]) {
    assert.throws(() => createOwnerObjectMapVerifier({
      sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
      mappingAuthority: f.authority,
    }, limits), deny);
  }
  let reads = 0;
  const authority = { ...f.authority, readCurrentHead: async (challenge) => {
    reads++;
    return signedHead(f, challenge);
  } };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority, mappingAuthority: authority,
  });
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(verify(f.input, { signal: cancelled.signal }), deny);
  assert.equal(reads, 0);
});
