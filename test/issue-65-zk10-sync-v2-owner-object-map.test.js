"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const vm = require("node:vm");
const test = require("node:test");
const protocol = require("../sync-client/rootark-sync-protocol");
const { DOMAIN: SOURCE_DOMAIN, verifyPinnedAtomicOwnerProvision } =
  require("../sync-client/rootark-sync-atomic-owner-provision");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { signOwnerCutover, digestOwnerCutover, signOwnerRotation, spkiHash,
  verifyOwnerRotationKeys } =
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

test("P2 mapping: callback iterator must not hide genuine owner Ed25519 A when CURRENT key is also A", async () => {
  const f = await fixture();
  const ownHead = (challenge) => signCurrentMappingHead({
    type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
    sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
    mapping_sequence: f.payload.mapping_sequence, mapping_digest: f.mappingDigest,
  }, keys.owner.privateKey);
  const sameSignerAuthority = { ...f.authority,
    pinnedPublicKey: keys.owner.publicKey, readCurrentHead: ownHead };
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: sameSignerAuthority,
  }), deny, "owner Ed25519 A cannot issue purported independent CURRENT Ed25519 A");
  const handle = Object.getOwnPropertySymbols(keys.owner.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle);
  const poisoned = Object.create(keys.owner.publicKey);
  const actualIterator = Array.prototype[Symbol.iterator];
  const nativeEquals = crypto.KeyObject.prototype.equals;
  let reads = 0, skipped = 0;
  Object.defineProperty(poisoned, handle, { get() {
    reads++;
    Array.prototype[Symbol.iterator] = function*() {
      if (this.length === 1 && this[0] instanceof crypto.KeyObject
        && Reflect.apply(nativeEquals, this[0], [keys.owner.publicKey])) {
        skipped++;
        return;
      }
      yield* Reflect.apply(actualIterator, this, []);
    };
    return keys.owner.publicKey[handle];
  } });
  try {
    assert.throws(() => createOwnerObjectMapVerifier({
      sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
      mappingAuthority: { ...sameSignerAuthority, pinnedPublicKey: poisoned },
    }), deny, "inherited KeyObject getter cannot omit owner from separation check");
  } finally { Array.prototype[Symbol.iterator] = actualIterator; }
  assert.ok(reads > 0, "native owner key callback executed");
  assert.equal(skipped, 0, "native iteration or indexed role checks must ignore forged iterator");
  const good = await fixture();
  const valid = createOwnerObjectMapVerifier({
    sourceAuthority: good.sourceAuthority, zkAuthority: good.zkAuthority,
    mappingAuthority: good.authority,
  });
  assert.equal((await valid(good.input)).authorizesIo, false);
});

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

async function fixture(overrides = {}, { coveredCompartments = [id(9)] } = {}) {
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
    complete_corpus: true, covered_compartments: coveredCompartments,
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

test("P2: reentrant source KeyObjects cannot change any pinned role after provisioning verification", async () => {
  const f = await fixture();
  for (const [role, pair] of [
    ["provisionerPublicKey", keys.source],
    ["witnessPublicKey", keys.witness],
    ["casPublicKey", keys.cas],
  ]) {
    const handle = Object.getOwnPropertySymbols(pair.publicKey)
      .find((symbol) => symbol.description === "kHandle");
    assert.ok(handle, "real Node22 Ed25519 native handle required");
    const controlledHandle = (acceptedReads = Infinity) => {
      const substituted = Object.create(pair.publicKey);
      let reads = 0;
      Object.defineProperty(substituted, handle, { get() {
        // A native KeyObject import may read kHandle more than once for
        // type/algorithm/export. Count a full successful provisioning first;
        // after that boundary, any re-read supplies unrelated real key B.
        // No stack-trace branch or method-name inference is involved.
        reads += 1;
        return reads <= acceptedReads
          ? pair.publicKey[handle] : keys.attacker.publicKey[handle];
      } });
      return { substituted, reads: () => reads };
    };
    const admission = controlledHandle();
    const admitted = verifyPinnedAtomicOwnerProvision({
      identity: f.sourceAuthority.identity,
      scope: f.sourceAuthority.scope,
      provisioning: f.sourceAuthority.provisioning,
      expectedDigest: f.sourceAuthority.provisioningDigest,
      provisionerPublicKey: role === "provisionerPublicKey"
        ? admission.substituted : f.sourceAuthority.provisionerPublicKey,
      witnessPublicKey: role === "witnessPublicKey"
        ? admission.substituted : f.sourceAuthority.witnessPublicKey,
      casPublicKey: role === "casPublicKey"
        ? admission.substituted : f.sourceAuthority.casPublicKey,
    });
    assert.equal(admitted.identity.accountId, identity.accountId,
      `first genuine ${role} A key must pass real signed provisioning`);
    const verifiedReadCount = admission.reads();
    assert.ok(verifiedReadCount > 0,
      `genuine ${role} A must be read by the real native provisioning verifier`);
    const attack = controlledHandle(verifiedReadCount);
    assert.throws(() => createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, [role]: attack.substituted },
      zkAuthority: f.zkAuthority,
      mappingAuthority: {
        ...f.authority, pinnedPublicKey: pair.publicKey,
        readCurrentHead: async (challenge) => signCurrentMappingHead({
          type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
          sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
          mapping_sequence: f.payload.mapping_sequence, mapping_digest: f.mappingDigest,
        }, pair.privateKey),
      },
    }), deny, `the true ${role} signer A cannot be its own CURRENT authority`);
    assert.equal(attack.reads(), verifiedReadCount,
      `the verified ${role} A native key must be reused without ever reading B`);
  }
  const valid = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  });
  assert.equal((await valid(f.input)).authorizesIo, false);
});

test("P2: genuine signed owner cutovers accept 100 to 128 covered compartments", async () => {
  for (const count of [100, 128]) {
    const covered = Array.from({ length: count }, (_, index) => id(index + 1)).sort();
    const f = await fixture({}, { coveredCompartments: covered });
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
      mappingAuthority: f.authority,
    });
    const result = await verify(f.input);
    assert.equal(result.authorizesIo, false);
    assert.equal(result.ownerMappingVerified, true);
    assert.equal(result.independentCustodyProven, false);
  }
  const overLimit = Array.from({ length: 129 }, (_, index) => id(index + 1)).sort();
  await assert.rejects(fixture({}, { coveredCompartments: overLimit }),
    /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/,
    "an unsigned or oversized corpus cannot silently raise the 128-compartment limit");
});

test("P2: native source key callback cannot erase a pinned device revocation", async () => {
  const f = await fixture();
  const revoked = f.sourceAuthority.pinnedDevicePolicy.revokedDeviceIds;
  revoked.push(f.source.deviceId);
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "real Node22 Ed25519 native handle required");
  const injected = Object.create(keys.source.publicKey);
  let reads = 0;
  Object.defineProperty(injected, handle, { get() {
    reads += 1;
    revoked.splice(0, revoked.length);
    return keys.source.publicKey[handle];
  } });
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
    zkAuthority: f.zkAuthority, mappingAuthority: f.authority,
  });
  assert.ok(reads > 0, "native callback must actually mutate caller policy");
  assert.equal(revoked.length, 0, "the input policy was actually poisoned");
  await assert.rejects(verify(f.input), deny,
    "a valid signed operation by previously revoked A remains denied after callback poisoning");
  const good = await fixture();
  const valid = createOwnerObjectMapVerifier({
    sourceAuthority: good.sourceAuthority, zkAuthority: good.zkAuthority,
    mappingAuthority: good.authority,
  });
  assert.equal((await valid(good.input)).ownerMappingVerified, true,
    "the same genuine Ed25519 A operation succeeds when never revoked");
});

test("P2: hostile CURRENT authority cannot erase noncooperative Set readback quota", async () => {
  const f = await fixture();
  const originalSize = Object.getOwnPropertyDescriptor(Set.prototype, "size");
  assert.ok(originalSize?.get && originalSize.configurable,
    "native Set.size descriptor must exist for the adversarial oracle");
  const calls = [];
  const authority = { ...f.authority, readCurrentHead: (challenge, { signal }) =>
    new Promise((resolve) => {
      calls.push({ challenge, signal, resolve });
      if (calls.length === 1) {
        // The first read was already added to the local/global Sets. A
        // hostile callback now replaces the inherited size getter so the
        // vulnerable next check sees zero occupied slots.
        Object.defineProperty(Set.prototype, "size", { configurable: true,
          get() { return 0; } });
      }
    }) };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: authority,
  }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
  try {
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
    assert.equal(calls.length, 1, "first genuine signed mapping reached the external adapter");
    assert.equal(calls[0].signal.aborted, true);
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
    assert.equal(calls.length, 1,
      "a timed-out, still-unsettled authority read must occupy its native slot");
  } finally {
    Object.defineProperty(Set.prototype, "size", originalSize);
    for (const call of calls) call.resolve(signedHead(f, call.challenge));
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
  }
});

test("P2: native key callback cannot invoke Promise.then cleanup before CURRENT read resolves", async () => {
  const f = await fixture();
  const originalThen = Promise.prototype.then;
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "real Ed25519 KeyObject native handle required");
  const injected = Object.create(keys.source.publicKey);
  let nativeReads = 0;
  Object.defineProperty(injected, handle, { get() {
    nativeReads += 1;
    Promise.prototype.then = function forgedThen(onFulfilled, onRejected) {
      // Parent attaches the accounting cleanup to a still-unsettled Promise
      // using a mutable .then lookup after this genuine KeyObject callback.
      if (typeof onFulfilled === "function"
        && Function.prototype.toString.call(onFulfilled).includes("NATIVE_SET_DELETE")) {
        onFulfilled();
      }
      return Reflect.apply(originalThen, this, [onFulfilled, onRejected]);
    };
    return keys.source.publicKey[handle];
  } });
  const outstanding = [];
  try {
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
      zkAuthority: f.zkAuthority,
      mappingAuthority: { ...f.authority, readCurrentHead: (challenge, { signal }) =>
        new Promise((resolve) => outstanding.push({ resolve, challenge, signal })) },
    }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
    assert.ok(nativeReads > 0, "native source key getter must install the mutation");
    assert.notEqual(Promise.prototype.then, originalThen,
      "the untrusted native getter must actually replace Promise.prototype.then");
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
    assert.equal(outstanding.length, 1, "first genuinely signed mapping reached real head adapter");
    assert.equal(outstanding[0].signal.aborted, true);
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
    assert.equal(outstanding.length, 1,
      "a malicious premature Promise.then callback cannot release unsettled read capacity");
  } finally {
    Promise.prototype.then = originalThen;
    for (const call of outstanding) call.resolve(signedHead(f, call.challenge));
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
  }
});

test("P2: cross-realm native Promise keeps its true outstanding read slot until settlement", async () => {
  const f = await fixture();
  const ForeignPromise = vm.runInNewContext("Promise");
  const calls = [];
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority,
      readCurrentHead: (challenge, { signal }) => new ForeignPromise((resolve) => {
        calls.push({ challenge, signal, resolve });
      }),
    },
  }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(calls.length, 1, "a cross-realm native Promise must reach the real adapter");
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(calls.length, 1,
    "a foreign unresolved native Promise cannot free its physical pending slot early");
  calls[0].resolve(signedHead(f, calls[0].challenge));
  for (let i = 0; i < 5; i += 1) await Promise.resolve();
  const fresh = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority, readCurrentHead: (challenge) =>
      new ForeignPromise((resolve) => resolve(signedHead(f, challenge))) },
  });
  assert.equal((await fresh(f.input)).authorizesIo, false,
    "settled genuine foreign-realm Ed25519 authority response remains supported");
});

test("P2: unsupported async thenable cannot free a still-running adapter read slot", async () => {
  const f = await fixture();
  let externalReads = 0;
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority, readCurrentHead: () => {
      externalReads += 1;
      const trulyRunningRead = new Promise(() => {});
      return { then(resolve) { void trulyRunningRead; void resolve; } };
    } },
  }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(externalReads, 1);
  await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  assert.equal(externalReads, 1,
    "a rejected unsupported thenable cannot manufacture a completed physical read");
});

test("P2: hostile Promise species cannot redirect native reactions or disable genuine signed head", async () => {
  const f = await fixture();
  const { newNativePromise, nativePromiseThen, nativePromiseRace } =
    require("../src/crypto/rootark-zk10-native-intrinsics-v1");
  const real = newNativePromise((resolve) => resolve(12));
  const original = Object.getOwnPropertyDescriptor(Promise, Symbol.species);
  assert.ok(original && original.configurable, "native Promise species must be poisonable");
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  });
  let next, race, signed;
  try {
    Object.defineProperty(Promise, Symbol.species, { configurable: true,
      get() { throw new Error("hostile Promise species getter"); } });
    next = nativePromiseThen.call(real, (value) => value);
    race = nativePromiseRace(real, next, newNativePromise(() => {}));
    signed = verify(f.input);
  } finally {
    Object.defineProperty(Promise, Symbol.species, original);
  }
  assert.equal(await next, 12);
  assert.equal(await race, 12);
  assert.equal((await signed).ownerMappingVerified, true,
    "real signed authority does not depend on poisoned global species");
});

test("P2: hostile Ed25519 getter cannot disable CURRENT head's native timeout", async () => {
  const f = await fixture();
  const nativeSetTimeout = setTimeout;
  const originalSetTimeout = global.setTimeout;
  const injected = Object.create(keys.source.publicKey);
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node22 real native Ed25519 handle is required");
  let getterReads = 0, poisonedTimerCalls = 0;
  Object.defineProperty(injected, handle, { get() {
    getterReads++;
    global.setTimeout = () => { poisonedTimerCalls++; return undefined; };
    return keys.source.publicKey[handle];
  } });
  const calls = [];
  let pending;
  try {
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
      zkAuthority: f.zkAuthority,
      mappingAuthority: { ...f.authority, readCurrentHead: (challenge, { signal }) =>
        new Promise((resolve) => calls.push({ resolve, challenge, signal })) },
    }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
    assert.ok(getterReads > 0, "genuine source key getter executed");
    pending = verify(f.input);
    const settled = await Promise.race([
      pending.then(() => "accepted", () => "denied"),
      new Promise((resolve) => nativeSetTimeout(() => resolve("deadline_missing"), 200)),
    ]);
    assert.equal(calls.length, 1, "external read was actually dispatched");
    assert.equal(settled, "denied",
      "a missing ambient setTimeout must never suppress the pinned 20ms deadline");
    assert.equal(calls[0].signal.aborted, true,
      "the real native AbortController must cancel expired work");
  } finally {
    global.setTimeout = originalSetTimeout;
    for (const call of calls) call.resolve(signedHead(f, call.challenge));
    if (pending) await Promise.race([pending.catch(() => {}),
      new Promise((resolve) => nativeSetTimeout(resolve, 150))]);
  }
  assert.equal(poisonedTimerCalls, 0,
    "never consult the replaced global setTimeout after source key callbacks");
});

test("P2: hostile Ed25519 getter cannot rewind the CURRENT head monotonic deadline", async () => {
  const f = await fixture();
  const clock = process.hrtime.bigint;
  const injected = Object.create(keys.source.publicKey);
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node22 real native Ed25519 handle is required");
  let getterReads = 0, actualReads = 0;
  Object.defineProperty(injected, handle, { get() {
    getterReads++;
    process.hrtime.bigint = () => 0n;
    return keys.source.publicKey[handle];
  } });
  let startedAt;
  try {
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
      zkAuthority: f.zkAuthority,
      mappingAuthority: { ...f.authority, readCurrentHead: (challenge) => {
        actualReads++;
        startedAt = Date.now();
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 45);
        return signedHead(f, challenge);
      } },
    }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
    assert.ok(getterReads > 0);
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  } finally { process.hrtime.bigint = clock; }
  assert.equal(actualReads, 1, "genuinely signed readback executed");
  assert.ok(Date.now() - startedAt >= 20, "external callback blocked longer than expiry");
});

test("P2: hostile Ed25519 getter cannot stretch CURRENT deadline by replacing global BigInt", async () => {
  const f = await fixture();
  const nativeBigInt = BigInt;
  const injected = Object.create(keys.source.publicKey);
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle);
  let getterReads = 0, changedCalls = 0, actualReads = 0;
  Object.defineProperty(injected, handle, { get() {
    getterReads += 1;
    global.BigInt = function poisonedBigInt(value) {
      if (value === 20) { changedCalls += 1; return 999999999999999999n; }
      return nativeBigInt(value);
    };
    return keys.source.publicKey[handle];
  } });
  try {
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
      zkAuthority: f.zkAuthority,
      mappingAuthority: { ...f.authority, readCurrentHead: (challenge) => {
        actualReads += 1;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 45);
        return signedHead(f, challenge);
      } },
    }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
  } finally { global.BigInt = nativeBigInt; }
  assert.ok(getterReads > 0 && actualReads === 1);
  assert.equal(changedCalls, 0,
    "untrusted global BigInt must never be consulted for the deadline");
});

test("P2: inherited poisoned Object.then cannot swallow CURRENT timeout settlement", async () => {
  const f = await fixture();
  const originalThen = Object.getOwnPropertyDescriptor(Object.prototype, "then");
  const readerCalls = [];
  let inheritedThenCalls = 0;
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority, readCurrentHead: (challenge) => {
      Object.defineProperty(Object.prototype, "then", { configurable: true,
        get() {
          if (this && Object.hasOwn(this, "settled")) {
            inheritedThenCalls += 1;
            return function neverSettleSentinel() {};
          }
          return undefined;
        },
      });
      return new Promise((resolve) => readerCalls.push({ resolve, challenge }));
    } },
  }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
  const pending = verify(f.input);
  try {
    const outcome = await Promise.race([
      pending.then(() => "accepted", () => "denied"),
      new Promise((resolve) => setTimeout(() => resolve("timeout_swallowed"), 200)),
    ]);
    assert.equal(outcome, "denied", "native deadline must settle despite poisoned Object.then");
  } finally {
    if (originalThen) Object.defineProperty(Object.prototype, "then", originalThen);
    else delete Object.prototype.then;
    for (const call of readerCalls) call.resolve(signedHead(f, call.challenge));
    await Promise.race([pending.catch(() => {}),
      new Promise((resolve) => setTimeout(resolve, 100))]);
  }
  assert.equal(inheritedThenCalls, 0,
    "settlement values must not inherit arbitrary Object.prototype.then");
});

test("P2: signed CURRENT head cannot be re-assimilated through inherited then after readback", async () => {
  const f = await fixture();
  const originalThen = Object.getOwnPropertyDescriptor(Object.prototype, "then");
  let trapReads = 0, genuineHead;
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority, readCurrentHead: (challenge) => {
      genuineHead = signedHead(f, challenge);
      // The native Promise already owns the genuine signed head BEFORE
      // its external callback poisons future ordinary-object then lookups.
      const settled = Promise.resolve(genuineHead);
      Object.defineProperty(Object.prototype, "then", { configurable: true,
        get() {
          if (this === genuineHead) {
            trapReads += 1;
            return function hangReassimilation() {};
          }
          return undefined;
        },
      });
      return settled;
    } },
  }, { headTimeoutMs: 1000, maxPendingHeadReads: 1 });
  const pending = verify(f.input);
  try {
    const outcome = await Promise.race([
      pending.then((value) => value.ownerMappingVerified === true ? "accepted" : "bad_result",
        () => "denied"),
      new Promise((resolve) => setTimeout(() => resolve("signed_head_hung"), 200)),
    ]);
    assert.equal(outcome, "accepted",
      "genuinely signed native readback must not hang at an extra async return boundary");
    assert.equal(trapReads, 0,
      "verified CURRENT head must be consumed without inherited then assimilation");
  } finally {
    if (originalThen) Object.defineProperty(Object.prototype, "then", originalThen);
    else delete Object.prototype.then;
    await Promise.race([pending.catch(() => {}),
      new Promise((resolve) => setTimeout(resolve, 100))]);
  }
});

test("P2: hostile Ed25519 getter cannot suppress actual caller AbortSignal cancellation", async () => {
  const f = await fixture();
  const caller = new AbortController();
  const nativeAbort = AbortController.prototype.abort;
  const nativeAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted");
  const originalAdd = EventTarget.prototype.addEventListener;
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle && nativeAborted?.get);
  const injected = Object.create(keys.source.publicKey);
  let getterReads = 0, forgedEventAdds = 0;
  Object.defineProperty(injected, handle, { get() {
    getterReads++;
    Object.defineProperty(AbortSignal.prototype, "aborted", {
      configurable: true, get() { return false; },
    });
    EventTarget.prototype.addEventListener = function ignoredAbort() {
      forgedEventAdds++;
    };
    return keys.source.publicKey[handle];
  } });
  const calls = [];
  let reached;
  const dispatched = new Promise((resolve) => { reached = resolve; });
  let pending;
  try {
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
      zkAuthority: f.zkAuthority,
      mappingAuthority: { ...f.authority,
        readCurrentHead: (challenge, { signal }) => new Promise((resolve) => {
          calls.push({ challenge, signal, resolve });
          reached();
        }) },
    }, { headTimeoutMs: 1000, maxPendingHeadReads: 1 });
    assert.ok(getterReads > 0, "genuine native Ed25519 handle getter executed");
    pending = verify(f.input, { signal: caller.signal });
    await withinHeadDeadline(dispatched);
    Reflect.apply(nativeAbort, caller, []);
    assert.equal(Reflect.apply(nativeAborted.get, caller.signal, []), true,
      "actual caller AbortSignal is cancelled despite poisoned prototype getter");
    calls[0].resolve(signedHead(f, calls[0].challenge));
    await withinHeadDeadline(assert.rejects(pending, deny), 500);
    assert.equal(forgedEventAdds, 0, "native abort listener is never intercepted");
  } finally {
    EventTarget.prototype.addEventListener = originalAdd;
    Object.defineProperty(AbortSignal.prototype, "aborted", nativeAborted);
    for (const call of calls) call.resolve(signedHead(f, call.challenge));
    if (pending) await Promise.race([pending.catch(() => {}),
      new Promise((resolve) => setTimeout(resolve, 100))]);
  }
});

test("P2: hostile Ed25519 getter cannot prevent native timeout abort on external read", async () => {
  const f = await fixture();
  const nativeAbort = AbortController.prototype.abort;
  const nativeAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, "aborted").get;
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle);
  const injected = Object.create(keys.source.publicKey);
  let getterReads = 0, forgedAbortCalls = 0;
  Object.defineProperty(injected, handle, { get() {
    getterReads++;
    AbortController.prototype.abort = function ignoredAbort() { forgedAbortCalls++; };
    return keys.source.publicKey[handle];
  } });
  const calls = [];
  try {
    const verify = createOwnerObjectMapVerifier({
      sourceAuthority: { ...f.sourceAuthority, provisionerPublicKey: injected },
      zkAuthority: f.zkAuthority,
      mappingAuthority: { ...f.authority,
        readCurrentHead: (challenge, { signal }) =>
          new Promise((resolve) => calls.push({ resolve, challenge, signal })) },
    }, { headTimeoutMs: 20, maxPendingHeadReads: 1 });
    assert.ok(getterReads > 0);
    await withinHeadDeadline(assert.rejects(verify(f.input), deny));
    assert.equal(calls.length, 1, "external adapter must actually be reached");
    assert.equal(Reflect.apply(nativeAborted, calls[0].signal, []), true,
      "the real native AbortController must abort after timeout");
    assert.equal(forgedAbortCalls, 0, "native abort cannot dispatch to poisoned prototype method");
  } finally {
    AbortController.prototype.abort = nativeAbort;
    for (const call of calls) call.resolve(signedHead(f, call.challenge));
    for (let i = 0; i < 5; i += 1) await Promise.resolve();
  }
});

test("P2: pinned native Set add/delete/size ignore later same-realm prototype changes", () => {
  const { newNativeSet, setAdd, setDelete, setSize } =
    require("../src/crypto/rootark-zk10-native-intrinsics-v1");
  const originalAdd = Set.prototype.add;
  const originalDelete = Set.prototype.delete;
  const originalSize = Object.getOwnPropertyDescriptor(Set.prototype, "size");
  try {
    Set.prototype.add = function forgedAdd() { return this; };
    Set.prototype.delete = function forgedDelete() { return false; };
    Object.defineProperty(Set.prototype, "size", { configurable: true, get() { return 0; } });
    const native = newNativeSet();
    const token = {};
    setAdd.call(native, token);
    assert.equal(setSize.call(native), 1, "native add and size use real internal slots");
    assert.equal(setDelete.call(native, token), true);
    assert.equal(setSize.call(native), 0, "native delete reclaims the original slot");
  } finally {
    Set.prototype.add = originalAdd;
    Set.prototype.delete = originalDelete;
    Object.defineProperty(Set.prototype, "size", originalSize);
  }
});

test("P2: signed ZK target and 256-slot Merkle proof retain invocation-time bytes across async source verification", async () => {
  const f = await fixture();
  const verifier = () => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  });
  const originalProof = f.proof.siblings.slice();
  const alteredTarget = { ...f.target,
    ciphertext: Buffer.from("unsubmitted-foreign-ciphertext").toString("base64url") };
  const alteredProof = originalProof.slice();
  alteredProof[0] = hex(9);
  assert.notEqual(alteredProof[0], originalProof[0]);
  const pending = verifier()({ ...f.input, zkObject: alteredTarget,
    zkMembershipProof: alteredProof });
  Object.assign(alteredTarget, f.target);
  alteredProof.splice(0, alteredProof.length, ...originalProof);
  await assert.rejects(pending, deny,
    "a caller cannot replace originally invalid signed target/proof after first await");

  const proofOnly = originalProof.slice();
  proofOnly[0] = hex(10);
  assert.notEqual(proofOnly[0], originalProof[0]);
  const pendingProof = verifier()({ ...f.input, zkMembershipProof: proofOnly });
  proofOnly.splice(0, proofOnly.length, ...originalProof);
  await assert.rejects(pendingProof, deny,
    "an invalid proof alone cannot be repaired by a late caller mutation");
  const accepted = await verifier()(f.input);
  assert.equal(accepted.ownerMappingVerified, true,
    "genuinely Ed25519-signed and unmodified 256-sibling evidence remains valid");
  assert.equal(accepted.authorizesIo, false);
});

test("P2: late hostile Array iterator cannot substitute signed 256-slot Merkle proof", async () => {
  const f = await fixture();
  const genuineSiblings = f.proof.siblings.slice();
  const invalidSiblings = genuineSiblings.slice();
  invalidSiblings[0] = hex(11);
  assert.notEqual(invalidSiblings[0], genuineSiblings[0]);
  const verifier = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  });
  const pending = verifier({ ...f.input, zkMembershipProof: invalidSiblings });
  const originalIterator = Array.prototype[Symbol.iterator];
  let forgedReads = 0;
  Array.prototype[Symbol.iterator] = function hostileSiblingIterator() {
    if (this.length === 256 && this[0] === invalidSiblings[0]) {
      forgedReads += 1;
      return Reflect.apply(originalIterator, genuineSiblings, []);
    }
    return Reflect.apply(originalIterator, this, []);
  };
  try {
    await assert.rejects(pending, deny,
      "a poisoned global iterator must not replace the actual 256 bound sibling bytes");
  } finally {
    Array.prototype[Symbol.iterator] = originalIterator;
  }
  // This oracle is intentionally conditional: a native-index verifier never
  // invokes the hostile iterator, while a vulnerable for-of verifier does.
  assert.ok(forgedReads <= 1, "no repeated trusted proof reads via caller iterator");
  const valid = await createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  })(f.input);
  assert.equal(valid.zkSignedInventoryMembershipVerified, true);
});

test("P2: invalid source provision is rejected before executing caller-owned KeyObject getters", async () => {
  const f = await fixture();
  const handle = Object.getOwnPropertySymbols(keys.source.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node22 physical native key required");
  const hostile = Object.create(keys.source.publicKey);
  let reads = 0;
  Object.defineProperty(hostile, handle, { get() {
    reads += 1;
    return keys.source.publicKey[handle];
  } });
  const badIdentity = { ...identity,
    accountId: "33333333-3333-4333-8333-333333333333" };
  assert.throws(() => createOwnerObjectMapVerifier({
    sourceAuthority: { ...f.sourceAuthority, identity: badIdentity,
      provisionerPublicKey: hostile },
    zkAuthority: f.zkAuthority, mappingAuthority: f.authority,
  }), deny);
  assert.equal(reads, 0,
    "an invalid signed source identity must fail before any attacker-owned key callback");
});

test("P2 review: owner map for provisioned compartment A cannot certify device-signed operation B", async () => {
  const f = await fixture();
  // Rebuild the whole encrypted operation with real compartment B AAD; only
  // changing compartmentId on A would fail an unrelated integrity check.
  const foreign = protocol.createOperation({
    operation: "create", objectId: f.source.objectId, fileId: f.source.fileId,
    versionId: f.source.versionId, operationId: f.source.operationId,
    deviceId: f.source.deviceId, compartmentId: "foreign-compartment",
    keyEpoch: f.source.keyEpoch, revision: f.source.revision,
    metadata: { path: "encrypted.fixture" }, fileKey: Buffer.alloc(32, 8),
    plaintext: Buffer.from("synthetic-sync-v2-data"),
  });
  foreign.authorization = await createAuthorizationProof(foreign, {
    privateKey: keys.device.privateKey, publicKey: b64(keys.device),
    username: identity.username, expiresAt: Date.now() + 600_000,
  });
  const { verifyHistoricalAuthorizationProof } =
    require("../sync-client/rootark-sync-authorization");
  await verifyHistoricalAuthorizationProof(foreign.authorization, foreign,
    f.sourceAuthority.pinnedDevicePolicy);
  assert.notEqual(foreign.compartmentId, identity.compartmentId);
  assert.equal(f.payload.sync_compartment_id, identity.compartmentId);
  // Owner-signed A map and genuine external CURRENT both attest exact
  // ciphertext B/identifiers. The only invalid pairing is source compartment.
  const mapB = signOwnerObjectMap({ ...f.payload,
    sync_ciphertext_sha256: crypto.createHash("sha256")
      .update(Buffer.from(foreign.ciphertext, "base64url")).digest("hex"),
  }, keys.owner.privateKey);
  const mapBDigest = digestOwnerObjectMap(mapB);
  const authorityB = { ...f.authority, readCurrentHead: (challenge) =>
    signCurrentMappingHead({
      type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
      sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
      mapping_sequence: f.payload.mapping_sequence, mapping_digest: mapBDigest,
    }, keys.authority.privateKey),
  };
  const verify = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: authorityB,
  });
  await assert.rejects(verify({ ...f.input, sourceOperation: foreign, ownerMapping: mapB }), deny,
    "genuine device-signed B may not be mapped into owner-provisioned compartment A");
  const positive = await createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  })(f.input);
  assert.equal(positive.authorizesIo, false, "valid compartment A remains nonauthorizing");
});

test("P2 review: native authority KeyObject getter cannot rewind independently retained mapping floor", async () => {
  const f = await fixture();
  const floor = { sequence: 6, digest: hex(99) };
  const initialFloor = { ...floor };
  const handle = Object.getOwnPropertySymbols(keys.authority.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "physical native Ed25519 KeyObject handle required");
  const keyWithGetter = Object.create(keys.authority.publicKey);
  let callbacks = 0;
  Object.defineProperty(keyWithGetter, handle, { get() {
    callbacks++;
    floor.sequence = 4;
    floor.digest = hex(77);
    return keys.authority.publicKey[handle];
  } });
  const verifier = createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: { ...f.authority, independentlyRetainedFloor: floor,
      pinnedPublicKey: keyWithGetter },
  });
  assert.ok(callbacks > 0, "attacker-controlled native getter ran");
  assert.deepEqual(initialFloor, { sequence: 6, digest: hex(99) },
    "the original trusted minimum must be strictly higher than mapping sequence 5");
  await assert.rejects(verifier(f.input), deny,
    "a valid sequence-5 Ed25519 mapping cannot rewind original floor sequence 6");
  assert.deepEqual(floor, { sequence: 4, digest: hex(77) },
    "the callback really altered the caller-owned floor; only the detached snapshot denied rollback");
  const valid = await createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: f.authority,
  })(f.input);
  assert.equal(valid.authorizesIo, false, "genuine floor-4 mapping-5 still works");
});

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

test("P2 device Ed25519 ciphertext A must not authorize independently owner-signed ciphertext B after a native key callback", async () => {
  const f = await fixture();
  const ciphertextB = Buffer.from("different ciphertext B").toString("base64url");
  const envelopeB = { ...f.source, ciphertext: ciphertextB };
  const signedB = signOwnerObjectMap({
    ...f.payload,
    sync_ciphertext_sha256: crypto.createHash("sha256")
      .update(Buffer.from(ciphertextB, "base64url")).digest("hex"),
  }, keys.owner.privateKey);
  const digestB = digestOwnerObjectMap(signedB);
  const authorityB = { ...f.authority,
    readCurrentHead: (challenge) => signCurrentMappingHead({
      type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
      sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
      mapping_sequence: f.payload.mapping_sequence, mapping_digest: digestB,
    }, keys.authority.privateKey),
  };
  const candidate = { ...f.input, sourceOperation: envelopeB, ownerMapping: signedB };
  const create = (authority) => createOwnerObjectMapVerifier({
    sourceAuthority: f.sourceAuthority, zkAuthority: f.zkAuthority,
    mappingAuthority: authority,
  });
  await assert.rejects(create(authorityB)(candidate), deny,
    "without a hostile iterator the genuine device signature for A rejects ciphertext B");

  const nativeHandle = Object.getOwnPropertySymbols(keys.authority.publicKey)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(nativeHandle, "Node 22 native Ed25519 handle is required");
  const hostileAuthorityKey = Object.create(keys.authority.publicKey);
  const originalIterator = Array.prototype[Symbol.iterator];
  let getterReads = 0;
  let skippedChecks = 0;
  Object.defineProperty(hostileAuthorityKey, nativeHandle, { get() {
    getterReads += 1;
    Array.prototype[Symbol.iterator] = function*() {
      if (this.length === 16 && this[0] === "protocolVersion"
        && this[13] === "ciphertextDigest") {
        skippedChecks += 1;
        return;
      }
      yield* Reflect.apply(originalIterator, this, []);
    };
    return keys.authority.publicKey[nativeHandle];
  } });
  try {
    await assert.rejects(create({ ...authorityB, pinnedPublicKey: hostileAuthorityKey })(candidate),
      deny, "native owner-map key callback cannot suppress ciphertext A/B device binding");
  } finally {
    Array.prototype[Symbol.iterator] = originalIterator;
  }
  assert.ok(getterReads > 0, "genuine KeyObject callback was exercised");
  assert.equal(skippedChecks, 0, "authorization comparison must not use poisoned Array iterator");
  assert.equal((await create(f.authority)(f.input)).authorizesIo, false,
    "genuine owner and device Ed25519 authorization still passes");
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

test("P2 real Ed25519 owner map and live revoked device cannot bypass post-await Array.includes", async () => {
  const f = await fixture();
  const revoked = { username: identity.username,
    trustedDevicePublicKeys: { "source-device-4": b64(keys.device) },
    revokedDeviceIds: ["source-device-4"] };
  const originalIncludes = Array.prototype.includes;
  let callbackRan = false;
  const authority = { ...f.authority, readCurrentHead: async (...args) => {
    const signedHead = await f.authority.readCurrentHead(...args);
    Array.prototype.includes = function(value, ...rest) {
      if (value === "source-device-4" && this.length === 1
        && this[0] === "source-device-4") return false;
      return Reflect.apply(originalIncludes, this, [value, ...rest]);
    };
    callbackRan = true;
    return signedHead;
  } };
  const verifier = createOwnerObjectMapVerifier({
    sourceAuthority: { ...f.sourceAuthority, currentDevicePolicy: () => revoked },
    zkAuthority: f.zkAuthority, mappingAuthority: authority,
  });
  try {
    await assert.rejects(verifier(f.input), deny);
  } finally { Array.prototype.includes = originalIncludes; }
  assert.equal(callbackRan, true, "poison happens inside async signed head callback");
  const valid = await createOwnerObjectMapVerifier({ sourceAuthority: f.sourceAuthority,
    zkAuthority: f.zkAuthority, mappingAuthority: f.authority })(f.input);
  assert.equal(valid.status, "VERIFIED_SIGNED_SYNC_V2_ZK10_MAPPING_NONAUTHORIZING");
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

test("P2: inherited KeyObject kHandle cannot splice owner A's signature onto claimed SPKI B", () => {
  const ownerA = crypto.generateKeyPairSync("ed25519");
  const claimedB = crypto.generateKeyPairSync("ed25519");
  const next = crypto.generateKeyPairSync("ed25519");
  const handle = Object.getOwnPropertySymbols(ownerA.publicKey)
    .find((symbol) => String(symbol) === "Symbol(kHandle)");
  assert.ok(handle, "Node 22 must expose a physical kHandle to exercise this exploit");
  const rogueRoot = Object.create(ownerA.publicKey);
  assert.ok(rogueRoot instanceof crypto.KeyObject);
  const seen = [];
  Object.defineProperty(rogueRoot, handle, { get() {
    // Native algorithm/type reads A, SPKI export reads B, signature verify
    // reads A again. Repeated references to the same JS object are NOT a pin.
    const keyPair = seen.length === 1 ? claimedB : ownerA;
    seen.push(keyPair === claimedB ? "B" : "A");
    return keyPair.publicKey[handle];
  } });
  const signRotation = (claimedSpki) => {
    const body = {
      type: "rootark-zk10-owner-rotation/v1",
      immutable_account_id: immutableId,
      generation: 1, from_spki_sha256: claimedSpki,
      next_public_key: b64(next), previous_rotation_digest: null,
    };
    const signedBytes = Buffer.concat([
      Buffer.from("Root.ark/zk10/owner-rotation/v1\0"),
      Buffer.from(JSON.stringify(body), "utf8"),
    ]);
    return { ...body,
      signature_from: crypto.sign(null, signedBytes, ownerA.privateKey).toString("base64url"),
      signature_next: crypto.sign(null, signedBytes, next.privateKey).toString("base64url"),
    };
  };
  // Compute A's genuine SPKI hash without pre-warming its cached asymmetric
  // metadata, which otherwise changes the exploit's native getter sequence.
  const ownerAHash = crypto.createHash("sha256")
    .update(crypto.createPublicKey(ownerA.privateKey)
      .export({ type: "spki", format: "der" })).digest("hex");
  const claimedBHash = spkiHash(claimedB.publicKey);
  assert.notEqual(ownerAHash, claimedBHash);
  assert.throws(() => verifyOwnerRotationKeys([signRotation(claimedBHash)],
    rogueRoot, immutableId), /ZK10_ACCOUNT_CUTOVER_UNVERIFIED/,
  "signed rotation from real owner A must never authenticate claimed SPKI B");
  assert.ok(seen.length >= 2, `native kHandle splicing was exercised: ${seen.join(",")}`);
  const genuine = verifyOwnerRotationKeys(
    [signRotation(ownerAHash)], ownerA.publicKey, immutableId);
  assert.equal(genuine.length, 2, "legitimate distinct signed rotation remains valid");
  assert.equal(crypto.KeyObject.prototype.equals.call(genuine[1], next.publicKey), true);
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

test("P2: physical owner kHandle cannot redirect signed mapping A digest onto independently retained B", async () => {
  const f = await fixture();
  const otherMapping = signOwnerObjectMap({
    ...f.payload, nonce: Buffer.alloc(32, 77).toString("base64url"),
  }, keys.owner.privateKey);
  const otherDigest = digestOwnerObjectMap(otherMapping);
  assert.notEqual(f.mappingDigest, otherDigest, "both mappings must be genuinely distinct owner signatures");
  const handle = Object.getOwnPropertySymbols(keys.owner.publicKey)
    .find((symbol) => String(symbol) === "Symbol(kHandle)");
  assert.ok(handle, "the native key handle is required for the physical attack");
  const root = Object.create(keys.owner.publicKey);
  const hashPrototype = Object.getPrototypeOf(crypto.createHash("sha256"));
  const original = Object.getOwnPropertyDescriptor(hashPrototype, "digest");
  let armed = false;
  let intercepted = 0;
  let readbacks = 0;
  Object.defineProperty(root, handle, { get() {
    if (!armed) {
      armed = true;
      Object.defineProperty(hashPrototype, "digest", { ...original, value(encoding) {
        const digest = original.value.call(this, encoding);
        if (encoding === "hex" && digest === f.mappingDigest) {
          intercepted++;
          return otherDigest;
        }
        return digest;
      } });
    }
    return keys.owner.publicKey[handle];
  } });
  try {
    const verifier = createOwnerObjectMapVerifier({
      sourceAuthority: f.sourceAuthority,
      zkAuthority: { ...f.zkAuthority, ownerRootPublicKey: root },
      mappingAuthority: {
        ...f.authority,
        independentlyRetainedFloor: { sequence: 5, digest: otherDigest },
        readCurrentHead: async (challenge) => {
          readbacks++;
          return signCurrentMappingHead({
            type: "rootark-zk10-sync-v2-current-map-head/v1", challenge,
            sync_account_id: identity.accountId, zk_immutable_account_id: immutableId,
            mapping_sequence: f.payload.mapping_sequence, mapping_digest: otherDigest,
          }, keys.authority.privateKey);
        },
      },
    });
    await assert.rejects(verifier(f.input), deny,
      "signed mapping A must not match retained digest B even if an attacker poisons Hash.digest");
    assert.equal(armed, true, "owner KeyObject getter must have installed the poison");
    assert.equal(intercepted, 0, "mapping hashing must bypass a poisoned Hash prototype");
    assert.equal(readbacks, 0, "mismatched retained digest must fail before an external head read");
  } finally {
    Object.defineProperty(hashPrototype, "digest", original);
  }
});
