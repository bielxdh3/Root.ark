"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const protocol = require("../sync-client/rootark-sync-protocol");
const { DOMAIN: OWNER_PROVISION_DOMAIN, verifyPinnedAtomicOwnerProvision } =
  require("../sync-client/rootark-sync-atomic-owner-provision");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");
const { trustedAtomicBatchWitnessOptions,
  assertPinnedStrictLocalDeviceIdentity } = require("../sync-client/rootark-sync-v2");
const DENIED_UNTRUSTED_WITNESS = /(?:independently pinned readback and external CAS floor|immutable canonical owner authority options|owner provision is not independently authenticated)/;
const sha256 = (value) => crypto.createHash("sha256").update(value, "utf8").digest("hex");
const ownerTestSigners = new WeakMap();

function trustedFixture() {
  const keys = crypto.generateKeyPairSync("ed25519");
  const casKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const identity = {
    accountId: "ca628a48-765e-4b0d-a746-3bc67d53e3b1",
    storeId: "d95a7868-857c-4213-a5ad-3c10374b4fa7",
    username: "alice", compartmentId: "private",
  };
  const witnessSpki = keys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const casSpki = casKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const statement = { type: "atomic-owner-provisioning", version: 1, scope: "alice:store",
    ...identity, witnessSpki, casSpki, sequence: 1 };
  const ownerProvisioning = { statement, signature: crypto.sign(null,
    Buffer.from(OWNER_PROVISION_DOMAIN + protocol.canonicalJson(statement)),
    ownerKeys.privateKey).toString("base64url") };
  const supplied = {
    pinnedPublicKey: keys.publicKey.export({ type: "spki", format: "der" }),
    scope: "alice:store",
    ownerIdentity: identity,
    readback: async () => null,
    casPinnedPublicKey: casKeys.publicKey.export({ type: "spki", format: "der" }),
    casReadback: async () => null,
    ownerProvisionerPublicKey: ownerKeys.publicKey.export({ type: "spki", format: "der" }),
    ownerProvisioning,
    ownerProvisionDigest: sha256(OWNER_PROVISION_DOMAIN + protocol.canonicalJson(ownerProvisioning)),
  };
  ownerTestSigners.set(supplied, ownerKeys.privateKey);
  return supplied;
}

function resignOwnerCertificate(base, statement) {
  const signer = ownerTestSigners.get(base);
  assert.ok(signer, "test must use the ORIGINAL trusted provisioner signer");
  const ownerProvisioning = { statement, signature: crypto.sign(null,
    Buffer.from(OWNER_PROVISION_DOMAIN + protocol.canonicalJson(statement)),
    signer).toString("base64url") };
  return { ...base, ownerProvisioning,
    ownerProvisionDigest: sha256(OWNER_PROVISION_DOMAIN + protocol.canonicalJson(ownerProvisioning)) };
}

test("P2: authentic owner provision cannot certify one physical Ed25519 witness as CAS", () => {
  const base = trustedFixture();
  const witness = crypto.createPublicKey({ key: base.pinnedPublicKey, format: "der", type: "spki" });
  const sameCas = crypto.createPublicKey({ key: base.pinnedPublicKey, format: "der", type: "spki" });
  const coverSpki = crypto.generateKeyPairSync("ed25519").publicKey
    .export({ type: "spki", format: "der" });
  const nativeEquals = crypto.KeyObject.prototype.equals;
  assert.equal(nativeEquals.call(witness, sameCas), true, "same native material, independent JS objects");
  const withCasSpki = (casSpki) => resignOwnerCertificate(base, {
    ...base.ownerProvisioning.statement, casSpki,
  });
  const makeDirect = (owner, cas) => verifyPinnedAtomicOwnerProvision({
    identity: owner.ownerIdentity, scope: owner.scope,
    provisionerPublicKey: owner.ownerProvisionerPublicKey,
    witnessPublicKey: witness, casPublicKey: cas,
    provisioning: owner.ownerProvisioning, expectedDigest: owner.ownerProvisionDigest,
  });
  const makeEngine = (owner) => {
    const configured = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: owner }, true);
    return new SyncEngine({ ...configured,
      adapter: { list: async () => ({ objects: [] }), push: async () => null },
    });
  };
  const makeDirectEngine = (owner) => new SyncEngine({
    adapter: { list: async () => ({ objects: [] }), push: async () => null },
    atomicBatchWitnessPublicKey: owner.pinnedPublicKey,
    atomicBatchCasFloorPublicKey: owner.casPinnedPublicKey,
    atomicBatchWitnessReadback: owner.readback,
    atomicBatchCasFloorReadback: owner.casReadback,
    atomicBatchWitnessScope: owner.scope,
    atomicBatchOwnerIdentity: owner.ownerIdentity,
    atomicBatchOwnerProvisionerPublicKey: owner.ownerProvisionerPublicKey,
    atomicBatchOwnerProvisioning: owner.ownerProvisioning,
    atomicBatchOwnerProvisionDigest: owner.ownerProvisionDigest,
  });
  // Genuine independent roles and a valid externally pinned signed digest work.
  const distinct = withCasSpki(base.ownerProvisioning.statement.casSpki);
  assert.ok(makeDirect(distinct, base.casPinnedPublicKey));
  const goodEngine = makeEngine(distinct);
  assert.equal(crypto.KeyObject.prototype.equals.call(goodEngine.atomicBatchWitnessPublicKey,
    goodEngine.atomicBatchCasFloorPublicKey), false);
  assert.ok(makeDirectEngine(distinct));
  assert.ok(makeDirectEngine({ ...distinct,
    pinnedPublicKey: base.pinnedPublicKey.toString("base64url"),
    casPinnedPublicKey: base.casPinnedPublicKey.toString("base64url"),
    ownerProvisionerPublicKey: base.ownerProvisionerPublicKey.toString("base64url") }),
  "legacy canonical base64url pins remain supported alongside raw DER buffers");
  const unmasked = withCasSpki(base.ownerProvisioning.statement.witnessSpki);
  assert.throws(() => makeDirect(unmasked, sameCas), { code: "authorization_required" });
  assert.throws(() => makeEngine({ ...unmasked, pinnedPublicKey: witness,
    casPinnedPublicKey: sameCas }), { code: "authorization_required" });
  assert.throws(() => makeDirectEngine({ ...unmasked, pinnedPublicKey: witness,
    casPinnedPublicKey: sameCas }), { code: "authorization_required" });
  // Same native key, but fake CAS instance .export claims an unrelated SPKI;
  // this formerly passed BOTH the certificate verifier and SyncEngine.
  Object.defineProperty(sameCas, "export", { value: () => coverSpki });
  const masked = withCasSpki(coverSpki.toString("base64url"));
  assert.throws(() => makeDirect(masked, sameCas), { code: "authorization_required" });
  assert.throws(() => makeEngine({ ...masked, pinnedPublicKey: witness,
    casPinnedPublicKey: sameCas }), { code: "authorization_required" });
  assert.throws(() => makeDirectEngine({ ...masked, pinnedPublicKey: witness,
    casPinnedPublicKey: sameCas }), { code: "authorization_required" });

  // A genuinely signed provisioning statement also cannot make the SOURCE
  // owner/provisioner itself impersonate EITHER of its two independent roles.
  for (const [role, field] of [["witness", "witnessSpki"], ["cas", "casSpki"]]) {
    const ownerAsRole = crypto.createPublicKey({ key: base.ownerProvisionerPublicKey,
      format: "der", type: "spki" });
    Object.defineProperty(ownerAsRole, "export", { value: () => coverSpki });
    const signed = resignOwnerCertificate(base, {
      ...base.ownerProvisioning.statement, [field]: coverSpki.toString("base64url"),
    });
    const overridden = { ...signed,
      [role === "witness" ? "pinnedPublicKey" : "casPinnedPublicKey"]: ownerAsRole };
    assert.throws(() => makeDirectEngine(overridden), { code: "authorization_required" },
      `native provisioner and ${role} identity must be pairwise distinct`);
    assert.throws(() => makeEngine(overridden), { code: "authorization_required" });
  }

  // Shadowed instance metadata must not reject truly DISTINCT native keys.
  const independentCas = crypto.createPublicKey({ key: base.casPinnedPublicKey,
    format: "der", type: "spki" });
  const independentProvisioner = crypto.createPublicKey({ key: base.ownerProvisionerPublicKey,
    format: "der", type: "spki" });
  for (const key of [witness, independentCas, independentProvisioner]) {
    Object.defineProperties(key, {
      type: { value: "private" }, asymmetricKeyType: { value: "rsa" },
      export: { value: () => { throw Error("caller export must never execute"); } },
    });
  }
  const independent = { ...distinct, pinnedPublicKey: witness,
    casPinnedPublicKey: independentCas, ownerProvisionerPublicKey: independentProvisioner };
  assert.ok(verifyPinnedAtomicOwnerProvision({ identity: independent.ownerIdentity,
    scope: independent.scope, provisionerPublicKey: independentProvisioner,
    witnessPublicKey: witness, casPublicKey: independentCas,
    provisioning: independent.ownerProvisioning, expectedDigest: independent.ownerProvisionDigest }));
  const accepted = makeEngine(independent);
  assert.equal(nativeEquals.call(accepted.atomicBatchWitnessPublicKey,
    accepted.atomicBatchCasFloorPublicKey), false);
  assert.notEqual(accepted.atomicBatchCasFloorPublicKey, independentCas,
    "engine retains a canonical native clone, not caller's mutable object");

  assert.throws(() => makeEngine({ ...distinct,
    casPinnedPublicKey: new Proxy(independentCas, {}) }),
  { code: "authorization_required" });
});

test("P2: inherited witness key getter cannot retarget canonical owner A bytes to certify identity B", () => {
  const base = trustedFixture();
  const original = base.ownerProvisioning;
  const alteredIdentity = { ...base.ownerIdentity, username: "mallory" };
  const forged = { ...original, statement: {
    ...original.statement, username: alteredIdentity.username,
  } };
  assert.notEqual(forged.statement.username, original.statement.username);
  assert.notEqual(protocol.canonicalJson(forged), protocol.canonicalJson(original));
  assert.equal(crypto.createHash("sha256").update(
    OWNER_PROVISION_DOMAIN + protocol.canonicalJson(original)).digest("hex"),
  base.ownerProvisionDigest, "independently pinned digest belongs to signed owner A");

  const witness = crypto.createPublicKey({ key: base.pinnedPublicKey,
    format: "der", type: "spki" });
  const nativeHandle = Object.getOwnPropertySymbols(witness)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(nativeHandle, "Node22 native-handle getter required");
  const inherited = Object.create(witness);
  const saved = protocol.canonicalJson;
  let getterReads = 0, retargetedBytes = 0;
  Object.defineProperty(inherited, nativeHandle, { get() {
    getterReads++;
    protocol.canonicalJson = (value) => {
      if (value?.type === "atomic-owner-provisioning"
        && value.username === alteredIdentity.username) {
        retargetedBytes++;
        return saved(original.statement);
      }
      if (value?.statement?.username === alteredIdentity.username
        && value.signature === original.signature) {
        retargetedBytes++;
        return saved(original);
      }
      return saved(value);
    };
    return witness[nativeHandle];
  } });
  try {
    assert.throws(() => verifyPinnedAtomicOwnerProvision({
      identity: alteredIdentity, scope: base.scope,
      provisionerPublicKey: base.ownerProvisionerPublicKey,
      witnessPublicKey: inherited, casPublicKey: base.casPinnedPublicKey,
      provisioning: forged, expectedDigest: base.ownerProvisionDigest,
    }), { code: "authorization_required" },
    "signed owner A cannot authenticate unowned identity B with retained digest A");
  } finally { protocol.canonicalJson = saved; }
  assert.ok(getterReads > 0, "genuine inherited KeyObject handle getter executed");
  assert.equal(retargetedBytes, 0, "authority does not dispatch to mutable protocol export after getter");
  assert.ok(verifyPinnedAtomicOwnerProvision({
    identity: base.ownerIdentity, scope: base.scope,
    provisionerPublicKey: base.ownerProvisionerPublicKey,
    witnessPublicKey: base.pinnedPublicKey, casPublicKey: base.casPinnedPublicKey,
    provisioning: original, expectedDigest: base.ownerProvisionDigest,
  }), "legitimate signed A still verifies under independent pinned digest A");
});

test("atomic witness accepts a pinned Ed25519 KeyObject and retains canonical native material", () => {
  // PR236 additionally requires owner-signed provision and a separate CAS
  // floor. Preserve that full authority chain while testing KeyObject input.
  const witness = trustedFixture();
  const publicKey = crypto.createPublicKey({ key: witness.pinnedPublicKey,
    format: "der", type: "spki" });
  witness.pinnedPublicKey = publicKey;
  const configured = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: witness }, true);
  const makeEngine = (atomicBatchWitnessPublicKey) => new SyncEngine({
    ...configured,
    adapter: { push: async () => null, list: async () => [] },
    atomicBatchWitnessPublicKey,
  });
  const held = makeEngine(configured.atomicBatchWitnessPublicKey).atomicBatchWitnessPublicKey;
  assert.notEqual(held, publicKey, "never retain caller-owned mutable KeyObject");
  assert.equal(crypto.KeyObject.prototype.equals.call(held, publicKey), true);
  assert.equal(makeEngine(publicKey.export({ type: "spki", format: "der" }))
    .atomicBatchWitnessPublicKey.asymmetricKeyType, "ed25519");
  assert.throws(() => makeEngine(crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048 }).publicKey), /must be an Ed25519 public key/);
});

test("standalone Sync v2 keeps remote atomic witness disabled without external injection", () => {
  assert.deepEqual(trustedAtomicBatchWitnessOptions({}, false), {});
  assert.deepEqual(trustedAtomicBatchWitnessOptions({}, true), {});
});

test("config-only or legacy admission cannot enable the atomic batch witness", () => {
  const trusted = trustedFixture();
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: trusted,
  }, false), DENIED_UNTRUSTED_WITNESS);
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: null,
  }, true), DENIED_UNTRUSTED_WITNESS);
});

test("external atomic witness requires a complete independent key, scope and readback", () => {
  const base = trustedFixture();
  for (const changed of [
    { readback: null }, { pinnedPublicKey: null }, { scope: "../unsafe" },
    { scope: "alice:store", remotePhysicalDurable: true },
    { casReadback: null }, { casPinnedPublicKey: null },
    { ownerProvisioning: null }, { ownerProvisionerPublicKey: null },
    { ownerProvisionDigest: null }, { ownerProvisionDigest: "0".repeat(64) },
    { ownerIdentity: null },
    { ownerIdentity: { ...trustedFixture().ownerIdentity, storeId: "not-a-uuid" } },
    { ownerIdentity: { ...trustedFixture().ownerIdentity, accountId: "not-a-uuid" } },
    { ownerIdentity: { ...trustedFixture().ownerIdentity, extra: true } },
  ]) {
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: { ...trustedFixture(), ...changed },
    }, true), DENIED_UNTRUSTED_WITNESS);
  }
  // These are AUTHENTIC statements signed with the original trusted root,
  // with a matching updated digest. Denial cannot be attributed to a forged
  // Ed25519 signature or stale digest alone.
  const statement = base.ownerProvisioning.statement;
  for (const change of [
    { storeId: "ad112afc-ff8e-4803-9f5c-b517cc778588" },
    { accountId: "ffef1473-eb42-48a4-9c7e-2d9e7c458211" },
    { scope: "mallory:store" },
    { username: "mallory" },
    { compartmentId: "other" },
    { version: 2 }, { sequence: 0 }, { extra: true },
    { witnessSpki: base.casPinnedPublicKey.toString("base64url") },
    { casSpki: base.pinnedPublicKey.toString("base64url") },
  ]) {
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: resignOwnerCertificate(base, { ...statement, ...change }),
    }, true), /owner provision is not independently authenticated/,
    `valid Ed25519 certificate must still reject ${Object.keys(change)[0]}`);
  }
  const updated = resignOwnerCertificate(base, { ...statement, sequence: 2 });
  assert.equal(trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: updated,
  }, true).atomicBatchOwnerIdentity.storeId, base.ownerIdentity.storeId);
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: { ...base,
      ownerProvisionDigest: updated.ownerProvisionDigest },
  }, true), /owner provision is not independently authenticated/,
  "authentic old certificate must fail under independently advanced current digest");
});

test("trusted batch witness snapshots owner key and keeps challenge arrays isolated", async () => {
  const trusted = trustedFixture();
  let received;
  trusted.readback = async (challenge) => {
    received = challenge;
    challenge.operationIds[0] = "ATTACKER_REPLACED";
    challenge.envelopeDigests[0] = "BAD_DIGEST";
    return null;
  };
  trusted.casReadback = async (challenge) => {
    received = challenge;
    return null;
  };
  const opts = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted },
    true, { username: "alice" }, "private");
  const pinnedCopy = Buffer.from(opts.atomicBatchWitnessPublicKey);
  const casPinnedCopy = Buffer.from(opts.atomicBatchCasFloorPublicKey);
  const ownerPinCopy = opts.atomicBatchOwnerProvisionerPublicKey.export({ type: "spki", format: "der" });
  trusted.pinnedPublicKey.fill(0);
  trusted.casPinnedPublicKey.fill(0);
  assert.deepEqual(opts.atomicBatchWitnessPublicKey, pinnedCopy);
  assert.deepEqual(opts.atomicBatchCasFloorPublicKey, casPinnedCopy);
  assert.deepEqual(opts.atomicBatchOwnerProvisionerPublicKey.export({ type: "spki", format: "der" }), ownerPinCopy);
  assert.equal(opts.atomicBatchWitnessScope, "alice:store");
  assert.equal(Object.isFrozen(opts.atomicBatchOwnerIdentity), true);
  assert.equal(opts.atomicBatchOwnerIdentity.accountId,
    "ca628a48-765e-4b0d-a746-3bc67d53e3b1");
  trusted.ownerIdentity.storeId = "ad112afc-ff8e-4803-9f5c-b517cc778588";
  trusted.ownerProvisioning.statement.storeId = "ad112afc-ff8e-4803-9f5c-b517cc778588";
  assert.equal(opts.atomicBatchOwnerIdentity.storeId,
    "d95a7868-857c-4213-a5ad-3c10374b4fa7");
  const challenge = {
    scope: "alice:store", accountId: opts.atomicBatchOwnerIdentity.accountId,
    storeId: opts.atomicBatchOwnerIdentity.storeId, nonce: "challenge-nonce",
    operationIds: ["delete-id", "move-id"],
    envelopeDigests: ["delete-digest", "move-digest"],
  };
  await opts.atomicBatchWitnessReadback(challenge);
  assert.deepEqual(challenge.operationIds, ["delete-id", "move-id"]);
  assert.deepEqual(challenge.envelopeDigests, ["delete-digest", "move-digest"]);
  assert.equal(received.nonce, challenge.nonce);
  const floorChallenge = {
    scope: "alice:store", accountId: opts.atomicBatchOwnerIdentity.accountId,
    storeId: opts.atomicBatchOwnerIdentity.storeId,
    nonce: "second-nonce", commitId: "commit-1",
    storeHeadSha256: "a".repeat(64), fencingEpoch: 3,
  };
  await opts.atomicBatchCasFloorReadback(floorChallenge);
  assert.deepEqual(received, floorChallenge);
});

test("external atomic witness rejects owner or compartment mismatches from trusted local policy", () => {
  const trusted = trustedFixture();
  assert.throws(() => trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted },
    true, { username: "mallory" }, "private"), /external CAS floor/);
  assert.throws(() => trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: trusted },
    true, { username: "alice" }, "other-compartment"), /external CAS floor/);
  assert.deepEqual(trustedAtomicBatchWitnessOptions({}, true,
    { username: "alice" }, "private"), {});
});

test("owner provision requires exact independent signature, trusted root, scope and schema", () => {
  const base = trustedFixture();
  const wrongRoot = crypto.generateKeyPairSync("ed25519").publicKey;
  for (const changed of [
    { ownerProvisionerPublicKey: wrongRoot },
    { ownerProvisionerPublicKey: base.pinnedPublicKey },
    { ownerProvisionerPublicKey: base.casPinnedPublicKey },
    { ownerProvisionDigest: "f".repeat(64) },
    { ownerProvisioning: { ...base.ownerProvisioning,
      statement: { ...base.ownerProvisioning.statement,
        storeId: "ad112afc-ff8e-4803-9f5c-b517cc778588" } } },
    { ownerProvisioning: { ...base.ownerProvisioning,
      statement: { ...base.ownerProvisioning.statement, scope: "mallory:store" } } },
    { ownerProvisioning: { ...base.ownerProvisioning,
      statement: { ...base.ownerProvisioning.statement, extra: true } } },
    { ownerProvisioning: { ...base.ownerProvisioning,
      statement: { ...base.ownerProvisioning.statement, version: 2 } } },
    { ownerProvisioning: { ...base.ownerProvisioning,
      statement: { ...base.ownerProvisioning.statement, sequence: 0 } } },
    { ownerProvisioning: { ...base.ownerProvisioning,
      statement: { ...base.ownerProvisioning.statement,
        witnessSpki: base.casPinnedPublicKey.toString("base64url") } } },
    { ownerProvisioning: { ...base.ownerProvisioning,
      signature: "a".repeat(86) } },
  ]) {
    const supplied = { ...base, ...changed };
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: supplied,
    }, true), /(?:owner provision is not independently authenticated|distinct pinned keys)/);
  }
  const attackerSigned = trustedFixture();
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: { ...base, ownerProvisioning: attackerSigned.ownerProvisioning },
  }, true), /owner provision is not independently authenticated/);
  // Even compromise of an arbitrary second root is insufficient to swap
  // the current certificate when its digest is independently pinned.
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: { ...base,
      ownerProvisionerPublicKey: attackerSigned.ownerProvisionerPublicKey,
      ownerProvisioning: attackerSigned.ownerProvisioning },
  }, true), /owner provision is not independently authenticated/);
  const olderDomainKey = crypto.generateKeyPairSync("ed25519");
  const legacyDomainReceipt = { statement: base.ownerProvisioning.statement,
    signature: crypto.sign(null, Buffer.from("rootark-sync-atomic-owner-provision-v1\0"
      + protocol.canonicalJson(base.ownerProvisioning.statement)),
    olderDomainKey.privateKey).toString("base64url") };
  assert.throws(() => trustedAtomicBatchWitnessOptions({
    trustedAtomicBatchWitness: { ...base,
      ownerProvisionerPublicKey: olderDomainKey.publicKey,
      ownerProvisioning: legacyDomainReceipt,
      ownerProvisionDigest: sha256(OWNER_PROVISION_DOMAIN
        + protocol.canonicalJson(legacyDomainReceipt)) },
  }, true), /owner provision is not independently authenticated/);
});

test("direct SyncEngine callers cannot bypass externally signed owner provenance", () => {
  const trusted = trustedFixture();
  const plainOptions = {
    adapter: { list: async () => ({ objects: [] }), push: async () => null },
    atomicBatchWitnessPublicKey: trusted.pinnedPublicKey,
    atomicBatchWitnessScope: trusted.scope,
    atomicBatchOwnerIdentity: trusted.ownerIdentity,
    atomicBatchWitnessReadback: trusted.readback,
    atomicBatchCasFloorPublicKey: trusted.casPinnedPublicKey,
    atomicBatchCasFloorReadback: trusted.casReadback,
  };
  assert.throws(() => new SyncEngine(plainOptions),
    /owner provision is not independently authenticated/);
  const withRoot = { ...plainOptions,
    atomicBatchOwnerProvisionerPublicKey: trusted.ownerProvisionerPublicKey,
    atomicBatchOwnerProvisioning: trusted.ownerProvisioning,
    atomicBatchOwnerProvisionDigest: trusted.ownerProvisionDigest };
  const engine = new SyncEngine(withRoot);
  assert.equal(engine.atomicBatchOwnerIdentity.storeId, trusted.ownerIdentity.storeId);
  assert.equal(Object.isFrozen(engine.atomicBatchOwnerIdentity), true);
  assert.throws(() => { engine.atomicBatchOwnerProvisionerPublicKey = null; }, TypeError);
  assert.throws(() => new SyncEngine({ ...withRoot,
    atomicBatchOwnerIdentity: { ...trusted.ownerIdentity, storeId:
      "ad112afc-ff8e-4803-9f5c-b517cc778588" },
  }), /owner provision is not independently authenticated/);
  for (const missingKey of ["atomicBatchWitnessPublicKey", "atomicBatchCasFloorPublicKey"]) {
    assert.throws(() => new SyncEngine({ ...withRoot, [missingKey]: null }),
      { code: "authorization_required" },
      `missing ${missingKey} must deny at construction, not wait until remote batch`);
  }
});

test("trusted atomic witness rejects getter authority swaps before construction", () => {
  for (const key of ["scope", "pinnedPublicKey", "casPinnedPublicKey",
    "readback", "casReadback", "ownerIdentity", "ownerProvisioning",
    "ownerProvisionerPublicKey", "ownerProvisionDigest"]) {
    const supplied = trustedFixture();
    Object.defineProperty(supplied, key, {
      enumerable: true, configurable: true,
      get: () => { throw new Error("SHOULD_NOT_READ_ACCESSOR"); },
    });
    assert.throws(() => trustedAtomicBatchWitnessOptions({
      trustedAtomicBatchWitness: supplied,
    }, true), /immutable canonical owner authority options/);
  }
});

test("trusted atomic witness captures one Proxy descriptor snapshot, not mutable get traps", () => {
  const original = trustedFixture();
  let getTraps = 0;
  const supplied = new Proxy(original, {
    get(target, prop, receiver) {
      getTraps++;
      if (prop === "scope") return "mallory:store";
      if (prop === "readback") return async () => { throw Error("SWAPPED_CALLBACK"); };
      return Reflect.get(target, prop, receiver);
    },
  });
  const opts = trustedAtomicBatchWitnessOptions({ trustedAtomicBatchWitness: supplied }, true);
  assert.equal(getTraps, 0, "capture must use only own property descriptors");
  assert.equal(opts.atomicBatchWitnessScope, "alice:store");
  assert.equal(opts.atomicBatchOwnerIdentity.username, "alice");
});

test("strict Sync v2 checks owner-pinned local device identity before opening the engine", () => {
  const signing = crypto.generateKeyPairSync("ed25519");
  const pinnedDeviceSpki = signing.publicKey
    .export({ type: "spki", format: "der" }).toString("base64url");
  const policy = {
    username: "alice",
    trustedDevicePublicKeys: { "device-a": pinnedDeviceSpki },
    revokedDeviceIds: [],
  };
  const config = {
    username: "alice", deviceId: "device-a",
    publicKey: pinnedDeviceSpki, privateKey: signing.privateKey,
  };
  assert.equal(assertPinnedStrictLocalDeviceIdentity(config, policy), true);
  for (const altered of [
    { username: "mallory" },
    { deviceId: "other-device" },
    { publicKey: "locally-replaced-signing-key" },
    { deviceId: "__proto__" },
  ]) {
    assert.throws(() => assertPinnedStrictLocalDeviceIdentity(
      { ...config, ...altered }, policy), /externally pinned owner policy/);
  }
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity(config, {
    ...policy, revokedDeviceIds: ["device-a"],
  }), /externally pinned owner policy/);
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity(config, {
    ...policy,
    trustedDevicePublicKeys: Object.create({ "device-a": config.publicKey }),
  }), /externally pinned owner policy/,
  "inherited device entries are never trusted owner pins");
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity(config, {
    ...policy, username: "mallory",
  }), /externally pinned owner policy/);
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity({
    ...config, privateKey: crypto.generateKeyPairSync("ed25519").privateKey,
  }, policy), /externally pinned owner policy/,
  "an attacker cannot supply the pinned public key with a different private key");
  assert.throws(() => assertPinnedStrictLocalDeviceIdentity({
    ...config, privateKey: null,
  }, policy), /externally pinned owner policy/);
});
