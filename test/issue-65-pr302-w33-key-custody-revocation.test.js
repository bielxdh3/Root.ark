"use strict";

// Parent RED / child GREEN: disposable genuine Ed25519 evidence, hostile
// same-realm native KeyObject getters, and independent positive controls.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const pg = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");
const binding = require("../sync-client/rootark-sync-zk1-physical-binding");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");

function fixture() {
  const signer = crypto.generateKeyPairSync("ed25519");
  const attestor = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("private"), keyring_id: crypto.randomBytes(16) };
  const operation = { operation_id: crypto.randomBytes(16), expected_sequence: 0,
    expected_root: crypto.randomBytes(32), object_id: crypto.randomBytes(16),
    revision: 1, epoch: 1, ciphertext_sha256: crypto.randomBytes(32) };
  return { signer, attestor, scope, operation, signerKeyId: crypto.randomBytes(16),
    nonce: crypto.randomBytes(32), now: Math.floor(Date.now() / 1000) };
}

async function committed(f) {
  const op = f.operation;
  const unsigned = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: f.signerKeyId, scope: f.scope, sequence: op.expected_sequence + 1,
    previous_root: op.expected_root, root: crypto.randomBytes(32),
    operation_id: op.operation_id, expected_sequence: op.expected_sequence,
    expected_root: op.expected_root,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(op)).digest(),
    entry: { object_id: op.object_id, revision: op.revision, epoch: op.epoch,
      ciphertext_sha256: op.ciphertext_sha256 } };
  const signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0"),
    await z.encodeDeterministic(unsigned),
  ]), f.signer.privateKey);
  return z.encodeDeterministic({ ...unsigned, signature });
}

async function physical(f) {
  const op = f.operation;
  return pg.signCommittedPhysicalReadback({
    scope: f.scope, operation: op, nonce: f.nonce, issuedAt: f.now,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: crypto.randomBytes(16),
      operationId: op.operation_id, revision: op.revision, epoch: op.epoch,
      digest: crypto.randomBytes(32), expectedInventorySequence: op.expected_sequence,
      expectedInventoryRoot: op.expected_root, chunkCount: 1,
      root: crypto.randomBytes(32), ciphertextSha256: op.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, f.attestor.privateKey);
}

function commitOptions(f, serialized, pin) {
  return { serialized, pinnedPublicKey: pin, pinnedSignerKeyId: f.signerKeyId,
    expectedScope: f.scope, operation: f.operation };
}
function physicalOptions(f, pin) {
  return { scope: f.scope, operation: f.operation, expected: undefined,
    nonce: f.nonce, nowSeconds: f.now, pinnedPublicKey: pin };
}
function compositeOptions(f, receipt, physicalAttestation, inventoryPin = f.signer.publicKey,
  physicalPin = f.attestor.publicKey) {
  return { receipt, physicalAttestation, scope: f.scope,
    operation: f.operation, nonce: f.nonce, nowSeconds: f.now,
    pinnedInventoryPublicKey: inventoryPin, pinnedInventorySignerKeyId: f.signerKeyId,
    pinnedPhysicalAttestorPublicKey: physicalPin };
}

// The pin is B at native key validation. A microtask swaps only the inherited
// kHandle before the asynchronous CBOR verifier uses the same caller object.
function delayedKeySwap(publicB, publicA) {
  const handle = Object.getOwnPropertySymbols(publicB)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle, "Node 22 native KeyObject handle is required");
  const pin = Object.create(publicB);
  let swapped = false;
  let reads = 0;
  Object.defineProperty(pin, handle, { get() {
    reads++;
    return (swapped ? publicA : publicB)[handle];
  } });
  Object.defineProperty(pin, "type", { get() {
    queueMicrotask(() => { swapped = true; });
    return "public";
  } });
  return { pin, get swapped() { return swapped; }, get reads() { return reads; } };
}

// This is a stricter race: the native kHandle changes synchronously *inside*
// the first own KeyObject.type getter, before a later SPKI export can run.
function immediateKeySwap(publicB, publicA) {
  const handle = Object.getOwnPropertySymbols(publicB)
    .find((symbol) => symbol.description === "kHandle");
  assert.ok(handle);
  const pin = Object.create(publicB);
  let changed = false;
  Object.defineProperty(pin, handle, { get() {
    return (changed ? publicA : publicB)[handle];
  } });
  Object.defineProperty(pin, "type", { get() {
    changed = true;
    return "public";
  } });
  return { pin, get changed() { return changed; } };
}

test("P2 native receipt pin B cannot become signer A synchronously during KeyObject.type", async () => {
  const f = fixture();
  const receipt = await committed(f);
  const foreign = crypto.generateKeyPairSync("ed25519");
  const hostile = immediateKeySwap(foreign.publicKey, f.signer.publicKey);
  await assert.rejects(inventory.verifyCommittedEntryProof(commitOptions(f,
    receipt, hostile.pin)), { code: "INVENTORY_SIGNER_KEY" });
  assert.ok(hostile.changed, "real native type getter retargeted the handle");
  assert.equal((await inventory.verifyCommittedEntryProof(commitOptions(f,
    receipt, f.signer.publicKey))).outcome, "COMMITTED_IN_SIGNED_LEDGER");
});

test("P2 native snapshot pin B cannot become signer A synchronously during KeyObject.type", async () => {
  const f = fixture();
  const root = await inventory.computeRoot(f.scope, 0, null, []);
  const snapshot = await inventory.createSignedSnapshot({ signerKeyId: f.signerKeyId,
    privateKey: f.signer.privateKey, scope: f.scope, sequence: 0,
    previousRoot: null, entries: [], nonce: f.nonce });
  const verify = (pin) => inventory.verifySnapshot({ serialized: snapshot,
    pinnedPublicKey: pin, pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope,
    requested: { object_id: crypto.randomBytes(16), revision: 1,
      epoch: 1, ciphertext_sha256: crypto.randomBytes(32) },
    minimumHead: { sequence: 0, root }, nonce: f.nonce });
  const foreign = crypto.generateKeyPairSync("ed25519");
  const hostile = immediateKeySwap(foreign.publicKey, f.signer.publicKey);
  await assert.rejects(verify(hostile.pin), { code: "INVENTORY_SIGNER_KEY" });
  assert.ok(hostile.changed);
  assert.equal((await verify(f.signer.publicKey)).outcome, "ABSENT");
});

test("P2 native PG attestor pin B cannot become signer A synchronously during KeyObject.type", async () => {
  const f = fixture();
  const signed = await physical(f);
  const foreign = crypto.generateKeyPairSync("ed25519");
  const hostile = immediateKeySwap(foreign.publicKey, f.attestor.publicKey);
  await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
    physicalOptions(f, hostile.pin)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  assert.ok(hostile.changed);
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    physicalOptions(f, f.attestor.publicKey))).verified, true);
});

test("P2 receipt pin B cannot verify real A after a delayed native kHandle swap", async () => {
  const f = fixture();
  const receipt = await committed(f);
  assert.equal((await inventory.verifyCommittedEntryProof(commitOptions(f, receipt,
    f.signer.publicKey))).outcome, "COMMITTED_IN_SIGNED_LEDGER");
  const foreign = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(inventory.verifyCommittedEntryProof(commitOptions(f,
    receipt, foreign.publicKey)), { code: "INVENTORY_SIGNATURE" });
  const hostile = delayedKeySwap(foreign.publicKey, f.signer.publicKey);
  await assert.rejects(inventory.verifyCommittedEntryProof(commitOptions(f,
    receipt, hostile.pin)), { code: "INVENTORY_SIGNATURE" });
  assert.ok(hostile.swapped && hostile.reads > 0, "actual native kHandle A/B switch ran");
});

test("P2 signed snapshot pin B cannot verify A after a delayed native kHandle swap", async () => {
  const f = fixture();
  const root = await inventory.computeRoot(f.scope, 0, null, []);
  const snapshot = await inventory.createSignedSnapshot({ signerKeyId: f.signerKeyId,
    privateKey: f.signer.privateKey, scope: f.scope, sequence: 0,
    previousRoot: null, entries: [], nonce: f.nonce });
  const verify = (pin) => inventory.verifySnapshot({ serialized: snapshot,
    pinnedPublicKey: pin, pinnedSignerKeyId: f.signerKeyId, expectedScope: f.scope,
    requested: { object_id: crypto.randomBytes(16), revision: 1,
      epoch: 1, ciphertext_sha256: crypto.randomBytes(32) },
    minimumHead: { sequence: 0, root }, nonce: f.nonce });
  assert.equal((await verify(f.signer.publicKey)).outcome, "ABSENT");
  const foreign = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(verify(foreign.publicKey), { code: "INVENTORY_SIGNATURE" });
  const hostile = delayedKeySwap(foreign.publicKey, f.signer.publicKey);
  await assert.rejects(verify(hostile.pin), { code: "INVENTORY_SIGNATURE" });
  assert.ok(hostile.swapped && hostile.reads > 0);
});

test("P2 physical attestor pin B cannot attest real A after delayed native kHandle swap", async () => {
  const f = fixture();
  const signed = await physical(f);
  assert.equal((await pg.verifyCommittedPhysicalReadback(signed,
    physicalOptions(f, f.attestor.publicKey))).verified, true);
  const foreign = crypto.generateKeyPairSync("ed25519");
  await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
    physicalOptions(f, foreign.publicKey)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  const hostile = delayedKeySwap(foreign.publicKey, f.attestor.publicKey);
  await assert.rejects(pg.verifyCommittedPhysicalReadback(signed,
    physicalOptions(f, hostile.pin)), /ZK_PHYSICAL_ATTESTATION_DENIED/);
  assert.ok(hostile.swapped && hostile.reads > 0);
});

test("P2 composite snapshots externally trusted B before inventory key getter rewrites B to signed A", async () => {
  const f = fixture();
  const receipt = await committed(f);
  const signedPg = await physical(f);
  const trustedB = Buffer.from(f.scope.account_id);
  trustedB[0] ^= 0xff;
  const fakeScope = { ...f.scope, account_id: trustedB };
  const base = compositeOptions(f, receipt, signedPg);
  assert.equal((await verifyAttestedInventoryCommit(base)).status,
    "VERIFIED_COMPOSITE_NONAUTHORIZING");
  await assert.rejects(verifyAttestedInventoryCommit({ ...base, scope: fakeScope }),
    /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  const previousB = Buffer.from(trustedB);
  let triggered = 0, restored = 0;
  const poisoned = Object.create(f.signer.publicKey);
  Object.defineProperty(poisoned, "type", { get() {
    triggered++;
    f.scope.account_id.copy(trustedB);
    queueMicrotask(() => { previousB.copy(trustedB); restored++; });
    return "public";
  } });
  await assert.rejects(verifyAttestedInventoryCommit({ ...base, scope: fakeScope,
    pinnedInventoryPublicKey: poisoned }), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  assert.ok(triggered > 0);
  assert.equal(triggered, restored);
  assert.deepEqual(trustedB, previousB, "caller expectation B must survive injection");
});

test("P2 composite rejects same native signer despite KeyObject getter rewriting equals", async () => {
  const f = fixture();
  f.attestor = f.signer;
  const receipt = await committed(f);
  const signedPg = await physical(f);
  const base = compositeOptions(f, receipt, signedPg);
  await assert.rejects(verifyAttestedInventoryCommit(base),
    /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  const nativeEquals = crypto.KeyObject.prototype.equals;
  const poisoned = Object.create(f.signer.publicKey);
  let getterReads = 0, substitutedCalls = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getterReads++;
    crypto.KeyObject.prototype.equals = function() {
      substitutedCalls++;
      return false;
    };
    return "public";
  } });
  try {
    await assert.rejects(verifyAttestedInventoryCommit({ ...base,
      pinnedInventoryPublicKey: poisoned }), /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/);
  } finally {
    crypto.KeyObject.prototype.equals = nativeEquals;
  }
  assert.ok(getterReads > 0);
  assert.equal(substitutedCalls, 0, "only original native key equality may decide role separation");
});

test("P2 composite pins physical attestor reference before inventory key getter replaces it", async () => {
  const f = fixture();
  const receipt = await committed(f);
  const signedPg = await physical(f);
  const trustedB = crypto.generateKeyPairSync("ed25519");
  const original = compositeOptions(f, receipt, signedPg);
  assert.equal((await verifyAttestedInventoryCommit(original)).status,
    "VERIFIED_COMPOSITE_NONAUTHORIZING", "signed A inventory + signed C PG positive");
  const input = { ...original, pinnedPhysicalAttestorPublicKey: trustedB.publicKey };
  let replaced = 0;
  const poisonedInventory = Object.create(f.signer.publicKey);
  Object.defineProperty(poisonedInventory, "type", { get() {
    replaced += 1;
    input.pinnedPhysicalAttestorPublicKey = f.attestor.publicKey;
    return "public";
  } });
  input.pinnedInventoryPublicKey = poisonedInventory;
  await assert.rejects(verifyAttestedInventoryCommit(input),
    /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/,
    "original trusted attestor B never signed PG C despite a hostile getter swap");
  assert.ok(replaced > 0, "real inventory KeyObject callback executed");
});

test("P2 composite cannot accept unsigned inventory after a native key getter replaces its verifier", async () => {
  const f = fixture();
  const physicalAttestation = await physical(f);
  const unsignedInventory = Buffer.from([0x01, 0x02, 0x03]);
  const base = compositeOptions(f, unsignedInventory, physicalAttestation);
  await assert.rejects(verifyAttestedInventoryCommit(base),
    /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/,
    "unsigned inventory cannot be committed even with a genuine PG signature");
  const originalVerify = inventory.verifyCommittedEntryProof;
  const injected = Object.create(f.signer.publicKey);
  let getterCalls = 0, forgedCalls = 0;
  Object.defineProperty(injected, "type", { get() {
    getterCalls++;
    inventory.verifyCommittedEntryProof = async () => {
      forgedCalls++;
      return { outcome: "COMMITTED_IN_SIGNED_LEDGER",
        operationId: Buffer.from(f.operation.operation_id), authorizesIo: false };
    };
    return "public";
  } });
  try {
    await assert.rejects(verifyAttestedInventoryCommit({ ...base,
      pinnedInventoryPublicKey: injected }),
    /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/,
    "a getter-swapped verifier must not impersonate genuine Ed25519 inventory verification");
  } finally { inventory.verifyCommittedEntryProof = originalVerify; }
  assert.ok(getterCalls > 0, "real key getter executed");
  assert.equal(forgedCalls, 0, "composite must call the verifier pinned before native key callbacks");
});

test("P2 composite cannot accept unsigned inventory after key getter forges Promise.all", async () => {
  const f = fixture();
  const physicalAttestation = await physical(f);
  const legitimatePhysical = await pg.verifyCommittedPhysicalReadback(physicalAttestation,
    physicalOptions(f, f.attestor.publicKey));
  const unsignedInventory = Buffer.from([0x01, 0x02, 0x03]);
  const originalAll = Promise.all;
  const originalVerify = inventory.verifyCommittedEntryProof;
  const injected = Object.create(f.signer.publicKey);
  let getterCalls = 0, forgedAllCalls = 0, verificationAttempts = 0;
  Object.defineProperty(injected, "type", { get() {
    getterCalls++;
    inventory.verifyCommittedEntryProof = () => {
      verificationAttempts++;
      return new Promise(() => {});
    };
    Promise.all = () => {
      forgedAllCalls++;
      return Promise.resolve([{
        outcome: "COMMITTED_IN_SIGNED_LEDGER",
        operationId: Buffer.from(f.operation.operation_id), authorizesIo: false,
      }, legitimatePhysical]);
    };
    return "public";
  } });
  try {
    await assert.rejects(verifyAttestedInventoryCommit(compositeOptions(f,
      unsignedInventory, physicalAttestation, injected)),
    /ZK_ATTESTED_INVENTORY_COMMIT_DENIED/,
    "forged Promise.all must never replace two independently signed verifications");
  } finally {
    Promise.all = originalAll;
    inventory.verifyCommittedEntryProof = originalVerify;
  }
  assert.ok(getterCalls > 0);
  assert.equal(forgedAllCalls, 0, "composite must not consult untrusted Promise.all");
  assert.equal(verificationAttempts, 0, "late mutable module verifier must not be consulted");
});

test("P2 composite compares signed operation IDs with pinned native timingSafeEqual", async () => {
  const f = fixture();
  const receipt = await committed(f);
  const physicalAttestation = await physical(f);
  const original = crypto.timingSafeEqual;
  const injected = Object.create(f.signer.publicKey);
  let getterCalls = 0, poisonedCalls = 0;
  Object.defineProperty(injected, "type", { get() {
    getterCalls++;
    crypto.timingSafeEqual = () => { poisonedCalls++; return false; };
    return "public";
  } });
  let result;
  try {
    result = await verifyAttestedInventoryCommit(compositeOptions(f,
      receipt, physicalAttestation, injected));
  } finally { crypto.timingSafeEqual = original; }
  assert.ok(getterCalls > 0);
  assert.equal(poisonedCalls, 0, "untrusted same-realm reassignment must not decide signed identity");
  assert.equal(result.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(result.authorizesIo, false);
});

test("P2 composite native key getter cannot forge nonauthorizing return via Object.freeze", async () => {
  const f = fixture();
  const receipt = await committed(f);
  const physicalAttestation = await physical(f);
  const originalFreeze = Object.freeze;
  const poisoned = Object.create(f.signer.publicKey);
  let getters = 0, forged = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getters++;
    Object.freeze = (value) => {
      if (value?.status === "VERIFIED_COMPOSITE_NONAUTHORIZING") {
        forged++;
        return { ...value, authorizesIo: true,
          externalDurabilityProven: true, independentlyAnchoredFloorProven: true };
      }
      return originalFreeze(value);
    };
    return "public";
  } });
  let result;
  try {
    result = await verifyAttestedInventoryCommit(compositeOptions(f,
      receipt, physicalAttestation, poisoned));
  } finally { Object.freeze = originalFreeze; }
  assert.ok(getters > 0, "native getter executed before final evidence was returned");
  assert.equal(forged, 0, "composite cannot delegate signed security flags to injected Object.freeze");
  assert.equal(Object.isFrozen(result), true);
  assert.equal(result.status, "VERIFIED_COMPOSITE_NONAUTHORIZING");
  assert.equal(result.authorizesIo, false);
  assert.equal(result.externalDurabilityProven, false);
  assert.equal(result.independentlyAnchoredFloorProven, false);
});

const hash64 = (value) => crypto.createHash("sha256").update(value).digest("base64url");

async function historicalFixture() {
  const f = fixture();
  const witness = crypto.generateKeyPairSync("ed25519");
  const device = crypto.generateKeyPairSync("ed25519");
  const deviceSpki = device.publicKey.export({ format: "der", type: "spki" });
  const publicKey = deviceSpki.toString("base64url");
  const plain = protocol.createOperation({ operation: "create", objectId: "object-revoke",
    fileId: "file-revoke", versionId: "version-revoke", operationId: "operation-revoke",
    deviceId: "device-revoke", keyEpoch: "epoch-1", compartmentId: "private",
    revision: { counter: 1, deviceId: "device-revoke" },
    metadata: { path: "protected.txt" },
    plaintext: Buffer.from("real ciphertext fixture"), fileKey: crypto.randomBytes(32) });
  const authorization = await createAuthorizationProof(plain, { username: "alice",
    publicKey, privateKey: device.privateKey, expiresAt: Date.now() + 60_000 });
  const envelope = { ...plain, authorization };
  const bound = binding.envelopeBinding(envelope, f.scope, 0, f.operation.expected_root);
  f.operation = bound.operation;
  const receipt = await committed(f);
  const physicalAttestation = await physical(f);
  const witnessKeyId = crypto.randomBytes(16);
  const statusKeyId = crypto.randomBytes(16);
  const floor = { type: "rootark-zk1-witness-cas-physical-floor/v2",
    witnessKeyId: witnessKeyId.toString("base64url"),
    statusKeyId: statusKeyId.toString("base64url"), sequence: 1,
    lastHash: crypto.randomBytes(32).toString("hex"),
    physicalFenceDigest: crypto.randomBytes(32).toString("hex"),
    nonce: f.nonce.toString("base64url") };
  floor.signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0"),
    Buffer.from(JSON.stringify(floor)),
  ]), witness.privateKey).toString("base64url");
  const admission = { type: "rootark-sync-v2-historical-witness-admission/v1",
    envelopeSha256: hash64(bound.canonicalEnvelope),
    operationId: bound.operation.operation_id.toString("base64url"),
    deviceId: "device-revoke", deviceSpkiSha256: hash64(deviceSpki),
    epoch: 1, checkpointSequence: 0,
    checkpointRoot: bound.operation.expected_root.toString("base64url"),
    inventoryReceiptSha256: hash64(receipt), admittedAtMs: Date.now() - 1000,
    witnessSequence: floor.sequence, witnessLastHash: floor.lastHash,
    witnessPhysicalFenceDigest: floor.physicalFenceDigest };
  admission.signature = crypto.sign(null, Buffer.concat([
    Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0"),
    Buffer.from(JSON.stringify(admission)),
  ]), witness.privateKey).toString("base64url");
  const initialPolicy = { username: "alice", trustedDevicePublicKeys: { "device-revoke": publicKey },
    revokedDeviceIds: [] };
  const args = { envelope, scope: f.scope, expectedSequence: 0,
    expectedRoot: f.operation.expected_root, receipt, physicalAttestation,
    nonce: f.nonce, pinnedInventoryPublicKey: f.signer.publicKey,
    pinnedInventorySignerKeyId: f.signerKeyId,
    pinnedPhysicalAttestorPublicKey: f.attestor.publicKey,
    localTrustedDevicePolicy: initialPolicy, trustedCurrentDevicePolicyProvider: () => initialPolicy,
    admission, freshFloor: floor, pinnedWitnessPublicKey: witness.publicKey,
    witnessKeyId, statusKeyId, trustedMinimumFloor: {
      sequence: floor.sequence, lastHash: floor.lastHash,
      physicalFenceDigest: floor.physicalFenceDigest,
    } };
  return { f, witness, args, initialPolicy };
}

test("P2 historical signed READ denies live revoked device after witness getter changes Array.includes", async () => {
  const { witness, args, initialPolicy } = await historicalFixture();
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args))
    .authorizesHistoricalRead, true, "real positive witness/inventory/PG/device Ed25519 proofs");
  const revokedPolicy = { ...initialPolicy, revokedDeviceIds: ["device-revoke"] };
  const denied = { ...args, trustedCurrentDevicePolicyProvider: () => revokedPolicy };
  await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission(denied),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  const originalIncludes = Array.prototype.includes;
  let getReads = 0, bypasses = 0;
  const hostile = Object.create(witness.publicKey);
  Object.defineProperty(hostile, "type", { get() {
    getReads++;
    Array.prototype.includes = function (value, ...args_) {
      if (this.length === 1 && this[0] === "device-revoke" && value === "device-revoke") {
        bypasses++;
        return false;
      }
      return Reflect.apply(originalIncludes, this, [value, ...args_]);
    };
    return "public";
  } });
  try {
    await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission({ ...denied,
      pinnedWitnessPublicKey: hostile }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  } finally { Array.prototype.includes = originalIncludes; }
  assert.ok(getReads > 0, "real KeyObject witness property callback executed");
  assert.equal(bypasses, 0, "live revocation must use captured native includes");
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args))
    .authorizesHistoricalRead, true, "signed historical positive is preserved");
});

test("P2 historical signed READ cannot replace a revoked device via poisoned descriptor", async () => {
  const { witness, args, initialPolicy } = await historicalFixture();
  const revokedPolicy = { ...initialPolicy, revokedDeviceIds: ["device-revoke"] };
  const originalDescriptor = Object.getOwnPropertyDescriptor;
  const hostile = Object.create(witness.publicKey);
  let getterCalls = 0, spoofedDescriptors = 0;
  Object.defineProperty(hostile, "type", { get() {
    getterCalls += 1;
    Object.getOwnPropertyDescriptor = function poisonedDescriptor(value, key) {
      if (value === revokedPolicy.revokedDeviceIds && key === "0") {
        spoofedDescriptors += 1;
        return { value: "device-other", enumerable: true, writable: true, configurable: true };
      }
      return Reflect.apply(originalDescriptor, Object, [value, key]);
    };
    return "public";
  } });
  try {
    await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission({ ...args,
      trustedCurrentDevicePolicyProvider: () => revokedPolicy,
      pinnedWitnessPublicKey: hostile }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  } finally { Object.getOwnPropertyDescriptor = originalDescriptor; }
  assert.ok(getterCalls > 0, "witness getter must execute");
  assert.equal(spoofedDescriptors, 0, "revocation slots must be read via pinned native descriptor");
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args))
    .authorizesHistoricalRead, true, "genuine signed historical READ remains allowed");
});

test("P2 real historical signed READ cannot erase a live revocation via descriptor poisoning", async () => {
  const { witness, args, initialPolicy } = await historicalFixture();
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args))
    .authorizesHistoricalRead, true, "real positive signed inventory/PG/witness/device control");
  const revoked = { ...initialPolicy, revokedDeviceIds: ["device-revoke"] };
  const denied = { ...args, trustedCurrentDevicePolicyProvider: () => revoked };
  await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission(denied),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  const originalDescriptor = Object.getOwnPropertyDescriptor;
  const poisoned = Object.create(witness.publicKey);
  let callbackReads = 0, substituted = 0;
  Object.defineProperty(poisoned, "type", { get() {
    callbackReads++;
    Object.getOwnPropertyDescriptor = function substituteRevocation(obj, name) {
      const descriptor = Reflect.apply(originalDescriptor, Object, [obj, name]);
      if (obj === revoked.revokedDeviceIds && name === "0" && descriptor) {
        substituted++;
        return { ...descriptor, value: "other-device" };
      }
      return descriptor;
    };
    return "public";
  } });
  try {
    await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission({
      ...denied, pinnedWitnessPublicKey: poisoned,
    }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "a late fake descriptor must not remove genuine live revoked device");
  } finally { Object.getOwnPropertyDescriptor = originalDescriptor; }
  assert.ok(callbackReads > 0, "real native public key callback executed");
  assert.equal(substituted, 0, "no unauthenticated descriptor read after hostile key callback");
  assert.equal(revoked.revokedDeviceIds[0], "device-revoke", "actual backing policy stayed revoked");
});

test("P2 historical signed floor B cannot verify authentic A via a poisoned Object.fromEntries", async () => {
  const { witness, args } = await historicalFixture();
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args)).authorizesHistoricalRead,
    true, "real signed A proof is valid");
  const floorAUnsigned = { ...args.freshFloor };
  delete floorAUnsigned.signature;
  const admissionAUnsigned = { ...args.admission };
  delete admissionAUnsigned.signature;
  const bHash = crypto.randomBytes(32).toString("hex");
  assert.notEqual(bHash, args.freshFloor.lastHash);
  const floorB = { ...args.freshFloor, lastHash: bHash };
  const admissionB = { ...args.admission, witnessLastHash: bHash };
  const expectedB = { ...args, freshFloor: floorB, admission: admissionB,
    trustedMinimumFloor: { ...args.trustedMinimumFloor, lastHash: bHash } };
  await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission(expectedB),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/, "B is not signed by witness A");
  const original = Object.fromEntries;
  const poisoned = Object.create(witness.publicKey);
  let getterReads = 0, signedBytesSubstitutions = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getterReads++;
    Object.fromEntries = (tuples) => {
      const unsigned = Reflect.apply(original, Object, [tuples]);
      if (unsigned.type === floorAUnsigned.type && unsigned.lastHash === bHash) {
        signedBytesSubstitutions++;
        return floorAUnsigned;
      }
      if (unsigned.type === admissionAUnsigned.type && unsigned.witnessLastHash === bHash) {
        signedBytesSubstitutions++;
        return admissionAUnsigned;
      }
      return unsigned;
    };
    return "public";
  } });
  try {
    await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission({
      ...expectedB, pinnedWitnessPublicKey: poisoned,
    }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "a genuine A Ed25519 signature cannot be reassigned to uncommitted B floor/admission");
  } finally { Object.fromEntries = original; }
  assert.ok(getterReads > 0);
  assert.equal(signedBytesSubstitutions, 0,
    "unsigned fields must be built without the mutated global fromEntries");
});

test("P2 historical signed floor B cannot verify authentic A via a poisoned Buffer.from", async () => {
  const { witness, args } = await historicalFixture();
  const floorAUnsigned = { ...args.freshFloor };
  delete floorAUnsigned.signature;
  const admissionAUnsigned = { ...args.admission };
  delete admissionAUnsigned.signature;
  const bHash = crypto.randomBytes(32).toString("hex");
  assert.notEqual(bHash, args.freshFloor.lastHash);
  const floorB = { ...args.freshFloor, lastHash: bHash };
  const admissionB = { ...args.admission, witnessLastHash: bHash };
  const expectedB = { ...args, freshFloor: floorB, admission: admissionB,
    trustedMinimumFloor: { ...args.trustedMinimumFloor, lastHash: bHash } };
  await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission(expectedB),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/);
  const original = Buffer.from;
  const poisoned = Object.create(witness.publicKey);
  let getterReads = 0, substituted = 0;
  const floorBUnsigned = { ...floorB };
  delete floorBUnsigned.signature;
  const admissionBUnsigned = { ...admissionB };
  delete admissionBUnsigned.signature;
  const fakeSignatures = new Map([
    [JSON.stringify(floorBUnsigned), JSON.stringify(floorAUnsigned)],
    [JSON.stringify(admissionBUnsigned), JSON.stringify(admissionAUnsigned)],
  ]);
  Object.defineProperty(poisoned, "type", { get() {
    getterReads++;
    Buffer.from = function replacedSignedBytes(input, ...rest) {
      if (typeof input === "string" && fakeSignatures.has(input)) {
        substituted++;
        return Reflect.apply(original, Buffer, [fakeSignatures.get(input), ...rest]);
      }
      return Reflect.apply(original, Buffer, [input, ...rest]);
    };
    return "public";
  } });
  try {
    await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission({
      ...expectedB, pinnedWitnessPublicKey: poisoned,
    }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "late Buffer.from poisoning cannot turn checked B into authentically signed A bytes");
  } finally { Buffer.from = original; }
  assert.ok(getterReads > 0);
  assert.equal(substituted, 0, "signed wire serialization must use captured native Buffer.from");
});

test("P2 historical read cannot forge authorizesIo by poisoning Object.freeze after witness key getter", async () => {
  const { witness, args } = await historicalFixture();
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args)).authorizesIo,
    false, "genuine signed evidence is strictly nonauthorizing for I/O");
  const originalFreeze = Object.freeze;
  const poisoned = Object.create(witness.publicKey);
  let getterReads = 0, forgedReturns = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getterReads++;
    Object.freeze = (value) => {
      if (value && value.status === "SYNC_V2_HISTORICAL_WITNESS_VERIFIED") {
        forgedReturns++;
        return { ...value, authorizesIo: true, externalDurabilityProven: true };
      }
      return originalFreeze(value);
    };
    return "public";
  } });
  let result;
  try {
    result = await binding.verifySyncV2HistoricalWitnessAdmission({
      ...args, pinnedWitnessPublicKey: poisoned,
    });
  } finally { Object.freeze = originalFreeze; }
  assert.ok(getterReads > 0, "native witness getter was exercised");
  assert.equal(forgedReturns, 0, "no late global freeze may rewrite security flags");
  assert.equal(Object.isFrozen(result), true);
  assert.equal(result.authorizesHistoricalRead, true);
  assert.equal(result.authorizesIo, false);
  assert.equal(result.externalDurabilityProven, false);
});

test("P2 genuine PG nonce B cannot use a witness-signed stale nonce A through poisoned Buffer.toString", async () => {
  const { f, witness, args } = await historicalFixture();
  const nonceA = Buffer.from(args.nonce);
  const nonceB = crypto.randomBytes(32);
  assert.notDeepEqual(nonceA, nonceB);
  const physicalB = await physical({ ...f, nonce: nonceB });
  const swapped = { ...args, nonce: nonceB, physicalAttestation: physicalB };
  await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission(swapped),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "authentic signed floor for A cannot answer the independent fresh B challenge");
  const original = Buffer.prototype.toString;
  const originalB64A = Reflect.apply(original, nonceA, ["base64url"]);
  const hostile = Object.create(witness.publicKey);
  let getterCalls = 0, forgedNonceReads = 0;
  Object.defineProperty(hostile, "type", { get() {
    getterCalls++;
    Buffer.prototype.toString = function poisonedNonceString(encoding, ...rest) {
      if (encoding === "base64url" && this.length === nonceB.length
        && crypto.timingSafeEqual(this, nonceB)) {
        forgedNonceReads++;
        return originalB64A;
      }
      return Reflect.apply(original, this, [encoding, ...rest]);
    };
    return "public";
  } });
  try {
    await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission({
      ...swapped, pinnedWitnessPublicKey: hostile,
    }), /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
    "signed floor A must not bind to nonce B through a poisoned byte-to-string method");
  } finally { Buffer.prototype.toString = original; }
  assert.ok(getterCalls > 0, "genuine witness key callback executed");
  assert.equal(forgedNonceReads, 0, "nonce matching must never consult poisoned Buffer.toString");
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args)).authorizesHistoricalRead,
    true, "authentic signed floor and PG both for A remain positive");
});

test("P2 signed PG freshness cannot be extended by Math.abs poisoning after a real slow read", async () => {
  const { f, args } = await historicalFixture();
  const signedOlderPg = await physical({ ...f,
    now: Math.floor(Date.now() / 1000) - 28 });
  const unsignedRead = {
    envelope: args.envelope, scope: args.scope,
    expectedSequence: args.expectedSequence, expectedRoot: args.expectedRoot,
    receipt: args.receipt, physicalAttestation: signedOlderPg,
    nonce: args.nonce, pinnedInventoryPublicKey: args.pinnedInventoryPublicKey,
    pinnedInventorySignerKeyId: args.pinnedInventorySignerKeyId,
    pinnedPhysicalAttestorPublicKey: args.pinnedPhysicalAttestorPublicKey,
    localTrustedDevicePolicy: args.localTrustedDevicePolicy,
  };
  assert.equal((await binding.verifySyncV2PhysicalEnvelopeEvidence(unsignedRead)).localPgReadbackVerified,
    true, "a real Ed25519 PG signature 28 seconds old passes without a late stall");
  const nativeAbs = Math.abs;
  const poisoned = Object.create(f.signer.publicKey);
  let getterCalls = 0, poisonedClockReads = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getterCalls++;
    Math.abs = () => { poisonedClockReads++; return 0; };
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 4200);
    return "public";
  } });
  const started = process.hrtime.bigint();
  try {
    await assert.rejects(binding.verifySyncV2PhysicalEnvelopeEvidence({
      ...unsignedRead, pinnedInventoryPublicKey: poisoned,
    }), /SYNC_ZK1_PHYSICAL_BINDING_DENIED/,
    "signed PG must be rechecked with native clock after verification exceeds 30 seconds");
  } finally { Math.abs = nativeAbs; }
  assert.ok(getterCalls > 0, "real inventory key getter performed a blocking stall");
  assert.ok(Number(process.hrtime.bigint() - started) / 1e6 >= 4000,
    "the callback genuinely stalled after the verifier entered the signed PG path");
  assert.equal(poisonedClockReads, 0, "no dynamic Math.abs after an Ed25519 callback");
});

test("P2 physical verifier cannot adopt fake success from poisoned native Promise constructor and then", async () => {
  const { f, args } = await historicalFixture();
  const invalid = {
    envelope: args.envelope, scope: args.scope, expectedSequence: args.expectedSequence,
    expectedRoot: args.expectedRoot, receipt: args.receipt,
    physicalAttestation: Buffer.from([0x01, 0x02, 0x03]), nonce: args.nonce,
    pinnedInventoryPublicKey: args.pinnedInventoryPublicKey,
    pinnedInventorySignerKeyId: args.pinnedInventorySignerKeyId,
    pinnedPhysicalAttestorPublicKey: args.pinnedPhysicalAttestorPublicKey,
    localTrustedDevicePolicy: args.localTrustedDevicePolicy,
  };
  await assert.rejects(binding.verifySyncV2PhysicalEnvelopeEvidence(invalid),
    /SYNC_ZK1_PHYSICAL_BINDING_DENIED/, "invalid physical signed bytes deny normally");
  const originalConstructor = Object.getOwnPropertyDescriptor(Promise.prototype, "constructor");
  const originalThen = Promise.prototype.then;
  const fakeComposite = { status: "VERIFIED_COMPOSITE_NONAUTHORIZING",
    authorizesIo: false, physicalReadback: { issuedAt: Math.floor(Date.now() / 1000) },
    receiptDigest: Buffer.alloc(32) };
  const poisoned = Object.create(f.signer.publicKey);
  const nativePromiseConstructor = Promise;
  let getterCalls = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getterCalls++;
    Object.defineProperty(Promise.prototype, "constructor", {
      configurable: true, writable: true, value: function ForgedPromise() {},
    });
    Promise.prototype.then = function fakeNativePromiseReaction(onFulfilled, onRejected) {
      if (typeof onFulfilled === "function" && typeof onRejected === "function") {
        return Reflect.apply(originalThen, this, [onFulfilled,
          () => onFulfilled(fakeComposite)]);
      }
      return Reflect.apply(originalThen, this, [onFulfilled, onRejected]);
    };
    return "public";
  } });
  try {
    const pending = binding.verifySyncV2PhysicalEnvelopeEvidence({
      ...invalid, pinnedInventoryPublicKey: poisoned,
    });
    // The oracle must observe the actual Promise internal state, not the
    // exact same hostile Promise.prototype.constructor injected into product.
    Object.defineProperty(pending, "constructor", { value: nativePromiseConstructor,
      enumerable: false, configurable: false, writable: false });
    await assert.rejects(pending, /SYNC_ZK1_PHYSICAL_BINDING_DENIED/,
    "actual bad PG bytes cannot become a verified physical receipt by fake native then");
  } finally {
    Object.defineProperty(Promise.prototype, "constructor", originalConstructor);
    Promise.prototype.then = originalThen;
  }
  assert.ok(getterCalls > 0, "hostile KeyObject getter executed inside composite");
  // A nested verifier may still consult a poisoned reaction and fail closed.
  // The only safety oracle is that invalid PG bytes never yield physical proof;
  // the test itself pins the returned Promise so its own await cannot be forged.
});

test("P2 historical signed witness cannot admit invalid PG after hostile Promise reactions", async () => {
  const { witness, args } = await historicalFixture();
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args)).authorizesHistoricalRead,
    true, "real Ed25519 witness, inventory, PG and device signatures are positive");
  const invalid = { ...args, physicalAttestation: Buffer.from([0x01, 0x02, 0x03]) };
  await assert.rejects(binding.verifySyncV2HistoricalWitnessAdmission(invalid),
    /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/, "invalid physical proof cannot authorize normally");
  const originalConstructor = Object.getOwnPropertyDescriptor(Promise.prototype, "constructor");
  const originalThen = Promise.prototype.then;
  const nativeConstructor = Promise;
  const fake = { status: "VERIFIED_COMPOSITE_NONAUTHORIZING", authorizesIo: false,
    localPgReadbackVerified: true, physicalReadback: { issuedAt: Math.floor(Date.now() / 1000) },
    receiptDigest: Buffer.alloc(32) };
  const poisoned = Object.create(witness.publicKey);
  let getterCalls = 0;
  Object.defineProperty(poisoned, "type", { get() {
    getterCalls++;
    Object.defineProperty(Promise.prototype, "constructor", {
      configurable: true, writable: true, value: function ForgedPromise() {},
    });
    Promise.prototype.then = function fakeRejectionToProof(onFulfilled, onRejected) {
      if (typeof onFulfilled === "function" && typeof onRejected === "function") {
        return Reflect.apply(originalThen, this, [onFulfilled,
          () => onFulfilled(fake)]);
      }
      return Reflect.apply(originalThen, this, [onFulfilled, onRejected]);
    };
    return "public";
  } });
  try {
    const pending = binding.verifySyncV2HistoricalWitnessAdmission({
      ...invalid, pinnedWitnessPublicKey: poisoned,
    });
    Object.defineProperty(pending, "constructor", { value: nativeConstructor,
      enumerable: false, configurable: false, writable: false });
    await assert.rejects(pending, /SYNC_ZK1_HISTORICAL_ADMISSION_DENIED/,
      "genuine witness signatures never replace the missing PG readback");
  } finally {
    Promise.prototype.then = originalThen;
    Object.defineProperty(Promise.prototype, "constructor", originalConstructor);
  }
  assert.ok(getterCalls > 0, "native witness getter poisoned the Promise prototype");
  assert.equal((await binding.verifySyncV2HistoricalWitnessAdmission(args)).authorizesIo,
    false, "normal nonauthorizing positive continues to work after restored globals");
});
