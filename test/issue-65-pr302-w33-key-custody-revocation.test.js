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
