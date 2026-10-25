"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const z = require("../src/crypto/rootark-zk-1");
const { createOperation } = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { signCommittedPhysicalReadback } =
  require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { envelopeBinding, physicalWriteRequest, verifySyncV2PhysicalEnvelopeEvidence } =
  require("../sync-client/rootark-sync-zk1-physical-binding");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");

const ENTRY_DOMAIN = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const sha = (data) => crypto.createHash("sha256").update(data).digest();
const random = (n) => crypto.randomBytes(n);

async function createFixture({ deviceExpiryOffsetMs = 60000 } = {}) {
  const device = crypto.generateKeyPairSync("ed25519");
  const inventory = crypto.generateKeyPairSync("ed25519");
  const attestor = crypto.generateKeyPairSync("ed25519");
  const rogue = crypto.generateKeyPairSync("ed25519");
  const devicePublicKey = device.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  const fileKey = random(32);
  const scope = { account_id: random(16), compartment_id: Buffer.from("private"),
    keyring_id: random(16) };
  const syncFields = { operation: "create", operationId: "sync-pg-bind-op",
    objectId: "sync-pg-bind-object", deviceId: "device-a", compartmentId: "private",
    keyEpoch: "epoch-6", revision: { counter: 5, deviceId: "device-a" },
    metadata: { path: "opaque-test.txt" }, fileKey };
  const signSync = async (plaintext, extra = {}) => {
    const operation = createOperation({ ...syncFields, ...extra, plaintext: Buffer.from(plaintext) });
    operation.authorization = await createAuthorizationProof(operation, {
      username: "alice", privateKey: device.privateKey, publicKey: devicePublicKey,
      expiresAt: Date.now() + deviceExpiryOffsetMs });
    return operation;
  };
  const envelope = await signSync("encrypted client payload");
  const expectedSequence = 4;
  const expectedRoot = random(32);
  const bound = envelopeBinding(envelope, scope, expectedSequence, expectedRoot);
  const signerId = random(16);
  const unsignedEntry = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: signerId, scope, sequence: expectedSequence + 1,
    previous_root: expectedRoot, root: random(32),
    operation_id: bound.operation.operation_id,
    expected_sequence: expectedSequence, expected_root: expectedRoot,
    request_digest: sha(await z.encodeDeterministic(bound.operation)),
    entry: { object_id: bound.operation.object_id,
      revision: bound.operation.revision, epoch: bound.operation.epoch,
      ciphertext_sha256: bound.operation.ciphertext_sha256 },
  };
  const unsignedBytes = await z.encodeDeterministic(unsignedEntry);
  const receipt = Buffer.from(await z.encodeDeterministic({ ...unsignedEntry,
    signature: crypto.sign(null, Buffer.concat([ENTRY_DOMAIN, unsignedBytes]), inventory.privateKey) }));
  const readback = { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
    walFlushConfirmed: true, authorizesIo: false, provesIndependentOperator: false,
    generation: 7, admissionId: random(16),
    operationId: bound.operation.operation_id, revision: bound.operation.revision,
    epoch: bound.operation.epoch,
    expectedInventorySequence: expectedSequence, expectedInventoryRoot: expectedRoot,
    ciphertextSha256: bound.operation.ciphertext_sha256,
    digest: random(32), root: random(32), chunkCount: 1 };
  const nonce = random(32);
  const issuedAt = Math.floor(Date.now() / 1000);
  const physicalAttestation = await signCommittedPhysicalReadback({
    scope, operation: bound.operation, readback, nonce,
    issuedAt }, attestor.privateKey);
  const input = { envelope, scope, expectedSequence, expectedRoot, receipt,
    physicalAttestation, nonce, pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: signerId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    localTrustedDevicePolicy: { username: "alice", trustedDevicePublicKeys: {
      "device-a": devicePublicKey }, revokedDeviceIds: [] } };
  return { input, bound, readback, inventory, attestor, rogue, signSync, scope,
    issuedAt };
}

test("a signed Sync v2 envelope binds exactly to two independent ZK1 signer identities and PG readback", async () => {
  const f = await createFixture();
  const verified = await verifySyncV2PhysicalEnvelopeEvidence(f.input);
  assert.equal(verified.status, "SYNC_ZK1_PHYSICAL_ENVELOPE_VERIFIED_NONAUTHORIZING");
  assert.deepEqual(verified.operationId, f.bound.operation.operation_id);
  assert.deepEqual(verified.ciphertextSha256, sha(f.bound.canonicalEnvelope));
  assert.equal(verified.localPgReadbackVerified, true);
  assert.equal(verified.historicalServerAdmissionProven, false);
  assert.equal(verified.externalDurabilityProven, false);
  assert.equal(verified.independentlyAnchoredFloorProven, false);
  assert.equal(verified.authorizesIo, false);
});

test("another legitimately signed same-ID ciphertext cannot borrow someone else's physical receipt", async () => {
  const f = await createFixture();
  const substituted = await f.signSync("different valid ciphertext with same operation ID");
  const second = envelopeBinding(substituted, f.scope, f.input.expectedSequence,
    f.input.expectedRoot);
  assert.notDeepEqual(second.operation.ciphertext_sha256, f.bound.operation.ciphertext_sha256);
  assert.deepEqual(second.operation.operation_id, f.bound.operation.operation_id);
  await assert.rejects(verifySyncV2PhysicalEnvelopeEvidence({ ...f.input,
    envelope: substituted }), /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
});

test("scope, epoch, nonce, signer separation and original device revocation are checked independently", async () => {
  const f = await createFixture();
  const deny = (change) => assert.rejects(verifySyncV2PhysicalEnvelopeEvidence({
    ...f.input, ...change }), /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
  await deny({ scope: { ...f.scope, account_id: random(16) } });
  await deny({ scope: { ...f.scope, compartment_id: Buffer.from("other") } });
  await deny({ expectedSequence: f.input.expectedSequence + 1 });
  await deny({ expectedRoot: random(32) });
  await deny({ nonce: random(32) });
  await deny({ physicalAttestation: "forged status" });
  await deny({ receipt: "forged receipt" });
  await deny({ pinnedPhysicalAttestorPublicKey: f.inventory.publicKey });
  await deny({ pinnedPhysicalAttestorPublicKey: f.rogue.publicKey });
  await deny({ localTrustedDevicePolicy: { ...f.input.localTrustedDevicePolicy,
    revokedDeviceIds: ["device-a"] } });
  const revokedWithOverriddenMap = ["device-a"];
  Object.defineProperty(revokedWithOverriddenMap, "map", { value: () => [] });
  await deny({ localTrustedDevicePolicy: { ...f.input.localTrustedDevicePolicy,
    revokedDeviceIds: revokedWithOverriddenMap } });
  const revokedGetter = ["device-a"];
  Object.defineProperty(revokedGetter, "0", { get: () => "device-a", enumerable: true });
  await deny({ localTrustedDevicePolicy: { ...f.input.localTrustedDevicePolicy,
    revokedDeviceIds: revokedGetter } });
  await deny({ localTrustedDevicePolicy: { ...f.input.localTrustedDevicePolicy,
    revokedDeviceIds: new Array(1) } });
  const pinGetter = {};
  Object.defineProperty(pinGetter, "device-a", { get: () =>
    f.input.localTrustedDevicePolicy.trustedDevicePublicKeys["device-a"], enumerable: true });
  await deny({ localTrustedDevicePolicy: { ...f.input.localTrustedDevicePolicy,
    trustedDevicePublicKeys: pinGetter } });
  const invalidEpoch = { ...f.input.envelope, keyEpoch: "different-epoch" };
  assert.throws(() => envelopeBinding(invalidEpoch, f.scope,
    f.input.expectedSequence, f.input.expectedRoot),
  /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
});

test("PG writer request uses exact canonical envelope bytes in bounded root-authenticated chunks", async () => {
  const f = await createFixture();
  const gateDigest = random(32);
  const request = await physicalWriteRequest(f.input.envelope, f.scope,
    f.input.expectedSequence, f.input.expectedRoot, gateDigest,
    f.input.localTrustedDevicePolicy);
  assert.deepEqual(request.operation, f.bound.operation);
  assert.deepEqual(request.digest, gateDigest);
  assert.deepEqual(Buffer.concat(request.chunks), f.bound.canonicalEnvelope);
  assert.deepEqual(request.expectedRootHash, computeZk1CiphertextRoot(request.chunks));
  assert.deepEqual(sha(Buffer.concat(request.chunks)), request.operation.ciphertext_sha256);
  assert.equal(request.expectedChunkCount, request.chunks.length);
  const racePin = random(32);
  const expectedPin = Buffer.from(racePin);
  const inFlight = physicalWriteRequest(f.input.envelope, f.scope,
    f.input.expectedSequence, f.input.expectedRoot, racePin,
    f.input.localTrustedDevicePolicy);
  racePin.fill(0);
  const raceResult = await inFlight;
  assert.deepEqual(raceResult.digest, expectedPin,
    "the actual gate digest must not be swapped during async signer verification");
  await assert.rejects(physicalWriteRequest(f.input.envelope, f.scope,
    f.input.expectedSequence, f.input.expectedRoot, "fake-GATE-DIGEST",
    f.input.localTrustedDevicePolicy),
  /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
  await assert.rejects(physicalWriteRequest(f.input.envelope, f.scope,
    f.input.expectedSequence, f.input.expectedRoot, gateDigest,
    { ...f.input.localTrustedDevicePolicy, revokedDeviceIds: ["device-a"] }),
  /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
  await assert.rejects(physicalWriteRequest(f.input.envelope, f.scope,
    f.input.expectedSequence, f.input.expectedRoot, gateDigest,
    { ...f.input.localTrustedDevicePolicy,
      trustedDevicePublicKeys: { "device-a": f.rogue.publicKey.export({
        format: "der", type: "spki" }).toString("base64url") } }),
  /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
  const originalNow = Date.now;
  let reads = 0;
  try {
    const expires = f.input.envelope.authorization.expiresAt;
    Date.now = () => ++reads === 1 ? expires - 1 : expires + 1;
    await assert.rejects(physicalWriteRequest(f.input.envelope, f.scope,
      f.input.expectedSequence, f.input.expectedRoot, gateDigest,
      f.input.localTrustedDevicePolicy),
    /SYNC_ZK1_PHYSICAL_BINDING_DENIED/,
    "a deadline crossing during asynchronous signature verification cannot activate a PG write");
  } finally { Date.now = originalNow; }
  const large = await f.signSync("x".repeat(1048578));
  const largeWrite = await physicalWriteRequest(large, f.scope,
    f.input.expectedSequence, f.input.expectedRoot, gateDigest,
    f.input.localTrustedDevicePolicy);
  assert.ok(largeWrite.chunks.length > 1);
  assert.ok(largeWrite.chunks.every((chunk) => chunk.length >= 1 && chunk.length <= 1048576));
  assert.deepEqual(largeWrite.expectedRootHash, computeZk1CiphertextRoot(largeWrite.chunks));
  assert.deepEqual(sha(Buffer.concat(largeWrite.chunks)), largeWrite.operation.ciphertext_sha256);
});

test("valid signatures on an expired Sync v2 envelope still do not prove original admission time", async () => {
  const f = await createFixture({ deviceExpiryOffsetMs: 500 });
  const expires = f.input.envelope.authorization.expiresAt;
  const original = Date.now;
  try {
    Date.now = () => expires + 1;
    // This is deliberately non-authorizing: independent physical existence
    // today cannot prove when the server originally admitted the ciphertext.
    const result = await verifySyncV2PhysicalEnvelopeEvidence(f.input);
    assert.equal(result.historicalServerAdmissionProven, false);
    assert.equal(result.authorizesIo, false);
  } finally { Date.now = original; }
});

test("physical freshness must remain valid after asynchronous signature verification", async () => {
  const f = await createFixture();
  const original = Date.now;
  let reads = 0;
  try {
    // The physical attestation begins at age 29 s and finishes at age 31 s.
    // A pre-await clock sample is insufficient to authorize even the
    // nonauthorizing evidence result for an expired physical readback.
    Date.now = () => f.issuedAt * 1000 + (++reads === 1 ? 29000 : 31000);
    await assert.rejects(verifySyncV2PhysicalEnvelopeEvidence(f.input),
      /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
    assert.ok(reads >= 2, "the verifier must recheck the clock after awaited crypto");
  } finally { Date.now = original; }
});

test("non-finite post-verification clock cannot bypass physical freshness", async () => {
  const f = await createFixture();
  const original = Date.now;
  let reads = 0;
  try {
    Date.now = () => ++reads === 1 ? f.issuedAt * 1000 : NaN;
    await assert.rejects(verifySyncV2PhysicalEnvelopeEvidence(f.input),
      /SYNC_ZK1_PHYSICAL_BINDING_DENIED/);
    assert.ok(reads >= 2);
  } finally { Date.now = original; }
});
