"use strict";

// Real Ed25519 owner-independent inventory/PG/witness/device proof chain with
// an operator-owned live revocation decision. This is a synthetic, non-durable
// read proof, never a claim of independent production custody.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const pg = require("../src/crypto/rootark-zk-pg-physical-attestation-v1");
const { envelopeBinding, verifySyncV2HistoricalWitnessAdmission } =
  require("../sync-client/rootark-sync-zk1-physical-binding");

const sha = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const id = (value) => Buffer.alloc(16, value);
const hash = (value) => Buffer.alloc(32, value);
const domainEntry = Buffer.from("Root.ark/zk-1/content-inventory-entry/v1\0");
const domainFloor = Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0");
const domainAdmission = Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0");

async function genuineHistoricalEvidence() {
  const device = crypto.generateKeyPairSync("ed25519");
  const inventory = crypto.generateKeyPairSync("ed25519");
  const attestor = crypto.generateKeyPairSync("ed25519");
  const witness = crypto.generateKeyPairSync("ed25519");
  const spki = device.publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  const envelope = protocol.createOperation({ operation: "create", objectId: "object_1",
    fileId: "file_1", versionId: "version_1", deviceId: "device_1",
    compartmentId: "vault", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device_1" },
    metadata: { path: "read-me.txt" }, plaintext: Buffer.from("historical positive"),
    fileKey: crypto.randomBytes(32) });
  envelope.authorization = await createAuthorizationProof(envelope, {
    username: "alice", publicKey: spki, privateKey: device.privateKey,
    expiresAt: Date.now() + 120_000,
  });
  const scope = { account_id: id(35), compartment_id: Buffer.from("vault"),
    keyring_id: id(36) };
  const bound = envelopeBinding(envelope, scope, 0, hash(37));
  const operation = bound.operation;
  const signerKeyId = id(38);
  const nonce = hash(39);
  const nowSeconds = Math.floor(Date.now() / 1000);
  const entry = { object_id: operation.object_id, revision: operation.revision,
    epoch: operation.epoch, ciphertext_sha256: operation.ciphertext_sha256 };
  const receiptBody = { type: "rootark-content-inventory-entry/v1", version: 1,
    signer_key_id: signerKeyId, scope, sequence: 1,
    previous_root: operation.expected_root, root: hash(40),
    operation_id: operation.operation_id,
    expected_sequence: operation.expected_sequence,
    expected_root: operation.expected_root,
    request_digest: crypto.createHash("sha256")
      .update(await z.encodeDeterministic(operation)).digest(), entry };
  const receiptSignature = crypto.sign(null, Buffer.concat([
    domainEntry, await z.encodeDeterministic(receiptBody),
  ]), inventory.privateKey);
  const receipt = Buffer.from(await z.encodeDeterministic({
    ...receiptBody, signature: receiptSignature,
  }));
  const physicalAttestation = await pg.signCommittedPhysicalReadback({
    scope, operation, nonce, issuedAt: nowSeconds,
    readback: { status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation: 1, admissionId: id(41),
      operationId: operation.operation_id, revision: operation.revision,
      epoch: operation.epoch, digest: hash(42),
      expectedInventorySequence: operation.expected_sequence,
      expectedInventoryRoot: operation.expected_root, chunkCount: 1,
      root: hash(43), ciphertextSha256: operation.ciphertext_sha256,
      authorizesIo: false, provesIndependentOperator: false },
  }, attestor.privateKey);
  const witnessKeyId = id(44);
  const statusKeyId = id(45);
  const floorBody = { type: "rootark-zk1-witness-cas-physical-floor/v2",
    witnessKeyId: witnessKeyId.toString("base64url"),
    statusKeyId: statusKeyId.toString("base64url"),
    sequence: 2, lastHash: hash(46).toString("hex"),
    physicalFenceDigest: hash(47).toString("hex"),
    nonce: nonce.toString("base64url") };
  const freshFloor = { ...floorBody, signature: crypto.sign(null,
    Buffer.concat([domainFloor, Buffer.from(JSON.stringify(floorBody))]),
    witness.privateKey).toString("base64url") };
  const admissionBody = { type: "rootark-sync-v2-historical-witness-admission/v1",
    envelopeSha256: sha(bound.canonicalEnvelope),
    operationId: operation.operation_id.toString("base64url"),
    deviceId: envelope.deviceId,
    deviceSpkiSha256: sha(Buffer.from(spki, "base64url")),
    epoch: operation.epoch, checkpointSequence: operation.expected_sequence,
    checkpointRoot: operation.expected_root.toString("base64url"),
    inventoryReceiptSha256: sha(receipt),
    admittedAtMs: Date.now() - 1000,
    witnessSequence: floorBody.sequence, witnessLastHash: floorBody.lastHash,
    witnessPhysicalFenceDigest: floorBody.physicalFenceDigest };
  const admission = { ...admissionBody, signature: crypto.sign(null,
    Buffer.concat([domainAdmission, Buffer.from(JSON.stringify(admissionBody))]),
    witness.privateKey).toString("base64url") };
  const allowed = { username: "alice", trustedDevicePublicKeys: { device_1: spki },
    revokedDeviceIds: [] };
  const revoked = { username: "alice", trustedDevicePublicKeys: { device_1: spki },
    revokedDeviceIds: ["device_1"] };
  const input = { envelope, scope, expectedSequence: 0,
    expectedRoot: operation.expected_root, receipt, physicalAttestation,
    nonce, pinnedInventoryPublicKey: inventory.publicKey,
    pinnedInventorySignerKeyId: signerKeyId,
    pinnedPhysicalAttestorPublicKey: attestor.publicKey,
    localTrustedDevicePolicy: allowed, trustedCurrentDevicePolicyProvider: () => allowed,
    admission, freshFloor, pinnedWitnessPublicKey: witness.publicKey,
    witnessKeyId, statusKeyId,
    trustedMinimumFloor: { sequence: floorBody.sequence,
      lastHash: floorBody.lastHash, physicalFenceDigest: floorBody.physicalFenceDigest } };
  return { input, allowed, revoked, witness };
}

test("P2 historical: real signed valid read survives, revoked device never becomes authorized after witness getter", async () => {
  const f = await genuineHistoricalEvidence();
  const positive = await verifySyncV2HistoricalWitnessAdmission(f.input);
  assert.equal(positive.status, "SYNC_V2_HISTORICAL_WITNESS_VERIFIED");
  assert.equal(positive.authorizesHistoricalRead, true);
  assert.equal(positive.authorizesIo, false);
  const revokedInput = { ...f.input,
    trustedCurrentDevicePolicyProvider: () => f.revoked };
  await assert.rejects(verifySyncV2HistoricalWitnessAdmission(revokedInput),
    { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });

  const handle = Object.getOwnPropertySymbols(f.witness.publicKey)
    .find((value) => value.description === "kHandle");
  assert.ok(handle, "real Ed25519 witness native getter");
  const inherited = Object.create(f.witness.publicKey);
  let reads = 0;
  const nativePush = Array.prototype.push;
  const nativeIncludes = Array.prototype.includes;
  Object.defineProperty(inherited, handle, { get() {
    reads += 1;
    Array.prototype.push = function(...values) {
      if (values.length === 1 && values[0] === "device_1") return this.length;
      return Reflect.apply(nativePush, this, values);
    };
    Array.prototype.includes = function(value, ...rest) {
      if (value === "device_1" && this[0] === "device_1") return false;
      return Reflect.apply(nativeIncludes, this, [value, ...rest]);
    };
    return f.witness.publicKey[handle];
  } });
  try {
    await assert.rejects(verifySyncV2HistoricalWitnessAdmission({
      ...revokedInput, pinnedWitnessPublicKey: inherited,
    }), { code: "SYNC_ZK1_HISTORICAL_ADMISSION_DENIED" });
  } finally {
    Array.prototype.push = nativePush;
    Array.prototype.includes = nativeIncludes;
  }
  assert.ok(reads > 0, "physical native witness getter must be exercised");
  assert.equal((await verifySyncV2HistoricalWitnessAdmission(f.input))
    .authorizesHistoricalRead, true, "valid historical signer and device remain accepted");
});
