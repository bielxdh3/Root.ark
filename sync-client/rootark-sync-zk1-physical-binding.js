"use strict";

// Opt-in, NON-AUTHORIZING bridge between the exact signed Sync v2 envelope
// bytes and an independently signed ZK1 inventory + PostgreSQL readback.
// The physical writer must have stored these SAME canonical envelope bytes as
// its opaque ciphertext object. A server-supplied operation mapping or a
// success flag is never evidence of such a write. An admission timestamp,
// witness/CAS floor, and external cloud durability are NOT proven here.
const crypto = require("node:crypto");
const protocol = require("./rootark-sync-protocol");
const { verifyAuthorizationProof, verifyHistoricalAuthorizationProof } =
  require("./rootark-sync-authorization");
const { verifyAttestedInventoryCommit } =
  require("../src/crypto/rootark-zk1-attested-inventory-commit-v1");
const inventory = require("../src/crypto/rootark-zk-content-inventory-v1");
const { computeZk1CiphertextRoot } =
  require("../src/crypto/rootark-zk-chunk-root-v1");

const OPERATION_DOMAIN = Buffer.from("Root.ark/sync-v2/zk1-operation-id/v1\0", "utf8");
const OBJECT_DOMAIN = Buffer.from("Root.ark/sync-v2/zk1-object-id/v1\0", "utf8");
const MAX_CANONICAL_ENVELOPE_BYTES = 9 * 1024 * 1024;
const PG_CHUNK_BYTES = 1024 * 1024;

function deny() {
  const error = new Error("SYNC_ZK1_PHYSICAL_BINDING_DENIED");
  error.code = error.message;
  throw error;
}
function strict(raw, fields) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(raw))
    || Reflect.ownKeys(raw).length !== fields.length
    || fields.some((field) => !Object.hasOwn(raw, field))) deny();
  const result = Object.create(null);
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(raw, field);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    result[field] = descriptor.value;
  }
  return result;
}
function checkedBytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)) deny();
  return Buffer.from(value);
}
function lengthPrefixed(bytes) {
  const value = Buffer.from(bytes);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}
function snapshotLocalDevicePolicy(input) {
  const raw = strict(input, ["username", "trustedDevicePublicKeys", "revokedDeviceIds"]);
  if (typeof raw.username !== "string" || !raw.username || raw.username.length > 512
    || !raw.trustedDevicePublicKeys || typeof raw.trustedDevicePublicKeys !== "object"
    || Array.isArray(raw.trustedDevicePublicKeys)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(raw.trustedDevicePublicKeys))
    || !Array.isArray(raw.revokedDeviceIds)
    || raw.revokedDeviceIds.length > 10000) deny();
  const pins = Object.create(null);
  const pinKeys = Reflect.ownKeys(raw.trustedDevicePublicKeys);
  if (pinKeys.length < 1 || pinKeys.length > 10000) deny();
  for (const deviceId of pinKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(raw.trustedDevicePublicKeys, deviceId);
    if (typeof deviceId !== "string" || !descriptor || !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value")) deny();
    const spki = descriptor.value;
    if (!/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId)
      || typeof spki !== "string" || spki.length > 160
      || !/^[A-Za-z0-9_-]+$/.test(spki)) deny();
    pins[deviceId] = spki;
  }
  // Never call an untrusted Array's overridable `.map`. A forged own `map`
  // function can silently discard revocations while leaving Array.isArray true.
  if (Reflect.ownKeys(raw.revokedDeviceIds).length !== raw.revokedDeviceIds.length + 1) deny();
  const revoked = [];
  for (let index = 0; index < raw.revokedDeviceIds.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(raw.revokedDeviceIds, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, "value")) deny();
    const deviceId = descriptor.value;
    if (typeof deviceId !== "string"
      || !/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId)) deny();
    revoked.push(deviceId);
  }
  if (new Set(revoked).size !== revoked.length) deny();
  return { username: raw.username, trustedDevicePublicKeys: pins,
    revokedDeviceIds: revoked };
}
function derivedId(domain, scope, identifier) {
  return crypto.createHash("sha256").update(domain)
    .update(scope.account_id).update(lengthPrefixed(scope.compartment_id))
    .update(scope.keyring_id).update(lengthPrefixed(Buffer.from(identifier, "utf8")))
    .digest().subarray(0, 16);
}
function envelopeBinding(envelope, suppliedScope, expectedSequence, expectedRoot) {
  try {
    const scope = inventory.normalizeScope(suppliedScope);
    // The public sync route has a finite request budget. Do not fully decode
    // a server-supplied unbounded ciphertext merely to discover later that
    // its canonical envelope exceeds the physical-binding size budget.
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)
      || typeof envelope.ciphertext !== "string"
      || envelope.ciphertext.length > MAX_CANONICAL_ENVELOPE_BYTES) deny();
    const normalized = protocol.validateStoredOperation(envelope);
    if (!normalized.authorization || !Number.isSafeInteger(expectedSequence)
      || expectedSequence < 0 || expectedSequence > inventory.MAX_ENTRIES
      || !Number.isSafeInteger(normalized.revision.counter)
      || normalized.revision.counter < 1
      || !/^epoch-[1-9][0-9]*$/.test(normalized.keyEpoch)
      || normalized.revision.deviceId !== normalized.deviceId) deny();
    const epoch = Number(normalized.keyEpoch.slice(6));
    if (!Number.isSafeInteger(epoch) || epoch < 1) deny();
    if (!scope.compartment_id.equals(Buffer.from(normalized.compartmentId, "utf8"))) deny();
    const root = checkedBytes(expectedRoot, 32);
    // SHA256 is exactly over the BYTES intended for the PG writer. Domain
    // separation is instead used for the compact ZK1 operation/object IDs.
    const canonicalEnvelope = Buffer.from(protocol.canonicalJson(normalized), "utf8");
    if (canonicalEnvelope.length > MAX_CANONICAL_ENVELOPE_BYTES) deny();
    const operation = {
      operation_id: derivedId(OPERATION_DOMAIN, scope, normalized.operationId),
      expected_sequence: expectedSequence, expected_root: root,
      object_id: derivedId(OBJECT_DOMAIN, scope, normalized.objectId),
      revision: normalized.revision.counter, epoch,
      ciphertext_sha256: crypto.createHash("sha256").update(canonicalEnvelope).digest(),
    };
    return { envelope: normalized, canonicalEnvelope, scope, operation };
  } catch (_) { deny(); }
}

async function physicalWriteRequest(envelope, scope, expectedSequence, expectedRoot,
  externallyPinnedGateDigest, localTrustedDevicePolicy) {
  try {
    const bound = envelopeBinding(envelope, scope, expectedSequence, expectedRoot);
    // Caller-retained gate identity MUST be detached before the asynchronous
    // device signature check; otherwise the same caller can rewrite the
    // authority/fencing digest while this request is being authenticated.
    const gateDigest = checkedBytes(externallyPinnedGateDigest, 32);
    // A newly admitted physical PG write must satisfy FRESH, currently valid
    // Ed25519 device authorization and revocation before being handed to any
    // gate/writer. Mere structural envelopeBinding() is never an IO grant.
    const policy = snapshotLocalDevicePolicy(localTrustedDevicePolicy);
    if (await verifyAuthorizationProof(bound.envelope.authorization,
      bound.envelope, policy) !== true
      || bound.envelope.authorization.expiresAt <= Date.now()) deny();
    // This is exactly the API accepted by Zk1PgPhysicalInventoryBridge
    // .putAndAttest(). Never attach a signer-controlled success flag to it.
    // The gate's 32-byte digest comes from the independently trusted current
    // gate head, NOT an untrusted Sync HTTP response.
    const chunks = [];
    for (let position = 0; position < bound.canonicalEnvelope.length;
      position += PG_CHUNK_BYTES) {
      chunks.push(Buffer.from(bound.canonicalEnvelope.subarray(position,
        position + PG_CHUNK_BYTES)));
    }
    if (!chunks.length || chunks.some((chunk) => chunk.length < 1
      || chunk.length > PG_CHUNK_BYTES)) deny();
    return { scope: bound.scope, operation: bound.operation,
      digest: gateDigest,
      expectedRootHash: computeZk1CiphertextRoot(chunks),
      expectedChunkCount: chunks.length, chunks };
  } catch (_) { deny(); }
}

async function verifySyncV2PhysicalEnvelopeEvidence(input) {
  try {
    const v = strict(input, ["envelope", "scope", "expectedSequence", "expectedRoot",
      "receipt", "physicalAttestation", "nonce", "pinnedInventoryPublicKey",
      "pinnedInventorySignerKeyId", "pinnedPhysicalAttestorPublicKey",
      "localTrustedDevicePolicy"]);
    // Detach before the first async Ed25519 and deterministic CBOR verifier.
    const bound = envelopeBinding(v.envelope, v.scope, v.expectedSequence, v.expectedRoot);
    const receipt = checkedBytes(v.receipt, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
    const attestation = checkedBytes(v.physicalAttestation, 1, 2048);
    const nonce = checkedBytes(v.nonce, 32);
    const signerKeyId = checkedBytes(v.pinnedInventorySignerKeyId, 16);
    const inventoryKey = v.pinnedInventoryPublicKey;
    const physicalKey = v.pinnedPhysicalAttestorPublicKey;
    const policy = snapshotLocalDevicePolicy(v.localTrustedDevicePolicy);
    if (await verifyHistoricalAuthorizationProof(bound.envelope.authorization,
      bound.envelope, policy) !== true) deny();
    const result = await verifyAttestedInventoryCommit({
      receipt, physicalAttestation: attestation, scope: bound.scope,
      operation: bound.operation, nonce,
      pinnedInventoryPublicKey: inventoryKey,
      pinnedInventorySignerKeyId: signerKeyId,
      pinnedPhysicalAttestorPublicKey: physicalKey,
      nowSeconds: Math.floor(Date.now() / 1000),
    });
    const completedAtSeconds = Math.floor(Date.now() / 1000);
    if (result.status !== "VERIFIED_COMPOSITE_NONAUTHORIZING"
      || result.authorizesIo !== false
      // A proof may cross the ±30 s physical freshness window while CBOR and
      // Ed25519 verification await. Recheck the SIGNED issuance timestamp
      // rather than relying only on the pre-await wall-clock sample.
      || !Number.isSafeInteger(result.physicalReadback?.issuedAt)
      || !Number.isSafeInteger(completedAtSeconds) || completedAtSeconds < 1
      || Math.abs(completedAtSeconds - result.physicalReadback.issuedAt) > 30) deny();
    return Object.freeze({ status: "SYNC_ZK1_PHYSICAL_ENVELOPE_VERIFIED_NONAUTHORIZING",
      operationId: Buffer.from(bound.operation.operation_id),
      ciphertextSha256: Buffer.from(bound.operation.ciphertext_sha256),
      receiptDigest: Buffer.from(result.receiptDigest),
      localPgReadbackVerified: true,
      historicalServerAdmissionProven: false,
      independentlyAnchoredFloorProven: false,
      externalDurabilityProven: false, authorizesIo: false });
  } catch (_) { deny(); }
}

module.exports = { envelopeBinding, physicalWriteRequest,
  verifySyncV2PhysicalEnvelopeEvidence };
