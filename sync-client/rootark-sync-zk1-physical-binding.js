"use strict";

// Opt-in, NON-AUTHORIZING bridge between the exact signed Sync v2 envelope
// bytes and an independently signed ZK1 inventory + PostgreSQL readback.
// The physical writer must have stored these SAME canonical envelope bytes as
// its opaque ciphertext object. A server-supplied operation mapping or a
// success flag is never evidence of such a write. An admission timestamp,
// witness/CAS floor, and external cloud durability are NOT proven here.
const crypto = require("node:crypto");
const { types: { isProxy } } = require("node:util");
const { key: pinnedOwnerPublicKey } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");
const {
  keyEquals: NATIVE_KEY_EQUALS,
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  createHash: NATIVE_CREATE_HASH,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT,
  verify: NATIVE_VERIFY,
  jsonStringify: NATIVE_JSON_STRINGIFY,
  pickSignedFields: NATIVE_PICK_SIGNED_FIELDS,
  arrayIsArray: NATIVE_ARRAY_IS_ARRAY,
  arrayIncludes: NATIVE_ARRAY_INCLUDES,
  getPrototype: NATIVE_GET_PROTOTYPE,
  ownKeys: NATIVE_OWN_KEYS,
  ownDescriptor: NATIVE_OWN_DESCRIPTOR,
  hasOwn: NATIVE_HAS_OWN,
  objectCreate: NATIVE_OBJECT_CREATE,
  defineProperty: NATIVE_DEFINE_PROPERTY,
  freeze: NATIVE_FREEZE,
} = require("../src/crypto/rootark-zk10-native-intrinsics-v1");
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
const HISTORICAL_DOMAIN = Buffer.from("Root.ark/sync-v2/historical-witness-admission/v1\0");
const PHYSICAL_FLOOR_DOMAIN = Buffer.from("Root.ark/zk-1/witness-cas-physical-floor/v2\0");
const MAX_CANONICAL_ENVELOPE_BYTES = 9 * 1024 * 1024;
const PG_CHUNK_BYTES = 1024 * 1024;
const PHYSICAL_FLOOR_SIGNED_FIELDS = Object.freeze([
  "type", "witnessKeyId", "statusKeyId", "sequence", "lastHash",
  "physicalFenceDigest", "nonce",
]);
const PHYSICAL_FLOOR_WIRE_FIELDS = Object.freeze([
  "type", "witnessKeyId", "statusKeyId", "sequence", "lastHash",
  "physicalFenceDigest", "nonce", "signature",
]);
const ADMISSION_SIGNED_FIELDS = Object.freeze([
  "type", "envelopeSha256", "operationId", "deviceId", "deviceSpkiSha256",
  "epoch", "checkpointSequence", "checkpointRoot", "inventoryReceiptSha256",
  "admittedAtMs", "witnessSequence", "witnessLastHash", "witnessPhysicalFenceDigest",
]);
const ADMISSION_WIRE_FIELDS = Object.freeze([
  "type", "envelopeSha256", "operationId", "deviceId", "deviceSpkiSha256",
  "epoch", "checkpointSequence", "checkpointRoot", "inventoryReceiptSha256",
  "admittedAtMs", "witnessSequence", "witnessLastHash", "witnessPhysicalFenceDigest",
  "signature",
]);

function deny() {
  const error = new Error("SYNC_ZK1_PHYSICAL_BINDING_DENIED");
  error.code = error.message;
  throw error;
}
function strict(raw, fields) {
  const prototype = raw && typeof raw === "object" && !isProxy(raw)
    ? NATIVE_GET_PROTOTYPE(raw) : undefined;
  if (!raw || typeof raw !== "object" || isProxy(raw) || NATIVE_ARRAY_IS_ARRAY(raw)
    || (prototype !== Object.prototype && prototype !== null)
    || NATIVE_OWN_KEYS(raw).length !== fields.length) deny();
  const result = NATIVE_OBJECT_CREATE(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = NATIVE_OWN_DESCRIPTOR(raw, field);
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    NATIVE_DEFINE_PROPERTY(result, field, {
      value: descriptor.value, enumerable: true, writable: true, configurable: true,
    });
  }
  return result;
}
function checkedBytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)) deny();
  return NATIVE_BUFFER_FROM(value);
}
function lengthPrefixed(bytes) {
  const value = NATIVE_BUFFER_FROM(bytes);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return NATIVE_BUFFER_CONCAT([length, value]);
}
function snapshotLocalDevicePolicy(input) {
  const raw = strict(input, ["username", "trustedDevicePublicKeys", "revokedDeviceIds"]);
  const pinsPrototype = raw.trustedDevicePublicKeys
    && typeof raw.trustedDevicePublicKeys === "object"
    && !isProxy(raw.trustedDevicePublicKeys)
    ? NATIVE_GET_PROTOTYPE(raw.trustedDevicePublicKeys) : undefined;
  if (typeof raw.username !== "string" || !raw.username || raw.username.length > 512
    || !raw.trustedDevicePublicKeys || typeof raw.trustedDevicePublicKeys !== "object"
    || NATIVE_ARRAY_IS_ARRAY(raw.trustedDevicePublicKeys)
    || (pinsPrototype !== Object.prototype && pinsPrototype !== null)
    || !NATIVE_ARRAY_IS_ARRAY(raw.revokedDeviceIds)
    || raw.revokedDeviceIds.length > 10000) deny();
  const pins = NATIVE_OBJECT_CREATE(null);
  const pinKeys = NATIVE_OWN_KEYS(raw.trustedDevicePublicKeys);
  if (pinKeys.length < 1 || pinKeys.length > 10000) deny();
  for (let index = 0; index < pinKeys.length; index += 1) {
    const deviceId = pinKeys[index];
    const descriptor = NATIVE_OWN_DESCRIPTOR(raw.trustedDevicePublicKeys, deviceId);
    if (typeof deviceId !== "string" || !descriptor || !descriptor.enumerable
      || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    const spki = descriptor.value;
    if (!/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId)
      || typeof spki !== "string" || spki.length > 160
      || !/^[A-Za-z0-9_-]+$/.test(spki)) deny();
    NATIVE_DEFINE_PROPERTY(pins, deviceId, {
      value: spki, enumerable: true, writable: true, configurable: true,
    });
  }
  // Never call an untrusted Array's overridable `.map`. A forged own `map`
  // function can silently discard revocations while leaving Array.isArray true.
  if (NATIVE_OWN_KEYS(raw.revokedDeviceIds).length !== raw.revokedDeviceIds.length + 1) deny();
  const revoked = [];
  const seen = NATIVE_OBJECT_CREATE(null);
  for (let index = 0; index < raw.revokedDeviceIds.length; index += 1) {
    const descriptor = NATIVE_OWN_DESCRIPTOR(raw.revokedDeviceIds, String(index));
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    const deviceId = descriptor.value;
    if (typeof deviceId !== "string"
      || !/^[A-Za-z0-9._:-]{1,160}$/.test(deviceId)
      || NATIVE_HAS_OWN(seen, deviceId)) deny();
    NATIVE_DEFINE_PROPERTY(seen, deviceId, { value: true });
    // Defining own DATA slots avoids a hostile Array.push and inherited numeric
    // setters installed by a signed native KeyObject's kHandle callback.
    NATIVE_DEFINE_PROPERTY(revoked, String(index), {
      value: deviceId, enumerable: true, writable: true, configurable: true,
    });
  }
  return { username: raw.username, trustedDevicePublicKeys: pins,
    revokedDeviceIds: revoked };
}
function derivedId(domain, scope, identifier) {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, domain);
  NATIVE_HASH_UPDATE.call(hash, scope.account_id);
  NATIVE_HASH_UPDATE.call(hash, lengthPrefixed(scope.compartment_id));
  NATIVE_HASH_UPDATE.call(hash, scope.keyring_id);
  NATIVE_HASH_UPDATE.call(hash, lengthPrefixed(NATIVE_BUFFER_FROM(identifier, "utf8")));
  return NATIVE_HASH_DIGEST.call(hash).subarray(0, 16);
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
    if (!scope.compartment_id.equals(NATIVE_BUFFER_FROM(normalized.compartmentId, "utf8"))) deny();
    const root = checkedBytes(expectedRoot, 32);
    // SHA256 is exactly over the BYTES intended for the PG writer. Domain
    // separation is instead used for the compact ZK1 operation/object IDs.
    const canonicalEnvelope = NATIVE_BUFFER_FROM(protocol.canonicalJson(normalized), "utf8");
    if (canonicalEnvelope.length > MAX_CANONICAL_ENVELOPE_BYTES) deny();
    const operation = {
      operation_id: derivedId(OPERATION_DOMAIN, scope, normalized.operationId),
      expected_sequence: expectedSequence, expected_root: root,
      object_id: derivedId(OBJECT_DOMAIN, scope, normalized.objectId),
      revision: normalized.revision.counter, epoch,
      ciphertext_sha256: (() => {
        const hash = NATIVE_CREATE_HASH("sha256");
        NATIVE_HASH_UPDATE.call(hash, canonicalEnvelope);
        return NATIVE_HASH_DIGEST.call(hash);
      })(),
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
    return NATIVE_FREEZE({ status: "SYNC_ZK1_PHYSICAL_ENVELOPE_VERIFIED_NONAUTHORIZING",
      operationId: Buffer.from(bound.operation.operation_id),
      ciphertextSha256: Buffer.from(bound.operation.ciphertext_sha256),
      receiptDigest: Buffer.from(result.receiptDigest),
      localPgReadbackVerified: true,
      historicalServerAdmissionProven: false,
      independentlyAnchoredFloorProven: false,
      externalDurabilityProven: false, authorizesIo: false });
  } catch (_) { deny(); }
}

// Opt-in historical READ authorization. A local journal hash, HTTP ACK or
// self-declared server bool cannot satisfy this verifier. The independently
// provisioned witness key must sign an exact envelope/PG receipt admission
// AND answer a fresh challenge with the exact externally pinned physical
// witness head. The equality rule deliberately rejects advancing histories
// until an authenticated ancestry protocol is available.
async function verifySyncV2HistoricalWitnessAdmission(input) {
  try {
    const v = strict(input, ["envelope", "scope", "expectedSequence", "expectedRoot",
      "receipt", "physicalAttestation", "nonce", "pinnedInventoryPublicKey",
      "pinnedInventorySignerKeyId", "pinnedPhysicalAttestorPublicKey",
      "localTrustedDevicePolicy", "trustedCurrentDevicePolicyProvider",
      "admission", "freshFloor", "pinnedWitnessPublicKey",
      "witnessKeyId", "statusKeyId", "trustedMinimumFloor"]);
    if (typeof v.trustedCurrentDevicePolicyProvider !== "function") deny();
    const bound = envelopeBinding(v.envelope, v.scope, v.expectedSequence, v.expectedRoot);
    const challenge = checkedBytes(v.nonce, 32);
    const committedInventoryReceipt = checkedBytes(v.receipt, 1,
      inventory.MAX_COMMITTED_PROOF_BYTES);
    const witnessId = checkedBytes(v.witnessKeyId, 16).toString("base64url");
    const statusId = checkedBytes(v.statusKeyId, 16).toString("base64url");
    const witness = pinnedOwnerPublicKey(v.pinnedWitnessPublicKey, "public");
    const deviceSpki = checkedBytes(Buffer.from(bound.envelope.authorization.publicKey,
      "base64url"), 44);
    const deviceKey = NATIVE_CREATE_PUBLIC_KEY({ key: deviceSpki,
      type: "spki", format: "der" });
    // Witness and all signers must be independently provisioned principals.
    for (const pin of [v.pinnedInventoryPublicKey, v.pinnedPhysicalAttestorPublicKey,
      deviceKey]) {
      if (NATIVE_KEY_EQUALS.call(witness, pinnedOwnerPublicKey(pin, "public"))) deny();
    }
    const floorFields = PHYSICAL_FLOOR_WIRE_FIELDS;
    const floor = strict(v.freshFloor, floorFields);
    const minimum = strict(v.trustedMinimumFloor,
      ["sequence", "lastHash", "physicalFenceDigest"]);
    const HEX = /^[a-f0-9]{64}$/;
    if (floor.type !== "rootark-zk1-witness-cas-physical-floor/v2"
      || floor.witnessKeyId !== witnessId || floor.statusKeyId !== statusId
      || floor.nonce !== challenge.toString("base64url")
      || !Number.isSafeInteger(floor.sequence) || floor.sequence < 1
      || floor.sequence > 100000 || !HEX.test(floor.lastHash)
      || !HEX.test(floor.physicalFenceDigest)
      || !Number.isSafeInteger(minimum.sequence) || minimum.sequence !== floor.sequence
      || minimum.lastHash !== floor.lastHash
      || minimum.physicalFenceDigest !== floor.physicalFenceDigest) deny();
    const canonicalSignature = (encoded) => {
      if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(encoded)) deny();
      return checkedBytes(Buffer.from(encoded, "base64url"), 64);
    };
    const floorUnsigned = NATIVE_PICK_SIGNED_FIELDS(floor, PHYSICAL_FLOOR_SIGNED_FIELDS);
    if (!NATIVE_VERIFY(null, NATIVE_BUFFER_CONCAT([PHYSICAL_FLOOR_DOMAIN,
      NATIVE_BUFFER_FROM(NATIVE_JSON_STRINGIFY(floorUnsigned))]), witness,
    canonicalSignature(floor.signature))) deny();

    const admissionFields = ADMISSION_WIRE_FIELDS;
    const admission = strict(v.admission, admissionFields);
    const digest = (data) => {
      const hash = NATIVE_CREATE_HASH("sha256");
      NATIVE_HASH_UPDATE.call(hash, data);
      return NATIVE_HASH_DIGEST.call(hash, "base64url");
    };
    if (admission.type !== "rootark-sync-v2-historical-witness-admission/v1"
      || admission.envelopeSha256 !== digest(bound.canonicalEnvelope)
      || admission.operationId !== bound.operation.operation_id.toString("base64url")
      || admission.deviceId !== bound.envelope.deviceId
      || admission.deviceSpkiSha256 !== digest(deviceSpki)
      || admission.epoch !== bound.operation.epoch
      || admission.checkpointSequence !== bound.operation.expected_sequence
      || admission.checkpointRoot !== bound.operation.expected_root.toString("base64url")
      || !Number.isSafeInteger(admission.admittedAtMs) || admission.admittedAtMs < 1
      || admission.admittedAtMs >= bound.envelope.authorization.expiresAt
      || admission.admittedAtMs > Date.now()
      || admission.witnessSequence !== floor.sequence
      || admission.witnessLastHash !== floor.lastHash
      || admission.witnessPhysicalFenceDigest !== floor.physicalFenceDigest) deny();
    const admissionUnsigned = NATIVE_PICK_SIGNED_FIELDS(admission, ADMISSION_SIGNED_FIELDS);
    if (!NATIVE_VERIFY(null, NATIVE_BUFFER_CONCAT([HISTORICAL_DOMAIN,
      NATIVE_BUFFER_FROM(NATIVE_JSON_STRINGIFY(admissionUnsigned))]), witness,
    canonicalSignature(admission.signature))) deny();
    // Both cryptographic verifications above happen before the asynchronous
    // PG/inventory proof check; all attacker-controlled values were detached.
    const physical = await verifySyncV2PhysicalEnvelopeEvidence({
      envelope: bound.envelope, scope: bound.scope,
      expectedSequence: bound.operation.expected_sequence,
      expectedRoot: bound.operation.expected_root,
      receipt: committedInventoryReceipt,
      physicalAttestation: checkedBytes(v.physicalAttestation, 1, 2048), nonce: challenge,
      pinnedInventoryPublicKey: v.pinnedInventoryPublicKey,
      pinnedInventorySignerKeyId: checkedBytes(v.pinnedInventorySignerKeyId, 16),
      pinnedPhysicalAttestorPublicKey: v.pinnedPhysicalAttestorPublicKey,
      localTrustedDevicePolicy: snapshotLocalDevicePolicy(v.localTrustedDevicePolicy),
    });
    // Bind the immutable inventory receipt rather than the fresh PG readback
    // signature: its nonce cannot be known when the *historical* admission is
    // signed. The current PG attestor signature is independently challenged.
    if (admission.inventoryReceiptSha256 !== digest(committedInventoryReceipt)
      || physical.localPgReadbackVerified !== true
      || physical.authorizesIo !== false) deny();
    // All awaited work is complete. The operator-owned live revocation source
    // must be sampled synchronously at the final historical READ decision.
    // A detached pre-await snapshot is insufficient: revocation can happen
    // while a valid Ed25519 PG signature is being checked.
    const live = snapshotLocalDevicePolicy(v.trustedCurrentDevicePolicyProvider());
    if (live.username !== bound.envelope.authorization.username
      || live.trustedDevicePublicKeys[bound.envelope.deviceId]
        !== bound.envelope.authorization.publicKey
      || NATIVE_ARRAY_INCLUDES.call(live.revokedDeviceIds, bound.envelope.deviceId)) deny();
    return NATIVE_FREEZE({ status: "SYNC_V2_HISTORICAL_WITNESS_VERIFIED",
      envelopeSha256: Buffer.from(bound.operation.ciphertext_sha256),
      historicalServerAdmissionProven: true, independentlyAnchoredFloorProven: true,
      localPgReadbackVerified: true, externalDurabilityProven: false,
      authorizesHistoricalRead: true, authorizesIo: false });
  } catch (_) {
    const error = new Error("SYNC_ZK1_HISTORICAL_ADMISSION_DENIED");
    error.code = error.message;
    throw error;
  }
}

module.exports = { envelopeBinding, physicalWriteRequest,
  snapshotLocalDevicePolicy, verifySyncV2PhysicalEnvelopeEvidence,
  verifySyncV2HistoricalWitnessAdmission };
