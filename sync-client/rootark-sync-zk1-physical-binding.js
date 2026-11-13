"use strict";

// Opt-in, NON-AUTHORIZING bridge between the exact signed Sync v2 envelope
// bytes and an independently signed ZK1 inventory + PostgreSQL readback.
// The physical writer must have stored these SAME canonical envelope bytes as
// its opaque ciphertext object. A server-supplied operation mapping or a
// success flag is never evidence of such a write. An admission timestamp,
// witness/CAS floor, and external cloud durability are NOT proven here.
const crypto = require("node:crypto");
const { types: { isProxy, isPromise } } = require("node:util");
// A native Ed25519 KeyObject getter runs before later local policy snapshots.
// Define own array data slots instead of consulting mutable Array.push.
const NATIVE_DEFINE_PROPERTY = Object.defineProperty.bind(Object);
const NATIVE_OBJECT_PROTOTYPE = Object.prototype;
const NATIVE_PROMISE = Promise;
const NATIVE_IS_SAFE_INTEGER = Number.isSafeInteger.bind(Number);
const { arrayIncludes: NATIVE_ARRAY_INCLUDES,
  arrayIsArray: NATIVE_ARRAY_IS_ARRAY,
  getPrototype: NATIVE_GET_PROTOTYPE,
  ownKeys: NATIVE_OWN_KEYS,
  ownDescriptor: NATIVE_OWN_DESCRIPTOR,
  hasOwn: NATIVE_HAS_OWN,
  objectCreate: NATIVE_OBJECT_CREATE,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT,
  bufferToString: NATIVE_BUFFER_TO_STRING,
  jsonStringify: NATIVE_JSON_STRINGIFY,
  pickSignedFields: NATIVE_PICK_SIGNED_FIELDS,
  createHash: NATIVE_CREATE_HASH,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  createPublicKey: NATIVE_CREATE_PUBLIC_KEY,
  verify: NATIVE_VERIFY,
  keyEquals: NATIVE_KEY_EQUALS,
  freeze: NATIVE_FREEZE,
  dateNow: NATIVE_DATE_NOW,
  mathFloor: NATIVE_MATH_FLOOR,
  mathAbs: NATIVE_MATH_ABS } =
  require("../src/crypto/rootark-zk10-native-intrinsics-v1");
const { pinNativeEd25519PublicKey } =
  require("../src/crypto/rootark-zk1-native-ed25519-public-key");
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
const FLOOR_UNSIGNED_FIELDS = NATIVE_FREEZE(["type", "witnessKeyId", "statusKeyId",
  "sequence", "lastHash", "physicalFenceDigest", "nonce"]);
const FLOOR_FIELDS = NATIVE_FREEZE(["type", "witnessKeyId", "statusKeyId",
  "sequence", "lastHash", "physicalFenceDigest", "nonce", "signature"]);
const ADMISSION_UNSIGNED_FIELDS = NATIVE_FREEZE(["type", "envelopeSha256", "operationId",
  "deviceId", "deviceSpkiSha256", "epoch", "checkpointSequence", "checkpointRoot",
  "inventoryReceiptSha256", "admittedAtMs", "witnessSequence", "witnessLastHash",
  "witnessPhysicalFenceDigest"]);
const ADMISSION_FIELDS = NATIVE_FREEZE(["type", "envelopeSha256", "operationId",
  "deviceId", "deviceSpkiSha256", "epoch", "checkpointSequence", "checkpointRoot",
  "inventoryReceiptSha256", "admittedAtMs", "witnessSequence", "witnessLastHash",
  "witnessPhysicalFenceDigest", "signature"]);
const MAX_CANONICAL_ENVELOPE_BYTES = 9 * 1024 * 1024;
const PG_CHUNK_BYTES = 1024 * 1024;

function deny() {
  const error = new Error("SYNC_ZK1_PHYSICAL_BINDING_DENIED");
  error.code = error.message;
  throw error;
}
function pinnedNativeAwait(value) {
  // Await normally reads Promise.prototype.constructor and assimilates `.then`
  // when those properties no longer identify the native constructor. A hostile
  // KeyObject getter could otherwise turn a rejected PG/device verifier into
  // an attacker-supplied successful result after the Ed25519 check was skipped.
  if (isProxy(value) || !isPromise(value)) deny();
  NATIVE_DEFINE_PROPERTY(value, "constructor", {
    value: NATIVE_PROMISE, enumerable: false, configurable: false, writable: false,
  });
  return value;
}
function strict(raw, fields) {
  if (!raw || typeof raw !== "object" || isProxy(raw) || NATIVE_ARRAY_IS_ARRAY(raw)) deny();
  const prototype = NATIVE_GET_PROTOTYPE(raw);
  if ((prototype !== NATIVE_OBJECT_PROTOTYPE && prototype !== null)
    || NATIVE_OWN_KEYS(raw).length !== fields.length) deny();
  const result = NATIVE_OBJECT_CREATE(null);
  for (let index = 0; index < fields.length; index += 1) {
    const field = fields[index];
    const descriptor = NATIVE_OWN_DESCRIPTOR(raw, field);
    if (typeof field !== "string" || !descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    NATIVE_DEFINE_PROPERTY(result, field, { value: descriptor.value,
      enumerable: true, configurable: true, writable: true });
  }
  return result;
}
function checkedBytes(value, min, max = min) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max
    || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)) deny();
  return NATIVE_BUFFER_FROM(value);
}
function nativeDigest(value) {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, value);
  return NATIVE_HASH_DIGEST.call(hash, "base64url");
}
function signedWire(domain, snapshot, fields) {
  return NATIVE_BUFFER_CONCAT([domain,
    NATIVE_BUFFER_FROM(NATIVE_JSON_STRINGIFY(
      NATIVE_PICK_SIGNED_FIELDS(snapshot, fields)), "utf8")]);
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
    || isProxy(raw.trustedDevicePublicKeys) || isProxy(raw.revokedDeviceIds)
    || NATIVE_ARRAY_IS_ARRAY(raw.trustedDevicePublicKeys)
    || (NATIVE_GET_PROTOTYPE(raw.trustedDevicePublicKeys) !== NATIVE_OBJECT_PROTOTYPE
      && NATIVE_GET_PROTOTYPE(raw.trustedDevicePublicKeys) !== null)
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
    NATIVE_DEFINE_PROPERTY(pins, deviceId, { value: spki,
      enumerable: true, configurable: true, writable: true });
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
    NATIVE_DEFINE_PROPERTY(seen, deviceId, { value: true,
      enumerable: true, configurable: true, writable: false });
    NATIVE_DEFINE_PROPERTY(revoked, String(index), {
      value: deviceId, enumerable: true, writable: true, configurable: true,
    });
  }
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
    if (await pinnedNativeAwait(verifyAuthorizationProof(bound.envelope.authorization,
      bound.envelope, policy)) !== true
      || bound.envelope.authorization.expiresAt <= NATIVE_DATE_NOW()) deny();
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
    if (await pinnedNativeAwait(verifyHistoricalAuthorizationProof(bound.envelope.authorization,
      bound.envelope, policy)) !== true) deny();
    const result = await pinnedNativeAwait(verifyAttestedInventoryCommit({
      receipt, physicalAttestation: attestation, scope: bound.scope,
      operation: bound.operation, nonce,
      pinnedInventoryPublicKey: inventoryKey,
      pinnedInventorySignerKeyId: signerKeyId,
      pinnedPhysicalAttestorPublicKey: physicalKey,
      nowSeconds: NATIVE_MATH_FLOOR(NATIVE_DATE_NOW() / 1000),
    }));
    const completedAtSeconds = NATIVE_MATH_FLOOR(NATIVE_DATE_NOW() / 1000);
    if (result.status !== "VERIFIED_COMPOSITE_NONAUTHORIZING"
      || result.authorizesIo !== false
      // A proof may cross the ±30 s physical freshness window while CBOR and
      // Ed25519 verification await. Recheck the SIGNED issuance timestamp
      // rather than relying only on the pre-await wall-clock sample.
      || !NATIVE_IS_SAFE_INTEGER(result.physicalReadback?.issuedAt)
      || !NATIVE_IS_SAFE_INTEGER(completedAtSeconds) || completedAtSeconds < 1
      || NATIVE_MATH_ABS(completedAtSeconds - result.physicalReadback.issuedAt) > 30) deny();
    return NATIVE_FREEZE({ status: "SYNC_ZK1_PHYSICAL_ENVELOPE_VERIFIED_NONAUTHORIZING",
      operationId: NATIVE_BUFFER_FROM(bound.operation.operation_id),
      ciphertextSha256: NATIVE_BUFFER_FROM(bound.operation.ciphertext_sha256),
      receiptDigest: NATIVE_BUFFER_FROM(result.receiptDigest),
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
    const witnessId = NATIVE_BUFFER_TO_STRING.call(checkedBytes(v.witnessKeyId, 16), "base64url");
    const statusId = NATIVE_BUFFER_TO_STRING.call(checkedBytes(v.statusKeyId, 16), "base64url");
    // Bind every caller-owned expected byte, record and device identity BEFORE
    // any KeyObject getter can rewrite ambient factories or the input graph.
    const floor = strict(v.freshFloor, FLOOR_FIELDS);
    const minimum = strict(v.trustedMinimumFloor,
      ["sequence", "lastHash", "physicalFenceDigest"]);
    const admission = strict(v.admission, ADMISSION_FIELDS);
    const physicalAttestation = checkedBytes(v.physicalAttestation, 1, 2048);
    const inventorySignerKeyId = checkedBytes(v.pinnedInventorySignerKeyId, 16);
    const initialDevicePolicy = snapshotLocalDevicePolicy(v.localTrustedDevicePolicy);
    const deviceSpki = checkedBytes(NATIVE_BUFFER_FROM(
      bound.envelope.authorization.publicKey, "base64url"), 44);
    const deviceKey = NATIVE_CREATE_PUBLIC_KEY({ key: deviceSpki,
      type: "spki", format: "der" });
    // A native key getter can retarget its inherited kHandle. Reimport stable
    // SPKI identities and compare only native, independent verifier keys.
    const witness = pinNativeEd25519PublicKey(v.pinnedWitnessPublicKey);
    const inventoryKey = pinNativeEd25519PublicKey(v.pinnedInventoryPublicKey);
    const attestorKey = pinNativeEd25519PublicKey(v.pinnedPhysicalAttestorPublicKey);
    const roles = [inventoryKey, attestorKey, deviceKey];
    for (let index = 0; index < roles.length; index += 1) {
      if (NATIVE_KEY_EQUALS.call(witness, roles[index])) deny();
    }
    const HEX = /^[a-f0-9]{64}$/;
    if (floor.type !== "rootark-zk1-witness-cas-physical-floor/v2"
      || floor.witnessKeyId !== witnessId || floor.statusKeyId !== statusId
      || floor.nonce !== NATIVE_BUFFER_TO_STRING.call(challenge, "base64url")
      || !Number.isSafeInteger(floor.sequence) || floor.sequence < 1
      || floor.sequence > 100000 || !HEX.test(floor.lastHash)
      || !HEX.test(floor.physicalFenceDigest)
      || !Number.isSafeInteger(minimum.sequence) || minimum.sequence !== floor.sequence
      || minimum.lastHash !== floor.lastHash
      || minimum.physicalFenceDigest !== floor.physicalFenceDigest) deny();
    const canonicalSignature = (encoded) => {
      if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(encoded)) deny();
      return checkedBytes(NATIVE_BUFFER_FROM(encoded, "base64url"), 64);
    };
    if (!NATIVE_VERIFY(null, signedWire(PHYSICAL_FLOOR_DOMAIN,
      floor, FLOOR_UNSIGNED_FIELDS), witness, canonicalSignature(floor.signature))) deny();

    const digest = nativeDigest;
    if (admission.type !== "rootark-sync-v2-historical-witness-admission/v1"
      || admission.envelopeSha256 !== digest(bound.canonicalEnvelope)
      || admission.operationId !== NATIVE_BUFFER_TO_STRING.call(
        bound.operation.operation_id, "base64url")
      || admission.deviceId !== bound.envelope.deviceId
      || admission.deviceSpkiSha256 !== digest(deviceSpki)
      || admission.epoch !== bound.operation.epoch
      || admission.checkpointSequence !== bound.operation.expected_sequence
      || admission.checkpointRoot !== NATIVE_BUFFER_TO_STRING.call(
        bound.operation.expected_root, "base64url")
      || !Number.isSafeInteger(admission.admittedAtMs) || admission.admittedAtMs < 1
      || admission.admittedAtMs >= bound.envelope.authorization.expiresAt
      || admission.admittedAtMs > NATIVE_DATE_NOW()
      || admission.witnessSequence !== floor.sequence
      || admission.witnessLastHash !== floor.lastHash
      || admission.witnessPhysicalFenceDigest !== floor.physicalFenceDigest) deny();
    if (!NATIVE_VERIFY(null, signedWire(HISTORICAL_DOMAIN,
      admission, ADMISSION_UNSIGNED_FIELDS), witness,
    canonicalSignature(admission.signature))) deny();
    // Both cryptographic verifications above happen before the asynchronous
    // PG/inventory proof check; all attacker-controlled values were detached.
    const physical = await pinnedNativeAwait(verifySyncV2PhysicalEnvelopeEvidence({
      envelope: bound.envelope, scope: bound.scope,
      expectedSequence: bound.operation.expected_sequence,
      expectedRoot: bound.operation.expected_root,
      receipt: committedInventoryReceipt,
      physicalAttestation, nonce: challenge,
      pinnedInventoryPublicKey: inventoryKey,
      pinnedInventorySignerKeyId: inventorySignerKeyId,
      pinnedPhysicalAttestorPublicKey: attestorKey,
      localTrustedDevicePolicy: initialDevicePolicy,
    }));
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
      envelopeSha256: NATIVE_BUFFER_FROM(bound.operation.ciphertext_sha256),
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
