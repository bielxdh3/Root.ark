"use strict";

// Non-authorizing evidence produced by an independently operated, read-only
// PostgreSQL attestor AFTER it has verified bytes and a WAL flush barrier.
// Neither this signature nor an mTLS ACK proves external/cloud durability.
const crypto = require("node:crypto");
const { freeze: NATIVE_FREEZE, verify: NATIVE_VERIFY, mathAbs: NATIVE_MATH_ABS,
  sign: NATIVE_SIGN, timingSafeEqual: NATIVE_TIMING_SAFE_EQUAL, bufferConcat: NATIVE_BUFFER_CONCAT, bufferFrom: NATIVE_BUFFER_FROM, ownKeys: NATIVE_OWN_KEYS, ownDescriptor: NATIVE_DESCRIPTOR,
  getPrototype: NATIVE_GET_PROTOTYPE, hasOwn: NATIVE_HAS_OWN, arrayIsArray: NATIVE_IS_ARRAY } =
  require("./rootark-zk10-native-intrinsics-v1");
const z = require("./rootark-zk-1");

const DOMAIN = NATIVE_BUFFER_FROM("Root.ark/zk-1/physical-pg-readback-attestation/v1\0");
const TYPE = "rootark-zk1-physical-pg-readback-attestation/v1";
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "operation_id", "object_id", "revision", "epoch", "expected_inventory_sequence",
  "expected_inventory_root", "ciphertext_sha256", "physical_digest", "chunk_root",
  "chunk_count", "generation", "admission_id", "nonce", "issued_at"];
const ALL_FIELDS = [...FIELDS, "signature"];

function deny() {
  const e = new Error("ZK_PHYSICAL_ATTESTATION_DENIED");
  e.code = e.message;
  throw e;
}
function exact(v, keys) {
  if (!v || typeof v !== "object" || NATIVE_IS_ARRAY(v)) deny();
  const prototype = NATIVE_GET_PROTOTYPE(v);
  if (prototype !== Object.prototype && prototype !== null) deny();
  if (NATIVE_OWN_KEYS(v).length !== keys.length) deny();
  for (let i = 0; i < keys.length; i += 1) {
    const key = keys[i];
    if (!NATIVE_HAS_OWN(v, key) || !NATIVE_HAS_OWN(NATIVE_DESCRIPTOR(v, key), "value")) deny();
  }
}
function matchSignedBytes(unsigned, target, fields) {
  for (let i = 0; i < fields.length; i += 1) {
    const field = fields[i];
    if (!same(bytes(unsigned[field], target[field].length), target[field])) return false;
  }
  return true;
}
function hasSignedFields(unsigned) {
  for (let i = 0; i < FIELDS.length; i += 1) {
    if (!NATIVE_HAS_OWN(unsigned, FIELDS[i])) return false;
  }
  return true;
}function bytes(v, length) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array)) || v.length !== length
    || (typeof SharedArrayBuffer !== "undefined" && v.buffer instanceof SharedArrayBuffer)) deny();
  return NATIVE_BUFFER_FROM(v);
}
function count(n, minimum) {
  if (!Number.isSafeInteger(n) || n < minimum) deny();
  return n;
}
function same(a, b) {
  return a.length === b.length && NATIVE_TIMING_SAFE_EQUAL(a, b);
}
function key(value, kind) {
  if (!(value instanceof crypto.KeyObject) || value.type !== kind
    || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function scopeOf(scope) {
  exact(scope, ["account_id", "compartment_id", "keyring_id"]);
  const compartment = scope.compartment_id;
  if ((!Buffer.isBuffer(compartment) && !(compartment instanceof Uint8Array))
    || compartment.length < 1 || compartment.length > 128) deny();
  return { account_id: bytes(scope.account_id, 16),
    compartment_id: NATIVE_BUFFER_FROM(compartment), keyring_id: bytes(scope.keyring_id, 16) };
}
function operationOf(op) {
  exact(op, ["operation_id", "expected_sequence", "expected_root", "object_id",
    "revision", "epoch", "ciphertext_sha256"]);
  return { operation_id: bytes(op.operation_id, 16),
    object_id: bytes(op.object_id, 16), revision: count(op.revision, 1),
    epoch: count(op.epoch, 0), expected_inventory_sequence: count(op.expected_sequence, 0),
    expected_inventory_root: bytes(op.expected_root, 32),
    ciphertext_sha256: bytes(op.ciphertext_sha256, 32) };
}
function claimsOf({ scope, operation, readback, nonce, issuedAt }) {
  const o = operationOf(operation);
  exact(readback, ["status", "verified", "walFlushConfirmed", "generation",
    "admissionId", "operationId", "revision", "epoch", "digest",
    "expectedInventorySequence", "expectedInventoryRoot", "chunkCount", "root",
    "ciphertextSha256", "authorizesIo", "provesIndependentOperator"]);
  if (readback.status !== "PHYSICALLY_REREAD_PG_COMMITTED"
    || readback.verified !== true || readback.walFlushConfirmed !== true
    || readback.authorizesIo !== false || readback.provesIndependentOperator !== false
    || readback.revision !== o.revision || readback.epoch !== o.epoch
    || readback.expectedInventorySequence !== o.expected_inventory_sequence
    || !same(bytes(readback.expectedInventoryRoot, 32), o.expected_inventory_root)
    || !same(bytes(readback.operationId, 16), o.operation_id)
    || !same(bytes(readback.ciphertextSha256, 32), o.ciphertext_sha256)) deny();
  const issued = count(issuedAt, 1);
  return { type: TYPE, ...scopeOf(scope), ...o,
    physical_digest: bytes(readback.digest, 32),
    chunk_root: bytes(readback.root, 32),
    chunk_count: count(readback.chunkCount, 1),
    generation: count(readback.generation, 1),
    admission_id: bytes(readback.admissionId, 16), nonce: bytes(nonce, 32),
    issued_at: issued };
}

async function signCommittedPhysicalReadback(request, attestorPrivateKey) {
  try {
    key(attestorPrivateKey, "private");
    exact(request, ["scope", "operation", "readback", "nonce", "issuedAt"]);
    const unsigned = claimsOf(request);
    const encoded = NATIVE_BUFFER_FROM(await z.encodeDeterministic(unsigned));
    const signature = NATIVE_SIGN(null, NATIVE_BUFFER_CONCAT([DOMAIN, encoded]), attestorPrivateKey);
    return NATIVE_BUFFER_FROM(await z.encodeDeterministic({ ...unsigned, signature }));
  } catch (_) { deny(); }
}

async function verifyCommittedPhysicalReadback(raw, options = {}) {
  try {
    exact(options, ["scope", "operation", "expected", "nonce", "pinnedPublicKey", "nowSeconds"]);
    const expected = options.expected;
    if (expected !== undefined) exact(expected, ["digest", "root", "chunks"]);
    // Snapshot every operator-supplied expected byte/clock before the native
    // KeyObject can execute an inherited kHandle or other property getter.
    const op = operationOf(options.operation);
    const scope = scopeOf(options.scope);
    const challenge = bytes(options.nonce, 32);
    const nowSeconds = count(options.nowSeconds, 1);
    const expectedSnapshot = expected === undefined ? undefined : {
      digest: bytes(expected.digest, 32), root: bytes(expected.root, 32),
      chunks: count(expected.chunks, 1),
    };
    // Validate the untrusted transport value *before* any Buffer.from coercion.
    // A foreign object may have an attacker-supplied iterator/valueOf; an
    // enormous typed array must never be copied merely to measure its size.
    if ((!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array))
      || raw.length < 1 || raw.length > 2048
      || (typeof SharedArrayBuffer !== "undefined"
        && raw.buffer instanceof SharedArrayBuffer)) deny();
    const serialized = NATIVE_BUFFER_FROM(raw);
    const pin = key(options.pinnedPublicKey, "public");
    const proof = await z.decodeDeterministic(serialized);
    exact(proof, ALL_FIELDS);
    const { signature, ...unsigned } = proof;
    const canonical = NATIVE_BUFFER_FROM(await z.encodeDeterministic({ ...unsigned, signature }));
    if (!same(canonical, serialized)) deny();
    const encoded = NATIVE_BUFFER_FROM(await z.encodeDeterministic(unsigned));
    if (!NATIVE_VERIFY(null, NATIVE_BUFFER_CONCAT([DOMAIN, encoded]), pin, bytes(signature, 64))) deny();
    if (unsigned.type !== TYPE || !hasSignedFields(unsigned)
      || !matchSignedBytes(unsigned, scope, ["account_id", "compartment_id", "keyring_id"])
      || !matchSignedBytes(unsigned, op,
        ["operation_id", "object_id", "expected_inventory_root", "ciphertext_sha256"])
      || unsigned.revision !== op.revision || unsigned.epoch !== op.epoch
      || unsigned.expected_inventory_sequence !== op.expected_inventory_sequence
      || !same(bytes(unsigned.nonce, 32), challenge)
      || (expectedSnapshot !== undefined
        && (!same(bytes(unsigned.physical_digest, 32), expectedSnapshot.digest)
          || !same(bytes(unsigned.chunk_root, 32), expectedSnapshot.root)
          || unsigned.chunk_count !== expectedSnapshot.chunks))
      || !Number.isSafeInteger(unsigned.issued_at)
      || NATIVE_MATH_ABS(nowSeconds - unsigned.issued_at) > 30) deny();
    const generation = count(unsigned.generation, 1);
    const physicalDigest = bytes(unsigned.physical_digest, 32);
    const chunkRoot = bytes(unsigned.chunk_root, 32);
    const chunkCount = count(unsigned.chunk_count, 1);
    bytes(unsigned.admission_id, 16);
    return NATIVE_FREEZE({ status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation, admissionId: NATIVE_BUFFER_FROM(unsigned.admission_id),
      physicalDigest, chunkRoot, chunkCount,
      // Return the already-verified, signed issuance time so callers that
      // perform more asynchronous work can enforce freshness again at use.
      issuedAt: unsigned.issued_at,
      operationId: NATIVE_BUFFER_FROM(op.operation_id), authorizesIo: false,
      provesIndependentOperator: false });
  } catch (_) { deny(); }
}

module.exports = { signCommittedPhysicalReadback, verifyCommittedPhysicalReadback,
  DOMAIN, TYPE };
