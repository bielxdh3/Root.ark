"use strict";

// Non-authorizing evidence produced by an independently operated, read-only
// PostgreSQL attestor AFTER it has verified bytes and a WAL flush barrier.
// Neither this signature nor an mTLS ACK proves external/cloud durability.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const DOMAIN = Buffer.from("Root.ark/zk-1/physical-pg-readback-attestation/v1\0");
const TYPE = "rootark-zk1-physical-pg-readback-attestation/v1";
const FIELDS = ["type", "account_id", "compartment_id", "keyring_id",
  "operation_id", "object_id", "revision", "epoch", "expected_inventory_sequence",
  "expected_inventory_root", "ciphertext_sha256", "physical_digest", "chunk_root",
  "chunk_count", "generation", "admission_id", "nonce", "issued_at"];

function deny() {
  const e = new Error("ZK_PHYSICAL_ATTESTATION_DENIED");
  e.code = e.message;
  throw e;
}
function exact(v, keys) {
  if (!v || typeof v !== "object" || Array.isArray(v)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(v))
    || Reflect.ownKeys(v).length !== keys.length
    || keys.some((name) => !Object.hasOwn(v, name)
      || !Object.hasOwn(Object.getOwnPropertyDescriptor(v, name), "value"))) deny();
}
function bytes(v, length) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array)) || v.length !== length
    || (typeof SharedArrayBuffer !== "undefined" && v.buffer instanceof SharedArrayBuffer)) deny();
  return Buffer.from(v);
}
function count(n, minimum) {
  if (!Number.isSafeInteger(n) || n < minimum) deny();
  return n;
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
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
    compartment_id: Buffer.from(compartment), keyring_id: bytes(scope.keyring_id, 16) };
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
    const encoded = Buffer.from(await z.encodeDeterministic(unsigned));
    const signature = crypto.sign(null, Buffer.concat([DOMAIN, encoded]), attestorPrivateKey);
    return Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
  } catch (_) { deny(); }
}

async function verifyCommittedPhysicalReadback(raw, options = {}) {
  try {
    exact(options, ["scope", "operation", "expected", "nonce", "pinnedPublicKey", "nowSeconds"]);
    const pin = key(options.pinnedPublicKey, "public");
    const expected = options.expected;
    if (expected !== undefined) exact(expected, ["digest", "root", "chunks"]);
    // Validate the untrusted transport value *before* any Buffer.from coercion.
    // A foreign object may have an attacker-supplied iterator/valueOf; an
    // enormous typed array must never be copied merely to measure its size.
    if ((!Buffer.isBuffer(raw) && !(raw instanceof Uint8Array))
      || raw.length < 1 || raw.length > 2048
      || (typeof SharedArrayBuffer !== "undefined"
        && raw.buffer instanceof SharedArrayBuffer)) deny();
    const serialized = Buffer.from(raw);
    const proof = await z.decodeDeterministic(serialized);
    exact(proof, [...FIELDS, "signature"]);
    const { signature, ...unsigned } = proof;
    const canonical = Buffer.from(await z.encodeDeterministic({ ...unsigned, signature }));
    if (!same(canonical, serialized)) deny();
    const encoded = Buffer.from(await z.encodeDeterministic(unsigned));
    if (!crypto.verify(null, Buffer.concat([DOMAIN, encoded]), pin, bytes(signature, 64))) deny();
    const op = operationOf(options.operation);
    const scope = scopeOf(options.scope);
    if (unsigned.type !== TYPE || !FIELDS.every((f) => Object.hasOwn(unsigned, f))
      || !["account_id", "compartment_id", "keyring_id"].every((f) =>
        same(bytes(unsigned[f], scope[f].length), scope[f]))
      || !["operation_id", "object_id", "expected_inventory_root", "ciphertext_sha256"]
        .every((f) => same(bytes(unsigned[f], op[f].length), op[f]))
      || unsigned.revision !== op.revision || unsigned.epoch !== op.epoch
      || unsigned.expected_inventory_sequence !== op.expected_inventory_sequence
      || !same(bytes(unsigned.nonce, 32), bytes(options.nonce, 32))
      || (expected !== undefined
        && (!same(bytes(unsigned.physical_digest, 32), bytes(expected.digest, 32))
          || !same(bytes(unsigned.chunk_root, 32), bytes(expected.root, 32))
          || unsigned.chunk_count !== count(expected.chunks, 1)))
      || !Number.isSafeInteger(unsigned.issued_at)
      || Math.abs(count(options.nowSeconds, 1) - unsigned.issued_at) > 30) deny();
    const generation = count(unsigned.generation, 1);
    const physicalDigest = bytes(unsigned.physical_digest, 32);
    const chunkRoot = bytes(unsigned.chunk_root, 32);
    const chunkCount = count(unsigned.chunk_count, 1);
    bytes(unsigned.admission_id, 16);
    return Object.freeze({ status: "PHYSICALLY_REREAD_PG_COMMITTED", verified: true,
      walFlushConfirmed: true, generation, admissionId: Buffer.from(unsigned.admission_id),
      physicalDigest, chunkRoot, chunkCount,
      operationId: Buffer.from(op.operation_id), authorizesIo: false,
      provesIndependentOperator: false });
  } catch (_) { deny(); }
}

module.exports = { signCommittedPhysicalReadback, verifyCommittedPhysicalReadback,
  DOMAIN, TYPE };
