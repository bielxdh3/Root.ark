"use strict";

// Authenticates isolated, synthetic-compatible witness wire receipts. This
// module never authorizes recovery, admits content I/O, clears a pending gate,
// or verifies that the witness or CAS are independently operated/durable.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const PREFIX = "Root.ark/zk-1/recovery-witness-";
const MAX_RAW_BYTES = 8 * 1024 * 1024;
const COMMON_FIELDS = Object.freeze(["account_id", "compartment_id", "keyring_id",
  "reservation_id", "operation_id"]);
const OBJECTS = Object.freeze({
  reservation: Object.freeze({
    type: "rootark-recovery-witness-reservation/v1",
    domain: PREFIX + "reservation/v1",
    fields: Object.freeze([
      "type", "reservation_id", "witness_key_id", "account_id", "compartment_id",
      "keyring_id", "expected_revision", "expected_manifest_digest",
      "proposed_revision", "proposed_manifest_digest", "operation_id",
      "request_digest", "package_envelope_digest", "expires_at", "signature",
    ]),
  }),
  commit: Object.freeze({
    type: "rootark-recovery-witness-commit/v1",
    domain: PREFIX + "commit/v1",
    fields: Object.freeze([
      "type", "reservation_id", "account_id", "compartment_id", "keyring_id",
      "committed_revision", "committed_manifest_digest", "operation_id",
      "witness_sequence", "status", "signature",
    ]),
  }),
  cancel: Object.freeze({
    type: "rootark-recovery-witness-cancel/v1",
    domain: PREFIX + "cancel/v1",
    fields: Object.freeze([
      "type", "witness_key_id", "account_id", "compartment_id", "keyring_id",
      "reservation_id", "operation_id", "status_authority_proof_digest",
      "resolved_at", "status", "signature",
    ]),
  }),
});

function invalid() {
  throw new z.RootarkZkError("WITNESS_RECEIPT_INVALID");
}
function isBytes(value) {
  return Buffer.isBuffer(value) || value instanceof Uint8Array;
}
function bytesLen(value, n) {
  return isBytes(value) && value.byteLength === n;
}
function eqBytes(a, b) {
  return isBytes(a) && isBytes(b) && a.byteLength === b.byteLength
    && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function u64(v, minimum = 0n) {
  const n = typeof v === "bigint" ? v
    : Number.isSafeInteger(v) ? BigInt(v) : -1n;
  if (n < minimum || n > 0xffffffffffffffffn) invalid();
  return n;
}
function exact(a, b) {
  if (a === null || b === null) return a === b;
  if (isBytes(a) || isBytes(b)) return eqBytes(a, b);
  if (typeof a === "number" || typeof a === "bigint"
    || typeof b === "number" || typeof b === "bigint") return u64(a) === u64(b);
  return typeof a === typeof b && a === b;
}
function ensureScope(object) {
  if (!bytesLen(object.account_id, 16)
    || !isBytes(object.compartment_id)
    || object.compartment_id.byteLength < 1 || object.compartment_id.byteLength > 128
    || !bytesLen(object.keyring_id, 16)
    || !bytesLen(object.reservation_id, 16)
    || !bytesLen(object.operation_id, 16)) invalid();
}
function nextRevision(expected, proposed) {
  const next = u64(proposed, 1n);
  if (expected === null) {
    if (next !== 1n) invalid();
  } else {
    const prior = u64(expected, 1n);
    if (prior === 0xffffffffffffffffn || next !== prior + 1n) invalid();
  }
}
function validateReceipt(kind, proof, op, pinned, verifiedDigest) {
  ensureScope(proof);
  if (COMMON_FIELDS.some((key) => !exact(proof[key], op[key]))) invalid();
  if (kind === "reservation") {
    if (!bytesLen(proof.witness_key_id, 16)
      || !eqBytes(proof.witness_key_id, pinned.keyId)
      || !bytesLen(proof.proposed_manifest_digest, 32)
      || !bytesLen(proof.request_digest, 32)
      || (proof.package_envelope_digest !== null
        && !bytesLen(proof.package_envelope_digest, 32))
      || (proof.expected_revision === null) !== (proof.expected_manifest_digest === null)
      || (proof.expected_manifest_digest !== null
        && !bytesLen(proof.expected_manifest_digest, 32))) invalid();
    nextRevision(proof.expected_revision, proof.proposed_revision);
    u64(proof.expires_at);
    for (const key of ["expected_revision", "expected_manifest_digest",
      "proposed_revision", "proposed_manifest_digest", "request_digest",
      "package_envelope_digest"]) {
      if (!Object.hasOwn(op, key) || !exact(proof[key], op[key])) invalid();
    }
  } else if (kind === "commit") {
    if (proof.status !== "committed"
      || !bytesLen(proof.committed_manifest_digest, 32)
      || !Object.hasOwn(op, "proposed_revision")
      || !Object.hasOwn(op, "proposed_manifest_digest")
      || !bytesLen(op.proposed_manifest_digest, 32)
      || !exact(proof.committed_manifest_digest, op.proposed_manifest_digest)) invalid();
    const revision = u64(proof.committed_revision, 1n);
    if (u64(proof.witness_sequence, 1n) !== revision
      || u64(op.proposed_revision, 1n) !== revision) invalid();
  } else {
    if (proof.status !== "cancelled"
      || !bytesLen(proof.witness_key_id, 16)
      || !eqBytes(proof.witness_key_id, pinned.keyId)
      || !bytesLen(proof.status_authority_proof_digest, 32)
      || !bytesLen(verifiedDigest, 32)
      || !eqBytes(proof.status_authority_proof_digest, verifiedDigest)) invalid();
    u64(proof.resolved_at);
  }
}
async function verify(kind, input) {
  const def = OBJECTS[kind];
  const raw = input?.raw;
  const pinned = input?.pinned;
  const operation = input?.operation;
  if (!isBytes(raw) || raw.byteLength === 0 || raw.byteLength > MAX_RAW_BYTES
    || !pinned || !(pinned.publicKey instanceof crypto.KeyObject)
    || pinned.publicKey.type !== "public" || pinned.publicKey.asymmetricKeyType !== "ed25519"
    || !bytesLen(pinned.keyId, 16)
    || !operation || typeof operation !== "object" || Array.isArray(operation)
    || COMMON_FIELDS.some((field) => !Object.hasOwn(operation, field))) invalid();
  if (kind === "cancel" && !bytesLen(input.verifiedTerminalProofDigest, 32)) invalid();
  // Snapshot every caller-controlled byte before the first await. All signed
  // proof comparisons must refer to the exact input context at invocation.
  const rawSnapshot = Buffer.from(raw);
  const pinnedSnapshot = { publicKey: pinned.publicKey, keyId: Buffer.from(pinned.keyId) };
  const operationSnapshot = Object.create(null);
  for (const [key, value] of Object.entries(operation)) {
    operationSnapshot[key] = isBytes(value) ? Buffer.from(value) : value;
  }
  const digestSnapshot = kind === "cancel"
    ? Buffer.from(input.verifiedTerminalProofDigest) : undefined;
  try {
    const proof = await z.decodeDeterministic(rawSnapshot);
    if (!proof || typeof proof !== "object" || Array.isArray(proof)) invalid();
    const keys = Reflect.ownKeys(proof);
    if (keys.length !== def.fields.length
      || def.fields.some((field) => !Object.hasOwn(proof, field))
      || keys.some((key) => typeof key !== "string" || !def.fields.includes(key))
      || proof.type !== def.type || !bytesLen(proof.signature, 64)) invalid();
    validateReceipt(kind, proof, operationSnapshot, pinnedSnapshot, digestSnapshot);
    const unsigned = {};
    for (const field of def.fields) if (field !== "signature") unsigned[field] = proof[field];
    const bytes = Buffer.concat([
      Buffer.from(def.domain + "\0", "ascii"), await z.encodeDeterministic(unsigned),
    ]);
    if (!crypto.verify(null, bytes, pinnedSnapshot.publicKey, Buffer.from(proof.signature))) invalid();
  } catch (_) {
    invalid();
  }
  return Object.freeze({ verifiedSignatureOnly: true, authorizesRecovery: false, kind });
}

module.exports = {
  inspectVerifiedWitnessReservationV1: (input) => verify("reservation", input),
  inspectVerifiedWitnessCommitV1: (input) => verify("commit", input),
  inspectVerifiedWitnessCancellationV1: (input) => verify("cancel", input),
};
