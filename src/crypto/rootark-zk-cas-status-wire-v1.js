"use strict";

// Standalone verification of a signed CAS STATUS WIRE OBJECT only.
// This module deliberately does NOT authorize recovery, clear a witness
// reservation, establish terminal durability, or assert operator independence.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-cas-status/v1\0", "ascii");
const TYPE = "rootark-recovery-cas-status/v1";
const MAX_WIRE_BYTES = 8 * 1024 * 1024; // Bounds hostile decode; not a protocol size negotiation.
const FIELDS = Object.freeze([
  "type", "status_authority_key_id", "account_id", "compartment_id", "keyring_id",
  "reservation_id", "operation_id", "request_digest", "package_envelope_digest",
  "expected_revision", "expected_manifest_digest", "proposed_revision",
  "proposed_manifest_digest", "observed_revision", "observed_manifest_digest",
  "terminal_status", "observed_at", "nonce", "signature",
]);
const QUERY_FIELDS = Object.freeze([
  "account_id", "compartment_id", "keyring_id", "reservation_id", "operation_id",
  "request_digest", "package_envelope_digest", "expected_revision",
  "expected_manifest_digest", "proposed_revision", "proposed_manifest_digest",
]);

function invalid() {
  throw new z.RootarkZkError("AUTHORITY_PROOF_INVALID");
}
function isBytes(x) {
  return Buffer.isBuffer(x) || x instanceof Uint8Array;
}
function exactBytes(x, len) {
  return isBytes(x) && x.byteLength === len;
}
function eqBytes(a, b) {
  return isBytes(a) && isBytes(b) && a.byteLength === b.byteLength
    && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function u64(v, min = 0n) {
  let value;
  if (typeof v === "bigint") value = v;
  else if (Number.isSafeInteger(v)) value = BigInt(v);
  else invalid();
  if (value < min || value > 0xffffffffffffffffn) invalid();
  return value;
}
function exact(a, b) {
  if (a === null || b === null) return a === b;
  if (isBytes(a) || isBytes(b)) return eqBytes(a, b);
  if ((typeof a === "number" || typeof a === "bigint")
    && (typeof b === "number" || typeof b === "bigint")) return u64(a) === u64(b);
  return typeof a === typeof b && a === b;
}
function validateFields(p) {
  if (!p || typeof p !== "object" || Array.isArray(p)) invalid();
  const keys = Reflect.ownKeys(p);
  if (keys.length !== FIELDS.length || FIELDS.some((k) => !Object.hasOwn(p, k))
    || keys.some((k) => typeof k !== "string" || !FIELDS.includes(k))) invalid();
  if (p.type !== TYPE || !exactBytes(p.signature, 64)
    || !exactBytes(p.status_authority_key_id, 16)
    || !exactBytes(p.account_id, 16)
    || !isBytes(p.compartment_id) || p.compartment_id.byteLength < 1
    || p.compartment_id.byteLength > 128
    || !exactBytes(p.keyring_id, 16) || !exactBytes(p.reservation_id, 16)
    || !exactBytes(p.operation_id, 16)
    || !exactBytes(p.request_digest, 32)
    || (p.package_envelope_digest !== null && !exactBytes(p.package_envelope_digest, 32))
    || !exactBytes(p.proposed_manifest_digest, 32)
    || !exactBytes(p.nonce, 32)) invalid();
  u64(p.observed_at);
  const proposed = u64(p.proposed_revision, 1n);
  if ((p.expected_revision === null) !== (p.expected_manifest_digest === null)) invalid();
  if (p.expected_revision === null) {
    if (proposed !== 1n) invalid();
  } else {
    const expected = u64(p.expected_revision, 1n);
    if (!exactBytes(p.expected_manifest_digest, 32)
      || expected === 0xffffffffffffffffn || proposed !== expected + 1n) invalid();
  }
  if ((p.observed_revision === null) !== (p.observed_manifest_digest === null)) invalid();
  if (p.observed_revision !== null) {
    u64(p.observed_revision, 1n);
    if (!exactBytes(p.observed_manifest_digest, 32)) invalid();
  }
  if (p.terminal_status === "committed") {
    if (p.observed_revision === null
      || u64(p.observed_revision) !== proposed
      || !eqBytes(p.observed_manifest_digest, p.proposed_manifest_digest)) invalid();
  } else if (p.terminal_status === "not-committed-final") {
    if (p.expected_revision === null) {
      if (p.observed_revision !== null) invalid();
    } else if (p.observed_revision === null
      || u64(p.observed_revision) !== u64(p.expected_revision)
      || !eqBytes(p.observed_manifest_digest, p.expected_manifest_digest)) invalid();
  } else invalid();
}

async function inspectVerifiedCasStatusProofV1(input) {
  const raw = input?.raw;
  const pinned = input?.pinned;
  const query = input?.query;
  const nonce = input?.nonce;
  if (!isBytes(raw) || raw.byteLength === 0 || raw.byteLength > MAX_WIRE_BYTES
    || !pinned || !(pinned.publicKey instanceof crypto.KeyObject)
    || pinned.publicKey.type !== "public" || pinned.publicKey.asymmetricKeyType !== "ed25519"
    || !exactBytes(pinned.keyId, 16) || !exactBytes(nonce, 32)
    || !query || typeof query !== "object" || Array.isArray(query)
    || QUERY_FIELDS.some((k) => !Object.hasOwn(query, k))) invalid();
  // Make caller-provided proof and verification context immutable at the
  // invocation boundary. decodeDeterministic awaits an async module import;
  // mutable byte views could otherwise change before the tuple/nonce checks.
  const pinnedPublicKey = pinned.publicKey;
  const rawSnapshot = Buffer.from(raw);
  const keyIdSnapshot = Buffer.from(pinned.keyId);
  const nonceSnapshot = Buffer.from(nonce);
  const querySnapshot = Object.create(null);
  for (const field of QUERY_FIELDS) {
    const value = query[field];
    querySnapshot[field] = isBytes(value) ? Buffer.from(value) : value;
  }
  let proof;
  try {
    proof = await z.decodeDeterministic(rawSnapshot);
    validateFields(proof);
    if (!eqBytes(proof.status_authority_key_id, keyIdSnapshot)
      || !eqBytes(proof.nonce, nonceSnapshot)
      || QUERY_FIELDS.some((field) => !exact(proof[field], querySnapshot[field]))) invalid();
    const unsigned = {};
    for (const field of FIELDS) {
      if (field !== "signature") unsigned[field] = proof[field];
    }
    const signed = Buffer.concat([DOMAIN, await z.encodeDeterministic(unsigned)]);
    if (!crypto.verify(null, signed, pinnedPublicKey, Buffer.from(proof.signature))) invalid();
  } catch (_error) {
    invalid();
  }
  // Verified bytes alone cannot establish an authoritative result, fence,
  // expiry/skew health, witness high-water or physical data-plane admission.
  return Object.freeze({
    verifiedSignatureOnly: true,
    authorizesRecovery: false,
    terminal_status: proof.terminal_status,
    observed_revision: proof.observed_revision,
  });
}

module.exports = { inspectVerifiedCasStatusProofV1 };
