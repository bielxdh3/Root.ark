"use strict";

// Purely verifies a committed witness-head WIRE RECEIPT. It cannot establish
// independence of the witness, monotonic device storage or authorize any
// recovery, content I/O, gate opening, or protected key usage.
const crypto = require("node:crypto");
const z = require("./rootark-zk-1");

const TYPE = "rootark-recovery-witness-head/v1";
const DOMAIN = Buffer.from("Root.ark/zk-1/recovery-witness-head/v1\0", "ascii");
const MAX_RAW_BYTES = 8 * 1024 * 1024;
const FIELDS = Object.freeze([
  "type", "witness_key_id", "account_id", "compartment_id", "keyring_id",
  "current_revision", "current_manifest_digest", "witness_sequence", "nonce",
  "observed_at", "status", "pending_reservation_id", "signature",
]);

function invalid() {
  throw new z.RootarkZkError("WITNESS_HEAD_UNACCEPTABLE");
}
function isBytes(x) {
  return Buffer.isBuffer(x) || x instanceof Uint8Array;
}
function bytesOfLength(x, n) {
  return isBytes(x) && x.byteLength === n;
}
function sameBytes(a, b) {
  return isBytes(a) && isBytes(b) && a.byteLength === b.byteLength
    && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
function u64(value, min = 0n) {
  const num = typeof value === "bigint" ? value
    : Number.isSafeInteger(value) ? BigInt(value) : -1n;
  if (num < min || num > 0xffffffffffffffffn) invalid();
  return num;
}

async function inspectVerifiedWitnessFreshHeadV1(input) {
  const raw = input?.raw;
  const pinned = input?.pinned;
  const scope = input?.scope;
  const nonce = input?.nonce;
  const minimum = input?.minimumHead;
  if (!isBytes(raw) || raw.byteLength === 0 || raw.byteLength > MAX_RAW_BYTES
    || !pinned || !(pinned.publicKey instanceof crypto.KeyObject)
    || pinned.publicKey.type !== "public" || pinned.publicKey.asymmetricKeyType !== "ed25519"
    || !bytesOfLength(pinned.keyId, 16) || !bytesOfLength(nonce, 32)
    || !scope || !bytesOfLength(scope.account_id, 16)
    || !isBytes(scope.compartment_id) || scope.compartment_id.byteLength < 1
    || scope.compartment_id.byteLength > 128
    || !bytesOfLength(scope.keyring_id, 16)
    || !minimum || !bytesOfLength(minimum.digest, 32)) invalid();
  const floorRevision = u64(minimum.revision, 1n);
  const floorSequence = u64(minimum.witnessSequence, 1n);
  if (floorSequence !== floorRevision) invalid();
  // Compare with the values supplied at invocation, not with caller-owned
  // byte views that can be changed during deterministic CBOR's async decode.
  const pinnedPublicKey = pinned.publicKey;
  const rawSnapshot = Buffer.from(raw);
  const pinnedKeyIdSnapshot = Buffer.from(pinned.keyId);
  const nonceSnapshot = Buffer.from(nonce);
  const scopeSnapshot = {
    account_id: Buffer.from(scope.account_id),
    compartment_id: Buffer.from(scope.compartment_id),
    keyring_id: Buffer.from(scope.keyring_id),
  };
  const floorDigestSnapshot = Buffer.from(minimum.digest);

  let head;
  try {
    head = await z.decodeDeterministic(rawSnapshot);
    if (!head || typeof head !== "object" || Array.isArray(head)) invalid();
    const keys = Reflect.ownKeys(head);
    if (keys.length !== FIELDS.length || FIELDS.some((key) => !Object.hasOwn(head, key))
      || keys.some((key) => typeof key !== "string" || !FIELDS.includes(key))
      || head.type !== TYPE
      || !bytesOfLength(head.signature, 64)
      || !bytesOfLength(head.witness_key_id, 16)
      || !bytesOfLength(head.account_id, 16)
      || !isBytes(head.compartment_id) || head.compartment_id.byteLength < 1
      || head.compartment_id.byteLength > 128
      || !bytesOfLength(head.keyring_id, 16)
      || !bytesOfLength(head.nonce, 32)
      || !sameBytes(head.witness_key_id, pinnedKeyIdSnapshot)
      || !sameBytes(head.account_id, scopeSnapshot.account_id)
      || !sameBytes(head.compartment_id, scopeSnapshot.compartment_id)
      || !sameBytes(head.keyring_id, scopeSnapshot.keyring_id)
      || !sameBytes(head.nonce, nonceSnapshot)) invalid();
    u64(head.observed_at);
    // Pending is never acceptable as an authenticated committed head.
    if (head.status !== "committed" || head.pending_reservation_id !== null
      || !bytesOfLength(head.current_manifest_digest, 32)) invalid();
    const revision = u64(head.current_revision, 1n);
    const sequence = u64(head.witness_sequence, 1n);
    if (sequence !== revision || revision < floorRevision || sequence < floorSequence
      || (revision === floorRevision
        && !sameBytes(head.current_manifest_digest, floorDigestSnapshot))) invalid();
    const unsigned = {};
    for (const key of FIELDS) if (key !== "signature") unsigned[key] = head[key];
    const bytes = Buffer.concat([DOMAIN, await z.encodeDeterministic(unsigned)]);
    if (!crypto.verify(null, bytes, pinnedPublicKey, Buffer.from(head.signature))) invalid();
  } catch (_) {
    invalid();
  }

  return Object.freeze({
    verifiedSignatureOnly: true,
    authorizesRecovery: false,
    status: "committed",
    current_revision: head.current_revision,
  });
}

module.exports = { inspectVerifiedWitnessFreshHeadV1 };
