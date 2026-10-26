"use strict";

// Client/CAS/witness-facing opt-in composite proof. A signed inventory entry
// alone does not prove that PostgreSQL committed and re-read its ciphertext.
// A signed PG readback alone does not prove that the inventory appended it.
// Require BOTH independently pinned identities on the exact operation and a
// fresh, caller-owned nonce. Non-authorizing and not a cloud fsync receipt.
const crypto = require("node:crypto");
const inventory = require("./rootark-zk-content-inventory-v1");
const { verifyCommittedPhysicalReadback } =
  require("./rootark-zk-pg-physical-attestation-v1");

const DOMAIN = Buffer.from("Root.ark/zk-1/attested-inventory-commit/v1\0");
const CHAIN_NONCE_DOMAIN = Buffer.from("Root.ark/zk-1/physical-chain-nonce/v1\0");
const CHAIN_PAGE_NONCE_DOMAIN = Buffer.from("Root.ark/zk-1/physical-chain-page-nonce/v1\0");
const MAX_PHYSICAL_CHAIN_PAGE_RECEIPTS = 4;

function deny() {
  const error = new Error("ZK_ATTESTED_INVENTORY_COMMIT_DENIED");
  error.code = error.message;
  throw error;
}
function exact(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== keys.length
    || keys.some((key) => !Object.hasOwn(value, key)
      || !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"))) deny();
}
function rawBytes(value, min, max) {
  if ((!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
    || value.length < min || value.length > max
    || (typeof SharedArrayBuffer !== "undefined"
      && value.buffer instanceof SharedArrayBuffer)) deny();
  return Buffer.from(value);
}
function publicKey(value) {
  if (!(value instanceof crypto.KeyObject) || value.type !== "public"
    || value.asymmetricKeyType !== "ed25519") deny();
}
function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest(); }
function derivePhysicalChainPageNonce(chainNonce, afterSequence) {
  const nonce = rawBytes(chainNonce, 32, 32);
  if (!Number.isSafeInteger(afterSequence) || afterSequence < 0
    || afterSequence > inventory.MAX_ENTRIES) deny();
  const seq = Buffer.alloc(8);
  seq.writeBigUInt64BE(BigInt(afterSequence));
  return sha(Buffer.concat([CHAIN_PAGE_NONCE_DOMAIN, nonce, seq]));
}
function derivePhysicalChainNonce(pageNonce, sequence, operationId) {
  const nonce = rawBytes(pageNonce, 32, 32);
  const id = rawBytes(operationId, 16, 16);
  if (!Number.isSafeInteger(sequence) || sequence < 1 || sequence > inventory.MAX_ENTRIES) deny();
  const seq = Buffer.alloc(8);
  seq.writeBigUInt64BE(BigInt(sequence));
  return sha(Buffer.concat([CHAIN_NONCE_DOMAIN, nonce, seq, id]));
}
function snapshotOperation(value) {
  exact(value, ["operation_id", "expected_sequence", "expected_root", "object_id",
    "revision", "epoch", "ciphertext_sha256"]);
  if (!Number.isSafeInteger(value.expected_sequence) || value.expected_sequence < 0
    || !Number.isSafeInteger(value.revision) || value.revision < 1
    || !Number.isSafeInteger(value.epoch) || value.epoch < 1) deny();
  return { operation_id: rawBytes(value.operation_id, 16, 16),
    expected_sequence: value.expected_sequence,
    expected_root: rawBytes(value.expected_root, 32, 32),
    object_id: rawBytes(value.object_id, 16, 16),
    revision: value.revision, epoch: value.epoch,
    ciphertext_sha256: rawBytes(value.ciphertext_sha256, 32, 32) };
}

async function verifyAttestedInventoryCommit(input) {
  try {
    exact(input, ["receipt", "physicalAttestation", "scope", "operation", "nonce",
      "pinnedInventoryPublicKey", "pinnedInventorySignerKeyId",
      "pinnedPhysicalAttestorPublicKey", "nowSeconds"]);
    // The exact KeyObject references used for separation MUST also verify
    // both signatures. A top-level Proxy can otherwise serve separate keys
    // to this comparison then replace the attestor with the writer key.
    const inventoryKey = input.pinnedInventoryPublicKey;
    const attestorKey = input.pinnedPhysicalAttestorPublicKey;
    const nowSeconds = input.nowSeconds;
    publicKey(inventoryKey);
    publicKey(attestorKey);
    // The public KeyObject's .export() is an overridable own property.
    // Compare native cryptographic key identities with the intrinsic method,
    // not caller-supplied DER from an attacker-controlled export override.
    if (crypto.KeyObject.prototype.equals.call(inventoryKey, attestorKey)) deny();
    const receipt = rawBytes(input.receipt, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
    const physicalBytes = rawBytes(input.physicalAttestation, 1, 2048);
    const nonce = rawBytes(input.nonce, 32, 32);
    // Both signature parsers have asynchronous CBOR boundaries. If they read
    // the caller's mutable operation/scope independently, a hostile Proxy can
    // present a valid ledger operation A and a valid physical readback B.
    // Detach exactly ONCE before either parser awaits any promise.
    const scope = inventory.normalizeScope(input.scope);
    const operation = snapshotOperation(input.operation);
    const signerId = rawBytes(input.pinnedInventorySignerKeyId, 16, 16);
    const [signedReceipt, physical] = await Promise.all([
      inventory.verifyCommittedEntryProof({ serialized: receipt,
        pinnedPublicKey: inventoryKey,
        pinnedSignerKeyId: signerId,
        expectedScope: scope, operation }),
      verifyCommittedPhysicalReadback(physicalBytes, { scope,
        operation, expected: undefined, nonce,
        pinnedPublicKey: attestorKey,
        nowSeconds }),
    ]);
    if (signedReceipt.outcome !== "COMMITTED_IN_SIGNED_LEDGER"
      || physical.status !== "PHYSICALLY_REREAD_PG_COMMITTED"
      || physical.verified !== true || physical.walFlushConfirmed !== true
      || !crypto.timingSafeEqual(signedReceipt.operationId, physical.operationId)
      || physical.authorizesIo !== false || signedReceipt.authorizesIo !== false) deny();
    // Digest is an explicitly NON-DURABLE evidence-bundle fingerprint, not a
    // replacement for an externally anchored CAS/FLOOR or a recovery ticket.
    const receiptDigest = sha(Buffer.concat([DOMAIN, sha(receipt), sha(physicalBytes)]));
    return Object.freeze({ status: "VERIFIED_COMPOSITE_NONAUTHORIZING",
      inventoryReceipt: signedReceipt,
      physicalReadback: physical,
      receiptDigest,
      nonce: Buffer.from(nonce),
      authorizesIo: false, externalDurabilityProven: false,
      independentlyAnchoredFloorProven: false });
  } catch (_) { deny(); }
}

module.exports = { verifyAttestedInventoryCommit, derivePhysicalChainNonce,
  derivePhysicalChainPageNonce, MAX_PHYSICAL_CHAIN_PAGE_RECEIPTS, DOMAIN };
