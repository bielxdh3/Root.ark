"use strict";

// Client/CAS/witness-facing opt-in composite proof. A signed inventory entry
// alone does not prove that PostgreSQL committed and re-read its ciphertext.
// A signed PG readback alone does not prove that the inventory appended it.
// Require BOTH independently pinned identities on the exact operation and a
// fresh, caller-owned nonce. Non-authorizing and not a cloud fsync receipt.
const crypto = require("node:crypto");
const { keyEquals: NATIVE_KEY_EQUALS } =
  require("./rootark-zk10-native-intrinsics-v1");
const { pinNativeEd25519PublicKey } = require("./rootark-zk1-native-ed25519-public-key");
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
  // The exact KeyObject checked for independent role separation is the one
  // used by both signed proofs, even if the caller's native kHandle changes.
  return pinNativeEd25519PublicKey(value);
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
    // Detach trusted expectations before invoking ANY caller-owned native
    // KeyObject getter. Such a getter can rewrite even already-validated
    // buffers in this same realm, then restore B after an async signature.
    const nowSeconds = input.nowSeconds;
    const receipt = rawBytes(input.receipt, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
    const physicalBytes = rawBytes(input.physicalAttestation, 1, 2048);
    const nonce = rawBytes(input.nonce, 32, 32);
    const scope = inventory.normalizeScope(input.scope);
    const operation = snapshotOperation(input.operation);
    const signerId = rawBytes(input.pinnedInventorySignerKeyId, 16, 16);
    // Reimport immutable native SPKI while each caller-controlled key is
    // observed, then test independence on those same verifier identities.
    const inventoryKey = publicKey(input.pinnedInventoryPublicKey);
    const attestorKey = publicKey(input.pinnedPhysicalAttestorPublicKey);
    // The public KeyObject's .export() is an overridable own property.
    // Compare native cryptographic key identities with the intrinsic method,
    // not caller-supplied DER from an attacker-controlled export override.
    if (NATIVE_KEY_EQUALS.call(inventoryKey, attestorKey)) deny();
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
