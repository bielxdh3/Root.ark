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
  return value.export({ format: "der", type: "spki" });
}
function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest(); }

async function verifyAttestedInventoryCommit(input) {
  try {
    exact(input, ["receipt", "physicalAttestation", "scope", "operation", "nonce",
      "pinnedInventoryPublicKey", "pinnedInventorySignerKeyId",
      "pinnedPhysicalAttestorPublicKey", "nowSeconds"]);
    const inventoryPin = publicKey(input.pinnedInventoryPublicKey);
    const attestorPin = publicKey(input.pinnedPhysicalAttestorPublicKey);
    if (crypto.timingSafeEqual(inventoryPin, attestorPin)) deny();
    const receipt = rawBytes(input.receipt, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
    const physicalBytes = rawBytes(input.physicalAttestation, 1, 2048);
    const nonce = rawBytes(input.nonce, 32, 32);
    const [signedReceipt, physical] = await Promise.all([
      inventory.verifyCommittedEntryProof({ serialized: receipt,
        pinnedPublicKey: input.pinnedInventoryPublicKey,
        pinnedSignerKeyId: input.pinnedInventorySignerKeyId,
        expectedScope: input.scope, operation: input.operation }),
      verifyCommittedPhysicalReadback(physicalBytes, { scope: input.scope,
        operation: input.operation, expected: undefined, nonce,
        pinnedPublicKey: input.pinnedPhysicalAttestorPublicKey,
        nowSeconds: input.nowSeconds }),
    ]);
    if (signedReceipt.outcome !== "COMMITTED_IN_SIGNED_LEDGER"
      || physical.status !== "PHYSICALLY_REREAD_PG_COMMITTED"
      || physical.verified !== true || physical.walFlushConfirmed !== true
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

module.exports = { verifyAttestedInventoryCommit, DOMAIN };
