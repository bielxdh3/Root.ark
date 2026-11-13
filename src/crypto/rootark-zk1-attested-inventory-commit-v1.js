"use strict";

// Client/CAS/witness-facing opt-in composite proof. A signed inventory entry
// alone does not prove that PostgreSQL committed and re-read its ciphertext.
// A signed PG readback alone does not prove that the inventory appended it.
// Require BOTH independently pinned identities on the exact operation and a
// fresh, caller-owned nonce. Non-authorizing and not a cloud fsync receipt.
const crypto = require("node:crypto");
const { types: { isPromise, isProxy } } = require("node:util");
const { keyEquals: NATIVE_KEY_EQUALS,
  timingSafeEqual: NATIVE_TIMING_SAFE_EQUAL,
  createHash: NATIVE_CREATE_HASH,
  hashUpdate: NATIVE_HASH_UPDATE,
  hashDigest: NATIVE_HASH_DIGEST,
  bufferFrom: NATIVE_BUFFER_FROM,
  bufferConcat: NATIVE_BUFFER_CONCAT,
  freeze: NATIVE_FREEZE,
  defineProperty: NATIVE_DEFINE_PROPERTY, objectCreate: NATIVE_OBJECT_CREATE,
  ownKeys: NATIVE_OWN_KEYS, ownDescriptor: NATIVE_DESCRIPTOR,
  hasOwn: NATIVE_HAS_OWN } =
  require("./rootark-zk10-native-intrinsics-v1");
const { pinNativeEd25519PublicKey } = require("./rootark-zk1-native-ed25519-public-key");
const inventory = require("./rootark-zk-content-inventory-v1");
const { verifyCommittedPhysicalReadback } =
  require("./rootark-zk-pg-physical-attestation-v1");
// Capture the actual signed inventory verifier before any caller-provided
// KeyObject can execute a same-realm getter. The mutable exports object is not
// an authority boundary after that point.
const VERIFY_COMMITTED_ENTRY = inventory.verifyCommittedEntryProof;
const VERIFY_PHYSICAL_READBACK = verifyCommittedPhysicalReadback;
const NATIVE_PROMISE_CONSTRUCTOR = Promise;

function inertComposite(fields) {
  const result = NATIVE_OBJECT_CREATE(null);
  const keys = NATIVE_OWN_KEYS(fields);
  for (let i = 0; i < keys.length; i += 1) {
    const descriptor = NATIVE_DESCRIPTOR(fields, keys[i]);
    if (!descriptor || !NATIVE_HAS_OWN(descriptor, "value")) deny();
    NATIVE_DEFINE_PROPERTY(result, keys[i], { value: descriptor.value,
      writable: false, enumerable: true, configurable: false });
  }
  return NATIVE_FREEZE(result);
}

function verifiedNativePromise(promise) {
  if (isProxy(promise) || !isPromise(promise)) deny();
  // Async functions return native Promises. Their inherited constructor can be
  // replaced after a malicious KeyObject getter; pin an own native constructor
  // so await reads the true internal state without consulting a forged .then.
  NATIVE_DEFINE_PROPERTY(promise, "constructor", { value: NATIVE_PROMISE_CONSTRUCTOR,
    enumerable: false, configurable: false, writable: false });
  const existingThen = NATIVE_DESCRIPTOR(promise, "then");
  if (existingThen) {
    const existingCatch = NATIVE_DESCRIPTOR(promise, "catch");
    if (existingThen.configurable !== false || existingThen.writable !== false
      || typeof existingThen.value !== "function" || !existingCatch
      || existingCatch.configurable !== false || existingCatch.writable !== false
      || typeof existingCatch.value !== "function") deny();
    // The captured inventory verifier already supplies a fully pinned native
    // Promise. Never redefine its nonconfigurable own methods.
    return promise;
  }
  NATIVE_DEFINE_PROPERTY(promise, "then", { value(onFulfilled, onRejected) {
    async function settle() {
      let fulfilled = false, value;
      try { value = await promise; fulfilled = true; }
      catch (error) { value = error; }
      if (fulfilled) return typeof onFulfilled === "function" ? onFulfilled(value) : value;
      if (typeof onRejected !== "function") throw value;
      return onRejected(value);
    }
    return verifiedNativePromise(settle());
  }, configurable: false, writable: false });
  NATIVE_DEFINE_PROPERTY(promise, "catch", { value(onRejected) {
    return promise.then(undefined, onRejected);
  }, configurable: false, writable: false });
  return promise;
}

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
function sha(bytes) {
  const hash = NATIVE_CREATE_HASH("sha256");
  NATIVE_HASH_UPDATE.call(hash, bytes);
  return NATIVE_HASH_DIGEST.call(hash);
}
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

async function verifyAttestedInventoryCommitInternal(input) {
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
    // Preserve the two independently supplied signer references BEFORE either
    // key can invoke a hostile .type / inherited-kHandle getter. This retains
    // the remote e536 attestor-provisioning boundary during integration.
    const inventoryPin = input.pinnedInventoryPublicKey;
    const physicalPin = input.pinnedPhysicalAttestorPublicKey;
    // Reimport immutable native SPKI while each caller-controlled key is
    // observed, then test independence on those same verifier identities.
    const inventoryKey = publicKey(inventoryPin);
    const attestorKey = publicKey(physicalPin);
    // The public KeyObject's .export() is an overridable own property.
    // Compare native cryptographic key identities with the intrinsic method,
    // not caller-supplied DER from an attacker-controlled export override.
    if (NATIVE_KEY_EQUALS.call(inventoryKey, attestorKey)) deny();
    // Do not consult Promise.all or module exports after the key getters.
    // A forged Promise.all can synthesize a COMMITTED inventory result without
    // ever checking its Ed25519 signature, even with a genuine PG attestation.
    const signedReceipt = await verifiedNativePromise(
      VERIFY_COMMITTED_ENTRY({ serialized: receipt,
        pinnedPublicKey: inventoryKey,
        pinnedSignerKeyId: signerId,
        expectedScope: scope, operation }));
    const physical = await verifiedNativePromise(
      VERIFY_PHYSICAL_READBACK(physicalBytes, { scope,
        operation, expected: undefined, nonce,
        pinnedPublicKey: attestorKey,
        nowSeconds }));
    if (signedReceipt.outcome !== "COMMITTED_IN_SIGNED_LEDGER"
      || physical.status !== "PHYSICALLY_REREAD_PG_COMMITTED"
      || physical.verified !== true || physical.walFlushConfirmed !== true
      || !NATIVE_TIMING_SAFE_EQUAL(signedReceipt.operationId, physical.operationId)
      || physical.authorizesIo !== false || signedReceipt.authorizesIo !== false) deny();
    // Digest is an explicitly NON-DURABLE evidence-bundle fingerprint, not a
    // replacement for an externally anchored CAS/FLOOR or a recovery ticket.
    const receiptDigest = sha(NATIVE_BUFFER_CONCAT([DOMAIN, sha(receipt), sha(physicalBytes)]));
    return inertComposite({ status: "VERIFIED_COMPOSITE_NONAUTHORIZING",
      inventoryReceipt: signedReceipt,
      physicalReadback: physical,
      receiptDigest,
      nonce: NATIVE_BUFFER_FROM(nonce),
      authorizesIo: false, externalDurabilityProven: false,
      independentlyAnchoredFloorProven: false });
  } catch (_) { deny(); }
}

function verifyAttestedInventoryCommit(input) {
  // The two caller-owned KeyObjects may poison Promise.prototype while the
  // internal verifier runs. Never expose its mutable inherited constructor to
  // an external await that treats the composite as a security admission gate.
  return verifiedNativePromise(verifyAttestedInventoryCommitInternal(input));
}

module.exports = { verifyAttestedInventoryCommit, derivePhysicalChainNonce,
  derivePhysicalChainPageNonce, MAX_PHYSICAL_CHAIN_PAGE_RECEIPTS, DOMAIN };
