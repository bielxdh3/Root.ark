"use strict";

// Strict witness-side admission for CAS terminal anchors. A status signer
// cannot advance the independent floor by manufacturing only a CAS signature.
// The witness must retain its own owner/inventory/physical-attestor pins and
// fresh-challenge the *independent* read-only PG attestor over mTLS. Neither
// proof alone is external persistence or authorization for content I/O.
const crypto = require("node:crypto");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const z = require("../crypto/rootark-zk-1");
const { verifyAttestedInventoryCommit, derivePhysicalChainNonce,
  derivePhysicalChainPageNonce, MAX_PHYSICAL_CHAIN_PAGE_RECEIPTS } =
  require("../crypto/rootark-zk1-attested-inventory-commit-v1");

const OWNER_DOMAIN = Buffer.from("Root.ark/zk-1/cas-witness-physical-owner-binding/v1\0");
const B64 = /^[A-Za-z0-9_-]+$/;
const HEX = /^[0-9a-f]{64}$/;
const MAX_CHAIN_ELAPSED_NS = 300_000_000_000n;
function deny() {
  const error = new Error("WITNESS_CAS_PHYSICAL_ADMISSION_DENIED");
  error.code = error.message;
  throw error;
}
function exact(value, fields) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))
    || Reflect.ownKeys(value).length !== fields.length
    || fields.some((key) => !Object.hasOwn(value, key))) deny();
  const copy = Object.create(null);
  for (const name of fields) {
    const desc = Object.getOwnPropertyDescriptor(value, name);
    if (!desc || !Object.hasOwn(desc, "value")) deny();
    copy[name] = desc.value;
  }
  return copy;
}
function decode(encoded, min, max = min) {
  if (typeof encoded !== "string" || !B64.test(encoded)
    || encoded.length > max * 2 + 4) deny();
  const value = Buffer.from(encoded, "base64url");
  if (value.length < min || value.length > max
    || value.toString("base64url") !== encoded) deny();
  return value;
}
function key(value) {
  if (!(value instanceof crypto.KeyObject)
    || value.type !== "public" || value.asymmetricKeyType !== "ed25519") deny();
  return value;
}
function sameKey(a, b) {
  return crypto.KeyObject.prototype.equals.call(a, b);
}
function same(a, b) {
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function scopeKey(scope) {
  return scope.account_id.toString("hex") + ":" + scope.compartment_id.length
    + ":" + scope.compartment_id.toString("hex") + ":" + scope.keyring_id.toString("hex");
}
function snapshotOperation(wire) {
  const o = exact(wire, ["operation_id", "expected_sequence", "expected_root",
    "object_id", "revision", "epoch", "ciphertext_sha256"]);
  if (!Number.isSafeInteger(o.expected_sequence) || o.expected_sequence < 0
    || !Number.isSafeInteger(o.revision) || o.revision < 1
    || !Number.isSafeInteger(o.epoch) || o.epoch < 1) deny();
  return { operation_id: decode(o.operation_id, 16),
    expected_sequence: o.expected_sequence, expected_root: decode(o.expected_root, 32),
    object_id: decode(o.object_id, 16), revision: o.revision, epoch: o.epoch,
    ciphertext_sha256: decode(o.ciphertext_sha256, 32) };
}
function snapshotScope(wire) {
  const s = exact(wire, ["account_id", "compartment_id", "keyring_id"]);
  return { account_id: decode(s.account_id, 16),
    compartment_id: decode(s.compartment_id, 1, 128),
    keyring_id: decode(s.keyring_id, 16) };
}
function positive(keyObject, signature, unsigned) {
  return crypto.verify(null, Buffer.concat([OWNER_DOMAIN,
    Buffer.from(JSON.stringify(unsigned))]), keyObject, signature);
}
class Zk1WitnessCasPhysicalAdmission {
  #owner;
  #inventory;
  #signerId;
  #physical;
  #attestorClient;
  #inventoryClient;
  #minimumHead;
  #minimumSnapshot;
  constructor({ pinnedOwnerPublicKey, pinnedInventoryPublicKey,
    pinnedInventorySignerKeyId, pinnedPhysicalAttestorPublicKey,
    physicalAttestorClient, inventoryClient,
    trustedMinimumInventoryHead, trustedMinimumInventorySnapshot } = {}) {
    this.#owner = key(pinnedOwnerPublicKey);
    this.#inventory = key(pinnedInventoryPublicKey);
    this.#physical = key(pinnedPhysicalAttestorPublicKey);
    if (sameKey(this.#owner, this.#inventory)
      || sameKey(this.#owner, this.#physical)
      || sameKey(this.#inventory, this.#physical)) deny();
    if (!physicalAttestorClient || typeof physicalAttestorClient.requestAttestation !== "function"
      || !inventoryClient
      || typeof inventoryClient.getVerifiedSnapshotWithChain !== "function") deny();
    this.#attestorClient = physicalAttestorClient;
    this.#inventoryClient = inventoryClient;
    this.#signerId = Buffer.from(pinnedInventorySignerKeyId || []);
    if (this.#signerId.length !== 16) deny();
    const floor = exact(trustedMinimumInventoryHead, ["sequence", "root"]);
    if (!Number.isSafeInteger(floor.sequence) || floor.sequence < 0) deny();
    this.#minimumHead = Object.freeze({ sequence: floor.sequence,
      root: Buffer.from(floor.root || []) });
    if (this.#minimumHead.root.length !== 32) deny();
    if ((!Buffer.isBuffer(trustedMinimumInventorySnapshot)
      && !(trustedMinimumInventorySnapshot instanceof Uint8Array))
      || trustedMinimumInventorySnapshot.byteLength < 1
      || trustedMinimumInventorySnapshot.byteLength > inventory.MAX_SNAPSHOT_BYTES) deny();
    this.#minimumSnapshot = Buffer.from(trustedMinimumInventorySnapshot);
  }
  // A caller cannot configure the compromised CAS signer as the witness's
  // owner/inventory/PG attestor, nor reuse the private witness identity.
  assertSeparateFrom(statusPublicKey, witnessPublicKey) {
    const status = key(statusPublicKey);
    const witness = key(witnessPublicKey);
    for (const pin of [this.#owner, this.#inventory, this.#physical]) {
      if (sameKey(pin, status) || sameKey(pin, witness)) deny();
    }
  }
  assertSeparateDevice(devicePublicKey) {
    const device = key(devicePublicKey);
    for (const pin of [this.#owner, this.#inventory, this.#physical]) {
      if (sameKey(pin, device)) deny();
    }
  }
  policyDigest() {
    const nativeSpki = (pin) => Object.getPrototypeOf(pin).export.call(pin, {
      type: "spki", format: "der",
    }).toString("base64url");
    return crypto.createHash("sha256").update(JSON.stringify({
      owner: nativeSpki(this.#owner), inventory: nativeSpki(this.#inventory),
      attestor: nativeSpki(this.#physical), signer: this.#signerId.toString("base64url"),
      minimumSequence: this.#minimumHead.sequence,
      minimumRoot: this.#minimumHead.root.toString("base64url"),
      minimumSnapshotSha256: crypto.createHash("sha256")
        .update(this.#minimumSnapshot).digest("hex"),
    })).digest("hex");
  }
  // Challenge the witness's ALREADY PINNED independent mTLS PostgreSQL
  // attestor for the exact Sync envelope operation, and verify both Ed25519
  // signatures. A writer-provided success boolean is never admitted here.
  async attestSyncCommitted({ scope, operation, receipt, nonce } = {}) {
    try {
      const trustedScope = inventory.normalizeScope(scope);
      const trustedOperation = {
        operation_id: Buffer.from(operation.operation_id),
        expected_sequence: operation.expected_sequence,
        expected_root: Buffer.from(operation.expected_root),
        object_id: Buffer.from(operation.object_id), revision: operation.revision,
        epoch: operation.epoch,
        ciphertext_sha256: Buffer.from(operation.ciphertext_sha256),
      };
      const challenge = Buffer.from(nonce);
      const signedReceipt = Buffer.from(receipt);
      if (challenge.length !== 32 || signedReceipt.length < 1
        || signedReceipt.length > inventory.MAX_COMMITTED_PROOF_BYTES) deny();
      const raw = await this.#attestorClient.requestAttestation({
        scope: trustedScope, operation: trustedOperation,
        nonce: Buffer.from(challenge),
      });
      const verified = await verifyAttestedInventoryCommit({
        receipt: signedReceipt, physicalAttestation: Buffer.from(raw),
        scope: trustedScope, operation: trustedOperation,
        nonce: challenge, pinnedInventoryPublicKey: this.#inventory,
        pinnedInventorySignerKeyId: this.#signerId,
        pinnedPhysicalAttestorPublicKey: this.#physical,
        nowSeconds: Math.floor(Date.now() / 1000),
      });
      const now = Math.floor(Date.now() / 1000);
      if (verified.status !== "VERIFIED_COMPOSITE_NONAUTHORIZING"
        || verified.authorizesIo !== false
        || !Number.isSafeInteger(verified.physicalReadback.issuedAt)
        || !Number.isSafeInteger(now) || now < 1
        || Math.abs(now - verified.physicalReadback.issuedAt) > 30) deny();
      return Object.freeze({
        inventorySequence: verified.inventoryReceipt.sequence,
        inventoryRoot: Buffer.from(verified.inventoryReceipt.root),
        receiptSha256: crypto.createHash("sha256").update(signedReceipt).digest(),
        physicalIssuedAt: verified.physicalReadback.issuedAt,
        pgReadbackVerified: true, authorizesIo: false,
      });
    } catch (_) { deny(); }
  }
  async verify(record, evidence, minimumInventory = null) {
    try {
      const r = exact(record, ["line", "lastHash", "status", "scope"]);
      if (typeof r.line !== "string" || !HEX.test(r.lastHash)
        || crypto.createHash("sha256").update(r.line).digest("hex") !== r.lastHash
        || !["committed", "not-committed-final"].includes(r.status)) deny();
      const e = exact(evidence, ["recordHash", "scope", "operation",
        "inventoryReceipt", "ownerSignature"]);
      if (e.recordHash !== r.lastHash) deny();
      const scope = snapshotScope(e.scope);
      if (scopeKey(scope) !== r.scope) deny();
      // Detached, canonical values are shared by the owner-signature
      // decision and both asynchronous mTLS verifiers. Never parse a nested
      // Proxy twice, or an attacker could sign for tuple A but attest B.
      const signedScope = Object.fromEntries(Object.entries(scope)
        .map(([name, value]) => [name, value.toString("base64url")]));
      const operation = r.status === "committed" ? snapshotOperation(e.operation) : null;
      const signedOperation = operation === null ? null : {
        operation_id: operation.operation_id.toString("base64url"),
        expected_sequence: operation.expected_sequence,
        expected_root: operation.expected_root.toString("base64url"),
        object_id: operation.object_id.toString("base64url"),
        revision: operation.revision, epoch: operation.epoch,
        ciphertext_sha256: operation.ciphertext_sha256.toString("base64url"),
      };
      const unsigned = { recordHash: e.recordHash, scope: signedScope,
        operation: signedOperation, inventoryReceipt: e.inventoryReceipt };
      const signature = decode(e.ownerSignature, 64);
      if (!positive(this.#owner, signature, unsigned)) deny();
      // Even a terminal *negative* decision must carry owner authorization;
      // it cannot be turned into a fake committed record without a new
      // signature. No PG proof is expected for a non-commit event.
      if (r.status === "not-committed-final") {
        if (e.operation !== null || e.inventoryReceipt !== null) deny();
        return Object.freeze({ ownerBound: true, physicallyCommitted: false });
      }
      const receipt = decode(e.inventoryReceipt, 1, inventory.MAX_COMMITTED_PROOF_BYTES);
      const nonce = crypto.randomBytes(32);
      const physical = await this.#attestorClient.requestAttestation({
        scope, operation, nonce: Buffer.from(nonce),
      });
      const proof = await verifyAttestedInventoryCommit({
        receipt, physicalAttestation: physical, scope, operation, nonce,
        pinnedInventoryPublicKey: this.#inventory,
        pinnedInventorySignerKeyId: this.#signerId,
        pinnedPhysicalAttestorPublicKey: this.#physical,
        nowSeconds: Math.floor(Date.now() / 1000),
      });
      const minimumHead = minimumInventory?.head || this.#minimumHead;
      const minimumSnapshot = minimumInventory?.snapshot || this.#minimumSnapshot;
      const chainNonce = crypto.randomBytes(32);
      const chainStartSeconds = Math.floor(Date.now() / 1000);
      const chainStartMonotonic = process.hrtime.bigint();
      const requested = { object_id: Buffer.from(operation.object_id),
        revision: operation.revision, epoch: operation.epoch,
        ciphertext_sha256: Buffer.from(operation.ciphertext_sha256) };
      const continuation = await this.#inventoryClient.getVerifiedSnapshotWithChain({
        scope, nonce: Buffer.from(chainNonce), requested,
        minimumHead, minimumSnapshot: Buffer.from(minimumSnapshot),
        includeVerifiedProofChain: true,
      });
      const chainEndSeconds = Math.floor(Date.now() / 1000);
      if (process.hrtime.bigint() - chainStartMonotonic > MAX_CHAIN_ELAPSED_NS
        || chainEndSeconds < chainStartSeconds - 30
        || chainEndSeconds > chainStartSeconds + 330) deny();
      // Do not trust boolean VERIFIED claims from an injectable transport.
      // Reverify the actual Ed25519 signed checkpoint and every intervening
      // signed ancestry link inside this independently pinned witness process.
      if (!continuation || !Buffer.isBuffer(continuation.serializedSnapshot)
        || !Array.isArray(continuation.authenticatedProofChain)) deny();
      const snapshot = Buffer.from(continuation.serializedSnapshot);
      const chain = inventory.normalizeCommittedProofChain(
        continuation.authenticatedProofChain);
      if (!Array.isArray(continuation.authenticatedPhysicalProofChain)
        || continuation.authenticatedPhysicalProofChain.length !== chain.length) deny();
      // Recheck the *actual* attestor signatures under this witness's own
      // challenge. A transport-controlled `independentPhysicalChainVerified`
      // flag is not evidence and a target-only readback cannot bless ancestors.
      for (let i = 0; i < chain.length; i += 1) {
        const operationInChain = await inventory.readVerifiedCommittedOperation({
          serialized: chain[i], pinnedPublicKey: this.#inventory,
          pinnedSignerKeyId: this.#signerId, expectedScope: scope,
        });
        const sequence = minimumHead.sequence + i + 1;
        if (operationInChain.expected_sequence + 1 !== sequence) deny();
        const pageStart = minimumHead.sequence
          + Math.floor(i / MAX_PHYSICAL_CHAIN_PAGE_RECEIPTS)
            * MAX_PHYSICAL_CHAIN_PAGE_RECEIPTS;
        const pageNonce = derivePhysicalChainPageNonce(chainNonce, pageStart);
        const entryNonce = derivePhysicalChainNonce(pageNonce, sequence,
          operationInChain.operation_id);
        const physicalAttestation = continuation.authenticatedPhysicalProofChain[i];
        if ((!Buffer.isBuffer(physicalAttestation)
          && !(physicalAttestation instanceof Uint8Array))
          || physicalAttestation.length < 1 || physicalAttestation.length > 2048
          || (typeof SharedArrayBuffer !== "undefined"
            && physicalAttestation.buffer instanceof SharedArrayBuffer)) deny();
        const claims = await z.decodeDeterministic(Buffer.from(physicalAttestation));
        if (!Number.isSafeInteger(claims?.issued_at)
          || claims.issued_at < chainStartSeconds - 30
          || claims.issued_at > chainEndSeconds + 30) deny();
        // The signed nonce is unique to this witness invocation. A page can
        // legitimately be >30s old by the time 16 bounded pages finish, but
        // its signed issuance must lie inside this local challenge interval.
        await verifyAttestedInventoryCommit({ receipt: chain[i],
          physicalAttestation,
          scope, operation: operationInChain, nonce: entryNonce,
          pinnedInventoryPublicKey: this.#inventory,
          pinnedInventorySignerKeyId: this.#signerId,
          pinnedPhysicalAttestorPublicKey: this.#physical,
          nowSeconds: claims.issued_at,
        });
      }
      const checked = await inventory.verifySnapshot({
        serialized: snapshot, pinnedPublicKey: this.#inventory,
        pinnedSignerKeyId: this.#signerId,
        expectedScope: scope, requested, minimumHead,
        minimumSnapshot, committedProofChain: chain, nonce: chainNonce,
      });
      const offset = proof.inventoryReceipt.sequence - minimumHead.sequence - 1;
      if (checked.status !== "VERIFIED_NONAUTHORIZING"
        || checked.outcome !== "PRESENT"
        || !Number.isSafeInteger(offset) || offset < 0
        || offset >= chain.length || !same(chain[offset], receipt)
        || proof.inventoryReceipt.sequence > checked.sequence) deny();
      if (process.hrtime.bigint() - chainStartMonotonic > MAX_CHAIN_ELAPSED_NS) deny();
      return Object.freeze({ ownerBound: true, physicallyCommitted: true,
        localReadbackConfirmed: true, externallyDurable: false,
        operationId: Buffer.from(proof.physicalReadback.operationId),
        inventoryScope: r.scope,
        inventorySequence: checked.sequence, inventoryRoot: Buffer.from(checked.root),
        inventorySnapshot: snapshot });
    } catch (_) { deny(); }
  }
}
module.exports = { Zk1WitnessCasPhysicalAdmission };
