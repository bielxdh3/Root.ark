"use strict";

// Standalone trusted-operator reference. Does not expose a route or authorize
// physical GET. A PostgreSQL fenced ciphertext seal is reread in a separate
// restricted SQL transaction BEFORE the local Ed25519 inventory is advanced.
// There is no atomic 2PC across PG and SQLite: failure leaves intact orphan
// ciphertext to be reconciled, never silently declared committed.
const crypto = require("node:crypto");
const inventory = require("../crypto/rootark-zk-content-inventory-v1");
const { computeZk1CiphertextRoot } = require("../crypto/rootark-zk-chunk-root-v1");
const { Zk1SharedPgCiphertextSink } = require("./zk1SharedPgCiphertextSink");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("./zk1SharedPgPhysicalCiphertextVerifier");
const { Zk1SharedPgPhysicalInventoryIntent } =
  require("./zk1SharedPgPhysicalInventoryIntent");
const { Zk1DurableContentInventoryLedger } = require("./zk1DurableContentInventoryLedger");
const { Zk1CloudCiphertextReadbackVerifier } =
  require("./zk1CloudCiphertextReadbackVerifier");
const { Zk1CloudCiphertextCopyPublisher } =
  require("./zk1CloudCiphertextCopyPublisher");

function fail() {
  const e = new Error("ZK_PHYSICAL_INVENTORY_UNAVAILABLE");
  e.code = e.message;
  throw e;
}
function exact(input, fields) {
  if (!input || typeof input !== "object" || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))
    || Reflect.ownKeys(input).length !== fields.length
    || fields.some((name) => !Object.hasOwn(input, name))) fail();
  const result = Object.create(null);
  for (const name of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
    result[name] = descriptor.value;
  }
  return result;
}
function bytes(v, n) {
  if ((!Buffer.isBuffer(v) && !(v instanceof Uint8Array))
    || (typeof SharedArrayBuffer !== "undefined" && v.buffer instanceof SharedArrayBuffer)
    || v.byteLength !== n) fail();
  return Buffer.from(v);
}
function same(a, b) {
  return Buffer.isBuffer(a) && Buffer.isBuffer(b) && a.length === b.length
    && crypto.timingSafeEqual(a, b);
}
function copyRequest(input) {
  const r = exact(input, ["scope", "operation", "digest", "expectedRootHash", "expectedChunkCount"]);
  const scope = inventory.normalizeScope(r.scope);
  const op = exact(r.operation, [
    "operation_id", "expected_sequence", "expected_root", "object_id",
    "revision", "epoch", "ciphertext_sha256",
  ]);
  const tuple = inventory.normalizeEntry({
    object_id: op.object_id, revision: op.revision, epoch: op.epoch,
    ciphertext_sha256: op.ciphertext_sha256,
  });
  if (!Number.isSafeInteger(op.expected_sequence) || op.expected_sequence < 0
    || op.expected_sequence > inventory.MAX_ENTRIES
    || !Number.isSafeInteger(r.expectedChunkCount) || r.expectedChunkCount < 1
    || r.expectedChunkCount > 16) fail();
  const operation = { operation_id: bytes(op.operation_id, 16),
    expected_sequence: op.expected_sequence, expected_root: bytes(op.expected_root, 32),
    ...tuple };
  return {
    scope, operation, digest: bytes(r.digest, 32),
    expectedRootHash: bytes(r.expectedRootHash, 32),
    expectedChunkCount: r.expectedChunkCount,
    objectId: operation.object_id.toString("base64url"),
  };
}
function detachedChunks(chunks, count, expectedSha256, expectedRoot) {
  if (!Array.isArray(chunks) || chunks.length !== count
    || Reflect.ownKeys(chunks).length !== count + 1) fail();
  const detached = [];
  const hash = crypto.createHash("sha256");
  let total = 0;
  for (let i = 0; i < count; i += 1) {
    const d = Object.getOwnPropertyDescriptor(chunks, String(i));
    const value = d?.value;
    if (!d || !Object.hasOwn(d, "value")
      || (!Buffer.isBuffer(value) && !(value instanceof Uint8Array))
      || (typeof SharedArrayBuffer !== "undefined" && value.buffer instanceof SharedArrayBuffer)
      || value.byteLength < 1 || value.byteLength > 1024 * 1024
      || total > 16 * 1024 * 1024 - value.byteLength) fail();
    const copy = Buffer.from(value);
    detached.push(copy);
    total += copy.length;
    hash.update(copy);
  }
  if (!same(hash.digest(), expectedSha256)
    || !same(computeZk1CiphertextRoot(detached), expectedRoot)) fail();
  return detached;
}

class Zk1PgPhysicalInventoryBridge {
  #trustedInventoryFloor;
  constructor({ sink, verifier, intentAuthority, ledger, pinnedPublicKey, pinnedSignerKeyId,
    trustedInventoryFloor } = {}) {
    if (!(sink instanceof Zk1SharedPgCiphertextSink)
      || !(verifier instanceof Zk1SharedPgPhysicalCiphertextVerifier)
      || !(intentAuthority instanceof Zk1SharedPgPhysicalInventoryIntent)
      || !(ledger instanceof Zk1DurableContentInventoryLedger)
      || !(pinnedPublicKey instanceof crypto.KeyObject)
      || pinnedPublicKey.type !== "public" || pinnedPublicKey.asymmetricKeyType !== "ed25519") fail();
    this.sink = sink;
    this.verifier = verifier;
    this.intentAuthority = intentAuthority;
    this.ledger = ledger;
    this.ledgerScope = inventory.normalizeScope(ledger.scope);
    this.pinnedPublicKey = pinnedPublicKey;
    this.signerKeyId = bytes(pinnedSignerKeyId, 16);
    // Optional, independently retained owner floor. Never derive this from
    // the same mutable SQLite ledger whose rollback it is meant to detect.
    // A caller that does not possess an independently kept floor must not
    // claim rollback resistance from this reference bridge.
    if (trustedInventoryFloor !== undefined) {
      const floor = exact(trustedInventoryFloor, ["minimumHead", "minimumSnapshot"]);
      const head = exact(floor.minimumHead, ["sequence", "root"]);
      if (!Number.isSafeInteger(head.sequence) || head.sequence < 0
        || head.sequence > inventory.MAX_ENTRIES
        || (!Buffer.isBuffer(floor.minimumSnapshot)
          && !(floor.minimumSnapshot instanceof Uint8Array))
        || floor.minimumSnapshot.byteLength < 1
        || floor.minimumSnapshot.byteLength > inventory.MAX_SNAPSHOT_BYTES) fail();
      this.#trustedInventoryFloor = {
        minimumHead: { sequence: head.sequence, root: bytes(head.root, 32) },
        minimumSnapshot: Buffer.from(floor.minimumSnapshot),
      };
    }
  }
  #request(input) {
    const v = copyRequest(input);
    // CRITICAL: the physical verifier's scope and the Ed25519 local ledger
    // must match BEFORE signing or touching the physical provider. The
    // durable ledger binds its scope outside append(operation).
    if (!same(v.scope.account_id, this.ledgerScope.account_id)
      || !same(v.scope.compartment_id, this.ledgerScope.compartment_id)
      || !same(v.scope.keyring_id, this.ledgerScope.keyring_id)) fail();
    return v;
  }

  async #verifiedInventoryFloor(v) {
    if (!this.#trustedInventoryFloor) return null;
    try {
      const { minimumHead, minimumSnapshot } = this.#trustedInventoryFloor;
      const nonce = crypto.randomBytes(32);
      const current = await this.ledger.getSnapshot({ nonce });
      if (current.status !== "snapshot"
        || !Number.isSafeInteger(current.sequence)
        || current.sequence < minimumHead.sequence
        || current.sequence - minimumHead.sequence > 64) fail();
      let cursor = minimumHead.sequence;
      const proofs = [];
      while (cursor < current.sequence) {
        const page = await this.ledger.getCommittedProofPage({
          afterSequence: cursor, limit: Math.min(16, current.sequence - cursor),
        });
        if (page.status !== "chain_page" || page.afterSequence !== cursor
          || !Array.isArray(page.proofs)
          || page.proofs.length !== page.nextSequence - cursor
          || page.nextSequence <= cursor || page.nextSequence > current.sequence
          || page.headSequence !== current.sequence) fail();
        proofs.push(...page.proofs);
        cursor = page.nextSequence;
      }
      const verified = await inventory.verifySnapshot({
        serialized: current.bytes, pinnedPublicKey: this.pinnedPublicKey,
        pinnedSignerKeyId: this.signerKeyId, expectedScope: v.scope,
        requested: { object_id: v.operation.object_id,
          revision: v.operation.revision, epoch: v.operation.epoch,
          ciphertext_sha256: v.operation.ciphertext_sha256 },
        minimumHead, minimumSnapshot, committedProofChain: proofs, nonce,
      });
      if (verified.status !== "VERIFIED_NONAUTHORIZING") fail();
      return verified;
    } catch (_) { fail(); }
  }

  async #checkedCommit(v) {
    const head = await this.#verifiedInventoryFloor(v);
    const state = await this.ledger.getOperationStatus(v.operation.operation_id);
    if (state.status === "pending" || state.status === "unknown") return {
      status: state.status, authorizesIo: false };
    if (state.status !== "committed" || !Buffer.isBuffer(state.proof)) fail();
    const signed = await inventory.verifyCommittedEntryProof({
      serialized: state.proof, pinnedPublicKey: this.pinnedPublicKey,
      pinnedSignerKeyId: this.signerKeyId, expectedScope: v.scope,
      operation: v.operation,
    });
    if (signed.outcome !== "COMMITTED_IN_SIGNED_LEDGER"
      || state.sequence !== signed.sequence || !same(state.root, signed.root)
      || (head && head.outcome !== "PRESENT")) fail();
    return { status: "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY",
      sequence: signed.sequence, root: Buffer.from(signed.root), verifiedReceipt: signed,
      authorizesIo: false, localPgWalFlushConfirmed: true,
      externalProviderDurabilityProven: false,
      independentlyAnchoredFloorProven: false };
  }
  async #verifiedPhysical(v) {
    const proof = await this.verifier.verifyExact({
      scope: v.scope, objectId: v.objectId, revision: v.operation.revision,
      digest: v.digest, expectedRootHash: v.expectedRootHash,
      expectedChunkCount: v.expectedChunkCount,
      expectedSha256: v.operation.ciphertext_sha256,
      operationId: v.operation.operation_id,
      expectedInventorySequence: v.operation.expected_sequence,
      expectedInventoryRoot: v.operation.expected_root,
      epoch: v.operation.epoch,
    });
    if (proof.status !== "PHYSICALLY_REREAD_PG_COMMITTED"
      || proof.verified !== true || proof.walFlushConfirmed !== true
      || !same(proof.operationId, v.operation.operation_id)
      || !same(proof.root, v.expectedRootHash)
      || !same(proof.ciphertextSha256, v.operation.ciphertext_sha256)) fail();
    return proof;
  }

  // Lost ACK retry / restart reconciliation never needs to rewrite ciphertext.
  // Require physical re-read both before and after trusting the signed entry.
  async reconcile(input) {
    const v = this.#request(input);
    await this.#verifiedPhysical(v);
    const status = await this.#checkedCommit(v);
    if (status.status !== "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY") return status;
    await this.#verifiedPhysical(v);
    return status;
  }
  // An already verified local PG+signed operation can be matched against the
  // *current bytes* returned by a separately pinned S3/Drive reader. There is
  // no cloud PUT here, and a GET after upload cannot attest indefinite remote
  // persistence. Run local physical fencing again after the cloud readback.
  async reconcileCloudCopy({ physical, cloudVerifier, chunkLengths } = {}) {
    const v = this.#request(physical);
    if (!(cloudVerifier instanceof Zk1CloudCiphertextReadbackVerifier)
      || !Array.isArray(chunkLengths) || chunkLengths.length !== v.expectedChunkCount
      || Reflect.ownKeys(chunkLengths).length !== chunkLengths.length + 1) fail();
    // No caller-owned array is read after the first local PG network await.
    const fixedLengths = [];
    let lengthTotal = 0;
    for (let index = 0; index < v.expectedChunkCount; index += 1) {
      const desc = Object.getOwnPropertyDescriptor(chunkLengths, String(index));
      const size = desc?.value;
      if (!desc || !Object.hasOwn(desc, "value")
        || !Number.isSafeInteger(size) || size < 1 || size > 4 * 1024 * 1024
        || size > 16 * 1024 * 1024 - lengthTotal) fail();
      fixedLengths.push(size);
      lengthTotal += size;
    }
    // Use only the detached request throughout: the original `physical`
    // object can be changed by a getter/proxy while the cloud or PG call is
    // pending. Reusing it would let local PG proof describe operation B while
    // a cloud verifier was asked about the initially captured operation A.
    const fixedRequest = { scope: v.scope, operation: v.operation,
      digest: v.digest, expectedRootHash: v.expectedRootHash,
      expectedChunkCount: v.expectedChunkCount };
    const before = await this.reconcile(fixedRequest);
    if (before.status !== "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY") fail();
    let remote;
    try {
      remote = await cloudVerifier.verifyExact({
        scope: v.scope, operationId: v.operation.operation_id,
        ciphertextSha256: v.operation.ciphertext_sha256,
        expectedRootHash: v.expectedRootHash, chunkLengths: fixedLengths,
      });
    } catch (_) { fail(); }
    if (remote.status !== "EXTERNAL_CIPHERTEXT_REREAD_MATCHED"
      || remote.readbackMatched !== true
      || !same(remote.operationId, v.operation.operation_id)
      || remote.byteLength < 1 || remote.authorizesIo !== false
      || remote.externalProviderDurabilityProven !== false) fail();
    const after = await this.reconcile(fixedRequest);
    if (after.status !== before.status || after.sequence !== before.sequence
      || !same(after.root, before.root)) fail();
    return Object.freeze({ status: "PG_SIGNED_AND_CLOUD_BYTES_REREAD",
      operationId: Buffer.from(v.operation.operation_id),
      provider: remote.provider, providerFileId: remote.providerFileId,
      remoteReadbackMatched: true,
      localPgWalFlushConfirmed: true, authorizesIo: false,
      externalProviderDurabilityProven: false,
      ownerPinnedFloorChecked: Boolean(this.#trustedInventoryFloor),
      independentlyAnchoredFloorProven: false });
  }
  // Reconcile an already committed, physically immutable local ciphertext
  // before attempting external replication. Any cloud PUT begun here is an
  // NON-AUTHORIZING copy. There is no shared linearizable gate between S3,
  // GDrive, local PostgreSQL and the witness: an orphan may remain after a
  // failed post-PUT verification or quiescence. Never advertise durability.
  async publishAndReconcileCloudCopy({ physical, chunks, cloudPublisher,
    cloudVerifier } = {}) {
    const v = this.#request(physical);
    if (!(cloudPublisher instanceof Zk1CloudCiphertextCopyPublisher)
      || !(cloudVerifier instanceof Zk1CloudCiphertextReadbackVerifier)) fail();
    const detached = detachedChunks(chunks, v.expectedChunkCount,
      v.operation.ciphertext_sha256, v.expectedRootHash);
    const fixed = { scope: v.scope, operation: v.operation, digest: v.digest,
      expectedRootHash: v.expectedRootHash,
      expectedChunkCount: v.expectedChunkCount };
    const before = await this.reconcile(fixed);
    if (before.status !== "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY") fail();
    let write;
    try {
      write = await cloudPublisher.publishExact({ scope: v.scope,
        operationId: v.operation.operation_id,
        ciphertextSha256: v.operation.ciphertext_sha256,
        expectedRootHash: v.expectedRootHash, chunks: detached });
    } catch (_) { fail(); }
    if (write?.status !== "CLOUD_COPY_PUT_ACK_NONAUTHORITATIVE"
      || write.authorizesIo !== false || write.providerDurabilityProven !== false
      || !same(write.operationId, v.operation.operation_id)) fail();
    const remote = await this.reconcileCloudCopy({ physical: fixed,
      cloudVerifier, chunkLengths: detached.map((chunk) => chunk.length) });
    if (remote.provider !== write.provider
      || remote.providerFileId !== write.providerFileId
      || remote.authorizesIo !== false
      || !same(remote.operationId, v.operation.operation_id)) fail();
    return Object.freeze({ status: "PG_SIGNED_AND_EXTERNAL_COPY_REREAD",
      operationId: Buffer.from(v.operation.operation_id), provider: remote.provider,
      byteLength: write.byteLength, remoteReadbackMatched: true,
      authorizesIo: false, externalProviderDurabilityProven: false,
      independentRemoteIoFenceProven: false });
  }
  // An optional, deliberately NON-AUTHORIZING two-provider copy of one
  // historically signed physical operation. A late mutation/fault of the
  // first provider during the second provider's PUT is checked by a *second*
  // full readback of both providers. The two GETs are not an atomic snapshot;
  // none of these checks is a remotely fenced durable commit or I/O permit.
  async publishAndReconcileCloudCopies({ physical, chunks, copies } = {}) {
    const v = this.#request(physical);
    const detached = detachedChunks(chunks, v.expectedChunkCount,
      v.operation.ciphertext_sha256, v.expectedRootHash);
    if (!Array.isArray(copies) || copies.length !== 2
      || Reflect.ownKeys(copies).length !== 3) fail();
    const targets = [];
    for (let index = 0; index < 2; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(copies, String(index));
      if (!descriptor || !Object.hasOwn(descriptor, "value")) fail();
      const item = exact(descriptor.value, ["cloudPublisher", "cloudVerifier"]);
      if (!(item.cloudPublisher instanceof Zk1CloudCiphertextCopyPublisher)
        || !(item.cloudVerifier instanceof Zk1CloudCiphertextReadbackVerifier)) fail();
      if (Object.hasOwn(item.cloudPublisher, "pinnedCopyTarget")
        || Object.hasOwn(item.cloudVerifier, "pinnedCopyTarget")) fail();
      const pubTarget = item.cloudPublisher.pinnedCopyTarget;
      const readTarget = item.cloudVerifier.pinnedCopyTarget;
      if (pubTarget.provider !== readTarget.provider
        || pubTarget.driveFileId !== readTarget.driveFileId
        || !["s3", "gdrive"].includes(pubTarget.provider)) fail();
      targets.push({ publisher: item.cloudPublisher, verifier: item.cloudVerifier,
        configuredProvider: pubTarget.provider });
    }
    if (targets[0].publisher === targets[1].publisher
      || targets[0].verifier === targets[1].verifier
      || targets[0].configuredProvider === targets[1].configuredProvider) fail();
    const fixed = { scope: v.scope, operation: v.operation,
      digest: v.digest, expectedRootHash: v.expectedRootHash,
      expectedChunkCount: v.expectedChunkCount };
    const signed = await this.reconcile(fixed);
    if (signed.status !== "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY") fail();
    const receipts = [];
    const providerSet = new Set();
    for (const target of targets) {
      let status;
      try {
        status = await this.publishAndReconcileCloudCopy({ physical: fixed,
          chunks: detached, cloudPublisher: target.publisher,
          cloudVerifier: target.verifier });
      } catch (_) { fail(); }
      if (status.provider !== target.configuredProvider
        || providerSet.has(status.provider) || status.byteLength !== detached.reduce(
          (sum, chunk) => sum + chunk.length, 0)
        || status.authorizesIo !== false
        || status.externalProviderDurabilityProven !== false
        || status.independentRemoteIoFenceProven !== false) fail();
      providerSet.add(status.provider);
      receipts.push(status);
    }
    // Re-read BOTH after all network PUTs: a later copy operation or crashed
    // upload cannot silently replace the earlier ciphertext and still produce
    // a positive evidence receipt for two current copies.
    for (let index = 0; index < targets.length; index += 1) {
      let checked;
      try {
        checked = await this.reconcileCloudCopy({ physical: fixed,
          cloudVerifier: targets[index].verifier,
          chunkLengths: detached.map((chunk) => chunk.length) });
      } catch (_) { fail(); }
      if (checked.provider !== receipts[index].provider
        || checked.authorizesIo !== false
        || !same(checked.operationId, v.operation.operation_id)) fail();
    }
    const after = await this.reconcile(fixed);
    if (after.status !== signed.status || after.sequence !== signed.sequence
      || !same(after.root, signed.root)) fail();
    return Object.freeze({ status: "PG_SIGNED_AND_TWO_CLOUD_COPIES_REREAD",
      operationId: Buffer.from(v.operation.operation_id),
      providers: Object.freeze([...providerSet]),
      providerCount: 2, authorizesIo: false,
      externalProviderDurabilityProven: false,
      atomicCrossProviderCommitProven: false,
      independentRemoteIoFenceProven: false });
  }
  async publishExisting(input) {
    const v = this.#request(input);
    await this.#verifiedInventoryFloor(v);
    await this.#verifiedPhysical(v);
    const before = await this.#checkedCommit(v);
    if (before.status === "PHYSICAL_PG_AND_SIGNED_LOCAL_INVENTORY") {
      await this.#verifiedPhysical(v);
      return before;
    }
    const result = await this.ledger.append(v.operation);
    if (result.status !== "committed") {
      if (result.status === "pending" || result.status === "not_committed_final") {
        return { status: "pending", authorizesIo: false };
      }
      fail();
    }
    // Even a valid signed log write is not success if storage was changed or
    // the gate was advanced in the meantime.
    return this.reconcile({
      scope: v.scope, operation: v.operation, digest: v.digest,
      expectedRootHash: v.expectedRootHash, expectedChunkCount: v.expectedChunkCount,
    });
  }
  async putAndAttest(input) {
    const r = exact(input, ["scope", "operation", "digest",
      "expectedRootHash", "expectedChunkCount", "chunks"]);
    const v = this.#request({
      scope: r.scope, operation: r.operation, digest: r.digest,
      expectedRootHash: r.expectedRootHash, expectedChunkCount: r.expectedChunkCount,
    });
    const chunks = detachedChunks(r.chunks, v.expectedChunkCount,
      v.operation.ciphertext_sha256, v.expectedRootHash);
    // On a reverted signed ledger, refuse BEFORE reserving a new immutable
    // physical operation or calling any writer. Recovery must use the trusted
    // owner floor and a verified full chain, not opportunistic re-signing.
    await this.#verifiedInventoryFloor(v);
    // Exact signed retry must not invoke a new fenced writer against a
    // previously SEALED object. Physical readback is still mandatory.
    const previous = await this.ledger.getOperationStatus(v.operation.operation_id);
    if (previous.status === "committed") {
      return this.reconcile({
        scope: v.scope, operation: v.operation, digest: v.digest,
        expectedRootHash: v.expectedRootHash, expectedChunkCount: v.expectedChunkCount,
      });
    }
    const durableIntent = await this.intentAuthority.reserveExact({
      scope: v.scope, operation: v.operation, digest: v.digest,
      expectedRootHash: v.expectedRootHash, expectedChunkCount: v.expectedChunkCount,
    });
    if (durableIntent.status !== "IMMUTABLE_PREWRITE_INTENT"
      || !same(durableIntent.operationId, v.operation.operation_id)) fail();
    const stored = await this.sink.putSealed({
      scope: v.scope, objectId: v.objectId, revision: v.operation.revision,
      digest: v.digest, chunks, expectedChunkCount: v.expectedChunkCount,
      expectedRootHash: v.expectedRootHash,
    });
    if (stored.status !== "SEALED" || stored.chunkCount !== v.expectedChunkCount) fail();
    return this.publishExisting({
      scope: v.scope, operation: v.operation, digest: v.digest,
      expectedRootHash: v.expectedRootHash, expectedChunkCount: v.expectedChunkCount,
    });
  }
}
module.exports = { Zk1PgPhysicalInventoryBridge };
