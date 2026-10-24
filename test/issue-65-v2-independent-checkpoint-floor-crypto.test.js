"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const { verifySignedHead, assertIndependentV2Predecessor, DOMAIN, TYPE } =
  require("../src/services/zk1V2CheckpointRemoteFloor");

test("independent V2 floor head authenticates pinned key/nonce/epoch/monotonic minimum", async () => {
  const key = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("dev"), keyring_id: crypto.randomBytes(16) };
  const nonce = crypto.randomBytes(32);
  const data = { type: TYPE, ...scope, sequence: 128, epoch: 0,
    head_digest: crypto.randomBytes(32), checkpoint_digest: crypto.randomBytes(32),
    chain_hash: Buffer.alloc(32), operation_id: Buffer.alloc(32),
    cas_receipt_hash: Buffer.alloc(32), floor_receipt_hash: Buffer.alloc(32),
    cas_receipt_identity_hash: Buffer.alloc(32),
    floor_receipt_identity_hash: Buffer.alloc(32),
    ancestry: [], nonce,
    issued_at: Math.floor(Date.now() / 1000) };
  const proof = Buffer.from(await z.encodeDeterministic({ ...data,
    signature: crypto.sign(null, Buffer.concat([DOMAIN,
      Buffer.from(await z.encodeDeterministic(data))]), key.privateKey) }));
  const opts = { scope, pinnedFloorPublicKey: key.publicKey, nonce };
  const head = await verifySignedHead(proof, opts);
  assert.equal(head.sequence, 128);
  assert.equal(head.epoch, 0);
  assert.deepEqual(head.checkpointDigest, data.checkpoint_digest);
  const predecessor = { previousSequence: 128,
    previousDigest: head.headDigest, previousCheckpointDigest: head.checkpointDigest,
    proposedEpoch: 3 };
  assert.equal(assertIndependentV2Predecessor(head, predecessor), true);
  assert.throws(() => assertIndependentV2Predecessor(head,
    { ...predecessor, proposedEpoch: 0 }), /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "a stale owner epoch cannot pass independent remote high-water");
  assert.throws(() => assertIndependentV2Predecessor(head,
    { ...predecessor, previousSequence: 129 }), /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  assert.throws(() => assertIndependentV2Predecessor(head,
    { ...predecessor, previousCheckpointDigest: crypto.randomBytes(32) }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  await assert.rejects(verifySignedHead(proof, { ...opts, nonce: crypto.randomBytes(32) }),
    /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  await assert.rejects(verifySignedHead(proof, { ...opts,
    pinnedFloorPublicKey: crypto.generateKeyPairSync("ed25519").publicKey }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  await assert.rejects(verifySignedHead(proof, { ...opts,
    minimum: { sequence: 129, chainHash: crypto.randomBytes(32) } }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  await assert.rejects(verifySignedHead(proof, { ...opts,
    minimum: { sequence: 128, chainHash: crypto.randomBytes(32) } }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/);
  // RED on the old verifier: a validly signed seq130 B whose chain does not
  // contain externally retained seq129 A used to satisfy a numerical floor.
  const forkB = { ...data, sequence: 130, epoch: 4,
    head_digest: crypto.randomBytes(32),
    checkpoint_digest: crypto.randomBytes(32),
    chain_hash: crypto.randomBytes(32),
    operation_id: crypto.randomBytes(32),
    cas_receipt_hash: crypto.randomBytes(32),
    floor_receipt_hash: crypto.randomBytes(32),
    cas_receipt_identity_hash: crypto.randomBytes(32),
    floor_receipt_identity_hash: crypto.randomBytes(32) };
  const forkWire = Buffer.from(await z.encodeDeterministic({ ...forkB,
    signature: crypto.sign(null, Buffer.concat([DOMAIN,
      Buffer.from(await z.encodeDeterministic(forkB))]), key.privateKey) }));
  await assert.rejects(verifySignedHead(forkWire, { ...opts,
    pinnedOwnerPublicKey: crypto.generateKeyPairSync("ed25519").publicKey,
    minimum: { sequence: 129, chainHash: crypto.randomBytes(32) } }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "a valid Ed25519 signature and higher seq are not ancestry of pinned A129");
});

test("signed seq130 ancestry recomputes exact owner-approved chain from pinned seq129", async () => {
  const floorKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: crypto.randomBytes(16),
    compartment_id: Buffer.from("owner-archive"), keyring_id: crypto.randomBytes(16) };
  const nonce = crypto.randomBytes(32);
  const pinned = { sequence: 129, epoch: 3,
    chainHash: crypto.randomBytes(32), headDigest: crypto.randomBytes(32),
    checkpointDigest: crypto.randomBytes(32) };
  const statement = { ...scope, sequence: 130, epoch: 4,
    head_digest: crypto.randomBytes(32), checkpoint_digest: crypto.randomBytes(32),
    previous_head_digest: pinned.headDigest,
    previous_checkpoint_digest: pinned.checkpointDigest,
    operation_id: crypto.randomBytes(32),
    cas_receipt_hash: crypto.randomBytes(32),
    floor_receipt_hash: crypto.randomBytes(32) };
  const ownerDomain = Buffer.from("Root.ark/zk-1/v2-checkpoint-floor-owner-advance/v1\0");
  const entryDomain = Buffer.from("v2-independent-floor-entry\0");
  const canonical = Buffer.from(await z.encodeDeterministic(statement));
  const ownerSignature = crypto.sign(null,
    Buffer.concat([ownerDomain, canonical]), ownerKeys.privateKey);
  const chainHash = crypto.createHash("sha256").update(entryDomain)
    .update(pinned.chainHash).update(canonical).update(ownerSignature).digest();
  const step = { ...Object.fromEntries(Object.entries(statement)
    .filter(([key]) => !["account_id", "compartment_id", "keyring_id"].includes(key))),
    owner_signature: ownerSignature };
  const proof = { type: TYPE, ...scope, sequence: 130, epoch: 4,
    head_digest: statement.head_digest,
    checkpoint_digest: statement.checkpoint_digest,
    chain_hash: chainHash, operation_id: statement.operation_id,
    cas_receipt_hash: statement.cas_receipt_hash,
    floor_receipt_hash: statement.floor_receipt_hash,
    cas_receipt_identity_hash: crypto.randomBytes(32),
    floor_receipt_identity_hash: crypto.randomBytes(32),
    ancestry: [step], nonce, issued_at: Math.floor(Date.now() / 1000) };
  const signProof = async (value) => Buffer.from(await z.encodeDeterministic({
    ...value, signature: crypto.sign(null, Buffer.concat([DOMAIN,
      Buffer.from(await z.encodeDeterministic(value))]), floorKeys.privateKey),
  }));
  const options = { scope, nonce, pinnedFloorPublicKey: floorKeys.publicKey,
    pinnedOwnerPublicKey: ownerKeys.publicKey, minimum: pinned };
  const accepted = await verifySignedHead(await signProof(proof), options);
  assert.equal(accepted.sequence, 130);
  assert.deepEqual(accepted.operationId, statement.operation_id);
  assert.deepEqual(accepted.casReceiptHash, statement.cas_receipt_hash);
  await assert.rejects(verifySignedHead(await signProof(proof), {
    ...options, minimum: { ...pinned, chainHash: crypto.randomBytes(32) } }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "rollback and advance on B cannot prove externally pinned A129 as an ancestor");
  await assert.rejects(verifySignedHead(await signProof({ ...proof,
    operation_id: crypto.randomBytes(32) }), options),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "signed floor HEAD must preserve immutable operation ID from signed ancestry");
  await assert.rejects(verifySignedHead(await signProof({ ...proof,
    cas_receipt_hash: crypto.randomBytes(32) }), options),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "signed floor HEAD cannot reinterpret another CAS finalization receipt");
  await assert.rejects(verifySignedHead(await signProof(proof), {
    ...options, pinnedOwnerPublicKey: crypto.generateKeyPairSync("ed25519").publicKey }),
  /ZK_V2_INDEPENDENT_FLOOR_DENIED/,
  "untrusted owner key cannot certify successor of retained ancestor");
});
