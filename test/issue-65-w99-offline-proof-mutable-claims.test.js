"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const witness = require("../src/crypto/rootark-zk1-offline-commitment-receipt");
const cas = require("../src/crypto/rootark-zk1-offline-cas-commit-proof");

const b64 = (raw) => Buffer.from(raw).toString("base64url");
const random = (length) => crypto.randomBytes(length);
const hash = (raw) => crypto.createHash("sha256").update(raw).digest();
const scope = () => ({ account_id: random(16), compartment_id: Buffer.from("private-vault"),
  keyring_id: random(16) });
const spkiHash = (key) => b64(hash(key.export({ format: "der", type: "spki" })));

// A signed transport claim A is read exactly once for signature verification,
// then a malicious object exposes unsigned claim B for the authorization
// decision. Plain JSON cannot do this, but the offline trust API accepts
// caller-owned JavaScript objects and must reject the substitution.
function flipAfterFirstRead(signedA, unsignedB, fields) {
  const reads = new Map();
  return new Proxy(signedA, { get(target, field, receiver) {
    if (!fields.includes(field)) return Reflect.get(target, field, receiver);
    const next = (reads.get(field) || 0) + 1;
    reads.set(field, next);
    return next === 1 ? signedA[field] : unsignedB[field];
  } });
}

test("offline witness verifier cannot verify signed scope A then accept unsigned epoch and operation B", () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const before = scope();
  const after = scope();
  const now = Math.floor(Date.now() / 1000);
  const signed = { schema: witness.SCHEMA, status: "committed",
    account_id: b64(before.account_id), compartment_id: b64(before.compartment_id),
    keyring_id: b64(before.keyring_id), revision: 4, digest: b64(random(32)),
    epoch: 2, previous_revision: 3, previous_digest: b64(random(32)),
    operation_id: b64(random(16)), pop_challenge_id: b64(random(16)),
    request_nonce: b64(random(32)), commit_nonce: b64(random(32)),
    sequence: 9, previous_receipt_sha256: b64(random(32)),
    issued_at: now - 1, expires_at: now + 120 };
  const receipt = { ...signed, signature: b64(crypto.sign(null,
    witness.commitmentSigningBytes(signed), signer.privateKey)) };
  const forged = { ...signed, account_id: b64(after.account_id),
    compartment_id: b64(after.compartment_id), keyring_id: b64(after.keyring_id),
    revision: 50, epoch: 17, digest: b64(random(32)),
    operation_id: b64(random(16)), pop_challenge_id: b64(random(16)),
    request_nonce: b64(random(32)), commit_nonce: b64(random(32)) };
  assert.throws(() => witness.verifySignedReceipt({
    receipt: flipAfterFirstRead(receipt, forged, witness.FIELDS),
    signerPublicKey: signer.publicKey, independentSignerSpkiSha256: spkiHash(signer.publicKey),
    expectedScope: after,
    expectedHead: { revision: forged.revision, epoch: forged.epoch,
      digest: Buffer.from(forged.digest, "base64url") },
    expectedOperation: { operation_id: forged.operation_id,
      pop_challenge_id: forged.pop_challenge_id,
      request_nonce: forged.request_nonce, commit_nonce: forged.commit_nonce },
    nowSeconds: now,
  }), /ZK_OFFLINE_COMMITMENT_PROOF_DENIED/);
});

test("offline CAS verifier cannot verify signed sequence A then accept unsigned committed head B", () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const before = scope();
  const after = scope();
  const previousHead = { revision: 7, digest: random(32) };
  const now = Math.floor(Date.now() / 1000);
  const signed = { schema: cas.SCHEMA, status: "committed",
    account_id: b64(before.account_id), compartment_id: b64(before.compartment_id),
    keyring_id: b64(before.keyring_id), revision: 8, epoch: 4,
    digest: b64(random(32)), previous_revision: previousHead.revision,
    previous_digest: b64(previousHead.digest), operation_id: b64(random(16)),
    request_nonce: b64(random(32)), commit_nonce: b64(random(32)),
    witness_receipt_sha256: b64(random(32)), cas_sequence: 14,
    witness_sequence: 13, issued_at: now - 1, expires_at: now + 120 };
  const proof = { ...signed, signature: b64(crypto.sign(null,
    cas.signingBytes(signed), signer.privateKey)) };
  const forged = { ...signed, account_id: b64(after.account_id),
    compartment_id: b64(after.compartment_id), keyring_id: b64(after.keyring_id),
    revision: 8, epoch: 50, digest: b64(random(32)),
    operation_id: b64(random(16)), request_nonce: b64(random(32)),
    commit_nonce: b64(random(32)), witness_receipt_sha256: b64(random(32)) };
  assert.throws(() => cas.verifySignedCasProof({
    proof: flipAfterFirstRead(proof, forged, cas.FIELDS),
    signerPublicKey: signer.publicKey, independentSignerSpkiSha256: spkiHash(signer.publicKey),
    scope: after, previousHead,
    committedHead: { revision: forged.revision, epoch: forged.epoch,
      digest: Buffer.from(forged.digest, "base64url") },
    operationId: forged.operation_id, requestNonce: forged.request_nonce,
    commitNonce: forged.commit_nonce, witnessReceiptSha256: forged.witness_receipt_sha256,
    witnessSequence: forged.witness_sequence, minimumCasSequence: 13, nowSeconds: now,
  }), /ZK_OWNER_OFFLINE_CAS_PROOF_DENIED/);
});
