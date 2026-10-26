"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const witness = require("../src/crypto/rootark-zk1-offline-commitment-receipt");
const cas = require("../src/crypto/rootark-zk1-offline-cas-commit-proof");

const b64 = (value) => Buffer.from(value).toString("base64url");
const digest = (value) => crypto.createHash("sha256").update(value).digest();
const random = (length) => crypto.randomBytes(length);

function signerWithSpoofedExport() {
  const attacker = crypto.generateKeyPairSync("ed25519");
  const pinnedForeign = crypto.generateKeyPairSync("ed25519");
  const disguised = crypto.createPublicKey(attacker.privateKey);
  const foreignSpki = pinnedForeign.publicKey.export({ type: "spki", format: "der" });
  disguised.export = () => Buffer.from(foreignSpki);
  return { privateKey: attacker.privateKey, disguised,
    foreignPin: b64(digest(foreignSpki)),
    authenticPin: b64(digest(attacker.publicKey.export({ type: "spki", format: "der" }))) };
}

test("witness offline receipt rejects a signing key disguised as the externally pinned Ed25519 key", () => {
  const signer = signerWithSpoofedExport();
  const scope = { account_id: random(16), compartment_id: Buffer.from("test-scope"),
    keyring_id: random(16) };
  const head = { revision: 8, epoch: 4, digest: random(32) };
  const now = Math.floor(Date.now() / 1000);
  const unsigned = { schema: witness.SCHEMA, status: "committed",
    account_id: b64(scope.account_id), compartment_id: b64(scope.compartment_id),
    keyring_id: b64(scope.keyring_id), revision: head.revision,
    digest: b64(head.digest), epoch: head.epoch,
    previous_revision: head.revision - 1, previous_digest: b64(random(32)),
    operation_id: b64(random(16)), pop_challenge_id: null,
    request_nonce: b64(random(32)), commit_nonce: b64(random(32)),
    sequence: 10, previous_receipt_sha256: b64(random(32)),
    issued_at: now - 1, expires_at: now + 100 };
  const receipt = { ...unsigned, signature: b64(crypto.sign(null,
    witness.commitmentSigningBytes(unsigned), signer.privateKey)) };
  assert.equal(witness.verifySignedReceipt({ receipt,
    signerPublicKey: crypto.createPublicKey(signer.privateKey),
    independentSignerSpkiSha256: signer.authenticPin, expectedScope: scope,
    expectedHead: head, nowSeconds: now }).signedReceiptVerified, true);
  assert.throws(() => witness.verifySignedReceipt({ receipt,
    signerPublicKey: signer.disguised,
    independentSignerSpkiSha256: signer.foreignPin, expectedScope: scope,
    expectedHead: head, nowSeconds: now }),
  /ZK_OFFLINE_COMMITMENT_PROOF_DENIED/);
});

test("offline CAS proof rejects a signing key disguised as the separately pinned CAS authority", () => {
  const signer = signerWithSpoofedExport();
  const scope = { account_id: random(16), compartment_id: Buffer.from("test-scope"),
    keyring_id: random(16) };
  const previousHead = { revision: 5, digest: random(32) };
  const committedHead = { revision: 6, epoch: 7, digest: random(32) };
  const operationId = b64(random(16));
  const requestNonce = b64(random(32));
  const commitNonce = b64(random(32));
  const witnessReceiptSha256 = b64(random(32));
  const now = Math.floor(Date.now() / 1000);
  const unsigned = { schema: cas.SCHEMA, status: "committed",
    account_id: b64(scope.account_id), compartment_id: b64(scope.compartment_id),
    keyring_id: b64(scope.keyring_id), revision: committedHead.revision,
    epoch: committedHead.epoch, digest: b64(committedHead.digest),
    previous_revision: previousHead.revision, previous_digest: b64(previousHead.digest),
    operation_id: operationId, request_nonce: requestNonce,
    commit_nonce: commitNonce, witness_receipt_sha256: witnessReceiptSha256,
    cas_sequence: 11, witness_sequence: 8, issued_at: now - 1,
    expires_at: now + 100 };
  const proof = { ...unsigned, signature: b64(crypto.sign(null,
    cas.signingBytes(unsigned), signer.privateKey)) };
  const expected = { proof, signerPublicKey: crypto.createPublicKey(signer.privateKey),
    independentSignerSpkiSha256: signer.authenticPin, scope, previousHead,
    committedHead, operationId, requestNonce, commitNonce, witnessReceiptSha256,
    witnessSequence: 8, minimumCasSequence: 10, nowSeconds: now };
  assert.equal(cas.verifySignedCasProof(expected).independentlyPinnedCasSignatureVerified, true);
  assert.throws(() => cas.verifySignedCasProof({ ...expected,
    signerPublicKey: signer.disguised,
    independentSignerSpkiSha256: signer.foreignPin }),
  /ZK_OWNER_OFFLINE_CAS_PROOF_DENIED/);
});
