"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const witness = require("../src/crypto/rootark-zk1-offline-commitment-receipt");

const b64 = (v) => Buffer.from(v).toString("base64url");
const random = (length) => crypto.randomBytes(length);
const digest = (value) => crypto.createHash("sha256").update(value).digest();

test("witness predecessor fencing requires a genuine signature and the same scope", () => {
  const signer = crypto.generateKeyPairSync("ed25519");
  const foreign = crypto.generateKeyPairSync("ed25519");
  const scope = { account_id: random(16), compartment_id: Buffer.from("private-vault"),
    keyring_id: random(16) };
  const now = Math.floor(Date.now() / 1000);
  const sign = (record, key = signer.privateKey) => ({ ...record,
    signature: b64(crypto.sign(null, witness.commitmentSigningBytes(record), key)) });
  const predecessor = {
    schema: witness.SCHEMA, status: "committed",
    account_id: b64(scope.account_id), compartment_id: b64(scope.compartment_id),
    keyring_id: b64(scope.keyring_id), revision: 1, digest: b64(random(32)),
    epoch: 1, previous_revision: null, previous_digest: null,
    operation_id: null, pop_challenge_id: null, request_nonce: null,
    commit_nonce: null, sequence: 4, previous_receipt_sha256: null,
    issued_at: now - 30, expires_at: now + 100,
  };
  const previousGood = sign(predecessor);
  const currentHead = { revision: 2, epoch: 1, digest: random(32) };
  const current = (prior) => sign({
    ...predecessor, revision: currentHead.revision, digest: b64(currentHead.digest),
    previous_revision: prior.revision, previous_digest: prior.digest,
    sequence: 5, previous_receipt_sha256: b64(digest(Buffer.concat([
      witness.commitmentSigningBytes(Object.fromEntries(witness.FIELDS.map(
        (field) => [field, prior[field]]))), Buffer.from(prior.signature, "base64url"),
    ]))), issued_at: now - 5, expires_at: now + 90,
  });
  const expected = (prior) => ({ receipt: current(prior), previousReceipt: prior,
    signerPublicKey: signer.publicKey,
    independentSignerSpkiSha256: b64(digest(signer.publicKey.export({
      format: "der", type: "spki",
    }))), expectedScope: scope, expectedHead: currentHead, nowSeconds: now });
  assert.equal(witness.verifySignedReceipt(expected(previousGood)).signedReceiptVerified, true);

  const previousForged = sign(predecessor, foreign.privateKey);
  // The CURRENT receipt is genuinely witness-signed and hashes the exact
  // forged prior bytes. Hash continuity alone must not endorse that prior.
  assert.throws(() => witness.verifySignedReceipt(expected(previousForged)),
    /ZK_OFFLINE_COMMITMENT_PROOF_DENIED/);

  const previousWrongScope = sign({ ...predecessor, account_id: b64(random(16)) });
  assert.throws(() => witness.verifySignedReceipt(expected(previousWrongScope)),
    /ZK_OFFLINE_COMMITMENT_PROOF_DENIED/);

  const previousFuture = sign({ ...predecessor, issued_at: now,
    expires_at: now + 100 });
  assert.throws(() => witness.verifySignedReceipt(expected(previousFuture)),
    /ZK_OFFLINE_COMMITMENT_PROOF_DENIED/);
});
