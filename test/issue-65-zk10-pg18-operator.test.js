"use strict";

// RED gate for an actual disposable PG18-backed ZK10 operator.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { createZk10Pg18Operator, createZk10Pg18OperatorHttpsServer } =
  require("../lab/issue-65-zk10-pg18-operator/operator");
const { buildSparseEnrollmentProof, signOwnerCutover, digestOwnerCutover } =
  require("../src/crypto/rootark-zk10-account-cutover-v1");

test("ZK10 PG18 authority exposes a non-production SQL CAS and TLS1.3/mTLS endpoint", () => {
  assert.equal(typeof createZk10Pg18Operator, "function");
  assert.equal(typeof createZk10Pg18OperatorHttpsServer, "function");
});

test("ZK10 PG18 operator rejects SQL-writer forged CAS receipt before signing readback", async () => {
  const operatorKeys = crypto.generateKeyPairSync("ed25519");
  const ownerKeys = crypto.generateKeyPairSync("ed25519");
  const account = Buffer.alloc(16, 11).toString("base64url");
  const zkAccount = Buffer.alloc(16, 12).toString("base64url");
  const identityDigest = "b".repeat(64);
  const physicalDigest = "c".repeat(64);
  const operatorId = "zk10-dev-security-peer";
  const HEAD = Buffer.from("Root.ark/zk10/operator-account-head/v1\0");
  const RECEIPT = Buffer.from("Root.ark/zk10/operator-cutover-receipt/v1\0");
  const ownerStatement = signOwnerCutover({
    type: "rootark-zk10-owner-account-cutover/v1",
    immutable_account_id: account, zk_account_id: zkAccount,
    generation: 1, previous_cutover_digest: null,
    inventory_head: "e".repeat(64), complete_corpus: true,
    covered_compartments: [Buffer.alloc(16, 13).toString("base64url")],
    legacy_egress_scope: "all", reference_disposition: "fully_accounted",
    migration_disposition: "closed", grant: "protected_enforced", grants: [],
    suite: "zk1-v2", nonce: crypto.randomBytes(32).toString("base64url"),
    issued_at: Math.floor(Date.now() / 1000),
  }, ownerKeys.privateKey);
  const cutoverDigest = digestOwnerCutover(ownerStatement);
  const sign = (payload) => ({ ...payload, signature: crypto.sign(null,
    Buffer.concat([HEAD, Buffer.from(JSON.stringify(payload))]),
    operatorKeys.privateKey).toString("base64url") });
  const digest = (wire) => {
    const { signature, ...fields } = wire;
    return crypto.createHash("sha256").update(HEAD)
      .update(JSON.stringify(fields)).update(Buffer.from(signature, "base64url"))
      .digest("hex");
  };
  const first = sign({ type: "rootark-zk10-operator-account-head/v1",
    operator_id: operatorId, immutable_account_id: account, sequence: 1,
    previous_head_digest: "0".repeat(64),
    enrollment_root: buildSparseEnrollmentProof([], account).root,
    physical_digest: physicalDigest, ever_enrolled: false,
    owner_generation: 0, owner_cutover_digest: null });
  const second = sign({ type: "rootark-zk10-operator-account-head/v1",
    operator_id: operatorId, immutable_account_id: account, sequence: 2,
    previous_head_digest: digest(first),
    enrollment_root: buildSparseEnrollmentProof([
      { accountId: account, cutoverDigest }], account).root,
    physical_digest: physicalDigest, ever_enrolled: true,
    owner_generation: 1, owner_cutover_digest: cutoverDigest });
  const receiptPayload = {
    type: "rootark-zk10-operator-cutover-receipt/v1",
    operator_id: operatorId, immutable_account_id: account,
    owner_cutover_digest: cutoverDigest, expected_sequence: 1,
    expected_head_digest: digest(first),
    lease_id: crypto.randomBytes(16).toString("base64url"),
    fencing_epoch: 11, lease_expires_at_ms: Date.now() + 8000,
    challenge: crypto.randomBytes(32).toString("base64url"),
    status: "committed",
  };
  const signReceipt = (payload) => ({ ...payload,
    signature: crypto.sign(null, Buffer.concat([
      RECEIPT, Buffer.from(JSON.stringify(payload))]),
    operatorKeys.privateKey).toString("base64url") });
  const receipt = signReceipt(receiptPayload);
  const row = { sequence: "2", head_json: JSON.stringify(second),
    previous_head_json: JSON.stringify(first),
    owner_statement_json: JSON.stringify(ownerStatement),
    owner_digest: cutoverDigest, cas_receipt_json: JSON.stringify(receipt) };
  const pool = { connect: async () => { throw Error("SHOULD_NOT_CONNECT"); },
    query: async () => ({ rowCount: 1, rows: [row] }) };
  const operator = createZk10Pg18Operator({ pool, operatorId,
    immutableAccountId: account, canonicalZkAccountId: zkAccount,
    identityDigest, initialPhysicalDigest: physicalDigest,
    operatorPrivateKey: operatorKeys.privateKey,
    operatorPublicKey: operatorKeys.publicKey,
    ownerPublicKey: ownerKeys.publicKey });
  const request = { immutable_account_id: account, identity_digest: identityDigest,
    owner_cutover_digest: cutoverDigest,
    expected_head_digest: receipt.expected_head_digest,
    lease_id: receipt.lease_id, fencing_epoch: receipt.fencing_epoch,
    lease_expires_at_ms: receipt.lease_expires_at_ms,
    challenge: crypto.randomBytes(32).toString("base64url") };
  const accepted = await operator.readback(request);
  assert.equal(accepted.readback.decision, "committed",
    "original signed receipt and owner-signed head must allow lost ACK readback");
  for (const [label, forged] of [
    ["forged receipt signature", { ...receipt,
      signature: crypto.randomBytes(64).toString("base64url") }],
    ["unsigned lease substitution", { ...receipt,
      lease_id: crypto.randomBytes(16).toString("base64url") }],
    ["foreign account", signReceipt({ ...receiptPayload,
      immutable_account_id: Buffer.alloc(16, 99).toString("base64url") })],
    ["wrong signed prior head", signReceipt({ ...receiptPayload,
      expected_head_digest: "f".repeat(64) })],
    ["signed aborted receipt", signReceipt({ ...receiptPayload, status: "aborted" })],
  ]) {
    row.cas_receipt_json = JSON.stringify(forged);
    await assert.rejects(operator.readback(request), /ZK10_DEV_OPERATOR_REJECTED/,
      `database tamper must not mint signed CAS readback: ${label}`);
  }
});
