"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");
const { Zk1SharedPgPhysicalCiphertextVerifier } =
  require("../src/services/zk1SharedPgPhysicalCiphertextVerifier");

test("independent PostgreSQL readback returns the immutable tuple needed for its Ed25519 attestation", async () => {
  const random = (n) => crypto.randomBytes(n);
  const ciphertext = Buffer.from("ciphertext-only-fixture");
  const scope = { account_id: random(16), compartment_id: Buffer.from("vault"),
    keyring_id: random(16) };
  const objectId = random(16).toString("base64url");
  const digest = random(32);
  const root = computeZk1CiphertextRoot([ciphertext]);
  const sha = crypto.createHash("sha256").update(ciphertext).digest();
  const operationId = random(16);
  const expectedInventoryRoot = random(32);
  const admissionId = random(16);
  const v = { scope, objectId, revision: 9, digest,
    expectedRootHash: root, expectedChunkCount: 1,
    expectedSha256: sha, operationId, expectedInventorySequence: 2,
    expectedInventoryRoot, epoch: 3 };
  const role = Object.fromEntries([
    "superuser", "create_db", "create_role", "replication", "bypass_rls",
    "can_create_gate_schema", "gate", "gate_member", "writer", "writer_member",
    "stop", "stop_member", "can_insert_chunks", "can_insert_seal", "can_update_head",
    "can_delete_chunks", "can_truncate_chunks", "can_insert_chunk_column",
    "can_update_chunk_column", "can_insert_seal_column", "can_update_seal_column",
    "can_update_head_column", "can_insert_intent", "can_update_intent",
    "can_insert_binding", "can_update_binding", "dangerous_head", "dangerous_admission",
    "dangerous_seal", "dangerous_intent", "dangerous_binding", "dangerous_chunks",
    "refs_head", "refs_seal", "refs_intent", "refs_binding",
    "any_protected_mutation", "any_dormant_mutation",
  ].map((field) => [field, false]));
  Object.assign(role, { login: "readback_only", role: "readback_only", attestor: true,
    can_read_chunks: true, can_read_seal: true, can_read_head: true,
    can_read_binding: true });
  const sealed = { revision: 9, digest, root_hash: root, expected_chunks: 1,
    physically_sealed_operation_id: operationId, generation: 4, admission_id: admissionId,
    live_generation: 4, phase: "OPEN", keyring_id: scope.keyring_id, live_revision: 9,
    live_digest: digest, intent_required: true, operation_id: operationId,
    expected_inventory_sequence: 2, expected_inventory_root: expectedInventoryRoot,
    intent_keyring: scope.keyring_id, intent_revision: 9, intent_epoch: 3,
    intent_digest: digest, intent_generation: 4, intent_sha256: sha,
    intent_root: root, intent_count: 1, admission_operation_id: operationId,
    bound_admission_id: admissionId, bound_generation: 4 };
  const calls = [];
  const pool = { async connect() { return {
    async query(statement) {
      calls.push(statement);
      if (statement.startsWith("SELECT session_user")) return { rowCount: 1, rows: [role] };
      if (statement === "SHOW fsync") return { rows: [{ fsync: "on" }] };
      if (statement === "SHOW synchronous_commit") return { rows: [{ synchronous_commit: "on" }] };
      if (statement === "SHOW full_page_writes") return { rows: [{ full_page_writes: "on" }] };
      if (statement.includes("FROM zk1_gate.sealed_object")) return { rowCount: 1, rows: [sealed] };
      if (statement.includes("FROM zk1_gate.ciphertext_chunk")) return {
        rowCount: 1, rows: [{ chunk_index: 0, ciphertext }] };
      if (statement.includes("physical_inventory_wal_flush_barrier")) return {
        rowCount: 1, rows: [{ flushed: true }] };
      return { rowCount: 0, rows: [] };
    },
    release() {},
  }; } };
  const verifier = new Zk1SharedPgPhysicalCiphertextVerifier({ pool });
  const readback = await verifier.verifyExact(v);
  assert.equal(readback.walFlushConfirmed, true);
  assert.deepEqual(readback.digest, digest);
  assert.equal(readback.revision, 9);
  assert.equal(readback.epoch, 3);
  assert.equal(readback.expectedInventorySequence, 2);
  assert.deepEqual(readback.expectedInventoryRoot, expectedInventoryRoot);
  assert.ok(calls.some((sql) => sql.includes("physical_inventory_wal_flush_barrier")));
});
