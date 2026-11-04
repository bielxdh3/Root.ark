"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgSealedObjectStore } = require("../src/services/zk1SharedPgSealedObjectStore");
const { computeZk1CiphertextRoot } = require("../src/crypto/rootark-zk-chunk-root-v1");

const pg18 = {
  skip: !process.env.ROOTARK_ZK1_TEST_PG_URL || !process.env.ROOTARK_ZK1_RUNTIME_PG_URL
    ? "requires disposable PG18 administrator and isolated gate runtime" : false,
};

test("PG18 strict intent: partial FINISH cannot strand replay; seal and quiescence drain remain legal", pg18, async (t) => {
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL,
    max: 2, connectionTimeoutMillis: 3000 });
  const runtime = new Pool({ connectionString: process.env.ROOTARK_ZK1_RUNTIME_PG_URL,
    max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), runtime.end()]));
  const gate = new Zk1SharedPgGateAuthority({ pool: runtime });
  const seal = new Zk1SharedPgSealedObjectStore({ pool: runtime });
  const principal = "trusted-isolated-gateway";

  async function prepare() {
    const chunks = [crypto.randomBytes(34), crypto.randomBytes(79)];
    const scope = { account_id: crypto.randomBytes(16),
      compartment_id: crypto.randomBytes(8), keyring_id: crypto.randomBytes(16) };
    const scopeKey = `${scope.account_id.toString("hex")}:${scope.compartment_id.length.toString(16)}:${scope.compartment_id.toString("hex")}`;
    const operationId = crypto.randomBytes(16);
    const objectId = crypto.randomBytes(16).toString("base64url");
    const digest = crypto.randomBytes(32);
    const root = computeZk1CiphertextRoot(chunks);
    await admin.query(`INSERT INTO zk1_gate.head
      (scope_key,keyring_id,revision,digest,require_physical_inventory_intent)
      VALUES($1,$2,1,$3,true)`, [scopeKey, scope.keyring_id, digest]);
    await admin.query(`INSERT INTO zk1_gate.physical_inventory_intent
      (scope_key,object_id,operation_id,expected_inventory_sequence,expected_inventory_root,
        keyring_id,revision,epoch,digest,generation,ciphertext_sha256,
        expected_root_hash,expected_chunks)
      VALUES($1,$2,$3,0,$4,$5,1,0,$6,1,$7,$8,$9)`,
    [scopeKey, objectId, operationId, crypto.randomBytes(32), scope.keyring_id,
      digest, crypto.createHash("sha256").update(Buffer.concat(chunks)).digest(),
      root, chunks.length]);
    const io = { scope, workerId: crypto.createHash("sha256")
      .update("Root.ark/zk-1/physical-inventory-worker/v1\0")
      .update(operationId).digest().subarray(0, 16),
    principal, action: "put", objectId, revision: 1, digest };
    const start = await gate.beginIoAdmission(io);
    assert.equal(start.proceed, true);
    return { io, chunks, root, scopeKey, start };
  }

  const pending = await prepare();
  const write = { ...pending.io, admissionId: pending.start.admissionId,
    generation: pending.start.generation };
  assert.deepEqual(await gate.putCiphertextChunk(write, 0, pending.chunks[0]),
    { stored: true });
  // Even a compromised gate SQL login must not burn an unsealed operation.
  await assert.rejects(runtime.query(`UPDATE zk1_gate.admission
    SET state='FINISHED' WHERE id=$1`, [pending.start.admissionId]),
  /unsealed physical operation cannot finish while OPEN/i);
  await assert.rejects(gate.finishIoAdmission({ scope: pending.io.scope,
    admissionId: pending.start.admissionId, workerId: pending.io.workerId, principal }),
  /ZK_GATE_UNAVAILABLE|ZK_GATE_DENIED/);
  const active = await admin.query(`SELECT state FROM zk1_gate.admission WHERE id=$1`,
    [pending.start.admissionId]);
  assert.equal(active.rows[0].state, "ACTIVE");

  // A new gate process can recover the old durable ID under the unchanged
  // head CAS. Existing chunks may be replayed only with identical bytes.
  const restarted = new Zk1SharedPgGateAuthority({ pool: runtime });
  const replay = await restarted.beginIoAdmission(pending.io);
  assert.deepEqual(replay.admissionId, pending.start.admissionId);
  assert.equal(replay.generation, pending.start.generation);
  assert.equal(replay.proceed, true);
  assert.deepEqual(await restarted.putCiphertextChunk(write, 0, pending.chunks[0]),
    { stored: false });
  await assert.rejects(restarted.putCiphertextChunk(write, 0, crypto.randomBytes(34)),
    /ZK_GATE_CHUNK_CONFLICT/);
  await assert.rejects(restarted.beginIoAdmission({ ...pending.io,
    workerId: crypto.randomBytes(16) }), /ZK_GATE_UNAVAILABLE|ZK_GATE_DENIED/);
  await restarted.putCiphertextChunk(write, 1, pending.chunks[1]);
  assert.deepEqual(await seal.seal({ ...write, expectedChunkCount: pending.chunks.length,
    expectedRootHash: pending.root }), { status: "SEALED", chunkCount: 2 });
  assert.equal((await runtime.query(`UPDATE zk1_gate.admission
    SET state='FINISHED' WHERE id=$1`, [pending.start.admissionId])).rowCount, 1,
  "direct runtime FINISH after immutable seal remains permitted");
  assert.deepEqual(await restarted.finishIoAdmission({ scope: pending.io.scope,
    admissionId: pending.start.admissionId, workerId: pending.io.workerId, principal }),
  { status: "FINISHED" });
  const sealedState = await admin.query(`SELECT state FROM zk1_gate.admission WHERE id=$1`,
    [pending.start.admissionId]);
  assert.equal(sealedState.rows[0].state, "FINISHED");
  await assert.rejects(restarted.beginIoAdmission(pending.io),
    /ZK_GATE_UNAVAILABLE|ZK_GATE_DENIED/, "FINISHED cannot resurrect after a replay");

  // An operator may abandon unsealed staging by quiescing the scope. Once
  // fenced it can drain the old admission, but can never resume writing.
  const abandoned = await prepare();
  const abandonWrite = { ...abandoned.io, admissionId: abandoned.start.admissionId,
    generation: abandoned.start.generation };
  await gate.putCiphertextChunk(abandonWrite, 0, abandoned.chunks[0]);
  const operationId = crypto.randomBytes(16);
  const reservationId = crypto.randomBytes(16);
  const quiesced = await gate.beginQuiesce({ scope: abandoned.io.scope,
    revision: 1, digest: abandoned.io.digest, operationId, reservationId });
  assert.equal(quiesced.state, "QUIESCING");
  assert.equal((await runtime.query(`UPDATE zk1_gate.admission
    SET state='FINISHED' WHERE id=$1`, [abandoned.start.admissionId])).rowCount, 1,
  "direct runtime FINISH must be available for explicitly quiescing drain");
  assert.deepEqual(await gate.finishIoAdmission({ scope: abandoned.io.scope,
    admissionId: abandoned.start.admissionId,
    workerId: abandoned.io.workerId, principal }), { status: "FINISHED" });
  assert.equal((await gate.markPending({ scope: abandoned.io.scope,
    operationId, reservationId })).status, "PENDING");
  await assert.rejects(restarted.putCiphertextChunk(abandonWrite, 1, abandoned.chunks[1]),
    /ZK_GATE_UNAVAILABLE|ZK_GATE_DENIED/);
});
