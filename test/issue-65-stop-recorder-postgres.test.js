"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { createZk1PhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1IsolatedProcessStopSupervisor } =
  require("../src/services/zk1IsolatedProcessStopSupervisor");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const runtimeUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const stopUrl = process.env.ROOTARK_ZK1_STOP_PG_URL;

test("independent restricted STOP authority is required for strict PG physical-worker drain", {
  skip: !adminUrl || !runtimeUrl || !stopUrl
    ? "requires disposable PostgreSQL with isolated gate and stop logins" : false,
}, async (t) => {
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const gatePool = new Pool({ connectionString: runtimeUrl, max: 2, connectionTimeoutMillis: 3000 });
  const stopPool = new Pool({ connectionString: stopUrl, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), gatePool.end(), stopPool.end()]));
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(7),
    keyring_id: crypto.randomBytes(16) };
  const scopedKey = `${scope.account_id.toString("hex")}:`
    + `${scope.compartment_id.length.toString(16)}:${scope.compartment_id.toString("hex")}`;
  const digest = crypto.randomBytes(32);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof)
    VALUES($1,$2,1,$3,TRUE)`, [scopedKey, scope.keyring_id, digest]);
  const hostKeys = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool,
    stopPinned: { hostKeyId, hostPublicKey: hostKeys.publicKey } });
  const supervisor = new Zk1IsolatedProcessStopSupervisor({
    hostKeyId, hostPrivateKey: hostKeys.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/stop-child-worker.js"),
    nowSeconds: () => 900 });
  t.after(() => supervisor.dispose());
  const worker = { scope, workerId: crypto.randomBytes(16),
    principal: "AA:".repeat(31) + "AA", action: "put",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 1, digest };
  const process = supervisor.launch(worker);
  worker.hostKeyId = process.hostKeyId;
  worker.processEpoch = process.processEpoch;
  worker.processPid = process.processPid;
  const admitted = await gate.beginIoAdmission(worker);
  await assert.rejects(gate.beginIoAdmission({ ...worker,
    processEpoch: crypto.randomBytes(16) }), /ZK_GATE_DENIED/,
  "an existing strict admission cannot be replayed under a different OS process epoch");
  await assert.rejects(gate.beginIoAdmission({ ...worker,
    processPid: worker.processPid + 1 }), /ZK_GATE_DENIED/,
  "a PID substitution cannot hijack the same worker/admission identity");
  supervisor.bindAdmission({ scope, workerId: worker.workerId,
    principal: worker.principal, processEpoch: process.processEpoch,
    processPid: process.processPid, admissionId: admitted.admissionId,
    generation: admitted.generation });
  const op = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  assert.equal((await gate.beginQuiesce(op)).activeCount, 1);
  await assert.rejects(gate.finishIoAdmission({ scope,
    admissionId: admitted.admissionId,
    workerId: worker.workerId, principal: worker.principal }),
  /ZK_GATE_UNAVAILABLE|ZK_GATE_STOP_PROOF_INVALID/);

  // Only this isolated host supervisor owns the process handle and signer.
  // A raw PG STOP row cannot be treated as an OS exit receipt.
  const signedProof = await supervisor.stop({ processEpoch: process.processEpoch });
  assert.equal(supervisor.sessions.get(process.processEpoch.toString("hex")).closed, true);
  assert.equal(supervisor.sessions.get(process.processEpoch.toString("hex")).exited, true);
  const forgedInsert = [admitted.admissionId, scopedKey, worker.workerId,
    admitted.generation, hostKeyId, process.processEpoch, process.processPid, 900,
    crypto.createHash("sha256").update(signedProof).digest(), signedProof];
  await assert.rejects(stopPool.query(`INSERT INTO zk1_gate.physical_stop_receipt
    (admission_id,scope_key,worker_id,generation,host_key_id,process_epoch,
      process_pid,stopped_at,proof_digest,signed_proof)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, [
    ...forgedInsert.slice(0, 5), crypto.randomBytes(16),
    ...forgedInsert.slice(6),
  ]), /STOP receipt|admission|identity|proof/i,
  "even the trusted STOP role cannot rebind a registered worker epoch directly");
  await assert.rejects(gatePool.query(`INSERT INTO zk1_gate.physical_stop_receipt
    (admission_id,scope_key,worker_id,generation,host_key_id,process_epoch,
      process_pid,stopped_at,proof_digest,signed_proof)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, forgedInsert),
  /permission denied/i,
  "a compromised gate SQL login cannot manufacture independent STOP evidence");
  await assert.rejects(createZk1PhysicalStopRecorder({ pool: gatePool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: hostKeys.publicKey,
    nowSeconds: () => 900 }), /ZK_STOP_RUNTIME_INVALID/,
  "the trusted stop service cannot reuse the data-plane SQL credentials");

  const recorder = await createZk1PhysicalStopRecorder({ pool: stopPool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: hostKeys.publicKey,
    nowSeconds: () => 900 });
  const expected = { scope, admissionId: admitted.admissionId, workerId: worker.workerId,
    generation: admitted.generation, principal: worker.principal,
    processEpoch: process.processEpoch, processPid: process.processPid };
  const first = await recorder.record({ signedProof, expected });
  assert.equal(first.status, "STOP_ATTESTED");
  assert.deepEqual(await recorder.record({ signedProof, expected }), first,
    "a lost STOP ACK replays the exact immutable proof, not a new worker");
  await assert.rejects(recorder.record({ signedProof, expected: { ...expected,
    processEpoch: crypto.randomBytes(16) } }), /ZK_STOP_(PROOF_INVALID|LEDGER_UNAVAILABLE)/);
  await assert.rejects(stopPool.query(`UPDATE zk1_gate.head SET stop_lock=stop_lock
    WHERE scope_key=$1`, [scopedKey]), /immutable|transition|permission|illegal/i,
  "a separate STOP principal with nominal row-lock privilege cannot mutate the authoritative gate");
  await gate.finishIoAdmission({ scope, admissionId: admitted.admissionId,
    workerId: worker.workerId, principal: worker.principal });
  assert.equal((await gate.markPending({ scope, operationId: op.operationId,
    reservationId: op.reservationId })).status, "PENDING");
  assert.deepEqual(await recorder.record({ signedProof, expected }), first,
    "a lost STOP reply remains idempotently recoverable after PENDING without changing the gate");
  const row = await admin.query(`SELECT signed_proof,proof_digest
    FROM zk1_gate.physical_stop_receipt WHERE admission_id=$1`, [admitted.admissionId]);
  assert.equal(row.rowCount, 1);
  assert.deepEqual(row.rows[0].signed_proof, signedProof);
  assert.deepEqual(row.rows[0].proof_digest,
    crypto.createHash("sha256").update(signedProof).digest());
});

test("gate runtime re-verifies STOP host signature, not only a forged independent SQL row", {
  skip: !adminUrl || !runtimeUrl || !stopUrl
    ? "requires disposable PG with independently provisioned gate and stop logins" : false,
}, async (t) => {
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const gatePool = new Pool({ connectionString: runtimeUrl, max: 2, connectionTimeoutMillis: 3000 });
  const stopPool = new Pool({ connectionString: stopUrl, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), gatePool.end(), stopPool.end()]));
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(6),
    keyring_id: crypto.randomBytes(16) };
  const scopeKey = `${scope.account_id.toString("hex")}:`
    + `${scope.compartment_id.length.toString(16)}:${scope.compartment_id.toString("hex")}`;
  const digest = crypto.randomBytes(32);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)`,
  [scopeKey, scope.keyring_id, digest]);
  const signer = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  const gate = new Zk1SharedPgGateAuthority({ pool: gatePool,
    stopPinned: { hostKeyId, hostPublicKey: signer.publicKey } });
  const worker = { scope, workerId: crypto.randomBytes(16),
    principal: "AA:".repeat(31) + "AA", action: "put",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 1, digest,
    hostKeyId, processEpoch: crypto.randomBytes(16), processPid: 32101 };
  const admission = await gate.beginIoAdmission(worker);
  const operationId = crypto.randomBytes(16);
  const reservationId = crypto.randomBytes(16);
  await gate.beginQuiesce({ scope, operationId,
    reservationId, revision: 1, digest });
  const unsignedNoise = crypto.randomBytes(160);
  await stopPool.query(`INSERT INTO zk1_gate.physical_stop_receipt
    (admission_id,scope_key,worker_id,generation,host_key_id,process_epoch,
      process_pid,stopped_at,proof_digest,signed_proof)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
  [admission.admissionId, scopeKey, worker.workerId, admission.generation,
    hostKeyId, worker.processEpoch, worker.processPid, 900,
    crypto.createHash("sha256").update(unsignedNoise).digest(), unsignedNoise]);
  await assert.rejects(gate.finishIoAdmission({ scope,
    admissionId: admission.admissionId, workerId: worker.workerId,
    principal: worker.principal }), /ZK_GATE_(STOP_PROOF_INVALID|UNAVAILABLE|DENIED)/,
  "the trusted gate process must not complete an OS worker from forged SQL STOP evidence");
  const actual = await admin.query("SELECT state FROM zk1_gate.admission WHERE id=$1",
    [admission.admissionId]);
  assert.equal(actual.rows[0].state, "STOP_REQUESTED");
  // Even if BOTH independent SQL credentials are compromised and the gate
  // credential sets FINISHED directly (bypassing its JS verifier), the honest
  // GateAuthority method must still refuse to issue a PENDING receipt.
  // The database itself cannot stop direct PENDING SQL with those two roles;
  // that residual collusion risk is an explicit non-production limitation.
  await gatePool.query("UPDATE zk1_gate.admission SET state='FINISHED' WHERE id=$1",
    [admission.admissionId]);
  await assert.rejects(gate.markPending({ scope, operationId, reservationId }),
    /ZK_GATE_STOP_PROOF_INVALID/,
  "a caller may not get a trusted PENDING result from fake STOP bytes");
  const head = await admin.query("SELECT phase FROM zk1_gate.head WHERE scope_key=$1", [scopeKey]);
  assert.equal(head.rows[0].phase, "QUIESCING");
});
