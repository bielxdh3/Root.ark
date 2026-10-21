"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const path = require("node:path");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { Zk1SharedPgStrictStopOperator } = require("../src/services/zk1SharedPgStrictStopOperator");
const { Zk1IsolatedProcessStopSupervisor } = require("../src/services/zk1IsolatedProcessStopSupervisor");
const { createZk1PhysicalStopRecorder } = require("../src/services/zk1SharedPgPhysicalStopRecorder");
const { Zk1LabSupervisedPgWriter } = require("../lab/issue-65-packet-b/supervised-pg-writer-controller");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const gateUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const stopUrl = process.env.ROOTARK_ZK1_STOP_PG_URL;
const enabled = Boolean(adminUrl && gateUrl && stopUrl);
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function scopeKey(scope) {
  return `${hex(scope.account_id)}:${scope.compartment_id.length.toString(16)}:${hex(scope.compartment_id)}`;
}
async function context(t) {
  const admin = new Pool({ connectionString: adminUrl, max: 3, connectionTimeoutMillis: 3000 });
  const runtime = new Pool({ connectionString: gateUrl, max: 3, connectionTimeoutMillis: 3000 });
  const stopPool = new Pool({ connectionString: stopUrl, max: 2, connectionTimeoutMillis: 3000 });
  let supervisor;
  t.after(async () => {
    // Always terminate/observe ChildProcess handles BEFORE closing SQL pools;
    // especially important when an assertion interrupts a held transaction.
    try {
      if (supervisor) {
        const unfinished = [...supervisor.sessions.values()].filter((s) => !s.closed);
        const drained = Promise.all(unfinished.map((s) => new Promise((resolve) =>
          s.child.once("close", resolve))));
        supervisor.dispose();
        let timeout;
        try {
          await Promise.race([drained, new Promise((_, reject) => {
            timeout = setTimeout(() => reject(
              new Error("disposable supervised child close timeout")), 4000);
          })]);
        } finally { clearTimeout(timeout); }
      }
    } finally { await Promise.all([admin.end(), runtime.end(), stopPool.end()]); }
  });
  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(7),
    keyring_id: crypto.randomBytes(16) };
  const digest = crypto.randomBytes(32);
  await admin.query(`INSERT INTO zk1_gate.head
    (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)`,
  [scopeKey(scope), scope.keyring_id, digest]);
  const keys = crypto.generateKeyPairSync("ed25519");
  const hostKeyId = crypto.randomBytes(16);
  supervisor = new Zk1IsolatedProcessStopSupervisor({
    hostKeyId, hostPrivateKey: keys.privateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/supervised-pg-writer-child.js"),
    stopTimeoutMs: 5000,
  });
  const gate = new Zk1SharedPgGateAuthority({ pool: runtime,
    stopPinned: { hostKeyId, hostPublicKey: keys.publicKey } });
  const recorder = await createZk1PhysicalStopRecorder({ pool: stopPool,
    trustedHostKeyId: hostKeyId, trustedHostPublicKey: keys.publicKey });
  const operator = new Zk1SharedPgStrictStopOperator({ gate, supervisor, recorder });
  const lab = new Zk1LabSupervisedPgWriter({ operator, runtimePgUrl: gateUrl });
  const io = { scope, workerId: crypto.randomBytes(16),
    principal: "AB:".repeat(31) + "AB", action: "put",
    objectId: crypto.randomBytes(16).toString("base64url"), revision: 1, digest };
  return { admin, runtime, scope, digest, io, gate, operator, supervisor, lab };
}
function quiesce(c) {
  return { scope: c.scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest: c.digest };
}

test("real supervisor-owned CHILD commits physical ciphertext; gate quiesce cannot overtake held PG INSERT", {
  skip: !enabled && "requires isolated disposable PG18 gate/STOP credentials",
}, async (t) => {
  const c = await context(t);
  assert.throws(() => new Zk1LabSupervisedPgWriter({ operator: c.operator,
    runtimePgUrl: adminUrl }), /ZK_LAB_PG_WRITER_DENIED/,
  "superuser/ordinary application SQL login cannot be supplied to the writer");
  await assert.rejects(c.lab.begin({ ...c.io, processPid: 42 }), /ZK_LAB_PG_WRITER_DENIED/,
    "neither a PID nor a host identity can be supplied in the operator request");
  const { admitted, child, bootstrap } = await c.lab.begin(c.io);
  assert.equal(admitted.proceed, true);
  assert.deepEqual(bootstrap, { restrictedRoleVerified: true, inheritedSecrets: false },
    "child receives only separately authorized gate credentials via local IPC, no inherited key/env");
  const payload = crypto.randomBytes(128);
  await c.lab.holdChunk(0, payload);
  await assert.rejects(c.lab.holdChunk(1, Buffer.from("queued-effect")),
    /ZK_LAB_PG_WRITER_DENIED/,
  "untrusted parallel/queued IPC must not race a held physical transaction");
  await assert.rejects(c.lab.holdChunk(-1, payload), /ZK_LAB_PG_WRITER_DENIED/);
  const observed = await c.admin.query(`SELECT pid,state,query FROM pg_stat_activity
    WHERE datname=current_database() AND query LIKE '%INSERT INTO zk1_gate.ciphertext_chunk%'`);
  assert.ok(observed.rows.length >= 1, "a physical INSERT executes in child-owned PG session");
  const op = quiesce(c);
  let closed = false;
  const pending = c.gate.beginQuiesce(op).then((receipt) => { closed = true; return receipt; });
  await sleep(120);
  assert.equal(closed, false, "HEAD FOR UPDATE is held across child physical INSERT");
  assert.deepEqual(await c.lab.releaseChunk(), { stored: true });
  assert.equal((await pending).state, "QUIESCING");
  const chunks = await c.admin.query(`SELECT ciphertext FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1 AND object_id=$2 ORDER BY chunk_index`, [scopeKey(c.scope), c.io.objectId]);
  assert.equal(chunks.rowCount, 1);
  assert.deepEqual(chunks.rows[0].ciphertext, payload);
  await assert.rejects(c.lab.holdChunk(1, Buffer.from("late")), /ZK_LAB_PG_WRITER_DENIED/);
  await assert.rejects(c.lab.releaseChunk(), /ZK_LAB_PG_WRITER_DENIED/);
  const finished = await c.lab.stop();
  assert.equal(finished.status, "FINISHED");
  assert.equal(child.connected, false, "signed STOP follows the actual writer child kernel close");
  const receipt = await c.admin.query(`SELECT signed_proof FROM zk1_gate.physical_stop_receipt
    WHERE admission_id=$1`, [admitted.admissionId]);
  assert.equal(receipt.rowCount, 1, "independently signed STOP persisted under distinct SQL role");
  assert.equal((await c.gate.markPending(op)).status, "PENDING");
});

test("SIGKILL of child with uncommitted real PG transaction rolls back bytes and signed STOP permits drain", {
  skip: !enabled && "requires isolated disposable PG18 gate/STOP credentials",
}, async (t) => {
  const c = await context(t);
  const { admitted, child } = await c.lab.begin(c.io);
  await c.lab.holdChunk(0, crypto.randomBytes(120));
  const op = quiesce(c);
  let closed = false;
  const pending = c.gate.beginQuiesce(op).then((receipt) => { closed = true; return receipt; });
  await sleep(100);
  assert.equal(closed, false);
  const actual = c.lab.session;
  const completed = new Promise((resolve) => actual.child.once("close", resolve));
  assert.equal(actual.child.kill("SIGKILL"), true);
  await completed;
  assert.equal((await pending).state, "QUIESCING", "rollback releases held HEAD row lock");
  const physical = await c.admin.query(`SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk
    WHERE scope_key=$1`, [scopeKey(c.scope)]);
  assert.equal(physical.rows[0].n, 0, "uncommitted child INSERT is genuinely rolled back");
  await assert.rejects(c.lab.releaseChunk(), /ZK_LAB_PG_WRITER_DENIED/);
  await assert.rejects(c.lab.holdChunk(1, Buffer.from("late")), /ZK_LAB_PG_WRITER_DENIED/);
  await assert.rejects(c.lab.begin(c.io), /ZK_LAB_PG_WRITER_DENIED/,
    "stale terminated operator session cannot be replayed");
  const restartedSupervisor = new Zk1IsolatedProcessStopSupervisor({
    hostKeyId: c.supervisor.hostKeyId,
    hostPrivateKey: c.supervisor.hostPrivateKey,
    workerScript: path.resolve(__dirname, "../lab/issue-65-packet-b/supervised-pg-writer-child.js"),
  });
  await assert.rejects(restartedSupervisor.stop({
    processEpoch: c.lab.entry.process.processEpoch,
  }), /ZK_STOP_SUPERVISOR_UNAVAILABLE/,
  "after supervisor restart an absent OS handle cannot be forged into STOP evidence");
  assert.equal((await c.lab.stop()).status, "FINISHED");
  const receipt = await c.admin.query(`SELECT admission_id FROM zk1_gate.physical_stop_receipt
    WHERE admission_id=$1`, [admitted.admissionId]);
  assert.equal(receipt.rowCount, 1);
  assert.equal((await c.gate.markPending(op)).status, "PENDING");
  assert.equal(child.connected, false);
});
