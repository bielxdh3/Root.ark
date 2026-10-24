"use strict";

// Direct restricted-role writes must obey the same durable physical fence as
// the trusted gate adapter; a missing SEALED marker is not an OPEN permit.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const runtimeUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const skip = !adminUrl || !runtimeUrl
  ? "requires independent disposable admin and restricted gate PostgreSQL roles" : false;
const random = (n) => crypto.randomBytes(n);
const scopeKey = (s) => [
  s.account_id.toString("hex"),
  s.compartment_id.length.toString(16),
  s.compartment_id.toString("hex"),
].join(":");

test("restricted PostgreSQL raw chunk INSERT cannot outlive OPEN or an ACTIVE admission", {
  skip,
}, async (t) => {
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const restricted = new Pool({ connectionString: runtimeUrl, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), restricted.end()]));
  const gate = new Zk1SharedPgGateAuthority({ pool: restricted });
  const scope = { account_id: random(16), compartment_id: random(8), keyring_id: random(16) };
  const objectId = random(16).toString("base64url");
  const digest = random(32);
  const key = scopeKey(scope);
  await admin.query("INSERT INTO zk1_gate.head (scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key, scope.keyring_id, digest]);
  const rawInsert = (index) => restricted.query(
    "INSERT INTO zk1_gate.ciphertext_chunk(scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,$3,$4)",
    [key, objectId, index, random(32)]);
  await assert.rejects(rawInsert(0), /active admission|requires current OPEN|denied|23514/i,
    "raw SQL has no admission and cannot write even while OPEN");
  const io = { scope, objectId, workerId: random(16), principal: "restricted-sql-fixture",
    action: "put", revision: 1, digest };
  const started = await gate.beginIoAdmission(io);
  assert.equal(started.proceed, true);
  assert.equal((await rawInsert(0)).rowCount, 1, "live admission permits staging while OPEN");
  const op = { scope, operationId: random(16), reservationId: random(16), revision: 1, digest };
  assert.equal((await gate.beginQuiesce(op)).state, "QUIESCING");
  await assert.rejects(rawInsert(1), /requires current OPEN|phase|23514/i,
    "a restricted SQL credential cannot append an UNSEALED chunk after QUIESCING");
  await gate.finishIoAdmission({ scope, admissionId: started.admissionId,
    workerId: io.workerId, principal: io.principal });
  assert.equal((await gate.markPending({ scope,
    operationId: op.operationId, reservationId: op.reservationId })).status, "PENDING");
  await assert.rejects(rawInsert(2), /requires current OPEN|phase|23514/i,
    "an object without SEALED marker is still fenced after PENDING");
  const rows = await admin.query("SELECT chunk_index FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1 ORDER BY chunk_index",
    [key]);
  assert.deepEqual(rows.rows.map((r) => r.chunk_index), [0]);
});

test("raw SQL INSERT racing with quiesce is ordered and never commits late bytes", {
  skip,
}, async (t) => {
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const runtime = new Pool({ connectionString: runtimeUrl, max: 3, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), runtime.end()]));
  const gate = new Zk1SharedPgGateAuthority({ pool: runtime });
  const scope = { account_id: random(16), compartment_id: random(7), keyring_id: random(16) };
  const digest = random(32);
  const key = scopeKey(scope);
  const objectId = random(16).toString("base64url");
  await admin.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key, scope.keyring_id, digest]);
  const io = { scope, objectId, workerId: random(16), principal: "restrict-lock-lab",
    action: "put", revision: 1, digest };
  await gate.beginIoAdmission(io);
  // Locking the head forces quiesce to complete before the late direct INSERT
  // evaluates the authoritative OPEN predicate (not just a stale JS check).
  const blocker = await admin.connect();
  const op = { scope, operationId: random(16), reservationId: random(16), revision: 1, digest };
  let quiescing;
  let lateInsert;
  try {
    await blocker.query("BEGIN");
    await blocker.query("SELECT scope_key FROM zk1_gate.head WHERE scope_key=$1 FOR UPDATE", [key]);
    const blockerPid = (await blocker.query("SELECT pg_backend_pid() AS pid")).rows[0].pid;
    quiescing = gate.beginQuiesce(op);
    // Observe actual PostgreSQL lock contention before queuing the attacker.
    let blocked = false;
    for (let i = 0; i < 50; ++i) {
      const seen = await admin.query(
        "SELECT COUNT(*)::int AS n FROM pg_stat_activity WHERE pid<>$1 AND $1=ANY(pg_blocking_pids(pid))",
        [blockerPid]);
      if (seen.rows[0].n > 0) { blocked = true; break; }
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    assert.equal(blocked, true, "QUIESCE transaction must be waiting on the head lock");
    // Start the raw INSERT before QUIESCE commits. The head lock must order
    // the real DB transactions and reject the late physical effect.
    lateInsert = runtime.query(
      "INSERT INTO zk1_gate.ciphertext_chunk(scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,0,$3)",
      [key, objectId, random(17)]).then(() => ({ accepted: true }),
      (error) => ({ accepted: false, error }));
    await blocker.query("COMMIT");
  } finally {
    try { await blocker.query("ROLLBACK"); } catch (_) { /* disposable */ }
    blocker.release();
  }
  assert.equal((await quiescing).state, "QUIESCING");
  const late = await lateInsert;
  assert.equal(late.accepted, false, "physical INSERT queued after QUIESCE must not commit");
  assert.match(String(late.error?.message), /requires current OPEN|phase|23514/i);
  assert.equal((await admin.query("SELECT COUNT(*)::int AS n FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1",
    [key])).rows[0].n, 0);
});
