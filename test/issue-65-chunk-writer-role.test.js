"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { verifyZk1ChunkWriterRuntimePool } =
  require("../src/services/zk1SharedPgChunkWriterRuntime");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");

const urls = Object.freeze({
  admin: process.env.ROOTARK_ZK1_TEST_PG_URL,
  gate: process.env.ROOTARK_ZK1_RUNTIME_PG_URL,
  stop: process.env.ROOTARK_ZK1_STOP_PG_URL,
  writer: process.env.ROOTARK_ZK1_WRITER_PG_URL,
});
const enabled = Object.values(urls).every(Boolean);
const random = (length) => crypto.randomBytes(length);
const scopeKey = (scope) => [
  scope.account_id.toString("hex"),
  scope.compartment_id.length.toString(16),
  scope.compartment_id.toString("hex"),
].join(":");

test("independent physical chunk writer cannot forge admission, head or STOP", {
  skip: !enabled && "requires disposable admin/gate/STOP/writer PG logins",
}, async (t) => {
  const pools = Object.fromEntries(Object.entries(urls).map(([name, url]) =>
    [name, new Pool({ connectionString: url, max: 2, connectionTimeoutMillis: 3000 })]));
  t.after(async () => Promise.all(Object.values(pools).map((pool) => pool.end())));
  const verified = await verifyZk1ChunkWriterRuntimePool(pools.writer);
  assert.equal(verified.verified, true);
  for (const forbidden of ["admin", "gate", "stop"]) {
    await assert.rejects(verifyZk1ChunkWriterRuntimePool(pools[forbidden]),
      /ZK_CHUNK_WRITER_RUNTIME_INVALID/,
      forbidden + " must never be delegated as a physical child writer");
  }
  const scope = { account_id: random(16), compartment_id: random(8), keyring_id: random(16) };
  const key = scopeKey(scope);
  const digest = random(32);
  const objectId = random(16).toString("base64url");
  await pools.admin.query("INSERT INTO zk1_gate.head" +
    " (scope_key,keyring_id,revision,digest,require_stop_proof) VALUES($1,$2,1,$3,TRUE)",
  [key, scope.keyring_id, digest]);
  const admission = { scope, workerId: random(16), principal: "AA:".repeat(31) + "AA",
    action: "put", objectId, revision: 1, digest,
    hostKeyId: random(16), processEpoch: random(16), processPid: process.pid };
  const gate = new Zk1SharedPgGateAuthority({ pool: pools.gate });
  const started = await gate.beginIoAdmission(admission);
  assert.equal(started.proceed, true);
  await assert.rejects(pools.writer.query("INSERT INTO zk1_gate.admission" +
    " (id,scope_key,worker_id,principal,action,object_id,revision,digest,generation,state)" +
    " VALUES($1,$2,$3,'forged','put',$4,1,$5,1,'ACTIVE')",
  [random(16), key, random(16), objectId, digest]), /permission|denied|42501/i,
  "writer must not mint ACTIVE permits");
  await assert.rejects(pools.writer.query("UPDATE zk1_gate.head SET phase='QUIESCING' WHERE scope_key=$1",
    [key]), /permission|denied|42501/i,
  "writer must not control GateAuthority phase");
  await assert.rejects(pools.writer.query("INSERT INTO zk1_gate.physical_stop_receipt (admission_id) VALUES($1)",
    [started.admissionId]), /permission|denied|42501/i,
  "writer must not forge STOP proof receipts");
  const write = (index) => pools.writer.query("INSERT INTO zk1_gate.ciphertext_chunk" +
    " (scope_key,object_id,chunk_index,ciphertext) VALUES($1,$2,$3,$4)",
  [key, objectId, index, random(31)]);
  assert.equal((await write(0)).rowCount, 1, "strict child may write while OPEN with a true admission");
  const op = { scope, operationId: random(16), reservationId: random(16),
    revision: 1, digest };
  await gate.beginQuiesce(op);
  await assert.rejects(write(1), /requires current OPEN|phase|23514/i,
    "writer-only login cannot write in revoked generation");
  const rows = await pools.admin.query("SELECT chunk_index FROM zk1_gate.ciphertext_chunk" +
    " WHERE scope_key=$1 AND object_id=$2", [key, objectId]);
  assert.deepEqual(rows.rows.map((row) => row.chunk_index), [0]);
});

test("writer preflight rejects NOINHERIT login with SET ROLE access to the gate", {
  skip: !enabled && "requires disposable PG fixture and independently provisioned logins",
}, async (t) => {
  const admin = new Pool({ connectionString: urls.admin, max: 1,
    connectionTimeoutMillis: 3000 });
  const user = "zkwriterfixture_" + random(6).toString("hex");
  const password = random(24).toString("hex");
  const url = new URL(urls.writer);
  url.username = user;
  url.password = password;
  const extra = new Pool({ connectionString: url.toString(), max: 1,
    connectionTimeoutMillis: 3000 });
  let created = false;
  t.after(async () => {
    await extra.end();
    if (created) {
      // Disposable, randomly provisioned lab-only role; no shared login
      // alterations or production credentials.
      await admin.query("DROP ROLE IF EXISTS " + user);
    }
    await admin.end();
  });
  await admin.query("CREATE ROLE " + user + " LOGIN PASSWORD '" + password + "'");
  created = true;
  await admin.query("GRANT zk1_chunk_writer_runtime TO " + user);
  await admin.query("GRANT zk1_gate_runtime TO " + user + " WITH INHERIT FALSE, SET TRUE");
  const evidence = await extra.query("SELECT "
    + "pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','USAGE') AS inherited, "
    + "pg_catalog.pg_has_role(current_user,'zk1_gate_runtime','SET') AS can_switch");
  assert.equal(evidence.rows[0].inherited, false);
  assert.equal(evidence.rows[0].can_switch, true);
  await assert.rejects(verifyZk1ChunkWriterRuntimePool(extra),
    /ZK_CHUNK_WRITER_RUNTIME_INVALID/,
    "a child must not carry dormant gate privileges obtainable through SET ROLE");
});
