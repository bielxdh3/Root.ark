"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { Zk1SharedPgGateAuthority } = require("../src/services/zk1SharedPgGateAuthority");
const { verifyZk1SharedPgRuntimePool,
  createIsolatedZk1SharedPgGateServer } = require("../src/services/zk1SharedPgGateRuntime");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const gateUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;

test("real dedicated PG login uses shared gate without superuser privileges or direct destructive SQL", {
  skip: !adminUrl || !gateUrl ? "requires disposable privileged and restricted PostgreSQL URLs" : false,
}, async (t) => {
  const admin = new Pool({ connectionString: adminUrl, max: 2, connectionTimeoutMillis: 3000 });
  const restricted = new Pool({ connectionString: gateUrl, max: 2, connectionTimeoutMillis: 3000 });
  t.after(async () => Promise.all([admin.end(), restricted.end()]));
  await assert.rejects(verifyZk1SharedPgRuntimePool(admin),
    /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
  "standalone server must fail closed on a privileged database superuser");
  await assert.rejects(createIsolatedZk1SharedPgGateServer({ pool: admin }),
    /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
  "no listener may be created when database identity is privileged");
  // A PostgreSQL connection can shadow unqualified pg_roles with a TEMP
  // relation; startup checks must consult pg_catalog, never a session path.
  const shadowed = new Pool({ connectionString: adminUrl, max: 1, connectionTimeoutMillis: 3000 });
  t.after(async () => shadowed.end());
  const forged = await shadowed.connect();
  try {
    await forged.query("CREATE TEMP TABLE pg_roles AS SELECT * FROM pg_catalog.pg_roles WHERE rolname=current_user");
    await forged.query("UPDATE pg_roles SET rolsuper=false, rolcreatedb=false, rolcreaterole=false");
    await forged.query("SET search_path=pg_temp,public,pg_catalog");
  } finally { forged.release(); }
  await assert.rejects(verifyZk1SharedPgRuntimePool(shadowed),
    /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
  "forged pg_temp.pg_roles must not make a superuser appear to be a trusted gate runtime");
  const identity = await verifyZk1SharedPgRuntimePool(restricted);
  assert.equal(identity.verified, true);
  assert.match(identity.runtimeRole, /^zkgatefixture_[0-9a-f]{12}$/);

  const scope = { account_id: crypto.randomBytes(16), compartment_id: crypto.randomBytes(7),
    keyring_id: crypto.randomBytes(16) };
  const key = scope.account_id.toString("hex") + ":"
    + scope.compartment_id.length.toString(16) + ":"
    + scope.compartment_id.toString("hex");
  const digest = crypto.randomBytes(32);
  await admin.query("INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest) VALUES($1,$2,1,$3)",
    [key, scope.keyring_id, digest]);
  const gate = new Zk1SharedPgGateAuthority({ pool: restricted });
  const io = { scope, workerId: crypto.randomBytes(16), principal: "gate-test-client",
    action: "put", objectId: crypto.randomBytes(16).toString("base64url"),
    revision: 1, digest };
  const allowed = await gate.beginIoAdmission(io);
  assert.equal(allowed.proceed, true);
  const ciphertext = crypto.randomBytes(200);
  assert.deepEqual(await gate.putCiphertextChunk({ ...io,
    admissionId: allowed.admissionId, generation: allowed.generation }, 0, ciphertext),
  { stored: true });
  const operation = { scope, operationId: crypto.randomBytes(16),
    reservationId: crypto.randomBytes(16), revision: 1, digest };
  assert.equal((await gate.beginQuiesce(operation)).state, "QUIESCING");
  await gate.finishIoAdmission({ scope, admissionId: allowed.admissionId,
    workerId: io.workerId, principal: io.principal });
  assert.equal((await gate.markPending({ scope,
    operationId: operation.operationId, reservationId: operation.reservationId })).status, "PENDING");
  const saved = await admin.query("SELECT ciphertext FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1",
    [key]);
  assert.equal(saved.rowCount, 1);
  assert.deepEqual(saved.rows[0].ciphertext, ciphertext);
  await assert.rejects(restricted.query("UPDATE zk1_gate.head SET revision=2 WHERE scope_key=$1", [key]),
    /permission denied/i);
  await assert.rejects(restricted.query("DELETE FROM zk1_gate.ciphertext_chunk WHERE scope_key=$1", [key]),
    /permission denied/i);
});
