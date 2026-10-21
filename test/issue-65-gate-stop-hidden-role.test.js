"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");
const { verifyZk1SharedPgRuntimePool } = require("../src/services/zk1SharedPgGateRuntime");
const { verifyZk1StopRuntimePool } = require("../src/services/zk1SharedPgPhysicalStopRecorder");

const adminUrl = process.env.ROOTARK_ZK1_TEST_PG_URL;
const gateUrl = process.env.ROOTARK_ZK1_RUNTIME_PG_URL;
const stopUrl = process.env.ROOTARK_ZK1_STOP_PG_URL;
const skip = !adminUrl || !gateUrl || !stopUrl
  ? "requires disposable PostgreSQL admin and independently restricted gate/STOP logins" : false;

async function hiddenRoleFixture(t, primaryRole, dormantRole) {
  const adminAddress = new URL(adminUrl);
  if (adminAddress.hostname !== "127.0.0.1" || adminAddress.pathname !== "/gatefixture"
    || adminAddress.protocol !== "postgresql:") throw new Error("NON_DISPOSABLE_FIXTURE_DENIED");
  const name = "zkhiddenfixture_" + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  const database = new Pool({ connectionString: adminUrl, max: 1, connectionTimeoutMillis: 3000 });
  const connectedAddress = new URL(adminUrl);
  connectedAddress.username = name;
  connectedAddress.password = password;
  const hidden = new Pool({ connectionString: connectedAddress.toString(),
    max: 1, connectionTimeoutMillis: 3000 });
  let created = false;
  t.after(async () => {
    await hidden.end();
    try {
      if (created) await database.query("DROP ROLE " + name);
    } finally { await database.end(); }
  });
  await database.query("CREATE ROLE " + name + " LOGIN PASSWORD '" + password + "'");
  created = true;
  await database.query("GRANT " + primaryRole + " TO " + name);
  await database.query("GRANT " + dormantRole + " TO " + name + " WITH INHERIT FALSE, SET TRUE");
  const result = await hidden.query(
    "SELECT pg_catalog.pg_has_role(current_user,$1,'USAGE') AS inherited," +
    " pg_catalog.pg_has_role(current_user,$1,'MEMBER') AS member," +
    " pg_catalog.pg_has_role(current_user,$1,'SET') AS can_set",
    [dormantRole]);
  assert.deepEqual(result.rows[0],
    { inherited: false, member: true, can_set: true },
    "a dormant SQL membership is not visible to the old USAGE-only preflight");
  return hidden;
}

test("gate preflight rejects STOP capability hidden behind NOINHERIT/SET ROLE", {
  skip,
}, async (t) => {
  const gate = await hiddenRoleFixture(t, "zk1_gate_runtime", "zk1_stop_runtime");
  await assert.rejects(verifyZk1SharedPgRuntimePool(gate),
    /ZK_GATE_RUNTIME_IDENTITY_INVALID/,
    "controller login cannot also switch to independent STOP authority");
  const switched = await gate.query("SET ROLE zk1_stop_runtime");
  assert.equal(switched.command, "SET");
  assert.equal((await gate.query("SELECT current_user AS role")).rows[0].role,
    "zk1_stop_runtime", "dormant privilege is actually exploitable without a preflight check");
  await gate.query("RESET ROLE");
});

test("STOP preflight rejects dormant GateAuthority capabilities behind NOINHERIT/SET ROLE", {
  skip,
}, async (t) => {
  const stop = await hiddenRoleFixture(t, "zk1_stop_runtime", "zk1_gate_runtime");
  await assert.rejects(verifyZk1StopRuntimePool(stop),
    /ZK_STOP_RUNTIME_INVALID/,
    "STOP recorder login cannot switch to independently trusted gate-controller role");
  await stop.query("SET ROLE zk1_gate_runtime");
  assert.equal((await stop.query("SELECT current_user AS role")).rows[0].role,
    "zk1_gate_runtime", "STOP recorder had real dormant power to mint admissions");
  await stop.query("RESET ROLE");
});
