"use strict";

// This runs only against the disposable PG18 --wal-flush-only lab. Delay the
// background WAL writer so that a committed asynchronous write is still only
// in WAL buffers when the distinct read-only attestor invokes its fence.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { Pool } = require("pg");

test("operator WAL flush fence explicitly persists async commits before claiming durability", {
  skip: !process.env.ROOTARK_ZK1_TEST_PG_URL
    || !process.env.ROOTARK_ZK1_ATTESTOR_PG_URL,
}, async (t) => {
  const admin = new Pool({ connectionString: process.env.ROOTARK_ZK1_TEST_PG_URL });
  const attestor = new Pool({ connectionString: process.env.ROOTARK_ZK1_ATTESTOR_PG_URL });
  t.after(async () => {
    try {
      await admin.query("ALTER SYSTEM RESET wal_writer_delay");
      await admin.query("SELECT pg_reload_conf()");
    } finally { await Promise.all([attestor.end(), admin.end()]); }
  });
  assert.match((await admin.query("SHOW server_version")).rows[0].server_version, /^18\./);
  assert.equal((await admin.query("SHOW fsync")).rows[0].fsync, "on");
  await admin.query("ALTER SYSTEM SET wal_writer_delay = '10s'");
  await admin.query("SELECT pg_reload_conf()");
  assert.equal((await admin.query("SHOW wal_writer_delay")).rows[0].wal_writer_delay, "10s");

  let lag = 0;
  for (let attempt = 0; attempt < 8 && lag <= 0; attempt += 1) {
    const writer = await admin.connect();
    try {
      await writer.query("BEGIN");
      await writer.query("SET LOCAL synchronous_commit = off");
      await writer.query(`INSERT INTO zk1_gate.head(scope_key,keyring_id,revision,digest)
        VALUES($1,$2,1,$3)`, [crypto.randomBytes(16).toString("hex") + ":0:",
        crypto.randomBytes(16), crypto.randomBytes(32)]);
      await writer.query("COMMIT");
    } finally { writer.release(); }
    lag = Number((await attestor.query(`SELECT pg_catalog.pg_wal_lsn_diff(
      pg_catalog.pg_current_wal_insert_lsn(),
      pg_catalog.pg_current_wal_flush_lsn()) AS lag`)).rows[0].lag);
  }
  assert.ok(lag > 0, "test must establish real unflushed WAL before the barrier");

  const reader = await attestor.connect();
  try {
    await reader.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
    await reader.query("SET LOCAL statement_timeout = '8000ms'");
    const barrier = await reader.query(
      "SELECT zk1_gate.physical_inventory_wal_flush_barrier() AS flushed");
    assert.equal(barrier.rows[0]?.flushed, true,
      "the attestor cannot assert durable WAL until the server flushes it");
    const gap = await reader.query(`SELECT pg_catalog.pg_wal_lsn_diff(
      pg_catalog.pg_current_wal_insert_lsn(),
      pg_catalog.pg_current_wal_flush_lsn()) AS gap`);
    assert.ok(Number(gap.rows[0].gap) <= 0,
      "the true result must have physically flushed the pre-barrier WAL target");
    await reader.query("COMMIT");
  } finally { reader.release(); }
});
