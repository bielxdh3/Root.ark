"use strict";

const { runDisposablePgLab } = require("./disposable-postgres");

runDisposablePgLab("gate", async (fixture) => {
  const sql = fixture.readLabSql("db/zk1-gate-authority.sql");
  fixture.sql(sql);
  // Reproduce a legacy per-column writer ACL and prove that the current
  // operator migration revokes it. Table REVOKE alone is insufficient.
  fixture.sql("GRANT INSERT(scope_key,object_id,chunk_index,ciphertext) ON "
    + "zk1_gate.ciphertext_chunk TO zk1_chunk_writer_runtime;\n"
    + "GRANT SELECT(chunk_index) ON zk1_gate.ciphertext_chunk TO zk1_chunk_writer_runtime;\n");
  const probe = () => fixture.sql("SELECT "
    + "pg_catalog.has_column_privilege('zk1_chunk_writer_runtime',"
    + "'zk1_gate.ciphertext_chunk','scope_key','INSERT'),"
    + "pg_catalog.has_column_privilege('zk1_chunk_writer_runtime',"
    + "'zk1_gate.ciphertext_chunk','chunk_index','SELECT');");
  if (!/t\s*\|\s*t/.test(probe())) throw Error("ZK65_LEGACY_ACL_NOT_REPRODUCED");
  fixture.sql(sql);
  if (!/f\s*\|\s*f/.test(probe())) throw Error("ZK65_LEGACY_ACL_NOT_REVOKED");
  const runtimeUrl = fixture.provision("zkgatefixture_", "zk1_gate_runtime");
  const result = fixture.runTestsNoSkip([
    "test/issue-65-gate-runtime-role.test.js",
    "test/issue-65-pg-sealed-sink.test.js",
    "test/issue-65-shared-pg-sealed-object.test.js",
  ], { ROOTARK_ZK1_TEST_PG_URL: fixture.adminUrl,
    ROOTARK_ZK1_RUNTIME_PG_URL: runtimeUrl }, 150000);
  process.stdout.write("ZK65_SHARED_GATE_PG18_PASS files=" + result.files
    + " tests=" + result.tests + " skipped=0\n");
}).catch((error) => {
  process.stderr.write("ZK65_SHARED_GATE_FAILED: " + error.message + "\n");
  process.exitCode = 1;
});
