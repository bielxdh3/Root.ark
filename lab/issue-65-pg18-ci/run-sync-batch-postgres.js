"use strict";

// Separate opt-in real PG18 lab; do not alter shared gate/replay test allowlists.
// Disposable PostgreSQL image/cleanup and no ambient DB credentials are reused.
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { runDisposablePgLab } = require("./disposable-postgres");
const { checkCompleteTap } = require("./no-skip-tap");

runDisposablePgLab("gate", async (fixture) => {
  const project = path.resolve(__dirname, "../..");
  fixture.sql(fs.readFileSync(path.join(project, "db/zk1-sync-pg-atomic-batch.sql"), "utf8"));
  fixture.sql(fs.readFileSync(path.join(project,
    "db/zk1-sync-pg-atomic-batch-admission.sql"), "utf8"));
  const roleSql = fs.readFileSync(path.join(project,
    "db/zk1-sync-pg-atomic-batch-roles.sql"), "utf8");
  fixture.sql(roleSql);
  // Reproduce a formerly exploitable PostgreSQL column-level grant. Plain
  // table REVOKE leaves column ACLs behind; reapplying operator grants must
  // remove these explicitly, including on the protected commit marker.
  fixture.sql(`GRANT UPDATE(head) ON zk1_sync_batch.scope_head
    TO zk1_sync_batch_runtime;
    GRANT INSERT(scope,sequence,commit_id) ON zk1_sync_batch.batch_commit
    TO zk1_sync_batch_runtime;
    GRANT UPDATE(ciphertext) ON zk1_sync_batch.object_state
    TO zk1_sync_batch_attestor_reader;`);
  fixture.sql(roleSql);
  // Disjoint logins/credentials, in one throwaway cluster. No role membership
  // path from runtime or reader to the privileged trusted verifier.
  const runtimeUrl = fixture.provision("zkbatchruntime_", "zk1_sync_batch_runtime");
  const verifierUrl = fixture.provision("zkbatchverify_", "zk1_sync_batch_verifier");
  const attestorUrl = fixture.provision("zkbatchreader_", "zk1_sync_batch_attestor_reader");
  const issuerUrl = fixture.provision("zkbatchissuer_", "zk1_sync_batch_admission_issuer");
  const file = "lab/issue-65-pg18-ci/sync-batch-pg18.integration.cjs";
  const cleaned = Object.fromEntries(Object.entries(process.env).filter(([k]) =>
    !/^PG[A-Z_]+$/.test(k) && !/^ROOTARK_ZK1_.*_PG_URL$/.test(k)
    && !["DATABASE_URL", "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED"].includes(k)));
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", file], {
    cwd: project, encoding: "utf8", windowsHide: true, timeout: 150000,
    env: { ...cleaned, ROOTARK_ZK1_TEST_PG_URL: fixture.adminUrl,
      ROOTARK_ZK1_RUNTIME_PG_URL: runtimeUrl,
      ROOTARK_ZK1_VERIFIER_PG_URL: verifierUrl,
      ROOTARK_ZK1_ATTESTOR_PG_URL: attestorUrl,
      ROOTARK_ZK1_ADMISSION_ISSUER_PG_URL: issuerUrl }, maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw Error("ZK65_SYNC_PG_BATCH_FAILED: test run rejected (no database credentials emitted)");
  }
  const summary = checkCompleteTap(String(result.stdout || ""));
  process.stdout.write("ZK65_SYNC_PG_BATCH_PASS tests=" + summary.tests + " skipped=0\n");
}).catch((error) => {
  process.stderr.write("ZK65_SYNC_PG_BATCH_LAB_FAILED: " + error.message + "\n");
  process.exitCode = 1;
});
