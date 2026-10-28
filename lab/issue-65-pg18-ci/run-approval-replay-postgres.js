"use strict";

const { runDisposablePgLab } = require("./disposable-postgres");

runDisposablePgLab("replay", async (fixture) => {
  fixture.sql(fixture.readLabSql("db/zk1-gate-authority.sql"));
  fixture.sql(fixture.readLabSql("lab/issue-65-pg18-ci/approval-replay-lab.sql"));
  const writerUrl = fixture.provision("zkreplayfixture_", "zk1_approval_replay_writer");
  const result = fixture.runTestsNoSkip([
    "test/issue-65-approval-replay-postgres.test.js",
    "test/issue-65-approval-crypto-replay-postgres.test.js",
  ], { ROOTARK_ZK1_REPLAY_ADMIN_PG_URL: fixture.adminUrl,
    ROOTARK_ZK1_REPLAY_WRITER_PG_URL: writerUrl }, 120000);
  process.stdout.write("ZK65_APPROVAL_REPLAY_PG18_PASS files=" + result.files
    + " tests=" + result.tests + " skipped=0\n");
}).catch((error) => {
  process.stderr.write("ZK65_APPROVAL_REPLAY_FAILED: " + error.message + "\n");
  process.exitCode = 1;
});
