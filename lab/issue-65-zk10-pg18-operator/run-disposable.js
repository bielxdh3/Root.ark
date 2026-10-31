"use strict";
// Explicit opt-in. Never contacts production PG or any pre-existing container.
const { spawnSync } = require("node:child_process");
const { runDisposablePgLab } = require("../issue-65-pg18-ci/disposable-postgres");
const { checkCompleteTap } = require("../issue-65-pg18-ci/no-skip-tap");
runDisposablePgLab("gate", async ({ id, adminUrl }) => {
  const cleanEnv = Object.fromEntries(Object.entries(process.env)
    .filter(([k]) => !/^PG[A-Z_]+$/.test(k)
      && !["DATABASE_URL", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"].includes(k)));
  const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap",
    "lab/issue-65-zk10-pg18-operator/pg18-e2e-case.cjs"], {
    cwd: require("node:path").resolve(__dirname, "../.."),
    env: { ...cleanEnv, ROOTARK_ZK10_DEV_PG_URL: adminUrl,
      ROOTARK_ZK10_DEV_PG_CONTAINER: id },
    windowsHide: true, timeout: 145000,
    encoding: "utf8", maxBuffer: 4 * 1024 * 1024,
  });
  if (child.status !== 0 || child.error) {
    const output = String(child.stdout || "");
    const marks = [...output.matchAll(/ZK10_DEV_STAGE=([a-z-]{1,40})/g)]
      .map((m) => m[1]);
    const ordinal = /^not ok ([0-9]{1,4}) - /m.exec(output);
    const safeCode = [...output.matchAll(/ZK10_[A-Z0-9_]{2,75}/g)]
      .map((m) => m[0]).filter((v) => v !== "ZK10_DEV_STAGE").at(-1);
    const location = /pg18-e2e-case\.cjs:(\d{1,4}):(\d{1,4})/.exec(output);
    const message = ["ZK10_PG18_E2E_FAILED", "lastStage=" + (marks.at(-1) || "none"),
      "failedOrdinal=" + (ordinal?.[1] || "unknown"),
      "errorCode=" + (safeCode || "unknown"),
      "testLine=" + (location?.[1] || "unknown"),
      "raw TAP and credentials withheld"].join(" ");
    throw Error(message);
  }
  const result = checkCompleteTap(child.stdout || "");
  if (result.tests !== 1) throw Error("ZK10_PG18_E2E_INCOMPLETE");
  process.stdout.write("ZK10_DEV_PG18_MTLS_E2E_PASS tests=1 skipped=0\n");
}).catch((e) => {
  process.stderr.write("ZK10_DEV_PG18_OPERATOR_FAILED: "
    + String(e.message).replace(/postgresql:\/\/[^\s]+/g, "[redacted]") + "\n");
  process.exitCode = 1;
});
