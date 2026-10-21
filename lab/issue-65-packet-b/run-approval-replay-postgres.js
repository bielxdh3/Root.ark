"use strict";

// Issue #65: STRICTLY disposable PostgreSQL 18 replay challenge lab runner.
// Real app/production DB credentials are never read or used by this program.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(__dirname, "../..");
const image = "postgres:18.6-alpine3.24";
const name = "rootark-zk65-replay-" + crypto.randomBytes(6).toString("hex");
const password = crypto.randomBytes(24).toString("hex");
let id;
let failed = false;

function run(binary, args, { env, input, inherit = false } = {}) {
  const result = spawnSync(binary, args, { cwd: root, env: env || process.env,
    input, encoding: "utf8", windowsHide: true,
    timeout: inherit ? 120000 : 30000, stdio: inherit ? "inherit" : undefined });
  if (result.error || result.status !== 0) {
    throw new Error("isolated replay lab subprocess failed: " + binary + " " + args[0]
      + " exit=" + result.status); // NEVER render stderr: could hold URLs.
  }
  return String(result.stdout || "").trim();
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function main() {
  run("docker", ["image", "inspect", image]);
  id = run("docker", ["run", "-d", "--name", name,
    "--label", "rootark.lab=issue65-approval-replay",
    "--label", "rootark.owner=disposable-local",
    "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=gatefixture",
    "-p", "127.0.0.1::5432", image],
  { env: { ...process.env, POSTGRES_PASSWORD: password } });
  if (!/^[a-f0-9]{64}$/.test(id)) throw new Error("unexpected PG lab container id");
  let ready = false;
  for (let n = 0; n < 80; ++n) {
    const checked = spawnSync("docker", ["exec", id, "psql", "-X", "-tA",
      "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gatefixture", "-c", "SELECT 1"],
    { encoding: "utf8", windowsHide: true, timeout: 4000 });
    if (checked.status === 0 && checked.stdout.trim() === "1") { ready = true; break; }
    await sleep(250);
  }
  if (!ready) throw new Error("disposable PG18 not ready");
  const port = /^127\.0\.0\.1:(\d+)$/.exec(run("docker", ["port", id, "5432/tcp"]));
  if (!port) throw new Error("fixture PG port is not loopback-only");
  const load = (input) => run("docker", ["exec", "-i", id, "psql", "-X",
    "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gatefixture"], { input });
  // Only the test container receives these schema/ACL changes.
  load(fs.readFileSync(path.join(root, "db", "zk1-gate-authority.sql"), "utf8"));
  load(fs.readFileSync(path.join(root, "lab", "issue-65-packet-b", "approval-replay-lab.sql"), "utf8"));
  const user = "zkreplayfixture_" + crypto.randomBytes(6).toString("hex");
  const secret = crypto.randomBytes(24).toString("hex");
  load("CREATE ROLE " + user + " LOGIN PASSWORD '" + secret + "';\n"
    + "GRANT zk1_approval_replay_writer TO " + user + ";\n");
  const fixtureEnv = { ...process.env,
    ROOTARK_ZK1_REPLAY_ADMIN_PG_URL: "postgresql://postgres:" + password
      + "@127.0.0.1:" + port[1] + "/gatefixture",
    ROOTARK_ZK1_REPLAY_WRITER_PG_URL: "postgresql://" + user + ":" + secret
      + "@127.0.0.1:" + port[1] + "/gatefixture" };
  run("node", ["--test", "--test-reporter=spec",
    "test/issue-65-approval-replay-postgres.test.js"],
  { env: fixtureEnv, inherit: true });
  process.stdout.write("APPROVAL_REPLAY_PG18_NATIVE_PASS\n");
  if (process.platform === "win32") {
    const linuxRoot = run("wsl.exe", ["--exec", "wslpath", "-a", root]);
    const names = ["ROOTARK_ZK1_REPLAY_ADMIN_PG_URL", "ROOTARK_ZK1_REPLAY_WRITER_PG_URL"].join(":");
    run("wsl.exe", ["--exec", "bash", "-lc",
      "cd '" + linuxRoot.replaceAll("'", "'\\''")
        + "' && node --test --test-reporter=spec test/issue-65-approval-replay-postgres.test.js"],
    { env: { ...fixtureEnv, WSLENV: [process.env.WSLENV, names].filter(Boolean).join(":") },
      inherit: true });
    process.stdout.write("APPROVAL_REPLAY_PG18_WSL_NODE22_PASS\n");
  }
}
(async () => {
  try { await main(); }
  catch (error) { failed = true; process.stderr.write("APPROVAL_REPLAY_LAB_FAILED: " + error.message + "\n"); }
  finally {
    if (id) {
      try {
        const identity = run("docker", ["container", "inspect", "--format",
          "{{.Id}}|{{index .Config.Labels \"rootark.lab\"}}|{{index .Config.Labels \"rootark.owner\"}}", name]);
        if (identity !== id + "|issue65-approval-replay|disposable-local") {
          throw new Error("disposable identity mismatch; cleanup refused");
        }
        run("docker", ["rm", "-f", id]);
        process.stdout.write("APPROVAL_REPLAY_LAB_CLEANUP verified=true\n");
      } catch (error) {
        failed = true;
        process.stderr.write("APPROVAL_REPLAY_LAB_CLEANUP_FAILED: " + error.message + "\n");
      }
    }
    if (failed) process.exitCode = 1;
  }
})();
