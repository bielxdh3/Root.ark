"use strict";

// Disposable real PostgreSQL shared-gate runner. Uses the cached official
// image only; refuses to clean up resources without exact label/ID match.
// Never exposes the ephemeral database password in process output.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const name = "rootark-zk65-gate-" + crypto.randomBytes(6).toString("hex");
const password = crypto.randomBytes(24).toString("hex");
const image = "postgres:18.6-alpine3.24";
let containerId;
let failed = false;

function run(binary, args, { input, env, inherit = false } = {}) {
  const output = spawnSync(binary, args, {
    cwd: root, encoding: "utf8", input, env: env || process.env,
    timeout: inherit ? 150000 : 25000,
    stdio: inherit ? "inherit" : undefined,
    windowsHide: true,
  });
  if (output.error || output.status !== 0) {
    throw new Error("disposable lab subprocess failed: " + binary + " " + args[0]
      + " (exit=" + output.status + ", synthetic-stderr="
      + String(output.stderr || "").trim().slice(0, 250) + ")");
  }
  return String(output.stdout || "").trim();
}

function pause(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main() {
  run("docker", ["image", "inspect", image]);
  containerId = run("docker", ["run", "-d", "--name", name,
    "--label", "rootark.lab=issue65-shared-gate",
    "--label", "rootark.owner=disposable-local",
    "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=gatefixture",
    "-p", "127.0.0.1::5432", image],
  { env: { ...process.env, POSTGRES_PASSWORD: password } });
  if (!/^[0-9a-f]{64}$/i.test(containerId)) throw new Error("invalid disposable container id");
  let ready = false;
  for (let i = 0; i < 80; ++i) {
    const checked = spawnSync("docker", ["exec", containerId, "psql",
      "-X", "-tA", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gatefixture",
      "-c", "SELECT 1"],
    { windowsHide: true, encoding: "utf8", timeout: 5000 });
    if (checked.status === 0 && checked.stdout.trim() === "1") {
      await pause(300);
      ready = true;
      break;
    }
    await pause(250);
  }
  if (!ready) throw new Error("disposable PostgreSQL did not become ready");
  const portLine = run("docker", ["port", containerId, "5432/tcp"]);
  const match = /^127\.0\.0\.1:(\d+)\s*$/.exec(portLine);
  if (!match) throw new Error("loopback-only PostgreSQL port was not confirmed");
  const sql = fs.readFileSync(path.join(root, "db", "zk1-gate-authority.sql"), "utf8");
  run("docker", ["exec", "-i", containerId, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"], { input: sql });
  // Simulate legacy per-column writer ACLs left by the previous isolated
  // physical-writer milestone, then reapply the schema to prove migration
  // cleanup. Table-level REVOKE does NOT implicitly remove column grants.
  const staleWriterGrants =
    "GRANT INSERT(scope_key,object_id,chunk_index,ciphertext) ON "
      + "zk1_gate.ciphertext_chunk TO zk1_chunk_writer_runtime;\n"
      + "GRANT SELECT(chunk_index) ON zk1_gate.ciphertext_chunk TO zk1_chunk_writer_runtime;\n";
  run("docker", ["exec", "-i", containerId, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"], { input: staleWriterGrants });
  const directWriterAcl = () => run("docker", ["exec", containerId, "psql",
    "-X", "-tA", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gatefixture",
    "-c", "SELECT pg_catalog.has_column_privilege(" +
      "'zk1_chunk_writer_runtime','zk1_gate.ciphertext_chunk','scope_key','INSERT')" +
      ",pg_catalog.has_column_privilege(" +
      "'zk1_chunk_writer_runtime','zk1_gate.ciphertext_chunk','chunk_index','SELECT')"]);
  if (directWriterAcl() !== "t|t") {
    throw new Error("disposable legacy writer column grants were not reproduced");
  }
  run("docker", ["exec", "-i", containerId, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"], { input: sql });
  if (directWriterAcl() !== "f|f") {
    throw new Error("in-place operator DDL did not revoke legacy raw writer privileges");
  }
  const roleName = "zkgatefixture_" + crypto.randomBytes(6).toString("hex");
  const rolePassword = crypto.randomBytes(24).toString("hex");
  // Test-only dedicated login is issued to the exact independently seeded
  // NOLOGIN runtime role. Do not print or reuse either credential.
  const provisionRole = `CREATE ROLE ${roleName} LOGIN PASSWORD '${rolePassword}';\n`
    + `GRANT zk1_gate_runtime TO ${roleName};\n`;
  run("docker", ["exec", "-i", containerId, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"], { input: provisionRole });
  const uri = "postgresql://postgres:" + password + "@127.0.0.1:" + match[1] + "/gatefixture";
  const runtimeUri = "postgresql://" + roleName + ":" + rolePassword
    + "@127.0.0.1:" + match[1] + "/gatefixture";
  const stopRoleName = "zkstopfixture_" + crypto.randomBytes(6).toString("hex");
  const stopRolePassword = crypto.randomBytes(24).toString("hex");
  const provisionStop = `CREATE ROLE ${stopRoleName} LOGIN PASSWORD '${stopRolePassword}';\n`
    + `GRANT zk1_stop_runtime TO ${stopRoleName};\n`;
  run("docker", ["exec", "-i", containerId, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"], { input: provisionStop });
  const stopUri = "postgresql://" + stopRoleName + ":" + stopRolePassword
    + "@127.0.0.1:" + match[1] + "/gatefixture";
  const writerRoleName = "zkwriterfixture_" + crypto.randomBytes(6).toString("hex");
  const writerRolePassword = crypto.randomBytes(24).toString("hex");
  const provisionWriter = "CREATE ROLE " + writerRoleName
    + " LOGIN PASSWORD '" + writerRolePassword + "';\n"
    + "GRANT zk1_chunk_writer_runtime TO " + writerRoleName + ";\n";
  run("docker", ["exec", "-i", containerId, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"], { input: provisionWriter });
  const writerUri = "postgresql://" + writerRoleName + ":" + writerRolePassword
    + "@127.0.0.1:" + match[1] + "/gatefixture";
  run("node", ["--test", "--test-reporter=spec",
    "test/issue-65-shared-gate-postgres.test.js",
    "test/issue-65-gate-runtime-role.test.js",
    "test/issue-65-shared-pg-sealed-object.test.js",
    "test/issue-65-unsealed-sql-fence.test.js",
    "test/issue-65-chunk-writer-role.test.js",
    "test/issue-65-pg-sealed-sink.test.js",
    "test/issue-65-stop-recorder-postgres.test.js",
    "test/issue-65-strict-stop-operator-postgres.test.js",
    "test/issue-65-supervised-pg-writer-lab.test.js",
    "test/issue-65-shared-gate-real-witness.test.js"],
  { env: { ...process.env, ROOTARK_ZK1_TEST_PG_URL: uri,
    ROOTARK_ZK1_RUNTIME_PG_URL: runtimeUri,
    ROOTARK_ZK1_STOP_PG_URL: stopUri,
    ROOTARK_ZK1_WRITER_PG_URL: writerUri }, inherit: true });
  process.stdout.write("SHARED_GATE_PG_REAL_PASS loopback=true cleanup=pending\n");
}

(async () => {
  try { await main(); }
  catch (error) {
    failed = true;
    process.stderr.write("SHARED_GATE_LAB_FAILED: " + error.message + "\n");
  } finally {
    if (containerId) {
      try {
        const identity = run("docker", ["container", "inspect", "--format",
          "{{.Id}}|{{index .Config.Labels \"rootark.lab\"}}|{{index .Config.Labels \"rootark.owner\"}}", name]);
        if (identity !== containerId + "|issue65-shared-gate|disposable-local") {
          throw new Error("container identity/labels changed; cleanup refused");
        }
        run("docker", ["rm", "-f", containerId]);
        process.stdout.write("SHARED_GATE_PG_CLEANUP verified=true\n");
      } catch (error) {
        failed = true;
        process.stderr.write("SHARED_GATE_CLEANUP_FAILED: " + error.message + "\n");
      }
    }
    if (failed) process.exitCode = 1;
  }
})();
