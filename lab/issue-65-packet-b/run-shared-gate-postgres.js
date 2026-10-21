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
  const uri = "postgresql://postgres:" + password + "@127.0.0.1:" + match[1] + "/gatefixture";
  run("node", ["--test", "--test-reporter=spec",
    "test/issue-65-shared-gate-postgres.test.js"],
  { env: { ...process.env, ROOTARK_ZK1_TEST_PG_URL: uri }, inherit: true });
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
