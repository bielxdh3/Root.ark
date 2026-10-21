"use strict";

// Dedicated disposable PG18/Node22 GET-egress laboratory runner. No production
// credentials, no service runtime integration, no external container networking.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const image = "postgres:18.6-alpine3.24";
const name = "rootark-zk65-get-" + crypto.randomBytes(6).toString("hex");
const password = crypto.randomBytes(24).toString("hex");
let id;
let failed = false;

function run(binary, args, { env, input, inherit = false } = {}) {
  const output = spawnSync(binary, args, { cwd: root, env: env || process.env,
    encoding: "utf8", input, windowsHide: true,
    timeout: inherit ? 90000 : 25000, stdio: inherit ? "inherit" : undefined });
  if (output.error || output.status !== 0) {
    throw new Error("lab subprocess failed: " + binary + " " + args[0]
      + " (exit=" + output.status + ", stderr="
      + String(output.stderr || "").trim().slice(0, 140) + ")");
  }
  return String(output.stdout || "").trim();
}
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  run("docker", ["image", "inspect", image]);
  id = run("docker", ["run", "-d", "--name", name,
    "--label", "rootark.lab=issue65-get-egress",
    "--label", "rootark.owner=disposable-local",
    "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=gatefixture",
    "-p", "127.0.0.1::5432", image],
  { env: { ...process.env, POSTGRES_PASSWORD: password } });
  if (!/^[a-f0-9]{64}$/i.test(id)) throw new Error("invalid lab container id");
  let ready = false;
  for (let n = 0; n < 80; n++) {
    const check = spawnSync("docker", ["exec", id, "psql", "-X", "-tA",
      "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "gatefixture",
      "-c", "SELECT 1"], { encoding: "utf8", windowsHide: true, timeout: 4000 });
    if (check.status === 0 && check.stdout.trim() === "1") {
      ready = true;
      break;
    }
    await delay(250);
  }
  if (!ready) throw new Error("PG18 fixture not ready");
  const port = /^127\.0\.0\.1:(\d+)$/.exec(run("docker", ["port", id, "5432/tcp"]));
  if (!port) throw new Error("PostgreSQL must be bound to loopback");
  run("docker", ["exec", "-i", id, "psql", "-X", "-v", "ON_ERROR_STOP=1",
    "-U", "postgres", "-d", "gatefixture"],
  { input: fs.readFileSync(path.join(root, "db", "zk1-gate-authority.sql"), "utf8") });
  const role = (prefix, roleName) => {
    const username = prefix + crypto.randomBytes(6).toString("hex");
    const secret = crypto.randomBytes(24).toString("hex");
    run("docker", ["exec", "-i", id, "psql", "-X", "-v", "ON_ERROR_STOP=1",
      "-U", "postgres", "-d", "gatefixture"],
    { input: "CREATE ROLE " + username + " LOGIN PASSWORD '" + secret + "';\n"
      + "GRANT " + roleName + " TO " + username + ";\n" });
    return "postgresql://" + username + ":" + secret
      + "@127.0.0.1:" + port[1] + "/gatefixture";
  };
  const fixture = { ...process.env,
    ROOTARK_ZK1_TEST_PG_URL: "postgresql://postgres:" + password
      + "@127.0.0.1:" + port[1] + "/gatefixture",
    ROOTARK_ZK1_RUNTIME_PG_URL: role("zkgatefixture_", "zk1_gate_runtime"),
    ROOTARK_ZK1_STOP_PG_URL: role("zkstopfixture_", "zk1_stop_runtime") };

  // On Windows the child/supervisor both execute native Node and own native
  // Windows TCP sockets. Node22 tests may also run through existing WSL.
  run("node", ["--test", "--test-reporter=spec",
    "test/issue-65-supervised-get-egress-lab.test.js"],
  { env: fixture, inherit: true });
  process.stdout.write("GET_EGRESS_PG18_NATIVE_PASS\n");
  if (process.platform === "win32") {
    const linuxRoot = run("wsl.exe", ["--exec", "wslpath", "-a", root]);
    const passEnv = ["ROOTARK_ZK1_TEST_PG_URL", "ROOTARK_ZK1_RUNTIME_PG_URL",
      "ROOTARK_ZK1_STOP_PG_URL"].join(":");
    run("wsl.exe", ["--exec", "bash", "-lc", "cd '"
      + linuxRoot.replaceAll("'", "'\\''")
      + "' && node --test --test-reporter=spec test/issue-65-supervised-get-egress-lab.test.js"],
    { env: { ...fixture, WSLENV: [process.env.WSLENV, passEnv]
      .filter(Boolean).join(":") }, inherit: true });
    process.stdout.write("GET_EGRESS_PG18_WSL_NODE22_PASS\n");
  }
}

(async () => {
  try { await main(); }
  catch (error) {
    failed = true;
    process.stderr.write("GET_EGRESS_LAB_FAILED: " + error.message + "\n");
  } finally {
    if (id) {
      try {
        const identity = run("docker", ["container", "inspect", "--format",
          "{{.Id}}|{{index .Config.Labels \"rootark.lab\"}}|{{index .Config.Labels \"rootark.owner\"}}", name]);
        if (identity !== id + "|issue65-get-egress|disposable-local") {
          throw new Error("unexpected fixture container identity; cleanup refused");
        }
        run("docker", ["rm", "-f", id]);
        process.stdout.write("GET_EGRESS_LAB_CLEANUP verified=true\n");
      } catch (error) {
        failed = true;
        process.stderr.write("GET_EGRESS_LAB_CLEANUP_FAILED: " + error.message + "\n");
      }
    }
    if (failed) process.exitCode = 1;
  }
})();
