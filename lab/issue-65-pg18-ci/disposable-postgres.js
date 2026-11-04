"use strict";

// Only disposable, loopback-bound PostgreSQL 18 fixtures. No application DB,
// ambient PG* credentials, production URLs or shared Docker resources.
const { spawnSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { checkCompleteTap } = require("./no-skip-tap");
const { removeVerifiedDisposablePg } = require("./verified-anonymous-pg-cleanup");

const root = path.resolve(__dirname, "../..");
const image = "postgres:18.6-alpine3.24";
const database = "gatefixture";
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function requirePg18Version(version) {
  // Container tags are mutable. Refuse a replaced tag which no longer runs
  // the explicitly approved PostgreSQL 18.6 database release.
  if (version !== "18.6") throw Error("ZK65_PG_IMAGE_VERSION_MISMATCH");
  return true;
}

function run(binary, args, { env = process.env, input, timeout = 30000 } = {}) {
  const result = spawnSync(binary, args, {
    cwd: root, env, input, windowsHide: true,
    encoding: "utf8", timeout, maxBuffer: 16 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    // A failed child may print the ephemeral URL or password to stderr;
    // never relay untrusted subprocess stderr, command arguments or input.
    throw Error("ZK65_DISPOSABLE_COMMAND_FAILED: " + path.basename(binary)
      + " (" + String(args[0]) + ", exit=" + result.status + ")");
  }
  return String(result.stdout || "").trim();
}

function psql(id, statement) {
  return run("docker", ["exec", "-i", id, "psql", "-X",
    "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database], { input: statement });
}

function provisionLogin(id, prefix, membership) {
  if (!/^[a-z_]+$/.test(prefix)
    || !/^[a-z][a-z0-9_]*$/.test(membership)) throw Error("ZK65_FIXTURE_ROLE_INVALID");
  const user = prefix + crypto.randomBytes(6).toString("hex");
  const password = crypto.randomBytes(24).toString("hex");
  psql(id, "CREATE ROLE " + user + " LOGIN PASSWORD '" + password + "';\n"
    + "GRANT " + membership + " TO " + user + ";\n");
  return { user, password };
}

function loginUrl(port, credentials) {
  return "postgresql://" + credentials.user + ":" + credentials.password
    + "@127.0.0.1:" + port + "/" + database;
}

function readLabSql(relative) {
  if (!["db/zk1-gate-authority.sql", "lab/issue-65-pg18-ci/approval-replay-lab.sql"]
    .includes(relative)) throw Error("ZK65_SQL_PATH_INVALID");
  return fs.readFileSync(path.join(root, relative), "utf8");
}

function runTestsNoSkip(filenames, variables, timeout, spawn = spawnSync) {
  const gateFiles = [
    "test/issue-65-gate-runtime-role.test.js",
    "test/issue-65-pg-sealed-sink.test.js",
    "test/issue-65-shared-pg-sealed-object.test.js",
  ];
  const replayFiles = [
    "test/issue-65-approval-replay-postgres.test.js",
    "test/issue-65-approval-crypto-replay-postgres.test.js",
  ];
  if (!Array.isArray(filenames)
    || (filenames.join("\n") !== gateFiles.join("\n")
      && filenames.join("\n") !== replayFiles.join("\n"))) {
    throw Error("ZK65_PG_TESTS_UNVERIFIED");
  }
  // Disallow ambient credentials from ever being substituted for the newly
  // minted disposable fixture URL. The five tests get only their exact roles.
  const cleanEnv = Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => !/^PG[A-Z_]+$/.test(key)
      && !/^ROOTARK_ZK1_.*_PG_URL$/.test(key)
      && !["DATABASE_URL", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"].includes(key)));
  let totalTests = 0;
  // Run each required file independently. A single aggregated TAP summary
  // could otherwise pass even if one named file never executed.
  for (const file of filenames) {
    const result = spawn(process.execPath,
      ["--test", "--test-reporter=tap", file], {
        cwd: root, encoding: "utf8", windowsHide: true,
        timeout, maxBuffer: 16 * 1024 * 1024,
        env: { ...cleanEnv, ...variables },
      });
    if (result.error || result.status !== 0) {
      // Report only failing test titles which literally appear in the
      // checked-out source file; never relay untrusted TAP/pg stderr or URLs.
      const testSource = fs.readFileSync(path.join(root, file), "utf8");
      const knownTitles = new Set([...testSource.matchAll(/\btest\("([^"]+)"/g)]
        .map((item) => item[1]));
      const failedTitles = [...String(result.stdout || "")
        .matchAll(/^not ok \d+ - ([^\r\n]+)$/gm)]
        .map((item) => item[1]).filter((title) => knownTitles.has(title));
      throw Error("ZK65_PG_TESTS_FAILED in required file: " + file
        + "; cases=" + (failedTitles.join("; ") || "undetermined")
        + " (no credentials logged)");
    }
    const totals = checkCompleteTap(String(result.stdout || ""));
    totalTests += totals.tests;
  }
  return { files: filenames.length, tests: totalTests, skipped: 0 };
}

function recoverContainerId(name, docker) {
  if (typeof docker !== "function" ||
    !/^rootark-zk65-(gate|replay)-[a-f0-9]{12}$/.test(name)) return undefined;
  try {
    const candidate = docker(["container", "inspect", "--format", "{{.Id}}", name]);
    return /^[a-f0-9]{64}$/.test(candidate) ? candidate : undefined;
  } catch (_) {
    return undefined;
  }
}

async function runDisposablePgLab(kind, execute) {
  if (!["gate", "replay"].includes(kind) || typeof execute !== "function") {
    throw Error("ZK65_DISPOSABLE_LAB_INVALID");
  }
  const suffix = crypto.randomBytes(6).toString("hex");
  const name = "rootark-zk65-" + kind + "-" + suffix;
  const label = kind === "gate" ? "issue65-shared-gate" : "issue65-approval-replay";
  const password = crypto.randomBytes(24).toString("hex");
  let id;
  let failure;
  try {
    // The CI workflow pulls this exact image before starting the lab.
    run("docker", ["image", "inspect", image]);
    id = run("docker", ["run", "-d", "--name", name,
      "--label", "rootark.lab=" + label,
      "--label", "rootark.owner=disposable-local",
      "--env", "POSTGRES_PASSWORD", "--env", "POSTGRES_DB=" + database,
      "-p", "127.0.0.1::5432", image],
    { env: { ...process.env, POSTGRES_PASSWORD: password } });
    if (!/^[a-f0-9]{64}$/.test(id)) {
      throw Error("ZK65_DISPOSABLE_CONTAINER_UNVERIFIED");
    }
    let ready = false;
    for (let attempt = 0; attempt < 80; attempt += 1) {
      const check = spawnSync("docker", ["exec", id, "psql", "-X", "-tA",
        "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database, "-c", "SELECT 1"], {
          cwd: root, encoding: "utf8", windowsHide: true, timeout: 5000,
        });
      if (check.status === 0 && String(check.stdout || "").trim() === "1") {
        ready = true;
        break;
      }
      await delay(250);
    }
    if (!ready) throw Error("ZK65_DISPOSABLE_PG_NOT_READY");
    const serverVersion = run("docker", ["exec", id, "psql", "-X", "-tA",
      "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database,
      "-c", "SHOW server_version"]);
    requirePg18Version(serverVersion);
    const portLine = run("docker", ["port", id, "5432/tcp"]);
    const port = /^127\.0\.0\.1:(\d{2,5})$/.exec(portLine);
    if (!port || Number(port[1]) < 1024 || Number(port[1]) > 65535) {
      throw Error("ZK65_LOOPBACK_PORT_UNVERIFIED");
    }
    await execute({ id, port: port[1],
      adminUrl: loginUrl(port[1], { user: "postgres", password }),
      sql: (body) => psql(id, body),
      provision: (prefix, membership) => loginUrl(port[1],
        provisionLogin(id, prefix, membership)),
      readLabSql,
      runTestsNoSkip });
  } catch (error) {
    failure = error;
  } finally {
    // Docker run may create a fixture even if stdout/CLI failed before
    // reporting the ID. Recover by random exact name; deletion still requires
    // full ID, owned labels and anonymous volume proof.
    const ownedId = id && /^[a-f0-9]{64}$/.test(id) ? id
      : recoverContainerId(name, (args) => run("docker", args));
    if (ownedId) {
      try {
        removeVerifiedDisposablePg({
          docker: (args) => run("docker", args),
          inspectVolume: (volume) => spawnSync("docker", ["volume", "inspect", volume],
            { windowsHide: true, encoding: "utf8", timeout: 5000 }),
          containerId: ownedId, containerName: name, labLabel: label,
        });
        process.stdout.write("ZK65_DISPOSABLE_CLEANUP verified=true\n");
      } catch (_) {
        failure = Error("ZK65_DISPOSABLE_CLEANUP_FAILED");
      }
    }
  }
  if (failure) throw failure;
}

module.exports = {
  runDisposablePgLab, requirePg18Version, runTestsNoSkip, recoverContainerId,
};
