"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { checkCompleteTap } = require("../lab/issue-65-pg18-ci/no-skip-tap");
const { removeVerifiedDisposablePg } =
  require("../lab/issue-65-pg18-ci/verified-anonymous-pg-cleanup");
const { requirePg18Version, runTestsNoSkip, recoverContainerId } =
  require("../lab/issue-65-pg18-ci/disposable-postgres");

const containerId = "a".repeat(64);
const volumeId = "b".repeat(64);
const name = "rootark-zk65-gate-abcdef123456";
const lab = "issue65-shared-gate";
const valid = [
  "TAP version 13", "ok 1 - first", "ok 2 - second", "1..2",
  "# tests 2", "# suites 0", "# pass 2", "# fail 0", "# cancelled 0",
  "# skipped 0", "# todo 0", "# duration_ms 42",
].join("\n");

test("PG18 pull-request paths include zk1 Ed25519 and attested-inventory crypto", () => {
  const workflow = fs.readFileSync(path.join(__dirname,
    "../.github/workflows/zk1-disposable-postgres.yml"), "utf8");
  const lines = workflow.split(/\r?\n/);
  const pathsIndex = lines.indexOf("    paths:");
  assert.notEqual(pathsIndex, -1, "pull_request must declare its path filters");
  const globs = [];
  for (const line of lines.slice(pathsIndex + 1)) {
    const item = /^      - '([^']+)'$/.exec(line);
    if (!item) break;
    globs.push(item[1]);
  }
  const triggersFor = (file) => globs.some((glob) => {
    if (!glob.endsWith("*") || glob.endsWith("**")) return glob === file;
    const prefix = glob.slice(0, -1);
    return file.startsWith(prefix) && !file.slice(prefix.length).includes("/");
  });
  assert.equal(triggersFor("src/crypto/rootark-zk-recovery-history-v2.js"), true,
    "legacy ZK cryptography must continue to trigger the gate");
  assert.equal(triggersFor("src/crypto/rootark-zk1-native-ed25519-public-key.js"), true,
    "native Ed25519 source changes must trigger real PostgreSQL authority tests");
  assert.equal(triggersFor("src/crypto/rootark-zk1-attested-inventory-commit-v1.js"), true,
    "attested inventory changes must trigger the PostgreSQL gate");
  const zk1CryptoNames = fs.readdirSync(path.join(__dirname, "../src/crypto"))
    .filter((name) => name.startsWith("rootark-zk1-"));
  assert.ok(zk1CryptoNames.length >= 9, "reviewed PR234 zk1 cryptography baseline");
  for (const filename of zk1CryptoNames) {
    assert.equal(triggersFor("src/crypto/" + filename), true,
      "every zk1 cryptography file must trigger PostgreSQL authority tests: " + filename);
  }
  assert.equal(triggersFor("sync-client/rootark-sync-zk1-physical-binding.js"), true,
    "sync physical-binding changes must trigger the PostgreSQL gate");
  assert.equal(triggersFor("src/crypto/unrelated.js"), false,
    "do not broaden the crypto trigger beyond the two named families");
});

test("PostgreSQL 18 runner rejects a tag resolving to a different server minor version", () => {
  assert.equal(requirePg18Version("18.6"), true);
  for (const version of ["18.5", "18.7", "19.0", "17.6", "18.6-mismatch", ""]) {
    assert.throws(() => requirePg18Version(version), /ZK65_PG_IMAGE_VERSION_MISMATCH/);
  }
});

test("each mandatory PostgreSQL test file gets its own checked, zero-skip TAP execution", () => {
  const gateFiles = [
    "test/issue-65-gate-runtime-role.test.js",
    "test/issue-65-pg-sealed-sink.test.js",
    "test/issue-65-shared-pg-sealed-object.test.js",
  ];
  const replayFiles = [
    "test/issue-65-approval-replay-postgres.test.js",
    "test/issue-65-approval-crypto-replay-postgres.test.js",
  ];
  const invoked = [];
  const fakeSpawn = (_binary, args) => {
    invoked.push(args.at(-1));
    return { status: 0, stdout: valid };
  };
  assert.equal(runTestsNoSkip(gateFiles, {}, 150000, fakeSpawn).files, 3);
  assert.equal(runTestsNoSkip(replayFiles, {}, 120000, fakeSpawn).files, 2);
  assert.deepEqual(invoked, [...gateFiles, ...replayFiles]);
  assert.throws(() => runTestsNoSkip([gateFiles[0]], {}, 150000, fakeSpawn),
    /ZK65_PG_TESTS_UNVERIFIED/);
  const skipped = (_binary, args) => ({
    status: 0,
    stdout: args.at(-1) === gateFiles[1]
      ? valid.replace("# skipped 0", "# skipped 1")
      : valid,
  });
  assert.throws(() => runTestsNoSkip(gateFiles, {}, 150000, skipped),
    /ZK65_PG_TESTS_UNVERIFIED/);
});

test("failed docker run can recover only exact random-name container ID for verified cleanup", () => {
  const name = "rootark-zk65-gate-abcdef123456";
  const docker = (args) => {
    assert.deepEqual(args, ["container", "inspect", "--format", "{{.Id}}", name]);
    return containerId;
  };
  assert.equal(recoverContainerId(name, docker), containerId);
  assert.equal(recoverContainerId(name, () => "invalid"), undefined);
  assert.equal(recoverContainerId(name, () => { throw Error("daemon offline"); }), undefined);
  assert.equal(recoverContainerId("unknown-container", docker), undefined);
});

test("PostgreSQL CI gate refuses missing, skipped, todo and failed Node TAP summaries", () => {
  assert.equal(checkCompleteTap(valid).tests, 2);
  for (const bad of [
    valid.replace("# skipped 0", "# skipped 1"),
    valid.replace("# todo 0", "# todo 1"),
    valid.replace("# fail 0", "# fail 1"),
    valid.replace("# pass 2", "# pass 1"),
    valid.replace("# tests 2", "# tests 0"),
    valid.replace("# skipped 0", ""),
    valid.replace("ok 2 - second", "ok 2 - second # SKIP unavailable"),
    "TAP version 13\nok 1 - a",
  ]) assert.throws(() => checkCompleteTap(bad), /ZK65_PG_TESTS_UNVERIFIED/);
});

function fakeDocker({ label = lab, owner = "disposable-local", destination = "/var/lib/postgresql",
  mountType = "volume", volume = volumeId, container = containerId, missing = true } = {}) {
  const commands = [];
  const docker = (args) => {
    commands.push(args);
    if (args[0] === "container" && args[1] === "inspect") {
      return args[3] === "{{json .Mounts}}"
        ? JSON.stringify([{ Type: mountType, Destination: destination, Name: volume }])
        : `${container}|${label}|${owner}`;
    }
    if (args[0] === "rm") return container;
    throw Error("unexpected docker command");
  };
  const inspectVolume = (vol) => {
    commands.push(["volume", "inspect", vol]);
    return missing
      ? { status: 1, stderr: `Error response from daemon: get ${vol}: no such volume`, stdout: "" }
      : { status: 0, stderr: "", stdout: "[]" };
  };
  return { commands, docker, inspectVolume };
}

test("verified disposable cleanup deletes only exact labeled container and anonymous data volume", () => {
  const f = fakeDocker();
  assert.deepEqual(removeVerifiedDisposablePg({
    docker: f.docker, inspectVolume: f.inspectVolume,
    containerId, containerName: name, labLabel: lab,
  }), { containerRemoved: true, anonymousVolumeRemoved: true });
  assert.equal(f.commands.some((args) => args[0] === "rm"
    && args[1] === "-f" && args[2] === "-v" && args[3] === containerId), true);
});

test("approval replay fixture uses separate exact disposable cleanup identity", () => {
  const f = fakeDocker({ label: "issue65-approval-replay" });
  assert.deepEqual(removeVerifiedDisposablePg({
    docker: f.docker, inspectVolume: f.inspectVolume,
    containerId, containerName: "rootark-zk65-replay-abcdef123456",
    labLabel: "issue65-approval-replay",
  }), { containerRemoved: true, anonymousVolumeRemoved: true });
});

test("cleanup rejects foreign label, owner, mount, volume, container, or ambiguous erasure", () => {
  for (const altered of [
    { label: "unknown" }, { owner: "user-data" },
    { destination: "/home" }, { mountType: "bind" },
    { volume: "precious-volume" }, { container: "c".repeat(64) },
    { missing: false },
  ]) {
    const f = fakeDocker(altered);
    assert.throws(() => removeVerifiedDisposablePg({
      docker: f.docker, inspectVolume: f.inspectVolume,
      containerId, containerName: name, labLabel: lab,
    }), /ZK65_DISPOSABLE_CLEANUP_REFUSED/);
    if (altered.missing !== false) assert.equal(f.commands.some((a) => a[0] === "rm"), false);
  }
  const f = fakeDocker();
  assert.throws(() => removeVerifiedDisposablePg({
    docker: f.docker, inspectVolume: f.inspectVolume,
    containerId, containerName: name, labLabel: "untrusted-gate",
  }), /ZK65_DISPOSABLE_CLEANUP_REFUSED/);
});
