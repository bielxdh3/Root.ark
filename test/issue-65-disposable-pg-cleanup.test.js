"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const ID = "a".repeat(64);
const VOLUME = "b".repeat(64);
const NAME = "rootark-zk65-get-010203040506";
const LAB = "issue65-get-egress";
const output = (lab = LAB) => `${ID}|${lab}|disposable-local`;
const mount = (name = VOLUME) => JSON.stringify([{
  Type: "volume", Name: name, Destination: "/var/lib/postgresql",
}]);

function harness({ identity = output(), mounts = mount(),
  result = { status: 1,
    stdout: "[]", stderr: `Error response from daemon: get ${VOLUME}: no such volume` } } = {}) {
  const calls = [];
  return {
    calls,
    docker(args) {
      calls.push([...args]);
      if (args[0] === "container" && args[1] === "inspect") {
        return args[3].includes("json .Mounts") ? mounts : identity;
      }
      if (args[0] === "rm" && args[1] === "-f" && args[2] === "-v") return ID;
      throw new Error("unexpected Docker operation");
    },
    inspectVolume(name) {
      calls.push(["volume", "inspect", name]);
      return result;
    },
  };
}

test("verified disposable PG fixture removes exact container and its anonymous data volume", () => {
  const { removeVerifiedDisposablePg } = require("../lab/issue-65-packet-b/verified-anonymous-pg-cleanup");
  const h = harness();
  assert.deepEqual(removeVerifiedDisposablePg({
    docker: h.docker, inspectVolume: h.inspectVolume,
    containerId: ID, containerName: NAME, labLabel: LAB,
  }), { containerRemoved: true, anonymousVolumeRemoved: true });
  assert.deepEqual(h.calls.map((x) => x.slice(0, 3)), [
    ["container", "inspect", "--format"],
    ["container", "inspect", "--format"],
    ["rm", "-f", "-v"],
    ["volume", "inspect", VOLUME],
  ]);
  assert.equal(h.calls[2][3], ID, "only full verified Docker ID may be removed");
});

test("foreign container label, id or named volume never triggers docker rm", () => {
  const { removeVerifiedDisposablePg } = require("../lab/issue-65-packet-b/verified-anonymous-pg-cleanup");
  for (const options of [
    { identity: output("foreign-lab") },
    { identity: `${"f".repeat(64)}|${LAB}|disposable-local` },
    { mounts: mount("production_pg_volume") },
    { mounts: JSON.stringify([{ Type: "bind", Source: "/sensitive",
      Destination: "/var/lib/postgresql" }]) },
    { mounts: JSON.stringify([{ Type: "volume", Name: VOLUME,
      Destination: "/var/lib/postgresql" }, { Type: "volume",
      Name: "c".repeat(64), Destination: "/extra" }]) },
    { mounts: "not JSON" },
  ]) {
    const h = harness(options);
    assert.throws(() => removeVerifiedDisposablePg({
      docker: h.docker, inspectVolume: h.inspectVolume,
      containerId: ID, containerName: NAME, labLabel: LAB,
    }), /ZK65_DISPOSABLE_CLEANUP_REFUSED/);
    assert.equal(h.calls.some((x) => x[0] === "rm"), false);
  }
});

test("still-present volume or inconclusive inspection cannot claim verified cleanup", () => {
  const { removeVerifiedDisposablePg } = require("../lab/issue-65-packet-b/verified-anonymous-pg-cleanup");
  for (const result of [
    { status: 0 },
    { status: 2 },
    { status: null, error: new Error("Docker unavailable") },
    { status: 1, stderr: "Cannot connect to the Docker daemon at unix:///var/run/docker.sock" },
    { status: 1, stderr: "permission denied while trying to connect to Docker" },
    { status: 1, stderr: `Error: No such volume: ${"f".repeat(64)}` },
  ]) {
    const h = harness({ result });
    assert.throws(() => removeVerifiedDisposablePg({
      docker: h.docker, inspectVolume: h.inspectVolume,
      containerId: ID, containerName: NAME, labLabel: LAB,
    }), /ZK65_DISPOSABLE_CLEANUP_REFUSED/);
    assert.equal(h.calls.some((x) => x[0] === "rm"), true);
  }
});
