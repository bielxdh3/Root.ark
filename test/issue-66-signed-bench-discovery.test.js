"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const benchmark = path.join(__dirname, "support/issue-66-signed-eviction-bench.js");
const cliEnv = { ...process.env };
delete cliEnv.NODE_TEST_CONTEXT;

function run(args, env = cliEnv) {
  return spawnSync(process.execPath, args, {
    env, encoding: "utf8", timeout: 20000, windowsHide: true,
  });
}

test("#66 signed eviction benchmark is inert under canonical Node test discovery", () => {
  const discovery = run(["--test", benchmark]);
  assert.equal(discovery.error, undefined);
  assert.equal(discovery.status, 0, `${discovery.stdout}\n${discovery.stderr}`);
  assert.match(discovery.stdout, /benchmark is CLI-only.*SKIP/);

  const missingCount = run([benchmark]);
  assert.equal(missingCount.error, undefined);
  assert.notEqual(missingCount.status, 0);
  assert.match(missingCount.stderr, /Benchmark requires 1\.\.640 disposable fixture files/);
  assert.equal(missingCount.stdout, "");

  const explicit = run([benchmark, "1"]);
  assert.equal(explicit.error, undefined);
  assert.equal(explicit.status, 0, `${explicit.stdout}\n${explicit.stderr}`);
  const result = JSON.parse(explicit.stdout.trim());
  assert.equal(result.count, 1);
  assert.equal(result.verified, 1);
  assert.equal(result.remotePushes, 0);
});
