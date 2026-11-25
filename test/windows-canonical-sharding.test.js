"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { canonicalTestArgs } = require("../scripts/run-windows-canonical-tests");
const { requireAllCanonicalShards } = require("../scripts/check-windows-ci-results");

test("canonical runner defaults to full npm test and accepts only the two fixed shards", () => {
  const full = ["test", "--", "--test-reporter=tap", "--test-concurrency=2"];
  assert.deepEqual(canonicalTestArgs([]), full);
  for (const shard of ["1/2", "2/2"]) {
    assert.deepEqual(canonicalTestArgs([`--shard=${shard}`]), [...full, `--test-shard=${shard}`]);
  }
  for (const args of [["--shard=1/3"], ["--shard=0/2"], ["--shard=1/2", "--shard=2/2"],
    ["--test-name-pattern=anything"], ["--shard=1/2", "other.test.js"]]) {
    assert.throws(() => canonicalTestArgs(args));
  }
});

test("Node's fixed shards partition the same discovered test files without omissions or duplicates", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-canonical-shards-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (let i = 0; i < 7; i++) {
    fs.writeFileSync(path.join(dir, `sample-${i}.test.js`),
      `require('node:test')('canonical-shard-fixture-${i}', () => {});\n`);
  }
  const run = (args) => {
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, ["--test", ...canonicalTestArgs(args).slice(2)],
      { cwd: dir, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    return [...result.stdout.replace(/\r\n/g, "\n").matchAll(/^ok \d+ - canonical-shard-fixture-(\d+)$/gm)]
      .map((entry) => Number(entry[1]));
  };
  const full = run([]);
  const first = run(["--shard=1/2"]);
  const second = run(["--shard=2/2"]);
  assert.equal(full.length, 7);
  assert.ok(first.length > 0 && second.length > 0);
  assert.equal(new Set([...first, ...second]).size, first.length + second.length);
  assert.deepEqual([...first, ...second].sort(), full.sort());
});

test("stable canonical check rejects missing, failed, cancelled or skipped shard matrices", () => {
  assert.equal(requireAllCanonicalShards("success"), true);
  for (const result of [undefined, "", "failure", "cancelled", "skipped", "neutral"]) {
    assert.throws(() => requireAllCanonicalShards(result));
  }
});
