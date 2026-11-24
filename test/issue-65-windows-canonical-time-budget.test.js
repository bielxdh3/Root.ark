"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..");

test("Windows full canonical suite keeps a bounded budget beyond the observed active 55-minute cutoff", () => {
  const runner = fs.readFileSync(path.join(ROOT, "scripts", "run-windows-canonical-tests.js"), "utf8");
  const workflow = fs.readFileSync(path.join(ROOT, ".github", "workflows",
    "security-regression.yml"), "utf8");
  const total = /const TOTAL_LIMIT_MS = (\d+) \* 60_000;/.exec(runner);
  const idle = /const IDLE_LIMIT_MS = (\d+) \* 60_000;/.exec(runner);
  const job = /^  windows-canonical-suite:\s*\n(?:.*\n)*?    timeout-minutes: (\d+)$/m.exec(workflow);
  assert.ok(total && idle && job, "both finite runner timeouts and hosted job limit remain explicit");
  const totalMinutes = Number(total[1]);
  const jobMinutes = Number(job[1]);
  // The official second attempt was still emitting TAP results when the old
  // 55-minute wall clock limit terminated it without an observed assertion.
  assert.ok(totalMinutes > 55 && totalMinutes <= 85,
    "do not terminate an actively progressing full suite at the already-failed 55-minute cutoff");
  assert.ok(jobMinutes >= totalMinutes + 10 && jobMinutes <= 100,
    "the hosted job must leave finite setup and shutdown margin after the test deadline");
  assert.equal(Number(idle[1]), 15,
    "preserve the independent no-progress timeout; a hung suite must still fail closed");
  assert.match(runner, /getNpmInvocation\(\["test", "--", "--test-reporter=tap", "--test-concurrency=2"\]\)/,
    "still execute every canonical test with bounded file concurrency and no filters");
});
