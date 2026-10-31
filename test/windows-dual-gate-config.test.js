"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const workflow = fs.readFileSync(path.join(__dirname,
  "../.github/workflows/security-regression.yml"), "utf8");

function windowsJobs(yaml) {
  const jobs = new Map();
  const lines = yaml.split(/\r?\n/);
  let name = null;
  for (const line of lines) {
    const header = /^  ([a-z][a-z0-9-]+):\s*$/.exec(line);
    if (header) { name = header[1]; jobs.set(name, []); }
    else if (name && (line.startsWith("    ") || line.trim() === "")) jobs.get(name).push(line);
    else if (/^\S/.test(line)) name = null;
  }
  return jobs;
}

function assertDualGate(yaml) {
  const jobs = windowsJobs(yaml);
  const release = jobs.get("windows-release-gate")?.join("\n");
  const canonical = jobs.get("windows-canonical-suite")?.join("\n");
  const aggregate = jobs.get("windows-validation")?.join("\n");
  assert.ok(release && canonical && aggregate, "both independent Windows jobs and aggregator required");
  assert.match(release, /runs-on:\s*windows-2022/);
  assert.match(canonical, /runs-on:\s*windows-2022/);
  for (const job of [release, canonical]) {
    assert.match(job, /node-version:\s*22/);
    assert.match(job, /run:\s*npm ci/);
    assert.match(job, /timeout-minutes:\s*60/);
  }
  assert.match(release, /node scripts\/validate-edge-e2e\.js --probe/);
  assert.match(release, /node scripts\/validate-edge-e2e\.js --run/);
  assert.match(release, /run:\s*npm run validate:release-gate/);
  assert.match(canonical, /run:\s*node scripts\/run-windows-canonical-tests\.js/);
  assert.doesNotMatch(canonical, /--test-skip-pattern|--test-name-pattern/);
  assert.match(aggregate, /needs:\s*\[windows-release-gate, windows-canonical-suite\]/);
  assert.match(aggregate, /if:\s*\$\{\{ always\(\) \}\}/);
  assert.match(aggregate, /uses:\s*actions\/checkout@v7/);
  assert.match(aggregate, /uses:\s*actions\/setup-node@v7/);
  assert.match(aggregate, /RELEASE_RESULT:\s*\$\{\{ needs\.windows-release-gate\.result \}\}/);
  assert.match(aggregate, /SUITE_RESULT:\s*\$\{\{ needs\.windows-canonical-suite\.result \}\}/);
  assert.match(aggregate, /run:\s*node scripts\/check-windows-ci-results\.js/);
}

test("hosted CI requires both independent Windows gates and exact aggregator dependencies", () => {
  assertDualGate(workflow);
});

test("configuration gate fails closed when canonical job or aggregator is dropped", () => {
  assert.throws(() => assertDualGate(workflow.replace(/  windows-canonical-suite:/,
    "  intentionally-removed-suite:")));
  assert.throws(() => assertDualGate(workflow.replace(/  windows-validation:/,
    "  intentionally-removed-aggregate:")));
});

test("configuration gate fails closed on single-needs and omitted Edge probe", () => {
  assert.throws(() => assertDualGate(workflow.replace(
    "needs: [windows-release-gate, windows-canonical-suite]", "needs: [windows-release-gate]")));
  assert.throws(() => assertDualGate(workflow.replace(
    "node scripts/validate-edge-e2e.js --probe", "echo no-edge-probe")));
});

module.exports = { assertDualGate };
