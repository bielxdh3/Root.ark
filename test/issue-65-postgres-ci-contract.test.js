"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("PR CI runs all disposable ZK-1 PostgreSQL physical-effect suites without credentials", () => {
  const yaml = fs.readFileSync(path.join(__dirname, "..", ".github", "workflows",
    "zk1-disposable-postgres.yml"), "utf8");
  assert.match(yaml, /^name: ZK-1 Disposable PostgreSQL\s*$/m);
  assert.match(yaml, /^on:\s*\n\s+pull_request:/m);
  assert.match(yaml, /^\s+branches:\s*\n\s+- Root\/main/m);
  assert.match(yaml, /^permissions:\s*\n\s+contents: read\s*$/m);
  assert.match(yaml, /^\s+runs-on: ubuntu-latest\s*$/m);
  assert.match(yaml, /^\s+timeout-minutes: \d+\s*$/m);
  assert.match(yaml, /node-version: 22/);
  assert.match(yaml, /docker pull postgres:18\.6-alpine3\.24/);
  assert.match(yaml, /npm ci/);
  for (const runner of ["run-shared-gate-postgres.js",
    "run-supervised-mtls-bound-writer.js", "run-supervised-get-egress.js",
    "run-approval-replay-postgres.js"]) {
    assert.equal(yaml.split(runner).length - 1, 1,
      "exactly one CI invocation for " + runner);
  }
  assert.doesNotMatch(yaml, /\bsecrets\.|\bworkflow_run:|\bdeploy\b|\bworkflow_dispatch:/i);
  assert.doesNotMatch(yaml, /(?:permissions:\s*\n[^]*?)(?:contents: write|actions: write)/i);
});
