const assert = require("node:assert/strict");
const test = require("node:test");
const { failedTestDiagnostics, unrecognizedChildProgress } = require("../scripts/release-gate-diagnostics");

test("a Windows child that exits before TAP counters retains bounded safe progress", () => {
  const output = [
    "> servidor-drive@1.0.0 test",
    "TAP version 13",
    "# Subtest: finished but runner stopped abruptly",
    "ok 47 - finished but runner stopped abruptly",
  ].join("\r\n");
  assert.equal(failedTestDiagnostics(output), "");
  const progress = unrecognizedChildProgress(output);
  assert.match(progress, /tapHeader=true tapPlan=false resultLines=1 subtestLines=1 lastResult=ok lastIndex=47 /);
  assert.match(progress, /lastResultNameSha256=[0-9a-f]{24}/);
});

test("failed TAP diagnostics still report failures, counts, and no change in gate status", () => {
  const output = "TAP version 13\nnot ok 12 - regression\n# tests 12\n# fail 1\n";
  assert.equal(failedTestDiagnostics(output), "not ok 12 - regression\n# tests 12\n# fail 1");
  assert.match(unrecognizedChildProgress(output), /tapPlan=false resultLines=1 subtestLines=0 lastResult=not_ok lastIndex=12 /);
});

test("Windows release gate reports safe assertion facts without revealing opaque failure details", () => {
  const secret = "ultrasensitivefixturevalue";
  const output = [
    "not ok 726 - owner offline signer enforces independent inputs",
    "  failureType: 'testCodeFailure'",
    "  error: |-",
    "    OWNER_FLOOR_SIGN_FAILED",
    `    password=${secret}`,
    "  code: 'ERR_ASSERTION'",
    "  actual: 1",
    "  expected: 0",
    "  operator: 'strictEqual'",
    "not ok 928 - actual standalone witness refuses signed-prefix floor rollback",
    "  error: WITNESS_FLOOR_START_TIMEOUT",
    `  actual: '${secret}'`,
    `  expected: '${secret}'`,
    "# tests 2128",
    "# suites 0",
    "# pass 1981",
    "# fail 2",
    "# cancelled 0",
    "# skipped 145",
    "# todo 0",
    "# duration_ms 900300.6309",
  ].join("\n");
  const report = failedTestDiagnostics(output);
  assert.ok(report.includes("not ok 726 - owner offline signer"));
  assert.ok(report.includes("not ok 928 - actual standalone witness"));
  for (const safe of ["OWNER_FLOOR_SIGN_FAILED", "WITNESS_FLOOR_START_TIMEOUT",
    "actual: 1", "expected: 0", "code: 'ERR_ASSERTION'", "operator: 'strictEqual'"]) {
    assert.ok(report.includes(safe), `missing safe field: ${safe}`);
  }
  assert.ok(!report.includes(secret));
  assert.ok(!report.includes("password"));
});

test("no test titles, authorization data, or opaque child payloads are logged on fallback", () => {
  const secret = "ultrasensitivefixturevalue";
  const output = `other untrusted output ${secret}\n# Subtest: password=${secret}\nok 42 - Authorization: Bearer ${secret}\n`;
  assert.equal(failedTestDiagnostics(output), "");
  const progress = unrecognizedChildProgress(output);
  assert.ok(!progress.includes(secret));
  assert.ok(!progress.includes("password"));
  assert.ok(!progress.includes("Authorization"));
  assert.match(progress, /tapHeader=false tapPlan=false resultLines=1 subtestLines=1 lastResult=ok lastIndex=42 /);
});

test("a non-TAP or empty failed child is still failed and only has zero progress", () => {
  assert.equal(unrecognizedChildProgress("other format unknown payload"),
    "tapHeader=false tapPlan=false resultLines=0 subtestLines=0 lastResult=none lastIndex=none lastResultNameSha256=none lastSubtestNameSha256=none");
  assert.equal(unrecognizedChildProgress(null), unrecognizedChildProgress(""));
});
