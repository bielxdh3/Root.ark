"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const vm = require("node:vm");
const { extractHostedAclFailureDiagnostics } =
  require("../scripts/release-gate-acl-diagnostics");

const title = "Windows generic access ACEs cannot evade private snapshot ancestor checks";
const diagnostic = "# ROOTARK_ACL_V1 case=LEGACY_GENERIC_ACE stage=ACE_READBACK code=ASSERTION trust=UNKNOWN";

function failure({ name = title, location = String.raw`D:\a\Root.ark\Root.ark\test\issue-65-legacy-deterministic-evidence-manifest.test.js:689:1`, line = diagnostic } = {}) {
  return ["TAP version 13", `not ok 761 - ${name}`, "  ---",
    `  location: '${location}'`, "  failureType: 'testCodeFailure'", "  ...", line,
    "# tests 2238", "# fail 8"].join("\n");
}

test("hosted failure telemetry retains only pinned categorical ACL stage after a matching failed TAP test", () => {
  const result = extractHostedAclFailureDiagnostics(failure());
  assert.deepEqual(result, [diagnostic]);
  const twiceEscapedLocation = String.raw`D:\\a\\Root.ark\\Root.ark\\test\\issue-65-legacy-deterministic-evidence-manifest.test.js:689:1`;
  assert.deepEqual(extractHostedAclFailureDiagnostics(failure({ location: twiceEscapedLocation })), [diagnostic]);
});

test("hosted ACL telemetry rejects forged title, location, enum, or appended sensitive material", () => {
  const wrongFile = String.raw`D:\a\Root.ark\Root.ark\test\issue-65-other.test.js:689:1`;
  for (const sample of [
    failure({ name: "not the verified security regression" }),
    failure({ location: wrongFile }),
    failure({ line: diagnostic.replace("ACE_READBACK", "FAKE_STAGE") }),
    failure({ line: diagnostic.replace("ASSERTION", "LEAKED_PASSWORD") }),
    failure({ line: diagnostic.replace("UNKNOWN", "S-1-5-11") }),
    failure({ line: `${diagnostic} C:\\Users\\private\\secret.txt` }),
    failure().replace("not ok 761 -", "ok 761 -"),
    diagnostic,
  ]) assert.deepEqual(extractHostedAclFailureDiagnostics(sample), []);
});

test("hosted ACL telemetry cannot associate a prior passing case or unrelated failed case with #761", () => {
  const clean = [`ok 760 - some other test`, diagnostic, "not ok 761 - other failed case",
    "  location: 'D:\\a\\Root.ark\\Root.ark\\test\\other.test.js:1:1'", diagnostic].join("\n");
  assert.deepEqual(extractHostedAclFailureDiagnostics(clean), []);
  const safe = failure() + "\nnot ok 762 - unrelated failure\n" + diagnostic;
  assert.deepEqual(extractHostedAclFailureDiagnostics(safe), [diagnostic]);
});

test("release gate must include validated categorical ACL diagnostics and preserve redaction caps", () => {
  const source = fs.readFileSync(path.join(__dirname, "../scripts/validate-release-gate.js"), "utf8");
  assert.match(source, /extractHostedAclFailureDiagnostics\(tapStdout\)/);
  assert.match(source, /failedTestDiagnostics\(output,\s*result\.stdout(?:\s*\|\|\s*""\s*)?\)/);
  assert.match(source, /slice\(0, 12000\)/);
  assert.match(source, /slice\(0, 240\)/);
});

test("hosted release gate never attributes stderr-only diagnostics to a genuine stdout TAP failure", () => {
  const stdout = failure({ line: "# tests 2238" });
  const stderr = diagnostic + "\nC:\\Users\\private\\password=secret";
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout), []);
  // The old concatenated stream incorrectly attached the forged stderr line.
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout + "\n" + stderr), []);
});

test("hosted gate failure formatter uses only stdout for ACL while retaining generic sanitized stderr diagnostics", () => {
  const stdout = failure({ line: "  ..." }).split("# tests 2238")[0];
  const stderr = `${diagnostic}\nerror: EACCES`;
  // A concatenated stream without a TAP summary would be exploitable.
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout + stderr), [diagnostic]);
  const source = fs.readFileSync(path.join(__dirname, "../scripts/validate-release-gate.js"), "utf8");
  const functionBody = source.match(/function failedTestDiagnostics\(output, tapStdout\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(functionBody, "must test the actual production gate formatter");
  const format = vm.runInNewContext(`(${functionBody})`, { extractHostedAclFailureDiagnostics });
  const visible = format(`${stdout}\n${stderr}`, stdout);
  assert.match(visible, /not ok 761 - Windows generic access ACEs/);
  assert.match(visible, /error: EACCES/);
  assert.doesNotMatch(visible, /ROOTARK_ACL_V1|ACE_READBACK|S-1-5-11|password/);
});

test("hosted ACL diagnostic attribution ends at the TAP summary, plan and subsequent Subtest boundaries", () => {
  for (const boundary of ["# tests 2238", "# suites 0", "# pass 2157", "# fail 8",
    "# skipped 73", "# duration_ms 1418923.9444", "1..2238",
    "# Subtest: another unrelated test", "TAP version 13"]) {
    const output = failure({ line: boundary + "\n" + diagnostic });
    assert.deepEqual(extractHostedAclFailureDiagnostics(output), [],
      `the prior failed test must not own a diagnostic after ${boundary}`);
  }
  assert.deepEqual(extractHostedAclFailureDiagnostics(failure({ line: "  ...\n" + diagnostic })),
    [diagnostic], "real t.diagnostic after a YAML result must remain attributed");
});

test("Node TAP sends genuine t.diagnostic after failure YAML and before summary", () => {
  const script = [
    "const test=require('node:test');",
    "const assert=require('node:assert/strict');",
    `test(${JSON.stringify(title)}, t=> { t.diagnostic(${JSON.stringify(diagnostic)}); assert.equal(1,2); });`,
  ].join("\n");
  // A test-runner child inherits NODE_TEST_CONTEXT: remove it so this probe
  // emits human-readable TAP rather than the internal parent reporter wire.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, ["--test-reporter=tap", "-"], {
    input: script, env, encoding: "utf8", windowsHide: true, timeout: 12000,
  });
  assert.equal(child.status, 1, "the real Node TAP child must fail");
  const stdout = child.stdout || "";
  const yamlEnd = stdout.indexOf("  ...");
  const diag = stdout.indexOf(diagnostic);
  const summary = stdout.indexOf("# tests ");
  assert.ok(yamlEnd >= 0 && diag > yamlEnd && summary > diag,
    `a real diagnostic occurs after YAML and before TAP summary (${yamlEnd},${diag},${summary}; stdoutLength=${stdout.length}, stderrLength=${(child.stderr || "").length})`);
  assert.equal((child.stderr || "").includes(diagnostic), false);
});
