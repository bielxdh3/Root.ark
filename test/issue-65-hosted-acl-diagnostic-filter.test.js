"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const vm = require("node:vm");
const { extractHostedAclFailureDiagnostics } =
  require("../scripts/release-gate-acl-diagnostics");
const { parseAclFailureDiagnostic } = require("../scripts/acl-test-failure-diagnostic");
const { summarizeUnrecognizedChild } = require("../scripts/release-gate-child-diagnostics");

const title = "Windows generic access ACEs cannot evade private snapshot ancestor checks";
const file = "test/issue-65-legacy-deterministic-evidence-manifest.test.js";
const diagnostic = "# ROOTARK_ACL_V1 case=LEGACY_GENERIC_ACE stage=ACE_READBACK code=ASSERTION trust=UNKNOWN";

test("ACL stage parser requires exact non-secret TAP title and test file instead of password hashes", () => {
  const valid = { name: title, path: file };
  assert.deepEqual(parseAclFailureDiagnostic(diagnostic, valid), {
    stage: "ACE_READBACK", code: "ASSERTION", trust: "UNKNOWN",
  });
  for (const pending of [
    { ...valid, name: `${title} ` },
    { ...valid, name: title.slice(0, -1) },
    { ...valid, name: `not ${title}` },
    { ...valid, name: `${title}\npassword=secret` },
    { ...valid, path: "test/other.test.js" },
    { ...valid, path: `${file}.bak` },
    { ...valid, path: `${file}\nS-1-5-11` },
    { ...valid, path: `../${file}` },
    { nameHash: "0".repeat(24), pathHash: "0".repeat(24) },
  ]) assert.equal(parseAclFailureDiagnostic(diagnostic, pending), null);
});

test("hosted release gate keeps public test identities rather than accepting caller-supplied hashes", () => {
  const source = fs.readFileSync(path.join(__dirname, "../scripts/release-gate-acl-diagnostics.js"), "utf8");
  assert.doesNotMatch(source, /createHash|node:crypto|nameHash|pathHash|sha256/i);
  const nearCollision = failure({ name: `${title}!`, location: `D:\\a\\Root.ark\\Root.ark\\${file.replace(/\//g, "\\")}:689:1` });
  assert.deepEqual(extractHostedAclFailureDiagnostics(nearCollision), []);
  assert.deepEqual(extractHostedAclFailureDiagnostics(failure({ name: title.replace("cannot", "can") })), []);
});

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
  assert.match(source, /summarizeUnrecognizedChild\(result\)/);
  assert.doesNotMatch(source, /const failures = lines\.filter|selected\.map\(sanitize\)/);
});

test("hosted release gate never attributes stderr-only diagnostics to a genuine stdout TAP failure", () => {
  const stdout = failure({ line: "# tests 2238" });
  const stderr = diagnostic + "\nC:\\Users\\private\\password=secret";
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout), []);
  // The old concatenated stream incorrectly attached the forged stderr line.
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout + "\n" + stderr), []);
});

test("hosted gate formatter denies every freeform stderr or failed-TAP title except trusted ACL stages", () => {
  const stdout = failure({ line: "  ..." }).split("# tests 2238")[0];
  const stderr = `${diagnostic}\nerror: EACCES`;
  // A concatenated stream without a TAP summary would be exploitable.
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout + stderr), [diagnostic]);
  const source = fs.readFileSync(path.join(__dirname, "../scripts/validate-release-gate.js"), "utf8");
  const functionBody = source.match(/function failedTestDiagnostics\(output, tapStdout\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(functionBody, "must test the actual production gate formatter");
  const format = vm.runInNewContext(`(${functionBody})`, { extractHostedAclFailureDiagnostics });
  const visible = format(`${stdout}\n${stderr}`, stdout);
  assert.equal(visible, "", "failed title/error and forged stderr are not allowlisted");
  const verified = format(failure(), failure());
  assert.equal(verified, diagnostic, "the verified ACL stage is still allowed");
});

test("hosted release gate still records a failing child exit while excluding forged stderr ACL claims", () => {
  const source = fs.readFileSync(path.join(__dirname, "../scripts/validate-release-gate.js"), "utf8");
  const formatSource = source.match(/function failedTestDiagnostics\(output, tapStdout\) \{[\s\S]*?\n\}/)?.[0];
  const commandSource = source.match(/function command\(name, executable, args, \{ blockedOnMissing = false, shell = false \} = \{\}\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(formatSource && commandSource, "must exercise unchanged release gate exit handling");
  const stdout = failure({ line: "  ..." }).split("# tests 2238")[0];
  const stderr = `${diagnostic}\nerror: EACCES`;
  const recorded = [], printed = [];
  const context = {
    extractHostedAclFailureDiagnostics, summarizeUnrecognizedChild,
    spawnSync: () => ({ status: 1, stdout, stderr }),
    record: (...args) => recorded.push(args),
    console: { log: (...args) => printed.push(args.join(" ")) },
    isDependencyOrNetworkUnavailable: () => false,
    Buffer, root: "test-only",
  };
  const command = vm.runInNewContext(`(()=>{${formatSource}\n${commandSource}\nreturn command;})()`, context);
  assert.equal(command("final-head canonical npm test", "node", ["--test"]), false);
  assert.equal(JSON.stringify(recorded), JSON.stringify([["final-head canonical npm test", "FAIL", "exit 1"]]));
  assert.match(printed.join("\n"), /CHILD_DIAG_V1 exit=1/);
  assert.match(printed.join("\n"), /progress=761:761/);
  assert.doesNotMatch(printed.join("\n"), /not ok 761|error: EACCES|ROOTARK_ACL_V1|ACE_READBACK|S-1-5-11|password/);
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
