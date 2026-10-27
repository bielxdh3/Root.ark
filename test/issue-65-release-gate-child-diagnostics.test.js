"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { Buffer } = require("node:buffer");
const { summarizeUnrecognizedChild } = require("../scripts/release-gate-child-diagnostics");
const { extractHostedAclFailureDiagnostics } = require("../scripts/release-gate-acl-diagnostics");

const poisoned = ["password=my-dangerous-value", "Bearer sent-in-stdout",
  "D:\\a\\Root.ark\\fake\\private.key", "S-1-5-11", "host.internal.test",
  "synthetic_credential_marker_abcdefghijklmnopqrstuvwxyz0123456789", "ROOTARK_ACL_V1 case=LEGACY_GENERIC_ACE stage=ACE_WRITE code=ASSERTION trust=UNKNOWN"].join("\n");

test("realistic 79KB non-TAP Windows Node child exception yields bounded category without source details", () => {
  const stdout = `${"unrecognized opaque stdout\n".repeat(3000)}\nnode:internal/modules/cjs/loader:1234\nReferenceError: private key reference\n${poisoned}`;
  const value = summarizeUnrecognizedChild({ status: 1, signal: null, stdout, stderr: poisoned });
  assert.match(value, /^CHILD_DIAG_V1 /);
  assert.match(value, /exit=1 signal=none spawn=none/);
  assert.match(value, /footer=missing progress=none/);
  assert.match(value, /hint=node_trace/);
  assert.ok(value.length < 240);
  assert.doesNotMatch(value, /password|Bearer|private|S-1-|host\.internal|ghp_|ROOTARK|ACE_WRITE|ReferenceError/i);
});

test("partial TAP reports first and last bounded ordinal, never arbitrary test names", () => {
  const stdout = `TAP version 13\nok 1 - ${poisoned.replace(/\n/g, " ")}\nok 7 - leaked hostname\nnode:internal/test_runner:22`;
  const value = summarizeUnrecognizedChild({ status: 1, stdout });
  assert.match(value, /footer=missing progress=1:7/);
  assert.match(value, /reporter=tap/);
  assert.doesNotMatch(value, /hostname|password|private|S-1-|ROOTARK|ACE_WRITE/i);
});

test("TAP footer is valid only if plan and all aggregate counters are consistent", () => {
  const start = "TAP version 13\nok 1 - secret\nnot ok 2 - hidden\n1..2\n";
  const footer = "# tests 2\n# suites 0\n# pass 1\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 11.251\n";
  assert.match(summarizeUnrecognizedChild({ status: 1, stdout: start + footer }), /footer=valid progress=1:2/);
  assert.match(summarizeUnrecognizedChild({ status: 1, stdout: start + footer.replace("# fail 1", "# fail 0") }), /footer=invalid/);
  assert.match(summarizeUnrecognizedChild({ status: 1, stdout: start.replace("1..2", "1..3") + footer }), /footer=invalid/);
  assert.match(summarizeUnrecognizedChild({ status: 1, stdout: start.replace("TAP version 13", "arbitrary output") + footer }), /footer=missing/);
});

test("signals, spawn errors, malformed exit values are finite safe categories only", () => {
  assert.match(summarizeUnrecognizedChild({ status: null, signal: "SIGKILL", error: { code: "ENOBUFS" } }),
    /exit=unknown signal=SIGKILL spawn=ENOBUFS/);
  assert.match(summarizeUnrecognizedChild({ status: 256, signal: "S-1-5-11", error: { code: "password=secret" } }),
    /exit=unknown signal=other spawn=other/);
  assert.match(summarizeUnrecognizedChild({ status: 1, signal: null, error: { code: "ENOENT" } }),
    /exit=1 signal=none spawn=ENOENT/);
});

test("untrusted reporter markers and counterfeit ACL lines do not produce verified failure attribution", () => {
  const spoof = ["the strings 'not ok 33 - secret' and '# tests 4' are not TAP records",
    "TAP version 13 injected mid-line", "# ROOTARK_ACL_V1 case=LEGACY_GENERIC_ACE stage=START code=ASSERTION trust=UNKNOWN",
    "ok 99999999999 - oversized", "ok 2 - exception"];
  const actual = summarizeUnrecognizedChild({ status: 1, stdout: spoof.join("\n"), stderr: "TAP version 13\n1..1\n# tests 1\n# pass 1\n# fail 0" });
  assert.match(actual, /footer=missing/);
  assert.match(actual, /progress=none/);
  assert.doesNotMatch(actual, /ROOTARK|START|password|secret|exception/i);
});

test("large newline-saturated stdout retains bounded first and last ordinals without raw middle content", () => {
  const stdout = "TAP version 13\nok 1 - first-name-secret\n"
    + "middle-secret\n".repeat(140000)
    + "ok 2238 - last-name-secret\n1..2238\n# tests 2238\n# pass 2238\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n";
  const value = summarizeUnrecognizedChild({ status: 1, stdout });
  assert.match(value, /footer=valid progress=1:2238 reporter=tap/);
  assert.match(value, /window=sampled$/);
  assert.ok(value.length < 240);
  assert.doesNotMatch(value, /secret|middle/);
});

test("hosted release gate categorizes non-TAP child without stderr or ACL spoof and keeps FAIL contract", () => {
  const source = fs.readFileSync(path.join(__dirname, "../scripts/validate-release-gate.js"), "utf8");
  const stdout = `${"progress hidden\n".repeat(4500)}node:internal/test_runner:456\n`;
  const result = { status: 1, stdout, stderr: poisoned,
    error: { code: "SECRET_PRIVATE_APIKEY", message: poisoned } };
  const output = summarizeUnrecognizedChild(result);
  assert.match(output, /CHILD_DIAG_V1 exit=1 signal=none spawn=other footer=missing/);
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout), []);
  assert.match(source, /record\(name, "FAIL", `exit \$\{result\.status \?\? "unknown"\}`\)/);
  assert.match(source, /summarizeUnrecognizedChild\(result\)/);
  assert.match(source, /return false;\s*\}\s*function checkLock/);
  assert.doesNotMatch(output, /password|Bearer|private|S-1-|host\.internal|ghp_|ROOTARK|ACE_WRITE|node:internal/);
});

test("existing generic TAP error/title/location lines must never leak even when allowlisted ACL stage is absent", () => {
  const source = fs.readFileSync(path.join(__dirname, "../scripts/validate-release-gate.js"), "utf8");
  const stdout = ["TAP version 13", `not ok 9 - ${poisoned.replace(/\n/g, " ")}`,
    "  ---", `  location: 'C:\\Users\\private\\SECRET.txt:14:4'`,
    `  error: ${poisoned.replace(/\n/g, " ")}`, "  ...", "1..9", "# tests 9",
    "# pass 8", "# fail 1", "# cancelled 0", "# skipped 0", "# todo 0"].join("\n");
  const log = summarizeUnrecognizedChild({ status: 1, stdout, stderr: `error: ${poisoned.replace(/\n/g, " ")}` });
  assert.deepEqual(extractHostedAclFailureDiagnostics(stdout), []);
  assert.match(log, /CHILD_DIAG_V1 exit=1/);
  assert.match(log, /progress=9:9/);
  assert.match(source, /return \[\.\.\.new Set\(extractHostedAclFailureDiagnostics\(tapStdout\)\)\]/);
  assert.doesNotMatch(source, /selected\.map\(sanitize\)|failures\.slice\(/);
  assert.doesNotMatch(log, /password|Bearer|private|S-1-|host\.internal|ghp_|ROOTARK|ACE_WRITE|SECRET\.txt|fake\\/i);
});
