"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
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
  assert.match(source, /extractHostedAclFailureDiagnostics\(output\)/);
  assert.match(source, /slice\(0, 12000\)/);
  assert.match(source, /slice\(0, 240\)/);
});
