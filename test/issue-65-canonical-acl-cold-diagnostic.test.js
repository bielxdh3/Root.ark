"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");
const { parseAclFailureDiagnostic, createAclFailureDiagnostic } =
  require("../scripts/acl-test-failure-diagnostic");

const name = "Windows native ACL worker initialization leaves the Node event loop responsive";
const file = "test/issue-65-sync-webdav-windows-junction-acl.test.js";
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
const pending = Object.freeze({ nameHash: hash(name), pathHash: hash(file) });
const line = (stage) =>
  `# ROOTARK_ACL_V1 case=WEB_DAV_COLD stage=${stage} code=ASSERTION trust=UNKNOWN`;

test("canonical ACL diagnosis binds both hashed identities and only two failure classes", () => {
  for (const stage of ["INSUFFICIENT_TICKS", "EVENT_LOOP_STALL"]) {
    assert.deepEqual(parseAclFailureDiagnostic(line(stage), pending), {
      stage, code: "ASSERTION", trust: "UNKNOWN",
    });
    for (const bad of [
      { ...pending, nameHash: "0".repeat(24) },
      { ...pending, pathHash: "0".repeat(24) },
      { ...pending, nameHash: name },
      { ...pending, pathHash: file },
      { name, path: file, nameHash: "0".repeat(24), pathHash: "0".repeat(24) },
    ]) assert.equal(parseAclFailureDiagnostic(line(stage), bad), null);
  }
  for (const invalid of ["OTHER", "UNKNOWN", "INSUFFICIENT_TICKS C:/private", "EVENT_LOOP_STALL token=secret"]) {
    assert.equal(parseAclFailureDiagnostic(line(invalid), pending), null);
  }
  for (const malformed of [
    line("INSUFFICIENT_TICKS").replace("ASSERTION", "RUNTIME"),
    line("EVENT_LOOP_STALL").replace("trust=UNKNOWN", "trust=ACCEPTED"),
    line("EVENT_LOOP_STALL") + " SECRET_PATH",
  ]) assert.equal(parseAclFailureDiagnostic(malformed, pending), null);
});

test("hash matching retains the existing fixed ACL cases without trusting caller titles", () => {
  const oldTitle = "Windows generic access ACEs cannot evade private snapshot ancestor checks";
  const oldFile = "test/issue-65-legacy-deterministic-evidence-manifest.test.js";
  const old = "# ROOTARK_ACL_V1 case=LEGACY_GENERIC_ACE stage=ACE_READBACK code=ASSERTION trust=UNKNOWN";
  assert.deepEqual(parseAclFailureDiagnostic(old, {
    nameHash: hash(oldTitle), pathHash: hash(oldFile),
  }), { stage: "ACE_READBACK", code: "ASSERTION", trust: "UNKNOWN" });
  assert.equal(parseAclFailureDiagnostic(old, {
    nameHash: hash(oldTitle + " "), pathHash: hash(oldFile),
  }), null);
});

test("canonical TAP recorder reveals bounded cold-ACL categories but no raw title/path/secret", () => {
  for (const stage of ["INSUFFICIENT_TICKS", "EVENT_LOOP_STALL"]) {
    const printed = [];
    const tracker = createTapProgressRecorder((message) => printed.push(message));
    const lines = [
      `not ok 1079 - ${name}`,
      String.raw`  location: 'D:\a\Root.ark\Root.ark\test\issue-65-sync-webdav-windows-junction-acl.test.js:169:1'`,
      "  failureType: 'testCodeFailure'",
      "  code: 'ERR_ASSERTION'",
      line(stage),
    ];
    for (const sample of lines) tracker.accept(sample);
    tracker.finish();
    assert.match(printed.join("\n"), new RegExp(`aclStage=${stage} aclError=ASSERTION aclTrust=UNKNOWN`));
    assert.doesNotMatch(printed.join("\n"), /Windows native ACL|Root\.ark|D:\\|password|token=secret|not ok/);
    assert.equal(tracker.state.failures, 1);
  }
});

test("cold diagnostic producer has only pinned stage choices and retains a genuine failure", async () => {
  const printed = [];
  const diag = createAclFailureDiagnostic({ diagnostic: (message) => printed.push(message) }, "WEB_DAV_COLD");
  for (const stage of ["INSUFFICIENT_TICKS", "EVENT_LOOP_STALL"]) {
    diag.stage(stage);
    await assert.rejects(diag.run(() => { throw Object.assign(new Error("fixture-only"), { code: "ERR_ASSERTION" }); }),
      /fixture-only/);
  }
  assert.throws(() => diag.stage("SENSITIVE_CONTENT"), /INVALID_ACL_DIAGNOSTIC_STAGE/);
  // On non-Windows production diagnostics are deliberately disabled.
  if (process.platform === "win32") assert.deepEqual(printed, [line("INSUFFICIENT_TICKS").slice(2), line("EVENT_LOOP_STALL").slice(2)]);
  else assert.deepEqual(printed, []);
});
