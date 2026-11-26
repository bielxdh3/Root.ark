"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");

test("canonical Windows TAP reports a failed test-file process exit without exposing its module label", () => {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), "rootark-module-exit-probe-"));
  try {
    fs.mkdirSync(path.join(dir, "test"));
    fs.writeFileSync(path.join(dir, "test", "backup-restore-transaction-boundary.test.js"), "process.exit(1);\n");
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const child = spawnSync(process.execPath,
      ["--test", "--test-reporter=tap", "test/backup-restore-transaction-boundary.test.js"],
      { cwd: dir, env, encoding: "utf8", windowsHide: true, timeout: 15000 });
    assert.equal(child.status, 1);
    assert.equal(child.signal, null);
    const diagnostics = [];
    const tracker = createTapProgressRecorder((line) => diagnostics.push(line));
    for (const line of child.stdout.split(/\r?\n/)) tracker.accept(line);
    tracker.finish();
    assert.equal(tracker.state.failures, 1);
    assert.match(diagnostics.join("\n"), /failureType=testCodeFailure code=ERR_TEST_FAILURE category=runtime moduleExitCode=1/);
    assert.doesNotMatch(diagnostics.join("\n"), /backup-restore|rootark-module-exit|[A-Za-z]:\\|process\.exit/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("malformed TAP process status cannot leak secret text or claim a bounded module exit", () => {
  const diagnostics = [];
  const tracker = createTapProgressRecorder((line) => diagnostics.push(line));
  const secret = "credential=password-private-DO-NOT-LOG";
  for (const line of [
    `not ok 28 - ${secret}`,
    "  failureType: 'testCodeFailure'",
    "  code: 'ERR_TEST_FAILURE'",
    `  exitCode: 1 ${secret}`,
    "  exitCode: 9999",
    "  exitCode: -1",
  ]) tracker.accept(line);
  tracker.finish();
  const output = diagnostics.join("\n");
  assert.doesNotMatch(output, /moduleExitCode=|credential=|password-private|DO-NOT-LOG/);
});

test("a late exitCode outside the failed module YAML cannot impersonate its process status", () => {
  const output = [];
  const tracker = createTapProgressRecorder((line) => output.push(line));
  for (const line of [
    "TAP version 13",
    "not ok 9 - ordinary failed test",
    "  ---",
    "  failureType: 'testCodeFailure'",
    "  code: 'ERR_TEST_FAILURE'",
    "  error: 'test failed'",
    "  ...",
    "  exitCode: 137",
    "ok 10 - unaffected test",
  ]) tracker.accept(line);
  tracker.finish();
  const report = output.join("\n");
  assert.match(report, /failureType=testCodeFailure code=ERR_TEST_FAILURE category=runtime/);
  assert.doesNotMatch(report, /moduleExitCode=/);
  assert.equal(tracker.state.failures, 1);
});

test("post-YAML failure type, code and location cannot combine with a prior process exit", () => {
  const diagnostic = [];
  const tracker = createTapProgressRecorder((line) => diagnostic.push(line));
  for (const line of [
    "TAP version 13",
    "not ok 9 - ordinary failed test",
    "  ---",
    "  error: 'test failed'",
    "  exitCode: 137",
    "  ...",
    "  failureType: 'testCodeFailure'",
    "  code: 'ERR_TEST_FAILURE'",
    "  location: '/private/test/backup-restore-transaction-boundary.test.js:1:1'",
    "ok 10 - unrelated successful test",
  ]) tracker.accept(line);
  tracker.finish();
  const report = diagnostic.join("\n");
  assert.equal(tracker.state.failures, 1);
  assert.doesNotMatch(report, /moduleExitCode=137/);
  assert.doesNotMatch(report, /testCodeFailure|ERR_TEST_FAILURE|backup-restore-transaction|\/private\//);
});

test("pre-YAML code cannot combine with later module exit evidence", () => {
  const diagnostic = [];
  const tracker = createTapProgressRecorder((line) => diagnostic.push(line));
  for (const line of [
    "not ok 1 - ordinary failed test",
    "  code: 'ERR_TEST_FAILURE'",
    "  ---",
    "  failureType: 'testCodeFailure'",
    "  error: 'test failed'",
    "  exitCode: 137",
    "  ...",
    "ok 2 - unaffected test",
  ]) tracker.accept(line);
  tracker.finish();
  const report = diagnostic.join("\n");
  assert.equal(tracker.state.failures, 1);
  assert.doesNotMatch(report, /moduleExitCode=137/);
});

test("real Node TAP stack identifies the assertion rather than its declaration without exposing source", () => {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), "rootark-stack-probe-"));
  try {
    fs.mkdirSync(path.join(dir, "test"));
    fs.writeFileSync(path.join(dir, "test", "fixture.test.js"), [
      'const test = require("node:test");',
      'const assert = require("node:assert/strict");',
      'test("private synthetic assertion", () => {',
      '  assert.strictEqual("private actual", "private expected");',
      '});',
    ].join("\n"));
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const child = spawnSync(process.execPath,
      ["--test", "--test-reporter=tap", "test/fixture.test.js"],
      { cwd: dir, env, encoding: "utf8", windowsHide: true, timeout: 15000 });
    assert.equal(child.status, 1);
    assert.equal(child.signal, null);
    const messages = [];
    const tracker = createTapProgressRecorder((line) => messages.push(line));
    for (const line of child.stdout.split(/\r?\n/)) tracker.accept(line);
    tracker.finish();
    assert.equal(tracker.state.failures, 1);
    const output = messages.join("\n");
    assert.match(output, /locationLine=3 assertionLine=4/);
    assert.doesNotMatch(output, /private|fixture\.test\.js|rootark-stack-probe-/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("assertion location is collected only from the failed result's stack block", () => {
  const messages = [];
  const tracker = createTapProgressRecorder((line) => messages.push(line));
  for (const line of [
    "not ok 1 - failed fixture",
    "  ---",
    "  location: '/private/test/fixture.test.js:3:1'",
    "  code: 'ERR_ASSERTION'",
    "  error: |-",
    "    at forged (/private/test/fixture.test.js:999:1)",
    "  stack: |-",
    "    TestContext.<anonymous> (/private/test/fixture.test.js:4:1)",
    "  ...",
    "not ok 2 - second failed fixture",
    "  ---",
    "  location: '/private/test/fixture.test.js:7:1'",
    "  stack: |-",
    "    TestContext.<anonymous> (/private/test/foreign.test.js:8:1)",
    "  error: |-",
    "    at forged (/private/test/fixture.test.js:999:1)",
    "  ...",
  ]) tracker.accept(line);
  tracker.finish();
  const output = messages.join("\n");
  assert.match(output, /locationLine=3 assertionLine=4/);
  assert.match(output, /locationLine=7(?:\n|$)/);
  assert.doesNotMatch(output, /assertionLine=999|private|fixture\.test\.js|foreign\.test\.js/);
});

test("assertion location cannot be borrowed from a different tree with the same test basename", () => {
  for (const [location, foreign, own] of [
    ["/private/test/fixture.test.js", "/foreign/test/fixture.test.js", "/private/test/fixture.test.js"],
    [String.raw`D:\\private\\test\\fixture.test.js`, String.raw`D:\foreign\test\fixture.test.js`, String.raw`D:\private\test\fixture.test.js`],
  ]) {
    const messages = [];
    const tracker = createTapProgressRecorder((line) => messages.push(line));
    for (const line of [
      "not ok 1 - private assertion",
      "  ---",
      "  location: '" + location + ":3:1'",
      "  code: 'ERR_ASSERTION'",
      "  stack: |-",
      "    TestContext.<anonymous> (" + foreign + ":999:1)",
      "    TestContext.<anonymous> (" + own + ":4:1)",
      "  ...",
      "not ok 2 - no matching frame",
      "  ---",
      "  location: '" + location + ":7:1'",
      "  stack: |-",
      "    TestContext.<anonymous> (" + foreign + ":999:1)",
      "  ...",
    ]) tracker.accept(line);
    tracker.finish();
    const report = messages.join("\n");
    assert.equal(tracker.state.failures, 2);
    assert.match(report, /locationLine=3 assertionLine=4(?: |\n|$)/);
    assert.match(report, /locationLine=7(?:\n|$)/);
    assert.doesNotMatch(report, /assertionLine=999|private|foreign|fixture\.test\.js/);
  }
});
