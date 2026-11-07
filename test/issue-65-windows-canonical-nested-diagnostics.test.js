"use strict";

const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const test = require("node:test");
const { createTapProgressRecorder, createChildProcessProgress } = require("../scripts/run-windows-canonical-tests");

const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);

test("nested TAP failure retains bounded indentation and location evidence without exposing data", () => {
  const messages = [];
  const tracker = createTapProgressRecorder((message) => messages.push(message));
  const sensitiveName = "nested C:\\private\\hidden secret=NEVER_PRINT";
  const nestedPath = "test/issue-65-windows-canonical-nested-diagnostics.test.js";
  tracker.accept(`# Subtest: ${sensitiveName}`);
  tracker.accept(`    not ok 2 - ${sensitiveName}`);
  tracker.accept(`      location: 'C:\\private\\hidden\\${nestedPath.replaceAll("/", "\\")}:14:3'`);
  tracker.accept("      failureType: 'testCodeFailure'");
  tracker.accept("      code: 'ERR_ASSERTION'");
  assert.match(tracker.safeSummary(), /nestedPending=1/);
  tracker.accept("    ok 3 - subsequent nested test");
  tracker.accept("ok 1 - top-level completed");
  tracker.finish();
  const summary = tracker.safeSummary();
  assert.equal(tracker.state.results, 1);
  assert.equal(tracker.state.failures, 0);
  assert.equal(tracker.state.nestedResults, 2);
  assert.equal(tracker.state.nestedFailures, 1);
  assert.match(summary, /nestedPending=0/);
  assert.match(summary, /nestedFailureDepths=2:0,4:1,6:0,8:0,other:0/);
  assert.match(summary, new RegExp(`lastNestedFailureSha256=${hash(sensitiveName)}`));
  assert.match(messages.join("\n"), new RegExp(`nameSha256=${hash(sensitiveName)}`));
  assert.match(messages.join("\n"), new RegExp(`testPathSha256=${hash(nestedPath)}`));
  assert.match(messages.join("\n"), /code=ERR_ASSERTION/);
  assert.doesNotMatch(summary + messages.join("\n"), /NEVER_PRINT|hidden|C:\\private|secret=|nested C:/);
});

test("nested failure pending transitions on a new result and finish, without altering top-level status", () => {
  const messages = [];
  const tracker = createTapProgressRecorder((message) => messages.push(message));
  tracker.accept("  not ok 1 - inner failure one");
  tracker.accept("    code: 'SQLITE_BUSY'");
  tracker.accept("      not ok 2 - inner failure two");
  tracker.accept("    ok 3 - inner success");
  tracker.finish();
  assert.equal(tracker.state.results, 0);
  assert.equal(tracker.state.failures, 0);
  assert.equal(tracker.state.nestedFailures, 2);
  assert.match(tracker.safeSummary(), /nestedFailureDepths=2:1,4:0,6:1,8:0,other:0/);
  assert.match(messages.join("\n"), /code=SQLITE_BUSY/);
  assert.match(messages.join("\n"), /FAIL nested detail/);
  assert.match(tracker.safeSummary(), /nestedPending=0/);
});

test("nested diagnostics cap individual reports while counting all failures", () => {
  const messages = [];
  const tracker = createTapProgressRecorder((message) => messages.push(message));
  for (let i = 1; i <= 20; i++) tracker.accept(`    not ok ${i} - hidden C:\\private\\token${i}`);
  tracker.finish();
  assert.equal(tracker.state.nestedFailures, 20);
  assert.equal(messages.filter((line) => line.startsWith("FAIL nested detail")).length, 8);
  assert.match(tracker.safeSummary(), /nestedFailureDepths=2:0,4:20,6:0,8:0,other:0/);
  assert.doesNotMatch(messages.join("\n") + tracker.safeSummary(), /C:\\private|token\d/);
});

test("ordinary top-level failures and explicit file boundaries keep established digest semantics", () => {
  const messages = [];
  const tracker = createTapProgressRecorder((message) => messages.push(message));
  tracker.accept("ok 1 - test/backup-restore-sync-atomic.test.js");
  tracker.accept("not ok 2 - top level failure");
  tracker.accept("  code: 'EACCES'");
  tracker.accept("1..2");
  tracker.accept("# tests 2");
  tracker.accept("# fail 1");
  tracker.finish();
  assert.equal(tracker.state.results, 2);
  assert.equal(tracker.state.failures, 1);
  assert.equal(tracker.state.nestedFailures, 0);
  assert.match(tracker.safeSummary(), /fileBoundaries=1/);
  assert.match(tracker.safeSummary(), new RegExp(`lastFileSha256=${hash("test/backup-restore-sync-atomic.test.js")}`));
  assert.match(messages.join("\n"), /FAIL detail index=2 .*code=EACCES/);
  assert.equal(tracker.state.plan, true);
  assert.equal(tracker.state.reportedFailures, 1);
});

test("process lifecycle diagnostics distinguish exit, close, EOF and stream close without raw output", () => {
  const progress = createChildProcessProgress();
  progress.bytes("stdout", 55);
  progress.bytes("stderr", 3);
  progress.ended("stdout");
  progress.closed("stdout", false);
  progress.exited(1, null);
  let summary = progress.safeSummary();
  assert.match(summary, /stdoutBytes=55 stderrBytes=3/);
  assert.match(summary, /stdoutEof=1 stderrEof=0 stdoutClosed=1 stderrClosed=0/);
  assert.match(summary, /childExit=1 childClose=0 childExitCode=1 childSignal=none/);
  progress.ended("stderr");
  progress.closed("stderr", false);
  progress.finished(1, null);
  summary = progress.safeSummary();
  assert.match(summary, /childExit=1 childClose=1/);
  assert.match(summary, /childCloseState=nonzero_exit/);
  assert.match(summary, /stdoutEof=1 stderrEof=1 stdoutClosed=1 stderrClosed=1/);
  assert.doesNotMatch(summary, /private|secret|stdout:|stderr:/);
  const missingExit = createChildProcessProgress();
  missingExit.finished(0, null);
  assert.match(missingExit.safeSummary(), /childCloseState=close_without_exit/);
  const missingEof = createChildProcessProgress();
  missingEof.exited(0, null);
  missingEof.finished(0, null);
  assert.match(missingEof.safeSummary(), /childCloseState=stream_eof_missing/);
});
