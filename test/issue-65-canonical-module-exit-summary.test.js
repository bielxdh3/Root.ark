"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");

test("canonical summary retains aggregate process exits beyond the detail budget", () => {
  const output = [];
  const tracker = createTapProgressRecorder((line) => output.push(line));
  for (let i = 1; i <= 14; i++) {
    for (const line of [
      "not ok " + i + " - ordinary assertion",
      "  ---", "  failureType: 'testCodeFailure'",
      "  code: 'ERR_ASSERTION'", "  ..."
    ]) tracker.accept(line);
  }
  for (const [i, exit] of [[15, 1], [16, 1], [17, 2]]) {
    for (const line of [
      "not ok " + i + " - ordinary module",
      "  ---", "  failureType: 'testCodeFailure'",
      "  exitCode: " + exit, "  error: 'test failed'",
      "  code: 'ERR_TEST_FAILURE'", "  ..."
    ]) tracker.accept(line);
  }
  tracker.finish();
  assert.equal(tracker.state.failures, 17);
  assert.equal(output.filter((line) => line.startsWith("FAIL detail")).length, 12);
  assert.match(tracker.safeSummary(), /moduleExitGroups=2 moduleExitTotal=3 moduleExitTop=1:2,2:1/);
});

test("canonical summary does not count an assertion or missing exit status as a module exit", () => {
  const tracker = createTapProgressRecorder(() => {});
  for (const line of [
    "not ok 1 - ordinary assertion", "  ---",
    "  failureType: 'testCodeFailure'", "  code: 'ERR_ASSERTION'", "  ...",
    "not ok 2 - ordinary failure", "  ---",
    "  failureType: 'testCodeFailure'", "  code: 'ERR_TEST_FAILURE'", "  ...",
  ]) tracker.accept(line);
  tracker.finish();
  assert.equal(tracker.state.failures, 2);
  assert.match(tracker.safeSummary(), /moduleExitGroups=0 moduleExitTotal=0 moduleExitTop=none/);
});
