"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createTapProgressRecorder, createCanonicalTapLineAcceptor } =
  require("../scripts/run-windows-canonical-tests");

const passingTAP = ["TAP version 13", "ok 1 - synthetic pass", "1..1",
  "# tests 1", "# pass 1", "# fail 0"];

function closeWouldPass(tracker) {
  const s = tracker.state;
  // Mirrors the canonical close gate under a clean child exit. The purpose
  // is proving the source of TAP data, not changing its existing strictness.
  return s.plan && s.tests !== null && s.reportedFailures === 0
    && s.failures === 0;
}

test("Windows canonical TAP gate cannot pass when only stderr has a passing TAP footer", () => {
  const diagnostics = [];
  const tracker = createTapProgressRecorder((line) => diagnostics.push(line));
  const fromStderr = createCanonicalTapLineAcceptor(tracker, true);
  for (const line of passingTAP) fromStderr(line);
  assert.equal(tracker.state.results, 0);
  assert.equal(tracker.state.plan, false);
  assert.equal(tracker.state.tests, null);
  assert.equal(tracker.state.reportedFailures, null);
  assert.equal(closeWouldPass(tracker), false,
    "a zero-exit child with only forged stderr TAP must fail closed");
  assert.deepEqual(diagnostics, [], "stderr must not manufacture TAP progress");
});

test("Windows canonical TAP gate accepts real reporter stdout but never promotes stderr failures", () => {
  const diagnostics = [];
  const tracker = createTapProgressRecorder((line) => diagnostics.push(line));
  const fromStdout = createCanonicalTapLineAcceptor(tracker, false);
  const fromStderr = createCanonicalTapLineAcceptor(tracker, true);
  for (const line of passingTAP) fromStdout(line);
  fromStderr("not ok 2 - diagnostic false failure");
  fromStderr("# fail 1");
  assert.equal(tracker.state.results, 1);
  assert.equal(tracker.state.failures, 0);
  assert.equal(tracker.state.tests, 1);
  assert.equal(closeWouldPass(tracker), true,
    "valid stdout TAP remains authoritative independent of untrusted stderr text");
  assert.deepEqual(diagnostics, []);
});
