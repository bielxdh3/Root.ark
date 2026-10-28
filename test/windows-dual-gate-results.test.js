"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { requireBothWindowsJobs } = require("../scripts/check-windows-ci-results");

test("aggregate accepts success only from both independent Windows jobs", () => {
  assert.equal(requireBothWindowsJobs("success", "success"), true);
});

test("aggregate rejects failed, cancelled, skipped, missing, and misleading statuses", () => {
  for (const bad of ["failure", "cancelled", "skipped", "", undefined, "SUCCESS", "success ",
    "neutral", "timed_out", "success\nnot-success"]) {
    assert.throws(() => requireBothWindowsJobs(bad, "success"), /Windows jobs not both successful/);
    assert.throws(() => requireBothWindowsJobs("success", bad), /Windows jobs not both successful/);
  }
});
