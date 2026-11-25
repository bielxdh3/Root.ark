"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { summarizeFailedChildTests } = require("../scripts/release-gate-child-diagnostics");

const title = "real Edge opt-in UI refuses missing external pins and recovers signed local chunks without HTTP GET";
const file = "test/issue-65-browser-offline-persisted-restore.test.js";

function sample({ name = title, location = file, marker = "# EDGE_OFFLINE_STAGE_V1 cdp-port", status = 1 } = {}) {
  const stdout = ["TAP version 13", `not ok 1 - ${name}`, "  ---",
    `  location: '/checkout/${location}:1:1'`, "  failureType: 'testCodeFailure'",
    "  ...", marker, "1..1", "# tests 1", "# pass 0", "# fail 1",
    "# cancelled 0", "# skipped 0", "# todo 0"].join("\n");
  return summarizeFailedChildTests({ status, stdout });
}

test("canonical failure summaries retain the offline browser's bounded phase hint", () => {
  const result = sample();
  assert.match(result, /CHILD_FAIL_HASH_V1 observed=1/);
  assert.match(result, /edgeStage=CDP_PORT edgeError=UNKNOWN/);
  assert.ok(!result.includes(title));
  assert.ok(!result.includes(file));
});

test("offline stage hints require a matching failed test and a fixed phase token", () => {
  for (const options of [
    { name: "unrelated test" },
    { location: "test/unrelated.test.js" },
    { marker: "# EDGE_OFFLINE_STAGE_V1 not-a-known-stage" },
    { marker: "# EDGE_OFFLINE_STAGE_V1 cdp-port arbitrary text" },
  ]) {
    assert.doesNotMatch(sample(options), /edgeStage=|edgeError=|arbitrary text/);
  }
  assert.equal(sample({ status: 0 }), "");
});
