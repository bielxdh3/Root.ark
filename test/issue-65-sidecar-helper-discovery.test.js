"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("standalone sidecar restart subprocess is excluded from automatic Node test discovery", () => {
  const helper = path.resolve(__dirname, "../scripts/fixtures/issue-65-sidecar-restart-child.js");
  const oldAutoDiscoveredPath = path.join(__dirname, "support", "issue-65-sidecar-restart-child.js");

  assert.equal(fs.existsSync(oldAutoDiscoveredPath), false,
    "Node --test must not auto-execute a subprocess that blocks reading stdin");
  assert.equal(fs.existsSync(helper), true,
    "sidecar restart requires a standalone helper outside the test discovery tree");

  // The subprocess must remain a normal stdin-driven CLI for its caller. An
  // invalid framed input is rejected and exits, rather than leaving a reader
  // alive in an otherwise empty child process.
  const result = spawnSync(process.execPath, [helper], {
    input: "{",
    encoding: "utf8",
    timeout: 3000,
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 1, result.stderr);
});
