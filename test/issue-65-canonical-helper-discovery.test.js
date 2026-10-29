"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const HELPERS = [
  "issue-65-w110-foreign-uid-mover.js",
  "w147-inventory-reconciliation-child.cjs",
  "w147-strict-backup-http-server.cjs",
  "w147-trash-provider-child.cjs",
];

test("native child-process fixtures cannot be executed by the canonical node --test discovery", () => {
  for (const helper of HELPERS) {
    const executable = path.join(__dirname, "../lab/issue-65-test-processes", helper);
    const accidentalTest = path.join(__dirname, "support", helper);
    assert.equal(fs.existsSync(executable), true, "missing external process helper: " + helper);
    assert.equal(fs.existsSync(accidentalTest), false,
      "canonical node --test would execute this worker as an unauthenticated test: " + helper);
  }
});
