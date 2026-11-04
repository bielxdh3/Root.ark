"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");

test("backup mutation child processes must not be discovered by canonical node --test", () => {
  // Node's no-argument --test discovers JS/CJS files beneath test/. These
  // one-shot executables are only safe when explicitly spawned with a private
  // fixture cwd and action; otherwise they write to the checkout itself.
  for (const name of [
    "issue-65-retention-strict-child.cjs",
    "issue-65-startup-cleanup-child.cjs",
    "w147-strict-backup-child.cjs",
  ]) {
    const accidentalTest = path.join(root, "test", "support", name);
    const executable = path.join(root, "lab", "issue-65-test-processes", name);
    assert.equal(fs.existsSync(accidentalTest), false,
      "a destructive child executable may not live under test/: " + name);
    assert.equal(fs.statSync(executable).isFile(), true,
      "the dedicated child executable must remain runnable: " + name);
  }
});
