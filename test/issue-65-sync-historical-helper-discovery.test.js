"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("historical mTLS provider child stays outside automatic Node test discovery", () => {
  const oldPath = path.resolve(__dirname, "support/issue-65-sync-historical-provider-child.js");
  const fixturePath = path.resolve(__dirname, "../scripts/fixtures/issue-65-sync-historical-provider-child.js");

  assert.equal(fs.existsSync(oldPath), false,
    "Node --test must not execute the child without its fork-supplied arguments");
  assert.equal(fs.existsSync(fixturePath), true,
    "the historical mTLS test still needs the real child-process fixture");
});

test("historical recovery operator lock child stays outside automatic Node test discovery", () => {
  const oldPath = path.resolve(__dirname, "support/issue-65-historical-operator-lock-child.js");
  const fixturePath = path.resolve(__dirname, "../scripts/fixtures/issue-65-historical-operator-lock-child.js");
  assert.equal(fs.existsSync(oldPath), false,
    "Node --test must not execute the SQLite lock child without its spawn arguments");
  assert.equal(fs.existsSync(fixturePath), true,
    "the signed recovery operator must retain the real lock-process fixture");
});
