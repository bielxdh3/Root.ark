"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { findRealEdge } = require("./support/issue-65-checkpoint-v2-real-edge");

test("real Edge checkpoint fixture selects installed browser on Windows and Ubuntu without skipping", () => {
  const win = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
  const linux = "/usr/bin/microsoft-edge-stable";
  assert.equal(findRealEdge("win32", (candidate) => candidate === win), win);
  assert.equal(findRealEdge("linux", (candidate) => candidate === linux), linux);
  assert.equal(findRealEdge("linux", () => false), null);
  assert.equal(findRealEdge("darwin", () => true), null);
});
