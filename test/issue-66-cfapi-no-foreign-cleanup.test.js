"use strict";

// Source-level safety regression: disposable Windows CFAPI probes must never
// recursively delete an attacker-replaceable pathname during test teardown.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

test("#66 CFAPI native probe retains disposable fixtures rather than recursive cleanup by pathname", () => {
  const file = path.join(__dirname, "issue-66-windows-cfapi-native.test.js");
  const source = fs.readFileSync(file, "utf8");
  assert.doesNotMatch(source, /\bt\.after\s*\(\s*\(\s*\)\s*=>\s*fs\.rm\s*\(/,
    "a same-UID adversary could replace scratch by pathname before recursive teardown");
  assert.doesNotMatch(source, /\bfs\.rm\s*\(/,
    "no arbitrary recursive pathname cleanup belongs in this probe");
});
