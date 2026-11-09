"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// Test-only process launch must not resolve system interpreters from a
// caller-controlled PATH. This checks tool selection, NOT the identity of
// separately compiled native fixture executables.
test("#66 CFAPI harness never resolves cmd or PowerShell by PATH", () => {
  const files = [
    "issue-66-cfapi-deny-callback-native.test.js",
    "issue-66-cfapi-positive-shape-native.test.js",
    "issue-66-cfapi-acl-fixture-security.test.js",
  ];
  for (const name of files) {
    const code = fs.readFileSync(path.join(__dirname, name), "utf8");
    assert.doesNotMatch(code, /spawnSync\s*\(\s*["'](?:cmd|powershell)\.exe["']/i,
      `${name} must not dispatch a PATH-resolved system interpreter`);
    const powerShellCase = name === "issue-66-cfapi-acl-fixture-security.test.js";
    const fixedDefinition = powerShellCase
      ? String.raw`const systemPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";`
      : String.raw`const systemCmd = "C:\\Windows\\System32\\cmd.exe";`;
    assert.ok(code.includes(fixedDefinition),
      `${name} must pin the expected full Windows system tool path`);
    assert.ok(code.includes(powerShellCase
      ? "spawnSync(systemPowerShell," : "spawnSync(systemCmd,"),
    `${name} must actually use its pinned tool path`);
  }
});
