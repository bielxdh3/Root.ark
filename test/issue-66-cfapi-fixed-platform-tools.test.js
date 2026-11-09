"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

// Test-only process launch must not resolve system interpreters from a
// caller-controlled PATH. This checks tool selection, NOT the identity of
// separately compiled native fixture executables.
test("#66 CFAPI harness never resolves cmd or PowerShell by PATH", () => {
  const buildHelper = fs.readFileSync(
    path.join(__dirname, "support", "issue-66-cfapi-built-artifact.js"), "utf8");
  assert.ok(buildHelper.includes(String.raw`spawnSync("C:\\Windows\\System32\\cmd.exe",`),
    "compiled fixture helper must use the pinned System32 interpreter");
  assert.doesNotMatch(buildHelper, /spawnSync\s*\(\s*["']cmd\.exe["']/i);
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
    if (powerShellCase) {
      const fixedDefinition =
        String.raw`const systemPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";`;
      assert.ok(code.includes(fixedDefinition), `${name} must pin PowerShell`);
      assert.ok(code.includes("spawnSync(systemPowerShell,"),
        `${name} must use the pinned PowerShell path`);
    } else {
      const executable = name.includes("deny-callback")
        ? "deny-fetch.exe" : "positive-shape.exe";
      assert.ok(code.includes(`"${executable}", vcvars)`),
        `${name} must compile the allowlisted fixture via pinned helper`);
      assert.ok(code.includes("runCompiledFixture(receipt,"),
        `${name} must run via the build receipt rather than an arbitrary path`);
      assert.doesNotMatch(code, /spawnSync\s*\(\s*executable\b/,
        `${name} must not bypass the receipt with an executable pathname`);
    }
  }
});

test("#66 native ACL tool launches use literal paths rather than a dynamic executable dispatcher", () => {
  const code = fs.readFileSync(path.join(__dirname,
    "issue-66-cfapi-acl-preflight-native.test.js"), "utf8");
  // Check every spawnSync call site, not merely the presence of two expected
  // strings: another launch through process.env, a new local variable or a
  // lookup table must fail even if the two literal launches remain in place.
  const launchTargets = (sourceText) => [...sourceText.matchAll(/\bspawnSync\s*\(\s*([^,\r\n]+)\s*,/g)]
    .map((match) => match[1].trim());
  const expected = [
    String.raw`"C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe"`,
    String.raw`"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"`,
  ];
  assert.deepEqual(launchTargets(code), expected,
    "the only native ACL spawnSync targets must be two literal absolute Windows tool paths");
  for (const injected of [
    "spawnSync(process.env.UNTRUSTED_EXE, []);",
    "spawnSync(dynamicExecutable, []);",
    "spawnSync(fixedTools[tool], []);",
  ]) {
    assert.notDeepEqual(launchTargets(`${code}\n${injected}`), expected,
      "an added dynamic executable launch must invalidate the static guard");
  }
});
