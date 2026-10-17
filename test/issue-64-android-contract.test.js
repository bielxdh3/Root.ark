"use strict";

// Contract test for issue #64 (Android client, scaffold step 1).
// Keeps the Kotlin portable-path validator and the Node validator in sync by
// running the same shared fixture through both sides.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { validatePortableRelativePath } = require("../sync-client/rootark-sync-paths");

const root = path.join(__dirname, "..");
const fixturePath = path.join(root, "android/core/src/test/resources/portable-paths.json");
const kotlinTestPath = path.join(root, "android/core/src/test/kotlin/dev/rootark/core/paths/PortablePathValidatorTest.kt");
const kotlinValidatorPath = path.join(root, "android/core/src/main/kotlin/dev/rootark/core/paths/PortablePathValidator.kt");

const fixture = JSON.parse(fs.readFileSync(fixturePath, "utf8"));

function casePath(entry) {
  if (entry.repeat) return entry.repeat.char.repeat(entry.repeat.count);
  return entry.path;
}

test("issue-64 fixture has unique case names and both valid and invalid cases", () => {
  const names = fixture.cases.map((entry) => entry.name);
  assert.equal(new Set(names).size, names.length, "case names must be unique");
  assert.ok(fixture.cases.some((entry) => entry.valid === true));
  assert.ok(fixture.cases.some((entry) => entry.valid === false));
});

test("JS portable path validator matches every shared fixture case", () => {
  for (const entry of fixture.cases) {
    const input = casePath(entry);
    let accepted;
    try {
      validatePortableRelativePath(input, "path");
      accepted = true;
    } catch (error) {
      assert.equal(error.code, "unsafe_path", `${entry.name}: unexpected error code`);
      accepted = false;
    }
    assert.equal(accepted, entry.valid, `${entry.name}: expected valid=${entry.valid}`);
  }
});

test("Kotlin validator and its JUnit test consume the same shared fixture", () => {
  assert.ok(fs.existsSync(kotlinValidatorPath), "Kotlin PortablePathValidator.kt must exist");
  const testSource = fs.readFileSync(kotlinTestPath, "utf8");
  assert.match(testSource, /portable-paths\.json/, "Kotlin test must read the shared fixture");
  const validatorSource = fs.readFileSync(kotlinValidatorPath, "utf8");
  for (const token of ["\\u0000-\\u001f\\u007f","com[1-9]|lpt[1-9]", ".rootark-sync-lock-init-", "512"]) {
    assert.ok(validatorSource.includes(token), `Kotlin validator must contain rule token ${token}`);
  }
});
