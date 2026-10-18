"use strict";

// Contract test for issue #64 (Android client, scaffold step 1).
// 1. Shared path-validator fixture: the JS validator and the Kotlin validator must agree.
// 2. Wire models: every field of the Kotlin data classes must match the real server
//    responses captured by scripts/issue-64-android-fixtures.js (names, nullability, JSON types).
// 3. Drift: the committed server-responses.json must match a fresh capture from the route handlers.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { validatePortableRelativePath } = require("../sync-client/rootark-sync-paths");
const { FIXTURE_PATH, generateFixtures } = require("../scripts/issue-64-android-fixtures");

const root = path.join(__dirname, "..");
const pathFixturePath = path.join(root, "android/core/src/test/resources/portable-paths.json");
const kotlinTestPath = path.join(root, "android/core/src/test/kotlin/dev/rootark/core/paths/PortablePathValidatorTest.kt");
const kotlinValidatorPath = path.join(root, "android/core/src/main/kotlin/dev/rootark/core/paths/PortablePathValidator.kt");
const kotlinWireFiles = [
  path.join(root, "android/core/src/main/kotlin/dev/rootark/core/sync/SyncModels.kt"),
  path.join(root, "android/core/src/main/kotlin/dev/rootark/core/sync/RootArkApi.kt"),
];
const kotlinWireTestPath = path.join(root, "android/core/src/test/kotlin/dev/rootark/core/sync/ServerWireFixtureTest.kt");

// Result wrappers that are not server wire shapes; they are built from wire models by the client.
const NON_WIRE_CLASSES = new Set(["Accepted", "Rejected"]);
const ENUM_TYPES = new Set(["SyncOperationType"]);
const SYNC_OPERATIONS = new Set(["create", "update", "move", "delete"]);
const REDACTED = "<redacted>";

const pathFixture = JSON.parse(fs.readFileSync(pathFixturePath, "utf8"));

function casePath(entry) {
  if (entry.repeat) return entry.repeat.char.repeat(entry.repeat.count);
  return entry.path;
}

// Parses `data class Name( val a: T, ... )` blocks. Property types keep their `?` suffix.
function parseKotlinDataClasses(source) {
  const classes = new Map();
  const classRe = /data class (\w+)\(([\s\S]*?)\n\s*\)/g;
  for (const match of source.matchAll(classRe)) {
    const props = [];
    const propRe = /^\s*val\s+(\w+)\s*:\s*((?:[^=,\n<]|<[^>]*>)+?)\s*(?:=[^,\n]*)?,?\s*$/gm;
    for (const prop of match[2].matchAll(propRe)) props.push({ name: prop[1], type: prop[2].trim() });
    classes.set(match[1], props);
  }
  return classes;
}

function loadKotlinWireClasses() {
  const classes = new Map();
  for (const file of kotlinWireFiles) {
    for (const [name, props] of parseKotlinDataClasses(fs.readFileSync(file, "utf8"))) classes.set(name, props);
  }
  return classes;
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Returns null when the value fits the Kotlin type, otherwise a reason string.
function kotlinTypeMismatch(kotlinType, value, wireClassNames) {
  const nullable = kotlinType.endsWith("?");
  const base = nullable ? kotlinType.slice(0, -1) : kotlinType;
  if (value === null) return nullable ? null : "null for non-nullable type";
  if (base === "String") return typeof value === "string" ? null : "expected string";
  if (base === "Int" || base === "Long") return Number.isInteger(value) ? null : "expected integer number";
  if (base === "Boolean") return typeof value === "boolean" ? null : "expected boolean";
  if (base.startsWith("Map<")) return isPlainObject(value) ? null : "expected object";
  if (base.startsWith("List<")) return Array.isArray(value) ? null : "expected array";
  if (ENUM_TYPES.has(base)) return typeof value === "string" && SYNC_OPERATIONS.has(value) ? null : "expected sync operation string";
  if (wireClassNames.has(base)) return isPlainObject(value) ? null : "expected object";
  return `unsupported Kotlin type ${kotlinType}`;
}

function shapeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return value.length ? [shapeOf(value[0])] : [];
  if (typeof value === "object") {
    const shape = {};
    for (const key of Object.keys(value).sort()) shape[key] = shapeOf(value[key]);
    return shape;
  }
  return typeof value;
}

test("issue-64 path fixture has unique case names and both valid and invalid cases", () => {
  const names = pathFixture.cases.map((entry) => entry.name);
  assert.equal(new Set(names).size, names.length, "case names must be unique");
  assert.ok(pathFixture.cases.some((entry) => entry.valid === true));
  assert.ok(pathFixture.cases.some((entry) => entry.valid === false));
});

test("JS portable path validator matches every shared fixture case", () => {
  for (const entry of pathFixture.cases) {
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
  for (const token of ["\\u0000-\\u001f\\u007f", "com[1-9]|lpt[1-9]", ".rootark-sync-lock-init-", "512"]) {
    assert.ok(validatorSource.includes(token), `Kotlin validator must contain rule token ${token}`);
  }
});

test("Kotlin wire data classes declare exactly the fields of the captured server responses", async () => {
  const fixture = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const kotlinClasses = loadKotlinWireClasses();
  const wireClassNames = new Set([...kotlinClasses.keys()].filter((name) => !NON_WIRE_CLASSES.has(name)));

  assert.deepEqual([...wireClassNames].sort(), Object.keys(fixture.classes).sort(),
    "every Kotlin wire class needs a captured server sample, and vice versa");

  for (const [className, sample] of Object.entries(fixture.classes)) {
    const props = kotlinClasses.get(className);
    const kotlinNames = props.map((prop) => prop.name).sort();
    const sampleNames = Object.keys(sample).sort();
    assert.deepEqual(kotlinNames, sampleNames, `${className}: Kotlin property names must equal the server field names`);
    for (const prop of props) {
      const reason = kotlinTypeMismatch(prop.type, sample[prop.name], wireClassNames);
      assert.equal(reason, null, `${className}.${prop.name} (${prop.type}): ${reason}`);
    }
  }
});

test("Kotlin wire test deserializes the same captured fixture", () => {
  const source = fs.readFileSync(kotlinWireTestPath, "utf8");
  assert.match(source, /server-responses\.json/, "Kotlin wire test must read the captured fixture");
});

test("committed server-responses.json matches a fresh capture from the real route handlers", async () => {
  const committed = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  const fresh = await generateFixtures();
  assert.deepEqual(shapeOf(fresh.responses), shapeOf(committed.responses), "response shapes drifted; rerun scripts/issue-64-android-fixtures.js --write");
  assert.deepEqual(shapeOf(fresh.classes), shapeOf(committed.classes), "class samples drifted; rerun scripts/issue-64-android-fixtures.js --write");
});

test("captured fixture contains no live secrets", () => {
  const committed = JSON.parse(fs.readFileSync(FIXTURE_PATH, "utf8"));
  for (const [name, response] of Object.entries(committed.responses)) {
    for (const key of ["token", "challengeId"]) {
      if (response.body && key in response.body) {
        assert.equal(response.body[key], REDACTED, `${name}.${key} must be redacted`);
      }
    }
  }
});
