const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "..");
const securityWorkflow = fs.readFileSync(path.join(root, ".github/workflows/security-regression.yml"), "utf8");
const dependencyWorkflow = fs.readFileSync(path.join(root, ".github/workflows/dependency-review.yml"), "utf8");

test("Security Regression runs on canonical branch pushes and pull requests", () => {
  assert.match(securityWorkflow, /on:\s*push:\s*branches:\s*- Root\/main/);
  assert.match(securityWorkflow, /pull_request:\s*branches:\s*- Root\/main/);
});

test("issue 66 CFAPI head pushes trigger the real Windows canonical suite", () => {
  const pushBranches = securityWorkflow.match(/\n  push:\s*\n    branches:\s*\n((?:      - [^\n]+\n)+)/)?.[1];
  assert.ok(pushBranches, "Security Regression must define push branch filters");
  assert.ok(pushBranches.split(/\r?\n/).includes(
    "      - 'cdx/issue66-cfapi-native-w8-20261107'"),
    "a CFAPI head push must not be left with CodeQL as its only hosted check");
  assert.match(securityWorkflow,
    /windows-canonical-suite:[\s\S]*?runs-on: windows-2022[\s\S]*?run: node scripts\/run-windows-canonical-tests\.js/,
    "the covered branch must execute the real Windows canonical suite");
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  assert.equal(packageJson.scripts.test, "node --test",
    "canonical npm test must discover the CFAPI native test");
  assert.ok(fs.existsSync(path.join(root, "test/issue-66-windows-cfapi-native.test.js")));
});

test("issue 66 CFAPI exact head push also executes dependency review without changing main coverage", () => {
  const pushBranches = dependencyWorkflow.match(/\n  push:\s*\n    branches:\s*\n((?:      - [^\n]+\n)+)/)?.[1];
  assert.ok(pushBranches, "Dependency Review must declare an explicit push branch filter");
  assert.match(pushBranches, /      - Root\/main/);
  assert.ok(pushBranches.split(/\r?\n/).includes("      - 'cdx/issue66-cfapi-native-w8-20261107'"),
    "the exact #300 push must have a hosted dependency review job");
});

test("Security Regression does not cancel per-SHA default-branch validation", () => {
  assert.match(securityWorkflow, /group:\s*security-regression-\$\{\{\s*github\.event\.pull_request\.number\s*\|\|\s*format\('run-\{0\}',\s*github\.run_id\)\s*\}\}/);
  assert.match(securityWorkflow, /cancel-in-progress:\s*\$\{\{\s*github\.event_name\s*==\s*'pull_request'\s*\}\}/);
});

test("dependency review compares the exact pushed main commit with its previous commit", () => {
  assert.match(dependencyWorkflow, /on:\s*push:\s*branches:\s*- Root\/main/);
  assert.match(dependencyWorkflow, /pull_request:\s*branches:\s*- Root\/main/);
  assert.match(dependencyWorkflow, /base-ref:\s*\$\{\{\s*github\.event\.before\s*\}\}/);
  assert.match(dependencyWorkflow, /head-ref:\s*\$\{\{\s*github\.sha\s*\}\}/);
});
