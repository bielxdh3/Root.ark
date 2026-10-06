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

test("dependency review compares the exact pushed main commit with its previous commit", () => {
  assert.match(dependencyWorkflow, /on:\s*push:\s*branches:\s*- Root\/main/);
  assert.match(dependencyWorkflow, /pull_request:\s*branches:\s*- Root\/main/);
  assert.match(dependencyWorkflow, /base-ref:\s*\$\{\{\s*github\.event\.before\s*\}\}/);
  assert.match(dependencyWorkflow, /head-ref:\s*\$\{\{\s*github\.sha\s*\}\}/);
});
