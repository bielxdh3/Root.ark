"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");
const PR_68_BASE_GLOB = "'cdx/issue68-*'";

for (const workflow of ["security-regression.yml", "codeql.yml", "dependency-review.yml"]) {
  test(`#68 stacked PR base triggers ${workflow} without changing push targets`, () => {
    const source = fs.readFileSync(path.join(root, ".github", "workflows", workflow), "utf8");
    const match = source.match(/(?:^|\n)  pull_request:\s*\n([\s\S]*?)(?=\n  [a-z_]+:|\n\S|$)/);
    assert.ok(match, `${workflow} must declare a pull_request event`);
    assert.ok(match[1].includes(PR_68_BASE_GLOB), `${workflow} must cover #68's stacked branch base`);
    assert.match(source, /(?:^|\n)  push:\s*\n    branches:\s*\n      - Root\/main\s*\n  pull_request:/);
  });
}
