"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");
const PR_68_BASE_GLOB = "'cdx/issue68-*'";
const PR_290_HEAD = "'cdx/issue68-owner-recipient-use-w60-20261106'";

for (const workflow of ["security-regression.yml", "codeql.yml", "dependency-review.yml"]) {
  test(`#68 stacked PR base triggers ${workflow} and keeps canonical push coverage`, () => {
    const source = fs.readFileSync(path.join(root, ".github", "workflows", workflow), "utf8");
    const match = source.match(/(?:^|\n)  pull_request:\s*\n([\s\S]*?)(?=\n  [a-z_]+:|\n\S|$)/);
    assert.ok(match, `${workflow} must declare a pull_request event`);
    assert.ok(match[1].includes(PR_68_BASE_GLOB), `${workflow} must cover #68's stacked branch base`);
    assert.match(source, /(?:^|\n)  push:\s*\n    branches:\s*\n      - Root\/main\s*\n/);
  });

  test(`#290 conflicted stacked PR still runs ${workflow} on its exact head push`, () => {
    const source = fs.readFileSync(path.join(root, ".github", "workflows", workflow), "utf8");
    const match = source.match(/(?:^|\n)  push:\s*\n([\s\S]*?)(?=\n  [a-z_]+:|\n\S|$)/);
    assert.ok(match, `${workflow} must declare push`);
    assert.ok(match[1].includes(PR_290_HEAD), `${workflow} must run for the exact #290 head even with merge conflicts`);
    assert.match(match[1], /^    branches:\s*\n      - Root\/main/m, `${workflow} must preserve Root/main push coverage`);
  });
}
