"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { resolveRange } = require("../scripts/issue-68-full-pr-dependency-range");

const HEAD_BRANCH = "cdx/issue68-owner-recipient-use-w60-20261106";
const BASE_BRANCH = "cdx/issue68-recipient-enrollment-worker43-20261106";
const HEAD = "f0a16d1915359ffc6fd3d025b15817fd491ab2ba";
const BASE = "46b7b0706bb24602d9cb24eaf81e85d4e288b23e";
const LIVE_BASE = "3b2bee11c96a1d14315c801d667cc3a28b5a0218";
const ANCESTOR = "0f513f2bd0b13f1f1a29fd7d53aa83bb781ca76d";
const BEFORE = "da122e403858ea1bcfbd2e99339bf7845609e62d";
const repoName = "bielxdh3/Root.ark";

const input = () => ({
  pr: {
    number: 290, state: "open", merged: false,
    head: { sha: HEAD, ref: HEAD_BRANCH, repo: { full_name: repoName } },
    base: { sha: BASE, ref: BASE_BRANCH, repo: { full_name: repoName } },
  },
  event: { repository: repoName, ref: `refs/heads/${HEAD_BRANCH}`, sha: HEAD, before: BEFORE, name: "push" },
  checkoutHead: HEAD,
  actualBaseTip: LIVE_BASE,
  apiBaseIsAncestor: true,
  mergeBases: [ANCESTOR],
});

test("#68 full PR dependency range is Git merge-base versus current PR HEAD, never the incremental event.before", () => {
  const range = resolveRange(input());
  assert.deepEqual(range, { baseSha: ANCESTOR, headSha: HEAD, prBaseSha: BASE, liveBaseSha: LIVE_BASE });
  assert.notEqual(range.baseSha, BEFORE, "an incremental push diff is not the full stacked PR diff");
  assert.notEqual(range.baseSha, BASE, "the divergent live base is not the PR's common ancestor");
  assert.notEqual(range.liveBaseSha, range.prBaseSha,
    "GitHub's PR base.sha may lag a fast-forwarded live base; resolve from authenticated base ref");
});

test("#68 fails closed on a stale run when another commit moved the official PR HEAD", () => {
  const value = input();
  value.pr.head.sha = "f".repeat(40);
  assert.throws(() => resolveRange(value), /head SHA/i);
});

test("#68 fails closed if its official PR was retargeted to another base", () => {
  const value = input();
  value.pr.base.ref = "Root/main";
  assert.throws(() => resolveRange(value), /base ref/i);
});

test("#68 fails closed on fork, wrong PR, closed PR or wrong head branch", () => {
  const cases = [
    (v) => { v.pr.head.repo.full_name = "attacker/Root.ark"; },
    (v) => { v.pr.base.repo.full_name = "attacker/Root.ark"; },
    (v) => { v.pr.number = 288; },
    (v) => { v.pr.state = "closed"; },
    (v) => { v.pr.head.ref = "cdx/issue63-text-batch-prime-20261106"; },
    (v) => { v.event.ref = "refs/heads/Root/main"; },
    (v) => { v.event.name = "pull_request"; },
  ];
  for (const mutate of cases) {
    const value = input();
    mutate(value);
    assert.throws(() => resolveRange(value), /mismatch|expected|open|repository|branch|event|PR number/i);
  }
});

test("#68 rejects absent or ambiguous merge bases and remote base drift", () => {
  for (const mergeBases of [[], [ANCESTOR, "b".repeat(40)]]) {
    const value = input();
    value.mergeBases = mergeBases;
    assert.throws(() => resolveRange(value), /unique merge.base/i);
  }
  const drift = input();
  drift.actualBaseTip = "c".repeat(40);
  drift.apiBaseIsAncestor = false;
  assert.throws(() => resolveRange(drift), /base tip/i);
  const rewound = input();
  rewound.apiBaseIsAncestor = false;
  assert.throws(() => resolveRange(rewound), /base tip/i);
});

test("#68 rejects checkout SHA mismatch, malformed hashes and missing authorization", () => {
  const mismatch = input();
  mismatch.checkoutHead = "a".repeat(40);
  assert.throws(() => resolveRange(mismatch), /checkout/i);
  const malformed = input();
  malformed.mergeBases = ["bad"];
  assert.throws(() => resolveRange(malformed), /SHA|hash/i);
  const missingBase = input();
  missingBase.pr.base.sha = "";
  assert.throws(() => resolveRange(missingBase), /SHA|hash/i);
});

test("#68 workflow has a distinct full-PR job wired to semantic range outputs, retaining incremental push job", () => {
  const workflow = fs.readFileSync(path.resolve(__dirname, "../.github/workflows/dependency-review.yml"), "utf8");
  const incremental = workflow.match(/\n  default-branch-dependency-review:\n([\s\S]*?)(?=\n  [a-z][a-z0-9-]*:\n|$)/)?.[1];
  const full = workflow.match(/\n  issue68-full-pr-dependency-review:\n([\s\S]*?)(?=\n  [a-z][a-z0-9-]*:\n|$)/)?.[1];
  assert.ok(incremental, "preserve incremental push job");
  assert.match(incremental, /base-ref:\s*\$\{\{\s*github\.event\.before\s*\}\}/);
  assert.match(incremental, /head-ref:\s*\$\{\{\s*github\.sha\s*\}\}/);
  assert.ok(full, "dedicated full PR dependency job required on stacked push");
  assert.match(full, /github\.event_name\s*==\s*'push'/);
  assert.match(full, /fetch-depth:\s*0/);
  assert.match(full, /pull-requests:\s*read/);
  assert.match(full, /node scripts\/issue-68-full-pr-dependency-range\.js/);
  assert.match(full, /base-ref:\s*\$\{\{\s*steps\.range\.outputs\.base-sha\s*\}\}/);
  assert.match(full, /head-ref:\s*\$\{\{\s*steps\.range\.outputs\.head-sha\s*\}\}/);
  assert.match(full, /uses:\s*actions\/dependency-review-action@v5/);
  assert.match(full, /fail-on-severity:\s*high/);
});
