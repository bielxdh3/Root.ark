"use strict";

// This is a fail-closed gate for the COMPLETE delta of stacked PR #300.
// The ordinary push dependency-review job compares event.before..github.sha;
// it is not equivalent to the PR delta when the official base has advanced.
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");

const HEAD_BRANCH = "cdx/issue66-cfapi-native-w8-20261107";
const BASE_BRANCH = "feature/issue66-inventory-20261106";
const REPOSITORY = "bielxdh3/Root.ark";
const SHA = /^[a-f0-9]{40}$/;

function requireSha(value, label) {
  if (typeof value !== "string" || !SHA.test(value)) throw new Error(`Invalid ${label} SHA`);
  return value;
}

function resolveRange({ pr, event, checkoutHead, actualBaseTip, apiBaseIsAncestor, mergeBases }) {
  if (!event || event.name !== "push" || event.ref !== `refs/heads/${HEAD_BRANCH}`) {
    throw new Error("Unexpected event/branch for full PR dependency review");
  }
  if (event.repository !== REPOSITORY) throw new Error("Repository mismatch for full PR dependency review");
  if (!pr || pr.number !== 300 || pr.state !== "open" || pr.merged !== false) {
    throw new Error("Expected open PR number 300");
  }
  if (pr.head?.ref !== HEAD_BRANCH) throw new Error("Head branch mismatch");
  if (pr.base?.ref !== BASE_BRANCH) throw new Error("PR base ref mismatch / unauthorized retarget");
  if (pr.head?.repo?.full_name !== REPOSITORY || pr.base?.repo?.full_name !== REPOSITORY) {
    throw new Error("PR repository mismatch / fork denied");
  }
  const eventHead = requireSha(event.sha, "event head");
  const apiHead = requireSha(pr.head.sha, "API head");
  const apiBase = requireSha(pr.base.sha, "API base");
  const liveBase = requireSha(actualBaseTip, "live base tip");
  const localHead = requireSha(checkoutHead, "checkout head");
  if (eventHead !== apiHead) throw new Error("PR head SHA differs from triggered event SHA");
  if (eventHead !== localHead) throw new Error("Checkout head SHA differs from triggered event SHA");
  // GitHub's PR base.sha may lag the live base ref. Allow only a verified
  // fast-forward of the exact authorized base branch; reject a rewrite.
  if (apiBaseIsAncestor !== true) throw new Error("PR base tip rewound or does not descend from API base SHA");
  if (!Array.isArray(mergeBases) || mergeBases.length !== 1) {
    throw new Error("A unique merge-base is required for a complete PR dependency delta");
  }
  const common = requireSha(mergeBases[0], "merge-base");
  return Object.freeze({ baseSha: common, headSha: eventHead, prBaseSha: apiBase, liveBaseSha: liveBase });
}

function git(args) {
  return execFileSync("git", args, { encoding: "utf8", timeout: 25000,
    stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function isAncestor(ancestor, descendant) {
  const result = spawnSync("git", ["merge-base", "--is-ancestor", ancestor, descendant], {
    encoding: "utf8", timeout: 25000, windowsHide: true,
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && result.status !== 1) throw new Error("Unable to verify PR base ancestry");
  return result.status === 0;
}

async function main() {
  if (!process.env.GITHUB_TOKEN || !process.env.GITHUB_OUTPUT) {
    throw new Error("Authenticated GitHub token and step output are mandatory");
  }
  const event = {
    repository: process.env.GITHUB_REPOSITORY,
    ref: process.env.GITHUB_REF,
    sha: process.env.GITHUB_SHA,
    name: process.env.GITHUB_EVENT_NAME,
  };
  if (event.repository !== REPOSITORY || event.ref !== `refs/heads/${HEAD_BRANCH}` || event.name !== "push") {
    throw new Error("Unexpected GitHub repository/branch/event for PR #300");
  }
  requireSha(event.sha, "event head");
  const controller = AbortSignal.timeout(15000);
  const response = await fetch(`https://api.github.com/repos/${REPOSITORY}/pulls/300`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "rootark-pr300-dependency-range",
    },
    signal: controller,
  });
  if (!response.ok) throw new Error(`Cannot authenticate PR #300 metadata, HTTP ${response.status}`);
  const pr = await response.json();
  if (pr?.base?.ref !== BASE_BRANCH || pr?.head?.ref !== HEAD_BRANCH || pr?.head?.sha !== event.sha) {
    throw new Error("PR #300 base/head changed since workflow event; fail closed");
  }

  // checkout@v7 with fetch-depth:0 obtains the full repository history.
  // Explicitly fetch the CURRENT named base ref without modifying any branch,
  // then verify the remote has not moved in the meantime.
  const checkoutHead = git(["rev-parse", "HEAD"]);
  git(["fetch", "--no-tags", "origin", `refs/heads/${BASE_BRANCH}`]);
  const actualBaseTip = requireSha(git(["rev-parse", "FETCH_HEAD"]), "fetched base tip");
  const remote = git(["ls-remote", "origin", `refs/heads/${BASE_BRANCH}`]);
  if (remote !== `${actualBaseTip}\trefs/heads/${BASE_BRANCH}`) {
    throw new Error("Base ref moved or disappeared during PR #300 dependency review");
  }
  requireSha(pr.base.sha, "API base");
  const apiBaseIsAncestor = isAncestor(pr.base.sha, actualBaseTip);
  const mergeBases = git(["merge-base", "--all", actualBaseTip, event.sha]).split(/\r?\n/).filter(Boolean);
  const range = resolveRange({ pr, event, checkoutHead, actualBaseTip, apiBaseIsAncestor, mergeBases });
  fs.appendFileSync(process.env.GITHUB_OUTPUT, `base-sha=${range.baseSha}\nhead-sha=${range.headSha}\n`, { encoding: "utf8" });
  process.stdout.write("PR #300 full dependency delta range: authenticated base-ref, checked head and unique merge-base; not event.before\n");
}

if (require.main === module) {
  main().catch((error) => {
    // Never print tokens, filesystem paths, raw API bodies, or private metadata.
    process.stderr.write(`PR #300 full dependency delta unavailable: ${error.message.replace(/[\r\n]/g, " ")}\n`);
    process.exitCode = 1;
  });
}

module.exports = { resolveRange };
