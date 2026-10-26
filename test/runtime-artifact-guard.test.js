const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { validateRuntimeArtifacts } = require("../scripts/validate-runtime-artifacts");

test("runtime artifact guard passes cleanly and fails on a disposable seeded database", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-artifact-"));
  const gitEnv = { ...process.env };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"]) {
    delete gitEnv[name];
  }
  try {
    execFileSync("git", ["init", "-q"], { cwd: root, env: gitEnv });
    // A repo-level core.worktree may be stale even after inherited Git env
    // variables are removed. The guard must explicitly pin its own root.
    execFileSync("git", ["config", "core.worktree", path.join(root, "stale-other-worktree")],
      { cwd: root, env: gitEnv });
    // A caller's unrelated worktree must not steer the gate's git inspection.
    const originalWorkTree = process.env.GIT_WORK_TREE;
    process.env.GIT_WORK_TREE = path.join(root, "unrelated-worktree");
    try {
      assert.doesNotThrow(() => validateRuntimeArtifacts(root));
      fs.mkdirSync(path.join(root, "data"), { recursive: true });
      fs.writeFileSync(path.join(root, "data", "rootark.sqlite"), "disposable");
      assert.throws(() => validateRuntimeArtifacts(root), /Runtime artifact guard failed/);
    } finally {
      if (originalWorkTree === undefined) delete process.env.GIT_WORK_TREE;
      else process.env.GIT_WORK_TREE = originalWorkTree;
    }
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runtime artifact guard refuses a linked data directory hiding a protected database", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-artifact-linked-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: root,
      env: Object.fromEntries(Object.entries(process.env).filter(([name]) =>
        !["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"].includes(name))) });
    fs.mkdirSync(path.join(root, "outside"));
    fs.writeFileSync(path.join(root, "outside", "private.sqlite"), "disposable-only");
    fs.mkdirSync(path.join(root, "data"));
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "data", "linked"),
      process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => validateRuntimeArtifacts(root), /Runtime artifact guard failed/,
      "junctions must not let a protected runtime file escape the artifact scan");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("runtime artifact guard refuses a linked top-level uploads root even when empty", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-artifact-root-link-"));
  try {
    execFileSync("git", ["init", "-q"], { cwd: root,
      env: Object.fromEntries(Object.entries(process.env).filter(([name]) =>
        !["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"].includes(name))) });
    fs.mkdirSync(path.join(root, "outside"));
    fs.symlinkSync(path.join(root, "outside"), path.join(root, "uploads"),
      process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => validateRuntimeArtifacts(root), /Runtime artifact guard failed/,
      "a linked empty upload root is not a provably clean storage boundary");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
