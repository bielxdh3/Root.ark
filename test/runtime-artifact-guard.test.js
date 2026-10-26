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
