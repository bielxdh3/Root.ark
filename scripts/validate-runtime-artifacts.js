const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const protectedRoots = ["uploads", "temp", "data/backups", "data/trash", "data/quarantine"];
const protectedFiles = [/^data\/.*\.(sqlite|sqlite-wal|sqlite-shm)$/i, /^data\/.*\.(sqlite-wal|sqlite-shm)$/i, /^data\/(token|credential)/i];

function hasContent(root, relative) {
  const target = path.join(root, relative);
  return fs.existsSync(target) && fs.readdirSync(target).length > 0;
}

function findProtectedFiles(root, relative = "data") {
  const target = path.join(root, relative);
  if (!fs.existsSync(target)) return [];
  const found = [];
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const child = path.posix.join(relative.replace(/\\/g, "/"), entry.name);
    if (entry.isDirectory()) found.push(...findProtectedFiles(root, child));
    else if (protectedFiles.some((pattern) => pattern.test(child))) found.push(child);
  }
  return found;
}

function validateRuntimeArtifacts(root = process.cwd()) {
  const violations = [...protectedRoots.filter((relative) => hasContent(root, relative)), ...findProtectedFiles(root)];
  // The caller may be operating another worktree. Inspect this root's .git,
  // never a repository or index selected by inherited Git environment state.
  const gitEnv = { ...process.env };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_INDEX_FILE"]) {
    delete gitEnv[name];
  }
  // A repository-level core.worktree can also point at another checkout.
  // This invocation must inspect the root requested by this guard instead.
  gitEnv.GIT_WORK_TREE = path.resolve(root);
  const status = execFileSync("git", ["status", "--porcelain"],
    { cwd: root, encoding: "utf8", env: gitEnv });
  for (const line of status.split(/\r?\n/).filter(Boolean)) {
    const relative = line.slice(3).replace(/\\/g, "/");
    if (protectedFiles.some((pattern) => pattern.test(relative))) violations.push(relative);
  }
  if (violations.length) throw new Error(`Runtime artifact guard failed (${[...new Set(violations)].join(", ")})`);
}

if (require.main === module) validateRuntimeArtifacts();
module.exports = { validateRuntimeArtifacts };
