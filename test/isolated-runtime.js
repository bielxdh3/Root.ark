const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

module.exports = function isolateRuntime(test, prefix) {
  const originalCwd = process.cwd();
  const runtimeRoot = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  // Each test file otherwise shares the runtime-wide backup lock through the repository cwd.
  process.chdir(runtimeRoot);
  test.after(() => {
    process.chdir(originalCwd);
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
  });
};
