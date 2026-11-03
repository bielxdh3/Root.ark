const fs = require("node:fs");
const { createPrivateAuthorityFixture } = require("./support/issue-65-private-authority-fixture");

module.exports = function isolateRuntime(test, prefix) {
  const originalCwd = process.cwd();
  const runtimeRoot = createPrivateAuthorityFixture(prefix);
  // Each test file otherwise shares the runtime-wide backup lock through the repository cwd.
  process.chdir(runtimeRoot);
  test.after(() => {
    process.chdir(originalCwd);
    fs.rmSync(runtimeRoot, { recursive: true, force: true });
  });
};
