const assert = require("node:assert/strict");
const test = require("node:test");
const { getNpmInvocation, canonicalTestArgs, isDependencyOrNetworkUnavailable } = require("../scripts/release-gate-environment");

test("Windows canonical release gate bounds file concurrency without omitting any test", () => {
  assert.deepEqual(canonicalTestArgs({ platform: "win32" }),
    ["test", "--", "--test-reporter=tap", "--test-concurrency=2"]);
  assert.deepEqual(canonicalTestArgs({ platform: "linux" }),
    ["test", "--", "--test-reporter=tap"]);
  assert.deepEqual(getNpmInvocation(canonicalTestArgs({ platform: "win32" }), {
    platform: "win32", comSpec: "cmd.exe",
  }), {
    executable: "cmd.exe",
    args: ["/d", "/s", "/c", "npm.cmd test -- --test-reporter=tap --test-concurrency=2"],
  });
  // The package's canonical 'npm test' script remains unmodified.
  assert.equal(require("../package.json").scripts.test, "node --test");
});

test("release gate uses native npm instead of inherited Windows cmd on Linux", () => {
  assert.deepEqual(getNpmInvocation(["test"], { platform: "linux", comSpec: "C:\\Windows\\System32\\cmd.exe" }), {
    executable: "npm",
    args: ["test"],
  });
});

test("release gate runs npm.cmd through cmd.exe on Windows", () => {
  assert.deepEqual(getNpmInvocation(["audit", "--package-lock-only", "--audit-level=high"], {
    platform: "win32",
    comSpec: "C:\\Windows\\System32\\cmd.exe",
  }), {
    executable: "C:\\Windows\\System32\\cmd.exe",
    args: ["/d", "/s", "/c", "npm.cmd audit --package-lock-only --audit-level=high"],
  });
});

test("release gate ignores advisory and test output words that resemble environment errors", () => {
  assert.equal(isDependencyOrNetworkUnavailable("✔ rootark-zk-1 registry fails closed\n✔ retry handles ETIMEDOUT\nhttps://registry.npmjs.org/package"), false);
});

test("release gate recognizes missing modules and npm network failures", () => {
  const missingInstalledPackage = () => false;
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'better-sqlite3'\ncode: 'MODULE_NOT_FOUND'", { resolvePackage: missingInstalledPackage }), true);
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'express' imported from /repo/test/example.test.js", { resolvePackage: missingInstalledPackage }), true);
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@aws-sdk/checksums' imported from /repo/node_modules/@aws-sdk/client-s3/index.js", { resolvePackage: missingInstalledPackage }), true);
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module '@aws-sdk/checksums'\nRequire stack:\n- /repo/node_modules/@aws-sdk/client-s3/dist-cjs/index.js\n- /repo/src/server.js", { resolvePackage: missingInstalledPackage }), true);
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@aws-sdk/checksums' imported from /repo/src/server.js", { resolvePackage: missingInstalledPackage }), false);
  assert.equal(isDependencyOrNetworkUnavailable("npm error code ENETUNREACH\nnpm error network request to https://registry.npmjs.org failed"), true);
});

test("release gate recognizes missing locked transitive imports from dependency code", () => {
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'gaxios' imported from /repo/node_modules/google-auth-library/build/src/auth/oauth2client.js", { resolvePackage: () => false }), true);
});

test("release gate does not treat a lockfile-only app import as a dependency block", () => {
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'accepts'\nRequire stack:\n- /repo/src/server.js\nnpm error code ECONNRESET", { resolvePackage: () => false }), false);
});

test("release gate treats unknown external imports as source failures, not environment blocks", () => {
  const missingInstalledPackage = () => false;
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'rootark-release-gate-typo'\ncode: 'MODULE_NOT_FOUND'", { resolvePackage: missingInstalledPackage }), false);
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'accepts'\nRequire stack:\n- /repo/src/server.js\ncode: 'MODULE_NOT_FOUND'\nnpm error code ECONNRESET\nnpm error network request to https://registry.npmjs.org failed", { resolvePackage: missingInstalledPackage }), false);
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@rootark-release-gate/typo' imported from /repo/test/example.test.js", { resolvePackage: missingInstalledPackage }), false);
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'rootark-release-gate-typo'\ncode: 'MODULE_NOT_FOUND'\nnpm error code ECONNRESET\nnpm error network request to https://registry.npmjs.org failed", { resolvePackage: missingInstalledPackage }), false);
});

test("release gate treats missing local project imports as failures", () => {
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module './services/missing-local-module'\nRequire stack:\n- C:\\repo\\test\\example.test.js\ncode: 'MODULE_NOT_FOUND'"), false);
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find module '/repo/src/missing-local-module.js' imported from /repo/test/example.test.js"), false);
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'servidor-drive/services/missing-local-module'\nRequire stack:\n- C:\\repo\\test\\example.test.js"), false);
});

test("release gate treats missing installed-package subpaths as failures", () => {
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'express/__missing_release_gate_test_subpath__'\nRequire stack:\n- C:\\repo\\test\\example.test.js"), false);
});

test("release gate does not hide local failures behind external dependency errors", () => {
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module 'better-sqlite3'\ncode: 'MODULE_NOT_FOUND'\nError: Cannot find module './services/missing-local-module'\nRequire stack:\n- C:\\repo\\test\\example.test.js", { resolvePackage: () => false }), false);
});
