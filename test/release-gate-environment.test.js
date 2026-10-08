const assert = require("node:assert/strict");
const test = require("node:test");
const { isDependencyOrNetworkUnavailable } = require("../scripts/release-gate-environment");

test("release gate ignores advisory and test output words that resemble environment errors", () => {
  assert.equal(isDependencyOrNetworkUnavailable("✔ rootark-zk-1 registry fails closed\n✔ retry handles ETIMEDOUT\nhttps://registry.npmjs.org/package"), false);
});

test("release gate recognizes missing modules and npm network failures", () => {
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module '@rootark-release-gate/missing-ci-dependency'\ncode: 'MODULE_NOT_FOUND'"), true);
  assert.equal(isDependencyOrNetworkUnavailable("Error [ERR_MODULE_NOT_FOUND]: Cannot find package '@rootark-release-gate/missing-esm-dependency' imported from /repo/test/example.test.js"), true);
  assert.equal(isDependencyOrNetworkUnavailable("npm error code ENETUNREACH\nnpm error network request to https://registry.npmjs.org failed"), true);
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
  assert.equal(isDependencyOrNetworkUnavailable("Error: Cannot find module '@rootark-release-gate/missing-ci-dependency'\ncode: 'MODULE_NOT_FOUND'\nError: Cannot find module './services/missing-local-module'\nRequire stack:\n- C:\\repo\\test\\example.test.js"), false);
});
