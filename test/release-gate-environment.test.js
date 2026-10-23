const assert = require("node:assert/strict");
const test = require("node:test");
const { getNpmInvocation, canonicalTestArgs, hasSeparateWindowsCiCanonicalTest, isDependencyOrNetworkUnavailable } = require("../scripts/release-gate-environment");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");

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

test("only the explicitly split Windows Actions gate delegates the canonical suite", () => {
  assert.equal(hasSeparateWindowsCiCanonicalTest({ platform: "win32", githubActions: "true", separateJob: "true" }), true);
  assert.equal(hasSeparateWindowsCiCanonicalTest({ platform: "win32", githubActions: "true", separateJob: undefined }), false);
  assert.equal(hasSeparateWindowsCiCanonicalTest({ platform: "win32", githubActions: "false", separateJob: "true" }), false);
  assert.equal(hasSeparateWindowsCiCanonicalTest({ platform: "linux", githubActions: "true", separateJob: "true" }), false);
});

test("streaming Windows canonical runner reports progress without revealing test names or output", () => {
  const logged = [];
  const recorder = createTapProgressRecorder((message) => logged.push(message));
  recorder.accept("TAP version 13");
  recorder.accept("not ok 1 - fixture secret should never appear in a CI log");
  recorder.accept("ok 2 - passing test");
  recorder.accept("1..2");
  recorder.accept("# tests 2");
  recorder.accept("# fail 1");
  assert.deepEqual({ results: recorder.state.results, failures: recorder.state.failures, plan: recorder.state.plan,
    tests: recorder.state.tests, reportedFailures: recorder.state.reportedFailures },
  { results: 2, failures: 1, plan: true, tests: 2, reportedFailures: 1 });
  assert.match(logged.join("\n"), /nameSha256=[0-9a-f]{24}/);
  assert.doesNotMatch(logged.join("\n"), /fixture secret|passing test/);
});

test("canonical runner summarizes bounded failure categories, test path hashes and safe error codes", () => {
  const output = [];
  const recorder = createTapProgressRecorder((value) => output.push(value));
  const secret = "superSecretTokenValue";
  recorder.accept(`not ok 15 - password=${secret}`);
  recorder.accept(`  location: 'C:\\runner\\test\\issue-65-durable-witness-ledger.test.js:72:1'`);
  recorder.accept("  failureType: 'testCodeFailure'");
  recorder.accept(`  error: '${secret}'`);
  recorder.accept("  code: 'SQLITE_BUSY'");
  recorder.accept("ok 16 - another test");
  recorder.accept("not ok 17 - private test title");
  recorder.accept("  failureType: 'testCodeFailure'");
  recorder.accept("  code: 'ERR_ASSERTION'");
  recorder.finish();
  assert.equal(recorder.state.failures, 2);
  const diagnostic = output.join("\n") + " " + recorder.safeSummary();
  assert.match(diagnostic, /testPathSha256=[0-9a-f]{24}/);
  assert.match(diagnostic, /code=SQLITE_BUSY/);
  assert.match(diagnostic, /code=ERR_ASSERTION/);
  assert.match(diagnostic, /sqlite_busy=1/);
  assert.match(diagnostic, /assertion=1/);
  assert.doesNotMatch(diagnostic, /superSecretTokenValue|private test title|issue-65-durable-witness-ledger|C:\\runner/);
});

test("canonical runner groups every failing file by hash after the detail cap", () => {
  const { createHash } = require("node:crypto");
  const hash = (name) => createHash("sha256").update("test/" + name).digest("hex").slice(0, 24);
  const logged = [];
  const recorder = createTapProgressRecorder((line) => logged.push(line));
  for (let index = 1; index <= 20; index++) {
    const filename = index <= 15 ? "alpha.test.js" : "beta.test.js";
    recorder.accept("not ok " + index + " - secret fixture title " + index);
    recorder.accept("  location: 'C:/runner/test/" + filename + ":23:1'");
    recorder.accept("  code: 'ERR_ASSERTION'");
  }
  recorder.finish();
  const summary = recorder.safeSummary();
  assert.match(summary, /failurePathGroups=2/);
  assert.ok(summary.includes("topFailurePaths=" + hash("alpha.test.js") + ":15," + hash("beta.test.js") + ":5"));
  assert.equal(logged.filter((line) => line.startsWith("FAIL detail ")).length, 12);
  assert.doesNotMatch(summary + logged.join("\n"), /alpha\.test|beta\.test|secret fixture|C:\/runner/);
});

test("canonical runner ignores arbitrary error data, unsafe codes and bounds diagnostic output", () => {
  const logged = [];
  const recorder = createTapProgressRecorder((value) => logged.push(value));
  for (let i = 1; i <= 25; i++) {
    recorder.accept(`not ok ${i} - Bearer verySensitiveCredential${i}`);
    recorder.accept("  failureType: 'testCodeFailure'");
    recorder.accept("  code: 'SECRET_API_KEY_99'");
    recorder.accept("  location: 'C:\\top-secret\\test\\not-a-test.js:10:2'");
  }
  recorder.finish();
  assert.equal(recorder.state.failures, 25);
  const joined = logged.join("\n") + recorder.safeSummary();
  assert.doesNotMatch(joined, /SECRET_API_KEY_99|verySensitiveCredential|top-secret|not-a-test/);
  assert.match(joined, /unknown=25/);
  assert.ok(logged.filter((line) => line.startsWith("FAIL detail ")).length <= 12);
  assert.ok(recorder.safeSummary().length < 400);
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
