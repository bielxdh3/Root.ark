const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const { EventEmitter } = require("node:events");
const { PassThrough } = require("node:stream");
const { getNpmInvocation, canonicalTestArgs, hasSeparateWindowsCiCanonicalTest, isDependencyOrNetworkUnavailable } = require("../scripts/release-gate-environment");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");
const { createAclFailureDiagnostic } = require("../scripts/acl-test-failure-diagnostic");
const { reportEdgeFailure } = require("../scripts/edge-test-failure-diagnostic");

test("Windows Edge reporter emits fixed stage and code, rethrowing without secrets", () => {
  const output = [];
  const t = { diagnostic: (entry) => output.push(entry) };
  const error = Object.assign(Error("password=secret C:\\private\\profile"), { code: "ERR_ASSERTION" });
  reportEdgeFailure(t, "INDEXEDDB", "OWNER_CHECKPOINT", error);
  if (process.platform === "win32") assert.deepEqual(output, [
    "ROOTARK_EDGE_V1 case=INDEXEDDB stage=OWNER_CHECKPOINT code=ASSERTION",
  ]);
  else assert.deepEqual(output, []);
  assert.throws(() => reportEdgeFailure(t, "INDEXEDDB", "PRIVATE_TOKEN", error),
    /INVALID_EDGE_DIAGNOSTIC_STAGE/);
  assert.throws(() => reportEdgeFailure(t, "FOREIGN", "STARTUP", error),
    /INVALID_EDGE_DIAGNOSTIC_CASE/);
  assert.doesNotMatch(JSON.stringify(output), /secret|private|password|profile/);
});

test("canonical runner admits only named and path-pinned Edge diagnostics on failure", () => {
  const title = "real Edge IndexedDB restores nonextractable trusted-device keys for independent recovery";
  const location = "  location: 'C:\\host\\test\\issue-65-trusted-device-indexeddb-browser.test.js:405:1'";
  const lines = [];
  const tracker = createTapProgressRecorder((entry) => lines.push(entry));
  tracker.accept(`not ok 1 - ${title}`);
  tracker.accept(location);
  tracker.accept("  error: 'C:\\keys\\sensitive.pem password=secret'");
  tracker.accept("# ROOTARK_EDGE_V1 case=INDEXEDDB stage=OWNER_CHECKPOINT code=ASSERTION");
  tracker.accept("ok 2 - next test");
  assert.match(lines.join("\n"), /edgeStage=OWNER_CHECKPOINT edgeError=ASSERTION/);
  assert.doesNotMatch(lines.join("\n"), /keys|sensitive|secret|INDEXEDDB|checkpoint\.test\.js/);

  const wrong = [];
  const guard = createTapProgressRecorder((entry) => wrong.push(entry));
  guard.accept("not ok 3 - unrelated test with secrets");
  guard.accept(location);
  guard.accept("# ROOTARK_EDGE_V1 case=INDEXEDDB stage=OWNER_CHECKPOINT code=ASSERTION");
  guard.accept(`not ok 4 - ${title}`);
  guard.accept("  location: 'C:\\host\\test\\wrong-test.test.js:1:1'");
  guard.accept("# ROOTARK_EDGE_V1 case=INDEXEDDB stage=OWNER_CHECKPOINT code=ASSERTION");
  guard.accept(`not ok 5 - ${title}`);
  guard.accept(location);
  guard.accept("# ROOTARK_EDGE_V1 case=INDEXEDDB stage=PASSWORD_PRIVATE code=ASSERTION");
  guard.accept("# ROOTARK_EDGE_V1 case=INDEXEDDB stage=OWNER_CHECKPOINT code=EXPLOIT");
  guard.accept("# ROOTARK_EDGE_V1 case=INDEXEDDB stage=OWNER_CHECKPOINT code=ASSERTION password=secret");
  guard.finish();
  assert.doesNotMatch(wrong.join("\n"), /edgeStage=|edgeError=|EXPLOIT|password=secret|wrong-test/);
});

test("canonical runner names both Edge case profiles without leaking raw error content", () => {
  const names = [
    ["REAL Edge owner-witnessed V2 PoP import survives fresh realm and restores only through signed-history strict mTLS-backed server", "issue-65-edge-v2-witnessed-positive.test.js", "V2_WITNESSED", "EDGE_PERSISTED_POSITIVE"],
    ["real Edge IndexedDB restores nonextractable trusted-device keys for independent recovery", "issue-65-trusted-device-indexeddb-browser.test.js", "INDEXEDDB", "APPROVAL_REVOKE"],
  ];
  const lines = [];
  const tracker = createTapProgressRecorder((entry) => lines.push(entry));
  for (const [title, filename, caseId, stage] of names) {
    tracker.accept(`not ok ${lines.length + 1} - ${title}`);
    tracker.accept(`  location: 'C:\\secret\\test\\${filename}:15:1'`);
    tracker.accept(`# ROOTARK_EDGE_V1 case=${caseId} stage=${stage} code=RUNTIME`);
  }
  tracker.finish();
  const details = lines.filter((line) => line.startsWith("FAIL detail "));
  assert.equal(details.length, 2);
  for (const [, , , stage] of names)
    assert.ok(details.some((line) => line.includes(`edgeStage=${stage} edgeError=RUNTIME`)));
  assert.doesNotMatch(lines.join("\n"), /C:\\secret|\.test\.js|signed-history strict|nonextractable trusted-device/);
});

test("ACL stage reporter rethrows original failure but never emits source error text", async () => {
  const diagnostic = [];
  const wrapped = createAclFailureDiagnostic({ diagnostic: (value) => diagnostic.push(value) }, "ATOMIC_MUTATION");
  assert.throws(() => wrapped.stage("PRIVATE_SECRET_PATH"), /INVALID_ACL_DIAGNOSTIC_STAGE/);
  assert.throws(() => wrapped.trust("S-1-5-11"), /INVALID_ACL_DIAGNOSTIC_TRUST/);
  wrapped.stage("ACL_WRITE");
  wrapped.trust("UNTRUSTED_ADDED");
  const failure = Object.assign(new Error("C:\\private\\token.txt password=secret"), { code: "EPERM" });
  await assert.rejects(wrapped.run(async () => { throw failure; }), (error) => error === failure);
  if (process.platform === "win32") {
    assert.deepEqual(diagnostic, [
      "ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=PERMISSION trust=UNTRUSTED_ADDED",
    ]);
  } else assert.deepEqual(diagnostic, []);
  assert.doesNotMatch(JSON.stringify(diagnostic), /private|token|password|secret|S-1-5/);
});

test("Windows canonical runner emits only bounded verified ACL stage enums for known failing tests", () => {
  const { createHash } = require("node:crypto");
  const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
  const title = "strict atomic registry refuses a later untrusted file permission change";
  const nameHash = hash(title);
  const lines = [];
  const recorder = createTapProgressRecorder((line) => lines.push(line));
  recorder.accept(`not ok 7 - ${title}`);
  recorder.accept("  location: 'C:\\host\\test\\issue-65-sync-atomic-private-acl.test.js:77:1'");
  recorder.accept("  error: 'password=raw-secret C:\\host\\private\\keys.pem'");
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=ASSERTION trust=UNTRUSTED_ADDED");
  recorder.accept("ok 8 - next fixture");
  const emitted = lines.join("\n");
  assert.match(emitted, new RegExp(`nameSha256=${nameHash}`));
  assert.match(emitted, /aclStage=ACL_WRITE aclError=ASSERTION aclTrust=UNTRUSTED_ADDED/);
  assert.doesNotMatch(emitted, /raw-secret|keys\.pem|C:\\host|issue-65-sync-atomic-private-acl/);
});

test("Windows canonical runner ignores forged ACL diagnostics, unknown enums and passing tests", () => {
  const lines = [];
  const recorder = createTapProgressRecorder((line) => lines.push(line));
  const title = "strict atomic registry refuses a later untrusted file permission change";
  const location = "  location: 'C:\\host\\test\\issue-65-sync-atomic-private-acl.test.js:77:1'";
  recorder.accept(`ok 1 - ${title}`);
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=ASSERTION trust=UNTRUSTED_ADDED");
  recorder.accept("not ok 2 - unrelated private title");
  recorder.accept(location);
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=ASSERTION trust=UNTRUSTED_ADDED");
  recorder.accept(`not ok 3 - ${title}`);
  recorder.accept("  location: 'C:\\host\\test\\wrong-test.test.js:77:1'");
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=ASSERTION trust=UNTRUSTED_ADDED");
  recorder.accept(`not ok 4 - ${title}`);
  recorder.accept(location);
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=LEAK_private_path code=ASSERTION trust=UNTRUSTED_ADDED");
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=SECRET_PASSWORD trust=UNTRUSTED_ADDED");
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=ASSERTION trust=C:\\secrets");
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=ACL_WRITE code=ASSERTION trust=UNTRUSTED_ADDED password=shhh");
  recorder.accept("ok 5 - next fixture");
  const emitted = lines.join("\n");
  assert.doesNotMatch(emitted, /aclStage=|aclTrust=|aclError=|SECRET_PASSWORD|secrets|password=shhh|wrong-test|private title/);
});

test("Windows canonical runner recognizes all four ACL failure profiles without exposing paths", () => {
  const profiles = [
    ["Windows generic access ACEs cannot evade private snapshot ancestor checks",
      "issue-65-legacy-deterministic-evidence-manifest.test.js", "LEGACY_GENERIC_ACE", "GUARD_VERIFY"],
    ["strict atomic registry rejects unsafe inherited or explicit ACL/mode without mutating it",
      "issue-65-sync-atomic-private-acl.test.js", "ATOMIC_INHERIT", "INHERIT_CHECK"],
    ["strict atomic registry refuses a later untrusted file permission change",
      "issue-65-sync-atomic-private-acl.test.js", "ATOMIC_MUTATION", "ACL_WRITE"],
    ["a newly unsafe ACL after rename quarantines the lock instead of allowing a retry",
      "issue-65-sync-atomic-private-acl.test.js", "ATOMIC_RENAME", "RENAME_HOOK"],
  ];
  const logged = [];
  const recorder = createTapProgressRecorder((line) => logged.push(line));
  for (const [title, filename, caseId, stage] of profiles) {
    recorder.accept(`not ok ${logged.length + 1} - ${title}`);
    recorder.accept(`  location: 'C:\\private-host\\test\\${filename}:15:1'`);
    recorder.accept(`# ROOTARK_ACL_V1 case=${caseId} stage=${stage} code=RUNTIME trust=UNKNOWN`);
  }
  recorder.finish();
  const details = logged.filter((line) => line.startsWith("FAIL detail "));
  assert.equal(details.length, 4);
  for (const [, , , stage] of profiles)
    assert.ok(details.some((line) => line.includes(`aclStage=${stage} aclError=RUNTIME aclTrust=UNKNOWN`)), stage);
  assert.doesNotMatch(logged.join("\n"), /private-host|test\.js|generic access ACEs|permission change/);
});

test("Windows canonical reporter recognizes the current hostile inherited ACL fixture title", () => {
  const title = "strict atomic registry rejects unsafe inherited or explicit ACL/mode without mutating it";
  const output = [];
  const recorder = createTapProgressRecorder((line) => output.push(line));
  recorder.accept(`not ok 1 - ${title}`);
  recorder.accept("  location: 'C:\\ci-host\\test\\issue-65-sync-atomic-private-acl.test.js:73:1'");
  recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_INHERIT stage=INHERIT_CHECK code=ASSERTION trust=UNKNOWN");
  recorder.finish();
  assert.match(output.join("\n"), /aclStage=INHERIT_CHECK aclError=ASSERTION aclTrust=UNKNOWN/);
  assert.doesNotMatch(output.join("\n"), /ci-host|unsafe inherited or explicit ACL/);
});

test("Windows canonical runner preserves bounded trusted ACL details after unrelated failure cap", () => {
  const logged = [];
  const recorder = createTapProgressRecorder((line) => logged.push(line));
  for (let i = 1; i <= 14; i++) {
    recorder.accept(`not ok ${i} - unrelated failure ${i}`);
    recorder.accept("  code: 'ERR_TEST_FAILURE'");
  }
  const title = "strict atomic registry refuses a later untrusted file permission change";
  for (let i = 15; i <= 20; i++) {
    recorder.accept(`not ok ${i} - ${title}`);
    recorder.accept("  location: 'C:\\private\\test\\issue-65-sync-atomic-private-acl.test.js:88:1'");
    recorder.accept("# ROOTARK_ACL_V1 case=ATOMIC_MUTATION stage=REOPEN_CHECK code=ASSERTION trust=UNTRUSTED_ADDED");
  }
  recorder.finish();
  const overflow = logged.filter((line) => line.startsWith("FAIL verified ACL detail "));
  assert.equal(overflow.length, 4, "at most four vetted ACL overflow records");
  assert.ok(overflow.every((line) => line.includes("aclStage=REOPEN_CHECK aclError=ASSERTION aclTrust=UNTRUSTED_ADDED")));
  assert.doesNotMatch(logged.join("\n"), /C:\\private|\.test\.js|unrelated failure|private path/);
});

test("Windows canonical runner synchronously reports failure even when console output is buffered", () => {
  const runnerPath = path.join(__dirname, "..", "scripts", "run-windows-canonical-tests.js");
  const source = fs.readFileSync(runnerPath, "utf8");
  const runFixture = ({ closeChild }) => {
    const child = new EventEmitter();
    child.pid = 1234;
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    const synchronous = [];
    const processHooks = {};
    const fakeProcess = {
      platform: "linux", env: {}, exitCode: 0,
      on(name, handler) { processHooks[name] = handler; },
    };
    const fakeModule = { exports: {} };
    const fakeRequire = (id) => {
      if (id === "node:child_process") return { spawn: () => child };
      if (id === "node:fs") return { ...fs, writeSync: (fd, data) => {
        assert.equal(fd, 2, "failure diagnostics go to stderr");
        synchronous.push(String(data));
      } };
      if (id === "./release-gate-environment") return {
        getNpmInvocation: () => ({ executable: "fixture", args: [] }),
        canonicalTestArgs: () => [],
      };
      if (id === "./acl-test-failure-diagnostic")
        return require("../scripts/acl-test-failure-diagnostic");
      if (id === "./edge-test-failure-diagnostic")
        return require("../scripts/edge-test-failure-diagnostic");
      return require(id);
    };
    fakeRequire.main = fakeModule;
    vm.runInNewContext(source, {
      module: fakeModule, require: fakeRequire, __dirname: path.dirname(runnerPath),
      process: fakeProcess, console: { log() {}, error() {} },
      setInterval: () => 1, clearInterval: () => {},
    }, { filename: runnerPath });
    child.stdout.write("TAP version 13\nnot ok 1 - private token=fixture-secret\n");
    if (closeChild) child.emit("close", 1, null);
    else processHooks.exit?.(1);
    return { synchronous: synchronous.join(""), fakeProcess };
  };
  const closed = runFixture({ closeChild: true });
  assert.equal(closed.fakeProcess.exitCode, 1);
  assert.match(closed.synchronous, /FAIL Windows canonical suite: exit=1/);
  assert.doesNotMatch(closed.synchronous, /fixture-secret/);
  const premature = runFixture({ closeChild: false });
  assert.equal(premature.fakeProcess.exitCode, 1, "premature termination cannot pass the release gate");
  assert.match(premature.synchronous, /FAIL Windows canonical runner exited before child close/);
  assert.doesNotMatch(premature.synchronous, /fixture-secret/);
});

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
