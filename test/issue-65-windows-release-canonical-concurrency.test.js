"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.resolve(__dirname, "..");
function npmTestArgs(file, variable) {
  const source = fs.readFileSync(path.join(ROOT, "scripts", file), "utf8");
  const pattern = new RegExp(`const ${variable} = getNpmInvocation\\((\\[[^\\]]+\\])\\);`);
  const match = pattern.exec(source);
  assert.ok(match, `${file} must invoke the shared npm test entrypoint`);
  return JSON.parse(match[1]);
}

test("Windows mandatory release gate runs the same full canonical test suite with bounded file concurrency", () => {
  const expected = ["test", "--", "--test-reporter=tap", "--test-concurrency=2"];
  assert.deepEqual(npmTestArgs("run-windows-canonical-tests.js", "invocation"), expected,
    "existing canonical Windows runner must retain its complete two-worker suite");
  assert.deepEqual(npmTestArgs("validate-release-gate.js", "npmTest"), expected,
    "release gate must not use unbounded parallel files and destabilize restore fixtures");
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.equal(manifest.scripts.test, "node --test",
    "both invocations must retain the unfiltered, mandatory full test suite");
  const workflow = fs.readFileSync(path.join(ROOT, ".github", "workflows",
    "security-regression.yml"), "utf8");
  const release = /^  windows-release-gate:\s*\n(?:.*\n)*?    timeout-minutes: (\d+)$/m.exec(workflow);
  assert.ok(release, "the mandatory Windows release job must keep a finite timeout");
  assert.ok(Number(release[1]) >= 75 && Number(release[1]) <= 90,
    "a full bounded canonical suite (~45m) plus security release gates (~14m) needs time margin");
});

test("Windows release canonical child inherits the same physically resolved TEMP and TMP as the passing runner", () => {
  const source = fs.readFileSync(path.join(ROOT, "scripts", "validate-release-gate.js"), "utf8");
  const commandSource = source.match(/function command\(name, executable, args, \{ blockedOnMissing = false, shell = false \} = \{\}\) \{[\s\S]*?\n\}/)?.[0];
  assert.ok(commandSource, "exercise the actual production child-spawning function");
  const canonicalEnv = Object.freeze({ TEMP: "E:\\trusted-physical-temp", TMP: "E:\\trusted-physical-temp" });
  const calls = [];
  const command = vm.runInNewContext(`(()=>{${commandSource}\nreturn command;})()`, {
    process: { platform: "win32" }, root: "E:\\repo", Buffer,
    require(id) {
      assert.equal(id, "./run-windows-canonical-tests");
      return { canonicalWindowsTestEnvironment: () => canonicalEnv };
    },
    spawnSync(_binary, _args, options) {
      calls.push(options);
      return { status: 0, stdout: "", stderr: "" };
    },
    record() {}, console: { log() {} },
  });
  assert.equal(command("final-head canonical npm test", "npm", ["test"]), true);
  assert.equal(calls[0].env, canonicalEnv,
    "full release tests must not regress to the ambient Windows TEMP junction");
  assert.equal(command("Phase 14 backup/restore evidence", "node", ["--test"]), true);
  assert.equal(calls[1].env, undefined,
    "only the canonical npm-test child should receive the canonicalized TEMP environment");
});
