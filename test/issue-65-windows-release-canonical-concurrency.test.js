"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

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
