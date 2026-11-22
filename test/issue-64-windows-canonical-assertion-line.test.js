"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");

test("Windows canonical reports only a verified source line for a failed legacy sync assertion", () => {
  const messages = [];
  const recorder = createTapProgressRecorder((message) => messages.push(message));
  const secret = "SECRET_PRIVATE_STACK_PATH_AND_TOKEN";
  for (const line of [
    "not ok 7 - simultaneous legacy uploads serialize private state without lost entries",
    "  ---",
    "  location: 'D:\\fixture\\test\\legacy-sync-private-state.test.js:181:1'",
    "  failureType: 'testCodeFailure'",
    "  code: 'ERR_ASSERTION'",
    `    at TestContext.<anonymous> (D:\\${secret}\\test\\legacy-sync-private-state.test.js:193:10)`,
    `    at TestContext.<anonymous> (D:\\${secret}\\test\\unrelated.test.js:900:4)`,
    "  ...",
  ]) recorder.accept(line);
  recorder.finish();
  const report = messages.join("\n");
  assert.match(report, /assertionLine=193/);
  assert.doesNotMatch(report, /SECRET_PRIVATE|D:\\|unrelated\.test\.js|900/);
  assert.equal(recorder.state.failures, 1);
});
