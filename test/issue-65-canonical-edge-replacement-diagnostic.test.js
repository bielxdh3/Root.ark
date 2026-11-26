"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");
const { parseEdgeFailureDiagnostic, reportReplacementFailure } =
  require("../scripts/edge-test-failure-diagnostic");

const title = "real Edge: selected 128-revision UI batches consume replacement consent and cancel later-window search atomically";
const file = "test/issue-63-real-edge-replacement-consent.test.js";
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
const identity = { nameHash: hash(title), pathHash: hash(file) };
const diagnostic = (stage, code) => "# ROOTARK_EDGE_V1 case=REPLACEMENT_CONSENT stage=" + stage + " code=" + code;

test("replacement cancellation diagnostics require the exact fixture identity and a fixed reason", () => {
  const valid = diagnostic("VISIBLE_CANCEL", "VERIFY_INCREMENT");
  assert.deepEqual(parseEdgeFailureDiagnostic(valid, identity),
    { stage: "VISIBLE_CANCEL", code: "VERIFY_INCREMENT" });
  for (const bad of [
    { ...identity, nameHash: hash(title + " ") },
    { ...identity, pathHash: hash("test/foreign.test.js") },
  ]) assert.equal(parseEdgeFailureDiagnostic(valid, bad), null);
  for (const invalid of [
    diagnostic("INITIAL", "VERIFY_INCREMENT"),
    diagnostic("VISIBLE_CANCEL", "PRIVATE_TOKEN"),
    valid + " token=private",
    valid.replace("REPLACEMENT_CONSENT", "V2_ARCHIVE"),
  ]) assert.equal(parseEdgeFailureDiagnostic(invalid, identity), null);
});

test("browser terminal failures are reduced to pinned stage and reason without forwarding message text", () => {
  const messages = [];
  const t = { diagnostic: (message) => messages.push(message) };
  const prefix = "EDGE_REPLACE_ONCE_FAIL:visible-cancel-after-first-window:";
  reportReplacementFailure(t, prefix + "CANCEL_UI_VERIFIED_GET_INCREMENT_AFTER_CLEANUP");
  reportReplacementFailure(t, prefix + "private token /secret/path");
  reportReplacementFailure(t, prefix + "CANCEL_UI_VERIFIED_GET_INCREMENT_AFTER_CLEANUP private");
  reportReplacementFailure(t, "EDGE_REPLACE_ONCE_FAIL:private/path:secret");
  reportReplacementFailure(t, "EDGE_REPLACE_ONCE_PASS");
  assert.deepEqual(messages, process.platform === "win32" ? [
    diagnostic("VISIBLE_CANCEL", "VERIFY_INCREMENT").slice(2),
    diagnostic("VISIBLE_CANCEL", "RUNTIME").slice(2),
    diagnostic("VISIBLE_CANCEL", "RUNTIME").slice(2),
    diagnostic("UNKNOWN", "RUNTIME").slice(2),
  ] : []);
});

test("canonical TAP retains the replacement reason without changing its failing verdict", () => {
  const messages = [];
  const tracker = createTapProgressRecorder((line) => messages.push(line));
  for (const line of [
    "not ok 455 - " + title,
    "  ---",
    "  location: '/private/" + file + ":12:1'",
    "  failureType: 'testCodeFailure'",
    "  code: 'ERR_ASSERTION'",
    "  ...",
    diagnostic("VISIBLE_CANCEL", "VERIFY_INCREMENT"),
  ]) tracker.accept(line);
  tracker.finish();
  assert.equal(tracker.state.failures, 1);
  const report = messages.join("\n");
  assert.match(report, /edgeStage=VISIBLE_CANCEL edgeError=VERIFY_INCREMENT/);
  assert.doesNotMatch(report, /private|issue-63-real-edge|selected 128-revision/);
});

test("real Windows Node TAP carries the redacted replacement diagnostic from a failing fixture", {
  skip: process.platform !== "win32",
}, () => {
  const dir = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()), "rootark-edge-replacement-probe-"));
  try {
    fs.mkdirSync(path.join(dir, "test"));
    const helper = require.resolve("../scripts/edge-test-failure-diagnostic");
    fs.writeFileSync(path.join(dir, file), [
      'const test = require("node:test");',
      'const assert = require("node:assert/strict");',
      'const { reportReplacementFailure } = require(' + JSON.stringify(helper) + ');',
      'test(' + JSON.stringify(title) + ', t => {',
      '  const result = "EDGE_REPLACE_ONCE_FAIL:visible-cancel-after-first-window:CANCEL_UI_PARTIAL_INDEX_WRITE";',
      '  reportReplacementFailure(t, result);',
      '  assert.equal(result, "EDGE_REPLACE_ONCE_PASS");',
      '});',
    ].join("\n"));
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    const child = spawnSync(process.execPath, ["--test", "--test-reporter=tap", file],
      { cwd: dir, env, encoding: "utf8", windowsHide: true, timeout: 15000 });
    assert.equal(child.status, 1);
    assert.equal(child.signal, null);
    const messages = [];
    const tracker = createTapProgressRecorder((line) => messages.push(line));
    for (const line of child.stdout.split(/\r?\n/)) tracker.accept(line);
    tracker.finish();
    assert.equal(tracker.state.failures, 1);
    const report = messages.join("\n");
    assert.match(report, /edgeStage=VISIBLE_CANCEL edgeError=PARTIAL_INDEX/);
    assert.doesNotMatch(report, /rootark-edge-replacement-probe|issue-63-real-edge|EDGE_REPLACE_ONCE_FAIL/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
