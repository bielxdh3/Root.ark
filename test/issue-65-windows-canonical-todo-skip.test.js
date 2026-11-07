"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createTapProgressRecorder } = require("../scripts/run-windows-canonical-tests");

test("genuine Node TAP nested TODO fails by design but must not block a valid suite", () => {
  const script = [
    "const test=require('node:test');",
    "test('outer',async (t)=>{",
    "await t.test('deferred',{todo:'later'},()=>{throw Error('known issue')});",
    "await t.test('skipped',{skip:'later'},()=>{});",
    "});",
  ].join("");
  // Node test children inherit an internal binary harness channel; a nested
  // standalone Node invocation needs that context removed for genuine text TAP.
  const environment = { ...process.env };
  delete environment.NODE_TEST_CONTEXT;
  const child = spawnSync(process.execPath, ["-e", script], {
    encoding: "utf8", timeout: 10_000, windowsHide: true, env: environment,
  });
  assert.equal(child.status, 0, "TODO's intentional failure must leave Node suite successful");
  assert.match(child.stdout, /^    not ok 1 - deferred # TODO later$/m);
  assert.match(child.stdout, /^    ok 2 - skipped # SKIP later$/m);
  assert.match(child.stdout, /^# fail 0$/m);
  const out = [];
  const recorder = createTapProgressRecorder((message) => out.push(message));
  for (const line of child.stdout.split(/\r?\n/)) recorder.accept(line);
  recorder.finish();
  assert.equal(recorder.state.plan, true);
  assert.equal(recorder.state.reportedFailures, 0);
  assert.equal(recorder.state.results, 1);
  assert.equal(recorder.state.failures, 0);
  assert.equal(recorder.state.nestedObservedFailures, 1);
  assert.equal(recorder.state.nestedFailures, 0, "valid TODO does not count as actionable failure");
  assert.equal(recorder.state.nestedTodos, 1);
  assert.equal(recorder.state.nestedSkips, 0);
  assert.match(recorder.safeSummary(), /nestedObservedFailures=1 nestedFailures=0/);
  assert.doesNotMatch(out.join("\n"), /FAIL nested detail/);
});

test("nested TODO and SKIP directives are case insensitive with strict token boundaries", () => {
  const recorder = createTapProgressRecorder(() => {});
  for (const valid of [
    "    not ok 1 - deferred # TODO later",
    "    not ok 2 - deferred # todo",
    "    not ok 3 - deferred # ToDo a later issue",
    "    not ok 4 - deferred # skip",
    "    not ok 5 - deferred # sKiP not supported",
  ]) recorder.accept(valid);
  recorder.finish();
  assert.equal(recorder.state.nestedObservedFailures, 5);
  assert.equal(recorder.state.nestedFailures, 0);
  assert.equal(recorder.state.nestedTodos, 3);
  assert.equal(recorder.state.nestedSkips, 2);
  assert.match(recorder.safeSummary(), /nestedFailureDepths=2:0,4:0,6:0,8:0,other:0/);
});

test("malformed or nonterminal directives never excuse actionable nested failures", () => {
  const out = [];
  const recorder = createTapProgressRecorder((message) => out.push(message));
  const bad = [
    "    not ok 1 - malformed # TODOX later",
    "    not ok 2 - malformed # SKIPPED later",
    "    not ok 3 - malformed # TODO: later",
    "    not ok 4 - malformed # SKIP-later",
    "    not ok 5 - malformed #TODO later",
    "    not ok 6 - malformed # TODO ",
    "    not ok 7 - malformed # TOD O",
    "    not ok 8 - still actionable",
  ];
  for (const line of bad) recorder.accept(line);
  recorder.finish();
  assert.equal(recorder.state.nestedObservedFailures, bad.length);
  assert.equal(recorder.state.nestedFailures, bad.length);
  assert.equal(recorder.state.nestedTodos, 0);
  assert.equal(recorder.state.nestedSkips, 0);
  assert.equal(out.filter((line) => line.startsWith("FAIL nested detail")).length, 8);
});

test("valid TODO followed by real nested failure retains fail-closed verdict and redacted hashes", () => {
  const out = [];
  const recorder = createTapProgressRecorder((message) => out.push(message));
  const raw = "C:\\private\\password=DO_NOT_LOG";
  recorder.accept(`    not ok 1 - ${raw} # TODO deferred`);
  recorder.accept(`    not ok 2 - ${raw} unresolved`);
  recorder.accept("      code: 'ERR_ASSERTION'");
  recorder.finish();
  assert.equal(recorder.state.nestedObservedFailures, 2);
  assert.equal(recorder.state.nestedFailures, 1);
  assert.equal(recorder.state.nestedTodos, 1);
  assert.match(out.join("\n"), /FAIL nested detail/);
  assert.match(out.join("\n"), /nameSha256=[0-9a-f]{24}/);
  assert.doesNotMatch(out.join("\n") + recorder.safeSummary(), /DO_NOT_LOG|password=|C:\\private/);
});

test("top-level TODO directive also follows Node's # fail 0 while ordinary top-level failure stays blocking", () => {
  const out = [];
  const recorder = createTapProgressRecorder((message) => out.push(message));
  recorder.accept("not ok 1 - deferred top-level # TODO later");
  recorder.accept("not ok 2 - real failure # TODO_WRONG");
  recorder.accept("1..2");
  recorder.accept("# tests 2");
  recorder.accept("# fail 1");
  recorder.finish();
  assert.equal(recorder.state.observedFailures, 2);
  assert.equal(recorder.state.failures, 1);
  assert.equal(recorder.state.topLevelTodos, 1);
  assert.equal(out.filter((line) => line.startsWith("FAIL test result")).length, 1);
});
