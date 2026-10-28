"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const Module = require("node:module");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { EDGE_FILES, EXPECTED_EDGE_CASES, assessEdgeTap } =
  require("../scripts/validate-edge-e2e");

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 24);
const relative = EDGE_FILES[2];
const name = "real V2 CAS and FLOOR mTLS baseline refuses last-head-only checkpoint and missing full-128 owner proof";
const hostile = "JWT=very-private-token C:\\Users\\secret\\private.key";
const tap = (title = name, location = String.raw`C:\runner\Root.ark\test\issue-65-opaque-v1-v2-rollover-preflight.test.js:251:1`, type = "testTimeoutFailure") =>
  ["TAP version 13", "ok 1 - earlier", `not ok 19 - ${title}`, "  ---",
    `  location: '${location}'`, `  failureType: '${type}'`,
    "  error: 'JWT=very-private-token'", "  code: 'ERR_TEST_FAILURE'",
    `  stack: |`, `    ${hostile}`, "  ...", "ok 20 - later",
    "1..31", "# tests 31", "# pass 30", "# fail 1", "# cancelled 0",
    "# skipped 0", "# todo 0"].join("\n");

test("failed Edge child yields bounded hashed top ordinal, pinned filename and timeout class without leaking secrets", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  const safe = summarizeFailedEdgeChild({ status: 1, stdout: tap(), stderr: hostile }, EDGE_FILES);
  assert.equal(safe, `EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=19:${sha(name)}:${sha(relative)}:timeout nested=none`);
  assert.doesNotMatch(safe, /JWT|very-private|Users|private\.key|Root\.ark|real V2|C:/i);
});

test("real Node22 TAP failure schema feeds the same safe parser", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  // A fixture beneath this checkout matches the hosted Node --test entrypoint.
  const folder = fs.mkdtempSync(path.join(__dirname, ".w97-tap-shape-"));
  let sample;
  try {
    const file = path.join(folder, "shape.test.cjs");
    fs.writeFileSync(file, "require('node:test')('real-test-failure',()=>require('node:assert/strict').equal(1,2));", { flag: "wx" });
    // A nested Node test runner must not inherit the outer runner's private
    // NODE_TEST_CONTEXT marker: that marker bypasses discovery in the child.
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    sample = spawnSync(process.execPath, ["--test", "--test-reporter=tap", file],
      { encoding: "utf8", windowsHide: true, maxBuffer: 1024 * 1024, env });
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
  assert.equal(sample.status, 1);
  assert.ok(/failureType: 'testCodeFailure'/.test(sample.stdout), "NODE22_TEST_CODE_FAILURE_SHAPE");
  assert.ok(/code: 'ERR_ASSERTION'/.test(sample.stdout), "NODE22_ASSERTION_CODE_SHAPE");
  {
    const safe = summarizeFailedEdgeChild(sample, EDGE_FILES);
    assert.match(safe, /^EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=1:[a-f0-9]{24}:none:assertion nested=none$/);
  }
});

test("real Node22 nested describe failure reports the inner assertion under its hashed failed parent, not only a wrapper runtime", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  const folder = fs.mkdtempSync(path.join(__dirname, ".w97-nested-tap-shape-"));
  let sample;
  try {
    const file = path.join(folder, "nested.test.cjs");
    fs.writeFileSync(file, "const {describe,it}=require('node:test');const assert=require('node:assert/strict');describe('suite',()=>{it('inner',()=>assert.equal(1,2));});", { flag: "wx" });
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    sample = spawnSync(process.execPath, ["--test", "--test-reporter=tap", file],
      { encoding: "utf8", windowsHide: true, maxBuffer: 1024 * 1024, env });
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
  assert.equal(sample.status, 1);
  assert.ok(/^    not ok 1 - inner$/m.test(sample.stdout), "NODE22_INNER_ORDINAL");
  assert.ok(/^      failureType: 'testCodeFailure'$/m.test(sample.stdout), "NODE22_INNER_FAILURE_TYPE");
  assert.ok(/^      code: 'ERR_ASSERTION'$/m.test(sample.stdout), "NODE22_INNER_ASSERTION_CODE");
  assert.ok(/^not ok 1 - suite$/m.test(sample.stdout), "NODE22_PARENT_ORDINAL");
  assert.ok(/^  failureType: 'subtestsFailed'$/m.test(sample.stdout), "NODE22_PARENT_WRAPPER_TYPE");
  assert.ok(/^# fail 1$/m.test(sample.stdout), "NODE22_GLOBAL_FAIL_COUNT");
  const safe = summarizeFailedEdgeChild(sample, EDGE_FILES);
  assert.equal(safe, `EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=1:${sha("suite")}:none:runtime nested=1:${sha("suite")}:4:1:${sha("inner")}:none:assertion`);
  assert.doesNotMatch(safe, /suite|inner|Users|Root\.ark|test\.cjs|JWT|stack/i);
});

test("nested parent matching survives Node22 TAP escaping a literal hash in the suite title", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  const folder = fs.mkdtempSync(path.join(__dirname, ".w97-nested-escaped-tap-"));
  let sample;
  try {
    const file = path.join(folder, "hash.test.cjs");
    fs.writeFileSync(file, "const {describe,it}=require('node:test');const assert=require('node:assert/strict');describe('suite #128',()=>{it('inner #1',()=>assert.equal(1,2));});", { flag: "wx" });
    const env = { ...process.env };
    delete env.NODE_TEST_CONTEXT;
    sample = spawnSync(process.execPath, ["--test", "--test-reporter=tap", file],
      { encoding: "utf8", windowsHide: true, maxBuffer: 1024 * 1024, env });
  } finally { fs.rmSync(folder, { recursive: true, force: true }); }
  assert.equal(sample.status, 1);
  assert.ok(/^not ok 1 - suite \\#128$/m.test(sample.stdout), "NODE22_ESCAPED_PARENT_NAME");
  assert.ok(/^    not ok 1 - inner \\#1$/m.test(sample.stdout), "NODE22_ESCAPED_INNER_NAME");
  const safe = summarizeFailedEdgeChild(sample, EDGE_FILES);
  assert.equal(safe, `EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=1:${sha("suite \\#128")}:none:runtime nested=1:${sha("suite \\#128")}:4:1:${sha("inner \\#1")}:none:assertion`);
});

test("nested diagnostic binds to exact top parent and hashes allowed file only; never inflates summary counters", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  const parent = "parent suite";
  const childName = `inner assertion ${hostile}`;
  const nested = ["TAP version 13", `# Subtest: ${parent}`,
    `    not ok 1 - ${childName}`, "      ---",
    String.raw`      location: 'C:\runner\Root.ark\test\issue-65-opaque-v1-v2-rollover-preflight.test.js:251:1'`,
    "      failureType: 'testCodeFailure'", "      code: 'ERR_ASSERTION'",
    `      message: '${hostile}'`, "      ...",
    "    1..1", `not ok 2 - ${parent}`, "  ---",
    "  failureType: 'subtestsFailed'", "  code: 'ERR_TEST_FAILURE'", "  ...",
    "1..2", "# tests 2", "# pass 1", "# fail 1",
    "# cancelled 0", "# skipped 0", "# todo 0"].join("\n");
  const safe = summarizeFailedEdgeChild({ status: 1, stdout: nested, stderr: hostile }, EDGE_FILES);
  assert.equal(safe, `EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=2:${sha(parent)}:none:runtime nested=2:${sha(parent)}:4:1:${sha(childName)}:${sha(relative)}:assertion`);
  assert.doesNotMatch(safe, /JWT|very-private|private\.key|Root\.ark|test\.js|inner assertion|parent suite/i);
  // An unpaired inner result must not be claimed under an unrelated wrapper.
  const forgedParent = nested.replace(`not ok 2 - ${parent}`, "not ok 2 - unrelated");
  assert.equal(summarizeFailedEdgeChild({ status: 1, stdout: forgedParent }, EDGE_FILES),
    `EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=2:${sha("unrelated")}:none:runtime nested=none`);
});

test("nested diagnostic caps child details at six even if a single parent has many failed assertions", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  const children = Array.from({ length: 9 }, (_, index) => [
    `    not ok ${index + 1} - ${hostile} ${index}`,
    "      ---", "      failureType: 'testTimeoutFailure'",
    "      code: 'ERR_TEST_FAILURE'", "      ...",
  ].join("\n"));
  const output = ["TAP version 13", "# Subtest: wrapper", ...children,
    "not ok 1 - wrapper", "  ---", "  failureType: 'subtestsFailed'",
    "  code: 'ERR_TEST_FAILURE'", "  ...", "1..1", "# tests 1", "# fail 1"].join("\n");
  const safe = summarizeFailedEdgeChild({ status: 1, stdout: output }, EDGE_FILES);
  assert.match(safe, /^EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=1:[a-f0-9]{24}:none:runtime nested=/);
  const nested = safe.slice(safe.indexOf(" nested=") + 8);
  assert.equal(nested.split(",").length, 6);
  assert.match(nested, /:timeout\+$/);
  assert.doesNotMatch(safe, /JWT|private\.key|very-private|Users|wrapper/i);
});

test("synthetic Edge producer/consumer exposes nested assertion diagnostics yet still rejects the child", () => {
  const target = require.resolve("../scripts/validate-edge-e2e");
  const parent = "diagnostic suite";
  const innerName = `inner ${hostile}`;
  const nested = ["TAP version 13", `# Subtest: ${parent}`,
    `    not ok 1 - ${innerName}`, "      ---",
    "      failureType: 'testCodeFailure'", "      code: 'ERR_ASSERTION'", "      ...",
    `not ok 1 - ${parent}`, "  ---", "  failureType: 'subtestsFailed'",
    "  code: 'ERR_TEST_FAILURE'", "  ...", "1..1", "# tests 1", "# fail 1"].join("\n");
  const originalLoad = Module._load;
  const cached = require.cache[target];
  const oldError = console.error;
  const logs = [];
  try {
    delete require.cache[target];
    Module._load = function (request, parentModule, isMain) {
      if (request === "node:child_process" && parentModule?.filename === target) {
        return { spawnSync: () => ({ status: 1, stdout: nested, stderr: hostile }) };
      }
      return originalLoad.call(this, request, parentModule, isMain);
    };
    console.error = (message) => logs.push(message);
    const { runFocusedEdgeCases } = require(target);
    assert.throws(() => runFocusedEdgeCases(), /Focused Edge test child failed/);
  } finally {
    console.error = oldError;
    Module._load = originalLoad;
    delete require.cache[target];
    if (cached) require.cache[target] = cached;
  }
  assert.deepEqual(logs, [`EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=1:${sha(parent)}:none:runtime nested=1:${sha(parent)}:4:1:${sha(innerName)}:none:assertion`]);
  assert.doesNotMatch(logs[0], /JWT|very-private|Users|diagnostic suite|inner |private\.key/i);
});

test("unknown files, malicious enum and multiple failures never echo attacker-controlled text", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  const untrusted = tap(hostile, String.raw`C:\Users\secret\outside.test.js:44:2`, hostile);
  const safe = summarizeFailedEdgeChild({ status: 1, stdout: untrusted, stderr: hostile }, EDGE_FILES);
  assert.match(safe, /^EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=19:[a-f0-9]{24}:none:runtime nested=none$/);
  assert.doesNotMatch(safe, /JWT|very-private|outside|testCodeFailure|private\.key|secret/i);
  const many = ["TAP version 13", ...Array.from({ length: 20 }, (_, i) => `not ok ${i+1} - ${hostile}`), "# fail 20"].join("\n");
  assert.match(summarizeFailedEdgeChild({ status: 1, stdout: many }, EDGE_FILES), / top=[^\s]+\+ nested=none$/);
});

test("stderr-only, spawn failure and oversized TAP never expose untrusted content", () => {
  const { summarizeFailedEdgeChild } = require("../scripts/edge-child-failure-diagnostics");
  assert.equal(summarizeFailedEdgeChild({ status: null,
    error: { code: "EACCES", message: hostile }, stderr: hostile }, EDGE_FILES),
  "EDGE_CHILD_DIAG_V1 exit=unknown spawn=EACCES failCount=unknown top=none nested=none");
  assert.equal(summarizeFailedEdgeChild({ status: null,
    error: { code: hostile }, stderr: hostile }, EDGE_FILES),
  "EDGE_CHILD_DIAG_V1 exit=unknown spawn=other failCount=unknown top=none nested=none");
  const huge = tap() + "\n" + hostile.repeat(2_000_000);
  assert.equal(summarizeFailedEdgeChild({ status: 1, stdout: huge }, EDGE_FILES),
  "EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=unknown top=none nested=none");
});

test("Edge test child consumer emits only safe diagnostics on failure and cannot turn it into a pass", () => {
  const target = require.resolve("../scripts/validate-edge-e2e");
  const originalLoad = Module._load;
  const previous = require.cache[target];
  const originalError = console.error;
  const emitted = [];
  let runner;
  try {
    delete require.cache[target];
    Module._load = function (request, parent, isMain) {
      if (request === "node:child_process" && parent?.filename === target) {
        return { spawnSync: () => ({ status: 1, stdout: tap(), stderr: hostile }) };
      }
      return originalLoad.call(this, request, parent, isMain);
    };
    runner = require(target).runFocusedEdgeCases;
    console.error = (line) => emitted.push(line);
    assert.equal(typeof runner, "function");
    assert.throws(() => runner(), /Focused Edge test child failed/);
  } finally {
    console.error = originalError;
    Module._load = originalLoad;
    delete require.cache[target];
    if (previous) require.cache[target] = previous;
  }
  assert.deepEqual(emitted, [`EDGE_CHILD_DIAG_V1 exit=1 spawn=none failCount=1 top=19:${sha(name)}:${sha(relative)}:timeout nested=none`]);
  assert.throws(() => assessEdgeTap(tap(), 1), /failed/);
  assert.equal(EXPECTED_EDGE_CASES.length, 6);
  assert.equal(EDGE_FILES.length, 5);
});
