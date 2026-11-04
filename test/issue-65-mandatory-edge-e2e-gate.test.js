"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { EXPECTED_EDGE_CASES, assessEdgeTap } = require("../scripts/validate-edge-e2e");

function tap(names = EXPECTED_EDGE_CASES, { skipped = [], failed = [], summaryOverrides = {} } = {}) {
  const output = ["TAP version 13"];
  for (const [index, name] of names.entries()) {
    output.push(`# Subtest: ${name}`);
    output.push(`${failed.includes(name) ? "not ok" : "ok"} ${index + 1} - ${name}${skipped.includes(name) ? " # SKIP Edge unavailable" : ""}`);
  }
  const summary = { tests: names.length, pass: names.length - failed.length - skipped.length,
    fail: failed.length, cancelled: 0, skipped: skipped.length, todo: 0,
    ...summaryOverrides };
  output.push(`1..${names.length}`);
  for (const [name, count] of Object.entries(summary)) output.push(`# ${name} ${count}`);
  return output.join("\n");
}

test("mandatory Edge gate accepts six unique executed E2E cases and no skipped cases", () => {
  assert.equal(EXPECTED_EDGE_CASES.length, 6);
  const evidence = assessEdgeTap(tap(), 0);
  assert.equal(evidence.verifiedCases, 6);
  assert.equal(evidence.skipped, 0);
});

test("mandatory Edge gate recognizes Node TAP escaped hash in the owner V1 #128 title", () => {
  const escapedNodeTap = tap().replaceAll("V1 #128", "V1 \\#128");
  const evidence = assessEdgeTap(escapedNodeTap, 0);
  assert.equal(evidence.verifiedCases, 6);
  const duplicate = tap([...EXPECTED_EDGE_CASES, EXPECTED_EDGE_CASES[3]])
    .replace("V1 #128", "V1 \\#128");
  assert.throws(() => assessEdgeTap(duplicate, 0), /duplicate/i);
});

test("mandatory Edge gate rejects the exact hosted Ubuntu skip false-positive", () => {
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES,
    { skipped: EXPECTED_EDGE_CASES }), 0), /skipped/i);
});

test("mandatory Edge gate rejects absent, duplicate and renamed browser cases", () => {
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES.slice(1)), 0), /missing/i);
  assert.throws(() => assessEdgeTap(tap([...EXPECTED_EDGE_CASES, EXPECTED_EDGE_CASES[0]]), 0), /duplicate/i);
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES.map((name, i) =>
    i === 0 ? `${name} altered` : name)), 0), /missing/i);
});

test("mandatory Edge gate rejects failed child, failed E2E, skipped summary and missing summary", () => {
  assert.throws(() => assessEdgeTap(tap(), 1), /exit/i);
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES,
    { failed: [EXPECTED_EDGE_CASES[1]] }), 1), /exit|failed/i);
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES,
    { skipped: [EXPECTED_EDGE_CASES[2]] }), 0), /skipped/i);
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES,
    { summaryOverrides: { skipped: 1 } }), 0), /skipped/i);
  assert.throws(() => assessEdgeTap(tap().replace("# skipped 0", ""), 0), /summary/i);
});

test("mandatory Edge gate rejects TAP reporting inconsistencies and TODO evasions", () => {
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES,
    { summaryOverrides: { pass: 5 } }), 0), /summary/i);
  assert.throws(() => assessEdgeTap(tap(EXPECTED_EDGE_CASES,
    { summaryOverrides: { todo: 1 } }), 0), /summary|todo/i);
  assert.throws(() => assessEdgeTap(tap().replace(`ok 1 - ${EXPECTED_EDGE_CASES[0]}`,
    `ok 1 - ${EXPECTED_EDGE_CASES[0]} # TODO deferred`), 0), /todo/i);
});
