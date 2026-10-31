"use strict";

// This is a mandatory, separately observable hosted Windows browser gate.
// The canonical release gate remains responsible for the complete test suite.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { summarizeFailedEdgeChild } = require("./edge-child-failure-diagnostics");

const root = path.resolve(__dirname, "..");
const EDGE = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const EDGE_FILES = Object.freeze([
  "test/issue-65-browser-offline-persisted-restore.test.js",
  "test/issue-65-opaque-device-delta-sync.test.js",
  "test/issue-65-opaque-v1-v2-rollover-preflight.test.js",
  "test/issue-65-versioned-keyring-ciphertext-archive.test.js",
  "test/issue-65-independent-catalog-csp.test.js",
]);
const EXPECTED_EDGE_CASES = Object.freeze([
  "real Edge opt-in UI refuses missing external pins and recovers signed local chunks without HTTP GET",
  "real Edge runs opaque delta browser contract under restrictive CSP",
  "real Edge CSP exposes normal authenticated manual delta import, but no unconsented sync",
  "real Edge verifies owner V1 #128 -> V2 epoch handoff under strict CSP/loopback",
  "REAL Edge: authenticated signed CBOR v2 archive export/import and failure fencing",
  "Edge allows both independently configured loopback probes and blocks an unlisted origin",
]);

function assessEdgeTap(output, exitCode) {
  if (exitCode !== 0) throw new Error("Focused Edge test child failed or did not exit successfully");
  if (typeof output !== "string" || !output.startsWith("TAP version 13")) {
    throw new Error("Focused Edge test child did not emit TAP 13 evidence");
  }
  const summary = Object.create(null);
  const cases = new Map();
  for (const line of output.split(/\r?\n/)) {
    const count = /^# (tests|pass|fail|cancelled|skipped|todo) (\d+)$/.exec(line);
    if (count) {
      if (Object.hasOwn(summary, count[1])) throw new Error("Duplicate TAP summary counter");
      summary[count[1]] = Number(count[2]);
    }
    const result = /^(ok|not ok) [1-9]\d* - (.+)$/.exec(line);
    if (!result) continue;
    const annotation = / # (SKIP|TODO)(?:\s|$)/.exec(result[2]);
    const reportedName = annotation ? result[2].slice(0, annotation.index) : result[2];
    // Node's TAP reporter escapes literal # in test titles as \#.
    const name = EXPECTED_EDGE_CASES.find((expected) =>
      reportedName === expected || reportedName === expected.replaceAll("#", "\\#"));
    if (!name) continue;
    if (cases.has(name)) throw new Error("Duplicate mandatory Edge E2E case");
    cases.set(name, { passed: result[1] === "ok", annotation: annotation?.[1] || null });
  }
  if (["tests", "pass", "fail", "cancelled", "skipped", "todo"].some(
    (key) => !Number.isSafeInteger(summary[key]))) {
    throw new Error("Missing or invalid TAP summary counters");
  }
  if (summary.skipped !== 0) throw new Error("Focused Edge suite skipped one or more cases");
  if (summary.fail !== 0 || summary.cancelled !== 0 || summary.todo !== 0
    || summary.pass !== summary.tests) {
    throw new Error("Focused Edge TAP summary reports failed, pending, or inconsistent tests");
  }
  for (const name of EXPECTED_EDGE_CASES) {
    const result = cases.get(name);
    if (!result) throw new Error("Missing mandatory Edge E2E case");
    if (!result.passed || result.annotation) throw new Error("Mandatory Edge E2E case failed, skipped, or marked TODO");
  }
  return { verifiedCases: cases.size, tests: summary.tests, skipped: summary.skipped };
}

function probeEdge() {
  if (process.platform !== "win32") throw new Error("Mandatory Edge E2E gate requires Windows");
  if (!fs.existsSync(EDGE) || !fs.statSync(EDGE).isFile()) {
    throw new Error("Required Microsoft Edge executable missing");
  }
  const disposable = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-ci-edge-probe-"));
  try {
    const result = spawnSync(EDGE, ["--headless=new", "--disable-gpu", "--disable-extensions",
      "--no-first-run", "--no-default-browser-check", `--user-data-dir=${path.join(disposable, "profile")}`,
      "--dump-dom", "data:text/html,%3Coutput%20id%3D%22rootark-edge-probe%22%3EEDGE_READY%3C/output%3E"], {
      cwd: root, windowsHide: true, encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
    });
    if (result.status !== 0 || result.error || !result.stdout?.includes('<output id="rootark-edge-probe">EDGE_READY</output>')) {
      throw new Error("Required Microsoft Edge headless DOM probe failed");
    }
  } finally {
    fs.rmSync(disposable, { recursive: true, force: true, maxRetries: 10, retryDelay: 150 });
  }
}

function runFocusedEdgeCases() {
  for (const file of EDGE_FILES) {
    if (!fs.statSync(path.join(root, file)).isFile()) throw new Error("Missing focused Edge test file");
  }
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", ...EDGE_FILES], {
    cwd: root, windowsHide: true, encoding: "utf8", maxBuffer: 32 * 1024 * 1024,
  });
  // Never reproduce untrusted child logs here: test failures may include local
  // secrets or stack traces. This gate prints only controlled numeric evidence.
  if (result.status !== 0 || result.error) {
    console.error(summarizeFailedEdgeChild(result, EDGE_FILES));
  }
  const evidence = assessEdgeTap(result.stdout, result.status);
  console.log(`PASS: focused Edge E2E gate — ${evidence.verifiedCases} required cases executed, ${evidence.skipped} skipped, ${evidence.tests} tests passed`);
}

if (require.main === module) {
  try {
    if (process.argv.length !== 3 || !["--probe", "--run"].includes(process.argv[2])) {
      throw new Error("Expected --probe or --run");
    }
    if (process.argv[2] === "--probe") {
      probeEdge();
      console.log("PASS: required Microsoft Edge headless DOM probe");
    } else {
      // --run is independently safe even when a previous CI step was omitted.
      probeEdge();
      runFocusedEdgeCases();
    }
  } catch (error) {
    // No raw child output, external paths, or arbitrary error messages.
    const safe = new Set([
      "Expected --probe or --run", "Mandatory Edge E2E gate requires Windows",
      "Required Microsoft Edge executable missing", "Required Microsoft Edge headless DOM probe failed",
      "Missing focused Edge test file", "Focused Edge test child failed or did not exit successfully",
      "Focused Edge test child did not emit TAP 13 evidence", "Duplicate TAP summary counter",
      "Duplicate mandatory Edge E2E case", "Missing or invalid TAP summary counters",
      "Focused Edge suite skipped one or more cases",
      "Focused Edge TAP summary reports failed, pending, or inconsistent tests",
      "Missing mandatory Edge E2E case", "Mandatory Edge E2E case failed, skipped, or marked TODO",
    ]);
    console.error(`FAIL: mandatory Edge E2E gate — ${safe.has(error.message) ? error.message : "execution unavailable"}`);
    process.exitCode = 1;
  }
}

module.exports = { EDGE_FILES, EXPECTED_EDGE_CASES, assessEdgeTap, runFocusedEdgeCases };
