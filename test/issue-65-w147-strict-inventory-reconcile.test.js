"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const child = path.join(__dirname, "support", "w147-inventory-reconciliation-child.cjs");
function run(root, phase, strict) {
  const proc = spawnSync(process.execPath, [child, phase], {
    cwd: root, encoding: "utf8", timeout: 30000, windowsHide: true,
    env: { ...process.env, DB_ENABLED: "false", BACKUP_ENABLED: "true",
      ROOTARK_ZK10_SYNC_CUTOVER_STRICT: strict },
  });
  assert.equal(proc.status, 0, phase + ": " + (proc.stderr || proc.stdout));
  const line = proc.stdout.trim().split(/\r?\n/).at(-1);
  return JSON.parse(line);
}

test("STRICT with no pending inventory may boot without cloud I/O or falsely certifying reconciliation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-known-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const known = run(root, "known", "1");
  assert.deepEqual(known, { phase: "known", state: "known", changed: false,
    uploads: 0, inventoryCalls: 0 });
});

test("strict startup reconcile cannot bypass public guard through internal inventory worker; legacy OFF retries", { timeout: 120000 }, (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-inventory-p1-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const staged = run(root, "stage", "0");
  assert.equal(staged.state, "unknown");
  assert.equal(fs.existsSync(path.join(root, "fixture-provider-upload.bin")), false);
  const strict = run(root, "reconcile", "1");
  assert.deepEqual({
    outcome: strict.outcome, code: strict.code, uploads: strict.uploads,
    providerHasPlaintext: strict.providerHasPlaintext, markerState: strict.markerState,
  }, {
    outcome: "rejected", code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE", uploads: 0,
    providerHasPlaintext: false, markerState: "unknown",
  }, "STRICT must deny before every provider upload and preserve pending marker");
  const activeCutover = run(root, "flip", "0");
  assert.deepEqual({
    strict: activeCutover.strict, outcome: activeCutover.outcome,
    code: activeCutover.code, uploads: activeCutover.uploads,
    providerHasPlaintext: activeCutover.providerHasPlaintext, markerState: activeCutover.markerState,
  }, {
    strict: "1", outcome: "rejected", code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE",
    uploads: 0, providerHasPlaintext: false, markerState: "unknown",
  }, "an internal worker must re-check STRICT after the ZIP baseline validation, immediately before provider PUT");
  const lateCutover = run(root, "flipLate", "0");
  assert.deepEqual({
    strict: lateCutover.strict, outcome: lateCutover.outcome, code: lateCutover.code,
    uploads: lateCutover.uploads, providerHasPlaintext: lateCutover.providerHasPlaintext,
    markerState: lateCutover.markerState,
  }, {
    strict: "1", outcome: "rejected", code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE",
    uploads: 0, providerHasPlaintext: false, markerState: "unknown",
  }, "cutover after the Drive stable-id reservation must abort before PUT and preserve the inventory marker");
  const resumed = run(root, "reconcile", "0");
  assert.equal(resumed.outcome, "ok", JSON.stringify(resumed));
  assert.equal(resumed.uploads, 1, "OFF preserves actual legacy provider restore");
  assert.equal(resumed.providerHasPlaintext, true, "OFF uploaded authentic local bytes");
  assert.equal(resumed.markerState, "reconciled");
});
