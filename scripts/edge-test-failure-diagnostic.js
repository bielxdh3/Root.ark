"use strict";

const { createHash } = require("node:crypto");

// Only fixed enum values for TWO named, isolated browser fixtures are eligible
// for hosted logs. Browser exception messages, URLs, paths, key material, JS
// sources, filenames and error stacks are never forwarded.
const CASES = Object.freeze({
  V2_WITNESSED: {
    file: "test/issue-65-edge-v2-witnessed-positive.test.js",
    title: "REAL Edge owner-witnessed V2 PoP import survives fresh realm and restores only through signed-history strict mTLS-backed server",
    stages: Object.freeze({
      initial: "INITIAL", "seed-put": "SEED_PUT", "launch-edge": "LAUNCH_EDGE",
      "owner-stage": "OWNER_STAGE", "edge-import-restore": "EDGE_IMPORT_RESTORE",
      "edge-persisted-positive": "EDGE_PERSISTED_POSITIVE",
      "edge-persisted-wrong-pins": "EDGE_PERSISTED_WRONG_PINS",
      "edge-persisted-witness-revoked-after-first-get": "EDGE_PERSISTED_WITNESS_REVOKED",
      "edge-reload": "EDGE_RELOAD", "edge-negative": "EDGE_NEGATIVE",
      "edge-race-csrf-change": "EDGE_RACE_CSRF", "edge-race-logout": "EDGE_RACE_LOGOUT",
    }),
  },
  INDEXEDDB: {
    file: "test/issue-65-trusted-device-indexeddb-browser.test.js",
    title: "real Edge IndexedDB restores nonextractable trusted-device keys for independent recovery",
    stages: Object.freeze({ STARTUP: "STARTUP", TRUSTED_ROUNDTRIP: "TRUSTED_ROUNDTRIP",
      OWNER_CHECKPOINT: "OWNER_CHECKPOINT", NORMAL_SESSION: "NORMAL_SESSION",
      CROSS_TAB_REVOKE: "CROSS_TAB_REVOKE", APPROVAL_REVOKE: "APPROVAL_REVOKE" }),
  },
});
const SAFE_CODES = new Set(["ASSERTION", "RUNTIME", "PERMISSION", "DEPENDENCY"]);
const LINE = /^# ROOTARK_EDGE_V1 case=([A-Z0-9_]{1,32}) stage=([A-Z_]{1,40}) code=([A-Z_]{1,32})$/;
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);

function classify(error) {
  if (error?.code === "ERR_ASSERTION") return "ASSERTION";
  if (["EACCES", "EPERM"].includes(error?.code)) return "PERMISSION";
  if (["MODULE_NOT_FOUND", "ERR_MODULE_NOT_FOUND", "ERR_DLOPEN_FAILED"].includes(error?.code))
    return "DEPENDENCY";
  return "RUNTIME";
}

function reportEdgeFailure(t, caseId, stage, error) {
  const profile = CASES[caseId];
  if (!profile || typeof t?.diagnostic !== "function") throw Error("INVALID_EDGE_DIAGNOSTIC_CASE");
  const safeStage = profile.stages[stage];
  if (!safeStage) throw Error("INVALID_EDGE_DIAGNOSTIC_STAGE");
  if (process.platform === "win32")
    t.diagnostic(`ROOTARK_EDGE_V1 case=${caseId} stage=${safeStage} code=${classify(error)}`);
}

function parseEdgeFailureDiagnostic(line, pending) {
  if (!pending || typeof line !== "string" || line.length > 150) return null;
  const match = LINE.exec(line);
  if (!match) return null;
  const [, caseId, stage, code] = match;
  const profile = CASES[caseId];
  if (!profile || !Object.values(profile.stages).includes(stage) || !SAFE_CODES.has(code)
    || pending.nameHash !== hash(profile.title) || pending.pathHash !== hash(profile.file)) return null;
  return { stage, code };
}

module.exports = { reportEdgeFailure, parseEdgeFailureDiagnostic };
