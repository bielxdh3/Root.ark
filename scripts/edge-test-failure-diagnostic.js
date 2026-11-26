"use strict";

const { createHash } = require("node:crypto");

// Only fixed enum values for named, isolated browser fixtures are eligible
// for hosted logs. Browser exception messages, URLs, paths, key material, JS
// sources, filenames and error stacks are never forwarded.
const CASES = Object.freeze({
  V2_ARCHIVE: {
    file: "test/issue-65-versioned-keyring-ciphertext-archive.test.js",
    title: "REAL Edge: authenticated signed CBOR v2 archive export/import and failure fencing",
    stages: Object.freeze({
      initial: "INITIAL", "launch-edge": "LAUNCH_EDGE",
      "edge-ui": "EDGE_UI", "owner-provision": "OWNER_PROVISION",
      "archive-export": "ARCHIVE_EXPORT", "archive-import": "ARCHIVE_IMPORT",
      "negative-proofs": "NEGATIVE_PROOFS", "historical-recovery": "HISTORICAL_RECOVERY",
      "session-revocation": "SESSION_REVOCATION",
    }),
  },
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
  REPLACEMENT_CONSENT: {
    file: "test/issue-63-real-edge-replacement-consent.test.js",
    title: "real Edge: selected 128-revision UI batches consume replacement consent and cancel later-window search atomically",
    stages: Object.freeze({
      initial: "INITIAL",
      "busy-native-escape-cancels-batch-atomically": "BUSY_ESCAPE",
      "owner-batch-A-succeeds": "OWNER_BATCH",
      "native-escape-close-and-reopen-must-consume-consent": "ESCAPE_REOPEN",
      "fresh-B-default-append-denied-without-replace": "APPEND_DENIED",
      "fresh-B-explicit-replacement-succeeds": "REPLACEMENT",
      "visible-cancel-after-first-window": "VISIBLE_CANCEL",
      unknown: "UNKNOWN",
    }),
  },
});
const REPLACEMENT_CANCEL_CODES = Object.freeze({
  CANCEL_UI_NINTH_GET_NOT_PAUSED_AFTER_FIRST_WINDOW: "PAUSE_MISSING",
  CANCEL_UI_VERIFIED_GET_PRE_RELEASE_MISMATCH: "PRE_RELEASE_VERIFY",
  CANCEL_UI_NINTH_GET_NOT_RELEASED: "RELEASE_MISSING",
  CANCEL_UI_BUTTON_CLEANUP_FAILED: "BUTTON_CLEANUP",
  CANCEL_UI_FINAL_STATE_MISSING: "FINAL_STATE",
  CANCEL_UI_PARTIAL_RESULTS_SHOWN: "PARTIAL_RESULTS",
  CANCEL_UI_VERIFIED_GET_INCREMENT_AFTER_CLEANUP: "VERIFY_INCREMENT",
  CANCEL_UI_LATER_SIGNED_GET: "LATER_GET",
  CANCEL_UI_PARTIAL_INDEX_WRITE: "PARTIAL_INDEX",
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

function reportReplacementFailure(t, result) {
  if (typeof result !== "string" || !result.startsWith("EDGE_REPLACE_ONCE_FAIL:")) return;
  const match = /^EDGE_REPLACE_ONCE_FAIL:([^:]{1,80}):/.exec(result);
  const stages = CASES.REPLACEMENT_CONSENT.stages;
  const stage = match && Object.hasOwn(stages, match[1]) ? stages[match[1]] : "UNKNOWN";
  const reason = match && result.length - match[0].length <= 80
    ? result.slice(match[0].length) : "";
  const code = stage === "VISIBLE_CANCEL" && Object.hasOwn(REPLACEMENT_CANCEL_CODES, reason)
    ? REPLACEMENT_CANCEL_CODES[reason] : "RUNTIME";
  if (process.platform === "win32")
    t.diagnostic(`ROOTARK_EDGE_V1 case=REPLACEMENT_CONSENT stage=${stage} code=${code}`);
}

function parseEdgeFailureDiagnostic(line, pending) {
  if (!pending || typeof line !== "string" || line.length > 150) return null;
  const match = LINE.exec(line);
  if (!match) return null;
  const [, caseId, stage, code] = match;
  const profile = CASES[caseId];
  const allowedCode = caseId === "REPLACEMENT_CONSENT"
    ? code === "RUNTIME" || (stage === "VISIBLE_CANCEL" && Object.values(REPLACEMENT_CANCEL_CODES).includes(code))
    : SAFE_CODES.has(code);
  if (!profile || !Object.values(profile.stages).includes(stage) || !allowedCode
    || pending.nameHash !== hash(profile.title) || pending.pathHash !== hash(profile.file)) return null;
  return { stage, code };
}

module.exports = { reportEdgeFailure, reportReplacementFailure, parseEdgeFailureDiagnostic };
