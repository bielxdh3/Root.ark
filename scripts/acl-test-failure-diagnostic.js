"use strict";

// Security-sensitive Windows ACL test telemetry: fixed categorical vocabulary
// only. Never expose PowerShell stderr/stdout, paths, SIDs, ACEs or exception
// messages to the hosted canonical test log.
const { createHash } = require("node:crypto");
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
const CASES = Object.freeze({
  LEGACY_GENERIC_ACE: {
    file: "test/issue-65-legacy-deterministic-evidence-manifest.test.js",
    title: "Windows generic access ACEs cannot evade private snapshot ancestor checks",
    stages: ["START", "FIXTURE_READY", "BASELINE_PROTECT", "BASELINE_VERIFY",
      "ACE_WRITE", "ACE_READBACK",
      "ACE_FALLBACK_WRITE", "ACE_FALLBACK_READBACK", "ACE_DOTNET_WRITE",
      "ACE_DOTNET_READBACK", "GUARD_VERIFY", "CUSTODY_SCAN", "CUSTODY_ASSERT"],
  },
  ATOMIC_INHERIT: {
    file: "test/issue-65-sync-atomic-private-acl.test.js",
    title: "strict atomic registry rejects unsafe inherited or explicit ACL/mode without mutating it",
    stages: ["START", "ROOT_CREATED", "INHERIT_CHECK", "ROOT_OPEN", "NO_FILES"],
  },
  ATOMIC_MUTATION: {
    file: "test/issue-65-sync-atomic-private-acl.test.js",
    title: "strict atomic registry refuses a later untrusted file permission change",
    stages: ["START", "PRIVATE_ROOT", "REGISTRY_OPEN", "ACL_WRITE", "REOPEN_CHECK", "ACL_REVOKE", "TRUSTED_REOPEN"],
  },
  ATOMIC_RENAME: {
    file: "test/issue-65-sync-atomic-private-acl.test.js",
    title: "a newly unsafe ACL after rename quarantines the lock instead of allowing a retry",
    stages: ["START", "PRIVATE_ROOT", "REGISTRY_OPEN", "RENAME_HOOK", "ENROLL_CHECK", "FENCING_ASSERT"],
  },
  WEB_DAV_COLD: {
    file: "test/issue-65-sync-webdav-windows-junction-acl.test.js",
    title: "Windows native ACL worker initialization leaves the Node event loop responsive",
    stages: ["INSUFFICIENT_TICKS", "EVENT_LOOP_STALL"],
  },
});
const TRUST = new Set(["UNKNOWN", "INHERITED", "PROTECTED", "UNTRUSTED_ADDED", "REJECTED", "ACCEPTED", "QUARANTINED"]);
const ERRORS = new Set(["UNKNOWN", "ASSERTION", "ATOMIC_UNSAFE", "PERMISSION", "RUNTIME"]);
const LINE = /^# ROOTARK_ACL_V1 case=([A-Z_]{1,32}) stage=([A-Z_]{1,32}) code=([A-Z_]{1,32}) trust=([A-Z_]{1,32})$/;

function classify(error) {
  if (error?.code === "ERR_ASSERTION") return "ASSERTION";
  if (error?.code === "SYNC_ATOMIC_REGISTRY_STORAGE_UNSAFE") return "ATOMIC_UNSAFE";
  if (["EACCES", "EPERM"].includes(error?.code)) return "PERMISSION";
  return error ? "RUNTIME" : "UNKNOWN";
}

function createAclFailureDiagnostic(t, caseId) {
  const config = CASES[caseId];
  if (!config || typeof t?.diagnostic !== "function") throw Error("INVALID_ACL_DIAGNOSTIC_CASE");
  let stage = "START";
  let trust = "UNKNOWN";
  return {
    stage(value) {
      if (!config.stages.includes(value)) throw Error("INVALID_ACL_DIAGNOSTIC_STAGE");
      stage = value;
    },
    trust(value) {
      if (!TRUST.has(value)) throw Error("INVALID_ACL_DIAGNOSTIC_TRUST");
      trust = value;
    },
    async run(callback) {
      try { return await callback(); }
      catch (error) {
        if (process.platform === "win32") {
          t.diagnostic(`ROOTARK_ACL_V1 case=${caseId} stage=${stage} code=${classify(error)} trust=${trust}`);
        }
        throw error;
      }
    },
  };
}

function parseAclFailureDiagnostic(line, pending) {
  if (!pending || typeof line !== "string" || line.length > 160) return null;
  const match = LINE.exec(line);
  if (!match) return null;
  const [, caseId, stage, code, trust] = match;
  const config = CASES[caseId];
  if (!config || !config.stages.includes(stage) || !ERRORS.has(code) || !TRUST.has(trust)
    || (caseId === "WEB_DAV_COLD" && (code !== "ASSERTION" || trust !== "UNKNOWN"))) return null;
  const hasText = pending.name !== undefined || pending.path !== undefined;
  const hasHashes = pending.nameHash !== undefined || pending.pathHash !== undefined;
  // Release gate retains exact public text; canonical runner retains only
  // hashes. Mixed identities must never launder a forged test attribution.
  const matched = hasText !== hasHashes && (hasText
    ? pending.name === config.title && pending.path === config.file
    : pending.nameHash === hash(config.title) && pending.pathHash === hash(config.file));
  if (!matched) return null;
  return { stage, code, trust };
}

module.exports = { createAclFailureDiagnostic, parseAclFailureDiagnostic };
