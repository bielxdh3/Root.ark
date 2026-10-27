"use strict";

// The hosted release gate intentionally withholds arbitrary test output.
// Preserve only categorical, predeclared ACL failure stages from an actual
// failed TAP case whose title AND source file match the known security test.
// Never copy a pathname, ACE, SID, PowerShell output or exception into CI logs.
const { createHash } = require("node:crypto");
const { parseAclFailureDiagnostic } = require("./acl-test-failure-diagnostic");

const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
const ANSI = /\x1b\[[\d;]*m/g;
const FAILURE = /^not ok \d+ - (.+)$/;
const LOCATION = /^location:\s*['"]?(.+?):\d+:\d+['"]?$/;
const CATEGORICAL = /^# ROOTARK_ACL_V1 case=([A-Z_]{1,32}) stage=[A-Z_]{1,32} code=[A-Z_]{1,32} trust=[A-Z_]{1,32}$/;
// t.diagnostic() is legitimately printed *after* the failed test's YAML
// terminator, but never after the TAP plan/summary or a following Subtest.
// Keep this order-sensitive: do not let later output inherit old authority.
const BOUNDARY = /^(?:TAP version \d+|# Subtest:|\d+\.\.\d+(?:\s|$)|#\s*(?:tests|suites|pass|fail|cancelled|skipped|todo|duration_ms)\b)/;

function extractHostedAclFailureDiagnostics(output) {
  let pending = null;
  const safe = [];
  for (const raw of String(output || "").split(/\r?\n/)) {
    const line = raw.replace(ANSI, "").trim();
    if (BOUNDARY.test(line)) {
      pending = null;
      continue;
    }
    const failure = FAILURE.exec(line);
    if (failure) {
      pending = { nameHash: hash(failure[1]), pathHash: null };
      continue;
    }
    if (/^ok \d+ - /.test(line)) {
      pending = null;
      continue;
    }
    if (!pending) continue;
    const location = LOCATION.exec(line);
    if (location) {
      // Accept Windows/TAP-escaped backslashes and POSIX separators, but
      // hash ONLY a single test filename. The original path is never emitted.
      const normalized = location[1].replace(/\\+/g, "/");
      const relative = /(?:^|\/)(test\/[a-z0-9_.-]+\.test\.js)$/i.exec(normalized);
      pending.pathHash = relative ? hash(relative[1]) : null;
      continue;
    }
    const categorical = CATEGORICAL.exec(line);
    if (!categorical || !pending.pathHash) continue;
    const verified = parseAclFailureDiagnostic(line, pending);
    if (!verified) continue;
    safe.push(`# ROOTARK_ACL_V1 case=${categorical[1]} stage=${verified.stage} code=${verified.code} trust=${verified.trust}`);
    if (safe.length >= 16) break;
  }
  return safe;
}

module.exports = { extractHostedAclFailureDiagnostics };
