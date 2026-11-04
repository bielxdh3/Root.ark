"use strict";

// The hosted release gate intentionally withholds arbitrary test output.
// Preserve only categorical, predeclared ACL failure stages from an actual
// failed TAP case whose title AND source file match the known security test.
// Never copy a pathname, ACE, SID, PowerShell output or exception into CI logs.
const { parseAclFailureDiagnostic } = require("./acl-test-failure-diagnostic");

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
      // The TAP title and test source filename are public identity strings,
      // not secrets. Keep exact values in memory only; never emit either.
      pending = { name: failure[1], path: null };
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
      // retain ONLY the exact test-relative filename. Never emit the source path.
      const normalized = location[1].replace(/\\+/g, "/");
      const relative = /(?:^|\/)(test\/[a-z0-9_.-]+\.test\.js)$/i.exec(normalized);
      pending.path = relative ? relative[1] : null;
      continue;
    }
    const categorical = CATEGORICAL.exec(line);
    if (!categorical || !pending.path) continue;
    const verified = parseAclFailureDiagnostic(line, pending);
    if (!verified) continue;
    safe.push(`# ROOTARK_ACL_V1 case=${categorical[1]} stage=${verified.stage} code=${verified.code} trust=${verified.trust}`);
    if (safe.length >= 16) break;
  }
  return safe;
}

module.exports = { extractHostedAclFailureDiagnostics };
