"use strict";

// Node's process status alone is insufficient: node:test intentionally returns
// exit 0 for an entirely skipped PostgreSQL suite when its URLs are missing.
function checkCompleteTap(output) {
  if (typeof output !== "string"
    || /^\s*(?:ok|not ok)\s+\d+\b[^\r\n]*#\s*(?:SKIP|TODO)\b/im.test(output)) {
    throw Error("ZK65_PG_TESTS_UNVERIFIED");
  }
  const result = {};
  for (const key of ["tests", "pass", "fail", "cancelled", "skipped", "todo"]) {
    const matches = [...output.matchAll(new RegExp("^# " + key + " ([0-9]+)\\r?$", "gm"))];
    if (matches.length !== 1) throw Error("ZK65_PG_TESTS_UNVERIFIED");
    result[key] = Number(matches[0][1]);
    if (!Number.isSafeInteger(result[key])) throw Error("ZK65_PG_TESTS_UNVERIFIED");
  }
  if (result.tests < 1 || result.pass !== result.tests
    || result.fail !== 0 || result.cancelled !== 0
    || result.skipped !== 0 || result.todo !== 0) {
    throw Error("ZK65_PG_TESTS_UNVERIFIED");
  }
  return result;
}

module.exports = { checkCompleteTap };
