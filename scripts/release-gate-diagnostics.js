"use strict";

const { createHash } = require("node:crypto");

function failedTestDiagnostics(output) {
  return String(output || "").split(/\r?\n/)
    .map((line) => line.replace(/\x1b\[[\d;]*m/g, "").trim())
    .filter((line) => /^(?:not ok \d+ - |[✖✗×] |error:|failureType:|location:|(?:#\s*|ℹ\s*)(?:tests|pass|fail|cancelled|skipped|todo|suites|duration_ms)\s+\d+(?:\.\d+)?\s*$|npm (?:error|ERR!) (?:code|signal|exit)\s+[A-Z0-9_]+\s*$)/i.test(line))
    .slice(-20)
    .map((line) => line
      .replace(/\b(?:Bearer|Basic)\s+\S+/gi, "[REDACTED]")
      .replace(/\b(?:password|passphrase|client_secret|refresh_token|access_token|id_token|secret|token|cookie|authorization|api[_-]?key)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s;,]+)/gi, "[REDACTED]")
      .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, "[REDACTED]")
      .slice(0, 240))
    .join("\n").slice(0, 3000);
}

// Keep minimal metadata even when a failed Windows child exits before Node's
// final TAP counters (or prints output in another format). Test names can
// contain secrets, so only log their hashes; do not echo unrecognized output.
function unrecognizedChildProgress(output) {
  let tapHeader = false;
  let tapPlan = false;
  let results = 0;
  let subtests = 0;
  let lastResult = "none";
  let lastIndex = "none";
  let lastResultNameHash = "none";
  let lastSubtestNameHash = "none";
  const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
  for (const rawLine of String(output || "").split(/\r?\n/)) {
    const line = rawLine.replace(/\x1b\[[\d;]*m/g, "").trim();
    if (/^TAP version \d+$/.test(line)) tapHeader = true;
    if (/^1\.\.\d+$/.test(line)) tapPlan = true;
    const completed = /^(ok|not ok) ([1-9]\d{0,8}) - (.+)$/.exec(line);
    if (completed) {
      results += 1;
      lastResult = completed[1] === "ok" ? "ok" : "not_ok";
      lastIndex = completed[2];
      lastResultNameHash = hash(completed[3]);
    }
    const subtest = /^# Subtest: (.+)$/.exec(line);
    if (subtest) {
      subtests += 1;
      lastSubtestNameHash = hash(subtest[1]);
    }
  }
  return `tapHeader=${tapHeader} tapPlan=${tapPlan} resultLines=${results} subtestLines=${subtests} lastResult=${lastResult} lastIndex=${lastIndex} lastResultNameSha256=${lastResultNameHash} lastSubtestNameSha256=${lastSubtestNameHash}`;
}

module.exports = { failedTestDiagnostics, unrecognizedChildProgress };
