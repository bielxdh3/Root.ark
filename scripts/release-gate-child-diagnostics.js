"use strict";

// Failure-only, non-authoritative observability for a failed child.
// Parse stdout ONLY: stderr, exception text,
// test titles, paths, hostnames and secrets must never enter hosted logs.
// The fixed categories and numeric ordinals are HINTS, never a passing gate.
const MAX_ORDINAL = 9999999;
const SCAN_WINDOW = 256 * 1024;
const MAX_FAILED_ORDINALS = 6;
const EXIT = (status) => Number.isInteger(status) && status >= 0 && status <= 255
  ? String(status) : "unknown";
const SIGNALS = new Set(["SIGABRT", "SIGINT", "SIGKILL", "SIGQUIT", "SIGSEGV", "SIGTERM", "SIGBREAK"]);
const SPAWN_ERRORS = new Set(["EACCES", "EAGAIN", "EINTR", "EMFILE", "ENOBUFS", "ENOENT", "ENOMEM", "EPERM", "ETIMEDOUT", "EPIPE"]);
const FOOTER_COUNT = /^# (tests|pass|fail|cancelled|skipped|todo) (0|[1-9][0-9]{0,6})$/;
const PLAN = /^1\.\.(0|[1-9][0-9]{0,6})$/;
const PROGRESS = /^(?:ok|not ok) ([1-9][0-9]{0,6}) - /;
// Read only indentation and a bounded decimal, never the remaining TAP name.
// A full linear scan is needed: the failing case may be between both sampled
// windows. The caller's spawnSync already limits total stdout to 16 MiB.
const FAILURE_ORDINAL = /^( {0,24})not ok ([1-9][0-9]{0,6}) - /gm;

function boundedOrdinals(values) {
  return values.length ? `${values.slice(0, MAX_FAILED_ORDINALS).join(",")}${values.length > MAX_FAILED_ORDINALS ? "+" : ""}` : "none";
}

function summarizeUnrecognizedChild(child = {}) {
  const stdout = typeof child.stdout === "string" ? child.stdout : "";
  // spawnSync itself caps stdout at 16 MiB, but splitting a deliberately
  // newline-saturated 16 MiB buffer could allocate millions of JS strings.
  // Scan only bounded complete-line windows around the beginning and end.
  const sampled = stdout.length > 2 * SCAN_WINDOW;
  const firstWindow = stdout.slice(0, SCAN_WINDOW);
  const lastWindow = stdout.slice(-SCAN_WINDOW);
  const boundary = firstWindow.lastIndexOf("\n");
  const start = sampled ? firstWindow.slice(0, boundary + 1) : stdout;
  const end = sampled ? lastWindow.slice(lastWindow.indexOf("\n") + 1) : "";
  const observed = sampled ? `${start}\n${end}` : stdout;
  // Numeric status and known OS error/signal symbols originate from spawnSync,
  // not freeform child stdout/stderr. Anything unknown is collapsed to 'other'.
  const exit = EXIT(child.status);
  const signal = child.signal == null ? "none"
    : SIGNALS.has(child.signal) ? child.signal : "other";
  const code = child.error?.code;
  const spawn = code == null ? "none" : SPAWN_ERRORS.has(code) ? code : "other";
  let tap = false;
  let spec = false;
  let trace = false;
  let exception = false;
  let first = null;
  let last = null;
  let plan = null;
  const failedTop = [];
  const failedNested = [];
  const counters = Object.create(null);
  let footerStarted = false;
  for (const raw of observed.split(/\r?\n/)) {
    // Do not print raw, quoted, or redacted lines. Report only allowlisted
    // fixed marker names and bounded decimal ordinals.
    const line = raw.replace(/\x1b\[[\d;]*m/g, "");
    if (/^TAP version 13$/.test(line)) tap = true;
    if (/^[✔✖✗×] /.test(line)) spec = true;
    if (/^node:internal\//.test(line)) trace = true;
    if (/^(?:Error|TypeError|SyntaxError|RangeError|ReferenceError|AssertionError)(?:\s*\[|:)/.test(line)) exception = true;
    if (!tap) continue;
    const match = PROGRESS.exec(line);
    if (!footerStarted && match) {
      const number = Number(match[1]);
      if (number >= 1 && number <= MAX_ORDINAL) {
        if (first === null) first = number;
        last = number;
      }
    }
    const foundPlan = PLAN.exec(line);
    if (foundPlan) {
      footerStarted = true;
      plan = Number(foundPlan[1]);
      for (const key of Object.keys(counters)) delete counters[key];
      continue;
    }
    if (!footerStarted) continue;
    const counter = FOOTER_COUNT.exec(line);
    if (counter) counters[counter[1]] = Number(counter[2]);
  }
  if (tap) {
    for (const found of stdout.matchAll(FAILURE_ORDINAL)) {
      const indent = found[1].length;
      const ordinal = Number(found[2]);
      if (indent === 0 && failedTop.length <= MAX_FAILED_ORDINALS) {
        failedTop.push(ordinal);
      } else if (indent >= 4 && indent % 4 === 0 && failedNested.length <= MAX_FAILED_ORDINALS) {
        failedNested.push(`${indent}:${ordinal}`);
      }
    }
  }
  const required = ["tests", "pass", "fail", "cancelled", "skipped", "todo"];
  const hasFullCounters = required.every((name) => Object.hasOwn(counters, name));
  const footer = !tap || plan === null || !hasFullCounters ? "missing"
    // Node --test counts nested cases in #tests, while the plan counts only
    // top-level cases (e.g. 1..1661 with # tests 2286). Never equate them.
    : plan <= counters.tests && (last === null ? plan === 0 : last === plan)
      && required.slice(1).reduce((sum, name) => sum + counters[name], 0) === counters.tests
      ? "valid" : "invalid";
  const progress = first === null ? "none" : `${first}:${last}`;
  const reporter = tap ? "tap" : spec ? "spec" : "none";
  const hint = trace ? "node_trace" : exception ? "node_exception" : "none";
  const failCount = Object.hasOwn(counters, "fail") ? counters.fail : "unknown";
  return `CHILD_DIAG_V1 exit=${exit} signal=${signal} spawn=${spawn} footer=${footer} progress=${progress} reporter=${reporter} hint=${hint} failCount=${failCount} failTop=${boundedOrdinals(failedTop)} failNested=${boundedOrdinals(failedNested)} window=${sampled ? "sampled" : "complete"}`;
}

module.exports = { summarizeUnrecognizedChild };
