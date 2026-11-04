"use strict";

// Non-authoritative, failure-only telemetry. The child TAP contains untrusted
// messages, paths and potentially credentials. Never emit any of those bytes.
const { createHash } = require("node:crypto");

const MAX_STDOUT_CHARS = 32 * 1024 * 1024;
const MAX_FAILURES = 6;
const MAX_ORDINAL = 9999999;
const FILE = /^test\/[A-Za-z0-9._-]{1,160}\.test\.js$/;
const LOCATION = /^  location: '([^'\r\n]{1,4096})'$/;
const RESULT = /^not ok ([1-9][0-9]{0,6}) - (.{1,4096})$/;
const NESTED_RESULT = /^( {4,24})not ok ([1-9][0-9]{0,6}) - (.{1,4096})$/;
const NESTED_OK = /^ {4,24}ok [1-9][0-9]{0,6} - /;
const TOP_SUBTEST = /^# Subtest: (.{1,4096})$/;
const FAILURE_TYPE = /^  failureType: '([A-Za-z]{1,40})'$/;
const CODE = /^  code: '([A-Z0-9_]{1,40})'$/;
const INDENTED_LOCATION = /^( {6,26})location: '([^'\r\n]{1,4096})'$/;
const INDENTED_TYPE = /^( {6,26})failureType: '([A-Za-z]{1,40})'$/;
const INDENTED_CODE = /^( {6,26})code: '([A-Z0-9_]{1,40})'$/;
const SUMMARY = /^# fail (0|[1-9][0-9]{0,6})$/;
const SPAWN_ERRORS = new Set(["EACCES", "EAGAIN", "EINTR", "EMFILE", "ENOBUFS",
  "ENOENT", "ENOMEM", "EPERM", "ETIMEDOUT", "EPIPE"]);
const hash = (text) => createHash("sha256").update(text).digest("hex").slice(0, 24);
const EDGE_ARCHIVE_FILE = "test/issue-65-versioned-keyring-ciphertext-archive.test.js";
const EDGE_ARCHIVE_TITLE = "REAL Edge: authenticated signed CBOR v2 archive export/import and failure fencing";
const EDGE_ARCHIVE_TITLE_HASH = hash(EDGE_ARCHIVE_TITLE);
const EDGE_ARCHIVE_FILE_HASH = hash(EDGE_ARCHIVE_FILE);
const EDGE_OFFLINE_TITLE_HASH = hash("real Edge opt-in UI refuses missing external pins and recovers signed local chunks without HTTP GET");
const EDGE_OFFLINE_FILE_HASH = hash("test/issue-65-browser-offline-persisted-restore.test.js");
// Test-owned phase labels only. Never propagate Edge's raw DOM result, CDP
// errors, paths, ciphertext, key material or untrusted diagnostic strings.
const EDGE_OFFLINE_STAGE = /^# EDGE_OFFLINE_STAGE_V1 (fixture|lab-setup|server-listen|edge-launch|cdp-port|cdp-target|cdp-websocket|cdp-navigate|ui-outcome|cleanup)$/;
// Print only a numeric call-site from this allowlisted test, never any stack,
// error text or runtime value. A forged TAP can mislead diagnostics but never
// makes the actual release gate green.
const ARCHIVE_STACK_SITE = /(?:^|[\\/])test[\\/]+issue-65-versioned-keyring-ciphertext-archive\.test\.js:([1-9]\d{0,4}):[1-9]\d{0,3}\)?$/;

function categoryFor(result) {
  return result.type === "testTimeoutFailure" ? "timeout"
    : result.code === "ERR_ASSERTION" ? "assertion" : "runtime";
}

function fileHashFor(location, allowlist) {
  const found = /(?:^|[\\/])test[\\/]+([A-Za-z0-9._-]{1,160}\.test\.js):[1-9]\d{0,7}:[1-9]\d{0,7}$/.exec(location);
  if (!found) return "none";
  const relative = `test/${found[1]}`;
  return allowlist.has(relative) ? hash(relative) : "none";
}

function summarizeFailedEdgeChild(child, edgeFiles) {
  const exit = Number.isInteger(child?.status) && child.status >= 0 && child.status <= 255
    ? String(child.status) : "unknown";
  const spawnCode = child?.error?.code;
  const spawn = spawnCode == null ? "none"
    : SPAWN_ERRORS.has(spawnCode) ? spawnCode : "other";
  const allowlist = new Set(Array.isArray(edgeFiles) ? edgeFiles.filter(
    (name) => typeof name === "string" && FILE.test(name)).slice(0, 5) : []);
  const stdout = typeof child?.stdout === "string" && child.stdout.length <= MAX_STDOUT_CHARS
    ? child.stdout : "";
  const failures = [];
  const nestedFailures = [];
  let overflow = false;
  let nestedOverflow = false;
  let current = null;
  let group = null;
  let inner = null;
  let failCount = "unknown";
  let archiveCallSite = null;
  let archiveFailed = false;
  let offlineStage = null;
  let offlineFailed = false;
  function isArchiveHelperLine(number) {
    return (number >= 616 && number <= 623)
      || (number >= 643 && number <= 660)
      || (number >= 718 && number <= 728);
  }
  function flushNested() {
    if (!inner) return;
    if (group) {
      if (group.entries.length < MAX_FAILURES) {
        group.entries.push(`${inner.indent}:${inner.ordinal}:${inner.nameHash}:${inner.fileHash}:${categoryFor(inner)}`);
      } else group.overflow = true;
    }
    inner = null;
  }
  function flush() {
    if (!current) return;
    if (current.nameHash === EDGE_OFFLINE_TITLE_HASH
      && current.fileHash === EDGE_OFFLINE_FILE_HASH) offlineFailed = true;
    if (current.nameHash === EDGE_ARCHIVE_TITLE_HASH
      && current.fileHash === EDGE_ARCHIVE_FILE_HASH) {
      archiveFailed = true;
      if (current.archiveCallSite != null) archiveCallSite = current.archiveCallSite;
    }
    if (failures.length >= MAX_FAILURES) overflow = true;
    else {
      failures.push(`${current.ordinal}:${current.nameHash}:${current.fileHash}:${categoryFor(current)}`);
    }
    if (current.group) {
      for (const entry of current.group.entries) {
        if (nestedFailures.length >= MAX_FAILURES) nestedOverflow = true;
        else nestedFailures.push(`${current.ordinal}:${current.nameHash}:${entry}`);
      }
      if (current.group.overflow) nestedOverflow = true;
    }
    current = null;
  }
  // Scan bounded bytes line-by-line, without allocating an unbounded array of
  // strings. Indented nested TAP results are never mistaken for top-level.
  for (let start = 0; start < stdout.length;) {
    const next = stdout.indexOf("\n", start);
    const end = next === -1 ? stdout.length : next;
    const size = end - start;
    const line = size <= 8192
      ? stdout.slice(start, end).replace(/\r$/, "") : "";
    start = next === -1 ? stdout.length : next + 1;
    const offline = EDGE_OFFLINE_STAGE.exec(line);
    if (offline && offlineStage === null) offlineStage = offline[1];
    const subtest = TOP_SUBTEST.exec(line);
    if (subtest) {
      flushNested();
      flush();
      // A nested failure may be attributed ONLY to an exactly matching
      // subsequent top-level result, not to an unrelated suite or footer.
      group = { nameHash: hash(subtest[1]), entries: [], overflow: false };
      continue;
    }
    const nested = NESTED_RESULT.exec(line);
    if (nested) {
      flushNested();
      const indent = nested[1].length;
      if (group && indent % 4 === 0) {
        inner = { indent, ordinal: Number(nested[2]), nameHash: hash(nested[3]),
          fileHash: "none", type: "unknown", code: "unknown" };
      }
      continue;
    }
    if (NESTED_OK.test(line)) { flushNested(); continue; }
    const result = RESULT.exec(line);
    if (result) {
      flushNested();
      flush();
      const ordinal = Number(result[1]);
      if (ordinal <= MAX_ORDINAL) {
        const nameHash = hash(result[2]);
        current = { ordinal, nameHash, fileHash: "none",
          type: "unknown", code: "unknown",
          group: group?.nameHash === nameHash ? group : null };
      }
      group = null;
      continue;
    }
    // A passing top-level result terminates its preceding failure's details.
    if (/^ok [1-9][0-9]{0,6} - /.test(line)) {
      flushNested(); flush(); group = null; continue;
    }
    const footer = SUMMARY.exec(line);
    if (footer) failCount = footer[1];
    if (inner) {
      const location = INDENTED_LOCATION.exec(line);
      if (location && location[1].length === inner.indent + 2) {
        inner.fileHash = fileHashFor(location[2], allowlist);
      }
      const kind = INDENTED_TYPE.exec(line);
      if (kind && kind[1].length === inner.indent + 2) {
        inner.type = kind[2] === "testTimeoutFailure" ? kind[2] : "unknown";
      }
      const code = INDENTED_CODE.exec(line);
      if (code && code[1].length === inner.indent + 2) {
        inner.code = code[2] === "ERR_ASSERTION" ? code[2] : "unknown";
      }
    }
    if (!current) continue;
    const location = LOCATION.exec(line);
    if (location) {
      current.fileHash = fileHashFor(location[1], allowlist);
    }
    const kind = FAILURE_TYPE.exec(line);
    if (kind) current.type = kind[1] === "testTimeoutFailure" ? kind[1] : "unknown";
    const code = CODE.exec(line);
    if (code) current.code = code[1] === "ERR_ASSERTION" ? code[1] : "unknown";
    if (current.nameHash === EDGE_ARCHIVE_TITLE_HASH) {
      const stackSite = ARCHIVE_STACK_SITE.exec(line);
      if (stackSite) {
        const lineNumber = Number(stackSite[1]);
        if (lineNumber >= 535 && lineNumber <= 940
          && !isArchiveHelperLine(lineNumber)
          && current.archiveCallSite == null) current.archiveCallSite = lineNumber;
      }
    }
  }
  flushNested();
  flush();
  const top = failures.length ? failures.join(",") + (overflow ? "+" : "") : "none";
  const nested = nestedFailures.length
    ? nestedFailures.join(",") + (nestedOverflow ? "+" : "") : "none";
  const archiveHint = archiveFailed
    ? ` archiveCallSite=${archiveCallSite === null ? "none" : archiveCallSite}` : "";
  const offlineHint = offlineFailed && offlineStage !== null
    ? ` offlineStage=${offlineStage}` : "";
  return `EDGE_CHILD_DIAG_V1 exit=${exit} spawn=${spawn} failCount=${failCount} top=${top} nested=${nested}${archiveHint}${offlineHint}`;
}

module.exports = { summarizeFailedEdgeChild };
