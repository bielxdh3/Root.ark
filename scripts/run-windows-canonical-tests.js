"use strict";

const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const { StringDecoder } = require("node:string_decoder");
const { getNpmInvocation } = require("./release-gate-environment");
const { parseAclFailureDiagnostic } = require("./acl-test-failure-diagnostic");
const { parseEdgeFailureDiagnostic } = require("./edge-test-failure-diagnostic");

// Hosted Windows can terminate a process before Node exit/close callbacks run.
// Small, synchronous and secret-safe progress breadcrumbs preserve the last
// observed state even when the final TAP summary cannot be emitted.
const HEARTBEAT_MS = 15_000;
const IDLE_LIMIT_MS = 15 * 60_000;
const TOTAL_LIMIT_MS = 55 * 60_000;
const SAFE_CODES = new Set(["ERR_ASSERTION", "ERR_TEST_FAILURE", "SQLITE_BUSY",
  "SQLITE_LOCKED", "ENOENT", "EACCES", "EPERM", "EADDRINUSE", "ETIMEDOUT",
  "ECONNRESET", "ERR_DLOPEN_FAILED", "MODULE_NOT_FOUND", "ERR_MODULE_NOT_FOUND"]);
const SAFE_FAILURE_TYPES = new Set(["testCodeFailure", "hookFailed", "cancelledByParent",
  "uncaughtException", "unhandledRejection", "subtestsFailed"]);
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
// Only a complete, trailing TAP directive token excuses "not ok". A title
// containing e.g. "# TODOS", "# TODO:" or a bare trailing space remains FAIL.
function tapExemption(title) {
  const directive = / # (TODO|SKIP)(?:[ \t]+\S.*)?$/i.exec(title);
  return directive ? directive[1].toUpperCase() : null;
}
function categoryFor(code) {
  if (code === "ERR_ASSERTION") return "assertion";
  if (["SQLITE_BUSY", "SQLITE_LOCKED"].includes(code)) return "sqlite_busy";
  if (["ENOENT", "EACCES", "EPERM", "EADDRINUSE"].includes(code)) return "filesystem";
  if (["ETIMEDOUT", "ECONNRESET"].includes(code)) return "network_timeout";
  if (["ERR_DLOPEN_FAILED", "MODULE_NOT_FOUND", "ERR_MODULE_NOT_FOUND"].includes(code)) return "dependency";
  if (code === "ERR_TEST_FAILURE") return "runtime";
  return "unknown";
}

function canonicalWindowsTestEnvironment(environment = process.env,
  platform = process.platform, tempDirectory = os.tmpdir()) {
  if (platform !== "win32") return environment;
  // Hosted Windows runners can expose TEMP through an administrator-managed
  // junction. ZK SQLite fixtures must use the actual directory so their
  // strict ancestor-junction guard still rejects untrusted paths.
  const canonicalTemp = fs.realpathSync.native(tempDirectory);
  if (!fs.statSync(canonicalTemp).isDirectory()) {
    throw Error("Windows canonical suite requires a real temporary directory");
  }
  return { ...environment, TEMP: canonicalTemp, TMP: canonicalTemp };
}

function createTapProgressRecorder(write) {
  const state = { results: 0, failures: 0, plan: false, tests: null, reportedFailures: null,
    lastResultHash: "none", lastSubtestHash: "none", subtests: 0,
    observedFailures: 0, topLevelTodos: 0, topLevelSkips: 0,
    nestedResults: 0, nestedObservedFailures: 0, nestedFailures: 0,
    nestedTodos: 0, nestedSkips: 0, lastNestedFailureHash: "none",
    fileBoundaries: 0, lastFileHash: "none" };
  const categories = { assertion: 0, sqlite_busy: 0, filesystem: 0,
    network_timeout: 0, dependency: 0, runtime: 0, unknown: 0 };
  const failurePaths = new Map();
  const nestedFailurePaths = new Map();
  const nestedFailureDepths = { 2: 0, 4: 0, 6: 0, 8: 0, other: 0 };
  let pending = null;
  let nestedPending = null;
  let detailed = 0;
  let nestedDetailed = 0;
  let verifiedAclOverflowDetails = 0;
  const fileLocation = (location) => {
    const file = /(?:^|[\\/]+)test[\\/]+([A-Za-z0-9._-]{1,160}\.test\.js):\d+:\d+$/.exec(location);
    return file ? hash(`test/${file[1]}`) : "none";
  };
  const finishNested = () => {
    if (!nestedPending) return;
    if (nestedPending.pathHash !== "none" && (nestedFailurePaths.size < 32 || nestedFailurePaths.has(nestedPending.pathHash))) {
      nestedFailurePaths.set(nestedPending.pathHash, (nestedFailurePaths.get(nestedPending.pathHash) || 0) + 1);
    }
    if (nestedDetailed < 8) {
      write(`FAIL nested detail depth=${nestedPending.depth} index=${nestedPending.index} nameSha256=${nestedPending.nameHash} testPathSha256=${nestedPending.pathHash} failureType=${nestedPending.failureType} code=${nestedPending.code}`);
      nestedDetailed++;
    }
    nestedPending = null;
  };
  const finish = () => {
    finishNested();
    if (!pending) return;
    const category = categoryFor(pending.code);
    categories[category]++;
    if (pending.pathHash !== "none") {
      failurePaths.set(pending.pathHash, (failurePaths.get(pending.pathHash) || 0) + 1);
    }
    if (detailed < 12) {
      const acl = pending.acl
        ? ` aclStage=${pending.acl.stage} aclError=${pending.acl.code} aclTrust=${pending.acl.trust}` : "";
      const edge = pending.edge
        ? ` edgeStage=${pending.edge.stage} edgeError=${pending.edge.code}` : "";
      write(`FAIL detail index=${pending.index} nameSha256=${pending.nameHash} testPathSha256=${pending.pathHash} failureType=${pending.failureType} code=${pending.code} category=${category}${acl}${edge}`);
      detailed++;
    } else if (pending.acl && verifiedAclOverflowDetails < 4) {
      // Numerous unrelated failed tests must not suppress the bounded, strictly
      // allowlisted ACL diagnostics needed to investigate hosted security gates.
      // parseAclFailureDiagnostic already verified case, test title and path hashes.
      write(`FAIL verified ACL detail index=${pending.index} nameSha256=${pending.nameHash} testPathSha256=${pending.pathHash} aclStage=${pending.acl.stage} aclError=${pending.acl.code} aclTrust=${pending.acl.trust}`);
      verifiedAclOverflowDetails++;
    }
    pending = null;
  };
  return {
    state,
    finish,
    safeSummary() {
      const topFailurePaths = [...failurePaths].sort((a, b) => b[1] - a[1]
        || a[0].localeCompare(b[0])).slice(0, 4)
        .map(([pathHash, count]) => `${pathHash}:${count}`).join(",") || "none";
      const topNestedFailurePaths = [...nestedFailurePaths].sort((a, b) => b[1] - a[1]
        || a[0].localeCompare(b[0])).slice(0, 4)
        .map(([pathHash, count]) => `${pathHash}:${count}`).join(",") || "none";
      return `failureCategories=${Object.entries(categories).map(([name, count]) => `${name}=${count}`).join(",")} pending=${pending ? 1 : 0} details=${detailed} failurePathGroups=${failurePaths.size} topFailurePaths=${topFailurePaths} subtests=${state.subtests} lastSubtestSha256=${state.lastSubtestHash} lastResultSha256=${state.lastResultHash} observedFailures=${state.observedFailures} topLevelTodos=${state.topLevelTodos} topLevelSkips=${state.topLevelSkips} nestedResults=${state.nestedResults} nestedObservedFailures=${state.nestedObservedFailures} nestedFailures=${state.nestedFailures} nestedTodos=${state.nestedTodos} nestedSkips=${state.nestedSkips} nestedPending=${nestedPending ? 1 : 0} nestedFailureDepths=${Object.entries(nestedFailureDepths).map(([depth, count]) => `${depth}:${count}`).join(",")} nestedDetails=${nestedDetailed} nestedFailurePathGroups=${nestedFailurePaths.size} topNestedFailurePaths=${topNestedFailurePaths} lastNestedFailureSha256=${state.lastNestedFailureHash} fileBoundaries=${state.fileBoundaries} lastFileSha256=${state.lastFileHash}`;
    },
    accept(line) {
      const subtest = /^\s{0,8}# Subtest: (.{1,4096})$/.exec(line);
      if (subtest) {
        state.lastSubtestHash = hash(subtest[1]);
        state.subtests += 1;
      }
      // Keep existing top-level TAP counters stable. Nested failures are
      // separate evidence, since a later enclosing failure may repeat them.
      const nestedResult = /^( {1,64})(ok|not ok) ([1-9]\d{0,8}) - (.{1,4096})$/.exec(line);
      if (nestedResult) {
        finishNested();
        state.nestedResults++;
        if (nestedResult[2] === "not ok") {
          state.nestedObservedFailures++;
          const exemption = tapExemption(nestedResult[4]);
          if (exemption === "TODO") state.nestedTodos++;
          else if (exemption === "SKIP") state.nestedSkips++;
          else {
            const depth = nestedResult[1].length;
            const bucket = Object.hasOwn(nestedFailureDepths, depth) ? depth : "other";
            nestedFailureDepths[bucket]++;
            state.nestedFailures++;
            state.lastNestedFailureHash = hash(nestedResult[4]);
            nestedPending = { depth, index: nestedResult[3], nameHash: state.lastNestedFailureHash,
              pathHash: "none", failureType: "unknown", code: "unknown" };
          }
        }
      }
      const result = /^(ok|not ok) ([1-9]\d{0,8}) - (.{1,4096})$/.exec(line);
      if (result) {
        finish();
        state.results += 1;
        state.lastResultHash = hash(result[3]);
        const fileBoundary = /^(?:[A-Za-z]:[\\/]|\/)?(?:.*[\\/])?test[\\/]([A-Za-z0-9._-]{1,160}\.test\.js)$/.exec(result[3]);
        if (fileBoundary) {
          state.fileBoundaries++;
          state.lastFileHash = hash(`test/${fileBoundary[1]}`);
        }
        if (result[1] === "not ok") {
          state.observedFailures++;
          const exemption = tapExemption(result[3]);
          if (exemption === "TODO") state.topLevelTodos++;
          else if (exemption === "SKIP") state.topLevelSkips++;
          else {
            state.failures += 1;
            const nameHash = hash(result[3]);
            write(`FAIL test result index=${result[2]} nameSha256=${nameHash}`);
            pending = { index: result[2], nameHash, pathHash: "none",
              failureType: "unknown", code: "unknown" };
          }
        } else if (state.results % 25 === 0) {
          write(`Windows canonical progress: ${state.results} TAP results, ${state.failures} failed`);
        }
      }
      if (nestedPending && !nestedResult) {
        const detail = line.slice(nestedPending.depth + 2);
        if (line.startsWith(" ".repeat(nestedPending.depth + 2))) {
          const location = /^location: ['"](.{1,2048})['"]$/.exec(detail);
          if (location) nestedPending.pathHash = fileLocation(location[1]);
          const kind = /^failureType: '([A-Za-z]{1,40})'$/.exec(detail);
          if (kind && SAFE_FAILURE_TYPES.has(kind[1])) nestedPending.failureType = kind[1];
          const code = /^code: '([A-Z0-9_]{1,40})'$/.exec(detail);
          if (code && SAFE_CODES.has(code[1])) nestedPending.code = code[1];
        }
      }
      if (pending) {
        const location = /^  location: ['"](.{1,2048})['"]$/.exec(line);
        if (location) {
          pending.pathHash = fileLocation(location[1]);
        }
        const kind = /^  failureType: '([A-Za-z]{1,40})'$/.exec(line);
        if (kind && SAFE_FAILURE_TYPES.has(kind[1])) pending.failureType = kind[1];
        const code = /^  code: '([A-Z0-9_]{1,40})'$/.exec(line);
        if (code && SAFE_CODES.has(code[1])) pending.code = code[1];
        const acl = parseAclFailureDiagnostic(line, pending);
        if (acl) pending.acl = acl;
        const edge = parseEdgeFailureDiagnostic(line, pending);
        if (edge) pending.edge = edge;
      }
      if (/^1\.\.\d+$/.test(line)) state.plan = true;
      const tests = /^# tests (\d+)$/.exec(line);
      if (tests) state.tests = Number(tests[1]);
      const failures = /^# fail (\d+)$/.exec(line);
      if (failures) state.reportedFailures = Number(failures[1]);
    },
  };
}

// Fixed-shape, bounded process evidence: never retain or print child output.
function createChildProcessProgress() {
  const state = { stdoutBytes: 0, stderrBytes: 0, stdoutEof: false, stderrEof: false,
    stdoutClosed: false, stderrClosed: false, stdoutCloseError: false, stderrCloseError: false,
    stdoutError: "none", stderrError: "none", childExit: false, childClose: false,
    childExitCode: "unknown", childSignal: "none" };
  const named = (stream) => stream === "stdout" ? "stdout" : "stderr";
  return {
    state,
    bytes(stream, count) {
      const key = `${named(stream)}Bytes`;
      if (Number.isSafeInteger(count) && count > 0) state[key] = Math.min(Number.MAX_SAFE_INTEGER, state[key] + count);
    },
    ended(stream) { state[`${named(stream)}Eof`] = true; },
    closed(stream, hadError) {
      const key = named(stream);
      state[`${key}Closed`] = true;
      state[`${key}CloseError`] = Boolean(hadError);
    },
    errored(stream, error) {
      state[`${named(stream)}Error`] = SAFE_CODES.has(error?.code) ? error.code : "unknown";
    },
    exited(code, signal) {
      state.childExit = true;
      state.childExitCode = Number.isSafeInteger(code) ? code : "unknown";
      state.childSignal = signal ? "present" : "none";
    },
    finished(code, signal) {
      state.childClose = true;
      if (!state.childExit) {
        state.childExitCode = Number.isSafeInteger(code) ? code : "unknown";
        state.childSignal = signal ? "present" : "none";
      }
    },
    safeSummary() {
      const closeState = !state.childClose ? "pending"
        : !state.childExit ? "close_without_exit"
          : state.childSignal === "present" ? "signaled"
            : state.childExitCode !== 0 ? "nonzero_exit"
              : !state.stdoutEof || !state.stderrEof ? "stream_eof_missing" : "complete";
      const bit = (value) => value ? 1 : 0;
      return `stdoutBytes=${state.stdoutBytes} stderrBytes=${state.stderrBytes} stdoutEof=${bit(state.stdoutEof)} stderrEof=${bit(state.stderrEof)} stdoutClosed=${bit(state.stdoutClosed)} stderrClosed=${bit(state.stderrClosed)} stdoutCloseError=${bit(state.stdoutCloseError)} stderrCloseError=${bit(state.stderrCloseError)} stdoutError=${state.stdoutError} stderrError=${state.stderrError} childExit=${bit(state.childExit)} childClose=${bit(state.childClose)} childExitCode=${state.childExitCode} childSignal=${state.childSignal} childCloseState=${closeState}`;
    },
  };
}

function run() {
  // The split branch does not export #228's canonicalTestArgs helper.
  // Preserve its exact Windows invocation without changing the release gate:
  // full npm test, TAP reporter, bounded file concurrency, NO test filters.
  const invocation = getNpmInvocation(["test", "--", "--test-reporter=tap", "--test-concurrency=2"]);
  const started = Date.now();
  let lastOutput = started;
  let timedOut = false;
  let spawnFailed = false;
  let reportedSuite = false;
  function writeProgressDiagnostic(message) {
    try { fs.writeSync(1, `${message}\n`); }
    catch { console.log(message); }
  }
  const tracker = createTapProgressRecorder(writeProgressDiagnostic);
  const childProgress = createChildProcessProgress();
  // PowerShell/CI can lose the last asynchronous console line when npm or its
  // parent exits during a buffered write. Emit failures synchronously instead.
  function writeFailureDiagnostic(message) {
    try { fs.writeSync(2, `${message}\n`); }
    catch { console.error(message); }
  }
  const child = spawn(invocation.executable, invocation.args, {
    cwd: require("node:path").resolve(__dirname, ".."),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
    env: canonicalWindowsTestEnvironment(),
  });

  function consume(stream, streamName) {
    const decoder = new StringDecoder("utf8");
    let pending = "";
    stream.on("data", (chunk) => {
      lastOutput = Date.now();
      childProgress.bytes(streamName, chunk.length);
      pending += decoder.write(chunk);
      let newline;
      while ((newline = pending.indexOf("\n")) >= 0) {
        tracker.accept(pending.slice(0, newline).replace(/\r$/, ""));
        pending = pending.slice(newline + 1);
      }
      // Untrusted test output is never forwarded verbatim or retained without a bound.
      if (pending.length > 8192) pending = "";
    });
    stream.on("end", () => {
      childProgress.ended(streamName);
      pending += decoder.end();
      if (pending) tracker.accept(pending);
    });
    stream.on("error", (error) => childProgress.errored(streamName, error));
    stream.on("close", (hadError) => childProgress.closed(streamName, hadError));
  }

  consume(child.stdout, "stdout");
  consume(child.stderr, "stderr");
  process.on("uncaughtExceptionMonitor", (error, origin) => {
    const code = SAFE_CODES.has(error?.code) ? error.code : "unknown";
    writeFailureDiagnostic(`FAIL Windows canonical runner uncaught error: code=${code} origin=${origin === "unhandledRejection" ? "rejection" : "exception"} TAPresults=${tracker.state.results} failures=${tracker.state.failures} ${tracker.safeSummary()} ${childProgress.safeSummary()}`);
  });
  process.on("exit", (exitCode) => {
    if (!reportedSuite) {
      tracker.finish();
      process.exitCode = 1;
      writeFailureDiagnostic(`FAIL Windows canonical runner exited before child close: exit=${exitCode} TAPresults=${tracker.state.results} failures=${tracker.state.failures} ${tracker.safeSummary()} ${childProgress.safeSummary()}`);
    }
  });

  function terminate(reason) {
    if (timedOut) return;
    timedOut = true;
    tracker.finish();
    writeFailureDiagnostic(`FAIL Windows canonical test ${reason}; TAP results=${tracker.state.results}, failures=${tracker.state.failures}; ${tracker.safeSummary()} ${childProgress.safeSummary()}`);
    if (process.platform === "win32" && child.pid) {
      const killer = spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore", windowsHide: true });
      killer.on("error", () => child.kill());
      killer.on("close", (code) => { if (code !== 0) child.kill(); });
    } else {
      child.kill();
    }
  }

  const heartbeat = setInterval(() => {
    const elapsed = Math.floor((Date.now() - started) / 1000);
    const idle = Math.floor((Date.now() - lastOutput) / 1000);
    writeProgressDiagnostic(`Windows canonical heartbeat: elapsedSeconds=${elapsed} idleSeconds=${idle} TAPresults=${tracker.state.results} failures=${tracker.state.failures} ${tracker.safeSummary()} ${childProgress.safeSummary()}`);
    if (idle * 1000 >= IDLE_LIMIT_MS) terminate("idle timeout (15 minutes without child output)");
    else if (elapsed * 1000 >= TOTAL_LIMIT_MS) terminate("total timeout (55 minutes)");
  }, HEARTBEAT_MS);

  child.on("error", (error) => {
    spawnFailed = true;
    writeFailureDiagnostic(`FAIL Windows canonical child spawn error: code=${SAFE_CODES.has(error?.code) ? error.code : "unknown"} ${tracker.safeSummary()} ${childProgress.safeSummary()}`);
  });
  child.on("exit", (code, signal) => {
    childProgress.exited(code, signal);
    if (code !== 0 || signal) writeFailureDiagnostic(`FAIL Windows canonical child exit: code=${Number.isSafeInteger(code) ? code : "unknown"} signal=${signal ? "present" : "none"} TAPresults=${tracker.state.results} failures=${tracker.state.failures} ${tracker.safeSummary()} ${childProgress.safeSummary()}`);
  });
  child.on("close", (code, signal) => {
    childProgress.finished(code, signal);
    clearInterval(heartbeat);
    tracker.finish();
    const { results, failures, plan, tests, reportedFailures } = tracker.state;
    const passed = !timedOut && !spawnFailed && code === 0 && !signal && plan && tests !== null
      && reportedFailures === 0 && failures === 0 && tracker.state.nestedFailures === 0
      && childProgress.state.childExit && childProgress.state.stdoutEof && childProgress.state.stderrEof;
    const summary = `${passed ? "PASS" : "FAIL"} Windows canonical suite: exit=${code ?? "unknown"} signal=${signal ? "present" : "none"} TAPresults=${results} tests=${tests ?? "unknown"} failures=${failures} ${tracker.safeSummary()} ${childProgress.safeSummary()}`;
    reportedSuite = true;
    if (passed) console.log(summary);
    else writeFailureDiagnostic(summary);
    if (!passed) process.exitCode = 1;
  });
}

if (require.main === module) run();

module.exports = { createTapProgressRecorder, createChildProcessProgress, canonicalWindowsTestEnvironment };
