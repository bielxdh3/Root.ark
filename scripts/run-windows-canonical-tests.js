"use strict";

const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const { StringDecoder } = require("node:string_decoder");
const { getNpmInvocation, canonicalTestArgs } = require("./release-gate-environment");

const HEARTBEAT_MS = 60_000;
const IDLE_LIMIT_MS = 15 * 60_000;
const TOTAL_LIMIT_MS = 55 * 60_000;
const SAFE_CODES = new Set(["ERR_ASSERTION", "ERR_TEST_FAILURE", "SQLITE_BUSY",
  "SQLITE_LOCKED", "ENOENT", "EACCES", "EPERM", "EADDRINUSE", "ETIMEDOUT",
  "ECONNRESET", "ERR_DLOPEN_FAILED", "MODULE_NOT_FOUND", "ERR_MODULE_NOT_FOUND"]);
const SAFE_FAILURE_TYPES = new Set(["testCodeFailure", "hookFailed", "cancelledByParent",
  "uncaughtException", "unhandledRejection", "subtestsFailed"]);
const hash = (value) => createHash("sha256").update(value).digest("hex").slice(0, 24);
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
  const state = { results: 0, failures: 0, plan: false, tests: null, reportedFailures: null };
  const categories = { assertion: 0, sqlite_busy: 0, filesystem: 0,
    network_timeout: 0, dependency: 0, runtime: 0, unknown: 0 };
  const failurePaths = new Map();
  let pending = null;
  let detailed = 0;
  const finish = () => {
    if (!pending) return;
    const category = categoryFor(pending.code);
    categories[category]++;
    if (pending.pathHash !== "none") {
      failurePaths.set(pending.pathHash, (failurePaths.get(pending.pathHash) || 0) + 1);
    }
    if (detailed < 12) {
      write(`FAIL detail index=${pending.index} nameSha256=${pending.nameHash} testPathSha256=${pending.pathHash} failureType=${pending.failureType} code=${pending.code} category=${category}`);
      detailed++;
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
      return `failureCategories=${Object.entries(categories).map(([name, count]) => `${name}=${count}`).join(",")} pending=${pending ? 1 : 0} details=${detailed} failurePathGroups=${failurePaths.size} topFailurePaths=${topFailurePaths}`;
    },
    accept(line) {
      const result = /^(ok|not ok) ([1-9]\d{0,8}) - (.{1,4096})$/.exec(line);
      if (result) {
        finish();
        state.results += 1;
        if (result[1] === "not ok") {
          state.failures += 1;
          const nameHash = hash(result[3]);
          write(`FAIL test result index=${result[2]} nameSha256=${nameHash}`);
          pending = { index: result[2], nameHash, pathHash: "none",
            failureType: "unknown", code: "unknown" };
        } else if (state.results % 100 === 0) {
          write(`Windows canonical progress: ${state.results} TAP results, ${state.failures} failed`);
        }
      }
      if (pending) {
        const location = /^  location: ['"](.{1,2048})['"]$/.exec(line);
        if (location) {
          const file = /(?:^|[\\/]+)test[\\/]+([A-Za-z0-9._-]{1,160}\.test\.js):\d+:\d+$/.exec(location[1]);
          if (file) pending.pathHash = hash(`test/${file[1]}`);
        }
        const kind = /^  failureType: '([A-Za-z]{1,40})'$/.exec(line);
        if (kind && SAFE_FAILURE_TYPES.has(kind[1])) pending.failureType = kind[1];
        const code = /^  code: '([A-Z0-9_]{1,40})'$/.exec(line);
        if (code && SAFE_CODES.has(code[1])) pending.code = code[1];
      }
      if (/^1\.\.\d+$/.test(line)) state.plan = true;
      const tests = /^# tests (\d+)$/.exec(line);
      if (tests) state.tests = Number(tests[1]);
      const failures = /^# fail (\d+)$/.exec(line);
      if (failures) state.reportedFailures = Number(failures[1]);
    },
  };
}

function run() {
  const invocation = getNpmInvocation(canonicalTestArgs());
  const started = Date.now();
  let lastOutput = started;
  let timedOut = false;
  let spawnFailed = false;
  let stderrBytes = 0;
  let reportedSuite = false;
  const tracker = createTapProgressRecorder((message) => console.log(message));
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

  function consume(stream, fromStderr) {
    const decoder = new StringDecoder("utf8");
    let pending = "";
    stream.on("data", (chunk) => {
      lastOutput = Date.now();
      if (fromStderr) stderrBytes += chunk.length;
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
      pending += decoder.end();
      if (pending) tracker.accept(pending);
    });
  }

  consume(child.stdout, false);
  consume(child.stderr, true);
  process.on("exit", (exitCode) => {
    if (!reportedSuite) {
      tracker.finish();
      process.exitCode = 1;
      writeFailureDiagnostic(`FAIL Windows canonical runner exited before child close: exit=${exitCode} TAPresults=${tracker.state.results} failures=${tracker.state.failures} stderrBytes=${stderrBytes} ${tracker.safeSummary()}`);
    }
  });

  function terminate(reason) {
    if (timedOut) return;
    timedOut = true;
    tracker.finish();
    writeFailureDiagnostic(`FAIL Windows canonical test ${reason}; TAP results=${tracker.state.results}, failures=${tracker.state.failures}; ${tracker.safeSummary()}`);
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
    console.log(`Windows canonical heartbeat: elapsedSeconds=${elapsed} idleSeconds=${idle} TAPresults=${tracker.state.results} failures=${tracker.state.failures} ${tracker.safeSummary()}`);
    if (idle * 1000 >= IDLE_LIMIT_MS) terminate("idle timeout (15 minutes without child output)");
    else if (elapsed * 1000 >= TOTAL_LIMIT_MS) terminate("total timeout (55 minutes)");
  }, HEARTBEAT_MS);

  child.on("error", () => { spawnFailed = true; });
  child.on("close", (code, signal) => {
    clearInterval(heartbeat);
    tracker.finish();
    const { results, failures, plan, tests, reportedFailures } = tracker.state;
    const passed = !timedOut && !spawnFailed && code === 0 && !signal && plan && tests !== null && reportedFailures === 0 && failures === 0;
    const summary = `${passed ? "PASS" : "FAIL"} Windows canonical suite: exit=${code ?? "unknown"} signal=${signal ? "present" : "none"} TAPresults=${results} tests=${tests ?? "unknown"} failures=${failures} stderrBytes=${stderrBytes} ${tracker.safeSummary()}`;
    reportedSuite = true;
    if (passed) console.log(summary);
    else writeFailureDiagnostic(summary);
    if (!passed) process.exitCode = 1;
  });
}

if (require.main === module) run();

module.exports = { createTapProgressRecorder, canonicalWindowsTestEnvironment };
