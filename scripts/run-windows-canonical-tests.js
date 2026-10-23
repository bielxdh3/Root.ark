"use strict";

const { spawn } = require("node:child_process");
const { createHash } = require("node:crypto");
const { StringDecoder } = require("node:string_decoder");
const { getNpmInvocation, canonicalTestArgs } = require("./release-gate-environment");

const HEARTBEAT_MS = 60_000;
const IDLE_LIMIT_MS = 15 * 60_000;
const TOTAL_LIMIT_MS = 55 * 60_000;

function createTapProgressRecorder(write) {
  const state = { results: 0, failures: 0, plan: false, tests: null, reportedFailures: null };
  return {
    state,
    accept(line) {
      const result = /^(ok|not ok) ([1-9]\d{0,8}) - (.{1,4096})$/.exec(line);
      if (result) {
        state.results += 1;
        if (result[1] === "not ok") {
          state.failures += 1;
          const nameHash = createHash("sha256").update(result[3]).digest("hex").slice(0, 24);
          write(`FAIL test result index=${result[2]} nameSha256=${nameHash}`);
        } else if (state.results % 100 === 0) {
          write(`Windows canonical progress: ${state.results} TAP results, ${state.failures} failed`);
        }
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
  const tracker = createTapProgressRecorder((message) => console.log(message));
  const child = spawn(invocation.executable, invocation.args, {
    cwd: require("node:path").resolve(__dirname, ".."),
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true,
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

  function terminate(reason) {
    if (timedOut) return;
    timedOut = true;
    console.error(`FAIL Windows canonical test ${reason}; TAP results=${tracker.state.results}, failures=${tracker.state.failures}`);
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
    console.log(`Windows canonical heartbeat: elapsedSeconds=${elapsed} idleSeconds=${idle} TAPresults=${tracker.state.results} failures=${tracker.state.failures}`);
    if (idle * 1000 >= IDLE_LIMIT_MS) terminate("idle timeout (15 minutes without child output)");
    else if (elapsed * 1000 >= TOTAL_LIMIT_MS) terminate("total timeout (55 minutes)");
  }, HEARTBEAT_MS);

  child.on("error", () => { spawnFailed = true; });
  child.on("close", (code, signal) => {
    clearInterval(heartbeat);
    const { results, failures, plan, tests, reportedFailures } = tracker.state;
    const passed = !timedOut && !spawnFailed && code === 0 && !signal && plan && tests !== null && reportedFailures === 0 && failures === 0;
    console.log(`${passed ? "PASS" : "FAIL"} Windows canonical suite: exit=${code ?? "unknown"} signal=${signal ? "present" : "none"} TAPresults=${results} tests=${tests ?? "unknown"} failures=${failures} stderrBytes=${stderrBytes}`);
    if (!passed) process.exitCode = 1;
  });
}

if (require.main === module) run();

module.exports = { createTapProgressRecorder };
