"use strict";

const { createInterface } = require("node:readline");
const http = require("node:http");
const stdoutCompletion = new WeakMap();

function request(port, requestPath, options = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path: requestPath, ...options }, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
      res.once("aborted", () => reject(new Error("fixture HTTP response aborted")));
      res.once("error", () => reject(new Error("fixture HTTP response failed")));
    });
    req.once("error", reject);
    req.end(options.body);
  });
}

async function stop(child) {
  const code = await new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) {
      return resolve(child.exitCode);
    }
    child.once("exit", (code) => resolve(code));
    child.kill();
  });
  const completion = stdoutCompletion.get(child);
  if (completion) {
    const error = await completion;
    stdoutCompletion.delete(child);
    if (error) throw error;
  }
  return code;
}

// The test's existing AbortSignal supplies the deadline. A listener on some
// other process's port must not be mistaken for this fixture's readiness.
function waitForFixtureListen(child, port, signal) {
  // Readline stops observing the pipe as soon as readiness settles. Keep
  // failures observable until the pipe closes, including during teardown.
  const stdout = child.stdout;
  stdoutCompletion.set(child, new Promise((resolve) => {
    let error;
    function onError() { error = new Error("fixture stdout read failed"); }
    function onClose() {
      stdout.removeListener("error", onError);
      resolve(error);
    }
    if (stdout.closed) return onClose();
    stdout.on("error", onError);
    stdout.once("close", onClose);
  }));
  return new Promise((resolve, reject) => {
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    let settled = false;
    function finish(error) {
      if (settled) return;
      settled = true;
      lines.removeListener("line", onLine);
      lines.removeListener("close", onClose);
      lines.removeListener("error", onPipeError);
      child.removeListener("exit", onExit);
      child.removeListener("error", onError);
      signal.removeEventListener("abort", onAbort);
      lines.close();
      child.stdout.resume();
      if (error) reject(error);
      else resolve();
    }
    function onLine(line) {
      const match = /^Servidor rodando em http:\/\/(?:\[[^\]\r\n]+\]|[^:\s]+):(\d{1,5})$/.exec(line);
      if (!match) return;
      if (Number(match[1]) !== port) finish(new Error("fixture announced unexpected port"));
      else finish();
    }
    function onExit() { finish(new Error("fixture exited before announcing readiness")); }
    function onError() { finish(new Error("fixture spawn failed")); }
    function onClose() { finish(new Error("fixture stdout closed before announcing readiness")); }
    function onPipeError() { finish(new Error("fixture stdout read failed")); }
    function onAbort() { finish(new Error("fixture readiness aborted")); }
    lines.on("line", onLine);
    lines.once("close", onClose);
    lines.once("error", onPipeError);
    child.once("exit", onExit);
    child.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    else if (child.exitCode !== null || child.signalCode !== null) onExit();
  });
}

module.exports = { waitForFixtureListen, request, stop };
