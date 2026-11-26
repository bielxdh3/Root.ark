"use strict";

const { createInterface } = require("node:readline");

// The test's existing AbortSignal supplies the deadline. A listener on some
// other process's port must not be mistaken for this fixture's readiness.
function waitForFixtureListen(child, port, signal) {
  return new Promise((resolve, reject) => {
    const lines = createInterface({ input: child.stdout, crlfDelay: Infinity });
    let settled = false;
    function finish(error) {
      if (settled) return;
      settled = true;
      lines.removeListener("line", onLine);
      lines.removeListener("close", onClose);
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
    function onAbort() { finish(new Error("fixture readiness aborted")); }
    lines.on("line", onLine);
    lines.once("close", onClose);
    child.once("exit", onExit);
    child.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    else if (child.exitCode !== null || child.signalCode !== null) onExit();
  });
}

module.exports = { waitForFixtureListen };
