"use strict";

const fs = require("node:fs");
const path = require("node:path");

// The DevToolsActivePort file is written before Edge necessarily starts serving
// /json/list. Use one startup deadline for both readiness steps, even if the
// Windows test host is running other browser/SQLite test processes.
async function waitForEdgeDevtoolsPage({
  profileDir, child,
  timeoutMs = 15000,
  now = () => Date.now(),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  fetchTargets = async (url) => (await fetch(url, {
    signal: AbortSignal.timeout(1000),
  })).json(),
}) {
  const deadline = now() + timeoutMs;
  while (now() < deadline) {
    if (child && (child.exitCode !== null || child.signalCode !== null)) {
      throw Error("EDGE_V2_BROWSER_EXITED");
    }
    const active = path.join(profileDir, "DevToolsActivePort");
    if (fs.existsSync(active)) {
      const port = Number(fs.readFileSync(active, "utf8").split(/\r?\n/)[0]);
      if (Number.isSafeInteger(port) && port > 0 && port <= 65535) {
        try {
          const targets = await fetchTargets("http://127.0.0.1:" + port + "/json/list");
          const page = Array.isArray(targets) && targets.find((target) =>
            target.type === "page" && typeof target.webSocketDebuggerUrl === "string");
          if (page) return page.webSocketDebuggerUrl;
        } catch (_) {
          // Edge's HTTP debugger can refuse connections during startup.
          // No page is accepted until its actual debugger endpoint responds.
        }
      }
    }
    await sleep(Math.min(60, Math.max(1, deadline - now())));
  }
  throw Error("EDGE_V2_TIMEOUT_devtools");
}

module.exports = { waitForEdgeDevtoolsPage };
