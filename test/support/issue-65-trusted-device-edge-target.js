"use strict";

// Edge may write DevToolsActivePort before its HTTP target endpoint is ready.
// Both steps share the original 15-second startup budget, with no test skip.
async function waitForIndexedDbEdgePage({
  getPort, getTargets, isExited = () => false,
  now = () => Date.now(),
  pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutMs = 15000,
}) {
  const deadline = now() + timeoutMs;
  while (now() < deadline) {
    if (isExited()) throw Error("EDGE_INDEXEDDB_BROWSER_EXITED");
    const port = getPort();
    if (Number.isSafeInteger(port) && port > 0 && port <= 65535) {
      let targets;
      try {
        targets = await getTargets(port, Math.max(1, deadline - now()));
      } catch (_) {
        // Local debugger requests can fail while Edge starts listening.
        // Continue only within the original fixed startup deadline.
      }
      const page = Array.isArray(targets) && targets.find((target) =>
        target.type === "page" && typeof target.webSocketDebuggerUrl === "string");
      if (page) {
        const url = new URL(page.webSocketDebuggerUrl);
        if (url.protocol !== "ws:" || url.hostname !== "127.0.0.1"
          || Number(url.port) !== port || !url.pathname.startsWith("/devtools/page/")) {
          throw Error("EDGE_INDEXEDDB_UNSAFE_DEBUGGER_TARGET");
        }
        return { port, url: page.webSocketDebuggerUrl };
      }
    }
    await pause(Math.max(1, Math.min(100, deadline - now())));
  }
  throw Error("EDGE_INDEXEDDB_PAGE_NOT_READY");
}

module.exports = { waitForIndexedDbEdgePage };
