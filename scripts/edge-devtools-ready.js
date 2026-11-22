"use strict";

// The DevToolsActivePort file is created by a separate Edge process. A file
// can exist before its two lines are complete, or disappear between an
// existsSync check and readFileSync. Neither state proves a ready CDP server.
const fs = require("node:fs");
const path = require("node:path");

const TRANSIENT = new Set(["ENOENT", "EACCES", "EPERM", "EBUSY", "EAGAIN"]);
const BROWSER_LINE = /^\/devtools\/browser\/[A-Za-z0-9_-]{6,160}$/;

function readReadyEdgeDevToolsPort(profile) {
  const file = path.join(profile, "DevToolsActivePort");
  let contents;
  try { contents = fs.readFileSync(file, "utf8"); }
  catch (error) {
    if (TRANSIENT.has(error?.code)) return null;
    throw error;
  }
  if (contents.length > 4096) return null;
  const [first, browser] = contents.split(/\r?\n/);
  if (!/^[1-9][0-9]{0,4}$/.test(first) || !BROWSER_LINE.test(browser || "")) return null;
  const port = Number(first);
  return port >= 1 && port <= 65535 ? port : null;
}

async function fetchReadyEdgeDevToolsPage(port) {
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) return null;
  try {
    const response = await fetch(`http://127.0.0.1:${port}/json/list`,
      { signal: AbortSignal.timeout(500) });
    if (!response.ok) return null;
    const pages = await response.json();
    if (!Array.isArray(pages) || pages.length > 64) return null;
    for (const page of pages) {
      if (page?.type !== "page" || typeof page.webSocketDebuggerUrl !== "string"
        || page.webSocketDebuggerUrl.length > 4096) continue;
      const url = new URL(page.webSocketDebuggerUrl);
      if (url.protocol === "ws:" && url.port === String(port)
        && ["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)
        && url.pathname.startsWith("/devtools/page/")) return page;
    }
  } catch { /* Edge may still be opening its local CDP socket. */ }
  return null;
}

module.exports = { readReadyEdgeDevToolsPort, fetchReadyEdgeDevToolsPage };
