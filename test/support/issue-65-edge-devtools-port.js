"use strict";

const fs = require("node:fs");
const path = require("node:path");

function readEdgeDevToolsPort(profile, reader = fs) {
  const file = path.join(profile, "DevToolsActivePort");
  let contents;
  try {
    // Edge publishes this file asynchronously. A separate existsSync() check
    // races with creation, replacement and cleanup of the browser profile.
    contents = reader.readFileSync(file, "utf8");
  } catch (error) {
    if (["ENOENT", "EACCES", "EPERM", "EBUSY"].includes(error?.code)) return null;
    throw error;
  }
  const firstLine = contents.split(/\r?\n/, 1)[0];
  if (!/^[1-9][0-9]{0,4}$/.test(firstLine)) return null;
  const port = Number(firstLine);
  return port <= 65535 ? port : null;
}

module.exports = { readEdgeDevToolsPort };
