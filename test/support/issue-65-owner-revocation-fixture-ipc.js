"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

// This is disposable test-to-CLI IPC: the separate process must never observe
// a newly created, still-empty receipt or candidate at its final path.
function publishFixtureJson(root, filename, payload, beforePublish = () => {}) {
  if (!/^[a-z0-9-]+\.json$/.test(filename)) throw Error("FIXTURE_NAME_INVALID");
  const destination = path.join(root, filename);
  if (fs.existsSync(destination)) throw Error("FIXTURE_EXISTS");
  const staging = path.join(root, `.${filename}.${crypto.randomBytes(12).toString("hex")}.tmp`);
  const fd = fs.openSync(staging, fs.constants.O_CREAT | fs.constants.O_EXCL
    | fs.constants.O_WRONLY, 0o600);
  try {
    try {
      fs.writeFileSync(fd, JSON.stringify(payload));
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    beforePublish();
    if (fs.existsSync(destination)) throw Error("FIXTURE_EXISTS");
    fs.renameSync(staging, destination);
  } finally {
    if (fs.existsSync(staging)) fs.unlinkSync(staging);
  }
}

async function awaitFixtureJson(filename, {
  exited,
  attempts = 90,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  for (let i = 0; i < attempts; i++) {
    if (fs.existsSync(filename)) {
      try { return JSON.parse(fs.readFileSync(filename, "utf8")); }
      catch (error) {
        // The CLI's publishJson opens the destination exclusively before
        // writing and syncing it. A concurrent reader may see incomplete JSON.
        if (!(error instanceof SyntaxError)) throw error;
      }
    }
    if (exited()) throw Error("EARLY_CLI_EXIT");
    await sleep(50);
  }
  throw Error("MISSING_FIXTURE_JSON");
}

module.exports = { publishFixtureJson, awaitFixtureJson };
