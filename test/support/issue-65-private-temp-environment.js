"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createPrivateAuthorityFixture } = require("./issue-65-private-authority-fixture");

let active = false;

async function withPrivateWindowsTestTemp(run) {
  if (process.platform !== "win32") return run();
  if (active) throw Error("CONCURRENT_PRIVATE_TEST_TEMP");
  active = true;
  const original = { TEMP: process.env.TEMP, TMP: process.env.TMP };
  const parent = process.env.LOCALAPPDATA;
  let root;
  try {
    root = createPrivateAuthorityFixture("rootark-zk65-positive-temp-");
    const canonical = fs.realpathSync.native(root);
    if (path.resolve(root).toLowerCase() !== canonical.toLowerCase()) {
      throw Error("UNCANONICAL_PRIVATE_TEST_TEMP");
    }
    process.env.TEMP = canonical;
    process.env.TMP = canonical;
    return await run();
  } finally {
    try {
      for (const name of ["TEMP", "TMP"]) {
        if (original[name] === undefined) delete process.env[name];
        else process.env[name] = original[name];
      }
      if (root) {
        if (typeof parent !== "string" ||
            path.resolve(path.dirname(root)).toLowerCase() !== path.resolve(parent).toLowerCase() ||
            !/^rootark-zk65-positive-temp-[a-f0-9]{20}$/.test(path.basename(root))) {
          throw Error("UNEXPECTED_PRIVATE_TEST_TEMP");
        }
        fs.rmSync(root, { recursive: true, force: true });
      }
    } finally {
      active = false;
    }
  }
}

module.exports = { withPrivateWindowsTestTemp };
