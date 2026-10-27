"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

// Fixtures that must be read through canonical paths cannot inherit a hosted
// Windows TEMP junction. This changes test paths only, never runtime guards.
function canonicalTestTemp() {
  const root = fs.realpathSync.native(os.tmpdir());
  if (!path.isAbsolute(root)
    || (process.platform === "win32"
      ? fs.realpathSync.native(root).toLowerCase() !== root.toLowerCase()
      : fs.realpathSync.native(root) !== root)) {
    throw Error("UNCANONICAL_TEST_TEMP");
  }
  return root;
}

// The local-fixture migration intentionally requires fixtureDir's parent to
// equal os.tmpdir() exactly. For that one suite, also pin the test process's
// TEMP/TMP to the same canonical root and restore both after each test.
function canonicalTestTempEnvironment(t) {
  const root = canonicalTestTemp();
  if (process.platform === "win32") {
    const original = { TEMP: process.env.TEMP, TMP: process.env.TMP };
    process.env.TEMP = root;
    process.env.TMP = root;
    t.after(() => {
      for (const name of ["TEMP", "TMP"]) {
        if (original[name] === undefined) delete process.env[name];
        else process.env[name] = original[name];
      }
    });
  }
  return root;
}

module.exports = { canonicalTestTemp, canonicalTestTempEnvironment };
