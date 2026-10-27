"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const environmentRegisteredForTest = new WeakSet();

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
    if (!t || typeof t.after !== "function") throw Error("INVALID_TEST_CONTEXT");
    if (!environmentRegisteredForTest.has(t)) {
      // A test may create many fixtures. Register exactly one restoration:
      // multiple t.after hooks run FIFO and could otherwise restore a later
      // *canonical* intermediate value instead of the original TEMP alias.
      const original = { TEMP: process.env.TEMP, TMP: process.env.TMP };
      t.after(() => {
        for (const name of ["TEMP", "TMP"]) {
          if (original[name] === undefined) delete process.env[name];
          else process.env[name] = original[name];
        }
      });
      environmentRegisteredForTest.add(t);
    }
    process.env.TEMP = root;
    process.env.TMP = root;
  }
  return root;
}

module.exports = { canonicalTestTemp, canonicalTestTempEnvironment };
