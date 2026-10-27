"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { canonicalTestTempEnvironment } = require("./support/issue-65-canonical-temp-fixture");

test("canonical TEMP/TMP fixture restores original aliases after repeated calls under one test context", {
  skip: process.platform !== "win32",
}, (t) => {
  const before = { TEMP: process.env.TEMP, TMP: process.env.TMP };
  const canonical = fs.realpathSync.native(os.tmpdir());
  const alias = path.join(canonical, ".") + path.sep + ".";
  process.env.TEMP = alias;
  process.env.TMP = alias;
  assert.equal(canonicalTestTempEnvironment(t).toLowerCase(), canonical.toLowerCase());
  assert.equal(canonicalTestTempEnvironment(t).toLowerCase(), canonical.toLowerCase());
  t.after(() => {
    try {
      assert.equal(process.env.TEMP, alias, "TEMP must restore the original noncanonical alias");
      assert.equal(process.env.TMP, alias, "TMP must restore the original noncanonical alias");
    } finally {
      for (const name of ["TEMP", "TMP"]) {
        if (before[name] === undefined) delete process.env[name];
        else process.env[name] = before[name];
      }
    }
  });
});

test("canonical TEMP/TMP fixture refuses overlapping test contexts instead of leaking a global alias", {
  skip: process.platform !== "win32",
}, () => {
  const before = { TEMP: process.env.TEMP, TMP: process.env.TMP };
  const alias = fs.realpathSync.native(os.tmpdir()) + path.sep + ".";
  const cleanupA = [];
  const cleanupB = [];
  const firstTest = { after(callback) { cleanupA.push(callback); } };
  const secondTest = { after(callback) { cleanupB.push(callback); } };
  try {
    process.env.TEMP = alias;
    process.env.TMP = alias;
    const firstRoot = canonicalTestTempEnvironment(firstTest);
    assert.equal(process.env.TEMP, firstRoot);
    assert.throws(() => canonicalTestTempEnvironment(secondTest),
      /CONCURRENT_CANONICAL_TEMP_FIXTURE/);
    assert.equal(process.env.TEMP, firstRoot, "second context must not overwrite TEMP");
    assert.equal(process.env.TMP, firstRoot, "second context must not overwrite TMP");
  } finally {
    for (const callback of cleanupB) callback();
    for (const callback of cleanupA) callback();
    for (const name of ["TEMP", "TMP"]) {
      if (before[name] === undefined) delete process.env[name];
      else process.env[name] = before[name];
    }
  }
});
