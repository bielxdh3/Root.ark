"use strict";

// Preserve the opt-in native lab without treating an unconfigured default
// `node --test` discovery as a failed security regression.
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const test = require("node:test");

const lab = path.resolve(__dirname, "../scripts/issue-67-native-contained-read.lab.test.cjs");
const cleanEnv = { ...process.env };
delete cleanEnv.NODE_TEST_CONTEXT;
delete cleanEnv.ROOTARK_NATIVE_READ_EXE;
delete cleanEnv.ROOTARK_NATIVE_READ_TESTDIR;

function invoke(args, env = cleanEnv) {
  const result = spawnSync(process.execPath, args, {
    env, encoding: "utf8", timeout: 20000, windowsHide: true,
  });
  assert.equal(result.error, undefined);
  return result;
}

test("unconfigured native-read lab registers exactly one explicit discovery SKIP", () => {
  const result = invoke(["--test", lab]);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /native contained-read lab requires explicit compiled binary/i);
  assert.match(result.stdout, /# tests 1\b/);
  assert.match(result.stdout, /# skipped 1\b/);
  assert.match(result.stdout, /# fail 0\b/);
});

test("partial or invalid native-read lab configuration still fails closed", () => {
  const partial = invoke(["--test", lab], {
    ...cleanEnv, ROOTARK_NATIVE_READ_EXE: process.execPath,
  });
  assert.notEqual(partial.status, 0);
  assert.match(partial.stdout + partial.stderr, /ROOTARK_NATIVE_READ_TESTDIR/);
  assert.doesNotMatch(partial.stdout, /# skipped 1\b/);

  const malformed = invoke(["--test", lab], {
    ...cleanEnv, ROOTARK_NATIVE_READ_EXE: path.join(__dirname, "missing-native-executable"),
    ROOTARK_NATIVE_READ_TESTDIR: path.join(__dirname, "missing-disposable-dir"),
  });
  assert.notEqual(malformed.status, 0);
  assert.match(malformed.stdout + malformed.stderr, /ROOTARK_NATIVE_READ_EXE/);
  assert.doesNotMatch(malformed.stdout, /# skipped 1\b/);
});

test("native-read lab requires explicit configuration outside Node test discovery", () => {
  const result = invoke([lab]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ROOTARK_NATIVE_READ_EXE/);
});
