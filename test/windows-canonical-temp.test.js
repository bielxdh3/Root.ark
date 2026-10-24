"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { canonicalWindowsTestEnvironment } = require("../scripts/run-windows-canonical-tests");

test("Windows canonical runner resolves TEMP junction without relaxing SQLite ancestry checks", {
  skip: process.platform !== "win32",
}, (t) => {
  const base = fs.mkdtempSync(path.join(fs.realpathSync.native(os.tmpdir()),
    "rootark-windows-canonical-temp-"));
  const real = path.join(base, "real");
  const alias = path.join(base, "alias");
  fs.mkdirSync(real);
  t.after(() => {
    // Remove the disposable junction before deleting its owned destination.
    if (fs.existsSync(alias)) {
      try { fs.rmdirSync(alias); }
      catch (error) {
        if (error.code !== "ENOTDIR") throw error;
        fs.unlinkSync(alias);
      }
    }
    fs.rmSync(real, { recursive: true, force: true });
    fs.rmdirSync(base);
  });
  fs.symlinkSync(real, alias, "junction");
  assert.notEqual(path.resolve(alias).toLowerCase(),
    fs.realpathSync.native(alias).toLowerCase());

  const childArgs = ["--test", "--test-reporter=tap",
    "test/issue-65-authority-bootstrap-preservation.test.js"];
  const run = (env) => spawnSync(process.execPath, childArgs, {
    cwd: path.resolve(__dirname, ".."), env, encoding: "utf8", timeout: 15_000,
    windowsHide: true, maxBuffer: 256 * 1024,
  });
  const aliased = { ...process.env, TEMP: alias, TMP: alias };
  // node:test launches this file as a test child; the nested canonical
  // command must start as an independent CLI process, like the real runner.
  delete aliased.NODE_TEST_CONTEXT;
  const rejected = run(aliased);
  assert.equal(rejected.status, 1, rejected.stderr || rejected.stdout || rejected.error?.message);
  assert.match(rejected.stdout, /not ok 1 - witness rejects an unrelated SQLite file/);

  const environment = canonicalWindowsTestEnvironment(aliased, "win32", alias);
  assert.equal(environment.TEMP, real);
  assert.equal(environment.TMP, real);
  const accepted = run(environment);
  assert.equal(accepted.status, 0, accepted.stderr || accepted.stdout || accepted.error?.message);
  assert.match(accepted.stdout, /# pass 2\r?\n/);
  assert.match(accepted.stdout, /# fail 0\r?\n/);
});
