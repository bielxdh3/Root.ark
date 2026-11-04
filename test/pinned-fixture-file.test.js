"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");
const { readPinnedFixtureFileSync, readPinnedFixtureFile, writeExistingFixtureFileSync } =
  require("./support/pinned-fixture-file");

test("fixture inspection refuses a swapped pathname after opening its original inode", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-pinned-fixture-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "target.txt");
  const saved = path.join(dir, "saved.txt");
  fs.writeFileSync(target, "trusted");
  const nativeLstat = fs.lstatSync;
  let switched = false;
  try {
    fs.lstatSync = function swappedLstat(name, ...args) {
      if (name === target && !switched) {
        switched = true;
        fs.renameSync(target, saved);
        fs.writeFileSync(target, "replacement");
      }
      return nativeLstat.call(this, name, ...args);
    };
    assert.throws(() => readPinnedFixtureFileSync(target, "utf8"), /FIXTURE_FILE_CHANGED/);
  } finally {
    fs.lstatSync = nativeLstat;
  }
  assert.equal(switched, true);
  assert.equal(fs.readFileSync(target, "utf8"), "replacement");
  assert.equal(fs.readFileSync(saved, "utf8"), "trusted");
  assert.equal((await readPinnedFixtureFile(target, "utf8")), "replacement");
});

test("fixture inspection rejects symlink leaves before reading", async (t) => {
  const dir = createPrivateAuthorityFixture("rootark-pinned-leaf-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "private.txt");
  const link = path.join(dir, "link.txt");
  fs.writeFileSync(target, "sentinel");
  try { fs.symlinkSync(target, link, "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.diagnostic("symlinks unavailable under this Windows test token");
      return;
    }
    throw error;
  }
  assert.throws(() => readPinnedFixtureFileSync(link), /FIXTURE_FILE_CHANGED|ELOOP/);
  await assert.rejects(readPinnedFixtureFile(link), /FIXTURE_FILE_CHANGED|ELOOP/);
});

test("fixture mutation refuses an existing hardlink before changing either name", (t) => {
  const dir = createPrivateAuthorityFixture("rootark-pinned-write-");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "authority.txt");
  const alias = path.join(dir, "alias.txt");
  fs.writeFileSync(target, "must stay unchanged");
  fs.linkSync(target, alias);
  assert.throws(() => readPinnedFixtureFileSync(target), /FIXTURE_FILE_CHANGED/);
  assert.equal(readPinnedFixtureFileSync(target, "utf8", { allowHardlinks: true }),
    "must stay unchanged");
  assert.throws(() => writeExistingFixtureFileSync(target, "injected"), /FIXTURE_FILE_CHANGED/);
  assert.equal(fs.readFileSync(target, "utf8"), "must stay unchanged");
  assert.equal(fs.readFileSync(alias, "utf8"), "must stay unchanged");
  fs.unlinkSync(alias);
  writeExistingFixtureFileSync(target, "safe update");
  assert.equal(fs.readFileSync(target, "utf8"), "safe update");
});
