"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { buildCompiledFixture, runCompiledFixture } =
  require("./support/issue-66-cfapi-built-artifact");

test("CFAPI executable receipts refuse arbitrary TEMP contents even at a permitted name", (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const name = path.join(scratch, "acl-preflight.exe");
  fs.writeFileSync(name, "fixture");
  assert.throws(() => buildCompiledFixture(scratch, "acl-preflight.exe", path.join(scratch, "build.cmd")),
    /UNTRUSTED_EXECUTABLE/);
  assert.throws(() => buildCompiledFixture(scratch, "../outside.exe", path.join(scratch, "build.cmd")),
    /UNTRUSTED_EXECUTABLE/);
  assert.throws(() => runCompiledFixture({}, ["--inspect", scratch]), /UNTRUSTED_EXECUTABLE/);
  assert.throws(() => buildCompiledFixture(scratch, "acl-preflight.exe", path.join(scratch, "build.cmd")),
    /UNTRUSTED_EXECUTABLE/);
});

test("CFAPI receipt refuses a leaf reparse alias before any native launch", (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const outside = path.join(scratch, "outside.exe");
  fs.writeFileSync(outside, "fixture");
  try { fs.symlinkSync(outside, path.join(scratch, "acl-preflight.exe"), "file"); }
  catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.diagnostic("symlink privilege unavailable");
      return;
    }
    throw error;
  }
  assert.throws(() => buildCompiledFixture(scratch, "acl-preflight.exe", path.join(scratch, "build.cmd")),
    /UNTRUSTED_EXECUTABLE/);
});

test("a dangling executable symlink is still a preexisting and forbidden output name", (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  try {
    fs.symlinkSync(path.join(scratch, "nonexistent-external.exe"),
      path.join(scratch, "acl-preflight.exe"), "file");
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) {
      t.diagnostic("symlink privilege unavailable");
      return;
    }
    throw error;
  }
  assert.equal(fs.existsSync(path.join(scratch, "acl-preflight.exe")), false);
  assert.throws(() => buildCompiledFixture(scratch, "acl-preflight.exe", path.join(scratch, "build.cmd")),
    /UNTRUSTED_EXECUTABLE/);
});

test("a plausible forged PE under the allowed name is not a fresh native build", (t) => {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const fake = Buffer.alloc(2048);
  fake.write("MZ", 0, "ascii");
  fake.writeUInt32LE(128, 0x3c);
  fake.write("PE\0\0", 128, "ascii");
  fake.writeUInt16LE(0x8664, 132);
  fake.writeUInt16LE(0x0002, 150);
  fs.writeFileSync(path.join(scratch, "acl-preflight.exe"), fake);
  assert.throws(() => buildCompiledFixture(scratch, "acl-preflight.exe", path.join(scratch, "build.cmd")),
    /UNTRUSTED_EXECUTABLE/);
});
