"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const { buildCompiledFixture, runCompiledFixture, sanitizeBuildEnvironment } =
  require("./support/issue-66-cfapi-built-artifact");

test("CFAPI compiler ignores inherited tool selectors and PATH before vcvars initializes", () => {
  const incoming = {
    Path: "C:\\untrusted\\bin", PATH: "C:\\other-untrusted\\bin",
    ComSpec: "C:\\untrusted\\cmd.exe", COMSPEC: "C:\\other\\cmd.exe",
    SystemRoot: "C:\\untrusted", windir: "C:\\untrusted",
    VCToolsInstallDir: "C:\\untrusted\\vc", vctoolsinstalldir: "C:\\other\\vc",
    VCINSTALLDIR: "C:\\untrusted", VSINSTALLDIR: "C:\\untrusted",
    VSCMD_PREINIT_PATH: "C:\\untrusted\\bin", __VSCMD_PREINIT_PATH: "C:\\untrusted\\bin",
    CL: "/link C:\\untrusted", _CL_: "/DUNTRUSTED", LINK: "/LIBPATH:C:\\untrusted",
    _LINK_: "/LIBPATH:C:\\untrusted", INCLUDE: "C:\\untrusted", LIB: "C:\\untrusted",
    LIBPATH: "C:\\untrusted", CUSTOM_NON_TOOLCHAIN: "expected",
  };
  const env = sanitizeBuildEnvironment(incoming);
  assert.equal(env.CUSTOM_NON_TOOLCHAIN, "expected");
  for (const key of Object.keys(env)) {
    assert.ok(!/^(?:CL|_CL_|LINK|_LINK_|VCTOOLSINSTALLDIR|VCINSTALLDIR|VSINSTALLDIR|INCLUDE|LIB|LIBPATH)$/i.test(key));
    assert.ok(!/^_?_?VSCMD_/i.test(key));
  }
  assert.equal(env.Path, String.raw`C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem`);
  assert.equal(env.ComSpec, String.raw`C:\Windows\System32\cmd.exe`);
  assert.equal(env.SystemRoot, String.raw`C:\Windows`);
  assert.equal(env.windir, String.raw`C:\Windows`);
  assert.equal(Object.hasOwn(env, "PATH"), false);
  assert.equal(Object.hasOwn(env, "COMSPEC"), false);
});

test("CFAPI compiler never executes vcvars tools with disposable scratch as its working directory", () => {
  const code = fs.readFileSync(path.join(__dirname, "support", "issue-66-cfapi-built-artifact.js"), "utf8");
  assert.ok(code.includes(String.raw`const buildToolCwd = "C:\\Windows\\System32";`),
    "native compiler command lookup must start in the protected OS directory");
  assert.ok(code.includes("cwd: buildToolCwd"),
    "native compiler child process must not start in writable scratch");
  assert.ok(code.includes('/Fo:"${objectFile}"'),
    "native compiler must explicitly emit object output inside the fixture directory");
  assert.ok(code.includes('/Fd:"${pdbFile}"'),
    "native compiler must explicitly emit debug intermediate output inside the fixture directory");
});

test("CFAPI compiler rejects existing object and PDB output names before running MSVC", (t) => {
  for (const extension of [".obj", ".pdb"]) {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
    t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
    const output = path.join(scratch, `acl-preflight${extension}`);
    fs.writeFileSync(output, "PRESERVE_DISPOSABLE_CANARY");
    assert.throws(() => buildCompiledFixture(scratch, "acl-preflight.exe",
      String.raw`C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat`),
    /UNTRUSTED_EXECUTABLE/);
    assert.equal(fs.readFileSync(output, "utf8"), "PRESERVE_DISPOSABLE_CANARY");
  }
});

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
