"use strict";

// Test-only provenance receipt for a binary produced in THIS test run.
// This is NOT a Windows CreateProcess image-identity lock or a security
// authorization for executable paths. A same-principal writer can still race
// the check and path-based CreateProcess. See the accompanying tests/docs.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const RECEIPTS = new WeakMap();
const NAMES = new Map([
  ["acl-preflight.exe", "rootark-cfapi-acl-test-"],
  ["inherit-only-fixture.exe", "rootark-cfapi-ace-native-"],
  ["deny-fetch.exe", "rootark-cfapi-abi-"],
  ["positive-shape.exe", "rootark-cfapi-positive-abi-"],
]);
const FAIL = "UNTRUSTED_EXECUTABLE";
const UNSAFE_BUILD_ENV = new Set([
  "CL", "_CL_", "LINK", "_LINK_", "INCLUDE", "LIB", "LIBPATH",
  "VCTOOLSINSTALLDIR", "VCINSTALLDIR", "VSINSTALLDIR", "VCTOOLSVERSION",
  "VISUALSTUDIOVERSION", "WINDOWSSDKDIR", "WINDOWSSDKVERSION",
  "UNIVERSALCRTSDKDIR", "UCRTVERSION", "PLATFORM", "PLATFORMTOOLSET",
  "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR",
]);

// The test-runner's inherited environment is not a compiler authority.
// In particular a preseeded VCToolsInstallDir may redirect the vcvars inline
// invocation to a caller-writable cl.exe, and inherited PATH can influence
// compiler subprocess and DLL discovery. Use a minimal OS tools PATH until
// the explicitly selected vcvars64.bat establishes MSVC/SDK variables.
// This remains a test-only mitigation, not authentication of the toolchain.
function sanitizeBuildEnvironment(from = process.env) {
  const env = {};
  for (const [key, value] of Object.entries(from)) {
    const upper = key.toUpperCase();
    if (UNSAFE_BUILD_ENV.has(upper) || /^_?_?VSCMD_/.test(upper)) continue;
    env[key] = value;
  }
  env.Path = String.raw`C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem`;
  env.PATHEXT = ".COM;.EXE;.BAT;.CMD";
  env.ComSpec = String.raw`C:\Windows\System32\cmd.exe`;
  env.SystemRoot = String.raw`C:\Windows`;
  env.windir = String.raw`C:\Windows`;
  return env;
}

function comparable(value) {
  const result = path.normalize(value);
  return process.platform === "win32" ? result.toLowerCase() : result;
}

function unchangedDirectory(scratch, prefix) {
  assert.equal(typeof scratch, "string", FAIL);
  assert.ok(path.isAbsolute(scratch), FAIL);
  assert.match(path.basename(scratch), new RegExp(`^${prefix}[A-Za-z0-9_-]{6,}$`), FAIL);
  assert.equal(comparable(path.dirname(scratch)), comparable(os.tmpdir()), FAIL);
  const actual = fs.realpathSync.native(scratch);
  assert.equal(comparable(actual), comparable(scratch), FAIL);
  const stat = fs.lstatSync(scratch, { bigint: true });
  assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), FAIL);
  return stat;
}

function inspect(scratch, name) {
  assert.ok(NAMES.has(name), FAIL);
  const root = unchangedDirectory(scratch, NAMES.get(name));
  const executable = path.join(scratch, name);
  assert.equal(comparable(fs.realpathSync.native(executable)), comparable(executable), FAIL);
  const fd = fs.openSync(executable, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(executable, { bigint: true });
    assert.ok(opened.isFile() && named.isFile() && !named.isSymbolicLink()
      && opened.nlink === 1n && named.nlink === 1n
      && opened.dev === named.dev && opened.ino === named.ino, FAIL);
    assert.ok(opened.size >= 1024n && opened.size <= 20n * 1024n * 1024n, FAIL);
    const bytes = fs.readFileSync(fd);
    assert.equal(BigInt(bytes.length), opened.size, FAIL);
    assert.equal(bytes.toString("ascii", 0, 2), "MZ", FAIL);
    const offset = bytes.readUInt32LE(0x3c);
    assert.ok(offset >= 64 && offset + 24 <= bytes.length, FAIL);
    assert.equal(bytes.toString("ascii", offset, offset + 4), "PE\0\0", FAIL);
    assert.equal(bytes.readUInt16LE(offset + 4), 0x8664, FAIL);
    assert.ok((bytes.readUInt16LE(offset + 22) & 0x0002) !== 0, FAIL);
    const after = fs.lstatSync(executable, { bigint: true });
    const afterRoot = fs.lstatSync(scratch, { bigint: true });
    assert.ok(after.isFile() && after.dev === opened.dev && after.ino === opened.ino
      && afterRoot.dev === root.dev && afterRoot.ino === root.ino, FAIL);
    return { executable, scratch, rootDev: root.dev, rootIno: root.ino,
      dev: opened.dev, ino: opened.ino, size: opened.size,
      digest: crypto.createHash("sha256").update(bytes).digest("hex") };
  } finally { fs.closeSync(fd); }
}

function buildCompiledFixture(scratch, name, vcvars, timeout = 40000) {
  assert.equal(process.platform, "win32", FAIL);
  assert.ok(NAMES.has(name), FAIL);
  unchangedDirectory(scratch, NAMES.get(name));
  // A pre-existing file — even one containing plausible PE headers — is
  // never accepted as the result of the build performed by this helper.
  const executable = path.join(scratch, name);
  // existsSync follows a dangling symlink and would incorrectly report false.
  // A native compiler may then follow that alias while writing its output.
  try {
    fs.lstatSync(executable);
    throw new Error(FAIL);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  assert.equal(typeof vcvars, "string", FAIL);
  assert.match(vcvars,
    /^C:\\Program Files(?: \(x86\))?\\Microsoft Visual Studio\\(?:1\d|20\d{2})\\[\w .-]+\\VC\\Auxiliary\\Build\\vcvars64\.bat$/i,
    FAIL);
  const source = name === "acl-preflight.exe"
    ? path.resolve(__dirname, "../../sync-client/rootark-sync-windows-cfapi-acl-preflight.cpp")
    : name === "deny-fetch.exe"
      ? path.resolve(__dirname, "../../sync-client/rootark-sync-windows-cfapi-deny-callback.cpp")
      : name === "positive-shape.exe"
        ? path.resolve(__dirname, "../../sync-client/rootark-sync-windows-cfapi-positive-shape.cpp")
        : path.join(scratch, "inherit-only-fixture.cpp");
  for (const filename of [vcvars, source, executable]) {
    assert.doesNotMatch(filename, /[\r\n\x00-\x1f\x7f"%!^&|<>]/, FAIL);
  }
  for (const filename of [vcvars, source]) {
    assert.equal(comparable(fs.realpathSync.native(filename)), comparable(filename), FAIL);
    const stat = fs.lstatSync(filename, { bigint: true });
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1n, FAIL);
  }
  // No TEMP build.cmd is ever created or interpreted. The sole command is
  // assembled here from static switches and validated non-shell paths.
  // The separate VS-owned vcvars64.bat and compiler are still a toolchain
  // trust boundary; this does not authenticate their executed bytes.
  const libraries = name === "deny-fetch.exe" || name === "positive-shape.exe"
    ? "cldapi.lib" : "cldapi.lib advapi32.lib";
  const inline = `call "${vcvars}" >nul && if defined VCToolsInstallDir `
    + `"!VCToolsInstallDir!bin\\Hostx64\\x64\\cl.exe" /nologo /std:c++17 /W4 /WX /EHsc `
    + `/Fe:"${executable}" "${source}" ${libraries}`;
  const env = sanitizeBuildEnvironment();
  const buildResult = spawnSync("C:\\Windows\\System32\\cmd.exe",
    ["/d", "/v:on", "/s", "/c", `"${inline}"`], {
    cwd: scratch, encoding: "utf8", timeout, windowsHide: true, env,
    windowsVerbatimArguments: true,
  });
  // Preserve diagnostic categories; compiler output can reveal local paths.
  assert.ok(buildResult.status === 0 && !buildResult.error, FAIL);
  const snapshot = inspect(scratch, name);
  const receipt = Object.freeze({});
  RECEIPTS.set(receipt, snapshot);
  return { receipt, buildResult };
}

// A receipt is not a general-purpose executable launcher. Pin each fixture's
// allowed operations and local test targets before checking or launching its
// compiled output. This limits test-harness misuse; it does NOT solve the
// image-section/byte TOCTOU that remains after the checked FD is closed.
function validateFixtureArgs(name, scratch, args) {
  assert.ok(NAMES.has(name) && typeof scratch === "string", FAIL);
  const values = Array.isArray(args) ? Array.from(args) : null;
  assert.ok(values && values.length <= 2
    && values.every(value => typeof value === "string" && value.length <= 1024
      && !/[\x00-\x1f\x7f]/.test(value)), FAIL);
  const localTarget = (target, leaf) => comparable(target) === comparable(path.join(scratch, leaf));
  const scope = () => values.length === 2 && comparable(values[1]) === comparable(scratch);
  let allowed = false;
  if (name === "acl-preflight.exe") {
    allowed = values.length === 2 && (
      (values[0] === "--inspect"
        && ["owner-only", "broad-access", "inherited-access", "missing", "junction"]
          .some(leaf => localTarget(values[1], leaf)))
      || (values[0] === "--register" && localTarget(values[1], "owner-only"))
    );
  } else if (name === "inherit-only-fixture.exe") {
    allowed = values.length === 0;
  } else if (name === "deny-fetch.exe") {
    allowed = (values.length === 1 && values[0] === "--self-test")
      || (values[0] === "--connect" && scope());
  } else if (name === "positive-shape.exe") {
    allowed = values.length === 0
      || (values.length === 1 && values[0] === "--self-test")
      || (["--connect", "--register", "--hydrate"].includes(values[0]) && scope());
  }
  assert.ok(allowed, FAIL);
  return values;
}

function runCompiledFixture(receipt, args, timeout = 10000) {
  const previous = RECEIPTS.get(receipt);
  assert.ok(previous, FAIL);
  const name = path.basename(previous.executable);
  const vettedArgs = validateFixtureArgs(name, previous.scratch, args);
  const next = inspect(previous.scratch, name);
  assert.ok(next.rootDev === previous.rootDev && next.rootIno === previous.rootIno
    && next.dev === previous.dev && next.ino === previous.ino
    && next.size === previous.size && next.digest === previous.digest, FAIL);
  // Preserve the previously published *test-only* native coverage path.
  // This is still path-based spawn and is NOT secure process-image custody.
  // No production or release authorization may be derived from this runner.
  return spawnSync(previous.executable, vettedArgs, {
    cwd: previous.scratch, encoding: "utf8", timeout, windowsHide: true,
  });
}

module.exports = { buildCompiledFixture, runCompiledFixture, validateFixtureArgs,
  sanitizeBuildEnvironment };
