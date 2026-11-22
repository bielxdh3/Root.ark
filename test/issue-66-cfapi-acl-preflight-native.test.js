"use strict";

// Native, read-only ACL admission preflight for a future CFAPI provider.
// This test only changes ACLs on its own disposable TEMP directories.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { createAclFailureDiagnostic, readCfapiFixtureFailureStage } =
  require("../scripts/acl-test-failure-diagnostic");
const { buildCompiledFixture, runCompiledFixture } =
  require("./support/issue-66-cfapi-built-artifact");

const source = path.resolve(__dirname, "../sync-client/rootark-sync-windows-cfapi-acl-preflight.cpp");
const rootPolicy = path.resolve(__dirname, "../sync-client/rootark-sync-windows-cfapi-root-policy.hpp");
const aclScript = path.join(__dirname, "support/issue-66-cfapi-acl-fixture.ps1");

// Keep a distinct, literal executable at each process creation site. A
// generic file/lookup dispatcher obscures executable selection to static
// analysis and expands the set of callers capable of selecting a binary.
// Fixed paths reduce PATH hijacking; they do not authenticate loaded bytes.
function runVswhere(args, timeout = 10000) {
  return spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
    args, { encoding: "utf8", timeout, windowsHide: true });
}

function runFixturePowershell(args, cwd, timeout = 10000) {
  return spawnSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    args, { cwd, encoding: "utf8", timeout, windowsHide: true });
}

test("#66 native ACL preflight has no sync-root registration or file-content operations", async () => {
  const code = (await Promise.all([fs.readFile(source, "utf8"),
    fs.readFile(rootPolicy, "utf8")])).join("\n");
  for (const unsafe of [/\bCfRegisterSyncRoot\s*\(/, /\bCfConnectSyncRoot\s*\(/,
    /\bCfCreatePlaceholders\s*\(/, /\bCfExecute\s*\(/,
    /\bSetNamedSecurityInfoW\s*\(/, /\bSetSecurityInfo\s*\(/,
    /\bReadFile\s*\(/, /\bWriteFile\s*\(/]) {
    assert.doesNotMatch(code, unsafe);
  }
  assert.match(code, /GetSecurityInfo\s*\(/);
  assert.match(code, /FILE_FLAG_OPEN_REPARSE_POINT/);
  assert.match(code, /SE_DACL_PROTECTED/);
});

test("#66 Windows SDK ACL preflight accepts a protected owner-only DACL and rejects broad access or reparse points",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const diagnostic = createAclFailureDiagnostic(t, "CFAPI_PREFLIGHT");
    return diagnostic.run(async () => {
    diagnostic.stage("TOOLCHAIN_LOOKUP");
    const where = runVswhere(["-all", "-products", "*", "-prerelease",
      "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"], 6000);
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 toolchain unavailable"); return; }
    diagnostic.stage("TOOLCHAIN_RESOLVE");
    try { await fs.access(vcvars); }
    catch { t.skip("MSVC x64 vcvars missing"); return; }

    diagnostic.stage("SCRATCH_CREATE");
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
    t.after(() => fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const exe = path.join(scratch, "acl-preflight.exe");
    // Adversarial proof: a writable TEMP build.cmd may exist, but our build
    // must never read or invoke it. Its contents are disposable canary bytes.
    const batchCanary = path.join(scratch, "untrusted-build-script-ran.txt");
    await fs.writeFile(path.join(scratch, "build.cmd"), [
      "@echo off", `echo UNTRUSTED > "${batchCanary}"`, "",
    ].join("\r\n"));
    diagnostic.stage("SDK_BUILD");
    const { receipt, buildResult: build } =
      buildCompiledFixture(scratch, "acl-preflight.exe", vcvars);
    assert.equal(build.status, 0, `native SDK build failed: ${build.stdout}\n${build.stderr}`);
    await assert.rejects(fs.access(batchCanary), { code: "ENOENT" },
      "no TEMP build.cmd may execute as part of the native test compilation");

    diagnostic.stage("ROOT_CREATE");
    const strictRoot = path.join(scratch, "owner-only");
    const exposedRoot = path.join(scratch, "broad-access");
    const inheritedRoot = path.join(scratch, "inherited-access");
    await fs.mkdir(strictRoot);
    await fs.mkdir(exposedRoot);
    await fs.mkdir(inheritedRoot);
    diagnostic.stage("ACL_SCRIPT_CHECK");
    await fs.access(aclScript);
    for (const [dir, expose, stage] of [
      [strictRoot, "0", "ACL_OWNER_APPLY"],
      [exposedRoot, "1", "ACL_BROAD_APPLY"],
      [inheritedRoot, "2", "ACL_INHERITED_APPLY"],
    ]) {
      diagnostic.stage(stage);
      const applied = runFixturePowershell(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", aclScript, dir, expose], scratch, 10000);
      if (applied.status !== 0) {
        const fixedStage = readCfapiFixtureFailureStage(stage, applied.stderr);
        if (fixedStage) diagnostic.stage(fixedStage);
      }
      assert.equal(applied.status, 0, "disposable ACL setup failed");
    }

    const inspect = (dir) => {
      const outcome = runCompiledFixture(receipt, ["--inspect", dir]);
      return { status: outcome.status, output: JSON.parse(outcome.stdout.trim()) };
    };
    diagnostic.stage("OWNER_INSPECT");
    const strong = inspect(strictRoot);
    diagnostic.stage("OWNER_ACCEPT");
    assert.equal(strong.status, 0);
    assert.equal(strong.output.aclPreflightPassed, true);
    diagnostic.stage("OWNER_HANDLE");
    assert.equal(strong.output.handleIdentityCaptured, true);
    diagnostic.stage("OWNER_NO_REGISTER");
    assert.equal(strong.output.syncRootRegistered, false);
    diagnostic.stage("OWNER_NO_TRANSFER");
    assert.equal(strong.output.cloudDataBytesTransferred, 0);

    // A genuine native NTFS directory HANDLE must enumerate beyond 16,384
    // entries without JS pathname reopens or truncation. All generated empty
    // files are confined to the disposable owner-ACL fixture, not the user's
    // sync root; the result is informational, NEVER proof of signed custody.
    diagnostic.stage("OWNER_NATIVE_ENUMERATE_CREATE");
    const entries = 16_385;
    for (let start = 0; start < entries; start += 128) {
      await Promise.all(Array.from({ length: Math.min(128, entries - start) }, (_, i) =>
        fs.writeFile(path.join(strictRoot,
          `native-entry-${String(start + i).padStart(5, "0")}.bin`), "", { flag: "wx" })));
    }
    diagnostic.stage("OWNER_NATIVE_ENUMERATE_VERIFY");
    const enumerated = inspect(strictRoot); // ordinary ACL-only control remains unchanged
    assert.equal(enumerated.status, 0);
    const nativeEnumeration = runCompiledFixture(receipt, ["--enumerate", strictRoot], 25000);
    assert.equal(nativeEnumeration.status, 0,
      `native same-HANDLE enumeration failed: ${nativeEnumeration.stderr}`);
    const listing = JSON.parse(nativeEnumeration.stdout.trim());
    assert.equal(listing.aclPreflightPassed, true);
    assert.equal(listing.nativeEnumerationInformational, true);
    assert.equal(listing.directoryEntriesEnumerated, entries,
      "native opened-HANDLE enumeration may not truncate a >16,384-entry root");
    assert.equal(listing.cloudDataBytesTransferred, 0);
    assert.equal(listing.syncRootRegistered, false,
      "enumeration cannot activate or silently register a CFAPI sync root");

    diagnostic.stage("BROAD_INSPECT");
    const broad = inspect(exposedRoot);
    diagnostic.stage("BROAD_REJECT");
    assert.notEqual(broad.status, 0);
    assert.equal(broad.output.aclPreflightPassed, false);
    const unauthorizedEnumeration = runCompiledFixture(receipt, ["--enumerate", exposedRoot]);
    assert.notEqual(unauthorizedEnumeration.status, 0,
      "a broad-access root may not become a native enumeration authority");
    assert.equal(JSON.parse(unauthorizedEnumeration.stdout.trim()).directoryEntriesEnumerated, 0);
    diagnostic.stage("INHERITED_INSPECT");
    const inherited = inspect(inheritedRoot);
    diagnostic.stage("INHERITED_REJECT");
    assert.notEqual(inherited.status, 0);
    assert.equal(inherited.output.aclPreflightPassed, false);
    diagnostic.stage("MISSING_INSPECT");
    const missing = inspect(path.join(scratch, "missing"));
    diagnostic.stage("MISSING_REJECT");
    assert.notEqual(missing.status, 0);
    assert.equal(missing.output.aclPreflightPassed, false);

    diagnostic.stage("JUNCTION_CREATE");
    const junction = path.join(scratch, "junction");
    try {
      await fs.symlink(strictRoot, junction, "junction");
      diagnostic.stage("JUNCTION_INSPECT");
      const reparse = inspect(junction);
      diagnostic.stage("JUNCTION_REJECT");
      assert.notEqual(reparse.status, 0);
      assert.equal(reparse.output.aclPreflightPassed, false);
    } catch (error) {
      if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
      t.diagnostic("junction creation unavailable; native reparse-negative test skipped");
    }
    diagnostic.stage("REGISTER_REJECT");
    assert.notEqual(runCompiledFixture(receipt, ["--register", strictRoot]).status, 0);
    // An artifact modified after THIS compile receipt must not be relaunched.
    // This is not atomic Windows executable custody against concurrent swaps.
    await fs.appendFile(exe, Buffer.from([0x21]));
    assert.throws(() => runCompiledFixture(receipt, ["--inspect", strictRoot]),
      /UNTRUSTED_EXECUTABLE/);
    });
  });

test("#66 native DACL evaluator refuses inherit-only ACEs even alongside effective Administrators access",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const where = runVswhere(["-all", "-products", "*", "-prerelease",
      "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"], 6000);
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 toolchain unavailable"); return; }
    try { await fs.access(vcvars); }
    catch { t.skip("MSVC x64 vcvars missing"); return; }

    // Include the actual production translation unit to call its internal
    // evaluator with a real SDK DACL, independent of token elevation. A later
    // native caller could otherwise open via Administrators while a purported
    // owner-only ACE does not apply to the inspected directory itself.
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-ace-native-"));
    t.after(() => fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const fixture = path.join(scratch, "inherit-only-fixture.cpp");
    const exe = path.join(scratch, "inherit-only-fixture.exe");
    const includePath = source.replaceAll("\\", "/");
    await fs.writeFile(fixture, [
      "#define wmain preflight_fixture_only_entry",
      `#include "${includePath}"`,
      "#undef wmain",
      "",
      "bool evaluate(PSID user, PSID admins, DWORD ownerFlags, DWORD denyFlags, bool& result) {",
      "  unsigned char aclBytes[1024]{};",
      "  PACL acl = reinterpret_cast<PACL>(aclBytes);",
      "  if (!InitializeAcl(acl, sizeof(aclBytes), ACL_REVISION)) return false;",
      "  const DWORD rights = FILE_READ_ATTRIBUTES | READ_CONTROL;",
      "  if (denyFlags != 0 && !AddAccessDeniedAceEx(acl, ACL_REVISION, denyFlags, rights, admins))",
      "    return false;",
      "  if (!AddAccessAllowedAceEx(acl, ACL_REVISION, ownerFlags, rights, user)",
      "      || !AddAccessAllowedAceEx(acl, ACL_REVISION, 0, rights, admins)) return false;",
      "  SECURITY_DESCRIPTOR descriptor{};",
      "  if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION)",
      "      || !SetSecurityDescriptorOwner(&descriptor, user, FALSE)",
      "      || !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE)",
      "      || !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)",
      "      || !IsValidSecurityDescriptor(&descriptor) || !IsValidAcl(acl)) return false;",
      "  std::vector<unsigned char> identity(GetLengthSid(user));",
      "  if (!CopySid(static_cast<DWORD>(identity.size()), identity.data(), user)) return false;",
      "  result = trustedDacl(&descriptor, acl, user, identity);",
      "  return true;",
      "}",
      "",
      "int wmain() {",
      "  std::vector<unsigned char> user;",
      "  std::vector<unsigned char> admins;",
      "  if (!currentUserSid(user) || !wellKnownSid(WinBuiltinAdministratorsSid, admins)) return 80;",
      "  bool normal = false, ownerOnlyInherited = false, denyOnlyInherited = false;",
      "  const DWORD onlyChildren = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;",
      "  if (!evaluate(user.data(), admins.data(), 0, 0, normal)",
      "      || !evaluate(user.data(), admins.data(), onlyChildren, 0, ownerOnlyInherited)",
      "      || !evaluate(user.data(), admins.data(), 0, onlyChildren, denyOnlyInherited))",
      "    return 81;",
      "  std::printf(\"{\\\"normal\\\":%s,\\\"ownerInheritOnly\\\":%s,\\\"denyInheritOnly\\\":%s}\\n\",",
      "    normal ? \"true\" : \"false\", ownerOnlyInherited ? \"true\" : \"false\",",
      "    denyOnlyInherited ? \"true\" : \"false\");",
      "  return 0;",
      "}",
      "",
    ].join("\n"));
    const { receipt, buildResult: build } =
      buildCompiledFixture(scratch, "inherit-only-fixture.exe", vcvars);
    assert.equal(build.status, 0, `native SDK harness build failed: ${build.stdout}\n${build.stderr}`);
    const result = runCompiledFixture(receipt, []);
    assert.equal(result.status, 0, `native SDK fixture failed: ${result.stdout}\n${result.stderr}`);
    const acl = JSON.parse(result.stdout.trim());
    assert.equal(acl.normal, true, "effective owner ACE remains accepted");
    assert.equal(acl.ownerInheritOnly, false, "owner inheritable-only ACE must not grant root access");
    assert.equal(acl.denyInheritOnly, false, "strict preflight rejects inherit-only DENY ACE too");
  });
