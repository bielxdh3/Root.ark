"use strict";

// Native, read-only ACL admission preflight for a future CFAPI provider.
// This test only changes ACLs on its own disposable TEMP directories.
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const source = path.resolve(__dirname, "../sync-client/rootark-sync-windows-cfapi-acl-preflight.cpp");
const vswhere = "C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe";

function run(file, args, cwd, timeout = 10000) {
  return spawnSync(file, args, { cwd, encoding: "utf8", timeout, windowsHide: true });
}

test("#66 native ACL preflight has no sync-root registration or file-content operations", async () => {
  const code = await fs.readFile(source, "utf8");
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
    const where = run(vswhere, ["-all", "-products", "*", "-prerelease",
      "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"], undefined, 6000);
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 toolchain unavailable"); return; }
    try { await fs.access(vcvars); }
    catch { t.skip("MSVC x64 vcvars missing"); return; }

    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-acl-test-"));
    t.after(() => fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    const exe = path.join(scratch, "acl-preflight.exe");
    const batch = path.join(scratch, "build.cmd");
    await fs.writeFile(batch, ["@echo off", `call "${vcvars}" >nul`,
      "if errorlevel 1 exit /b 1",
      `cl /nologo /std:c++17 /W4 /WX /EHsc /Fe:"${exe}" "${source}" cldapi.lib advapi32.lib`,
      "exit /b %errorlevel%", ""].join("\r\n"));
    const build = run("cmd.exe", ["/d", "/c", batch], scratch, 40000);
    assert.equal(build.status, 0, `native SDK build failed: ${build.stdout}\n${build.stderr}`);

    const strictRoot = path.join(scratch, "owner-only");
    const exposedRoot = path.join(scratch, "broad-access");
    const inheritedRoot = path.join(scratch, "inherited-access");
    await fs.mkdir(strictRoot);
    await fs.mkdir(exposedRoot);
    await fs.mkdir(inheritedRoot);
    const aclScript = path.join(scratch, "fixture-acl.ps1");
    await fs.writeFile(aclScript, [
      "param([string]$Target, [string]$Expose)",
      "$ErrorActionPreference = 'Stop'",
      "$owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User",
      "$acl = Get-Acl -LiteralPath $Target",
      "$acl.SetOwner($owner)",
      "$acl.SetAccessRuleProtection($true, $false)",
      "foreach ($rule in @($acl.Access)) { $acl.RemoveAccessRuleSpecific($rule) | Out-Null }",
      "$access = [System.Security.AccessControl.FileSystemRights]::FullControl",
      "$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit",
      "$none = [System.Security.AccessControl.PropagationFlags]::None",
      "$allow = [System.Security.AccessControl.AccessControlType]::Allow",
      "$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($owner, $access, $inherit, $none, $allow))",
      "if ($Expose -eq '1') {",
      "  $world = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::WorldSid, $null)",
      "  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($world, $access, $inherit, $none, $allow))",
      "}",
      "if ($Expose -eq '2') { $acl.SetAccessRuleProtection($false, $true) }",
      "Set-Acl -LiteralPath $Target -AclObject $acl",
    ].join("\r\n"));
    for (const [dir, expose] of [[strictRoot, "0"], [exposedRoot, "1"], [inheritedRoot, "2"]]) {
      const applied = run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-File", aclScript, dir, expose], scratch, 10000);
      assert.equal(applied.status, 0, `disposable ACL setup failed: ${applied.stderr}`);
    }

    const inspect = (dir) => {
      const outcome = run(exe, ["--inspect", dir], scratch);
      return { status: outcome.status, output: JSON.parse(outcome.stdout.trim()) };
    };
    const strong = inspect(strictRoot);
    assert.equal(strong.status, 0);
    assert.equal(strong.output.aclPreflightPassed, true);
    assert.equal(strong.output.handleIdentityCaptured, true);
    assert.equal(strong.output.syncRootRegistered, false);
    assert.equal(strong.output.cloudDataBytesTransferred, 0);

    const broad = inspect(exposedRoot);
    assert.notEqual(broad.status, 0);
    assert.equal(broad.output.aclPreflightPassed, false);
    const inherited = inspect(inheritedRoot);
    assert.notEqual(inherited.status, 0);
    assert.equal(inherited.output.aclPreflightPassed, false);
    const missing = inspect(path.join(scratch, "missing"));
    assert.notEqual(missing.status, 0);
    assert.equal(missing.output.aclPreflightPassed, false);

    const junction = path.join(scratch, "junction");
    try {
      await fs.symlink(strictRoot, junction, "junction");
      const reparse = inspect(junction);
      assert.notEqual(reparse.status, 0);
      assert.equal(reparse.output.aclPreflightPassed, false);
    } catch (error) {
      if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
      t.diagnostic("junction creation unavailable; native reparse-negative test skipped");
    }
    assert.notEqual(run(exe, ["--register", strictRoot], scratch).status, 0);
  });
