"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { readCfapiFixtureFailureStage } = require("../scripts/acl-test-failure-diagnostic");

const fixtureScript = path.join(__dirname, "support/issue-66-cfapi-acl-fixture.ps1");
const systemPowerShell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const quote = (text) => `'${text.replace(/'/g, "''")}'`;

test("CFAPI disposable ACL fixtures persist without Get-Acl or Set-Acl under restricted shell command policy",
  { skip: process.platform !== "win32", timeout: 45000 }, async (t) => {
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-privilege-test-"));
    t.after(() => fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }));
    for (const [name, expose, expectProtected] of [
      ["owner-only", "0", true], ["broad-access", "1", true], ["inherited-access", "2", false],
    ]) {
      const target = path.join(scratch, name);
      await fs.mkdir(target);
      // The shell function models a Set-Acl implementation that cannot apply
      // security sections outside a restricted token's DACL permissions.
      // Calling it is an error; the fixture must persist through the narrower
      // .NET directory API under the existing non-elevated Windows token.
      const ps = [
        "function Set-Acl { throw 'FORBIDDEN_SET_ACL' }",
        "function Get-Acl { throw 'FORBIDDEN_GET_ACL' }",
        `& ${quote(fixtureScript)} ${quote(target)} ${quote(expose)}`,
        `if (([System.IO.Directory]::GetAccessControl(${quote(target)})).AreAccessRulesProtected -ne $${expectProtected.toString().toLowerCase()}) { exit 71 }`,
      ].join("; ");
      const child = spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command", ps], {
        cwd: scratch, encoding: "utf8", windowsHide: true, timeout: 15000,
      });
      assert.equal(child.status, 0, `ACL fixture ${name} requires a DACL-only write`);
    }
  });

test("CFAPI fixture phase telemetry recognizes only allowlisted failures, never stderr details", () => {
  for (const base of ["ACL_OWNER_APPLY", "ACL_BROAD_APPLY", "ACL_INHERITED_APPLY"]) {
    for (const phase of ["INIT", "OWNER", "PROTECT", "RULES", "WRITE"]) {
      assert.equal(readCfapiFixtureFailureStage(base, `ROOTARK_CFAPI_FIXTURE_V1 phase=${phase}\r\n`),
        `${base}_${phase}`);
    }
    for (const unsafe of [
      "ROOTARK_CFAPI_FIXTURE_V1 phase=SACL",
      "ROOTARK_CFAPI_FIXTURE_V1 phase=WRITE path=C:\\secret",
      "prefix ROOTARK_CFAPI_FIXTURE_V1 phase=WRITE",
      "ROOTARK_CFAPI_FIXTURE_V1 phase=WRITE\nROOTARK_CFAPI_FIXTURE_V1 phase=OWNER",
      "ROOTARK_CFAPI_FIXTURE_V1 phase=WRITE\nPowerShell: private error",
    ]) assert.equal(readCfapiFixtureFailureStage(base, unsafe), null);
  }
  assert.equal(readCfapiFixtureFailureStage("ALTERNATE_OWNER", "ROOTARK_CFAPI_FIXTURE_V1 phase=WRITE"), null);
});

test("CFAPI PowerShell fixture emits only a fixed category on rejected fixture mode",
  { skip: process.platform !== "win32", timeout: 15000 }, async (t) => {
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-phase-test-"));
    t.after(() => fs.rm(scratch, { recursive: true, force: true }));
    const target = path.join(scratch, "owner-only");
    await fs.mkdir(target);
    const ps = `& ${quote(fixtureScript)} ${quote(target)} 'INVALID_MODE_WITH_PRIVATE_PATH'`;
    const child = spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive",
      "-ExecutionPolicy", "Bypass", "-Command", ps], {
      cwd: scratch, encoding: "utf8", windowsHide: true, timeout: 12000,
    });
    assert.notEqual(child.status, 0, "the fixture must fail on unsupported access mode");
    assert.equal(child.stderr.trim(), "ROOTARK_CFAPI_FIXTURE_V1 phase=INIT");
    assert.equal(readCfapiFixtureFailureStage("ACL_OWNER_APPLY", child.stderr), "ACL_OWNER_APPLY_INIT");
  });

test("CFAPI fixture never changes an existing directory outside its disposable scratch contract",
  { skip: process.platform !== "win32", timeout: 15000 }, async (t) => {
    const foreign = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-foreign-"));
    t.after(() => fs.rm(foreign, { recursive: true, force: true }));
    const target = path.join(foreign, "owner-only");
    await fs.mkdir(target);
    const before = await fs.stat(target);
    const daclDigest = () => {
      const ps = [
        "$section = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access",
        `$acl = [System.IO.Directory]::GetAccessControl(${quote(target)}, $section)`,
        "$sha = [System.Security.Cryptography.SHA256]::Create()",
        "[Console]::Out.WriteLine(([BitConverter]::ToString($sha.ComputeHash($acl.GetSecurityDescriptorBinaryForm()))).Replace('-', ''))",
      ].join("; ");
      const result = spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive",
        "-Command", ps], { cwd: foreign, encoding: "utf8", windowsHide: true, timeout: 12000 });
      assert.equal(result.status, 0, "must inspect the disposable DACL");
      assert.match(result.stdout.trim(), /^[A-F0-9]{64}$/);
      return result.stdout.trim();
    };
    const beforeDacl = daclDigest();
    const child = spawnSync(systemPowerShell, ["-NoProfile", "-NonInteractive",
      "-ExecutionPolicy", "Bypass", "-File", fixtureScript, target, "0"], {
      cwd: foreign, encoding: "utf8", windowsHide: true, timeout: 12000,
    });
    assert.notEqual(child.status, 0, "the helper must reject an unexpected parent");
    assert.equal(child.stderr.trim(), "ROOTARK_CFAPI_FIXTURE_V1 phase=INIT");
    const after = await fs.stat(target);
    assert.equal(after.ino, before.ino, "untrusted target still references original object");
    assert.equal(daclDigest(), beforeDacl, "foreign directory owner and DACL remain unchanged");
  });
