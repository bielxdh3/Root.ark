"use strict";

const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { verifyWindowsChunkUploadTree, ensureWindowsChunkUploadRoot,
  getWindowsChunkAclDescriptor } = require("../services/chunkUploadWindowsAcl");

test("Windows ACL verification cannot be forged by a PATH-provided powershell.exe", (t) => {
  if (process.platform !== "win32") return t.skip("actual Windows NTFS and PowerShell required");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-acl-fake-powershell-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const fakeSource = path.join(directory, "FakeShell.cs");
  const fakePowerShell = path.join(directory, "powershell.exe");
  fs.writeFileSync(fakeSource, [
    "using System;",
    "public static class FakeShell {",
    "  public static int Main(string[] args) {",
    "    Console.WriteLine(\"FAKE_ACL_SUCCESS\");",
    "    return 0;",
    "  }",
    "}",
  ].join("\n"));
  const compiler = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe";
  assert.equal(fs.existsSync(compiler), true, "Windows test requires the native .NET compiler");
  execFileSync(compiler, ["/nologo", "/out:" + fakePowerShell, fakeSource],
    { windowsHide: true, stdio: "pipe" });
  const unsafe = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-acl-unsafe-tree-"));
  const safe = path.join(process.env.LOCALAPPDATA,
    "rootark-atomic-powershell-safe-" + crypto.randomBytes(8).toString("hex"));
  t.after(() => fs.rmSync(unsafe, { recursive: true, force: true }));
  t.after(() => fs.rmSync(safe, { recursive: true, force: true }));
  const original = process.env.PATH;
  try {
    process.env.PATH = directory + path.delimiter + original;
    assert.match(execFileSync("powershell.exe", ["-NoProfile"], {
      encoding: "utf8", windowsHide: true }), /FAKE_ACL_SUCCESS/,
    "prove the malicious binary is actually selected through PATH");
    // A default inherited %TEMP% DACL fails real native ACL verification.
    assert.throws(() => verifyWindowsChunkUploadTree(unsafe),
      /ACL validation failed|Untrusted principal|Unsafe chunk staging|Unverifiable/i,
      "an untrusted executable must never return a forged ACL success");
    ensureWindowsChunkUploadRoot(safe);
    assert.doesNotThrow(() => verifyWindowsChunkUploadTree(safe));
    assert.match(getWindowsChunkAclDescriptor(safe), /^O:/,
      "descriptor inspection must also ignore PATH and use real Windows API");
  } finally { process.env.PATH = original; }
});
