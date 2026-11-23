"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const vm = require("node:vm");
const { runDiagnostic, runIsolatedDiagnostic, classifyNativeAclCommand,
  buildReadAclFailureScript, classifyReadAclSubstep, classifyNativeAclAncestorDepth,
  getSnapshotAclDirectory } = require("../scripts/issue65-windows-snapshot-acl-probe");

const steps = (override = {}) => ({
  fixture_acl: () => undefined,
  snapshot_root_acl: () => undefined,
  snapshot_copy: () => undefined,
  cleanup: () => undefined,
  ...override,
});

test("#65 diagnostic reports distinct fixture, snapshot root, copy and cleanup stages without private data", async () => {
  const messages = [];
  assert.equal(await runDiagnostic(steps(), (text) => messages.push(text)), true);
  assert.deepEqual(messages, [
    "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=PASS",
    "ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_root_acl result=PASS",
    "ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_copy result=PASS",
    "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS",
  ]);
});

test("#65 fixture failure is distinguishable, later probes do not run, cleanup still runs", async () => {
  const messages = [];
  const touched = [];
  const result = await runDiagnostic(steps({
    fixture_acl: () => { throw Object.assign(new Error("hidden C:\\private\\path S-1-5-21"), { code: "EACCES" }); },
    snapshot_root_acl: () => { touched.push("snapshot_root_acl"); },
    snapshot_copy: () => { touched.push("snapshot_copy"); },
    cleanup: () => { touched.push("cleanup"); },
  }), (text) => messages.push(text));
  assert.equal(result, false);
  assert.deepEqual(touched, ["cleanup"]);
  assert.deepEqual(messages, [
    "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=FAIL code=EACCES",
    "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS",
  ]);
});

test("#65 snapshot ACL failure does not run egress copy or leak raw error details", async () => {
  const messages = [];
  let copied = false;
  const result = await runDiagnostic(steps({
    snapshot_root_acl: () => {
      throw Object.assign(new Error("token=secret path=C:\\Users\\private sid=S-1-5-21"), {
        code: "PRIVATE_SNAPSHOT_DIRECTORY_INVALID",
      });
    },
    snapshot_copy: () => { copied = true; },
  }), (text) => messages.push(text));
  assert.equal(result, false);
  assert.equal(copied, false);
  assert.ok(messages.includes("ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_root_acl result=FAIL code=PRIVATE_SNAPSHOT_DIRECTORY_INVALID"));
  assert.doesNotMatch(messages.join("\n"), /token=|sid=|S-1-5-21|C:\\Users|hidden/i);
});

test("#65 unfamiliar or attacker-supplied error codes cannot enter diagnostic logs", async () => {
  const messages = [];
  const result = await runDiagnostic(steps({
    snapshot_copy: () => { throw { code: "EPERM\nsecret=credential" }; },
    cleanup: () => { throw { code: "C:\\private\\sid=secret" }; },
  }), (text) => messages.push(text));
  assert.equal(result, false);
  assert.deepEqual(messages.slice(-2), [
    "ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_copy result=FAIL code=OTHER",
    "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=FAIL code=OTHER",
  ]);
});

test("#65 P2: native PowerShell raw stderr is captured, never forwarded to hosted job output", () => {
  const messages = [];
  let checkedPipe = false;
  const result = runIsolatedDiagnostic((file, args, options) => {
    assert.equal(file, process.execPath);
    assert.deepEqual(options.stdio, ["ignore", "pipe", "pipe"]);
    assert.equal(args[1], "--isolated-child");
    checkedPipe = true;
    return {
      status: 1,
      stdout: "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=FAIL code=EACCES\n"
        + "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS\n",
      stderr: "Get-Acl C:\\Users\\runner\\secret-key.pfx: S-1-5-21-USER credential=ABC123\n",
    };
  }, (line) => messages.push(line));
  assert.equal(checkedPipe, true);
  assert.equal(result, false);
  assert.deepEqual(messages, [
    "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=FAIL code=EACCES",
    "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS",
  ]);
  assert.doesNotMatch(messages.join("\n"), /C:\\Users|S-1-5-21|secret-key|credential=|Get-Acl/);
});

test("#65 P2: malformed native child output and hidden stderr always fail closed", () => {
  const messages = [];
  const result = runIsolatedDiagnostic(() => ({
    status: 0,
    stdout: "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=PASS\n"
      + "C:\\Users\\runner\\secret S-1-5-21 token=ABC\n",
    stderr: "Powershell private ACL dumping itself...",
  }), (line) => messages.push(line));
  assert.equal(result, false);
  assert.equal(messages.length, 1);
  assert.equal(messages[0], "ROOTARK_ISSUE65_ACL_PROBE stage=isolated_process result=FAIL code=OTHER");
  assert.doesNotMatch(messages.join("\n"), /C:\\Users|S-1-5-21|private ACL|token=/);
});

test("#65 P2: real Node child with hostile PowerShell stderr cannot leak its raw bytes", () => {
  const sentinels = "Get-Acl C:\\Users\\SECRET\\key.pfx SID=S-1-5-21-123456 key=TOP_SECRET";
  const script = `process.stdout.write(${JSON.stringify("ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=FAIL code=EACCES\nROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS\n")}); process.stderr.write(${JSON.stringify(sentinels)}); process.exitCode=1;`;
  const messages = [];
  const ok = runIsolatedDiagnostic((_binary, _args, options) =>
    spawnSync(process.execPath, ["-e", script], options), (line) => messages.push(line));
  assert.equal(ok, false);
  assert.deepEqual(messages, [
    "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=FAIL code=EACCES",
    "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS",
  ]);
  assert.doesNotMatch(messages.join("\n"), /SECRET|Get-Acl|S-1-5|key=|C:\\Users/);
});

test("#65 P2: even a zero-exit native child with private stderr fails closed", () => {
  const messages = [];
  assert.equal(runIsolatedDiagnostic(() => ({ status: 0, stdout: [
    "ROOTARK_ISSUE65_ACL_PROBE stage=fixture_acl result=PASS",
    "ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_root_acl result=PASS",
    "ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_copy result=PASS",
    "ROOTARK_ISSUE65_ACL_PROBE stage=cleanup result=PASS",
  ].join("\n") + "\n", stderr: "C:\\Users\\private" }), (line) => messages.push(line)), false);
  assert.deepEqual(messages, ["ROOTARK_ISSUE65_ACL_PROBE stage=isolated_process result=FAIL code=OTHER"]);
});

test("#65 hosted ACL probe categorizes native read/seal errors by trusted path ROLE, never by path content", () => {
  const root = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  const parent = "C:\\Users\\runner\\AppData\\Local\\Rootark";
  const ancestor = "C:\\Users\\runner\\AppData\\Local";
  const makeArgs = (target, action) => ["-NoLogo", "-Command",
    `$target = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${Buffer.from(target, "utf16le").toString("base64")}')); $acl=Get-Acl -LiteralPath $target; ${action === "seal" ? "Set-Acl -LiteralPath $target -AclObject $acl" : "ConvertTo-Json $acl"}`];
  assert.equal(classifyNativeAclCommand(makeArgs(ancestor, "read"), root), "ACL_READ_ANCESTOR");
  assert.equal(classifyNativeAclCommand(makeArgs(parent, "seal"), root), "ACL_SEAL_SCRIPT_PARENT");
  assert.equal(classifyNativeAclCommand(makeArgs(root, "read"), root), "ACL_READ_LEAF");
  assert.equal(classifyNativeAclCommand(makeArgs(root, "seal"), root), "ACL_SEAL_SCRIPT_LEAF");
  assert.equal(classifyNativeAclCommand(["-Command", "Write-Output C:\\Users\\runner\\secret"], root), "OTHER");
});

test("#65 ACL classifier recognizes the actual PowerShell scripts from fileReadHandle", () => {
  // Exercise the native script constructors from the production source, not a
  // hand-written approximation that can silently drift from the real commands.
  const source = fs.readFileSync(path.join(__dirname, "../services/fileReadHandle.js"), "utf8");
  const extract = (name, next) => {
    const first = source.indexOf(`function ${name}(`);
    const last = source.indexOf(`function ${next}(`, first);
    assert.ok(first >= 0 && last > first, `Production ${name} boundary missing`);
    return source.slice(first, last);
  };
  const root = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  const parent = path.win32.dirname(root);
  const ancestor = path.win32.dirname(parent);
  const captures = [];
  const context = { Buffer, runPowerShell(script) { captures.push(script); return "{}"; } };
  const read = vm.runInNewContext(`${extract("windowsDirectoryAcl", "secureNewWindowsSnapshotDirectory")}\nwindowsDirectoryAcl`, context);
  const seal = vm.runInNewContext(`${extract("secureNewWindowsSnapshotDirectory", "validateDirectorySecurity")}\nsecureNewWindowsSnapshotDirectory`, context);
  read(ancestor);
  assert.equal(classifyNativeAclCommand(["-Command", captures.pop()], root), "ACL_READ_ANCESTOR");
  read(parent);
  assert.equal(classifyNativeAclCommand(["-Command", captures.pop()], root), "ACL_READ_PARENT");
  read(root);
  assert.equal(classifyNativeAclCommand(["-Command", captures.pop()], root), "ACL_READ_LEAF");
  seal(parent);
  const sealScript = captures.pop();
  assert.ok(sealScript.indexOf("Get-Acl -LiteralPath $target") < sealScript.indexOf("Set-Acl -LiteralPath $target"),
    "Production seal script reads the existing ACL before attempting Set-Acl");
  // Even when the FIRST Get-Acl fails, only the script that was attempted is
  // observable: it must never be reported as proof that Set-Acl failed.
  assert.equal(classifyNativeAclCommand(["-Command", sealScript], root), "ACL_SEAL_SCRIPT_PARENT");
  seal(root);
  assert.equal(classifyNativeAclCommand(["-Command", captures.pop()], root), "ACL_SEAL_SCRIPT_LEAF");
});

test("#65 read-only ACL failure probe pinpoints a failed production script step without native data", () => {
  const source = fs.readFileSync(path.join(__dirname, "../services/fileReadHandle.js"), "utf8");
  const first = source.indexOf("function windowsDirectoryAcl(");
  const last = source.indexOf("function secureNewWindowsSnapshotDirectory(", first);
  assert.ok(first > 0 && last > first);
  const commands = [];
  const windowsDirectoryAcl = vm.runInNewContext(`${source.slice(first, last)}\nwindowsDirectoryAcl`, {
    Buffer, runPowerShell: (script) => { commands.push(script); return "{}"; },
  });
  const root = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  windowsDirectoryAcl("C:\\Users\\runner\\AppData\\Local");
  const args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", commands.pop()];
  let called = 0;
  const native = (_binary, nestedArgs, opts) => {
    called++;
    assert.deepEqual(opts.stdio, ["ignore", "pipe", "pipe"]);
    const transformed = nestedArgs.at(-1);
    assert.match(transformed, /ROOTARK_ISSUE65_READ_SUBSTEP=/);
    assert.match(transformed, /\[System\.IO\.Directory\]::GetAccessControl\(\$target\)/);
    assert.match(transformed, /GetOwner\(/);
    assert.match(transformed, /GetAccessRules\(/);
    assert.match(transformed, /ConvertTo-Json/);
    throw { stdout: "ROOTARK_ISSUE65_READ_SUBSTEP=RULES\r\n", stderr: "SID=S-1-5-21 path=C:\\Users\\runner\\secret" };
  };
  assert.equal(classifyReadAclSubstep(native, "powershell.exe", args, { encoding: "utf8" }, root), "ACL_READ_ANCESTOR_RULES");
  assert.equal(called, 1);
  assert.equal(classifyReadAclSubstep(() => { throw { stdout: "ROOTARK_ISSUE65_READ_SUBSTEP=RULES\nsecret=ABC" }; },
    "powershell.exe", args, {}, root), "ACL_READ_ANCESTOR");
});

test("#65 read ACL probe distinguishes GetOwner failure from current-user SID failure", () => {
  const root = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  const ancestor = "C:\\Users\\runner\\AppData\\Local";
  const encoded = Buffer.from(ancestor, "utf16le").toString("base64");
  const args = ["-NoLogo", "-Command", "$target = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('" + encoded + "')); $acl = Get-Acl -LiteralPath $target; $current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { [pscustomobject]@{ sid = $_.IdentityReference.Value; type = $_.AccessControlType.ToString(); rights = [int]$_.FileSystemRights } }); [pscustomobject]@{ owner = $owner; current = $current; protected = $acl.AreAccessRulesProtected; rules = $rules } | ConvertTo-Json -Depth 4 -Compress"];
  for (const [marker, expected] of [
    ["OWNER_READ", "ACL_READ_ANCESTOR_OWNER_READ"],
    ["CURRENT_USER", "ACL_READ_ANCESTOR_CURRENT_USER"],
  ]) {
    const result = classifyReadAclSubstep((_binary, nestedArgs) => {
      const script = nestedArgs.at(-1);
      assert.ok(script.includes("$rootarkProbeStage = '" + marker + "'"));
      throw { stdout: "ROOTARK_ISSUE65_READ_SUBSTEP=" + marker + "\r\n", stderr: "private SID and path" };
    }, "powershell.exe", args, {}, root);
    assert.equal(result, expected);
  }
});

test("#65 read ACL probe reports only fixed PowerShell error classes and trusted ancestor depth", () => {
  const root = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  const targets = [
    ["C:\\Users\\runner\\AppData\\Local", 2],
    ["C:\\Users\\runner\\AppData", 3],
    ["C:\\Users\\runner", 4],
  ];
  const source = fs.readFileSync(path.join(__dirname, "../services/fileReadHandle.js"), "utf8");
  const first = source.indexOf("function windowsDirectoryAcl(");
  const last = source.indexOf("function secureNewWindowsSnapshotDirectory(", first);
  assert.ok(first > 0 && last > first);
  const commands = [];
  const windowsDirectoryAcl = vm.runInNewContext(source.slice(first, last) + "\nwindowsDirectoryAcl", {
    Buffer, runPowerShell: (script) => { commands.push(script); return "{}"; },
  });
  for (const [target, depth] of targets) {
    windowsDirectoryAcl(target);
    const args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", commands.pop()];
    for (const errorClass of ["ACCESS_DENIED", "ITEM_NOT_FOUND"]) {
      let called = 0;
      let hasDefaultErrorClass = false;
      let hasHresultClassification = false;
      let hasItemNotFoundClassification = false;
      const result = classifyReadAclSubstep((_binary, nestedArgs) => {
        called++;
        const script = nestedArgs.at(-1);
        hasDefaultErrorClass = script.includes("$rootarkProbeError = 'OTHER'");
        hasHresultClassification = script.includes("$rootarkProbeException.HResult -eq -2147024891");
        hasItemNotFoundClassification = script.includes("[System.Management.Automation.ItemNotFoundException]");
        throw { stdout: "ROOTARK_ISSUE65_READ_SUBSTEP=GET_ACL;ERROR=" + errorClass + "\r\n",
          stderr: "private path=C:\\Users\\runner\\secret SID=S-1-5-21" };
      }, "powershell.exe", args, {}, root);
      assert.equal(called, 1);
      assert.equal(hasDefaultErrorClass, true);
      assert.equal(hasHresultClassification, true);
      assert.equal(hasItemNotFoundClassification, true);
      assert.equal(result, "ACL_READ_ANCESTOR_D" + depth + "_GET_ACL_" + errorClass);
    }
  }
});

test("#65 ACL diagnostic uses the effective production snapshot directory when an override is configured", () => {
  const override = "C:\\Users\\runner\\AppData\\Local\\Rootark";
  const defaultDirectory = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  const ancestor = "C:\\Users\\runner\\AppData";
  const encoded = Buffer.from(ancestor, "utf16le").toString("base64");
  const args = ["-NoLogo", "-Command", "$target = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('" + encoded + "')); $acl = Get-Acl -LiteralPath $target"];
  const snapshotApi = { getPrivateShareSnapshotDirectory: () => override };
  const effectiveDirectory = getSnapshotAclDirectory(snapshotApi);

  assert.equal(effectiveDirectory, override);
  assert.equal(classifyNativeAclAncestorDepth(args, effectiveDirectory), 2);
  assert.equal(classifyNativeAclAncestorDepth(args, defaultDirectory), 3);

  const probeSource = fs.readFileSync(path.join(__dirname, "../scripts/issue65-windows-snapshot-acl-probe.js"), "utf8");
  assert.match(probeSource, /snapshotDirectory = getSnapshotAclDirectory\(snapshotApi\)/);
  assert.match(probeSource, /loadSnapshotApiWithConfinedNativeErrors\(\)/);
  assert.doesNotMatch(probeSource, /loadSnapshotApiWithConfinedNativeErrors\(path\.join\(local, "Rootark", "share-snapshots"\)\)/);
});

test("#65 real Windows ACL reader uses native directory security instead of the PowerShell provider", () => {
  const source = fs.readFileSync(path.join(__dirname, "../services/fileReadHandle.js"), "utf8");
  const first = source.indexOf("function windowsDirectoryAcl(");
  const last = source.indexOf("function secureNewWindowsSnapshotDirectory(", first);
  assert.ok(first >= 0 && last > first);
  const commands = [];
  const read = vm.runInNewContext(`${source.slice(first, last)}\nwindowsDirectoryAcl`, {
    Buffer, runPowerShell: (script) => { commands.push(script); return "{}"; },
  });
  read("C:\\Users\\runner\\AppData\\Local");
  const script = commands.pop();
  assert.match(script, /\$acl = \[System\.IO\.Directory\]::GetAccessControl\(\$target\)/);
  assert.doesNotMatch(script, /Get-Acl -LiteralPath/);
});

test("#65 Windows PowerShell 5.1 retrieves owner and ACEs when its Get-Acl provider falsely misses an existing directory", {
  skip: process.platform !== "win32",
}, () => {
  const source = fs.readFileSync(path.join(__dirname, "../services/fileReadHandle.js"), "utf8");
  const first = source.indexOf("function windowsDirectoryAcl(");
  const last = source.indexOf("function secureNewWindowsSnapshotDirectory(", first);
  const commands = [];
  const read = vm.runInNewContext(`${source.slice(first, last)}\nwindowsDirectoryAcl`, {
    Buffer, runPowerShell: (script) => { commands.push(script); return "{}"; },
  });
  const target = process.env.LOCALAPPDATA;
  assert.ok(target && fs.statSync(target).isDirectory());
  read(target);
  const fakeProvider = "function Get-Acl { throw [System.Management.Automation.ItemNotFoundException]::new('simulated provider miss') }; ";
  const result = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    fakeProvider + commands.pop()], {
    encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 10000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, "native ACL reader must recover without emitting private PowerShell data");
  const acl = JSON.parse(result.stdout);
  assert.match(acl.current, /^S-1-/);
  assert.match(acl.owner, /^S-1-/);
  assert.ok(acl.rules);
  assert.equal(result.stderr, "");
});

test("#65 Windows ACL reading never depends on the PowerShell Get-Acl provider", {
  skip: process.platform !== "win32",
}, () => {
  const source = fs.readFileSync(path.join(__dirname, "../services/fileReadHandle.js"), "utf8");
  const first = source.indexOf("function windowsDirectoryAcl(");
  const last = source.indexOf("function secureNewWindowsSnapshotDirectory(", first);
  const commands = [];
  const read = vm.runInNewContext(`${source.slice(first, last)}\nwindowsDirectoryAcl`, {
    Buffer, runPowerShell: (script) => { commands.push(script); return "{}"; },
  });
  const target = process.env.LOCALAPPDATA;
  assert.ok(target && fs.statSync(target).isDirectory());
  read(target);
  const script = commands.pop();
  const result = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
    "function Get-Acl { throw 'provider unavailable' }; " + script], {
    encoding: "utf8", windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 10000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, "native Directory ACL reading must not require Get-Acl");
  assert.doesNotMatch(script, /Get-Acl -LiteralPath/);
  const acl = JSON.parse(result.stdout);
  assert.match(acl.owner, /^S-1-/);
  assert.ok(acl.rules);
  assert.equal(result.stderr, "");
});

test("#65 Windows PowerShell 5.1 maps missing Get-Acl targets to fixed ITEM_NOT_FOUND without leaking paths", {
  skip: process.platform !== "win32",
}, () => {
  const script = buildReadAclFailureScript("$ErrorActionPreference = 'Stop'; $target = Join-Path $env:TEMP ('rootark-missing-' + [Guid]::NewGuid().ToString('N')); $acl = Get-Acl -LiteralPath $target;");
  const result = spawnSync("powershell.exe", ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10000,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.status, 71);
  assert.equal(result.stdout.trim(), "ROOTARK_ISSUE65_READ_SUBSTEP=GET_ACL;ERROR=ITEM_NOT_FOUND");
  assert.equal(result.stderr, "");
  assert.doesNotMatch(result.stdout, /rootark-missing|[A-Z]:\\\\|S-1-5-/);
});

test("#65 no native substep can be claimed for an untrusted path, seal script or unknown output", () => {
  const root = "C:\\Users\\runner\\AppData\\Local\\Rootark\\share-snapshots";
  const encoded = Buffer.from("C:\\outside\\secret", "utf16le").toString("base64");
  const readScript = `$target = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('${encoded}')); $acl = Get-Acl -LiteralPath $target`;
  let invoked = 0;
  const native = () => { invoked++; throw { stdout: "ROOTARK_ISSUE65_READ_SUBSTEP=RULES\n" }; };
  assert.equal(classifyReadAclSubstep(native, "powershell.exe", ["-Command", readScript], {}, root), "OTHER");
  const sealScript = readScript.replace("Get-Acl", "Set-Acl");
  assert.equal(classifyReadAclSubstep(native, "powershell.exe", ["-Command", sealScript], {}, root), "OTHER");
  assert.equal(invoked, 0);
});

test("#65 hosted ACL native failure category is allowlisted and omits secret PowerShell details", async () => {
  const messages = [];
  const result = await runDiagnostic(steps({
    snapshot_root_acl: () => {
      throw Object.assign(new Error("Get-Acl C:\\Users\\runner\\secret.pfx S-1-5-21"), { code: "ACL_SEAL_SCRIPT_PARENT" });
    },
  }), (line) => messages.push(line));
  assert.equal(result, false);
  assert.ok(messages.includes("ROOTARK_ISSUE65_ACL_PROBE stage=snapshot_root_acl result=FAIL code=ACL_SEAL_SCRIPT_PARENT"));
  assert.doesNotMatch(messages.join("\n"), /C:\\Users|S-1-5|secret/);
});

test("#65 diagnostic is a separate exact-branch Windows job; no reduction of canonical suites", () => {
  const yaml = fs.readFileSync(path.join(__dirname, "../.github/workflows/issue65-windows-snapshot-acl-probe.yml"), "utf8");
  assert.match(yaml, /windows-2022/);
  assert.match(yaml, /cdx\/issue68-zk-recipient-w32-20261106/);
  assert.match(yaml, /node scripts\/issue65-windows-snapshot-acl-probe\.js/);
  assert.match(yaml, /npm ci/);
  assert.doesNotMatch(yaml, /continue-on-error:\s*true/);
  const canonical = fs.readFileSync(path.join(__dirname, "../.github/workflows/security-regression.yml"), "utf8");
  assert.match(canonical, /run: node scripts\/run-windows-canonical-tests\.js/);
});
