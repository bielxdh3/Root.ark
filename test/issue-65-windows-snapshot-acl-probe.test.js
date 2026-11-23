"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { runDiagnostic, runIsolatedDiagnostic } = require("../scripts/issue65-windows-snapshot-acl-probe");

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
