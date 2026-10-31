"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("backup fixture refuses a real foreign-UID replaceable TEMP parent before reading", (t) => {
  if (process.platform === "win32" || process.getuid?.() !== 0) {
    t.skip("requires POSIX root to run real separate unprivileged UIDs");
    return;
  }
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-w141-uid-boundary-"));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  fs.chmodSync(scratch, 0o755);
  const hostileTemp = path.join(scratch, "nonsticky-world-writable-temp");
  fs.mkdirSync(hostileTemp, { mode: 0o777 });
  fs.chmodSync(hostileTemp, 0o777);
  const fixture = path.join(hostileTemp, "rootark-zk-backup-fixture-otheruid");
  fs.mkdirSync(fixture, { mode: 0o700 });
  for (const folder of ["versions", "copies", "envelopes"]) {
    fs.mkdirSync(path.join(fixture, folder));
    fs.chownSync(path.join(fixture, folder), 62001, 62001);
  }
  for (const [name, data] of [
    [".rootark-disposable-fixture", "rootark-zk-backup-fixture-v1\n"],
    ["manifest.json", "{}"], ["backup-index.json", "{}"],
    ["owner-authorization.json", "{}"],
  ]) {
    const file = path.join(fixture, name);
    fs.writeFileSync(file, data);
    fs.chownSync(file, 62001, 62001);
  }
  fs.chownSync(fixture, 62001, 62001);

  const runAs = (uid, script) => spawnSync("setpriv", [
    `--reuid=${uid}`, `--regid=${uid}`, "--clear-groups", process.execPath,
    "-e", script, fixture,
  ], { cwd: path.resolve(__dirname, ".."), encoding: "utf8",
    env: { ...process.env, TMPDIR: hostileTemp, TMP: hostileTemp } });

  // Different physical UID can move the private 0700 fixture through its
  // unsafe writable parent without knowing the victim's owner credentials.
  const attacker = runAs(62002, `
    const fs=require('node:fs');const p=process.argv[1];
    fs.renameSync(p,p+'.foreign-moved');fs.renameSync(p+'.foreign-moved',p);
  `);
  assert.equal(attacker.status, 0, `foreign UID must really control the pathname: ${attacker.stderr}`);

  const victim = runAs(62001, `
    const fs=require('node:fs');const path=require('node:path');
    const original=fs.openSync;let opened=false;
    fs.openSync=function(filename,...args){
      if(path.basename(String(filename))==='.rootark-disposable-fixture')opened=true;
      return original.call(fs,filename,...args);
    };
    const {inspectZk1DisposableBackupPreRestore}=require('./src/services/zk1DisposableBackupPreRestore');
    const report=inspectZk1DisposableBackupPreRestore({fixtureDir:process.argv[1],
      expectedCompartmentId:'compartment1',checkpoint:{epoch:0,revision:0}});
    process.stdout.write(JSON.stringify({opened,findings:report.findings}));
  `);
  assert.equal(victim.status, 0, `victim should fail closed through normal API: ${victim.stderr}`);
  const outcome = JSON.parse(victim.stdout);
  assert.equal(outcome.opened, false,
    "an untrusted foreign-UID-replaceable fixture must be rejected before reading its first file");
  assert.ok(outcome.findings.includes("UNSAFE_FIXTURE"));
});
