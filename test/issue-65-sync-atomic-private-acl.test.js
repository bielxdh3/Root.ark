"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncObjectStore } = require("../src/routes/sync");
const { ensureWindowsChunkUploadRoot, verifyWindowsChunkUploadTree } =
  require("../services/chunkUploadWindowsAcl");
const { createAclFailureDiagnostic } =
  require("../scripts/acl-test-failure-diagnostic");

const UNSAFE = { code: "SYNC_ATOMIC_REGISTRY_STORAGE_UNSAFE" };
const TRUSTED_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
const TRUSTED_ICACLS = "C:\\Windows\\System32\\icacls.exe";
function assertUntrustedModifyPersisted(target) {
  const literal = "'" + target.replace(/'/g, "''") + "'";
  const verify = spawnSync(TRUSTED_POWERSHELL, ["-NoProfile", "-NonInteractive",
    "-Command", "$ErrorActionPreference='Stop';$p=" + literal + ";"
      + "$r=New-Object Security.AccessControl.RawSecurityDescriptor((Get-Acl -LiteralPath $p).GetSecurityDescriptorBinaryForm(),0);"
      + "$found=$false;foreach($a in $r.DiscretionaryAcl){"
      + "if($a.SecurityIdentifier.Value -eq 'S-1-5-11' -and"
      + " (($a.AccessMask -band 327682) -ne 0)){$found=$true}};"
      + "if(-not $found){exit 3};Write-Output 'UNTRUSTED_MODIFY_VERIFIED';"],
    { encoding: "utf8", windowsHide: true, timeout: 12000 });
  assert.equal(verify.status, 0, "disposable NTFS fixture must retain a real untrusted destructive ACE");
  assert.match(verify.stdout || "", /UNTRUSTED_MODIFY_VERIFIED/);
}
function ownedPrivateRoot(t) {
  let dir;
  if (process.platform === "win32") {
    dir = path.join(process.env.LOCALAPPDATA,
      `rootark-atomic-private-${crypto.randomBytes(9).toString("hex")}`);
    assert.equal(fs.existsSync(dir), false);
    ensureWindowsChunkUploadRoot(dir);
  } else {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-atomic-private-"));
  }
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function weakenRegistryFile(file) {
  if (process.platform === "win32") {
    // Native icacls applies the hostile ACE to the actual disposable inode.
    // Set-Acl may refuse to persist or normalize this ACE on hosted NTFS;
    // a synthetic test-only Boolean would not exercise the real guard.
    const folder = fs.statSync(file).isDirectory();
    const grant = spawnSync(TRUSTED_ICACLS,
      [file, "/grant", folder ? "*S-1-5-11:(OI)(CI)M" : "*S-1-5-11:M"],
      { encoding: "utf8", windowsHide: true, timeout: 12000 });
    assert.equal(grant.status, 0, "disposable NTFS fixture must accept the hostile ACE");
    assertUntrustedModifyPersisted(file);
  } else {
    fs.chmodSync(file, 0o666);
  }
}

function revokeUntrustedRegistryFileGrant(file) {
  if (process.platform === "win32") {
    const remove = spawnSync(TRUSTED_ICACLS, [file, "/remove:g", "*S-1-5-11"],
      { encoding: "utf8", windowsHide: true, timeout: 12000 });
    assert.equal(remove.status, 0, "disposable NTFS fixture must remove the hostile ACE");
  } else {
    fs.chmodSync(file, 0o600);
  }
}

test("strict atomic registry rejects unsafe inherited or explicit ACL/mode without mutating it", async (t) => {
  const diag = createAclFailureDiagnostic(t, "ATOMIC_INHERIT");
  return diag.run(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-atomic-unsafe-"));
  diag.stage("ROOT_CREATED");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  if (process.platform === "win32") {
    diag.stage("INHERIT_CHECK");
    const literal = "'" + dir.replace(/'/g, "''") + "'";
    let acl = "";
    try {
      acl = execFileSync(TRUSTED_POWERSHELL, ["-NoProfile", "-NonInteractive",
        "-Command", "(Get-Acl -LiteralPath " + literal + ").AreAccessRulesProtected"],
      { encoding: "utf8", windowsHide: true, timeout: 12000 });
    } catch (_) {
      // Probe failure must not be mistaken for a safe inherited directory;
      // materialize and read back a real explicit hostile ACL instead.
    }
    if (/False/i.test(acl)) diag.trust("INHERITED");
    else {
      // The hosted runner can supply an already protected TEMP root. Build a
      // real hostile DACL rather than asserting that ambient inheritance is
      // always enabled or weakening the runtime's private-ACL requirement.
      weakenRegistryFile(dir);
      diag.trust("UNTRUSTED_ADDED");
    }
  } else {
    fs.chmodSync(dir, 0o777);
  }
  const storePath = path.join(dir, "objects.json");
  diag.stage("ROOT_OPEN");
  await assert.rejects(new SyncObjectStore(storePath, { atomicDeviceRegistry: true }).open(), UNSAFE);
  diag.trust("REJECTED");
  diag.stage("NO_FILES");
  assert.equal(fs.existsSync(storePath), false, "unsafe root must not create registry or lock");
  assert.equal(fs.existsSync(storePath + ".writer-lock"), false);
  });
});

test("strict atomic registry permits private owner-only root, fences existing store, lock and temporary file", async (t) => {
  const dir = ownedPrivateRoot(t);
  const file = path.join(dir, "objects.json");
  const store = await new SyncObjectStore(file, { atomicDeviceRegistry: true }).open();
  assert.equal(store.atomicRegistryEpoch(), 0);
  await store.withWriteLock(async () => {
    assert.equal(fs.existsSync(file + ".writer-lock"), true);
    if (process.platform === "win32") verifyWindowsChunkUploadTree(dir);
  });
  const pair = crypto.generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
  assert.deepEqual(await store.enrollDevice({ username: "alice", deviceId: "device1",
    publicKey, expectedEpoch: 0 }), { epoch: 1 });
  const restarted = await new SyncObjectStore(file, { atomicDeviceRegistry: true }).open();
  assert.equal(restarted.atomicRegistryEpoch(), 1);
  if (process.platform === "win32") verifyWindowsChunkUploadTree(dir);
});

test("strict atomic registry refuses a later untrusted file permission change", async (t) => {
  const diag = createAclFailureDiagnostic(t, "ATOMIC_MUTATION");
  return diag.run(async () => {
  const dir = ownedPrivateRoot(t);
  diag.stage("PRIVATE_ROOT");
  const file = path.join(dir, "objects.json");
  await new SyncObjectStore(file, { atomicDeviceRegistry: true }).open();
  diag.stage("REGISTRY_OPEN");
  diag.stage("ACL_WRITE");
  weakenRegistryFile(file);
  diag.trust("UNTRUSTED_ADDED");
  diag.stage("REOPEN_CHECK");
  await assert.rejects(new SyncObjectStore(file, { atomicDeviceRegistry: true }).open(), UNSAFE);
  diag.trust("REJECTED");
  diag.stage("ACL_REVOKE");
  revokeUntrustedRegistryFileGrant(file);
  diag.stage("TRUSTED_REOPEN");
  await new SyncObjectStore(file, { atomicDeviceRegistry: true }).open();
  diag.trust("PROTECTED");
  });
});

test("a newly unsafe ACL after rename quarantines the lock instead of allowing a retry", async (t) => {
  const diag = createAclFailureDiagnostic(t, "ATOMIC_RENAME");
  return diag.run(async () => {
  const dir = ownedPrivateRoot(t);
  diag.stage("PRIVATE_ROOT");
  const file = path.join(dir, "objects.json");
  const store = await new SyncObjectStore(file, { atomicDeviceRegistry: true }).open();
  diag.stage("REGISTRY_OPEN");
  const originalRename = fsp.rename;
  t.after(() => { fsp.rename = originalRename; });
  let changed = 0;
  fsp.rename = async (...args) => {
    await originalRename(...args);
    if (args[1] === file) {
      changed += 1;
      diag.stage("RENAME_HOOK");
      weakenRegistryFile(file);
      diag.trust("UNTRUSTED_ADDED");
    }
  };
  const key = crypto.generateKeyPairSync("ed25519").publicKey.export({
    format: "der", type: "spki" }).toString("base64url");
  try {
    diag.stage("ENROLL_CHECK");
    await assert.rejects(store.enrollDevice({ username: "alice", deviceId: "device1",
      publicKey: key, expectedEpoch: 0 }), UNSAFE);
    diag.trust("REJECTED");
    diag.stage("FENCING_ASSERT");
    assert.equal(changed, 1, "ACL changed only after the actual JSON replacement");
    assert.equal(store.commitIndeterminate, true, "post-rename failure quarantines the store");
    assert.equal(fs.existsSync(file + ".writer-lock"), true, "durable writer lock is retained");
  } finally {
    fsp.rename = originalRename;
  }
  });
});
