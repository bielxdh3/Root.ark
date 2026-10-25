"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { execFileSync } = require("node:child_process");
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
    const literal = "'" + file.replace(/'/g, "''") + "'";
    const command = `$p=${literal}; $a=Get-Acl -LiteralPath $p; $sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11'); $r=New-Object System.Security.AccessControl.FileSystemAccessRule($sid,'Modify','Allow'); $a.AddAccessRule($r); Set-Acl -LiteralPath $p -AclObject $a`;
    execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive",
      "-Command", command], { windowsHide: true });
  } else {
    fs.chmodSync(file, 0o666);
  }
}

test("strict atomic registry rejects insecure default inherited ACL/mode without mutating it", async (t) => {
  const diag = createAclFailureDiagnostic(t, "ATOMIC_INHERIT");
  return diag.run(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-atomic-unsafe-"));
  diag.stage("ROOT_CREATED");
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  if (process.platform === "win32") {
    diag.stage("INHERIT_CHECK");
    const literal = "'" + dir.replace(/'/g, "''") + "'";
    const acl = execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive",
      "-Command", "(Get-Acl -LiteralPath " + literal + ").AreAccessRulesProtected"],
    { encoding: "utf8", windowsHide: true });
    diag.trust(/False/i.test(acl) ? "INHERITED" : "PROTECTED");
    assert.match(acl, /False/i, "real inherited NTFS DACL must be detected");
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
