"use strict";

// Real Windows kernel FETCH_DATA fixture. The registered sync root and its
// entire content live under disposable TEMP paths; the production gate remains
// closed until native RootSession custody and signed authority are proven.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const { buildCompiledFixture, runCompiledFixture } =
  require("./support/issue-66-cfapi-built-artifact");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof, verifyAuthorizationProof } =
  require("../sync-client/rootark-sync-authorization");

const aclScript = path.join(__dirname, "support/issue-66-cfapi-acl-fixture.ps1");
function protectDisposableRoot(root, cwd, expose = "0") {
  const outcome = spawnSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
      "-File", aclScript, root, expose],
    { cwd, encoding: "utf8", timeout: 10000, windowsHide: true });
  assert.equal(outcome.status, 0, "disposable owner-only root ACL must be established");
}

test("#66 live Windows CFAPI kernel FETCH_DATA completes and unregisters the disposable root",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const where = spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
      ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
      { encoding: "utf8", timeout: 6000, windowsHide: true });
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 unavailable"); return; }
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-live-"));
    const root = path.join(scratch, "owner-only");
    t.after(async () => {
      await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });
    await fs.mkdir(root);
    protectDisposableRoot(root, scratch);
    const { receipt, buildResult } = buildCompiledFixture(scratch, "live-fetch.exe", vcvars);
    assert.equal(buildResult.status, 0);
    assert.throws(() => runCompiledFixture(receipt, ["--disposable-live", scratch]),
      /UNTRUSTED_EXECUTABLE/, "the test runner must reject a non-dedicated root");
    const result = runCompiledFixture(receipt, ["--disposable-live", root], 20000);
    assert.equal(result.status, 0, `CFAPI live callback failed: ${result.stdout}\n${result.stderr}`);
    const evidence = JSON.parse(result.stdout.trim());
    assert.ok(evidence.liveKernelCallbackCount >= 1);
    assert.ok(evidence.successfulTransfers >= 1);
    assert.equal(evidence.rejectedTransfers, 0);
    assert.equal(evidence.verifiedBytes, 4097,
      "native real callback must hydrate the final unaligned EOF byte");
    assert.equal(evidence.unregistered, true);
    assert.equal(evidence.finalRootIdentity, true);
    assert.equal(evidence.finalAncestorsHeld, true,
      "every ordinary NTFS ancestor remains retained during the CFAPI callback");
    assert.equal(evidence.finalRootPolicy, true);
    assert.equal(evidence.finalOwnerAcl, true);
    assert.equal(evidence.finalCloudReparse, true);
    assert.equal(evidence.positiveReadVerified, true);
  });

test("#66 signed Ed25519/AES-GCM Sync v2 bytes hydrate through a real native CFAPI kernel callback",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const where = spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
      ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
      { encoding: "utf8", timeout: 6000, windowsHide: true });
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 unavailable"); return; }
    const plaintext = Buffer.alloc(4097);
    for (let i = 0; i < plaintext.length; ++i) plaintext[i] = (i * 23 + 11) % 251;
    const owner = crypto.generateKeyPairSync("ed25519");
    const publicKey = owner.publicKey.export({ format: "der", type: "spki" }).toString("base64url");
    const fileKey = crypto.randomBytes(32);
    const op = protocol.createOperation({
      operation: "create", objectId: "cfapi-signed-native", fileId: "cfapi-signed-file",
      versionId: crypto.randomUUID(), operationId: crypto.randomUUID(),
      deviceId: "device-1", keyEpoch: "epoch-1", compartmentId: "private",
      revision: { counter: 1, deviceId: "device-1" },
      metadata: { path: "docs/native.bin", size: plaintext.length },
      plaintext, fileKey,
    });
    op.authorization = await createAuthorizationProof(op, {
      username: "alice", publicKey, privateKey: owner.privateKey,
      expiresAt: Date.now() + 60_000,
    });
    const trusted = { username: "alice",
      trustedDevicePublicKeys: { "device-1": publicKey }, revokedDeviceIds: [] };
    assert.equal(await verifyAuthorizationProof(op.authorization, op, trusted), true);
    const revoked = { ...trusted, revokedDeviceIds: ["device-1"] };
    await assert.rejects(verifyAuthorizationProof(op.authorization, op, revoked),
      { code: "authorization_device_revoked" },
      "revoked device proof cannot become native materialization authority");
    assert.throws(() => protocol.decryptPayload(op, crypto.randomBytes(32)),
      "wrong AEAD key must fail before starting the native provider");
    const decrypted = protocol.decryptPayload(op, fileKey);
    assert.deepEqual(decrypted, plaintext, "native source is exact authenticated AEAD plaintext");

    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-live-"));
    const root = path.join(scratch, "owner-only");
    t.after(async () => {
      decrypted.fill(0);
      fileKey.fill(0);
      plaintext.fill(0);
      await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });
    await fs.mkdir(root);
    protectDisposableRoot(root, scratch);
    const { receipt } = buildCompiledFixture(scratch, "live-fetch.exe", vcvars);
    assert.throws(() => runCompiledFixture(receipt, ["--disposable-live-stdin", root]),
      /UNTRUSTED_EXECUTABLE/, "native stdin mode requires a bounded binary buffer");
    const result = runCompiledFixture(receipt, ["--disposable-live-stdin", root], 20000, decrypted);
    assert.equal(result.status, 0, `signed live hydration failed: ${result.stdout}\n${result.stderr}`);
    const evidence = JSON.parse(result.stdout.trim());
    assert.equal(evidence.positiveReadVerified, true);
    assert.equal(evidence.verifiedBytes, plaintext.length);
    assert.ok(evidence.liveKernelCallbackCount >= 1);
    assert.ok(evidence.successfulTransfers >= 1);
    assert.equal(evidence.rejectedTransfers, 0);
    assert.equal(evidence.unregistered, true);
    assert.equal(evidence.finalRootIdentity, true);
    assert.equal(evidence.finalAncestorsHeld, true);
    assert.equal(evidence.finalRootPolicy, true);
    assert.equal(evidence.finalCloudReparse, true);
  });

test("#66 native CFAPI registration rejects a broad DACL before creating any placeholder",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const where = spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
      ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
      { encoding: "utf8", timeout: 6000, windowsHide: true });
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 unavailable"); return; }
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-live-"));
    const root = path.join(scratch, "owner-only");
    t.after(async () => {
      await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });
    await fs.mkdir(root);
    protectDisposableRoot(root, scratch, "1");
    const { receipt } = buildCompiledFixture(scratch, "live-fetch.exe", vcvars);
    const result = runCompiledFixture(receipt, ["--disposable-live", root], 10000);
    assert.equal(result.status, 14,
      "broad ACL must fail the held-root preflight before any native registration");
    assert.deepEqual(await fs.readdir(root), [], "denied root remains unmodified");
  });

test("#66 real CFAPI callback refuses second physical placeholder with copied FileIdentity",
  { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
    const where = spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
      ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
      { encoding: "utf8", timeout: 6000, windowsHide: true });
    const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
    if (!vcvars) { t.skip("MSVC x64 unavailable"); return; }
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-live-"));
    const root = path.join(scratch, "owner-only");
    t.after(async () => {
      await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      await fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    });
    await fs.mkdir(root);
    protectDisposableRoot(root, scratch);
    const { receipt } = buildCompiledFixture(scratch, "live-fetch.exe", vcvars);
    const result = runCompiledFixture(receipt, ["--disposable-live-alias", root], 20000);
    assert.equal(result.status, 0,
      `copied-identity native callback must reject foreign inode: ${result.stdout}\n${result.stderr}`);
    const evidence = JSON.parse(result.stdout.trim());
    assert.equal(evidence.positiveReadVerified, true);
    assert.equal(evidence.alienAliasDenied, true);
    assert.ok(evidence.rejectedTransfers >= 1);
    assert.ok(evidence.successfulTransfers >= 1,
      "genuine original placeholder must still hydrate successfully");
    assert.equal(evidence.unregistered, true);
  });

for (const length of [1, 65537]) {
  test(`#66 native kernel CFAPI hydrates ${length} binary bytes across aligned EOF ranges`,
    { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
      const where = spawnSync("C:\\Program Files (x86)\\Microsoft Visual Studio\\Installer\\vswhere.exe",
        ["-all", "-products", "*", "-prerelease", "-find", "VC\\Auxiliary\\Build\\vcvars64.bat"],
        { encoding: "utf8", timeout: 6000, windowsHide: true });
      const vcvars = where.status === 0 ? where.stdout.trim().split(/\r?\n/).find(Boolean) : null;
      if (!vcvars) { t.skip("MSVC x64 unavailable"); return; }
      const scratch = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-cfapi-live-"));
      const root = path.join(scratch, "owner-only");
      t.after(async () => {
        await fs.rm(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
        await fs.rm(scratch, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      });
      await fs.mkdir(root);
      protectDisposableRoot(root, scratch);
      const { receipt } = buildCompiledFixture(scratch, "live-fetch.exe", vcvars);
      const bytes = Buffer.alloc(length);
      for (let i = 0; i < bytes.length; ++i) bytes[i] = (i * 29 + 3) % 251;
      const outcome = runCompiledFixture(receipt, ["--disposable-live-stdin", root],
        25000, bytes);
      bytes.fill(0);
      assert.equal(outcome.status, 0,
        `native short EOF/multirange physical hydration: ${outcome.stdout}\n${outcome.stderr}`);
      const evidence = JSON.parse(outcome.stdout.trim());
      assert.equal(evidence.positiveReadVerified, true);
      assert.equal(evidence.verifiedBytes, length);
      assert.ok(evidence.liveKernelCallbackCount >= 1);
      assert.ok(evidence.successfulTransfers >= 1);
      assert.equal(evidence.rejectedTransfers, 0);
      assert.equal(evidence.finalRootIdentity, true);
      assert.equal(evidence.finalAncestorsHeld, true);
      assert.equal(evidence.finalRootPolicy, true);
      assert.equal(evidence.unregistered, true);
    });
}
