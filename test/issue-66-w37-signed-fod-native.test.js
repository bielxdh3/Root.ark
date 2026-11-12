"use strict";

// Physical NTFS positive signed Sync v2 file-on-demand candidate. Real
// Ed25519/AES-GCM; no registered CFAPI callback or trusted RootSession.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const protocol = require("../sync-client/rootark-sync-protocol");
const { createAuthorizationProof } = require("../sync-client/rootark-sync-authorization");
const { materializeSelectedLab } = require(
  "../experiments/issue66-w37-signed-fod-native/bridge.lab.cjs");

const available = process.platform === "win32"
  && process.env.ROOTARK_ISSUE66_W37_FOD_LAB === "1";

async function signedFixture(plaintext) {
  const owner = crypto.generateKeyPairSync("ed25519");
  const spki = owner.publicKey.export({ format: "der", type: "spki" })
    .toString("base64url");
  const fileKey = crypto.randomBytes(32);
  const operation = protocol.createOperation({
    operation: "create", objectId: "object-real-fod", fileId: "file-real-fod",
    versionId: "version-real-fod", deviceId: "device_1",
    compartmentId: "vault", keyEpoch: "epoch-1",
    revision: { counter: 1, deviceId: "device_1" },
    metadata: { path: "docs/fod.bin", size: plaintext.length, name: "fod.bin" },
    plaintext, fileKey,
  });
  operation.authorization = await createAuthorizationProof(operation, {
    username: "alice", publicKey: spki, privateKey: owner.privateKey,
    expiresAt: Date.now() + 60000,
  });
  return { operation, fileKey, selectedPath: "docs/fod.bin",
    localTrustedDevicePolicy: { username: "alice",
      trustedDevicePublicKeys: { device_1: spki }, revokedDeviceIds: [] } };
}

for (const size of [1, 4097]) {
  test(`#66 W37 physical signed FOD: genuine Ed25519/AES-GCM ${size} byte original HANDLE is published no-replace`,
    { skip: !available, timeout: 30000 }, async () => {
      const bytes = Buffer.alloc(size);
      for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 19 + 7) % 251;
      const f = await signedFixture(bytes);
      const outcome = await materializeSelectedLab({ signedOperation: f.operation,
        fileKey: f.fileKey, selectedPath: f.selectedPath,
        localTrustedDevicePolicy: f.localTrustedDevicePolicy });
      assert.equal(outcome.status, "native_bytes_published");
      assert.equal(outcome.length, size);
      assert.equal(outcome.sha256, crypto.createHash("sha256").update(bytes).digest("hex"));
      assert.equal(outcome.authorizesIo, false);
      assert.equal(outcome.cfapiRegistered, false);
      assert.equal(outcome.independentRootCustody, false);
      const root = path.join(outcome.scratch, "held");
      const opened = fs.openSync(path.join(root, "published.bin"), "r");
      try {
        const identity = fs.fstatSync(opened, { bigint: true });
        assert.equal(identity.isFile(), true);
        assert.equal(identity.size, BigInt(size));
        assert.equal(identity.nlink, 1n, "native rename leaves one visible link");
        assert.deepEqual(fs.readFileSync(opened), bytes,
          "exact A plaintext reaches original opened NTFS inode");
        assert.equal(fs.fstatSync(opened, { bigint: true }).ino, identity.ino);
      } finally { fs.closeSync(opened); }
      assert.equal(fs.existsSync(path.join(root, "stage.bin")), false);
    });
}

test("#66 W37 physical signed FOD: later foreign NTFS destination is not replaced",
  { skip: !available, timeout: 30000 }, async () => {
    const bytes = Buffer.alloc(4097, 0xa5);
    const f = await signedFixture(bytes);
    const result = await materializeSelectedLab({ signedOperation: f.operation,
      fileKey: f.fileKey, selectedPath: f.selectedPath,
      localTrustedDevicePolicy: f.localTrustedDevicePolicy, collision: true });
    assert.equal(result.status, "collision_preserved");
    assert.equal(result.authorizesIo, false);
    const held = path.join(result.scratch, "held");
    assert.equal(fs.readFileSync(path.join(held, "published.bin"), "utf8"),
      "FOREIGN_UNTRUSTED_TARGET_BYTES");
    assert.deepEqual(fs.readFileSync(path.join(held, "stage.bin")), bytes,
      "native colliding publish retains original staged ciphertext-decrypted bytes");
    assert.notEqual(fs.statSync(path.join(held, "stage.bin"), { bigint: true }).ino,
      fs.statSync(path.join(held, "published.bin"), { bigint: true }).ino);
  });

test("#66 W37 signed FOD: forged B, revoked pin, wrong key and unselected path never reach the native writer",
  { skip: !available }, async () => {
    const f = await signedFixture(Buffer.from("authentic selected user bytes"));
    const selected = { signedOperation: f.operation, fileKey: f.fileKey,
      selectedPath: f.selectedPath, localTrustedDevicePolicy: f.localTrustedDevicePolicy };
    await assert.rejects(materializeSelectedLab({ ...selected, selectedPath: "other/fod.bin" }),
      { code: "fod_lab_not_selected" });
    await assert.rejects(materializeSelectedLab({ ...selected,
      signedOperation: { ...f.operation, metadata: {
        ...f.operation.metadata, path: "other/fod.bin" } },
      selectedPath: "other/fod.bin" }),
    { code: "fod_lab_signature_denied" });
    await assert.rejects(materializeSelectedLab({ ...selected,
      localTrustedDevicePolicy: { ...f.localTrustedDevicePolicy,
        revokedDeviceIds: ["device_1"] } }),
    { code: "fod_lab_signature_denied" });
    await assert.rejects(materializeSelectedLab({ ...selected,
      fileKey: crypto.randomBytes(32) }), { code: "fod_lab_aead_denied" });
    await assert.rejects(materializeSelectedLab({ ...selected,
      signedOperation: { ...f.operation, ciphertext: "AA" } }),
    { code: "fod_lab_signature_denied" });
  });

test("#66 W37 contract: no JS RootSession or CFAPI gate is opened by a positive lab",
  { skip: !available }, () => {
    const { openNativeRootSession } =
      require("../sync-client/rootark-sync-native-root-session-contract");
    assert.throws(() => openNativeRootSession(true),
      { code: "root_session_native_unavailable" });
  });

test("#66 W37 physical native boundary rejects wrong digest and >8192 byte stdin before creating held",
  { skip: !available, timeout: 30000 }, () => {
    const ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    const source = path.join(__dirname, "support",
      "issue-66-w26-native-file-publish-lab.ps1");
    const local = process.env.LOCALAPPDATA;
    for (const [payload, digest] of [
      [Buffer.from("A"), "0".repeat(64)],
      [Buffer.alloc(8193, 0xa5), crypto.createHash("sha256")
        .update(Buffer.alloc(8193, 0xa5)).digest("hex")],
    ]) {
      const scratch = fs.mkdtempSync(path.join(local, "rootark-w26-native-publish-w37-"));
      const native = spawnSync(ps, ["-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-File", source, "-Scratch", scratch,
        "-Mode", "FOD_POSITIVE", "-PayloadSha256", digest], {
        env: { ...process.env, ROOTARK_ISSUE66_W26_NATIVE_PUBLISH_LAB: "1",
          ROOTARK_ISSUE66_W37_FOD_LAB: "1" },
        input: payload, encoding: "utf8", windowsHide: true,
        timeout: 25000, maxBuffer: 8192,
      });
      assert.equal(native.status, 41, "unverified bytes must fail in native child");
      assert.equal(native.stdout, "");
      assert.match(native.stderr, /^ROOTARK_W26_HANDLE_PUBLISH_REJECTED\r?\n$/);
      assert.deepEqual(fs.readdirSync(scratch), [],
        "no native-held directory or staging occurs on invalid bytes");
    }
  });
