"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const z = require("../src/crypto/rootark-zk-1");
const { makeDualClientRecoveryLab } = require("./support/issue-65-dual-client-recovery-lab");

test("same opaque encrypted file opens via independent user-held emergency package and previously trusted device", async () => {
  const f = await makeDualClientRecoveryLab();
  const fromPackage = await f.openViaPackage(f.password);
  const fromDevice = await f.openViaTrustedDevice();
  assert.deepEqual(Buffer.from(fromPackage.data), f.plaintext);
  assert.deepEqual(Buffer.from(fromDevice.data), f.plaintext);
  assert.equal(fromPackage.name, "offline-private.txt");
  assert.equal(fromDevice.name, fromPackage.name);
  assert.equal(fromPackage.mediaType, "text/plain");
  assert.equal(f.fileCek.extractable, false);
  assert.equal(f.manifestAuthorityVerified, true);
  assert.equal(f.packageHistoryVerified, true);
  assert.equal(f.targetPopVerified, true, "replacement decrypts HPKE challenge and signs PoP");
  assert.equal(f.serverProjectionHasSecrets, false);
  assert.equal(f.authorizesRelease, false,
    "client round trips cannot substitute for fresh CAS/witness or an approved device keychain");
  fromPackage.data.fill(0);
  fromDevice.data.fill(0);
});

test("emergency package: wrong password, tampered ciphertext, wrong scope, lost device and opaque service fail closed", async () => {
  const f = await makeDualClientRecoveryLab();
  await assert.rejects(f.openViaPackage("incorrect-secret"), /AUTHENTICATION_FAILED|INVALID_RECOVERY_PACKAGE/);
  const envelope = await z.decodeDeterministic(f.packageBytes);
  envelope.ciphertext = Buffer.from(envelope.ciphertext);
  envelope.ciphertext[0] ^= 0xff;
  await assert.rejects(f.openViaPackage(f.password, { packageBytes: await z.encodeDeterministic(envelope) }),
    /AUTHENTICATION_FAILED|INVALID_RECOVERY_PACKAGE/);
  await assert.rejects(f.openViaPackage(f.password, {
    expectedScope: { ...f.scope, keyring_id: crypto.randomBytes(16) },
  }), /INVALID_RECOVERY_PACKAGE|SCOPE_MISMATCH/);
  await assert.rejects(f.openViaTrustedDevice({ lostDevice: true }), /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaPackage(f.password, { noTrustedWitness: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  assert.equal(f.serverProjectionHasSecrets, false);
});

test("revoked trusted device, replay, mismatched signed head and pending CAS/witness block candidate admission", async () => {
  const f = await makeDualClientRecoveryLab();
  const changed = await f.revokeTrustedDevice();
  assert.equal(changed.revokedEpoch, 2);
  assert.equal(changed.packageStillActive, true);
  assert.equal(changed.authorizesRelease, false);
  await assert.rejects(f.openViaTrustedDevice(),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  const oldBytes = await f.openViaPackage(f.password);
  assert.deepEqual(Buffer.from(oldBytes.data), f.plaintext,
    "user-held package may recover old epoch, not retroactively erase held ciphertext");
  oldBytes.data.fill(0);
  await assert.rejects(f.openViaTrustedDevice({ replayedRequest: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaPackage(f.password, { currentManifestDigest: crypto.randomBytes(32) }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaPackage(f.password, { pendingReservation: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaTrustedDevice({ pendingReservation: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaPackage(f.password, { staleHead: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
});

test("both paths bind key epoch, version, scope, root and authenticated content metadata", async () => {
  const f = await makeDualClientRecoveryLab();
  await assert.rejects(f.openViaPackage(f.password, { wrongEpoch: true }),
    /AUTHENTICATION_FAILED|ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaTrustedDevice({ wrongEpoch: true }),
    /AUTHENTICATION_FAILED|ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaPackage(f.password, { tamperedFile: true }),
    /ZK_FILE_INVALID|AUTHENTICATION_FAILED/);
  await assert.rejects(f.openViaTrustedDevice({ wrongVersion: true }),
    /ZK_FILE_INVALID|AUTHENTICATION_FAILED/);
  await assert.rejects(f.openViaPackage(f.password, { wrongRoot: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
  await assert.rejects(f.openViaTrustedDevice({ wrongRoot: true }),
    /ZK_DUAL_CLIENT_RECOVERY_UNAVAILABLE/);
});
