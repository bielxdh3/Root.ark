"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const z = require("../src/crypto/rootark-zk-1");
const m = require("../src/crypto/rootark-zk-recovery-manifest-v2");

function makeCompromiseTransition() {
  const oldPackageId = Buffer.alloc(16, 0x10);
  const newPackageId = Buffer.alloc(16, 0x20);
  const oldHpkeId = Buffer.alloc(16, 0x11);
  const newHpkeId = Buffer.alloc(16, 0x21);
  const oldAuthorizationId = Buffer.alloc(16, 0x12);
  const newAuthorizationId = Buffer.alloc(16, 0x22);
  const oldHpkePublicKey = Buffer.alloc(32, 0x13);
  const newHpkePublicKey = Buffer.alloc(32, 0x23);
  const oldAuthorizationPublicKey = Buffer.alloc(32, 0x14);
  const newAuthorizationPublicKey = Buffer.alloc(32, 0x24);
  const deviceId = "trusted-device";
  const previousManifest = {
    current_epoch: 2,
    epochs: [1, 2].map((epoch) => ({ epoch, key_ref: Buffer.alloc(32, epoch) })),
    devices: [{ device_id: deviceId, revoked_at_epoch: null, hpke_key_id: Buffer.alloc(16, 0x30) }],
    recovery_authority: {
      package_id: oldPackageId,
      hpke_key_id: oldHpkeId,
      hpke_public_key: oldHpkePublicKey,
      authorization_key_id: oldAuthorizationId,
      authorization_public_key: oldAuthorizationPublicKey,
      status: "active",
    },
  };
  const nextManifestCore = {
    current_epoch: 3,
    epochs: [1, 2, 3].map((epoch) => ({ epoch, key_ref: Buffer.alloc(32, epoch + 3) })),
    devices: [{ device_id: deviceId, revoked_at_epoch: null, hpke_key_id: Buffer.alloc(16, 0x30) }],
    recovery_authority: {
      package_id: newPackageId,
      hpke_key_id: newHpkeId,
      hpke_public_key: newHpkePublicKey,
      authorization_key_id: newAuthorizationId,
      authorization_public_key: newAuthorizationPublicKey,
      status: "active",
    },
    recovery_wraps: [1, 2, 3].map((epoch) => ({
      package_id: newPackageId,
      hpke_key_id: newHpkeId,
      epoch,
      key_ref: Buffer.alloc(32, epoch + 3),
      wrap_id: Buffer.alloc(16, epoch + 0x40),
      enc: Buffer.alloc(32, 0x50),
      ciphertext: Buffer.alloc(48, 0x60),
    })),
    wraps: [{
      device_id: deviceId,
      epoch: 3,
      key_ref: Buffer.alloc(32, 6),
      wrap_id: Buffer.alloc(16, 0x43),
      enc: Buffer.alloc(32, 0x51),
      ciphertext: Buffer.alloc(48, 0x61),
    }],
    operation: {
      operation_type: "compromise-package",
      compromised_package_id: oldPackageId,
    },
  };
  return {
    previousManifest,
    nextManifestCore,
    priorEpochKeys: new Map([[1, Buffer.alloc(32, 1)], [2, Buffer.alloc(32, 2)]]),
    oldPackageId,
  };
}

test("compromisePackageRequiresReplacementAndAtomicForwardRotation", () => {
  const input = makeCompromiseTransition();
  assert.equal(m.assertCompromisePackageTransition(input), true);
  assert.deepEqual(input.nextManifestCore.recovery_wraps.map((wrap) => wrap.epoch), [1, 2, 3]);
  assert.ok(input.nextManifestCore.recovery_wraps.every((wrap) => !wrap.package_id.equals(input.oldPackageId)));
  assert.equal(input.nextManifestCore.wraps.some((wrap) => wrap.epoch === 3), true);
});

test("missingEpochMaterialOrLastTrustedDeviceFailsClosed", () => {
  const missingEpoch = makeCompromiseTransition();
  missingEpoch.priorEpochKeys.delete(2);
  assert.throws(
    () => m.assertCompromisePackageTransition(missingEpoch),
    (error) => error instanceof z.RootarkZkError && error.code === "KEY_COVERAGE_INCOMPLETE",
  );

  const noDevice = makeCompromiseTransition();
  noDevice.previousManifest.devices[0].revoked_at_epoch = 2;
  noDevice.nextManifestCore.devices[0].revoked_at_epoch = 2;
  noDevice.nextManifestCore.wraps = [];
  assert.throws(
    () => m.assertCompromisePackageTransition(noDevice),
    (error) => error instanceof z.RootarkZkError && error.code === "COMPROMISE_RECOVERY_UNAVAILABLE",
  );
});
test("compromiseCannotKeepOrReceiveTheOldPackageAuthority", () => {
  const missingReplacement = makeCompromiseTransition();
  missingReplacement.nextManifestCore.recovery_authority = null;
  assert.throws(
    () => m.assertCompromisePackageTransition(missingReplacement),
    (error) => error instanceof z.RootarkZkError && error.code === "COMPROMISE_RECOVERY_UNAVAILABLE",
  );

  const oldWrap = makeCompromiseTransition();
  oldWrap.nextManifestCore.recovery_wraps[2].package_id = oldWrap.oldPackageId;
  oldWrap.nextManifestCore.recovery_wraps[2].hpke_key_id = oldWrap.previousManifest.recovery_authority.hpke_key_id;
  assert.throws(
    () => m.assertCompromisePackageTransition(oldWrap),
    (error) => error instanceof z.RootarkZkError && error.code === "COMPROMISE_RECOVERY_UNAVAILABLE",
  );
});

test("compromiseReplacementCannotReuseAnyCompromisedRecoveryKeyIdOrPublicKey", () => {
  const fields = [
    "hpke_key_id",
    "hpke_public_key",
    "authorization_key_id",
    "authorization_public_key",
  ];
  for (const field of fields) {
    const input = makeCompromiseTransition();
    input.nextManifestCore.recovery_authority[field] = Buffer.from(input.previousManifest.recovery_authority[field]);
    assert.throws(
      () => m.assertCompromisePackageTransition(input),
      (error) => error instanceof z.RootarkZkError && error.code === "COMPROMISE_RECOVERY_UNAVAILABLE",
      `accepted reuse of compromised recovery authority ${field}`,
    );
  }
});
