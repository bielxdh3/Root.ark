"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const z = require("../src/crypto/rootark-zk-1");
const h = require("../src/crypto/rootark-zk-recovery-history-v2");

test("warnsAt75PercentAndRejectsOnlyFirstOverLimitAppend", () => {
  const warningByCount = h.checkRecoveryHistoryCapacity({
    transitionCount: 3071,
    historyBytes: 0,
    nextEntryBytes: 1,
  });
  assert.equal(warningByCount.warning, true);
  assert.equal(warningByCount.usedTransitions, 3072);

  const warningByBytes = h.checkRecoveryHistoryCapacity({
    transitionCount: 1,
    historyBytes: 48 * 1024 * 1024 - 1,
    nextEntryBytes: 1,
  });
  assert.equal(warningByBytes.warning, true);

  const atEntryLimit = h.checkRecoveryHistoryCapacity({
    transitionCount: 0,
    historyBytes: 0,
    nextEntryBytes: 8 * 1024 * 1024,
  });
  assert.equal(atEntryLimit.maxEntryBytes, 8 * 1024 * 1024);
  assert.throws(
    () => h.checkRecoveryHistoryCapacity({ transitionCount: 0, historyBytes: 0, nextEntryBytes: 8 * 1024 * 1024 + 1 }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_CAPACITY_REACHED",
  );
  assert.throws(
    () => h.checkRecoveryHistoryCapacity({ transitionCount: 4096, historyBytes: 0, nextEntryBytes: 1 }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_CAPACITY_REACHED",
  );
  assert.throws(
    () => h.checkRecoveryHistoryCapacity({ transitionCount: 1, historyBytes: 64 * 1024 * 1024, nextEntryBytes: 1 }),
    (error) => error instanceof z.RootarkZkError && error.code === "HISTORY_CAPACITY_REACHED",
  );
  assert.equal(h.checkRecoveryHistoryCapacity({
    transitionCount: 4095,
    historyBytes: 64 * 1024 * 1024 - 1,
    nextEntryBytes: 1,
  }).usedTransitions, 4096);
  assert.equal(h.checkRecoveryHistoryCapacity({
    transitionCount: 1,
    historyBytes: 64 * 1024 * 1024 - 1,
    nextEntryBytes: 1,
  }).usedBytes, 64 * 1024 * 1024);
});

test("measuresTheSerializedMaximumDeviceAndEpochManifest", async (t) => {
  const id = (value) => {
    const bytes = Buffer.alloc(16);
    bytes.writeUInt32BE(value, 12);
    return bytes;
  };
  const epochs = Array.from({ length: 64 }, (_, index) => ({ epoch: index + 1, key_ref: Buffer.alloc(32, index + 1) }));
  const devices = Array.from({ length: 256 }, (_, index) => ({
    device_id: `device-${index.toString().padStart(3, "0")}`,
    hpke_key_id: id(1000 + index * 2),
    hpke_public_key: Buffer.alloc(32, index & 0xff),
    authorization_key_id: id(1001 + index * 2),
    authorization_public_key: Buffer.alloc(32, (index + 1) & 0xff),
    enrolled_epoch: 1,
    revoked_at_epoch: null,
  }));
  let wrapNumber = 10_000;
  const wraps = [];
  for (const device of devices) {
    for (const epoch of epochs) {
      wraps.push({
        device_id: device.device_id,
        epoch: epoch.epoch,
        key_ref: epoch.key_ref,
        wrap_id: id(wrapNumber++),
        enc: Buffer.alloc(32, 1),
        ciphertext: Buffer.alloc(48, 2),
      });
    }
  }
  const recoveryAuthority = {
    package_id: id(1),
    hpke_key_id: id(2),
    hpke_public_key: Buffer.alloc(32, 3),
    authorization_key_id: id(4),
    authorization_public_key: Buffer.alloc(32, 5),
    status: "active",
    activation_revision: 2,
    previous_revision: 1,
    previous_manifest_digest: Buffer.alloc(32, 6),
    operation_id: id(7),
    activation_context_digest: Buffer.alloc(32, 8),
    package_envelope_digest: Buffer.alloc(32, 9),
  };
  const recoveryWraps = epochs.map((epoch) => ({
    package_id: recoveryAuthority.package_id,
    hpke_key_id: recoveryAuthority.hpke_key_id,
    epoch: epoch.epoch,
    key_ref: epoch.key_ref,
    wrap_id: id(wrapNumber++),
    enc: Buffer.alloc(32, 10),
    ciphertext: Buffer.alloc(48, 11),
  }));
  const manifest = {
    type: "rootark-zk-keyring-manifest",
    version: 2,
    suite: "rootark-zk-1",
    account_id: Buffer.alloc(16, 1),
    compartment_id: Buffer.from("maximum-capacity-test"),
    keyring_id: Buffer.alloc(16, 2),
    revision: 4096,
    current_epoch: 64,
    epochs,
    devices,
    wraps,
    recovery_authority: recoveryAuthority,
    recovery_wraps: recoveryWraps,
    previous_manifest_digest: Buffer.alloc(32, 12),
    operation: {
      operation_id: id(13), operation_type: "revoke-device", actor_type: "device",
      actor_key_id: devices[0].authorization_key_id, target_device_id: devices[255].device_id,
      target_device_key_digest: null, compromised_package_id: null, recovery_policy_change: null,
      target_epoch_coverage: [], target_pop_proof: null, issued_at: 1, expires_at: 301,
      request_digest: Buffer.alloc(32, 14),
    },
    mac: Buffer.alloc(32, 15),
    actor_signature: Buffer.alloc(64, 16),
  };
  const serialized = await z.encodeDeterministic(manifest);
  const capacity = h.checkRecoveryHistoryCapacity({ transitionCount: 0, historyBytes: 0, nextEntryBytes: serialized.byteLength });
  t.diagnostic(`max serialized manifest bytes=${serialized.byteLength}`);
  assert.equal(serialized.byteLength, 3_284_324);
  assert.equal(capacity.usedBytes, serialized.byteLength);
  assert.ok(serialized.byteLength < 8 * 1024 * 1024);
});
