"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createCloudTempMutationQueue } = require("../services/cloudTempMutationQueue");
const { isZk10LegacyBackupStrict } = require("../src/services/zk10LegacyBackupDeny");

test("strict mode agrees with existing server HTTP/WebDAV spelling and case", () => {
  assert.equal(isZk10LegacyBackupStrict({ ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "" }), false);
  assert.equal(isZk10LegacyBackupStrict({ ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "0" }), false);
  assert.equal(isZk10LegacyBackupStrict({ ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "off" }), false);
  assert.equal(isZk10LegacyBackupStrict({ ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "1" }), true);
  assert.equal(isZk10LegacyBackupStrict({ ROOTARK_ZK10_SYNC_CUTOVER_STRICT: "OFF" }), true);
});

test("strict startup/retry cloud queue cannot PUT legacy bytes; OFF keeps durable retry", async (t) => {
  const previous = process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT;
  t.after(() => {
    if (previous === undefined) delete process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT;
    else process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = previous;
  });
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-w147-cloud-queue-"));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  const local = path.join(root, "legacy.txt");
  const provider = path.join(root, "remote.txt");
  fs.writeFileSync(local, "W147_DISPOSABLE_LEGACY_PROVIDER_PUT");
  const queueOptions = {
    directory: path.join(root, "queue"),
    lifecycleLock: { run: (_folder, _name, callback) => callback() },
    localPathFor: () => local,
    upload: async (source) => fs.copyFileSync(source, provider),
    remove: async () => fs.rmSync(provider, { force: true }),
    isEnabled: () => true,
  };
  process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "0";
  const beforeRestart = createCloudTempMutationQueue(queueOptions);
  beforeRestart.setDesired("root", "legacy.txt", "present");
  assert.equal(fs.existsSync(provider), false);

  // Fresh queue instance models process restart over the same persisted queue.
  process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";
  const strictProcess = createCloudTempMutationQueue(queueOptions);
  await assert.rejects(strictProcess.processAll(), { code: "ZK10_EXTERNAL_AUTHORITY_UNAVAILABLE" });
  assert.equal(fs.existsSync(provider), false, "provider upload must not run");
  assert.equal(strictProcess.hasPending("root", "legacy.txt"), true);

  process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "0";
  const restartedLegacy = createCloudTempMutationQueue(queueOptions);
  await restartedLegacy.processAll();
  assert.equal(fs.readFileSync(provider, "utf8"), "W147_DISPOSABLE_LEGACY_PROVIDER_PUT");
});
