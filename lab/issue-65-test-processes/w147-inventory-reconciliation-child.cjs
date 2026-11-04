"use strict";
// One-shot process: the parent owns the disposable runtime and restarts this
// program for every phase. No real account, file, cloud endpoint, or key.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const backupService = require("../../services/backupService");
const restoreService = require("../../services/restoreService");
const orphans = require("../../services/restoreProviderOrphans");
const backupRepository = require("../../repositories/backupRepository");

const name = "other-account-legacy.txt";
const relative = path.join("uploads", "root", name);
const localPath = path.resolve(relative);
const remotePath = path.resolve("fixture-provider-upload.bin");
const stateFile = path.resolve("fixture-reference-id.txt");
const plaintext = "W147_DISPOSABLE_OTHER_ACCOUNT_PROVIDER_PLAINTEXT";
const state = { inventoryCalls: 0, uploads: 0, enabledCalls: 0, strictAtUpload: null };
const provider = {
  enabled: () => {
    state.enabledCalls++;
    // Legitimate provider callback after the historic archive was validated:
    // the background worker cannot trust earlier admission at the ZIP layer.
    if (process.argv[2] === "flip" && state.enabledCalls === 2) {
      process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";
    }
    return true;
  },
  provider: process.argv[2] === "flipLate" ? "gdrive" : "s3",
  resolveUploadId: async () => {
    if (process.argv[2] === "flipLate") {
      process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";
    }
    return "w147-disposable-stable-provider-file-id";
  },
  inventory: async () => {
    state.inventoryCalls++;
    return fs.existsSync(remotePath)
      ? [{ area: "uploads", folderId: "root", name, provider: "s3",
        providerIdentity: "fixture-object-001" }]
      : [];
  },
  upload: async (sourcePath, folderId, fileName, area) => {
    assert.deepEqual([folderId, fileName, area], ["root", name, "uploads"]);
    state.uploads++;
    state.strictAtUpload = process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT;
    fs.copyFileSync(sourcePath, remotePath);
    return { provider: provider.provider, providerIdentity: "fixture-object-001" };
  },
  download: async () => { throw new Error("unexpected download"); },
};
backupService.setCloudStorage(provider);
restoreService.setCloudStorage(provider);

async function main() {
  const phase = process.argv[2];
  if (phase === "known") {
    const result = await restoreService.reconcileUnknownProviderInventory();
    console.log(JSON.stringify({ phase, state: result.state, changed: result.changed,
      uploads: state.uploads, inventoryCalls: state.inventoryCalls }));
    return;
  }
  if (phase === "stage") {
    assert.equal(process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT, "0");
    fs.mkdirSync(path.dirname(localPath), { recursive: true });
    fs.writeFileSync(localPath, plaintext);
    const backup = await backupService.createBackup({ createdBy: "fixture" });
    assert.equal(backup.metadata.manifest.cloud_complete, true,
      "reference backup must be real ZIP backed by complete cloud inventory");
    // Only a changed local delta should be sent to the provider. Without
    // this mutation the archived snapshot is already in sync and no upload
    // is due, falsely suggesting a strict fence was exercised.
    fs.writeFileSync(localPath, plaintext + "-POST-BACKUP-DELTA");
    fs.writeFileSync(stateFile, backup.id);
    await orphans.markInventoryUnknown(backup.id);
    assert.equal(orphans.getInventoryStatus().state, "unknown");
    console.log(JSON.stringify({ phase, backupId: backup.id, state: "unknown" }));
    return;
  }
  const backupId = fs.readFileSync(stateFile, "utf8");
  assert.equal(backupRepository.getBackup(backupId)?.metadata?.manifest?.cloud_complete, true);
  assert.equal(orphans.getInventoryStatus().state, "unknown",
    "the inventory marker must survive the previous process");
  let outcome = "ok";
  let code = null;
  try {
    await restoreService.reconcileUnknownProviderInventory({ sleep: async () => {} });
  } catch (error) {
    outcome = "rejected";
    code = error.code || "OTHER_ERROR";
  }
  console.log(JSON.stringify({
    phase, strict: process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT,
    outcome, code, uploads: state.uploads, strictAtUpload: state.strictAtUpload,
    enabledCalls: state.enabledCalls, inventoryCalls: state.inventoryCalls,
    providerHasPlaintext: fs.existsSync(remotePath)
      && fs.readFileSync(remotePath, "utf8") === plaintext + "-POST-BACKUP-DELTA",
    queueState: backupRepository.getBackup(backupId)?.metadata?.restoreSync?.state || null,
    markerState: orphans.getInventoryStatus().state,
  }));
}
main().then(() => process.exit(0), (error) => {
  console.error(error.stack);
  process.exit(1);
});
