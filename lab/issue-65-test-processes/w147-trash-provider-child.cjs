"use strict";
// Disposable real repository and trashService physical-provider side effect.
// Each invocation is a fresh Node process over the same fs-backed queue.
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const trashRepository = require("../../repositories/trashRepository");
const trashService = require("../../services/trashService");

const id = "847a46d1-98ca-4408-8301-4783e2aef147";
const name = "other-owner-legacy.txt";
const remotePath = path.join(process.cwd(), "fixture-cloud-object.txt");
const originalContent = "W147_DISPOSABLE_OTHER_OWNER_CLOUD_OBJECT";
const phase = process.argv[2];
const itemType = process.argv[3] === "folder" ? "folder" : "file";

async function main() {
  if (phase === "stage") {
    assert.equal(process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT, "0");
    const trashPath = itemType === "folder" ? path.join("folders", id) : path.join("files", id, name);
    const localFile = path.join(process.cwd(), "data", "trash", trashPath);
    fs.mkdirSync(path.dirname(localFile), { recursive: true });
    if (itemType === "folder") {
      fs.mkdirSync(localFile, { recursive: true });
      fs.writeFileSync(path.join(localFile, "disposable.txt"), "disposable local payload");
    } else fs.writeFileSync(localFile, "disposable local payload");
    fs.writeFileSync(remotePath, originalContent);
    const empty = () => ({});
    const loaders = Object.fromEntries([
      "FilePermissions", "FileExpirations", "FileVersions", "EncryptedFiles",
    ].flatMap((suffix) => [
      ["load" + suffix, empty], ["save" + suffix, () => {}],
    ]));
    const queued = trashService.queueRemoteDeletion({
      item: { id, itemType, originalFolderId: itemType === "folder" ? id : "root", originalFileName: name,
        trashPath, metadata: {}, restoreMetadata: { versions: { versions: [] } },
        status: "trashed" },
      deletedBy: "operator-fixture", loaders, provider: "s3",
    });
    assert.equal(queued.status, "remote_delete_pending");
    console.log(JSON.stringify({ phase, status: queued.status,
      state: queued.metadata.remoteDeletion.state }));
    return;
  }
  const item = trashRepository.getTrashItem(id);
  assert.equal(item.status, "remote_delete_pending", "durably queued item must be reloaded after restart");
  let deletes = 0;
  let errorCode = null;
  const provider = async () => {
    deletes++;
    fs.rmSync(remotePath);
    return true;
  };
  try {
    await trashService.processRemoteDeletion({
      item,
      provider,
      isReplacementActive: async () => {
        if (phase === "late") process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT = "1";
        return false;
      },
    });
  } catch (error) {
    errorCode = error.code || "OTHER_ERROR";
  }
  const after = trashRepository.getTrashItem(id);
  console.log(JSON.stringify({
    phase, itemType, strict: process.env.ROOTARK_ZK10_SYNC_CUTOVER_STRICT,
    deletes, errorCode, state: after.metadata.remoteDeletion.state,
    status: after.status, attempts: after.metadata.remoteDeletion.attempts,
    remotePreserved: fs.existsSync(remotePath)
      && fs.readFileSync(remotePath, "utf8") === originalContent,
  }));
}
main().then(() => process.exit(0), (error) => {
  console.error(error.stack);
  process.exit(1);
});
