const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const originalCwd = process.cwd();
const runtime = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-trash-delete-race-"));
process.chdir(runtime);
process.env.DB_ENABLED = "false";
const trashRepository = require("../repositories/trashRepository");
const trashService = require("../services/trashService");
const { createFileLifecycleLock } = require("../services/fileLifecycleLock");

const locks = createFileLifecycleLock({ directory: path.join(runtime, "locks"), timeoutMs: 2_000, pollMs: 5 });
const runFile = (folderId, fileName, work) => locks.run(folderId, fileName, work);
const runFolder = (folderId, work) => locks.runFolder(folderId, work);

function pendingFile(id, name) {
  const trashPath = path.join("files", id, name);
  const target = path.join(runtime, "data", "trash", trashPath);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, "old local bytes");
  return trashService.queueRemoteDeletion({
    item: {
      id,
      itemType: "file",
      originalFolderId: "root",
      originalFileName: name,
      trashPath,
      metadata: {},
      restoreMetadata: { versions: { versions: [] } },
      status: "trashed",
    },
    deletedBy: "tester",
    loaders: {},
    provider: "s3",
  });
}

function processItem(item, provider, isReplacementActive = () => false) {
  return trashService.processRemoteDeletion({
    item,
    provider,
    runFileLifecycleMutation: runFile,
    runFolderLifecycleMutation: runFolder,
    isReplacementActive,
  });
}

test("remote delete queued after a replacement does not delete its provider key", async () => {
  const item = pendingFile("11111111-1111-4111-8111-111111111111", "same-name.txt");
  let providerBytes = "old provider bytes";
  let replacementActive = false;
  let deleteCalls = 0;

  await runFile("root", "same-name.txt", async () => {
    providerBytes = "replacement provider bytes";
    replacementActive = true;
  });

  const result = await processItem(item, async () => {
    deleteCalls += 1;
    providerBytes = null;
  }, () => replacementActive);

  assert.equal(deleteCalls, 0, "the retry checks for replacement under the lifecycle lock before provider deletion");
  assert.equal(providerBytes, "replacement provider bytes");
  assert.equal(result.status, "permanently_deleted");
  assert.equal(result.metadata.remoteDeletion.state, "cancelled");
  assert.equal(trashRepository.getTrashItem(item.id).metadata.remoteDeletion.cancellationReason, "replacement_active");
});

test("restart recovers a cancelled remote deletion left pending by an older partial save", async () => {
  const item = pendingFile("55555555-5555-4555-8555-555555555555", "cancelled-pending.txt");
  const persisted = trashRepository.getTrashItem(item.id);
  persisted.metadata.remoteDeletion.state = "cancelled";
  persisted.metadata.remoteDeletion.cancellationReason = "replacement_active";
  persisted.status = "remote_delete_pending";
  trashRepository.saveTrashItem(persisted);

  // Re-read the repository record to model a worker restart.
  const restartedItem = trashRepository.getTrashItem(item.id);
  let deleteCalls = 0;
  const result = await processItem(restartedItem, async () => { deleteCalls += 1; }, () => true);

  assert.equal(deleteCalls, 0);
  assert.equal(result.status, "permanently_deleted");
  assert.equal(result.metadata.remoteDeletion.state, "cancelled");
  assert.equal(trashRepository.getTrashItem(item.id).status, "permanently_deleted");
});

test("failed cancellation persistence leaves a retryable record that recovers on the next worker run", async () => {
  const item = pendingFile("66666666-6666-4666-8666-666666666666", "cancel-save-failure.txt");
  const saveTrashItem = trashRepository.saveTrashItem;
  trashRepository.saveTrashItem = () => { throw new Error("simulated trash repository write failure"); };

  await assert.rejects(
    processItem(item, async () => assert.fail("replacement must not be deleted"), () => true),
    /simulated trash repository write failure/
  );

  trashRepository.saveTrashItem = saveTrashItem;
  const afterFailure = trashRepository.getTrashItem(item.id);
  assert.equal(afterFailure.status, "remote_delete_pending");
  assert.notEqual(afterFailure.metadata.remoteDeletion.state, "cancelled");

  const recovered = await processItem(afterFailure, async () => assert.fail("replacement must not be deleted"), () => true);
  assert.equal(recovered.status, "permanently_deleted");
  assert.equal(recovered.metadata.remoteDeletion.state, "cancelled");
});

test("worker-first ordering deletes old bytes before a waiting replacement upload", async () => {
  const item = pendingFile("22222222-2222-4222-8222-222222222222", "same-name-worker-first.txt");
  let providerBytes = "old provider bytes";
  let replacementActive = false;
  let deleteCalls = 0;
  let markStarted;
  let release;
  const started = new Promise((resolve) => { markStarted = resolve; });
  const held = new Promise((resolve) => { release = resolve; });

  const worker = processItem(item, async () => {
    deleteCalls += 1;
    markStarted();
    await held;
    providerBytes = null;
  }, () => replacementActive);
  await started;
  let uploadFinished = false;
  const upload = runFile("root", "same-name-worker-first.txt", async () => {
    providerBytes = "replacement provider bytes";
    replacementActive = true;
    uploadFinished = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal(uploadFinished, false, "replacement mutation waits while the worker holds the same lifecycle lock");
  release();
  const completed = await worker;
  await upload;

  assert.equal(deleteCalls, 1);
  assert.equal(providerBytes, "replacement provider bytes");
  assert.equal(replacementActive, true);
  assert.equal(completed.metadata.remoteDeletion.state, "completed");
});

test("folder retry is cancelled when the original folder id has been recreated", async () => {
  const id = "33333333-3333-4333-8333-333333333333";
  const trashPath = path.join("folders", id);
  const target = path.join(runtime, "data", "trash", trashPath);
  fs.mkdirSync(target, { recursive: true });
  fs.writeFileSync(path.join(target, "old.txt"), "old local folder bytes");
  const empty = () => ({});
  const loaders = {
    loadFolders: () => [{ id, name: "recreated" }], saveFolders() {},
    loadFilePermissions: empty, saveFilePermissions() {},
    loadFileExpirations: empty, saveFileExpirations() {},
    loadFileVersions: empty, saveFileVersions() {},
    loadEncryptedFiles: empty, saveEncryptedFiles() {},
    loadPublicLinks: empty, savePublicLinks() {},
  };
  const item = trashService.queueRemoteDeletion({
    item: { id: "44444444-4444-4444-8444-444444444444", itemType: "folder", originalFolderId: id, originalFolderName: "old", originalFileName: "old", trashPath, metadata: {}, restoreMetadata: { folder: { id } }, status: "trashed" },
    deletedBy: "tester", loaders, provider: "s3",
  });
  let deleteCalls = 0;
  const result = await trashService.processRemoteDeletion({
    item,
    provider: async () => { deleteCalls += 1; },
    runFolderLifecycleMutation: runFolder,
    isReplacementActive: (current) => loaders.loadFolders().some((folder) => folder.id === current.originalFolderId),
  });
  assert.equal(deleteCalls, 0, "recreated folder prefix is not deleted");
  assert.equal(result.status, "permanently_deleted");
  assert.equal(result.metadata.remoteDeletion.state, "cancelled");
});

test.after(() => {
  process.chdir(originalCwd);
  fs.rmSync(runtime, { recursive: true, force: true });
});
