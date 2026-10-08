const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createCloudTempMutationQueue } = require("../services/cloudTempMutationQueue");

function createHarness(directory, upload, isSuppressed = () => false, isEnabled = () => true, remove = async () => {}) {
  const lifecycleLock = { run: async (_folderId, _fileName, work) => work() };
  return createCloudTempMutationQueue({
    area: "uploads",
    directory: path.join(directory, "queue"),
    lifecycleLock,
    localPathFor: (_folderId, fileName) => path.join(directory, "files", fileName),
    upload,
    remove,
    isSuppressed,
    isEnabled,
  });
}

test("disabled upload reconciliation retains durable intent until the provider is enabled", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-upload-queue-disabled-"));
  try {
    const fileDirectory = path.join(directory, "files");
    fs.mkdirSync(fileDirectory, { recursive: true });
    fs.writeFileSync(path.join(fileDirectory, "deleted-version.txt.v1"), "archived version");
    let providerCalls = 0;
    const disabled = createHarness(directory, async () => { providerCalls += 1; }, () => false, () => false, async () => { providerCalls += 1; });
    disabled.setDesired("root", "deleted-version.txt.v1", "absent");
    await disabled.processAll();

    assert.equal(providerCalls, 0, "disabled cloud storage does not call provider operations");
    assert.equal(disabled.getRecord("root", "deleted-version.txt.v1")?.desired, "absent", "disabled reconciliation preserves the durable intent");

    const enabled = createHarness(directory, async () => { providerCalls += 1; }, () => false, () => true, async () => { providerCalls += 1; });
    await enabled.processAll();
    assert.equal(providerCalls, 1, "the intent is reconciled after cloud storage is enabled");
    assert.equal(enabled.hasPending("root", "deleted-version.txt.v1"), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("upload queue persists provider failure and retries it after restart", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-upload-queue-"));
  try {
    const fileDirectory = path.join(directory, "files");
    fs.mkdirSync(fileDirectory, { recursive: true });
    const localPath = path.join(fileDirectory, "approved.txt");
    fs.writeFileSync(localPath, "approved replacement");
    let attempts = 0;
    const first = createHarness(directory, async (_localPath, folderId, fileName, area) => {
      attempts += 1;
      assert.equal(folderId, "root");
      assert.equal(fileName, "approved.txt");
      assert.equal(area, "uploads");
      throw new Error("provider unavailable");
    }, () => true);

    await assert.rejects(first.enqueue("root", "approved.txt", "present"), /provider unavailable/);
    assert.equal(first.hasPending("root", "approved.txt"), true, "failed provider work remains durable");

    const restarted = createHarness(directory, async (sourcePath, folderId, fileName, area) => {
      attempts += 1;
      assert.equal(fs.readFileSync(sourcePath, "utf8"), "approved replacement");
      assert.deepEqual([folderId, fileName, area], ["root", "approved.txt", "uploads"]);
    }, () => true);
    await restarted.processAll();

    assert.equal(attempts, 2);
    assert.equal(restarted.hasPending("root", "approved.txt"), false, "queue entry is removed only after provider success");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("upload queue rejects a symlinked record without reading or changing its target", async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-upload-queue-symlink-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const queue = createHarness(directory, async () => {});
  const record = queue.setDesired("root", "linked.txt", "absent");
  const queueDirectory = path.join(directory, "queue");
  const recordPath = path.join(queueDirectory, `${require("node:crypto").createHash("sha256").update("root\0linked.txt").digest("hex")}.json`);
  const targetPath = path.join(directory, "outside-record.json");
  const target = JSON.stringify({ ...record, desired: "present", generation: "outside" });
  fs.writeFileSync(targetPath, target);
  fs.unlinkSync(recordPath);
  try {
    fs.symlinkSync(targetPath, recordPath);
  } catch (error) {
    if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) return t.skip(`symlink creation unavailable: ${error.code}`);
    throw error;
  }

  assert.throws(() => queue.getRecord("root", "linked.txt"));
  assert.equal(fs.readFileSync(targetPath, "utf8"), target);
  assert.equal(fs.lstatSync(recordPath).isSymbolicLink(), true);
});

test("upload queue rejects a record replaced between descriptor open and path validation", (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-cloud-upload-queue-path-swap-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const queue = createHarness(directory, async () => {});
  const original = queue.setDesired("root", "swapped.txt", "absent");
  const queueDirectory = path.join(directory, "queue");
  const recordPath = path.join(queueDirectory, `${require("node:crypto").createHash("sha256").update("root\0swapped.txt").digest("hex")}.json`);
  const replacementPath = path.join(directory, "replacement-record.json");
  const replacement = { ...original, generation: "replacement-generation" };
  fs.writeFileSync(replacementPath, JSON.stringify(replacement));
  const originalLstatSync = fs.lstatSync;
  let swapped = false;
  fs.lstatSync = function (target, ...args) {
    if (target === recordPath && !swapped) {
      swapped = true;
      fs.renameSync(recordPath, `${recordPath}.displaced`);
      fs.renameSync(replacementPath, recordPath);
    }
    return originalLstatSync.call(this, target, ...args);
  };
  try {
    assert.throws(() => queue.getRecord("root", "swapped.txt"), /stable regular file/);
    assert.equal(swapped, true);
    assert.equal(JSON.parse(fs.readFileSync(recordPath, "utf8")).generation, "replacement-generation");
  } finally {
    fs.lstatSync = originalLstatSync;
  }
});

