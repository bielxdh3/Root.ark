const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createCloudTempMutationQueue } = require("../services/cloudTempMutationQueue");

function createHarness(directory, upload, isSuppressed = () => false) {
  const lifecycleLock = { run: async (_folderId, _fileName, work) => work() };
  return createCloudTempMutationQueue({
    area: "uploads",
    directory: path.join(directory, "queue"),
    lifecycleLock,
    localPathFor: (_folderId, fileName) => path.join(directory, "files", fileName),
    upload,
    remove: async () => {},
    isSuppressed,
  });
}

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

