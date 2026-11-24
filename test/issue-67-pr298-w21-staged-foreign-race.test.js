"use strict";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncEngine } = require("../sync-client/rootark-sync-engine");

const hash = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");

test("#67 P2: staged rollback never links or unlinks a foreign inode substituted before the syscall", async (t) => {
  // The working tree can live on NTFS while WSL's os.tmpdir() is real ext4.
  // All files are synthetic and confined to this disposable directory.
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-67-w21-stage-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const engine = Object.create(SyncEngine.prototype);
  engine.rootDir = root;
  const target = path.join(root, "document.txt");
  const clean = Buffer.from("original synchronized ciphertext");
  await fsp.writeFile(target, clean);

  const originalStageExisting = engine.stageExisting.bind(engine);
  const originalLink = fsp.link;
  const originalUnlink = fsp.unlink;
  let foreignHandle, foreignStats, originalStagePath, retainedStagePath;
  let unsafeLink = false;
  let unsafeUnlink = false;
  engine.stageExisting = async (filePath) => {
    originalStagePath = await originalStageExisting(filePath);
    retainedStagePath = `${originalStagePath}.retained`;
    await fsp.rename(originalStagePath, retainedStagePath);
    await fsp.writeFile(originalStagePath, Buffer.from("foreign, unrelated synthetic data"));
    foreignHandle = await fsp.open(originalStagePath, "r");
    foreignStats = await foreignHandle.stat({ bigint: true });
    return originalStagePath;
  };
  fsp.link = async (from, to, ...rest) => {
    if (from === originalStagePath && to === target) {
      unsafeLink = true;
      // Kernel boundary: do NOT let the unsafe path link touch a foreign inode.
      throw Object.assign(new Error("intercepted foreign stage link"), { code: "EACCES" });
    }
    return originalLink(from, to, ...rest);
  };
  fsp.unlink = async (name, ...rest) => {
    if (name === originalStagePath) {
      unsafeUnlink = true;
      throw Object.assign(new Error("intercepted foreign stage unlink"), { code: "EACCES" });
    }
    return originalUnlink(name, ...rest);
  };
  try {
    await assert.rejects(engine.stageHistoricalRestore(target, "document.txt", hash(clean)),
      (error) => error.code === "restore_local_conflict");
  } finally {
    fsp.link = originalLink;
    fsp.unlink = originalUnlink;
  }
  try {
    assert.equal(unsafeLink, false, "no foreign stage inode may be hardlinked to the target");
    assert.equal(unsafeUnlink, false, "no foreign stage pathname may be unlinked");
    assert.equal(fs.existsSync(target), false);
    assert.deepEqual(await fsp.readFile(retainedStagePath), clean);
    assert.equal((await foreignHandle.stat({ bigint: true })).ino, foreignStats.ino);
    assert.equal((await fsp.lstat(originalStagePath, { bigint: true })).ino, foreignStats.ino);
    assert.equal((await foreignHandle.readFile()).toString(), "foreign, unrelated synthetic data");
  } finally {
    if (foreignHandle) await foreignHandle.close();
  }
});

test("#67: a genuine unchanged staged ciphertext still passes the positive SHA256 gate", async (t) => {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-67-w21-clean-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const engine = Object.create(SyncEngine.prototype);
  engine.rootDir = root;
  const target = path.join(root, "clean.txt");
  const original = Buffer.from("verified original bytes");
  await fsp.writeFile(target, original);
  const stage = await engine.stageHistoricalRestore(target, "clean.txt", hash(original));
  assert.ok(stage.startsWith(path.join(root, ".rootark-trash")));
  assert.equal(fs.existsSync(target), false);
  assert.deepEqual(await fsp.readFile(stage), original);
});
