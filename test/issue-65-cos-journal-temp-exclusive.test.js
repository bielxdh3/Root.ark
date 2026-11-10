"use strict";

// TEST_UNRUN until the exclusive Node22 gate opens. A real filesystem
// collision must NEVER truncate an unrelated preexisting journal temp file.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

test("durable journal uses exclusive creation and preserves a real planted collision", {
  timeout: 60000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("cos-journal-exclusive-");
  t.after(async () => fsp.rm(root, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(root, "journal.json");
  const journal = await new SyncJournal(filename).open();
  const original = { operationId: "first-physical-record", phase: "prepared" };
  await journal.enqueue(original);
  const originalDisk = await fsp.readFile(filename);
  assert.deepEqual(journal.pending(), [original]);
  assert.deepEqual(JSON.parse(originalDisk.toString()).pending, [original]);

  const id = "00000000-0000-4000-8000-000000000065";
  const planted = filename + ".tmp-" + process.pid + "-" + id;
  const plantedBytes = Buffer.from("UNRELATED_PRIVATE_TEMP_CONTENT_PRESERVE_EXACTLY");
  fs.writeFileSync(planted, plantedBytes, { flag: "wx", mode: 0o600 });
  const plantedStat = fs.lstatSync(planted, { bigint: true });

  // Constrain only the random-name provider for this journal commit; all
  // physical open(O_EXCL), rename and fd.sync calls remain actual filesystem
  // operations. This causally forces the otherwise astronomically unlikely
  // collision without faking an EEXIST error.
  const randomUUID = crypto.randomUUID;
  let draws = 0;
  try {
    crypto.randomUUID = () => { draws += 1; return id; };
    await assert.rejects(journal.update(original.operationId, {
      phase: "source-moved",
    }), (error) => error?.code === "EEXIST",
    "O_EXCL must reject, not truncate or overwrite, the planted inode");
  } finally {
    crypto.randomUUID = randomUUID;
  }
  assert.equal(draws, 1);
  assert.deepEqual(await fsp.readFile(planted), plantedBytes);
  const after = await fsp.lstat(planted, { bigint: true });
  assert.equal(after.dev, plantedStat.dev);
  assert.equal(after.ino, plantedStat.ino);
  assert.equal(after.nlink, 1n);
  assert.deepEqual(await fsp.readFile(filename), originalDisk);
  assert.deepEqual(journal.pending(), [original],
    "failed exclusive temporary admission must not advance in-memory phase");
  assert.deepEqual((await new SyncJournal(filename).open()).pending(), [original],
    "independently reopened durable journal must retain the prior phase");
});

test("ordinary journal commit still persists and independently reopens after an exclusive temp", {
  timeout: 60000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("cos-journal-exclusive-positive-");
  t.after(async () => fsp.rm(root, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(root, "journal.json");
  const journal = await new SyncJournal(filename).open();
  const operation = { operationId: "positive-physical-record", phase: "prepared" };
  await journal.enqueue(operation);
  await journal.update(operation.operationId, { phase: "source-moved" });
  const disk = await new SyncJournal(filename).open();
  assert.deepEqual(disk.pending(), [{ ...operation, phase: "source-moved" }]);
  const siblings = await fsp.readdir(root);
  assert.deepEqual(siblings, ["journal.json"],
    "a completed exclusive temp commit must not orphan intermediate files");
});

test("failed journal publication must never unlink a substituted foreign temporary inode", {
  timeout: 60000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("cos-journal-temp-substitute-");
  t.after(async () => fsp.rm(root, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(root, "journal.json");
  const journal = await new SyncJournal(filename).open();
  const first = { operationId: "original-prepared", phase: "prepared" };
  await journal.enqueue(first);
  const originalDisk = await fsp.readFile(filename);
  const parked = path.join(root, "original-temp-parked");
  const foreign = Buffer.from("FOREIGN_JOURNAL_TEMP_NEVER_UNLINK");
  const originalRename = fsp.rename;
  const originalUnlink = fsp.unlink;
  let planted = null;
  let attemptedForeignUnlink = false;
  try {
    fsp.rename = async (source, destination, ...args) => {
      if (!planted && path.resolve(String(destination)) === path.resolve(filename)
        && String(source).startsWith(filename + ".tmp-")) {
        planted = String(source);
        await originalRename(source, parked);
        await fsp.writeFile(source, foreign, { flag: "wx" });
        throw Object.assign(new Error("physical journal temporary changed before publication"), { code: "EIO" });
      }
      return originalRename(source, destination, ...args);
    };
    fsp.unlink = async (requested, ...args) => {
      if (planted && path.resolve(String(requested)) === path.resolve(planted)) {
        attemptedForeignUnlink = true;
        // Never allow the intentionally vulnerable parent to destroy a
        // disposable foreign inode while proving its attempted removal.
        throw Object.assign(new Error("foreign journal unlink intercepted"), { code: "EACCES" });
      }
      return originalUnlink(requested, ...args);
    };
    await assert.rejects(journal.update(first.operationId, { phase: "source-moved" }),
      { code: "EIO" });
  } finally {
    fsp.rename = originalRename;
    fsp.unlink = originalUnlink;
  }
  assert.ok(planted, "must replace the actual physical journal temp before rename");
  assert.equal(attemptedForeignUnlink, false,
    "a failed journal transaction may not remove a name rebound to foreign data");
  assert.deepEqual(await fsp.readFile(planted), foreign);
  assert.equal((await fsp.lstat(planted)).nlink, 1);
  assert.ok((await fsp.lstat(parked)).isFile());
  assert.deepEqual(await fsp.readFile(filename), originalDisk);
  assert.deepEqual((await new SyncJournal(filename).open()).pending(), [first]);
});
