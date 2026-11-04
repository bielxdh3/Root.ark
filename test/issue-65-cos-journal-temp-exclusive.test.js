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
