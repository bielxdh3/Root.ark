"use strict";

// TEST_UNRUN until the exclusive Node22 gate opens. A real filesystem
// collision must NEVER truncate an unrelated preexisting journal temp file.
const test = require("node:test");
const assert = require("node:assert/strict");
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

  // The journal pins crypto.randomUUID at module load, so patching the public
  // crypto export would not force a collision. Redirect only the one journal
  // temporary-path open to a preexisting real inode; the actual filesystem
  // still enforces O_EXCL, and no EEXIST error is fabricated by this test.
  const realOpen = fsp.open;
  let collisionOpens = 0;
  try {
    fsp.open = (candidate, flags, mode) => {
      if (typeof candidate === "string"
        && candidate.startsWith(`${filename}.tmp-${process.pid}-`)) {
        collisionOpens += 1;
        assert.equal(flags, "wx", "journal must demand exclusive temp creation");
        return realOpen(planted, flags, mode);
      }
      return realOpen(candidate, flags, mode);
    };
    await assert.rejects(journal.update(original.operationId, {
      phase: "source-moved",
    }), (error) => error?.code === "EEXIST",
    "O_EXCL must reject, not truncate or overwrite, the planted inode");
  } finally {
    fsp.open = realOpen;
  }
  assert.equal(collisionOpens, 1);
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
