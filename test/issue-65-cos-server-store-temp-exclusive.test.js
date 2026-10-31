"use strict";

// TEST_UNRUN: the user's exclusive Node/WSL gate is currently CLOSED.
// This isolates an actual pre-planted temporary-file collision in the
// durable SyncObjectStore JSON writer without touching any account DB.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsConstants = require("node:fs").constants;
const fs = require("node:fs/promises");
const path = require("node:path");
const test = require("node:test");
const { SyncObjectStore } = require("../src/routes/sync");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

test("store O_EXCL temp collision never truncates a planted inode and recovers on a new UUID", {
  timeout: 60_000,
}, async (t) => {
  const root = createPrivateAuthorityFixture("zk65-store-temp-excl-");
  const filename = path.join(root, "objects.json");
  const plantedId = "10000000-2222-4333-8444-555555555555";
  const plantedPath = `${filename}.tmp-${process.pid}-${plantedId}`;
  const original = Buffer.from("DO_NOT_TRUNCATE_EXISTING_OR_FOREIGN_TEMP\n");
  await fs.writeFile(plantedPath, original, { mode: 0o600, flag: "wx" });
  const originalUUID = crypto.randomUUID;
  t.after(async () => {
    crypto.randomUUID = originalUUID;
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5 });
  });
  // Keep the planted evidence on one pinned descriptor across both attempts.
  // Reopening a path to read it after lstat could silently read a replacement.
  const planted = await fs.open(plantedPath,
    fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0));
  try {
    const before = await planted.stat({ bigint: true });
    assert.equal(before.isFile(), true);
    assert.equal(before.nlink, 1n);
    const assertOriginalEvidence = async (message) => {
      // Explicit position zero: two FileHandle.readFile calls would advance
      // the same descriptor and make the second no-clobber check vacuous.
      const buffer = Buffer.alloc(original.length);
      let offset = 0;
      while (offset < buffer.length) {
        const { bytesRead } = await planted.read(buffer, offset,
          buffer.length - offset, offset);
        assert.ok(bytesRead > 0, `Planted evidence truncated: ${message}`);
        offset += bytesRead;
      }
      assert.deepEqual(buffer, original, message);
      const opened = await planted.stat({ bigint: true });
      const named = await fs.lstat(plantedPath, { bigint: true });
      for (const stat of [opened, named]) {
        assert.equal(stat.isFile(), true, message);
        assert.equal(stat.dev, before.dev, message);
        assert.equal(stat.ino, before.ino, message);
        assert.equal(stat.size, BigInt(original.length), message);
        assert.equal(stat.nlink, 1n, message);
      }
    };
    crypto.randomUUID = () => plantedId;
    try {
      await assert.rejects(new SyncObjectStore(filename).open(),
        { code: "EEXIST" }, "O_EXCL collision must reject instead of opening with w and truncating");
    } finally { crypto.randomUUID = originalUUID; }
    await assertOriginalEvidence("failed collision must preserve exact planted inode and bytes");
    await assert.rejects(fs.lstat(filename), { code: "ENOENT" },
      "failed temp creation cannot rename the forged evidence into the live store");

    const successful = await new SyncObjectStore(filename).open();
    assert.deepEqual(successful.readSnapshot().users, {});
    await assertOriginalEvidence("later genuine write must preserve planted inode and bytes");
  } finally { await planted.close(); }
});
