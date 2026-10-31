"use strict";

// TEST_UNRUN: the user's exclusive Node/WSL gate is currently CLOSED.
// This isolates an actual pre-planted temporary-file collision in the
// durable SyncObjectStore JSON writer without touching any account DB.
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
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
  const before = await fs.lstat(plantedPath, { bigint: true });
  const originalUUID = crypto.randomUUID;
  t.after(async () => {
    crypto.randomUUID = originalUUID;
    await fs.rm(root, { recursive: true, force: true, maxRetries: 5 });
  });
  crypto.randomUUID = () => plantedId;
  try {
    await assert.rejects(new SyncObjectStore(filename).open(),
      { code: "EEXIST" }, "O_EXCL collision must reject instead of opening with w and truncating");
  } finally { crypto.randomUUID = originalUUID; }
  assert.deepEqual(await fs.readFile(plantedPath), original);
  const after = await fs.lstat(plantedPath, { bigint: true });
  assert.equal(after.dev, before.dev);
  assert.equal(after.ino, before.ino);
  await assert.rejects(fs.lstat(filename), { code: "ENOENT" },
    "failed temp creation cannot rename the forged evidence into the live store");

  const successful = await new SyncObjectStore(filename).open();
  assert.deepEqual(successful.readSnapshot().users, {});
  assert.deepEqual(await fs.readFile(plantedPath), original,
    "later genuine write must not remove, rename, or truncate planted evidence");
});
