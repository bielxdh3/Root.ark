"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");

const entry = (i) => ({ operationId: `remote-batch-${i}`,
  digest: crypto.createHash("sha256").update(String(i)).digest("hex") });

async function fixture(t) {
  const root = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-w22-markseen-"));
  t.after(() => fsp.rm(root, { recursive: true, force: true }));
  const file = path.join(root, "journal.json");
  return { file, journal: await new SyncJournal(file).open() };
}

test("W22 inert batch markSeen promotes 160/640 exact observed digests in a single durable commit", async (t) => {
  for (const count of [160, 640]) {
    const { file, journal } = await fixture(t);
    const items = Array.from({ length: count }, (_, i) => entry(i));
    await journal.batchObserveAdmission(items);
    const originalRename = fsp.rename;
    let writes = 0;
    fsp.rename = async (...args) => {
      if (args[1] === file) writes++;
      return originalRename(...args);
    };
    try { await journal.batchMarkSeenRemoteOnly(items); }
    finally { fsp.rename = originalRename; }
    assert.equal(writes, 1);
    const reopened = await new SyncJournal(file).open();
    assert.equal(reopened.state.seen.length, count);
    assert.equal(Object.keys(reopened.state.observed).length, 0);
    assert.equal(Object.keys(reopened.state.admitted).length, count);
    for (const item of items) assert.equal(reopened.hasLocalAdmission(item.operationId, item.digest), true);
  }
});

test("W22 inert batch markSeen refuses unobserved, duplicated, conflicting and partially pending IDs", async (t) => {
  const { file, journal } = await fixture(t);
  await journal.batchObserveAdmission([entry(1), entry(2)]);
  const before = await fsp.readFile(file, "utf8");
  for (const attempt of [[entry(1), entry(3)], [entry(1), entry(1)],
    [entry(1), { ...entry(2), digest: entry(77).digest }]]) {
    await assert.rejects(journal.batchMarkSeenRemoteOnly(attempt));
    assert.equal(await fsp.readFile(file, "utf8"), before);
  }
  await journal.batchMarkSeenRemoteOnly([entry(1), entry(2)]);
  await journal.batchMarkSeenRemoteOnly([entry(1), entry(2)]);
  const cold = await new SyncJournal(file).open();
  assert.deepEqual(cold.state.seen, [entry(1).operationId, entry(2).operationId]);
});

test("W22 inert batch markSeen EIO leaves entire observed window available for cold replay", async (t) => {
  const { file, journal } = await fixture(t);
  const items = [entry(1), entry(2)];
  await journal.batchObserveAdmission(items);
  const originalRename = fsp.rename;
  fsp.rename = async (...args) => args[1] === file
    ? Promise.reject(Object.assign(new Error("EIO"), { code: "EIO" }))
    : originalRename(...args);
  try { await assert.rejects(journal.batchMarkSeenRemoteOnly(items), { code: "EIO" }); }
  finally { fsp.rename = originalRename; }
  const reopened = await new SyncJournal(file).open();
  assert.equal(Object.keys(reopened.state.observed).length, 2);
  assert.equal(reopened.state.seen.length, 0);
  await reopened.batchMarkSeenRemoteOnly(items);
  assert.equal((await new SyncJournal(file).open()).state.seen.length, 2);
});
