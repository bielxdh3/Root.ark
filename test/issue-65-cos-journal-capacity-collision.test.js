"use strict";

// TEST_UNRUN until the exclusive Node22 gate permits filesystem tests.
// These are disposable, real fsync/rename-backed journal regressions.
const assert = require("node:assert/strict");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");

async function fixture(t) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-journal-collision-"));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "journal.json");
  return { filename, journal: await new SyncJournal(filename).open() };
}

function item(operationId, ciphertext = "same-ciphertext") {
  return {
    operationId,
    operation: "update",
    metadata: { path: "document.txt", owner: { deviceId: "device-1", revision: 4 } },
    ciphertext,
    authorization: { signature: "signed-envelope" },
  };
}

test("full 10000-entry journal rejects single enqueue without evicting earliest pending event", async (t) => {
  const { filename, journal } = await fixture(t);
  const full = Array.from({ length: 10000 }, (_, index) => ({ operationId: `queued-${index}` }));
  await journal.enqueueMany(full);
  const before = await fsp.readFile(filename);

  await assert.rejects(journal.enqueue({ operationId: "overflow-single" }),
    /Sync journal capacity exceeded/);
  assert.deepEqual(await fsp.readFile(filename), before,
    "capacity rejection must not change durable bytes");
  assert.deepEqual(journal.pending(), full,
    "earliest pending operation must remain available for retry");

  const recovered = await new SyncJournal(filename).open();
  assert.equal(recovered.pending().length, 10000);
  assert.equal(recovered.pending()[0].operationId, "queued-0");
  assert.equal(recovered.pending()[9999].operationId, "queued-9999");
  await journal.enqueue({ operationId: "queued-0" });
  assert.equal(journal.pending().length, 10000,
    "identical pending retry stays idempotent even at capacity");
});

test("single enqueue rejects different signed bytes under an existing pending operationId", async (t) => {
  const { filename, journal } = await fixture(t);
  const initial = item("same-id");
  await journal.enqueue(initial);
  const before = await fsp.readFile(filename);

  await assert.rejects(journal.enqueue(item("same-id", "different-ciphertext")),
    { code: "sync_journal_operation_conflict" });
  assert.deepEqual(await fsp.readFile(filename), before);
  assert.deepEqual((await new SyncJournal(filename).open()).pending(), [initial]);

  // Reordered object keys must not turn an identical signed envelope into a
  // false collision after it has passed through JSON storage.
  const sameReordered = {
    authorization: { signature: "signed-envelope" },
    ciphertext: "same-ciphertext",
    metadata: { owner: { revision: 4, deviceId: "device-1" }, path: "document.txt" },
    operation: "update",
    operationId: "same-id",
  };
  await journal.enqueue(sameReordered);
  assert.deepEqual(journal.pending(), [initial]);
});

test("batch pending-ID collision aborts all additions atomically and preserves replay", async (t) => {
  const { filename, journal } = await fixture(t);
  const original = item("batch-existing");
  await journal.enqueue(original);
  const before = await fsp.readFile(filename);

  await assert.rejects(journal.enqueueMany([
    item("batch-new"), item("batch-existing", "forged-different-payload"),
  ]), { code: "sync_journal_operation_conflict" });
  assert.deepEqual(await fsp.readFile(filename), before,
    "collision anywhere in batch cannot partially add a new pending operation");
  assert.deepEqual(journal.pending(), [original]);

  await journal.enqueueMany([item("batch-existing"), item("batch-new")]);
  assert.deepEqual((await new SyncJournal(filename).open()).pending(),
    [original, item("batch-new")]);
});
