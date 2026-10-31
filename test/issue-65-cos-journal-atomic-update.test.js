"use strict";

// TEST_UNRUN: the exclusive Node22 gate is closed until NODE_COUNT === 0.
// True RED predecessor: SyncJournal.commit() formerly cloned only the pending
// array, retaining references to this.state.pending's entry objects. When
// SyncJournal.update() set an entry's phase, it changed live memory *before*
// durableWrite(), so a failed temporary-file open left memory at source-moved
// while a separately reopened journal still had prepared. The regression
// below fails on that former implementation; it needs no fake journal state.

const assert = require("node:assert/strict");
const fsp = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");

test("failed durable phase update preserves the exact in-memory and on-disk pre-transaction journal", {
  concurrency: false,
}, async (t) => {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), "rootark-journal-atomic-phase-"));
  t.after(() => fsp.rm(directory, { recursive: true, force: true }));
  const filename = path.join(directory, "journal.json");
  const journal = await new SyncJournal(filename).open();
  const original = {
    operationId: "phase-rollback-001",
    journalType: "webdav-mutation",
    kind: "put",
    phase: "prepared",
    path: "/document.txt",
    putBytes: 12,
    putSha256: "f".repeat(64),
  };
  await journal.enqueue(original);

  // Snapshot ONLY the committed journal. The real durableWrite path has
  // already created, fsynced and renamed the JSON file on disk.
  const beforeBytes = await fsp.readFile(filename);
  // IMPORTANT: enqueue() historically kept the caller's original object by
  // reference too. Do NOT compare against `original` after the fault: that
  // would let the predecessor bug mutate both actual and expected values,
  // producing a false GREEN. The disk JSON snapshot is detached evidence.
  const expectedPrepared = JSON.parse(beforeBytes.toString("utf8")).pending[0];
  assert.deepEqual(expectedPrepared, original);
  assert.deepEqual(journal.pending(), [expectedPrepared]);
  const openBeforeFault = fsp.open;
  let interceptedTarget = null;
  let injectedFailures = 0;
  const expectedPrefix = `${filename}.tmp-`;
  try {
    // A narrowly scoped fault on SyncJournal.durableWrite's own temporary
    // file, never on the journal's source records or on reopen/read paths.
    // The mutator must have run first, since commit awaits it before writing.
    fsp.open = async (file, flags, mode) => {
      if (typeof file === "string" && file.startsWith(expectedPrefix)
        && flags === "wx") {
        interceptedTarget = file;
        injectedFailures += 1;
        throw Object.assign(new Error("injected journal temporary open failure"), {
          code: "EACCES",
        });
      }
      return openBeforeFault(file, flags, mode);
    };
    await assert.rejects(journal.update(original.operationId, {
      phase: "source-moved",
    }), { code: "EACCES", message: "injected journal temporary open failure" });
  } finally {
    fsp.open = openBeforeFault;
  }

  assert.equal(injectedFailures, 1,
    "must reach exactly one actual durableWrite temporary-file open");
  assert.ok(interceptedTarget?.startsWith(expectedPrefix),
    "fault must target this journal only, not a preceding test/helper call");
  assert.deepEqual(journal.pending(), [expectedPrepared],
    "failed disk commit must NOT advance the phase in the live journal");
  assert.deepEqual(await fsp.readFile(filename), beforeBytes,
    "failed write must not replace or alter the durable journal bytes");

  const reopenedAfterFailure = await new SyncJournal(filename).open();
  assert.deepEqual(await reopenedAfterFailure.recover(), [expectedPrepared],
    "independent reopened real disk must still contain the prepared phase");

  // Fault removed. The same journal instance must remain usable; a genuine
  // successful fsync-backed update advances memory and independent disk state.
  await journal.update(original.operationId, { phase: "source-moved" });
  const updated = { ...expectedPrepared, phase: "source-moved" };
  assert.deepEqual(journal.pending(), [updated]);
  const reopenedAfterSuccess = await new SyncJournal(filename).open();
  assert.deepEqual(await reopenedAfterSuccess.recover(), [updated]);
  assert.notDeepEqual(await fsp.readFile(filename), beforeBytes,
    "successful update must durably replace the prior transaction bytes");
});
