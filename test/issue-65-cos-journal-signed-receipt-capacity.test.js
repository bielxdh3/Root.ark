"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncJournal, durableWrite } = require("../sync-client/rootark-sync-journal");
const { canonicalJson } = require("../sync-client/rootark-sync-protocol");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

function signed(operationId, ciphertext = "original") {
  return { operationId, operation: "update", ciphertext,
    authorization: { signature: "TEST_ONLY_UNVERIFIED_SIGNATURE" } };
}

function digest(operation) {
  return crypto.createHash("sha256").update(canonicalJson(operation)).digest("hex");
}

async function seededJournal(t, pendingCount = 0) {
  const directory = createPrivateAuthorityFixture("cos-journal-receipt-capacity-");
  t.after(() => fsp.rm(directory, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(directory, "journal.json");
  const state = { version: 1, pending: [], seen: [], admitted: {}, observed: {},
    committedSigned: Object.create(null), atomicSignedGroups: {} };
  for (let index = 0; index < 10000; index += 1) {
    const operation = signed(`completed-${index}`);
    state.seen.push(operation.operationId);
    state.committedSigned[operation.operationId] = digest(operation);
  }
  for (let index = 0; index < pendingCount; index += 1) {
    const operation = signed(`queued-${index}`);
    state.pending.push(operation);
    state.committedSigned[operation.operationId] = digest(operation);
  }
  await durableWrite(filename, state);
  return { filename, state };
}

test("10k completed signed receipts survive reopen and permit a new signed enqueue", {
  timeout: 60000,
}, async (t) => {
  const { filename, state } = await seededJournal(t);
  let journal = await new SyncJournal(filename).open();
  assert.deepEqual(journal.pending(), []);
  assert.equal(journal.hasSeen("completed-0"), true);
  assert.equal(journal.hasDurableSignedReceipt("completed-9999"), true);

  const historicalBytes = await fsp.readFile(filename);
  await journal.enqueue(signed("completed-0"));
  await assert.rejects(journal.enqueue(signed("completed-0", "forged")), {
    code: "sync_journal_operation_conflict",
  });
  assert.deepEqual(await fsp.readFile(filename), historicalBytes,
    "a historical signed replay may neither change nor erase persisted evidence");

  const operation = signed("new-after-10000");
  await journal.enqueue(operation);
  assert.deepEqual(journal.pending(), [operation]);
  assert.equal(journal.hasDurableSignedReceipt(operation.operationId), true);
  journal = await new SyncJournal(filename).open();
  assert.deepEqual(journal.pending(), [operation]);
  assert.equal(journal.hasDurableSignedReceipt(operation.operationId), true);
  await assert.rejects(journal.enqueue(signed(operation.operationId, "forged")), {
    code: "sync_journal_operation_conflict",
  });

  await journal.markSeen(operation.operationId);
  journal = await new SyncJournal(filename).open();
  const persisted = JSON.parse(await fsp.readFile(filename, "utf8"));
  assert.equal(persisted.seen.length, 10000);
  assert.deepEqual(persisted.seen, [...state.seen.slice(1), operation.operationId]);
  assert.equal(Object.keys(persisted.committedSigned).length, 10000);
  assert.equal(journal.hasSeen("completed-0"), false);
  assert.equal(journal.hasDurableSignedReceipt("completed-0"), false);
  assert.equal(journal.hasDurableSignedReceipt(operation.operationId), true);
});

test("10k signed history and 10k signed pending receipts fit without evicting work", {
  timeout: 60000,
}, async (t) => {
  const { filename } = await seededJournal(t, 9999);
  let journal = await new SyncJournal(filename).open();
  const operation = signed("queued-last");
  await journal.enqueue(operation);
  const before = await fsp.readFile(filename);
  assert.equal(journal.pending().length, 10000);
  assert.equal(journal.hasDurableSignedReceipt(operation.operationId), true);
  assert.equal(Object.keys(JSON.parse(before).committedSigned).length, 20000);
  await assert.rejects(journal.enqueue(signed("queued-overflow")),
    /Sync journal capacity exceeded/);
  assert.deepEqual(await fsp.readFile(filename), before);
  journal = await new SyncJournal(filename).open();
  assert.equal(journal.pending().length, 10000);
  assert.equal(journal.pending()[0].operationId, "queued-0");
  assert.deepEqual(journal.pending()[9999], operation);
  assert.equal(journal.hasDurableSignedReceipt("queued-0"), true);
  assert.equal(journal.hasDurableSignedReceipt("completed-9999"), true);
});

test("reopen rejects tampered pending signed receipt beyond the 10k history window", {
  timeout: 60000,
}, async (t) => {
  const { filename } = await seededJournal(t);
  const journal = await new SyncJournal(filename).open();
  await journal.enqueue(signed("new-pending"));
  const state = JSON.parse(await fsp.readFile(filename, "utf8"));
  state.committedSigned["new-pending"] = "a".repeat(64);
  await fsp.writeFile(filename, JSON.stringify(state));
  const tampered = await fsp.readFile(filename);
  await assert.rejects(new SyncJournal(filename).open(),
    /Invalid durable signed outbox receipt journal/);
  assert.deepEqual(await fsp.readFile(filename), tampered,
    "failed cold open may not repair or rewrite hostile signed evidence");
});
