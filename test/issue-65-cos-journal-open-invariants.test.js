"use strict";

// TEST_UNRUN: Node gate requires no other Node process and >=4096 MiB RAM.
// Each negative uses actual private persisted JSON and a fresh SyncJournal
// instance. No test changes the in-memory state to fake a corrupted disk.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

async function baseFixture(t) {
  const root = createPrivateAuthorityFixture("cos-journal-open-");
  t.after(() => fsp.rm(root, { recursive: true, force: true, maxRetries: 5 }));
  const filename = path.join(root, "journal.json");
  const journal = await new SyncJournal(filename).open();
  await journal.enqueue({ operationId: "pending-physical", phase: "prepared" });
  await journal.enqueue({ operationId: "seen-physical", phase: "prepared" });
  await journal.markSeen("seen-physical");
  const bytes = await fsp.readFile(filename);
  const state = JSON.parse(bytes);
  assert.equal(state.pending.length, 1);
  assert.deepEqual(state.seen, ["seen-physical"]);
  return { filename, state, bytes };
}

for (const scenario of [
  ["duplicate pending physical operation ID", (state) => {
    state.pending.push({ ...state.pending[0], phase: "source-moved" });
  }],
  ["duplicate seen acknowledgement ID", (state) => {
    state.seen.push(state.seen[0]);
  }],
  ["pending and seen for the same operation ID", (state) => {
    state.seen.push(state.pending[0].operationId);
  }],
  ["nonstring pending operation ID", (state) => {
    state.pending[0].operationId = { attacker: true };
  }],
  ["invalid pending entry", (state) => {
    state.pending.push(null);
  }],
  ["nonstring seen receipt", (state) => {
    state.seen.push({ operationId: "fake-seen" });
  }],
  ["unbounded seen observation array", (state) => {
    state.seen = Array.from({ length: 10001 }, (_, i) => "seen-" + i);
  }],
]) {
  test("fresh durable journal open rejects " + scenario[0], {
    timeout: 60000,
  }, async (t) => {
    const { filename, state } = await baseFixture(t);
    scenario[1](state);
    const poisoned = Buffer.from(JSON.stringify(state) + "\n", "utf8");
    const handle = await fsp.open(filename, "r+");
    try {
      await handle.truncate(0);
      await handle.writeFile(poisoned);
      await handle.sync();
    } finally {
      await handle.close();
    }
    const before = await fsp.readFile(filename);
    assert.deepEqual(before, poisoned);
    await assert.rejects(new SyncJournal(filename).open(),
      /Invalid sync journal/i,
      "malformed durable evidence must be refused before any mutation or replay");
    assert.deepEqual(await fsp.readFile(filename), before,
      "rejected open must preserve all original disk evidence for diagnosis");
  });
}

test("valid disjoint pending and seen durable IDs reopen exactly without repair", {
  timeout: 60000,
}, async (t) => {
  const { filename, bytes } = await baseFixture(t);
  const reopened = await new SyncJournal(filename).open();
  assert.deepEqual(reopened.pending(),
    [{ operationId: "pending-physical", phase: "prepared" }]);
  assert.equal(reopened.hasSeen("seen-physical"), true);
  assert.equal(reopened.hasSeen("pending-physical"), false);
  assert.deepEqual(await fsp.readFile(filename), bytes,
    "fresh open must not rewrite or touch intact journal bytes");
  assert.equal(fs.statSync(filename).isFile(), true);
});

test("new admissions refuse IDs that would make their own durable journal unreopenable", {
  timeout: 60000,
}, async (t) => {
  const { filename, bytes } = await baseFixture(t);
  const journal = await new SyncJournal(filename).open();
  const malformedIds = ["", "spaces not allowed", "has/slash", "../parent",
    "x".repeat(161), "__proto__/pollution"];
  for (const operationId of malformedIds) {
    await assert.rejects(journal.enqueue({ operationId, phase: "prepared" }),
      /valid journal operationId required/i);
    await assert.rejects(journal.enqueueMany([
      { operationId: "safe-candidate" },
      { operationId, phase: "prepared" },
    ]), /valid operationId/i);
  }
  assert.deepEqual(await fsp.readFile(filename), bytes,
    "rejected malformed admissions must not persist poison or partial batches");
  const recovered = await new SyncJournal(filename).open();
  assert.deepEqual(recovered.pending(),
    [{ operationId: "pending-physical", phase: "prepared" }]);
  assert.equal(recovered.hasSeen("seen-physical"), true);
});

for (const scenario of [
  ["empty signed witness batch", []],
  ["unsigned digest bytes", [{ operationId: "signed-id", digest: "broken-digest" }]],
  ["duplicate signed witness IDs", [
    { operationId: "same-id", digest: "a".repeat(64) },
    { operationId: "same-id", digest: "b".repeat(64) },
  ]],
  ["oversized signed witness batch", Array.from({ length: 5 }, (_, i) => ({
    operationId: "signed-" + i, digest: "a".repeat(64),
  }))],
  ["nonarray signed witness", { id: "fake", digest: "a".repeat(64) }],
]) {
  test("signed WebDAV journal witness rejects " + scenario[0] + " in memory and on fresh disk open", {
    timeout: 60000,
  }, async (t) => {
    const { filename, bytes, state } = await baseFixture(t);
    const journal = await new SyncJournal(filename).open();
    await assert.rejects(journal.update("pending-physical", {
      signedOutboxReceipts: scenario[1],
    }), /Invalid protected WebDAV signed receipt binding/i);
    assert.deepEqual(await fsp.readFile(filename), bytes);
    assert.deepEqual(journal.pending(), [{ operationId: "pending-physical", phase: "prepared" }]);

    // Tamper disk independently, then test a NEW instance; a runtime
    // rejection alone could otherwise give false-green cold-start safety.
    state.pending[0].signedOutboxReceipts = scenario[1];
    const poisoned = Buffer.from(JSON.stringify(state) + "\n");
    const handle = await fsp.open(filename, "r+");
    try {
      await handle.truncate(0);
      await handle.writeFile(poisoned);
      await handle.sync();
    } finally { await handle.close(); }
    await assert.rejects(new SyncJournal(filename).open(),
      /Invalid sync journal operationId partition/i);
    assert.deepEqual(await fsp.readFile(filename), poisoned,
      "invalid signed witness evidence must be preserved for manual diagnosis");
  });
}

test("update and replace refuse to persist invalid pending partitions or orphan signed receipts", {
  timeout: 60000,
}, async (t) => {
  const { filename, bytes } = await baseFixture(t);
  const journal = await new SyncJournal(filename).open();
  for (const attempt of [
    () => journal.update("pending-physical", { operationId: "seen-physical" }),
    () => journal.update("pending-physical", { operationId: "invalid/path" }),
    () => journal.replace("pending-physical", null),
    () => journal.replace("pending-physical", { operationId: "seen-physical" }),
  ]) {
    await assert.rejects(attempt(), /Invalid sync journal operationId partition/);
    assert.deepEqual(await fsp.readFile(filename), bytes,
      "invalid in-memory update may not publish unreopenable journal bytes");
    assert.deepEqual(journal.pending(), [{ operationId: "pending-physical", phase: "prepared" }]);
  }

  const signed = { operationId: "signed-pending", operation: "create",
    authorization: { signature: "test-only-signed-receipt" } };
  await journal.enqueue(signed);
  const signedBytes = await fsp.readFile(filename);
  const digest = journal.durableSignedReceiptDigest("signed-pending");
  assert.match(digest, /^[a-f0-9]{64}$/);
  await assert.rejects(journal.update("signed-pending", { operation: "delete" }),
    /Invalid durable signed outbox receipt journal/);
  assert.deepEqual(await fsp.readFile(filename), signedBytes);
  assert.equal(journal.durableSignedReceiptDigest("signed-pending"), digest);
  const reopened = await new SyncJournal(filename).open();
  assert.equal(reopened.durableSignedReceiptDigest("signed-pending"), digest);
});

test("signed receipt identities never resolve Object.prototype inherited properties", {
  timeout: 60000,
}, async (t) => {
  const { filename } = await baseFixture(t);
  let journal = await new SyncJournal(filename).open();
  for (const operationId of ["constructor", "toString", "__proto__"]) {
    const signed = { operationId, operation: "create",
      authorization: { signature: "inert-journal-test-only" } };
    await journal.enqueue(signed);
    const expected = journal.durableSignedReceiptDigest(operationId);
    assert.match(expected, /^[a-f0-9]{64}$/);
    journal = await new SyncJournal(filename).open();
    assert.equal(journal.durableSignedReceiptDigest(operationId), expected);
    await journal.markSeen(operationId);
    journal = await new SyncJournal(filename).open();
    assert.equal(journal.durableSignedReceiptDigest(operationId), expected,
      "signed seen receipt must remain exact after JSON.parse reopen");
  }
});

test("signed MOVE cannot persist a receipt without its physical content witness", {
  timeout: 60000,
}, async (t) => {
  const { filename, state, bytes } = await baseFixture(t);
  const journal = await new SyncJournal(filename).open();
  const receipts = [{ operationId: "signed-move", digest: "a".repeat(64) }];
  await assert.rejects(journal.update("pending-physical", {
    kind: "move", signedOutboxReceipts: receipts,
  }), /Invalid protected WebDAV signed receipt binding/);
  assert.deepEqual(await fsp.readFile(filename), bytes);

  // A separate cold-open failure proves that poisoned durable JSON cannot
  // be laundered through a fresh recovery process.
  state.pending[0] = { ...state.pending[0], kind: "move",
    signedOutboxReceipts: receipts };
  const poisoned = Buffer.from(JSON.stringify(state) + "\n");
  const handle = await fsp.open(filename, "r+");
  try {
    await handle.truncate(0);
    await handle.writeFile(poisoned);
    await handle.sync();
  } finally { await handle.close(); }
  await assert.rejects(new SyncJournal(filename).open(),
    /Invalid sync journal operationId partition/);
  assert.deepEqual(await fsp.readFile(filename), poisoned);

  // A fresh independent fixture exercises the valid complete pair.
  const second = await baseFixture(t);
  const valid = await new SyncJournal(second.filename).open();
  await valid.update("pending-physical", { kind: "move", signedOutboxReceipts: receipts,
    moveBytes: 123, moveSha256: "b".repeat(64) });
  const reopened = await new SyncJournal(second.filename).open();
  assert.deepEqual(reopened.pending()[0].signedOutboxReceipts, receipts);
  assert.equal(reopened.pending()[0].moveBytes, 123);
});

test("atomic DELETE+MOVE markSeenMany refuses partial ACK and durably acknowledges both in one commit", {
  timeout: 60000,
}, async (t) => {
  const { filename } = await baseFixture(t);
  const journal = await new SyncJournal(filename).open();
  await journal.enqueueMany([
    { operationId: "webdav-atomic-delete", operation: "delete" },
    { operationId: "webdav-atomic-move", operation: "move" },
  ]);
  const before = await fsp.readFile(filename);
  const first = { operationId: "webdav-atomic-delete", admittedDigest: "a".repeat(64) };
  const second = { operationId: "webdav-atomic-move", admittedDigest: "b".repeat(64) };
  for (const invalid of [
    [first], [first, first], [first, { operationId: "missing-companion" }],
    [first, { ...second, admittedDigest: "wrong" }],
  ]) {
    await assert.rejects(journal.markSeenMany(invalid),
      /Invalid atomic sync batch acknowledgement|requires both pending envelopes/);
    assert.deepEqual(await fsp.readFile(filename), before,
      "an invalid half-ACK cannot commit the first destructive operation alone");
  }
  await journal.markSeenMany([first, second]);
  const disk = await new SyncJournal(filename).open();
  assert.deepEqual(disk.pending(), [{ operationId: "pending-physical", phase: "prepared" }]);
  assert.equal(disk.hasSeen(first.operationId), true);
  assert.equal(disk.hasSeen(second.operationId), true);
  assert.equal(disk.hasLocalAdmission(first.operationId, first.admittedDigest), true);
  assert.equal(disk.hasLocalAdmission(second.operationId, second.admittedDigest), true);
});
