"use strict";

// TEST_UNRUN: requires exclusive Node22 gate (NODE_COUNT=0, free RAM>=4096MiB).
// Journal-only tests use real fsync/rename and a fresh independent disk reopen.
// A fixture authorization marker is intentionally NOT a claim of Ed25519
// verification; production protected ingress verifies signatures separately.
const test = require("node:test");
const assert = require("node:assert/strict");
const fsp = require("node:fs/promises");
const path = require("node:path");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");
const { createPrivateAuthorityFixture } =
  require("./support/issue-65-private-authority-fixture");

async function fixture(t) {
  const root = createPrivateAuthorityFixture("cos-journal-seen-");
  t.after(() => fsp.rm(root, { recursive: true, force: true, maxRetries: 5 }));
  const filePath = path.join(root, "outbox.json");
  return { filePath, journal: await new SyncJournal(filePath).open() };
}

function signed(operationId, payload = "one") {
  return {
    operationId,
    operation: "update",
    metadata: { path: "doc.enc", size: payload.length },
    ciphertext: payload,
    authorization: { signature: "TEST_ONLY_UNVERIFIED_SIGNATURE" },
  };
}

test("an unsigned historical seen-only ID cannot silently suppress a new signed mutation", {
  timeout: 60000,
}, async (t) => {
  const { filePath, journal } = await fixture(t);
  await journal.enqueue({ operationId: "old-unsigned" });
  await journal.markSeen("old-unsigned");
  const previousBytes = await fsp.readFile(filePath);

  await assert.rejects(journal.enqueue(signed("old-unsigned")), {
    code: "sync_journal_operation_conflict",
  });
  assert.deepEqual(await fsp.readFile(filePath), previousBytes);
  const reopened = await new SyncJournal(filePath).open();
  assert.deepEqual(reopened.pending(), []);
  assert.equal(reopened.hasSeen("old-unsigned"), true);
  assert.equal(reopened.hasDurableSignedReceipt("old-unsigned"), false,
    "a legacy seen-only ID is not independent proof of signed admission");
});

test("a signed seen receipt accepts only the byte-identical envelope on single retry", {
  timeout: 60000,
}, async (t) => {
  const { filePath, journal } = await fixture(t);
  const original = signed("signed-seen", "first");
  await journal.enqueue(original);
  await journal.markSeen(original.operationId);
  const before = await fsp.readFile(filePath);
  assert.equal(journal.hasDurableSignedReceipt(original.operationId), true);
  await journal.enqueue({ ...original, metadata: { size: 5, path: "doc.enc" } });
  assert.deepEqual(await fsp.readFile(filePath).then(JSON.parse), JSON.parse(before),
    "exact canonical signed retry remains idempotent");
  await assert.rejects(journal.enqueue(signed("signed-seen", "other")), {
    code: "sync_journal_operation_conflict",
  });
  await assert.rejects(journal.enqueue({ operationId: "signed-seen" }), {
    code: "sync_journal_operation_conflict",
  });
  assert.deepEqual(await fsp.readFile(filePath), before,
    "failed or identical signed retries never alter original receipt bytes");
  const reopened = await new SyncJournal(filePath).open();
  assert.equal(reopened.hasDurableSignedReceipt(original.operationId), true);
  assert.deepEqual(reopened.pending(), []);
});

test("batch seen-ID mismatch cannot partially persist unrelated new signed events", {
  timeout: 60000,
}, async (t) => {
  const { filePath, journal } = await fixture(t);
  await journal.enqueue({ operationId: "old-batch-unsigned" });
  await journal.markSeen("old-batch-unsigned");
  const before = await fsp.readFile(filePath);
  await assert.rejects(journal.enqueueMany([
    signed("new-batch-physical"),
    signed("old-batch-unsigned"),
  ]), { code: "sync_journal_operation_conflict" });
  assert.deepEqual(await fsp.readFile(filePath), before);
  const reopened = await new SyncJournal(filePath).open();
  assert.deepEqual(reopened.pending(), []);
  assert.equal(reopened.hasDurableSignedReceipt("new-batch-physical"), false);
  assert.equal(reopened.hasSeen("old-batch-unsigned"), true);
});

test("single and batch input envelopes cannot mutate committed in-memory pending after enqueue", {
  timeout: 60000,
}, async (t) => {
  const { filePath, journal } = await fixture(t);
  const one = signed("detached-single");
  const two = signed("detached-batch", "two");
  await journal.enqueue(one);
  await journal.enqueueMany([two]);
  const before = await fsp.readFile(filePath);
  one.metadata.path = "FORGED_ONE";
  one.authorization.signature = "FORGED_ONE_SIGNATURE";
  two.metadata.path = "FORGED_TWO";
  two.authorization.signature = "FORGED_TWO_SIGNATURE";
  assert.deepEqual(journal.pending(),
    [signed("detached-single"), signed("detached-batch", "two")]);
  assert.deepEqual(await fsp.readFile(filePath), before);
  assert.deepEqual((await new SyncJournal(filePath).open()).pending(), journal.pending());
  assert.equal(journal.hasDurableSignedReceipt("detached-single"), true);
  assert.equal(journal.hasDurableSignedReceipt("detached-batch"), true);
});

test("nested patch objects cannot change the in-memory durable phase after update completes", {
  timeout: 60000,
}, async (t) => {
  const { filePath, journal } = await fixture(t);
  await journal.enqueue({ operationId: "detached-update", phase: "prepared" });
  const witness = { identity: { ino: "13", dev: "7", type: "file" } };
  await journal.update("detached-update", { phase: "source-moved", witness });
  const before = await fsp.readFile(filePath);
  witness.identity.ino = "999999";
  witness.identity.dev = "999";
  assert.deepEqual(journal.pending(),
    [{ operationId: "detached-update", phase: "source-moved",
      witness: { identity: { ino: "13", dev: "7", type: "file" } } }]);
  assert.deepEqual(await fsp.readFile(filePath), before);
  assert.deepEqual((await new SyncJournal(filePath).open()).pending(), journal.pending());
});

test("read-only pending/recover snapshots cannot mutate nested signed or physical journal witnesses", {
  timeout: 60000,
}, async (t) => {
  const { filePath, journal } = await fixture(t);
  const envelope = signed("detached-reader");
  envelope.metadata.identity = { dev: "5", ino: "17", type: "file" };
  await journal.enqueue(envelope);
  const diskBefore = await fsp.readFile(filePath);
  const exported = journal.pending();
  const recovered = await journal.recover();
  assert.deepEqual(exported, [envelope]);
  assert.deepEqual(recovered, [envelope]);
  exported[0].metadata.path = "REPLACED_BY_CALLER";
  exported[0].metadata.identity.ino = "999999";
  exported[0].authorization.signature = "INJECTED_CALLER_SIGNATURE";
  recovered[0].ciphertext = "INJECTED_CALLER_CIPHERTEXT";
  recovered[0].metadata.identity.dev = "888";
  assert.deepEqual(journal.pending(), [envelope]);
  assert.deepEqual((await new SyncJournal(filePath).open()).pending(), [envelope]);
  assert.deepEqual(await fsp.readFile(filePath), diskBefore);
  assert.equal(journal.hasDurableSignedReceipt(envelope.operationId), true);
});
