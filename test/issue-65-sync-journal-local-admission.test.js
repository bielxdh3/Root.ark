"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { SyncJournal } = require("../sync-client/rootark-sync-journal");

test("legacy operation-ID-only seen lists never become authenticated admission pins", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-observed-journal-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "journal.json");
  await fs.writeFile(file, JSON.stringify({ version: 1, pending: [], seen: ["old-op"] }));
  const restored = await new SyncJournal(file).open();
  const digest = "a".repeat(64);
  assert.equal(restored.hasSeen("old-op"), true);
  assert.equal(restored.hasLocalAdmission("old-op", digest), false,
    "an unsigned legacy seen ID never proves a historical server admission");
  await restored.markSeen("old-op", digest);
  assert.equal(restored.hasLocalAdmission("old-op", digest), true);
  assert.equal(restored.hasLocalAdmission("old-op", "b".repeat(64)), false);
  const rebooted = await new SyncJournal(file).open();
  assert.equal(rebooted.hasLocalAdmission("old-op", digest), true,
    "an exact local pre-expiry observation survives journal restart");
  await assert.rejects(rebooted.markSeen("old-op", "b".repeat(64)),
    /Conflicting local sync admission evidence/);
  const afterConflict = await new SyncJournal(file).open();
  assert.equal(afterConflict.hasLocalAdmission("old-op", digest), true,
    "a conflicting same-ID pin cannot rewrite a durable prior observation");
});

test("truncated or mismatched local historical observations fail closed on restart", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-observed-corrupt-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "journal.json");
  const malformed = [
    { version: 1, pending: [], seen: ["op"], admitted: { op: "short" } },
    { version: 1, pending: [], seen: [], admitted: { op: "a".repeat(64) } },
    { version: 1, pending: [], seen: ["op"], admitted: [] },
    { version: 1, pending: [], seen: [], admitted: {}, observed: { op: "short" } },
    { version: 1, pending: [], seen: ["op"], admitted: { op: "a".repeat(64) },
      observed: { op: "b".repeat(64) } },
  ];
  for (const value of malformed) {
    await fs.writeFile(file, JSON.stringify(value));
    await assert.rejects(new SyncJournal(file).open(),
      /Invalid previously (admitted|observed) sync envelope journal/);
  }
});

test("pre-observation is durable before completion and cannot be reassigned", async (t) => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "rootark-preobserved-journal-"));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, "journal.json");
  const digest = "a".repeat(64);
  const journal = await new SyncJournal(file).open();
  await journal.observeAdmission("signed-op", digest);
  assert.equal(journal.hasSeen("signed-op"), false,
    "a pre-observed envelope is never falsely marked as applied");
  assert.equal((await new SyncJournal(file).open()).hasLocalAdmission("signed-op", digest), true);
  await assert.rejects(journal.observeAdmission("signed-op", "b".repeat(64)),
    /Conflicting local sync admission evidence/);
  await journal.markSeen("signed-op", digest);
  const restored = await new SyncJournal(file).open();
  assert.equal(restored.hasSeen("signed-op"), true);
  assert.equal(restored.hasLocalAdmission("signed-op", digest), true);
  assert.equal(Object.hasOwn(restored.state.observed, "signed-op"), false,
    "completion transfers the observation into the applied admission map");
});
