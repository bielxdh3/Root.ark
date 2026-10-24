"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { indexedDbJournalStore } = require("../public/client/rootark-zk1-browser-opaque-catalog-commit");
const { strictIndexedDB } = require("./support/issue-65-strict-indexeddb-fixture");

test("opaque catalog pre-PUT journal rejects browsers that ignore strict durability", async () => {
  const db = strictIndexedDB({ refuseStrict: true });
  const store = indexedDbJournalStore(db);
  await assert.rejects(store.write("nonce", { body: { kind: "intent" }, signature: "signed" }),
    /journal strict transaction unavailable/);
  assert.equal(db.writes, 0, "no journal write may be accepted without strict durability");
  assert.equal(db.values.size, 0);
});

test("opaque catalog pre-PUT journal accepts and reads strict committed intent", async () => {
  const db = strictIndexedDB();
  const store = indexedDbJournalStore(db);
  const record = { body: { kind: "intent" }, signature: "signed" };
  await store.write("nonce", record);
  assert.deepEqual(await store.read("nonce"), record);
  assert.equal(db.writes, 1);
});
