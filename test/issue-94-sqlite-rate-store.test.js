const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const SqliteSlidingWindowStore = require("../src/middlewares/sqliteSlidingWindowStore");

function withClock(t, start) {
  const originalNow = Date.now;
  const clock = { now: start };
  Date.now = () => clock.now;
  t.after(() => {
    Date.now = originalNow;
  });
  return clock;
}

// Hooks run in registration order, so each test shuts its stores down before removing the directory.
function createTempDatabase(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "issue-94-rate-"));
  return { directory, databasePath: path.join(directory, ".rate-limit.sqlite") };
}

function removeAfterStores(t, directory, stores) {
  t.after(() => {
    for (const store of stores) store.shutdown();
    fs.rmSync(directory, { recursive: true, force: true });
  });
}

test("sqlite chunk rate store applies the same sliding window as the in-memory store", (t) => {
  const clock = withClock(t, 1000);
  const { directory, databasePath } = createTempDatabase(t);
  const store = new SqliteSlidingWindowStore(databasePath, 2000, 2);
  removeAfterStores(t, directory, [store]);

  assert.deepEqual(store.increment("uploader"), { totalHits: 1, resetTime: new Date(3000) });
  clock.now = 2300;
  assert.deepEqual(store.increment("uploader"), { totalHits: 2, resetTime: new Date(3000) });

  clock.now = 3100;
  assert.deepEqual(store.increment("uploader"), { totalHits: 2, resetTime: new Date(4300) });
  assert.deepEqual(store.increment("uploader"), { totalHits: 3, resetTime: new Date(4300) });
  assert.deepEqual(store.get("uploader"), { totalHits: 2, resetTime: new Date(4300) });
  assert.deepEqual(store.get("someone-else"), undefined);
});

test("sqlite chunk rate store does not count rejected attempts and decrements the newest hit", (t) => {
  withClock(t, 5000);
  const { directory, databasePath } = createTempDatabase(t);
  const store = new SqliteSlidingWindowStore(databasePath, 60000, 1);
  removeAfterStores(t, directory, [store]);

  assert.equal(store.increment("account").totalHits, 1);
  assert.equal(store.increment("account").totalHits, 2);
  assert.equal(store.get("account").totalHits, 1);
  store.decrement("account");
  assert.equal(store.get("account"), undefined);
  assert.equal(store.increment("account").totalHits, 1);
  store.resetKey("account");
  assert.equal(store.get("account"), undefined);
});

test("two sqlite store instances on the same database file share counts like two processes", (t) => {
  withClock(t, 10000);
  const { directory, databasePath } = createTempDatabase(t);
  const first = new SqliteSlidingWindowStore(databasePath, 60000, 3);
  const second = new SqliteSlidingWindowStore(databasePath, 60000, 3);
  removeAfterStores(t, directory, [first, second]);

  assert.equal(first.increment("alice").totalHits, 1);
  assert.equal(second.increment("alice").totalHits, 2);
  assert.equal(first.increment("alice").totalHits, 3);
  assert.equal(second.increment("alice").totalHits, 4, "over-limit attempt is reported above the limit");
  assert.equal(first.get("alice").totalHits, 3, "rejected attempt is not stored");

  assert.equal(second.increment("bob").totalHits, 1, "keys stay isolated per account");
  first.resetKey("alice");
  assert.equal(second.get("alice"), undefined);
  assert.equal(second.get("bob").totalHits, 1);
});

test("sqlite chunk rate store expires hits after the window and sweeps them from the table", (t) => {
  const clock = withClock(t, 0);
  const { directory, databasePath } = createTempDatabase(t);
  const writer = new SqliteSlidingWindowStore(databasePath, 1000, 2);
  const reader = new SqliteSlidingWindowStore(databasePath, 1000, 2);
  removeAfterStores(t, directory, [writer, reader]);

  writer.increment("expiring");
  clock.now = 500;
  writer.increment("expiring");
  assert.equal(reader.increment("expiring").totalHits, 3, "second instance sees both hits and rejects at the limit");

  clock.now = 1200;
  assert.deepEqual(reader.get("expiring"), { totalHits: 1, resetTime: new Date(1500) });
  clock.now = 1600;
  assert.equal(reader.get("expiring"), undefined);
  assert.equal(writer.increment("expiring").totalHits, 1);

  clock.now = 5000;
  writer.sweep(clock.now);
  const rows = writer.open().prepare("SELECT COUNT(*) AS count FROM upload_chunk_rate_hits").get();
  assert.equal(rows.count, 0);
});
