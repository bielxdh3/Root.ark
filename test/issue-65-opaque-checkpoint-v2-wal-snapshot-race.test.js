"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { withReadonlySqliteSnapshot } =
  require("../src/services/zk1OpaqueCheckpointV2SqliteGuard");

test("readonly preflight fails closed if live WAL advances after the snapshot read", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-v2-wal-race-"));
  if (process.platform !== "win32") fs.chmodSync(dir, 0o700);
  t.after(() => {
    if (live.open) live.close();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 4 });
  });
  const file = path.join(dir, "authority.sqlite");
  const live = new Database(file);
  live.pragma("journal_mode=WAL");
  live.pragma("wal_autocheckpoint=0");
  live.exec("CREATE TABLE samples (token BLOB NOT NULL)");
  live.prepare("INSERT INTO samples VALUES (?)").run(crypto.randomBytes(64));
  assert.equal(fs.existsSync(file + "-wal"), true);
  let inspected = false;
  assert.throws(() => withReadonlySqliteSnapshot(file, (copy) => {
    assert.equal(copy.prepare("SELECT count(*) AS count FROM samples").get().count, 1);
    inspected = true;
    // A legitimate concurrent writer produces a newer consistent WAL while
    // the preflight is still deciding whether the captured state is trusted.
    live.prepare("INSERT INTO samples VALUES (?)").run(crypto.randomBytes(64));
  }, () => { throw new Error("WAL_SNAPSHOT_CHANGED"); }, 4 * 1024 * 1024),
  /WAL_SNAPSHOT_CHANGED/);
  assert.equal(inspected, true);
  assert.equal(live.prepare("SELECT count(*) AS count FROM samples").get().count, 2);
});
