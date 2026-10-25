"use strict";

// Disposable TEST authority only. A different SQLite database proves that the
// witness never reads its OWN restored database to authorize the recovery
// head. Production authority custody MUST be on an independently governed
// host/service and use the operator's durable synchronous CAS adapter.
const path = require("node:path");
const Database = require("better-sqlite3");
const ZERO = "0".repeat(64);

function createExternalRecoveryHeadFixture(filename, initialHead = {
  sequence: 0, lastHash: ZERO,
}) {
  if (typeof filename !== "string" || !path.isAbsolute(filename)) throw Error("FIXTURE_PATH");
  const db = new Database(filename);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = FULL");
  db.exec(`CREATE TABLE IF NOT EXISTS operator_recovery_floor (
    id INTEGER PRIMARY KEY CHECK(id=1),
    sequence INTEGER NOT NULL, last_hash TEXT NOT NULL);
  `);
  db.prepare("INSERT OR IGNORE INTO operator_recovery_floor"
    + " (id,sequence,last_hash) VALUES(1,?,?)").run(
      initialHead.sequence, initialHead.lastHash);
  let available = true;
  let failurePhase = null;
  let reads = 0;
  const read = () => {
    if (!available) throw Error("TEST_AUTHORITY_UNAVAILABLE");
    reads += 1;
    const row = db.prepare(
      "SELECT sequence,last_hash FROM operator_recovery_floor WHERE id=1").get();
    if (!row) throw Error("TEST_AUTHORITY_MISSING");
    return { sequence: row.sequence, lastHash: row.last_hash };
  };
  const authority = {
    loadHead: read,
    compareAndAdvance(expected, next) {
      if (!available) throw Error("TEST_AUTHORITY_UNAVAILABLE");
      if (!Number.isSafeInteger(expected?.sequence)
        || !Number.isSafeInteger(next?.sequence)
        || next.sequence !== expected.sequence + 1
        || !/^[a-f0-9]{64}$/.test(expected.lastHash)
        || !/^[a-f0-9]{64}$/.test(next.lastHash))
        throw Error("TEST_NON_MONOTONIC_EXTERNAL_CAS");
      if (failurePhase === "before") throw Error("TEST_EXTERNAL_CAS_DOWN");
      const n = db.transaction(() => db.prepare(
        "UPDATE operator_recovery_floor SET sequence=?,last_hash=?"
        + " WHERE id=1 AND sequence=? AND last_hash=?").run(
          next.sequence, next.lastHash, expected.sequence, expected.lastHash).changes);
      const changed = n.immediate();
      if (failurePhase === "after") throw Error("TEST_EXTERNAL_ACK_LOST");
      return changed === 1;
    },
  };
  return { authority, read, setAvailable(value) { available = value; },
    setFailurePhase(phase) { failurePhase = phase; },
    get reads() { return reads; }, close() { db.close(); } };
}

module.exports = { createExternalRecoveryHeadFixture };
