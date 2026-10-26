"use strict";

// Disposable test child: hold an actual cross-process SQLite RESERVED writer
// lock while a virtual clock advances beyond the PG evidence 30-second TTL.
const fs = require("node:fs");
const Database = require("better-sqlite3");

const [database, acquired, advanced] = process.argv.slice(2);
if (![database, acquired, advanced].every((value) => typeof value === "string")) {
  process.exitCode = 2;
} else {
  const db = new Database(database);
  try {
    db.exec("BEGIN IMMEDIATE");
    fs.writeFileSync(acquired, "locked", { flag: "wx" });
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 650);
    fs.writeFileSync(advanced, "expired", { flag: "wx" });
    db.exec("COMMIT");
  } catch (_) {
    if (db.inTransaction) db.exec("ROLLBACK");
    process.exitCode = 1;
  } finally { db.close(); }
}
