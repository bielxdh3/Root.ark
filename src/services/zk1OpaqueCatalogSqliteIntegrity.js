"use strict";

// SQLite's CREATE TRIGGER IF NOT EXISTS silently accepts a pre-existing
// trigger of the same name, even when it is attached to a different table.
// Validate the actual immutable guard before serving signed CAS receipts.
function requireImmutableTriggers(db, specifications, reject) {
  const lookup = db.prepare("SELECT type,tbl_name,sql FROM sqlite_master WHERE name=?");
  for (const [name, table, action] of specifications) {
    const row = lookup.get(name);
    const expected = new RegExp(
      `^CREATE\\s+TRIGGER\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?${name}`
      + `\\s+BEFORE\\s+${action}\\s+ON\\s+${table}\\s+BEGIN\\s+SELECT`
      + "\\s+RAISE\\s*\\(\\s*ABORT\\s*,\\s*'IMMUTABLE'\\s*\\)\\s*;\\s*END\\s*;?$", "i");
    if (row?.type !== "trigger" || row.tbl_name !== table
      || typeof row.sql !== "string" || !expected.test(row.sql.trim())) reject();
  }
}

module.exports = { requireImmutableTriggers };
