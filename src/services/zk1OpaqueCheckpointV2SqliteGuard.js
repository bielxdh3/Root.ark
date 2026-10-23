"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const Database = require("better-sqlite3");
const { assertPrivateSqliteFile } = require("./zk1PrivateSqlitePath");

function assertSafeSqliteSidecars(filename, reject) {
  for (const suffix of ["-wal", "-shm", "-journal"]) {
    let stat;
    try { stat = fs.lstatSync(filename + suffix); }
    catch (error) {
      if (error.code === "ENOENT") continue;
      reject();
    }
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
      || (process.platform !== "win32"
        && (stat.uid !== process.getuid() || (stat.mode & 0o077)))) reject();
  }
}

// Opening a WAL-mode SQLite DB with readonly:true can still create WAL/SHM
// files on the source path. Probe a bounded, private copy of the DB and WAL;
// never hand SQLite an unverified external authority's original pathname.
function withReadonlySqliteSnapshot(filename, inspect, reject, maxBytes) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) reject();
  const initial = assertPrivateSqliteFile(filename);
  assertSafeSqliteSidecars(filename, reject);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-sqlite-probe-"));
  if (process.platform !== "win32") fs.chmodSync(scratch, 0o700);
  const dest = path.join(scratch, "snapshot.sqlite");
  let probe;
  try {
    let size = 0;
    for (const suffix of ["", "-wal"]) {
      const source = filename + suffix;
      if (suffix && !fs.existsSync(source)) continue;
      const stat = fs.lstatSync(source);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
        || (process.platform !== "win32"
          && (stat.uid !== process.getuid() || (stat.mode & 0o077)))) reject();
      size += stat.size;
      if (size < 1 || size > maxBytes) reject();
      fs.copyFileSync(source, dest + suffix, fs.constants.COPYFILE_EXCL);
      if (process.platform !== "win32") fs.chmodSync(dest + suffix, 0o600);
    }
    // A hot rollback journal cannot be verified from main DB+WAL alone.
    if (fs.existsSync(filename + "-journal")) reject();
    probe = new Database(dest, { readonly: true, fileMustExist: true });
    inspect(probe);
    const current = assertPrivateSqliteFile(filename);
    assertSafeSqliteSidecars(filename, reject);
    if (current.dev !== initial.dev || current.ino !== initial.ino) reject();
    return initial;
  } catch (_) { reject(); }
  finally {
    probe?.close();
    fs.rmSync(scratch, { force: true, recursive: true, maxRetries: 4 });
  }
}

// Only compare fixed, application-authored DDL. A same-name trigger attached
// to another table (or with a different WHEN/RAISE body) is not an authority.
function requireCheckpointV2Triggers(db, schema, expected, reject) {
  if (db.pragma("quick_check", { simple: true }) !== "ok") reject();
  const definitions = [...schema.matchAll(
    /CREATE TRIGGER IF NOT EXISTS ([a-z_]+)\s+BEFORE (?:INSERT|UPDATE|DELETE) ON ([a-z_]+)[\s\S]*?END;/g,
  )];
  if (definitions.length !== expected.length
    || new Set(definitions.map((match) => match[1])).size !== expected.length) reject();
  const lookup = db.prepare("SELECT type, tbl_name, sql FROM sqlite_master WHERE name=?");
  const canonical = (sql) => sql.trim()
    .replace(/^CREATE\s+TRIGGER\s+IF\s+NOT\s+EXISTS\s+/i, "CREATE TRIGGER ")
    .replace(/;$/, "")
    .replace(/\s+/g, " ");
  for (const [name, table] of expected) {
    const ddl = definitions.find((match) => match[1] === name && match[2] === table);
    const stored = lookup.get(name);
    if (!ddl || stored?.type !== "trigger" || stored.tbl_name !== table
      || typeof stored.sql !== "string"
      || canonical(stored.sql) !== canonical(ddl[0])) reject();
  }
}

module.exports = { assertSafeSqliteSidecars, requireCheckpointV2Triggers,
  withReadonlySqliteSnapshot };
