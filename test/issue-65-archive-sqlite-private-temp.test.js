"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { DatabaseSync } = require("node:sqlite");
const { inspectZk1LiveLegacyArchivedSqliteJoin: inspect } =
  require("../src/services/zk1LiveLegacyArchivedSqliteJoin");

function archived(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-historical-private-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const image = path.join(root, "archived.sqlite");
  const db = new DatabaseSync(image);
  db.exec(`
    CREATE TABLE file_versions(folder_id TEXT,file_name TEXT,versions_json TEXT);
    CREATE TABLE file_search_index(folder_id TEXT,file_name TEXT);
    CREATE TABLE file_expirations(folder_id TEXT,file_name TEXT);
    CREATE TABLE public_links(folder_id TEXT,file_name TEXT);
    CREATE TABLE encrypted_files(folder_id TEXT,file_name TEXT);
    CREATE TABLE file_permissions(folder_id TEXT,file_name TEXT);
    CREATE TABLE trash_items(status TEXT,item_type TEXT,trash_path TEXT,size_bytes INTEGER);
  `);
  const name = "old-version.ct", folder = "root";
  db.prepare("INSERT INTO file_versions VALUES (?,?,?)").run(folder, name,
    JSON.stringify({ versions: [{ version: 1, storedAs: name, size: 8 }] }));
  for (const table of ["file_search_index", "file_expirations", "public_links",
    "encrypted_files", "file_permissions"])
    db.prepare(`INSERT INTO ${table} VALUES (?,?)`).run(folder, name);
  const trashPath = "files/11223344-1234-4234-8234-123456789abc/trashed.ct";
  db.prepare("INSERT INTO trash_items VALUES (?,?,?,?)")
    .run("trashed", "file", trashPath, 9);
  db.close();
  return { image, sqliteBytes: fs.readFileSync(image),
    members: new Map([
      ["uploads/old-version.ct", { size: 8, digest: "synthetic" }],
      ["data/trash/" + trashPath, { size: 9, digest: "synthetic" }],
    ]) };
}

test("persisted historical versions, trash and links retain nonauthorizing joins across process restart", (t) => {
  const saved = archived(t);
  const first = inspect({ sqliteBytes: saved.sqliteBytes, members: saved.members });
  assert.equal(first.joinedVersionReferences, 1);
  assert.equal(first.joinedTrashReferences, 1);
  assert.equal(first.joinedMetadataReferences, 3);
  assert.equal(first.joinedDerivedReferences, 1);
  assert.equal(first.joinedRetentionReferences, 1);
  assert.equal(first.authorizesCutover, false);
  assert.equal(first.canDeleteLegacy, false);
  assert.equal(first.globallyComplete, false);
  const script = `const fs=require('node:fs');
    const { inspectZk1LiveLegacyArchivedSqliteJoin: inspect } =
      require('./src/services/zk1LiveLegacyArchivedSqliteJoin');
    const map=new Map([['uploads/old-version.ct',{size:8,digest:'synthetic'}],
      ['data/trash/files/11223344-1234-4234-8234-123456789abc/trashed.ct',
        {size:9,digest:'synthetic'}]]);
    const result=inspect({sqliteBytes:fs.readFileSync(process.env.ROOTARK_ARCHIVED_SQL),members:map});
    process.exit(result.joinedVersionReferences===1 && result.joinedTrashReferences===1
      && result.joinedMetadataReferences===3 && result.globallyComplete===false
      && result.authorizesCutover===false && result.canDeleteLegacy===false ? 0 : 9);`;
  const child = spawnSync(process.execPath, ["-e", script], {
    cwd: path.resolve(__dirname, ".."), encoding: "utf8", windowsHide: true,
    timeout: 20000, env: { ...process.env, ROOTARK_ARCHIVED_SQL: saved.image },
  });
  assert.equal(child.status, 0, "restart must preserve bounded real SQL joins: " + child.stderr);
  assert.deepEqual(fs.readFileSync(saved.image), saved.sqliteBytes,
    "archive source remains untouched across both observations");
});

test("POSIX refuses foreign-writable TEMP before any historical SQLite staging directory", {
  skip: process.platform === "win32",
}, (t) => {
  const saved = archived(t);
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-untrusted-archive-temp-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  fs.chmodSync(parent, 0o777); // Unlike root-owned sticky /tmp, any UID may replace children.
  const prior = process.env.TMPDIR, mkdtemp = fs.mkdtempSync;
  let created = 0;
  process.env.TMPDIR = parent;
  fs.mkdtempSync = function (prefix, ...args) {
    if (String(prefix).includes("zk1-archive-sql-")) created++;
    return mkdtemp.call(this, prefix, ...args);
  };
  try {
    assert.throws(() => inspect({ sqliteBytes: saved.sqliteBytes,
      members: saved.members }), /ZK_LEGACY_ARCHIVE_SQLITE_JOIN_UNVERIFIED/);
  } finally {
    fs.mkdtempSync = mkdtemp;
    if (prior === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = prior;
  }
  assert.equal(created, 0,
    "reject hostile parent before creating even an empty staging directory");
  assert.deepEqual(fs.readdirSync(parent), [], "no foreign-controlled staging remains");
});
