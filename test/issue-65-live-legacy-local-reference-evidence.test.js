"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { DatabaseSync } = require("node:sqlite");
const { inspectZk1LiveLegacyReferencePreflight: inspect } =
  require("../src/services/zk1LiveLegacyReferencePreflight");
const { MIGRATIONS } = require("../db/migrations");
const { withInodeGrowthAfterFstat } = require("./support/issue-65-inode-growth-race");

const MODE = { dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false };
const PRIVATE_NAME = "PRIVATE-LEGACY-DO-NOT-EXPORT.txt";
const PRIVATE_ARCHIVE = `${PRIVATE_NAME}.v1`;
const PAYLOAD = Buffer.from("local test-only historic version bytes");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-local-ref-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const uploadsDir = path.join(root, "uploads");
  const child = path.join(uploadsDir, "folder-a");
  fs.mkdirSync(child, { recursive: true });
  const databasePath = path.join(root, "legacy.sqlite");
  const db = new DatabaseSync(databasePath);
  db.exec(`
    CREATE TABLE folders(id TEXT PRIMARY KEY, name TEXT);
    CREATE TABLE file_versions(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, versions_json TEXT);
    CREATE TABLE backup_history(id TEXT PRIMARY KEY, filename TEXT, type TEXT, status TEXT, metadata_json TEXT);
    CREATE TABLE trash_items(id TEXT PRIMARY KEY, item_type TEXT, status TEXT, original_file_name TEXT, trash_path TEXT, metadata_json TEXT, restore_metadata_json TEXT);
    CREATE TABLE public_links(token TEXT PRIMARY KEY, folder_id TEXT, file_name TEXT, revoked_at TEXT, metadata_json TEXT);
    CREATE VIRTUAL TABLE file_search_index USING fts5(folder_id UNINDEXED, file_name, tokenize = 'trigram case_sensitive 0');
    CREATE TABLE file_expirations(id INTEGER PRIMARY KEY, folder_id TEXT, file_name TEXT, expires_at TEXT);
  `);
  db.prepare("INSERT INTO folders VALUES (?,?)").run("folder-a", "Private Folder");
  db.prepare("INSERT INTO file_versions VALUES (?,?,?,?)").run(1, "folder-a", PRIVATE_NAME, JSON.stringify({
    currentVersion: 2,
    versions: [{ version: 1, storedAs: PRIVATE_ARCHIVE, size: PAYLOAD.length },
      { version: 2, storedAs: PRIVATE_NAME, size: PAYLOAD.length }],
  }));
  db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("folder-a", PRIVATE_NAME);
  db.close();
  fs.writeFileSync(path.join(child, PRIVATE_ARCHIVE), PAYLOAD);
  fs.writeFileSync(path.join(child, PRIVATE_NAME), PAYLOAD);
  return { root, uploadsDir, child, databasePath, history: path.join(child, PRIVATE_ARCHIVE),
    current: path.join(child, PRIVATE_NAME) };
}
function scan(f, overrides = {}) {
  return inspect({ optIn: true, persistence: MODE, databasePath: f.databasePath,
    localUploadsDir: f.uploadsDir, ...overrides });
}
function denied(f, overrides) {
  assert.throws(() => scan(f, overrides), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
}

test("opt-in real SQLite derived index and historical-version bytes yield only partial opaque local evidence", (t) => {
  const f = fixture(t);
  const before = [fs.readFileSync(f.databasePath), fs.readFileSync(f.current), fs.readFileSync(f.history)];
  const first = scan(f), second = scan(f);
  const data = first.legacy.localReferenceEvidence;
  assert.equal(data.observation, "partial-local-legacy-file-references-only");
  assert.deepEqual([data.versions, data.versionPayloads, data.derivedSearchReferences, data.localFiles, data.unmappedLocalFiles],
    [1, 2, 1, 2, 0]);
  assert.equal(data.globallyComplete, false);
  assert.notEqual(data.ephemeralFingerprint, second.legacy.localReferenceEvidence.ephemeralFingerprint);
  for (const key of ["canDeleteLegacy", "authorizesCutover", "wholeCorpusVerified", "snapshotOwnerSigned"])
    assert.equal(first[key], false);
  const text = JSON.stringify(first);
  for (const secret of [PRIVATE_NAME, PRIVATE_ARCHIVE, f.root, f.uploadsDir, "Private Folder"])
    assert.equal(text.includes(secret), false);
  assert.deepEqual([fs.readFileSync(f.databasePath), fs.readFileSync(f.current), fs.readFileSync(f.history)], before);
  const uninspected = scan(f, { localUploadsDir: undefined });
  assert.deepEqual(uninspected.legacy.localReferenceEvidence,
    { observation: "uninspected", globallyComplete: false });
});

test("unknown/extra local files remain countable and never turn into complete evidence", (t) => {
  const f = fixture(t);
  fs.writeFileSync(path.join(f.uploadsDir, "unindexed-file.txt"), "unregistered legacy file");
  const evidence = scan(f).legacy.localReferenceEvidence;
  assert.equal(evidence.unmappedLocalFiles, 1);
  assert.equal(evidence.globallyComplete, false);
});

test("missing derived target, lost historical bytes and stale SQL rollback refuse", (t) => {
  for (const attack of [
    (f) => fs.rmSync(f.history),
    (f) => fs.rmSync(f.current),
    (f) => { const db = new DatabaseSync(f.databasePath); db.exec("UPDATE file_search_index SET file_name = 'absent-index.txt'"); db.close(); },
    (f) => { const db = new DatabaseSync(f.databasePath); db.prepare("UPDATE file_versions SET versions_json = ?").run(JSON.stringify({
      currentVersion: 1, versions: [{ version: 1, storedAs: "lost-rollback.v1" }],
    })); db.close(); },
    (f) => { const db = new DatabaseSync(f.databasePath); db.prepare("UPDATE file_versions SET versions_json = ?").run(JSON.stringify({
      currentVersion: 2, versions: [{ version: 1, storedAs: PRIVATE_ARCHIVE }, { version: 2, storedAs: "../escape" }],
    })); db.close(); },
    (f) => { const db = new DatabaseSync(f.databasePath); db.prepare("UPDATE file_versions SET versions_json = ?").run(JSON.stringify({
      currentVersion: 2, versions: [{ version: 1, storedAs: PRIVATE_NAME }, { version: 2, storedAs: PRIVATE_NAME }],
    })); db.close(); },
    (f) => { const db = new DatabaseSync(f.databasePath); db.prepare("UPDATE file_versions SET versions_json = ?").run(JSON.stringify({
      currentVersion: 2, versions: [{ version: 1, storedAs: PRIVATE_NAME }, { version: 2, storedAs: PRIVATE_ARCHIVE }],
    })); db.close(); },
    (f) => { const db = new DatabaseSync(f.databasePath); db.exec("INSERT INTO file_search_index VALUES ('unknown-folder', 'phantom')"); db.close(); },
  ]) {
    const f = fixture(t);
    attack(f);
    const before = fs.readFileSync(f.databasePath);
    denied(f);
    assert.deepEqual(fs.readFileSync(f.databasePath), before);
  }
});

test("symlink, directory redirect, hardlink and unknown descendant refuse without touching source", (t) => {
  for (const attack of [
    (f) => fs.linkSync(f.current, path.join(f.child, "unindexed-hardlink.txt")),
    (f) => fs.mkdirSync(path.join(f.child, "unexpected-subdirectory")),
    (f) => fs.mkdirSync(path.join(f.uploadsDir, "unrecognized-folder")),
    (f) => fs.symlinkSync(f.current, path.join(f.child, "dangling-alias.txt")),
    (f) => {
      const alias = path.join(f.root, "uploads-alias");
      fs.symlinkSync(f.uploadsDir, alias, process.platform === "win32" ? "junction" : "dir");
      return alias;
    },
  ]) {
    const f = fixture(t);
    try {
      const alternate = attack(f);
      denied(f, alternate ? { localUploadsDir: alternate } : {});
      assert.equal(fs.existsSync(f.current), true);
    } catch (error) {
      if (!["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) throw error;
    }
  }
});

test("late same-name inode replacement is caught by final local identity recheck", (t) => {
  const f = fixture(t);
  const original = fs.lstatSync;
  let hits = 0;
  fs.lstatSync = function (name, ...args) {
    if (String(name) === f.current && ++hits === 3) {
      const replacement = f.current + ".swap";
      fs.writeFileSync(replacement, PAYLOAD);
      fs.renameSync(replacement, f.current);
    }
    return original.call(this, name, ...args);
  };
  try { denied(f); assert.ok(hits >= 3); }
  finally { fs.lstatSync = original; }
});

test("explicit local root must be absolute, present, and bounded", (t) => {
  const f = fixture(t);
  for (const localUploadsDir of ["./uploads", path.join(f.root, "absent"), null])
    denied(f, { localUploadsDir });
  fs.writeFileSync(f.history, Buffer.alloc(32 * 1024 * 1024 + 1));
  denied(f);
});

test("full migrated SQLite, real backup archive and real derived/version files combine without cutover proof", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-combined-preflight-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dataDir = path.join(root, "data");
  const backupDir = path.join(dataDir, "backups");
  const uploadsDir = path.join(root, "uploads");
  fs.mkdirSync(backupDir, { recursive: true });
  fs.mkdirSync(uploadsDir);
  const databasePath = path.join(dataDir, "rootark.sqlite");
  const db = new DatabaseSync(databasePath);
  for (const migration of MIGRATIONS) migration.up(db);
  const timestamp = "2026-10-23T09:00:00Z";
  db.prepare("INSERT INTO folders (id,name,created_at,updated_at) VALUES (?,?,?,?)")
    .run("root", "Root", timestamp, timestamp);
  db.prepare("INSERT INTO file_versions (folder_id,file_name,versions_json,updated_at) VALUES (?,?,?,?)")
    .run("root", PRIVATE_NAME, JSON.stringify({
      currentVersion: 1, versions: [{ version: 1, storedAs: PRIVATE_NAME, size: PAYLOAD.length }],
    }), timestamp);
  db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("root", PRIVATE_NAME);
  const backupName = "rootark-backup-2026-10-23-09-00-00.zip";
  const backupBytes = Buffer.from("fake archive synthetic bytes");
  db.prepare("INSERT INTO backup_history (id,filename,type,status,created_at,checksum) VALUES (?,?,?,?,?,?)")
    .run("b-1", backupName, "manual", "success", timestamp,
      crypto.createHash("sha256").update(backupBytes).digest("hex"));
  db.close();
  fs.writeFileSync(path.join(uploadsDir, PRIVATE_NAME), PAYLOAD);
  const archive = path.join(backupDir, backupName);
  fs.writeFileSync(archive, backupBytes);
  const args = { optIn: true, databasePath, persistence: MODE, backupDataDir: dataDir,
    sqlCoverageOptIn: true, localUploadsDir: uploadsDir };
  const report = inspect(args);
  assert.equal(report.legacy.backupEvidence.archives, 1);
  assert.equal(report.legacy.sqlCoverage.unrecognizedTables, 0);
  assert.equal(report.legacy.localReferenceEvidence.derivedSearchReferences, 1);
  assert.equal(report.authorizesCutover, false);
  assert.equal(report.wholeCorpusVerified, false);
  assert.equal(report.legacy.coverage, "partial");
  const opaque = JSON.stringify(report);
  for (const marker of [PRIVATE_NAME, backupName, root, dataDir, uploadsDir])
    assert.equal(opaque.includes(marker), false);
  fs.writeFileSync(archive, "tampered archive bytes");
  assert.throws(() => inspect(args), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
  fs.writeFileSync(archive, backupBytes);
  fs.rmSync(path.join(uploadsDir, PRIVATE_NAME));
  assert.throws(() => inspect(args), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
});

test("legacy uploaded version never allocates bytes grown after descriptor fstat", async (t) => {
  const f = fixture(t);
  const observed = await withInodeGrowthAfterFstat({ target: f.current,
    extraBytes: 33 * 1024 * 1024,
    run: () => denied(f) });
  assert.equal(observed.attacked, true);
  assert.deepEqual(observed.numericFdReadLengths, [],
    "a mutable upload cannot trigger an unbounded descriptor allocation");
});
