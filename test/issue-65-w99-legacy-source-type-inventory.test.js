"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const { MIGRATIONS } = require("../db/migrations");
const { inspectZk1LiveLegacyReferencePreflight: inspect } =
  require("../src/services/zk1LiveLegacyReferencePreflight");

const MODE = { dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false };
const SECRET_NAME = "PRIVATE-OWNER-ENCRYPTED-SOURCE.dat";
const ARCHIVE_NAME = "rootark-backup-2026-10-23-09-00-00.zip";
const PAYLOAD = Buffer.from("synthetic encrypted legacy fixture data");
const ARCHIVE = Buffer.from("synthetic archived legacy fixture data");

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-source-type-inventory-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dataDir = path.join(root, "data");
  const backupDir = path.join(dataDir, "backups");
  const uploadsDir = path.join(root, "uploads");
  fs.mkdirSync(backupDir, { recursive: true });
  fs.mkdirSync(uploadsDir);
  const databasePath = path.join(dataDir, "legacy.sqlite");
  const db = new DatabaseSync(databasePath);
  for (const migration of MIGRATIONS) migration.up(db);
  const now = "2026-10-23T09:00:00Z";
  db.prepare("INSERT INTO folders (id,name,created_at,updated_at) VALUES (?,?,?,?)")
    .run("root", "Root", now, now);
  db.prepare("INSERT INTO file_versions (folder_id,file_name,versions_json,updated_at) VALUES (?,?,?,?)")
    .run("root", SECRET_NAME, JSON.stringify({ currentVersion: 1,
      versions: [{ version: 1, storedAs: SECRET_NAME, size: PAYLOAD.length }] }), now);
  db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("root", SECRET_NAME);
  db.prepare("INSERT INTO encrypted_files (folder_id,file_name,encryption_level,metadata_json,created_at,updated_at) VALUES (?,?,?,?,?,?)")
    .run("root", SECRET_NAME, "full", "{}", now, now);
  db.prepare("INSERT INTO public_links (token,folder_id,file_name,metadata_json,created_at,expires_at) VALUES (?,?,?,?,?,?)")
    .run("fixture-link", "root", SECRET_NAME, "{}", now, "2026-11-01T00:00:00Z");
  db.prepare("INSERT INTO file_permissions (folder_id,file_name,allowed_users_json,created_at,updated_at) VALUES (?,?,?,?,?)")
    .run("root", SECRET_NAME, "[]", now, now);
  db.prepare("INSERT INTO file_expirations (folder_id,file_name,expires_at,created_at) VALUES (?,?,?,?)")
    .run("root", SECRET_NAME, "2026-11-01T00:00:00Z", now);
  db.prepare("INSERT INTO backup_history (id,filename,type,status,created_at,checksum,metadata_json) VALUES (?,?,?,?,?,?,?)")
    .run("archive-1", ARCHIVE_NAME, "manual", "success", now,
      crypto.createHash("sha256").update(ARCHIVE).digest("hex"), "{}");
  db.close();
  fs.writeFileSync(path.join(uploadsDir, SECRET_NAME), PAYLOAD);
  fs.writeFileSync(path.join(backupDir, ARCHIVE_NAME), ARCHIVE);
  return { root, dataDir, backupDir, uploadsDir, databasePath };
}

function scan(f, changes = {}) {
  return inspect({ optIn: true, databasePath: f.databasePath, persistence: MODE,
    backupDataDir: f.dataDir, localUploadsDir: f.uploadsDir, sqlCoverageOptIn: true,
    strictSourceInventoryOptIn: true, ...changes });
}
function refuse(f) {
  assert.throws(() => scan(f), /ZK_LIVE_LEGACY_INVENTORY_UNAVAILABLE/);
}

test("strict inventory reconciles encrypted sources, derived index, links, permissions, expiry and archives", (t) => {
  const f = fixture(t);
  const originalArchive = fs.readFileSync(path.join(f.backupDir, ARCHIVE_NAME));
  const a = scan(f), b = scan(f);
  const proof = a.legacy.sourceInventory;
  assert.equal(proof.observation, "bounded-reconciled-local-source-types-only");
  assert.deepEqual(proof.local, {
    versionRows: 1, historicalPayloads: 1, derivedSearchReferences: 1,
    unmappedLocalFiles: 0, encryptedFiles: 1, publicLinks: 1,
    filePermissions: 1, retention: 1,
  });
  assert.equal(proof.backupHistoryRows, 1);
  assert.equal(proof.archiveFiles, 1);
  assert.equal(proof.sqlTablesRecognized, true);
  for (const status of ["externalReferencesVerified", "derivedOutsideSearchIndexVerified",
    "ownerSignedCorpusProofVerified", "globallyComplete", "authorizesCutover", "canDeleteLegacy"])
    assert.equal(proof[status], false);
  for (const status of ["wholeCorpusVerified", "authorizesCutover", "canDeleteLegacy"])
    assert.equal(a[status], false);
  assert.notEqual(a.legacy.localReferenceEvidence.ephemeralFingerprint,
    b.legacy.localReferenceEvidence.ephemeralFingerprint);
  for (const secret of [SECRET_NAME, ARCHIVE_NAME, f.root, f.databasePath])
    assert.equal(JSON.stringify(a).includes(secret), false);
  assert.deepEqual(fs.readFileSync(path.join(f.backupDir, ARCHIVE_NAME)), originalArchive);
});

test("orphan encrypted, derived and retained source references all fail closed", (t) => {
  const cases = [
    (f, db) => db.prepare("UPDATE encrypted_files SET file_name=?").run("orphan-encrypted-file"),
    (f, db) => db.prepare("UPDATE public_links SET file_name=?").run("orphan-public-link"),
    (f, db) => db.prepare("UPDATE file_permissions SET file_name=?").run("orphan-permission"),
    (f, db) => db.prepare("UPDATE file_expirations SET file_name=?").run("orphan-retention"),
    (f, db) => db.prepare("UPDATE file_search_index SET file_name=?").run("orphan-derived-search"),
    (f, db) => db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("root", "unversioned-derived"),
    (f, db) => db.prepare("INSERT INTO pending_uploads (id,file_name,folder_id,metadata_json) VALUES (?,?,?,?)")
      .run("pending-1", "staged-secret", "root", "{}"),
    (f, db) => db.prepare("INSERT INTO trash_items (id,item_type,original_file_name,status,deleted_at) VALUES (?,?,?,?,?)")
      .run("trashed-1", "file", SECRET_NAME, "trashed", "2026-10-23T09:00:00Z"),
    (f, db) => db.exec("CREATE TABLE unrecognized_legacy_source(id TEXT PRIMARY KEY)"),
  ];
  for (const mutate of cases) {
    const f = fixture(t);
    const db = new DatabaseSync(f.databasePath);
    mutate(f, db);
    db.close();
    const before = fs.readFileSync(f.databasePath);
    refuse(f);
    assert.deepEqual(fs.readFileSync(f.databasePath), before, "no SQLite mutation");
    assert.equal(fs.existsSync(path.join(f.uploadsDir, SECRET_NAME)), true);
  }
});
