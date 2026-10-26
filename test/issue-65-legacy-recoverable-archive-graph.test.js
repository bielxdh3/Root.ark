"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { once } = require("node:events");
const { ZipArchive } = require("archiver");
const { DatabaseSync } = require("node:sqlite");
const { MIGRATIONS } = require("../db/migrations");
const { inspectZk1LiveLegacyRecoverableArchiveGraph: inspect } =
  require("../src/services/zk1LiveLegacyRecoverableArchiveGraph");
const { withInodeGrowthAfterFstat } = require("./support/issue-65-inode-growth-race");

const MODE = { dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false };
const FILE = "SECRET-ARCHIVED-ENCRYPTED-FILE.dat";
const ARCHIVE = "rootark-backup-2026-10-23-09-00-00.zip";
const ID = "legacy-backup-id-1";
const DATA = Buffer.from("encrypted legacy source, for test only");
const TRASH = "data/trash/files/11223344-1234-4234-8234-123456789abc/old-private-file.bin";
const DERIVED = "temp/generated/derived-outside-search-index.bin";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "rootark-archive-graph-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dataDir = path.join(root, "data"), backupDir = path.join(dataDir, "backups");
  fs.mkdirSync(backupDir, { recursive: true });
  const databasePath = path.join(dataDir, "rootark.sqlite");
  const db = new DatabaseSync(databasePath);
  for (const migration of MIGRATIONS) migration.up(db);
  db.close();
  return { root, dataDir, backupDir, databasePath, archive: path.join(backupDir, ARCHIVE) };
}
function members(f) {
  return [
    { path: "data/rootark.sqlite", bytes: fs.readFileSync(f.databasePath) },
    { path: "uploads/" + FILE, bytes: DATA },
    { path: DERIVED, bytes: Buffer.from("derived artifact independent from FTS") },
    { path: TRASH, bytes: Buffer.from("historical trash payload") },
  ];
}
async function writeZip(file, manifest, entries) {
  const stream = fs.createWriteStream(file);
  const closed = once(stream, "close");
  const zip = new ZipArchive({ zlib: { level: 6 } });
  zip.pipe(stream);
  zip.append(Buffer.from(JSON.stringify(manifest)), { name: "backup-manifest.json" });
  for (const item of entries) zip.append(item.bytes, { name: item.path });
  await zip.finalize();
  await closed;
}
async function archive(f, entries = members(f), override = {}) {
  const manifest = {
    backup_id: ID, type: "manual", persistence_mode: "sqlite", status: "success",
    created_at: "2026-10-23T09:00:00Z",
    cloud_complete: false, total_size: entries.reduce((s, x) => s + x.bytes.length, 0),
    included_files: entries.map((x) => ({ path: x.path, size: x.bytes.length })),
    ...override,
  };
  await writeZip(f.archive, manifest, entries);
  const checksum = crypto.createHash("sha256").update(fs.readFileSync(f.archive)).digest("hex");
  const db = new DatabaseSync(f.databasePath);
  db.prepare("INSERT INTO backup_history (id,filename,type,status,created_at,checksum,metadata_json) VALUES (?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET checksum=excluded.checksum")
    .run(ID, ARCHIVE, "manual", "success", "2026-10-23T09:00:00Z", checksum, "{}");
  db.close();
}
function scan(f, extra = {}) {
  return inspect({ optIn: true, databasePath: f.databasePath,
    backupDataDir: f.dataDir, persistence: MODE, ...extra });
}
function rejected(f, extra) {
  return assert.rejects(scan(f, extra), /ZK_LEGACY_RECOVERABLE_GRAPH_UNVERIFIED/);
}

test("actual checksum-pinned ZIP graph observes archived uploads, non-FTS candidates and trash while forbidding cutover", async (t) => {
  const f = fixture(t);
  await archive(f);
  const before = fs.readFileSync(f.archive);
  const a = await scan(f), b = await scan(f);
  assert.equal(a.observation, "bounded-readonly-legacy-recoverable-archive-members");
  assert.equal(a.inspectedArchives, 1);
  assert.equal(a.archivedUploads, 1);
  assert.equal(a.archivedTempCandidates, 1);
  assert.equal(a.derivedOutsideFtsVerified, false);
  assert.equal(a.archivedTrash, 1);
  assert.equal(a.archiveMetadataAndState, 1);
  assert.equal(a.archiveMembers, 4);
  assert.equal(a.unresolvedBackupRows, 0);
  assert.notEqual(a.ephemeralFingerprint, b.ephemeralFingerprint);
  for (const key of ["sourceReferencesGloballyJoined", "protectedRecoveryVerified",
    "wholeCorpusVerified", "canDeleteLegacy", "authorizesCutover"])
    assert.equal(a[key], false);
  for (const secret of [FILE, TRASH, DERIVED, f.root, ID, ARCHIVE])
    assert.equal(JSON.stringify(a).includes(secret), false);
  assert.deepEqual(fs.readFileSync(f.archive), before);
});

test("broken manifest, missing member, unknown entry type and traversal fail closed", async (t) => {
  const attacks = [
    (f) => ({ entries: members(f), overrides: { included_files: [] } }),
    (f) => ({ entries: members(f), overrides: { total_size: 1 } }),
    (f) => ({ entries: members(f), overrides: { persistence_mode: "legacy" } }),
    (f) => ({ entries: members(f), overrides: { created_at: "2026-10-22T09:00:00Z" } }),
    (f) => ({ entries: members(f).filter((x) => x.path !== "data/rootark.sqlite") }),
    (f) => ({ entries: [...members(f), { path: "unknown-root/future.bin", bytes: DATA }] }),
    (f) => ({ entries: [...members(f), { path: "uploads/../hidden.bin", bytes: DATA }] }),
    (f) => ({ entries: [...members(f), { path: "uploads/SECRET-ARCHIVED-ENCRYPTED-FILE.dat", bytes: DATA }] }),
    (f) => ({ entries: [...members(f), { path: "uploads/secret-archived-encrypted-file.dat", bytes: DATA }] }),
  ];
  for (const mutate of attacks) {
    const f = fixture(t);
    const { entries, overrides } = mutate(f);
    await archive(f, entries, overrides);
    const before = fs.readFileSync(f.archive);
    await rejected(f);
    assert.deepEqual(fs.readFileSync(f.archive), before, "invalid backup was not modified");
  }
});

test("mismatched archive bytes, SQL checksum forgery and absent digest refuse", async (t) => {
  const f = fixture(t);
  await archive(f);
  fs.appendFileSync(f.archive, Buffer.from("unauthenticated suffix"));
  await rejected(f);
  await archive(f);
  let db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE backup_history SET checksum=? WHERE id=?").run("f".repeat(64), ID);
  db.close();
  await rejected(f);
  await archive(f);
  db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE backup_history SET checksum=NULL WHERE id=?").run(ID);
  db.close();
  await rejected(f);
});

test("renamed archive, unknown schema and invalid opt-in never produce recovery proof", async (t) => {
  const f = fixture(t);
  await archive(f);
  await rejected(f, { optIn: false });
  await rejected(f, { persistence: { ...MODE, jsonReadFallback: true } });
  await rejected(f, { backupDataDir: path.join(f.root, "missing") });
  const db = new DatabaseSync(f.databasePath);
  db.exec("CREATE TABLE hidden_legacy_recovery_reference(id TEXT PRIMARY KEY)");
  db.close();
  await rejected(f);
});

test("retained history with archive no longer present stays unresolved, never 'recovered'", async (t) => {
  const f = fixture(t);
  await archive(f);
  fs.renameSync(f.archive, f.archive + ".retention-tombstone");
  // A missing tombstone metadata pair itself is unverifiable and refused.
  await rejected(f);
  assert.equal(fs.existsSync(f.archive + ".retention-tombstone"), true);
});

test("valid retained tombstone is observed as unresolved history, never as recovered bytes", async (t) => {
  const f = fixture(t);
  await archive(f);
  const db = new DatabaseSync(f.databasePath, { readOnly: true });
  const history = db.prepare("SELECT checksum FROM backup_history WHERE id=?").get(ID);
  db.close();
  fs.renameSync(f.archive, f.archive + ".retention-tombstone");
  fs.writeFileSync(f.archive + ".retention-tombstone.json", JSON.stringify({
    backupId: ID, filename: ARCHIVE, checksum: history.checksum,
  }));
  const observed = await scan(f);
  assert.equal(observed.inspectedArchives, 0);
  assert.equal(observed.unresolvedBackupRows, 1);
  assert.equal(observed.backupRetentionTombstones, 1);
  assert.equal(observed.wholeCorpusVerified, false);
  assert.equal(observed.canDeleteLegacy, false);
  assert.equal(observed.authorizesCutover, false);
  assert.equal(fs.existsSync(f.archive + ".retention-tombstone"), true);
});

test("opt-in local non-FTS temp graph accounts for derived files absent from SQLite search index", async (t) => {
  const f = fixture(t);
  await archive(f);
  const temp = path.join(f.root, "temp");
  const derivedDir = path.join(temp, "generated");
  fs.mkdirSync(derivedDir, { recursive: true });
  fs.writeFileSync(path.join(derivedDir, "private-unindexed-derived.bin"), DATA);
  const a = await scan(f, { localTempDir: temp });
  const b = await scan(f);
  assert.equal(a.liveNonFtsDerived, 1);
  assert.equal(a.liveNonFtsDerivedInspected, true);
  assert.equal(b.liveNonFtsDerived, null);
  assert.equal(b.liveNonFtsDerivedInspected, false);
  assert.equal(a.wholeCorpusVerified, false);
  assert.equal(a.authorizesCutover, false);
  assert.equal(a.canDeleteLegacy, false);
  assert.equal(JSON.stringify(a).includes("private-unindexed-derived.bin"), false);
});

test("local derived root refuses unknown aliases, hardlinks and noncanonical directories", async (t) => {
  for (const attack of [
    (f, temp) => fs.linkSync(f.archive, path.join(temp, "hardlink.zip")),
    (f, temp) => fs.symlinkSync(f.archive, path.join(temp, "symlink.zip")),
    (f, temp) => fs.writeFileSync(path.join(temp, "over-limit.bin"), Buffer.alloc(16 * 1024 * 1024 + 1)),
  ]) {
    const f = fixture(t);
    await archive(f);
    const temp = path.join(f.root, "temp");
    fs.mkdirSync(temp);
    try { attack(f, temp); } catch (error) {
      if (["EPERM", "EACCES", "EINVAL", "ENOTSUP"].includes(error.code)) continue;
      throw error;
    }
    await rejected(f, { localTempDir: temp });
    assert.equal(fs.existsSync(f.archive), true);
  }
});

test("graph's second archive read cannot allocate inode growth beyond ZIP cap", async (t) => {
  const f = fixture(t);
  await archive(f);
  // The legacy preflight intentionally reads this ZIP first. Race only the
  // graph's SECOND descriptor open, so this tests its own readPinnedArchive.
  const observed = await withInodeGrowthAfterFstat({ target: f.archive,
    openOrdinal: 2, extraBytes: 33 * 1024 * 1024,
    run: () => rejected(f) });
  assert.equal(observed.attacked, true);
  assert.deepEqual(observed.numericFdReadLengths, [],
    "a renamed or enlarged graph archive must not allocate beyond its cap");
});
