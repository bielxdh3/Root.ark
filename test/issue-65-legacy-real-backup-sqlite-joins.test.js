"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const { MIGRATIONS } = require("../db/migrations");
const { createZipArchive } = require("../services/backupService");
const { inspectZk1LiveLegacyRecoverableArchiveGraph: inspect } =
  require("../src/services/zk1LiveLegacyRecoverableArchiveGraph");
const { signZk1LegacyArchiveReferentialProof } =
  require("../src/services/zk1LegacyArchiveReferentialProof");

const MODE = { dbEnabled: true, jsonReadFallback: false, jsonWriteMirror: false };
const ARCHIVE = "rootark-backup-2026-10-23-09-00-00.zip";
const ID = "archived-owner-recovery-fixture";
const NOW = "2026-10-23T09:00:00Z";
const ORIGINAL = "PRIVATE-ARCHIVED-SOURCE.bin";
const RETAINED = "data/trash/files/11223344-1234-4234-8234-123456789abc/trashed.bin";
const SOURCE = Buffer.from("private synthetic encrypted material");
const TRASH = Buffer.from("private synthetic trash data");

function make(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-real-backup-join-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const data = path.join(root, "data");
  const backup = path.join(data, "backups");
  fs.mkdirSync(backup, { recursive: true });
  const databasePath = path.join(data, "rootark.sqlite");
  const db = new DatabaseSync(databasePath);
  for (const migration of MIGRATIONS) migration.up(db);
  db.prepare("INSERT INTO folders (id,name,created_at,updated_at) VALUES (?,?,?,?)")
    .run("root", "Root", NOW, NOW);
  db.prepare("INSERT INTO file_versions (folder_id,file_name,versions_json,updated_at) VALUES (?,?,?,?)")
    .run("root", ORIGINAL, JSON.stringify({ currentVersion: 1, versions: [
      { version: 1, storedAs: ORIGINAL, size: SOURCE.length },
    ] }), NOW);
  db.prepare("INSERT INTO file_search_index VALUES (?,?)").run("root", ORIGINAL);
  db.prepare("INSERT INTO encrypted_files (folder_id,file_name,encryption_level,metadata_json,created_at,updated_at) VALUES (?,?,?,?,?,?)")
    .run("root", ORIGINAL, "full", "{}", NOW, NOW);
  db.prepare("INSERT INTO public_links (token,folder_id,file_name,metadata_json,created_at,expires_at) VALUES (?,?,?,?,?,?)")
    .run("synthetic-link", "root", ORIGINAL, "{}", NOW, NOW);
  db.prepare("INSERT INTO file_permissions (folder_id,file_name,allowed_users_json,created_at,updated_at) VALUES (?,?,?,?,?)")
    .run("root", ORIGINAL, "[]", NOW, NOW);
  db.prepare("INSERT INTO file_expirations (folder_id,file_name,expires_at,created_at) VALUES (?,?,?,?)")
    .run("root", ORIGINAL, NOW, NOW);
  db.prepare("INSERT INTO trash_items (id,item_type,original_file_name,trash_path,status,deleted_at,size_bytes) VALUES (?,?,?,?,?,?,?)")
    .run("trash-one", "file", ORIGINAL, RETAINED.slice("data/trash/".length), "trashed", NOW, TRASH.length);
  db.close();
  return { root, data, databasePath, backup: path.join(backup, ARCHIVE) };
}
function copies(f, options = {}) {
  const bytes = fs.readFileSync(f.databasePath);
  const result = [
    { entryPath: "data/rootark.sqlite", contents: bytes, size: bytes.length },
    { entryPath: "uploads/" + ORIGINAL, contents: SOURCE, size: SOURCE.length },
    { entryPath: RETAINED, contents: TRASH, size: TRASH.length },
  ];
  if (options.unmapped) result.push({ entryPath: "temp/derived/unindexed.bin",
    contents: Buffer.from("derived outside FTS"), size: 19 });
  if (options.omitSource) result.splice(1, 1);
  if (options.omitTrash) result.splice(result.findIndex((x) => x.entryPath === RETAINED), 1);
  if (options.orphanUpload) result.push({ entryPath: "uploads/unreferenced.bin",
    contents: Buffer.from("orphan"), size: 6 });
  if (options.alteredSameSizeSource) result[1] = { ...result[1],
    contents: Buffer.alloc(SOURCE.length, 0x61), size: SOURCE.length };
  return result;
}
async function build(f, options = {}) {
  const files = copies(f, options);
  const manifest = {
    backup_id: ID, type: "manual", created_at: NOW,
    persistence_mode: "sqlite", status: "success", cloud_complete: false,
    total_size: files.reduce((n, file) => n + file.contents.length, 0),
    included_files: files.map(({ entryPath, contents }) =>
      ({ path: entryPath, size: contents.length })),
  };
  // This is the real archive writer that the app uses, not an ad-hoc ZIP fixture.
  await createZipArchive(f.backup, manifest, files);
  const checksum = crypto.createHash("sha256").update(fs.readFileSync(f.backup)).digest("hex");
  const db = new DatabaseSync(f.databasePath);
  db.prepare("INSERT INTO backup_history (id,filename,type,status,created_at,checksum,metadata_json) VALUES (?,?,?,?,?,?,?)")
    .run(ID, ARCHIVE, "manual", "success", NOW, checksum, "{}");
  db.close();
}
function scan(f, options = {}) {
  return inspect({ optIn: true, databasePath: f.databasePath,
    backupDataDir: f.data, persistence: MODE, ...options });
}
test("real generated ZIP/SQLite historical joins need independent owner Ed25519 referential proof", async (t) => {
  const f = make(t);
  await build(f);
  const original = fs.readFileSync(f.backup);
  const unauthenticated = await scan(f);
  assert.equal(unauthenticated.historicalSqlite.status, "BOUNDED_JOINS_ONLY");
  assert.equal(unauthenticated.referentialAuthentication.status, "UNKNOWN");
  assert.equal(unauthenticated.referentialAuthentication.verifiedArchives, 0);
  assert.equal(unauthenticated.archiveEvidence.length, 1);
  const owner = crypto.generateKeyPairSync("ed25519");
  const signed = signZk1LegacyArchiveReferentialProof({
    evidence: unauthenticated.archiveEvidence[0], ownerPrivateKey: owner.privateKey });
  const checked = await scan(f, { pinnedArchiveReferentialPublicKey: owner.publicKey,
    signedArchiveReferentialProofs: [signed] });
  assert.equal(checked.referentialAuthentication.status, "AUTHENTICATED_BOUNDED_JOINS");
  assert.equal(checked.referentialAuthentication.verifiedArchives, 1);
  assert.equal(checked.referentialAuthentication.unresolvedArchives, 0);
  assert.equal(checked.referentialAuthentication.authorizesCutover, false);
  assert.equal(checked.canDeleteLegacy, false);
  assert.equal(checked.wholeCorpusVerified, false);
  assert.deepEqual(fs.readFileSync(f.backup), original);
  assert.equal(JSON.stringify(checked).includes(ORIGINAL), false);
  assert.equal(JSON.stringify(checked).includes(ID), false);
});

test("archive reissued with equal-size different ciphertext and updated live checksum cannot borrow old owner proof", async (t) => {
  const base = make(t);
  await build(base);
  const owner = crypto.generateKeyPairSync("ed25519");
  const baseline = await scan(base);
  const signed = signZk1LegacyArchiveReferentialProof({
    evidence: baseline.archiveEvidence[0], ownerPrivateKey: owner.privateKey });
  const replaced = make(t);
  await build(replaced, { alteredSameSizeSource: true });
  const independent = await scan(replaced);
  assert.equal(independent.historicalSqlite.status, "BOUNDED_JOINS_ONLY",
    "SQLite byte-size joins alone miss equal-size ciphertext substitution");
  const refused = await scan(replaced, { pinnedArchiveReferentialPublicKey: owner.publicKey,
    signedArchiveReferentialProofs: [signed] });
  assert.equal(refused.referentialAuthentication.status, "UNKNOWN");
  assert.equal(refused.referentialAuthentication.verifiedArchives, 0);
  assert.equal(refused.referentialAuthentication.unresolvedArchives, 1);
  assert.equal(refused.authorizesCutover, false);
  assert.equal(refused.canDeleteLegacy, false);
});

test("untrusted keys, missing proof, forged evidence and unresolved historical references fail closed", async (t) => {
  const f = make(t);
  await build(f);
  const original = await scan(f);
  const owner = crypto.generateKeyPairSync("ed25519");
  const attacker = crypto.generateKeyPairSync("ed25519");
  const valid = signZk1LegacyArchiveReferentialProof({
    evidence: original.archiveEvidence[0], ownerPrivateKey: owner.privateKey });
  const options = { pinnedArchiveReferentialPublicKey: owner.publicKey,
    signedArchiveReferentialProofs: [] };
  for (const proofs of [[], [{ ...valid, signature: (valid.signature[0] === "A" ? "B" : "A") + valid.signature.slice(1) }],
    [signZk1LegacyArchiveReferentialProof({ evidence: original.archiveEvidence[0],
      ownerPrivateKey: attacker.privateKey })]]) {
    const result = await scan(f, { ...options, signedArchiveReferentialProofs: proofs });
    assert.equal(result.referentialAuthentication.status, "UNKNOWN");
    assert.equal(result.authorizesCutover, false);
  }
  const wrongHistory = make(t);
  const db = new DatabaseSync(wrongHistory.databasePath);
  db.prepare("UPDATE trash_items SET size_bytes=?").run(TRASH.length + 7);
  db.close();
  await build(wrongHistory);
  const unproven = await scan(wrongHistory);
  const signedUnknown = signZk1LegacyArchiveReferentialProof({
    evidence: unproven.archiveEvidence[0], ownerPrivateKey: owner.privateKey });
  const denied = await scan(wrongHistory, { ...options,
    signedArchiveReferentialProofs: [signedUnknown] });
  assert.equal(denied.referentialAuthentication.status, "UNKNOWN");
  assert.equal(denied.historicalSqlite.status, "UNKNOWN");
  assert.equal(denied.canDeleteLegacy, false);
  assert.ok(denied.referentialAuthentication.unresolvedArchives > 0);

  // Even a valid owner signature on an incomplete archive cannot upgrade an
  // unjoined old version, FTS-derived reference and retention reference.
  const missingVersion = make(t);
  const history = new DatabaseSync(missingVersion.databasePath);
  history.prepare("UPDATE file_versions SET versions_json=? WHERE file_name=?")
    .run(JSON.stringify({ currentVersion: 2, versions: [
      { version: 1, storedAs: "old-revision-not-in-archive.bin", size: SOURCE.length },
      { version: 2, storedAs: ORIGINAL, size: SOURCE.length },
    ] }), ORIGINAL);
  history.close();
  await build(missingVersion);
  const candidate = await scan(missingVersion);
  const signedIncomplete = signZk1LegacyArchiveReferentialProof({
    evidence: candidate.archiveEvidence[0], ownerPrivateKey: owner.privateKey });
  const stillUnknown = await scan(missingVersion, { ...options,
    signedArchiveReferentialProofs: [signedIncomplete] });
  assert.equal(stillUnknown.referentialAuthentication.verifiedArchives, 1);
  assert.equal(stillUnknown.referentialAuthentication.status, "UNKNOWN");
  assert.equal(stillUnknown.referentialAuthentication.unresolvedArchives, 1);
  assert.equal(stillUnknown.historicalSqlite.joinedDerivedReferences, 0);
  assert.equal(stillUnknown.historicalSqlite.joinedRetentionReferences, 0);
  assert.equal(stillUnknown.canDeleteLegacy, false);
});
test("backupService-generated archive joins SQLite versions, FTS, retention, trash and metadata", async (t) => {
  const f = make(t);
  await build(f);
  const bytes = fs.readFileSync(f.backup);
  const report = await scan(f);
  const graph = report.historicalSqlite;
  assert.equal(graph.inspectedSnapshots, 1);
  assert.equal(graph.joinedVersionReferences, 1);
  assert.equal(graph.joinedDerivedReferences, 1);
  assert.equal(graph.joinedTrashReferences, 1);
  assert.equal(graph.joinedRetentionReferences, 1);
  assert.equal(graph.joinedMetadataReferences, 3);
  assert.equal(graph.unknownReferences, 0);
  assert.equal(graph.status, "BOUNDED_JOINS_ONLY");
  for (const flag of ["wholeCorpusVerified", "canDeleteLegacy", "authorizesCutover"])
    assert.equal(report[flag], false);
  for (const fragment of [ORIGINAL, RETAINED, ID, f.root])
    assert.equal(JSON.stringify(report).includes(fragment), false);
  assert.deepEqual(fs.readFileSync(f.backup), bytes, "archive was only read");
});
test("real backup with omitted referenced bytes marks UNKNOWN without a deletion grant", async (t) => {
  for (const type of ["omitSource", "omitTrash", "orphanUpload", "unmapped"]) {
    const f = make(t);
    await build(f, { [type]: true });
    const report = await scan(f);
    assert.equal(report.historicalSqlite.status, "UNKNOWN", type);
    assert.ok(report.historicalSqlite.unknownReferences > 0, type);
    assert.equal(report.authorizesCutover, false);
    assert.equal(report.canDeleteLegacy, false);
  }
});
test("altered archived SQLite metadata with current live database intact stays UNKNOWN", async (t) => {
  const f = make(t);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE file_versions SET versions_json=? WHERE file_name=?")
    .run(JSON.stringify({ currentVersion: 1, versions: [
      { version: 1, storedAs: "missing-in-archive.bin", size: 4 },
    ] }), ORIGINAL);
  db.close();
  await build(f);
  const report = await scan(f);
  assert.equal(report.historicalSqlite.joinedVersionReferences, 0);
  assert.ok(report.historicalSqlite.unknownReferences > 0);
  assert.equal(report.historicalSqlite.status, "UNKNOWN");
  assert.equal(report.wholeCorpusVerified, false);
});

test("archived in-flight upload and unfamiliar SQL table remain UNKNOWN even when ZIP is internally consistent", async (t) => {
  const f = make(t);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("INSERT INTO pending_uploads (id,file_name,folder_id,metadata_json) VALUES (?,?,?,?)")
    .run("pending-legacy", "encrypted-partial-upload.bin", "root", "{}");
  db.exec("CREATE TABLE newer_encrypted_legacy_refs(id TEXT PRIMARY KEY, source_path TEXT)");
  db.close();
  await build(f);
  // The live database still uses the supported schema, so the read-only outer
  // preflight succeeds. The unrecognized SQL schema exists in the ZIP only.
  const now = new DatabaseSync(f.databasePath);
  now.exec("DROP TABLE newer_encrypted_legacy_refs");
  now.close();
  const report = await scan(f);
  assert.equal(report.historicalSqlite.status, "UNKNOWN");
  assert.ok(report.historicalSqlite.unknownReferences >= 2);
  assert.equal(report.canDeleteLegacy, false);
  assert.equal(report.authorizesCutover, false);
});

test("no archived snapshots is UNKNOWN rather than vacuously a proven empty corpus", async (t) => {
  const f = make(t);
  const report = await scan(f);
  assert.equal(report.historicalSqlite.inspectedSnapshots, 0);
  assert.equal(report.historicalSqlite.status, "UNKNOWN");
  assert.ok(report.historicalSqlite.unknownReferences > 0);
  assert.equal(report.canDeleteLegacy, false);
});

test("a missing old revision poisons logical FTS, retention and encrypted-file joins", async (t) => {
  const f = make(t);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE file_versions SET versions_json=? WHERE file_name=?")
    .run(JSON.stringify({ currentVersion: 2, versions: [
      { version: 1, storedAs: "archived-v1-but-missing.bin", size: 17 },
      { version: 2, storedAs: ORIGINAL, size: SOURCE.length },
    ] }), ORIGINAL);
  db.close();
  await build(f);
  const graph = (await scan(f)).historicalSqlite;
  assert.equal(graph.joinedVersionReferences, 1);
  assert.equal(graph.joinedDerivedReferences, 0);
  assert.equal(graph.joinedRetentionReferences, 0);
  assert.equal(graph.joinedMetadataReferences, 0);
  assert.equal(graph.status, "UNKNOWN");
});

test("trash source with incorrect archived SQL size is not a recoverable join", async (t) => {
  const f = make(t);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE trash_items SET size_bytes=?").run(TRASH.length + 1);
  db.close();
  await build(f);
  const graph = (await scan(f)).historicalSqlite;
  assert.equal(graph.joinedTrashReferences, 0);
  assert.equal(graph.status, "UNKNOWN");
});
