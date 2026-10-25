"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { DatabaseSync } = require("node:sqlite");
const archiver = require("archiver");
const unzipper = require("unzipper");
const { MIGRATIONS } = require("../db/migrations");
const { inspectZk1LegacyEvidenceManifest: inspect } =
  require("../src/services/zk1LegacyEvidenceManifest");

const sha = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex");
const payload = Buffer.from("fixture ciphertext bytes \0 stored");
const old = Buffer.from("version-one ciphertext");
const trashBytes = Buffer.from("trashed previous generation");
const zipData = Buffer.from("separate backup content");
const now = "2026-10-25T00:00:00Z";
const backupName = "rootark-backup-2026-10-25-00-00-00.zip";

async function archive(filename) {
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(filename);
    const zip = archiver("zip", { zlib: { level: 5 } });
    output.on("close", resolve);
    output.on("error", reject);
    zip.on("error", reject);
    zip.pipe(output);
    zip.append(zipData, { name: "uploads/nested/copied.bin" });
    zip.append(Buffer.from("historical reference"), { name: "data/archived.json" });
    zip.append(JSON.stringify({ included_files: [
      { path: "uploads/nested/copied.bin", size: zipData.length },
      { path: "data/archived.json", size: 20 },
    ] }), { name: "backup-manifest.json" });
    zip.finalize().catch(reject);
  });
}

async function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "zk65-deterministic-manifest-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dirs = Object.fromEntries(["uploads", "temp", "trash", "backups", "data"]
    .map((item) => [item, path.join(root, item)]));
  for (const dir of Object.values(dirs)) fs.mkdirSync(dir);
  fs.mkdirSync(path.join(dirs.uploads, "nested"));
  fs.mkdirSync(path.join(dirs.temp, "preview", "documents"), { recursive: true });
  fs.mkdirSync(path.join(dirs.trash, "files", "trash-1"), { recursive: true });
  fs.writeFileSync(path.join(dirs.uploads, "nested", "source.bin"), payload);
  fs.writeFileSync(path.join(dirs.uploads, "nested", "old-version.bin"), old);
  fs.writeFileSync(path.join(dirs.temp, "preview", "documents", "derived.png"), "preview");
  fs.writeFileSync(path.join(dirs.trash, "files", "trash-1", "trash.bin"), trashBytes);
  const zipFile = path.join(dirs.backups, backupName);
  await archive(zipFile);
  const databasePath = path.join(dirs.data, "rootark.sqlite");
  const db = new DatabaseSync(databasePath);
  for (const migration of MIGRATIONS) migration.up(db);
  db.prepare("INSERT INTO folders(id,name,created_at,updated_at) VALUES (?,?,?,?)")
    .run("nested", "Nested", now, now);
  db.prepare("INSERT INTO file_versions(folder_id,file_name,versions_json,updated_at) VALUES (?,?,?,?)")
    .run("nested", "source.bin", JSON.stringify({ currentVersion: 2, versions: [
      { version: 1, storedAs: "old-version.bin", size: old.length },
      { version: 2, storedAs: "source.bin", size: payload.length },
    ] }), now);
  db.prepare("INSERT INTO file_search_index(folder_id,file_name) VALUES (?,?)")
    .run("nested", "source.bin");
  db.prepare("INSERT INTO encrypted_files(folder_id,file_name,encryption_level,created_at,updated_at) VALUES (?,?,?,?,?)")
    .run("nested", "source.bin", "full", now, now);
  db.prepare("INSERT INTO public_links(token,folder_id,file_name,created_at,expires_at) VALUES (?,?,?,?,?)")
    .run("signed-ref", "nested", "source.bin", now, now);
  db.prepare("INSERT INTO file_expirations(folder_id,file_name,expires_at,created_at) VALUES (?,?,?,?)")
    .run("nested", "source.bin", now, now);
  db.prepare("INSERT INTO trash_items(id,item_type,trash_path,status,deleted_at,size_bytes) VALUES (?,?,?,?,?,?)")
    .run("trash-1", "file", "files/trash-1/trash.bin", "trashed", now, trashBytes.length);
  db.prepare("INSERT INTO backup_history(id,filename,type,status,created_at,checksum) VALUES (?,?,?,?,?,?)")
    .run("backup-1", backupName, "manual", "success", now, sha(fs.readFileSync(zipFile)));
  db.close();
  return { ...dirs, databasePath, root, zipFile };
}
function scan(f) {
  return inspect({ optIn: true, databasePath: f.databasePath, uploadsDir: f.uploads,
    tempDir: f.temp, trashDir: f.trash, backupsDir: f.backups });
}
function section(report, name) { return report.sections[name]; }

test("real SQLite, nested revisions, trash, preview and ZIP produce repeatable byte evidence", async (t) => {
  const f = await fixture(t);
  const before = fs.readFileSync(f.databasePath);
  const a = await scan(f), b = await scan(f);
  assert.deepEqual(a, b);
  assert.equal(a.schema, "rootark-zk1-legacy-evidence-manifest/v1");
  assert.equal(a.readOnly, true);
  assert.equal(a.status, "UNKNOWN");
  assert.equal(a.wholeCorpusVerified, false);
  assert.equal(a.canDeleteLegacy, false);
  assert.equal(a.authorizesCutover, false);
  for (const key of ["sqlite", "uploads", "temp", "trash", "backups",
    "versions", "links", "derivedIndex", "retention", "encryptedMetadata"])
    assert.equal(section(a, key).status, "PROVEN", key);
  assert.equal(section(a, "versions").count, 2);
  assert.equal(section(a, "trash").count, 1);
  assert.ok(a.entries.some((item) => item.source === "uploads" && item.sha256 === sha(payload)));
  assert.ok(a.entries.some((item) => item.source === "backup-member" && item.sha256 === sha(zipData)));
  assert.equal(fs.readFileSync(f.databasePath).equals(before), true);
  for (const sensitive of ["source.bin", "old-version.bin", f.root, "signed-ref", backupName])
    assert.equal(JSON.stringify(a).includes(sensitive), false, sensitive);
  const hash = a.manifestSha256;
  assert.match(hash, /^[a-f0-9]{64}$/);
});

test("missing revision, stale link and unavailable trash custody stay UNKNOWN with unchanged files", async (t) => {
  for (const mutate of [
    (f) => fs.unlinkSync(path.join(f.uploads, "nested", "old-version.bin")),
    (f) => { const db = new DatabaseSync(f.databasePath); db.exec("UPDATE public_links SET file_name='missing.bin'"); db.close(); },
    (f) => { const db = new DatabaseSync(f.databasePath); db.exec("UPDATE trash_items SET status='restored'"); db.close(); },
  ]) {
    const f = await fixture(t);
    mutate(f);
    const before = fs.readFileSync(f.databasePath);
    const report = await scan(f);
    assert.equal(report.status, "UNKNOWN");
    assert.equal(report.canDeleteLegacy, false);
    assert.equal(report.authorizesCutover, false);
    assert.ok(Object.values(report.sections).some((section) => section.status === "UNKNOWN"));
    assert.deepEqual(fs.readFileSync(f.databasePath), before);
  }
});

test("symlink, SQLite journal and corrupted archive never produce PROVEN for their sources", async (t) => {
  const f = await fixture(t);
  const link = path.join(f.uploads, "nested", "alias.bin");
  let linked = false;
  try { fs.symlinkSync(path.join(f.uploads, "nested", "source.bin"), link); linked = true; }
  catch (error) { if (!["EPERM", "EACCES"].includes(error.code)) throw error; }
  if (linked) {
    const report = await scan(f);
    assert.equal(section(report, "uploads").status, "UNKNOWN");
    assert.equal(section(report, "versions").status, "UNKNOWN");
    fs.unlinkSync(link);
  }
  fs.writeFileSync(f.databasePath + "-journal", Buffer.from("inflight-transaction"));
  const journal = await scan(f);
  assert.equal(section(journal, "sqlite").status, "UNKNOWN");
  assert.equal(section(journal, "versions").status, "UNKNOWN");
  fs.unlinkSync(f.databasePath + "-journal");
  fs.appendFileSync(f.zipFile, Buffer.from("corrupt-zip"));
  const corrupted = await scan(f);
  assert.equal(section(corrupted, "backups").status, "UNKNOWN");
  assert.equal(corrupted.canDeleteLegacy, false);
});

test("asynchronous ZIP inflation cannot certify a concurrent rewrite of a prior local scan", async (t) => {
  const f = await fixture(t);
  const original = unzipper.Open.buffer;
  let mutated = false;
  unzipper.Open.buffer = async (...args) => {
    if (!mutated) {
      mutated = true;
      fs.writeFileSync(path.join(f.uploads, "nested", "source.bin"),
        Buffer.from("replaced while archive was being inspected"));
    }
    return original.apply(unzipper.Open, args);
  };
  try {
    const report = await scan(f);
    assert.equal(mutated, true);
    assert.equal(section(report, "uploads").status, "UNKNOWN");
    assert.equal(section(report, "versions").status, "UNKNOWN");
    assert.equal(report.entries.some((item) => item.source === "uploads"), false);
    assert.equal(report.canDeleteLegacy, false);
  } finally { unzipper.Open.buffer = original; }
});

test("restore of archived ZIP bytes is observed but cannot grant an unversioned restored source custody", async (t) => {
  const f = await fixture(t);
  const archiveBefore = fs.readFileSync(f.zipFile);
  const zip = await unzipper.Open.buffer(archiveBefore);
  const historical = zip.files.find((item) => item.path === "uploads/nested/copied.bin");
  assert.ok(historical);
  fs.writeFileSync(path.join(f.uploads, "nested", "copied.bin"), await historical.buffer());
  const report = await scan(f);
  assert.equal(section(report, "backups").status, "PROVEN");
  assert.equal(section(report, "backupMembers").status, "PROVEN");
  assert.equal(section(report, "versions").status, "UNKNOWN");
  assert.ok(report.entries.some((item) => item.sha256 === sha(zipData)));
  assert.equal(report.status, "UNKNOWN");
  assert.equal(fs.readFileSync(f.zipFile).equals(archiveBefore), true);
});

test("unknown SQL tables, pending uploads, and ambiguous hardlinks fail closed", async (t) => {
  const f = await fixture(t);
  const db = new DatabaseSync(f.databasePath);
  db.exec("CREATE TABLE unexpected_recoverable_content(id TEXT PRIMARY KEY, payload BLOB)");
  db.close();
  const report = await scan(f);
  assert.equal(section(report, "sqlite").status, "UNKNOWN");
  assert.equal(section(report, "versions").status, "UNKNOWN");
  const other = await fixture(t);
  const pending = new DatabaseSync(other.databasePath);
  pending.prepare("INSERT INTO pending_uploads(id,file_name,folder_id) VALUES (?,?,?)")
    .run("inflight-1", "pending.bin", "nested");
  pending.close();
  assert.equal(section(await scan(other), "pendingUploads").status, "UNKNOWN");
  const hardlink = path.join(other.uploads, "nested", "alias.bin");
  try {
    fs.linkSync(path.join(other.uploads, "nested", "source.bin"), hardlink);
  } catch (error) {
    if (["EPERM", "EACCES"].includes(error.code)) return;
    throw error;
  }
  const linked = await scan(other);
  assert.equal(section(linked, "uploads").status, "UNKNOWN");
  assert.equal(linked.canDeleteLegacy, false);
});

test("operator CLI requires explicit opt-in and emits the same redacted stable manifest", async (t) => {
  const f = await fixture(t);
  const entry = path.resolve(__dirname, "../scripts/zk1-legacy-evidence-manifest.js");
  const args = ["--database", f.databasePath, "--uploads", f.uploads,
    "--temp", f.temp, "--trash", f.trash, "--backups", f.backups];
  const blocked = spawnSync(process.execPath, [entry, ...args], { encoding: "utf8" });
  assert.equal(blocked.status, 2);
  assert.equal(blocked.stdout, "");
  assert.equal(blocked.stderr.includes(f.root), false);
  const allowed = spawnSync(process.execPath, [entry, "--opt-in", ...args], {
    encoding: "utf8", env: process.env,
  });
  assert.equal(allowed.status, 0, allowed.stderr);
  const parsed = JSON.parse(allowed.stdout);
  assert.deepEqual(parsed, await scan(f));
  assert.equal(parsed.sections.backupRetention.status, "UNKNOWN");
  assert.equal(parsed.sections.derivedSemantics.status, "UNKNOWN");
  assert.equal(parsed.sections.remoteProviderCopies.status, "UNKNOWN");
  assert.equal(fs.existsSync(f.databasePath + "-journal"), false);
});

test("invalid ZIP stays UNKNOWN even when its untrusted local SQLite checksum is updated", async (t) => {
  const f = await fixture(t);
  fs.appendFileSync(f.zipFile, "bytes outside ZIP central directory");
  const db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE backup_history SET checksum=?").run(sha(fs.readFileSync(f.zipFile)));
  db.close();
  const report = await scan(f);
  assert.equal(report.sections.backupReferences.status, "PROVEN");
  assert.equal(report.sections.backupMembers.status, "UNKNOWN");
  assert.equal(report.sections.backups.status, "UNKNOWN");
  assert.equal(report.canDeleteLegacy, false);
});
