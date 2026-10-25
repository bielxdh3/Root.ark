"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { DatabaseSync } = require("node:sqlite");
const { ZipArchive } = require("archiver");
const unzipper = require("unzipper");
const { MIGRATIONS } = require("../db/migrations");
const { inspectZk1LegacyEvidenceManifest: inspect } =
  require("../src/services/zk1LegacyEvidenceManifest");
const { createAclFailureDiagnostic } =
  require("../scripts/acl-test-failure-diagnostic");

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
    const zip = new ZipArchive({ zlib: { level: 5 } });
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

test("SQLite query uses the exact pinned image even if a different database is substituted at reopen", async (t) => {
  const a = await fixture(t);
  const b = await fixture(t);
  const replacement = new DatabaseSync(b.databasePath);
  replacement.exec("UPDATE file_versions SET versions_json='{\"currentVersion\":1,\"versions\":[{\"version\":1,\"storedAs\":\"missing-b.bin\",\"size\":1}]}'");
  replacement.close();
  const sqlite = require("node:sqlite");
  const Native = sqlite.DatabaseSync;
  let sourceOpenCount = 0;
  const location = require.resolve("../src/services/zk1LegacyEvidenceManifest");
  try {
    sqlite.DatabaseSync = class PathRebindDatabase extends Native {
      constructor(filename, options) {
        if (filename === a.databasePath) sourceOpenCount++;
        super(filename === a.databasePath ? b.databasePath : filename, options);
      }
    };
    delete require.cache[location];
    const isolated = require(location).inspectZk1LegacyEvidenceManifest;
    const report = await isolated({ optIn: true, databasePath: a.databasePath,
      uploadsDir: a.uploads, tempDir: a.temp, trashDir: a.trash, backupsDir: a.backups });
    assert.equal(report.sections.sqlite.sha256, sha(fs.readFileSync(a.databasePath)));
    assert.equal(report.sections.sqlite.status, "PROVEN");
    assert.equal(report.sections.versions.status, "PROVEN",
      "SQL rows must be derived from the exact hashed image of A, never from B");
    assert.equal(sourceOpenCount, 0,
      "opening the mutable original pathname cannot bind a SQLite transaction to hashed bytes");
    assert.equal(report.canDeleteLegacy, false);
  } finally {
    sqlite.DatabaseSync = Native;
    delete require.cache[location];
  }
});

test("growing file is read through bounded descriptor requests and cannot be PROVEN", async (t) => {
  const f = await fixture(t);
  const victim = path.join(f.uploads, "nested", "old-version.bin");
  const originalSize = fs.statSync(victim).size;
  const originalReadSync = fs.readSync;
  let grew = false;
  const requested = [];
  try {
    fs.readSync = function (fd, buffer, offset, length, position) {
      requested.push(length);
      if (!grew) {
        fs.appendFileSync(victim, Buffer.alloc(128 * 1024, 0x41));
        grew = true;
      }
      return originalReadSync.call(fs, fd, buffer, offset, length, position);
    };
    const report = await scan(f);
    assert.equal(grew, true, "reader must control the allocated and requested byte count");
    assert.ok(requested.length > 0 && requested.every((n) => n > 0 && n <= 16 * 1024));
    assert.ok(requested.some((n) => n <= originalSize));
    assert.equal(report.sections.uploads.status, "UNKNOWN");
    assert.equal(report.sections.versions.status, "UNKNOWN");
  } finally { fs.readSync = originalReadSync; }
});

test("ZIP self-inclusion never substitutes for a missing real physical member", async (t) => {
  const f = await fixture(t);
  let declaredSize = 0;
  let forgedManifest;
  for (let i = 0; i < 10; i++) {
    forgedManifest = JSON.stringify({ included_files: [
      { path: "uploads/nested/copied.bin", size: zipData.length },
      { path: "backup-manifest.json", size: declaredSize },
    ] });
    const next = Buffer.byteLength(forgedManifest);
    if (next === declaredSize) break;
    declaredSize = next;
  }
  assert.equal(Buffer.byteLength(forgedManifest), declaredSize);
  const replaced = path.join(f.root, "forged.zip");
  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(replaced);
    const zip = new ZipArchive({ zlib: { level: 5 } });
    output.on("close", resolve);
    output.on("error", reject);
    zip.on("error", reject);
    zip.pipe(output);
    zip.append(zipData, { name: "uploads/nested/copied.bin" });
    zip.append(Buffer.from("orphan remains unlisted"), { name: "data/archived.json" });
    zip.append(forgedManifest, { name: "backup-manifest.json" });
    zip.finalize().catch(reject);
  });
  fs.copyFileSync(replaced, f.zipFile);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("UPDATE backup_history SET checksum=?").run(sha(fs.readFileSync(f.zipFile)));
  db.close();
  const report = await scan(f);
  assert.equal(report.sections.backupReferences.status, "PROVEN");
  assert.equal(report.sections.backupMembers.status, "UNKNOWN",
    "the declared set must equal the actual non-manifest members");
  assert.equal(report.sections.backups.status, "UNKNOWN");
  assert.equal(report.canDeleteLegacy, false);
});

test("two backup rows naming A cannot conceal unreferenced backup B", async (t) => {
  const f = await fixture(t);
  const secondName = "rootark-backup-2026-10-25-01-00-00.zip";
  fs.copyFileSync(f.zipFile, path.join(f.backups, secondName));
  const db = new DatabaseSync(f.databasePath);
  db.prepare("INSERT INTO backup_history(id,filename,type,status,created_at,checksum) VALUES (?,?,?,?,?,?)")
    .run("backup-2", backupName, "manual", "success", now, sha(fs.readFileSync(f.zipFile)));
  db.close();
  const report = await scan(f);
  assert.equal(report.sections.backupReferences.status, "UNKNOWN",
    "distinct SQL rows are not distinct physical archive identities");
  assert.equal(report.sections.backups.status, "UNKNOWN");
  assert.equal(report.authorizesCutover, false);
});

test("two trash rows naming A cannot conceal unreferenced trash B", async (t) => {
  const f = await fixture(t);
  const pathB = path.join(f.trash, "files", "trash-2");
  fs.mkdirSync(pathB);
  fs.writeFileSync(path.join(pathB, "trash.bin"), trashBytes);
  const db = new DatabaseSync(f.databasePath);
  db.prepare("INSERT INTO trash_items(id,item_type,trash_path,status,deleted_at,size_bytes) VALUES (?,?,?,?,?,?)")
    .run("trash-2", "file", "files/trash-1/trash.bin", "trashed", now, trashBytes.length);
  db.close();
  const report = await scan(f);
  assert.equal(report.sections.trashReferences.status, "UNKNOWN",
    "all physical files need exactly one distinct SQL owner");
  assert.equal(report.canDeleteLegacy, false);
});

test("an inaccessible private SQLite snapshot cleanup cannot leave PROVEN evidence", async (t) => {
  const f = await fixture(t);
  const originalRm = fs.rmSync;
  let snapshotDirectory;
  try {
    fs.rmSync = function (target, options) {
      if (typeof target === "string" && path.basename(target).startsWith("zk1-legacy-sql-image-")
        && !snapshotDirectory) {
        snapshotDirectory = target;
        throw Object.assign(new Error("simulated snapshot handle busy"), { code: "EPERM" });
      }
      return originalRm.call(fs, target, options);
    };
    const report = await scan(f);
    assert.ok(snapshotDirectory);
    assert.equal(report.sections.sqlite.status, "UNKNOWN");
    assert.equal(report.sections.versions.status, "UNKNOWN");
    assert.equal(report.canDeleteLegacy, false);
  } finally {
    fs.rmSync = originalRm;
    if (snapshotDirectory && fs.existsSync(snapshotDirectory))
      originalRm(snapshotDirectory, { recursive: true, force: true });
  }
});

test("legacy SQLite bytes are staged only after proving a private directory, never in the ordinary system temp root", async (t) => {
  const f = await fixture(t);
  const original = fs.openSync;
  let protectedStage = 0;
  let hookFailure;
  try {
    fs.openSync = function (target, ...args) {
      if (typeof target === "string" && path.basename(target) === "image.sqlite") {
        try {
        protectedStage++;
        const parent = path.dirname(target);
        const metadata = fs.lstatSync(parent);
        assert.equal(metadata.isSymbolicLink(), false);
        if (process.platform === "win32") {
          assert.equal(path.resolve(parent).toLowerCase().startsWith(
            path.resolve(os.tmpdir()).toLowerCase() + path.sep), false,
          "ordinary Windows temp has untrusted inherited Modify principals");
          const acl = spawnSync("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File",
            path.resolve(__dirname, "../scripts/zk1-legacy-private-snapshot-acl.ps1"),
            "-Action", "verify", "-Directory", parent], {
            encoding: "utf8", windowsHide: true, timeout: 10000,
          });
          assert.equal(acl.status, 0, "native Windows ACL must already be private before staging bytes");
        } else {
          assert.equal(metadata.mode & 0o777, 0o700, "private POSIX snapshot directory must be 0700");
          assert.equal(metadata.uid, process.getuid());
        }
        } catch (error) { hookFailure = error; throw error; }
      }
      return original.call(fs, target, ...args);
    };
    const report = await scan(f);
    if (hookFailure) throw hookFailure;
    assert.equal(report.sections.sqlite.status, "PROVEN", "private stage hook executed " + protectedStage + " time(s)");
    assert.ok(protectedStage > 0, "a fresh private descriptor-bound database image is required");
    assert.equal(report.sections.versions.status, "PROVEN");
  } finally { fs.openSync = original; }
});

test("hostile temporary ancestor never receives plaintext SQLite bytes", async (t) => {
  const f = await fixture(t);
  const hostileParent = path.join(f.root, "hostile-stage");
  fs.mkdirSync(hostileParent);
  const originalWrite = fs.openSync;
  const originalTmpdir = os.tmpdir;
  const previousLocal = process.env.LOCALAPPDATA;
  let wrote = false;
  try {
    if (process.platform === "win32") {
      // This is a real inherited-hostile subtree of Windows TEMP on the test host.
      // Deterministically make the synthetic parent hostile via an explicit
      // untrusted built-in principal so tests are independent of host policy.
      const cmd = spawnSync("icacls.exe", [hostileParent, "/grant", "*S-1-5-11:(OI)(CI)M"], {
        windowsHide: true, encoding: "utf8", timeout: 10000,
      });
      assert.equal(cmd.status, 0, "synthetic fixture must be writable by Authenticated Users");
      process.env.LOCALAPPDATA = hostileParent;
    } else {
      fs.chmodSync(hostileParent, 0o777);
      os.tmpdir = () => hostileParent;
    }
    fs.openSync = function (filename, ...rest) {
      if (typeof filename === "string" && path.basename(filename) === "image.sqlite") wrote = true;
      return originalWrite.call(fs, filename, ...rest);
    };
    const report = await scan(f);
    assert.equal(report.sections.sqlite.status, "UNKNOWN");
    assert.equal(report.sections.versions.status, "UNKNOWN");
    assert.equal(wrote, false, "never stage a sensitive SQLite copy below an untrusted ancestor");
    assert.equal(report.canDeleteLegacy, false);
  } finally {
    fs.openSync = originalWrite;
    os.tmpdir = originalTmpdir;
    if (previousLocal === undefined) delete process.env.LOCALAPPDATA;
    else process.env.LOCALAPPDATA = previousLocal;
    if (process.platform !== "win32") fs.chmodSync(hostileParent, 0o700);
  }
});

test("Windows parent inheritable-only foreign Modify is rejected before any SQLite staging", {
  skip: process.platform !== "win32",
}, async (t) => {
  const f = await fixture(t);
  const trustedRoot = process.env.LOCALAPPDATA;
  assert.ok(trustedRoot && path.isAbsolute(trustedRoot));
  const badParent = fs.mkdtempSync(path.join(trustedRoot, "zk65-acl-only-fixture-"));
  const original = fs.openSync;
  const previousLocal = process.env.LOCALAPPDATA;
  let staged = false;
  try {
    const acl = spawnSync("icacls.exe", [badParent, "/grant", "*S-1-5-11:(OI)(CI)(IO)M"], {
      windowsHide: true, encoding: "utf8", timeout: 10000,
    });
    assert.equal(acl.status, 0, "inheritable-only adversarial ACE fixture must exist");
    process.env.LOCALAPPDATA = badParent;
    fs.openSync = function (target, ...args) {
      if (typeof target === "string" && path.basename(target) === "image.sqlite") staged = true;
      return original.call(fs, target, ...args);
    };
    const report = await scan(f);
    assert.equal(staged, false, "inheritable Modify on the direct parent may reach new children");
    assert.equal(report.sections.sqlite.status, "UNKNOWN");
    assert.equal(report.sections.versions.status, "UNKNOWN");
    assert.equal(report.canDeleteLegacy, false);
  } finally {
    process.env.LOCALAPPDATA = previousLocal;
    fs.openSync = original;
    fs.rmSync(badParent, { recursive: true, force: true });
  }
});

test("Windows ACL verifier never resolves the PowerShell executable from hostile PATH", {
  skip: process.platform !== "win32",
}, async (t) => {
  const f = await fixture(t);
  const child = require("node:child_process");
  const actual = child.spawnSync;
  const cacheKey = require.resolve("../src/services/zk1LegacyEvidenceManifest");
  const hostile = path.join(f.root, "hostile-path");
  fs.mkdirSync(hostile);
  fs.writeFileSync(path.join(hostile, "powershell.exe"), Buffer.from("ATTACKER EXECUTABLE"));
  const savedPath = process.env.PATH;
  const calls = [];
  try {
    process.env.PATH = hostile + path.delimiter + savedPath;
    child.spawnSync = function (command, args, options) {
      calls.push(command);
      if (path.basename(command).toLowerCase() === "powershell.exe"
        && !path.isAbsolute(command))
        return { status: 0, stdout: "", stderr: "" }; // forged ACL approval
      return actual.call(child, command, args, options);
    };
    delete require.cache[cacheKey];
    const guarded = require(cacheKey).inspectZk1LegacyEvidenceManifest;
    const result = await guarded({ optIn: true, databasePath: f.databasePath,
      uploadsDir: f.uploads, tempDir: f.temp, trashDir: f.trash, backupsDir: f.backups });
    assert.ok(calls.length > 0);
    assert.ok(calls.every((command) => path.isAbsolute(command)
      && command.toLowerCase().includes("windows\\system32\\windowspowershell")),
    "PowerShell invocation must bypass hostile PATH and point into the native OS tree");
    assert.equal(result.sections.sqlite.status, "PROVEN");
  } finally {
    child.spawnSync = actual;
    process.env.PATH = savedPath;
    delete require.cache[cacheKey];
  }
});

test("simulated recursive-delete failure cannot orphan plaintext SQLite snapshot bytes", async (t) => {
  const f = await fixture(t);
  const originalRm = fs.rmSync;
  let isolatedPath;
  let blocked = false;
  try {
    fs.rmSync = function (target, options) {
      if (!blocked && typeof target === "string"
        && path.basename(target).startsWith("zk1-legacy-sql-image-")) {
        blocked = true;
        isolatedPath = target;
        throw Object.assign(Error("EACCES test injected during recursive cleanup"), { code: "EACCES" });
      }
      return originalRm.call(fs, target, options);
    };
    const report = await scan(f);
    assert.equal(blocked, true);
    assert.equal(report.sections.sqlite.status, "UNKNOWN");
    assert.equal(report.canDeleteLegacy, false);
    if (fs.existsSync(isolatedPath)) {
      const leftovers = fs.readdirSync(isolatedPath);
      for (const file of leftovers) {
        const contents = fs.readFileSync(path.join(isolatedPath, file));
        assert.equal(contents.includes(Buffer.from("SQLite format 3")), false,
          "even if the cleanup directory remains, no complete plaintext SQLite image may survive");
        assert.equal(contents.length, 0, "snapshot must be truncated after a verified scrub");
      }
    }
  } finally {
    fs.rmSync = originalRm;
    if (isolatedPath && fs.existsSync(isolatedPath))
      originalRm(isolatedPath, { recursive: true, force: true });
  }
});

test("unlink and recursive removal both blocked still leave zero-length private image", async (t) => {
  const f = await fixture(t);
  const originalUnlink = fs.unlinkSync;
  const originalRemove = fs.rmSync;
  let snapshotDir;
  let unlinkBlocked = false;
  try {
    fs.unlinkSync = function (target) {
      if (typeof target === "string" && path.basename(target) === "image.sqlite") {
        unlinkBlocked = true;
        snapshotDir = path.dirname(target);
        throw Object.assign(Error("injected unlink EACCES"), { code: "EACCES" });
      }
      return originalUnlink.apply(fs, arguments);
    };
    fs.rmSync = function (target, options) {
      if (typeof target === "string" && path.basename(target).startsWith("zk1-legacy-sql-image-"))
        throw Object.assign(Error("injected rm EACCES"), { code: "EACCES" });
      return originalRemove.call(fs, target, options);
    };
    const report = await scan(f);
    assert.equal(unlinkBlocked, true);
    assert.equal(report.sections.sqlite.status, "UNKNOWN");
    assert.ok(fs.existsSync(path.join(snapshotDir, "image.sqlite")));
    assert.equal(fs.statSync(path.join(snapshotDir, "image.sqlite")).size, 0);
    assert.equal(report.canDeleteLegacy, false);
  } finally {
    fs.unlinkSync = originalUnlink;
    fs.rmSync = originalRemove;
    if (snapshotDir && fs.existsSync(snapshotDir))
      originalRemove(snapshotDir, { recursive: true, force: true });
  }
});

test("Windows generic access ACEs cannot evade private snapshot ancestor checks", {
  skip: process.platform !== "win32",
}, async (t) => {
  const diag = createAclFailureDiagnostic(t, "LEGACY_GENERIC_ACE");
  return diag.run(async () => {
  const f = await fixture(t);
  diag.stage("FIXTURE_READY");
  const parent = fs.mkdtempSync(path.join(process.env.LOCALAPPDATA, "zk65-generic-ace-"));
  const oldRoot = process.env.LOCALAPPDATA;
  const nativePs = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const nativeScript = path.resolve(__dirname, "../scripts/zk1-legacy-private-snapshot-acl.ps1");
  const originalWrite = fs.openSync;
  let wrote = false;
  try {
    diag.stage("ACE_WRITE");
    const quotedParent = parent.replace(/'/g, "''");
    const apply = spawnSync(nativePs, ["-NoProfile", "-NonInteractive", "-Command",
      "$ErrorActionPreference='Stop';$p='" + quotedParent + "';$a=Get-Acl -LiteralPath $p;" +
      "$id=New-Object Security.Principal.SecurityIdentifier('S-1-5-11');" +
      "$raw=New-Object Security.AccessControl.RawSecurityDescriptor($a.GetSecurityDescriptorSddlForm('All'));" +
      "$ace=New-Object Security.AccessControl.CommonAce(" +
      "[Security.AccessControl.AceFlags]'ContainerInherit, ObjectInherit'," +
      "[Security.AccessControl.AceQualifier]::AccessAllowed,268435456,$id,$false,$null);" +
      "$raw.DiscretionaryAcl.InsertAce(0,$ace);" +
      "$buf=New-Object byte[] $raw.BinaryLength;$raw.GetBinaryForm($buf,0);" +
      "$a.SetSecurityDescriptorBinaryForm($buf,[Security.AccessControl.AccessControlSections]::Access);" +
      "Set-Acl -LiteralPath $p -AclObject $a;" +
      "$actual=(Get-Acl -LiteralPath $p).GetSecurityDescriptorBinaryForm();" +
      "$r=New-Object Security.AccessControl.RawSecurityDescriptor($actual,0);" +
      // Hosted NTFS may normalize GENERIC_ALL into destructive FILE_* rights on Set-Acl.
      // Require a persisted untrusted write/delete/WRITE_DAC ACE in either form.
      "$found=$false;foreach($entry in $r.DiscretionaryAcl) {" +
      "if($entry.SecurityIdentifier.Value -eq 'S-1-5-11' -and" +
      " (($entry.AccessMask -band 268435456) -ne 0 -or" +
      " ($entry.AccessMask -band 327682) -ne 0)){$found=$true}};" +
      "if(-not $found){throw 'Unsafe access ACE did not persist'};" +
      "Write-Output 'UNSAFE_GENERIC_OR_NORMALIZED_ACE_FOUND';"], {
      windowsHide: true, encoding: "utf8", timeout: 12000,
    });
    diag.stage("ACE_READBACK");
    if (apply.status === 0 && /UNSAFE_GENERIC_OR_NORMALIZED_ACE_FOUND/.test(apply.stdout || ""))
      diag.trust("UNTRUSTED_ADDED");
    assert.equal(apply.status, 0, apply.stderr);
    assert.match(apply.stdout, /UNSAFE_GENERIC_OR_NORMALIZED_ACE_FOUND/,
      "fixture must store a GENERIC_ALL ACE or its dangerous normalized file-right equivalent");
    diag.stage("GUARD_VERIFY");
    const check = spawnSync(nativePs, ["-NoProfile", "-NonInteractive", "-File", nativeScript,
      "-Action", "verify", "-Directory", parent], { encoding: "utf8", windowsHide: true });
    diag.trust(check.status === 0 ? "ACCEPTED" : "REJECTED");
    assert.notEqual(check.status, 0, "raw GENERIC_ALL cannot pass the ACL guardian");
    process.env.LOCALAPPDATA = parent;
    fs.openSync = function (name, ...args) {
      if (typeof name === "string" && path.basename(name) === "image.sqlite") wrote = true;
      return originalWrite.call(fs, name, ...args);
    };
    diag.stage("CUSTODY_SCAN");
    const report = await scan(f);
    diag.stage("CUSTODY_ASSERT");
    assert.equal(wrote, false, "no SQLite bytes can be staged under a GENERIC_ALL principal");
    assert.equal(report.sections.sqlite.status, "UNKNOWN");
  } finally {
    process.env.LOCALAPPDATA = oldRoot;
    fs.openSync = originalWrite;
    fs.rmSync(parent, { recursive: true, force: true });
  }
  });
});

test("native ACL unsafe mask explicitly covers raw GENERIC_ALL and GENERIC_WRITE", () => {
  const script = fs.readFileSync(path.resolve(__dirname,
    "../scripts/zk1-legacy-private-snapshot-acl.ps1"), "utf8");
  const m = script.match(/\$unsafe\s*=\s*\[long\]0x([a-f\d]+)/i);
  assert.ok(m, "native guardian must use a known audited rights mask");
  const mask = Number.parseInt(m[1], 16);
  assert.equal(mask & 0x10000000, 0x10000000, "raw GENERIC_ALL must fail closed");
  assert.equal(mask & 0x40000000, 0x40000000, "raw GENERIC_WRITE must fail closed");
  assert.equal(mask & 0x000D0152, 0x000D0152, "specific FILE_* destructive bits remain rejected");
});
